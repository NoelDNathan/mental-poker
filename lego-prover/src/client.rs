//! API cliente: prove + verify de los circuitos lego desde el FULL witness en
//! decimales (lo que produce el `ark-circom` del wasm_client). PK + R1CS
//! embebidos. Es la frontera que consume zk-reshuffle (ark 0.5): entra un
//! `&[String]`, sale un `LegoProofJson`. Ningun tipo ark 0.4 cruza la firma.

use core::str::FromStr;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use ark_bn254::{Bn254, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use ark_ec::AffineRepr;

use crate::{
    compute_link_d, derive_alpha_beta, link_v_from_bytes, load_pk, load_r1cs, make_link_gens,
    prove_with_link_v, CircuitR1cs, G1Json, LegoProofJson, COMMIT_WITNESS_COUNT,
};
use legogroth16::{prepare_verifying_key, verify_proof_incl_cp_link, PreparedVerifyingKey,
    ProvingKeyWithLink};

// Shuffle (residual con FS). PK ~677 KB, R1CS ~174 KB: se embeben.
static SHUFFLE_PK: &[u8] = include_bytes!("../artifacts/shuffle_pk.bin");
static SHUFFLE_R1CS: &[u8] = include_bytes!("../artifacts/shuffle_r1cs.bin");
// Reshuffle/cancellation (residual sin FS). PK ~4.7 MB, R1CS ~2.1 MB.
static RESHUFFLE_PK: &[u8] = include_bytes!("../artifacts/reshuffle_pk.bin");
static RESHUFFLE_R1CS: &[u8] = include_bytes!("../artifacts/reshuffle_r1cs.bin");

type E = Bn254;

// === Cache de artefactos parseados (#4) =====================================
// Deserializar una PK lego (hasta ~22 MB) o un R1CS es caro y se repetia en CADA
// prove/verify (load-on-demand del pool = N veces la misma PK). Cacheamos la
// estructura ya parseada y la reutilizamos mientras los bytes no cambien.
//
// Clave = hash del contenido (no de un puntero ni del tamano): asi un cambio de
// version del artefacto INVALIDA la entrada (protege de usar una PK cacheada con
// un circuito/R1CS de otra version). El hash (SipHash de std sobre los bytes) es
// ~ms, despreciable frente a la deserializacion que evita.
//
// Las PK/R1CS embebidos (statics) tienen direccion estable -> una `OnceLock` por
// artefacto basta (se parsean una sola vez en todo el proceso). Los dinamicos
// (precompute, llegan por bytes) usan una cache de 1 entrada (last-used) por rol:
// el pool reutiliza SIEMPRE la misma PK, asi que una sola ranura ya da "parsear
// una vez por version" + "N precomputes no reparsean".

fn content_key(bytes: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    bytes.len().hash(&mut h);
    bytes.hash(&mut h);
    h.finish()
}

/// Cache de 1 entrada (last-used) parametrizada por rol. Devuelve un `Arc` para
/// soltar el lock antes de usar el artefacto (el prove corre fuera del lock).
///
/// REGLA (2026-09-17, causa del "Atomics.wait cannot be called in this
/// context"): esta cache la tocan a la vez el HILO PRINCIPAL del navegador
/// (verificar una proof pendiente, la residual del turno) y los workers de
/// rayon (relleno del pool). El hilo principal no puede bloquearse: un
/// `lock()` contendido es `memory.atomic.wait`, el navegador corta la llamada
/// con una excepcion JS que no desenrolla Rust y el estado del wasm queda
/// envenenado. Por eso:
///   1. el PARSEO (segundos, ~20 MB) ocurre FUERA del candado;
///   2. la seccion critica es solo "comparar la clave y clonar/guardar el
///      `Arc`" (nanosegundos) y se toma con `try_lock` en bucle, nunca con
///      `lock()`;
///   3. no hay `OnceLock`: su `Once` tambien espera si otro hilo inicializa.
/// Coste aceptado: si dos hilos llegan a la vez con la cache fria, los dos
/// parsean (una vez por version de PK y pestana) y gana el ultimo en guardar;
/// con la misma clave el resultado es identico.
struct OneSlot<T> {
    slot: Mutex<Option<(u64, Arc<T>)>>,
}

impl<T> OneSlot<T> {
    const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// Seccion critica SIN espera bloqueante (ver la regla de arriba). Lo que
    /// se hace dentro debe ser de nanosegundos: nada de parsear ni de asignar
    /// memoria grande aqui.
    fn with_slot<R>(&self, f: impl FnOnce(&mut Option<(u64, Arc<T>)>) -> R) -> R {
        loop {
            match self.slot.try_lock() {
                Ok(mut guard) => return f(&mut guard),
                Err(TryLockError::WouldBlock) => std::hint::spin_loop(),
                Err(TryLockError::Poisoned(poisoned)) => return f(&mut poisoned.into_inner()),
            }
        }
    }

    fn get_or_parse(&self, bytes: &[u8], parse: impl FnOnce(&[u8]) -> T) -> Arc<T> {
        let key = content_key(bytes);
        let hit = self.with_slot(|slot| match slot {
            Some((k, v)) if *k == key => Some(Arc::clone(v)),
            _ => None,
        });
        if let Some(v) = hit {
            return v;
        }
        // Fuera del candado: puede tardar segundos.
        let parsed = Arc::new(parse(bytes));
        self.with_slot(|slot| *slot = Some((key, Arc::clone(&parsed))));
        parsed
    }

    /// Vacia la ranura (solo arnes).
    fn evict(&self) {
        self.with_slot(|slot| *slot = None);
    }
}

static PRECOMPUTE_PK: OneSlot<ProvingKeyWithLink<E>> = OneSlot::new();
static PRECOMPUTE_R1CS: OneSlot<CircuitR1cs> = OneSlot::new();
static PRECOMPUTE_PVK: OneSlot<PreparedVerifyingKey<E>> = OneSlot::new();

fn cached_precompute_pk(bytes: &[u8]) -> Arc<ProvingKeyWithLink<E>> {
    PRECOMPUTE_PK.get_or_parse(bytes, load_pk)
}
fn cached_precompute_r1cs(bytes: &[u8]) -> Arc<CircuitR1cs> {
    PRECOMPUTE_R1CS.get_or_parse(bytes, load_r1cs)
}
fn cached_precompute_pvk(pk_bytes: &[u8], pk: &ProvingKeyWithLink<E>) -> Arc<PreparedVerifyingKey<E>> {
    // Clave por los bytes de la PK: una PVK por version de PK.
    PRECOMPUTE_PVK.get_or_parse(pk_bytes, |_| prepare_verifying_key::<E>(&pk.vk.groth16_vk))
}

/// SOLO ARNES (test 1 de la carrera main/worker): vacia la cache de precompute
/// para que el siguiente `cached_*` vuelva a parsear de verdad (segundos).
/// Se llama SIN worker en vuelo (sin contencion).
pub fn chaos_evict_precompute_cache() {
    PRECOMPUTE_PK.evict();
    PRECOMPUTE_R1CS.evict();
    PRECOMPUTE_PVK.evict();
}

/// Toca la cache de precompute tal y como lo hace un prove o una verificacion
/// (`cached_r1cs` + `cached_pk` + `cached_pvk`). Con la cache fria parsea
/// (segundos); caliente, tres clones de `Arc`. El arnes mide el tiempo.
pub fn touch_precompute_cache(pk_bytes: &[u8], r1cs_bytes: &[u8]) {
    let _r1cs = cached_precompute_r1cs(r1cs_bytes);
    let pk = cached_precompute_pk(pk_bytes);
    let _pvk = cached_precompute_pvk(pk_bytes, &pk);
}

// PK/R1CS/PVK embebidos: parseados una sola vez por proceso (direccion estable).
fn shuffle_pk() -> &'static ProvingKeyWithLink<E> {
    static C: OnceLock<ProvingKeyWithLink<E>> = OnceLock::new();
    C.get_or_init(|| load_pk(SHUFFLE_PK))
}
fn shuffle_r1cs() -> &'static CircuitR1cs {
    static C: OnceLock<CircuitR1cs> = OnceLock::new();
    C.get_or_init(|| load_r1cs(SHUFFLE_R1CS))
}
fn shuffle_pvk() -> &'static PreparedVerifyingKey<E> {
    static C: OnceLock<PreparedVerifyingKey<E>> = OnceLock::new();
    C.get_or_init(|| prepare_verifying_key::<E>(&shuffle_pk().vk.groth16_vk))
}
fn reshuffle_pk() -> &'static ProvingKeyWithLink<E> {
    static C: OnceLock<ProvingKeyWithLink<E>> = OnceLock::new();
    C.get_or_init(|| load_pk(RESHUFFLE_PK))
}
fn reshuffle_r1cs() -> &'static CircuitR1cs {
    static C: OnceLock<CircuitR1cs> = OnceLock::new();
    C.get_or_init(|| load_r1cs(RESHUFFLE_R1CS))
}
fn reshuffle_pvk() -> &'static PreparedVerifyingKey<E> {
    static C: OnceLock<PreparedVerifyingKey<E>> = OnceLock::new();
    C.get_or_init(|| prepare_verifying_key::<E>(&reshuffle_pk().vk.groth16_vk))
}

/// RNG FRESCO con entropia real del OS (#1): cada proof Groth16 usa randomness
/// (r, s) nueva e independiente, como exige el modelo zero-knowledge. NO se
/// deriva de `link_v` ni de ninguna seed reproducible. `getrandom` (feature `js`)
/// da entropia tanto en nativo como en wasm32.
fn fresh_groth16_rng() -> StdRng {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS entropy para el RNG de Groth16");
    StdRng::from_seed(seed)
}

/// Resultado de probar: la proof serializable + el self-check de verificacion.
pub struct ProveOutput {
    pub proof: LegoProofJson,
    pub verified: bool,
}

fn parse_decimals(witness: &[String]) -> Vec<Fr> {
    witness
        .iter()
        .map(|s| Fr::from_str(s).expect("wire no decimal"))
        .collect()
}

fn prove_residual(
    pk: &ProvingKeyWithLink<Bn254>,
    pvk: &PreparedVerifyingKey<Bn254>,
    r1cs: &CircuitR1cs,
    full_witness: &[String],
    link_v_bytes: &[u8; 32],
) -> ProveOutput {
    let wires = parse_decimals(full_witness);
    let num_public = r1cs.num_public as usize;
    assert_eq!(
        wires.len(),
        num_public + r1cs.num_private as usize,
        "longitud del witness no cuadra con el R1CS"
    );
    let public_inputs: Vec<Fr> = wires[1..num_public].to_vec();
    let pubs_dec: Vec<String> = full_witness[1..num_public].to_vec();

    // link_v: Fr de ancho completo, reconstruido de los 32 bytes persistidos en
    // la entrada de precompute (compartido precompute<->residual para enlazar).
    let link_v = link_v_from_bytes(link_v_bytes);
    // RNG del blinding interno de Groth16 (r, s): fresco e independiente del link_v.
    let mut rng = fresh_groth16_rng();
    let proof = prove_with_link_v(pk, r1cs, wires, link_v, &mut rng);

    let verified = verify_proof_incl_cp_link(pvk, &pk.vk, &proof, &public_inputs).is_ok();
    let json = LegoProofJson::from_proof(&proof, &pubs_dec);
    ProveOutput {
        proof: json,
        verified,
    }
}

/// Challenges Fiat-Shamir del shuffle derivados por el cliente: `alpha`, `beta`
/// (decimales) y el commitment `link_d`. Se calculan en la pasada
/// commit-then-challenge ANTES de la pasada final del witness.
pub struct ShuffleChallenges {
    pub alpha: String,
    pub beta: String,
    pub link_d: G1Json,
}

/// Deriva los challenges del shuffle: `link_d = MSM(NUMS, committed || link_v)`
/// y `alpha/beta = keccak(...)`. `committed` son los 208 r'_G||r'_H (que el
/// cliente ya conoce: son inputs), `pubs` los 420 publics que preceden a los
/// challenges (`wires[1..421]`, no dependen de alpha/beta).
pub fn shuffle_challenges(
    committed: &[String],
    pubs: &[String],
    link_v_bytes: &[u8; 32],
    domain_sep: &[u8; 32],
) -> ShuffleChallenges {
    let cw = parse_decimals(committed);
    let pubs_fr = parse_decimals(pubs);
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let link_v = link_v_from_bytes(link_v_bytes);
    let link_d_pt = compute_link_d(&link_gens.pedersen_gens, &cw, link_v);
    let (alpha, beta) = derive_alpha_beta(domain_sep, &link_d_pt, &pubs_fr);
    let (x, y) = link_d_pt.xy().expect("link_d no es identidad");
    ShuffleChallenges {
        alpha: alpha.to_string(),
        beta: beta.to_string(),
        link_d: G1Json {
            x: x.to_string(),
            y: y.to_string(),
        },
    }
}

/// Prueba el residual del shuffle desde su FULL witness (debe traer ya los
/// challenges alpha/beta consistentes con `link_v`).
pub fn prove_shuffle(full_witness: &[String], link_v_bytes: &[u8; 32]) -> ProveOutput {
    prove_residual(
        shuffle_pk(),
        shuffle_pvk(),
        shuffle_r1cs(),
        full_witness,
        link_v_bytes,
    )
}

/// Prueba el residual del reshuffle/cancellation desde su FULL witness (sin FS).
pub fn prove_reshuffle(full_witness: &[String], link_v_bytes: &[u8; 32]) -> ProveOutput {
    prove_residual(
        reshuffle_pk(),
        reshuffle_pvk(),
        reshuffle_r1cs(),
        full_witness,
        link_v_bytes,
    )
}

/// Prueba el PRECOMPUTE (`rerandomization_precompute_52_lego`) desde su FULL
/// witness. A diferencia del shuffle/reshuffle, su PK (~20 MB) NO se embebe: se
/// pasa por bytes (load-on-demand en el navegador, capa 3.4b paso 3 — pool de
/// background). Comparte con el residual los MISMOS 208 committed witnesses
/// (r'_G||r'_H), asi que con el MISMO `link_v` produce el MISMO `link_d`:
/// ese es el enlace cp_link entre la precompute de background y la residual del
/// turno. Sin Fiat-Shamir (num_public = 5: G[2], H[2]).
///
/// La PK y el R1CS se cachean por contenido (#4): el pool genera N precomputes
/// con la MISMA PK -> se deserializa una sola vez, no N.
pub fn prove_precompute(
    pk_bytes: &[u8],
    r1cs_bytes: &[u8],
    full_witness: &[String],
    link_v_bytes: &[u8; 32],
) -> ProveOutput {
    let r1cs = cached_precompute_r1cs(r1cs_bytes);
    let pk = cached_precompute_pk(pk_bytes);
    let pvk = cached_precompute_pvk(pk_bytes, &pk);
    prove_residual(&pk, &pvk, &r1cs, full_witness, link_v_bytes)
}

/// Verificacion P2P del precompute desde el bundle: solo cp_link contra sus
/// publics (G, H), sin Fiat-Shamir. La PK (~20 MB) se pasa por bytes
/// (load-on-demand) y se cachea por contenido (#4). El enlace con la residual lo
/// comprueba el caller exigiendo `precompute.link_d == residual.link_d`.
pub fn verify_precompute_lego(proof: &LegoProofJson, pk_bytes: &[u8]) -> bool {
    let pk = cached_precompute_pk(pk_bytes);
    let pvk = cached_precompute_pvk(pk_bytes, &pk);
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) => p,
        None => return false,
    };
    verify_proof_incl_cp_link(&pvk, &pk.vk, &ark_proof, &public_inputs).is_ok()
}

/// `num_public` del shuffle (`shuffling_multiset_lego`): 1 + 422 publics. Los
/// `pubs` del JSON son `wires[1..num_public]` = 422 (420 FS-publics + alpha + beta).
const SHUFFLE_NUM_PUBS: usize = 422;

/// Verificacion P2P del residual del SHUFFLE desde el bundle (`LegoProofJson`),
/// lo que hace cada peer al recibir la proof de otro. Comprueba:
///   1. la proof cp_link verifica contra sus public inputs y la vk embebida;
///   2. (seguridad Fiat-Shamir) alpha/beta del circuito (`pubs[420]`,`pubs[421]`)
///      coinciden con los RE-DERIVADOS de `link_d` + los 420 FS-publics — impide
///      que un prover elija challenges a su antojo (mismo check que el verifier
///      Solidity `deriveChallenges`).
/// Devuelve `false` ante cualquier entrada malformada (sin panic).
pub fn verify_shuffle_lego(proof: &LegoProofJson, domain_sep: &[u8; 32]) -> bool {
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) if p.len() == SHUFFLE_NUM_PUBS => p,
        _ => return false,
    };
    if verify_proof_incl_cp_link(shuffle_pvk(), &shuffle_pk().vk, &ark_proof, &public_inputs)
        .is_err()
    {
        return false;
    }
    // Re-derivacion Fiat-Shamir desde el link_d de la propia proof + el contexto
    // (#5): si el domain_sep no es el del contexto en que se genero la proof,
    // alpha/beta re-derivados no cuadran y se rechaza (anti-replay entre contextos).
    let fs_pubs = &public_inputs[..crate::NUM_FS_PUBLICS];
    let (alpha, beta) = derive_alpha_beta(domain_sep, &ark_proof.link_d, fs_pubs);
    alpha == public_inputs[crate::NUM_FS_PUBLICS] && beta == public_inputs[crate::NUM_FS_PUBLICS + 1]
}

/// Verificacion P2P del residual del RESHUFFLE/cancellation desde el bundle.
/// Sin Fiat-Shamir (remask posicional): solo la proof cp_link contra sus publics.
pub fn verify_reshuffle_lego(proof: &LegoProofJson) -> bool {
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) => p,
        None => return false,
    };
    verify_proof_incl_cp_link(reshuffle_pvk(), &reshuffle_pk().vk, &ark_proof, &public_inputs)
        .is_ok()
}

#[cfg(test)]
mod one_slot_tests {
    use super::OneSlot;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    static SLOT: OneSlot<Vec<u8>> = OneSlot::new();
    static PARSES: AtomicUsize = AtomicUsize::new(0);

    fn slow_parse(bytes: &[u8]) -> Vec<u8> {
        PARSES.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(300));
        bytes.to_vec()
    }

    #[test]
    fn el_parseo_no_retiene_el_candado_y_la_cache_queda_caliente() {
        SLOT.evict();
        PARSES.store(0, Ordering::SeqCst);
        let bytes: Arc<Vec<u8>> = Arc::new((0..64u8).collect());

        // "Worker": entra con la cache fria y se pasa 300 ms parseando.
        let w_bytes = Arc::clone(&bytes);
        let worker = thread::spawn(move || SLOT.get_or_parse(&w_bytes, slow_parse));
        thread::sleep(Duration::from_millis(50));

        // "Main": llega con el worker dentro del parseo. Con el candado viejo
        // esperaria a que terminara (en el navegador: Atomics.wait). Ahora
        // parsea por su cuenta sin tocar un candado retenido.
        let t0 = Instant::now();
        let mine = SLOT.get_or_parse(&bytes, slow_parse);
        let mine_ms = t0.elapsed().as_millis();
        let theirs = worker.join().unwrap();

        assert_eq!(*mine, *bytes);
        assert_eq!(*theirs, *bytes);
        assert_eq!(PARSES.load(Ordering::SeqCst), 2, "cache fria a la vez: los dos parsean");
        assert!(mine_ms < 600, "el main no espero al worker ({} ms)", mine_ms);

        // Caliente: nadie parsea y es inmediato.
        let t1 = Instant::now();
        let again = SLOT.get_or_parse(&bytes, slow_parse);
        assert_eq!(PARSES.load(Ordering::SeqCst), 2);
        assert!(t1.elapsed() < Duration::from_millis(50));
        assert_eq!(*again, *bytes);

        // Otra version del artefacto: se reparsea y sustituye.
        let other: Vec<u8> = (100..164u8).collect();
        let got = SLOT.get_or_parse(&other, slow_parse);
        assert_eq!(*got, other);
        assert_eq!(PARSES.load(Ordering::SeqCst), 3);
    }
}
