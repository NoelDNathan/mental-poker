//! Pool de precompute (capa 3.4b paso 3) fuera del `wasm_client`: el tipo de la
//! entrada, su generacion y su formato binario. Lo comparten el wasm (relleno de
//! fondo en un worker de rayon) y el prover nativo de escritorio (Tauri, Fase 1
//! del plan de escritorio), que prueba la MISMA entrada con el MISMO codigo y se
//! la entrega al wasm por `import_precompute_entry`.
//!
//! La entrada lleva secretos (`r_prime`, `link_v`): sin `Debug`, y el formato
//! binario solo viaja por el IPC local del proceso de escritorio, nunca por un
//! canal publico ni a un log.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use barnett_smart_card_protocol::BarnettSmartProtocol;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use texas_holdem::{CardParameters, CardProtocol, PublicKey, Scalar};
use zk_reshuffle::lego::LegoProofJson;

/// Cartas del mazo: una `r_prime` por carta.
pub const DECK_SIZE: usize = 52;

/// Una entrada del pool de precompute: una proof generada en background con sus
/// `r_prime` y `link_v`. Al consumirla en el turno, el residual debe usar
/// EXACTAMENTE estos `r_prime`/`link_v` para que su `link_d` coincida con el de
/// la precompute (el enlace cp_link del pool). `link_v` son 32 bytes de entropia
/// real (#1): el blinding del cp_link de ancho completo (`Fr`), NO una seed de
/// 64 bits.
#[derive(Clone)]
pub struct PrecomputeEntry {
    pub r_prime: Vec<Scalar>,
    pub link_v: [u8; 32],
    pub proof: LegoProofJson,
    /// Clave conjunta (H del circuito) bajo la que se probo la entrada. Solo
    /// vale para esa clave: el turno descarta las de otra (`take_or_make`), y
    /// el relleno para la mano SIGUIENTE (`poker_prepare_next_hand`) puede
    /// dejar en el pool entradas de una clave que aun no es la vigente.
    pub joint_pk: PublicKey,
}

/// Los artefactos del precompute, fetcheados por JS al entrar a la sala
/// (no se embeben: ~30 MB juntos). `circom_wasm` + `circom_r1cs` calculan el
/// witness con ark-circom; `lego_*` (PK ~20 MB + `CircuitR1cs`) hacen el
/// prove/verify cp_link.
#[derive(Clone, Default)]
pub struct PrecomputeArtifacts {
    pub circom_wasm: Vec<u8>,
    pub circom_r1cs: Vec<u8>,
    pub lego_pk: Vec<u8>,
    pub lego_r1cs: Vec<u8>,
    /// `.graph` de witnesscalc (build-circuit) del MISMO circuito: witness ~4x
    /// más rápido con wires idénticos. VACÍO = usar el intérprete ark-circom
    /// (circom_wasm + circom_r1cs) de siempre.
    pub graph: Vec<u8>,
}

/// Parametros del protocolo con la generadora fija del juego. El precompute
/// solo usa `enc_parameters.generator` (la G del circuito), que no depende del
/// `rng`; el resto de `pp` no interviene.
pub fn card_parameters() -> CardParameters {
    let mut rng = StdRng::from_entropy();
    CardProtocol::setup(&mut rng, texas_holdem::generator(), 2, 26)
        .expect("Failed to setup CardParameters")
}

/// Núcleo del precompute **Send-safe**: SIN estado del juego, solo datos propios /
/// referencias a datos propios del caller, para poder correr dentro de
/// `rayon::spawn` (un Web Worker, que NO ve el `thread_local POKER_STATE`) o en un
/// hilo nativo. Genera `r_prime` (52 escalares < 2^100) + `link_v` (32 B CSPRNG,
/// #1) y prueba el cp_link de background. Error en `String` (Send: `Box<dyn
/// Error>` no es Send y no cruzaría el buzón worker->main).
pub fn build_precompute_entry_parts(
    pp: &CardParameters,
    shared_key: &PublicKey,
    artifacts: &PrecomputeArtifacts,
) -> Result<PrecomputeEntry, String> {
    let mut rng = StdRng::from_entropy();
    let max_value: u128 = 2u128.pow(100);
    let r_prime: Vec<Scalar> = (0..DECK_SIZE)
        .map(|_| Scalar::from(rng.gen_range(0..max_value)))
        .collect();
    // #1: link_v de ancho completo = 32 bytes del CSPRNG (StdRng sembrado por
    // entropia del OS), NO una seed de 64 bits. Se persiste en la entrada para
    // que el residual del turno reproduzca el MISMO link_d (enlace cp_link).
    let link_v: [u8; 32] = rng.gen();

    // Witness por grafo si el frontend lo aportó (vacío = intérprete ark-circom).
    let graph = if artifacts.graph.is_empty() {
        None
    } else {
        Some(artifacts.graph.as_slice())
    };
    let out = CardProtocol::prove_precompute_lego(
        &r_prime,
        pp,
        shared_key,
        &link_v,
        &artifacts.circom_wasm,
        &artifacts.circom_r1cs,
        &artifacts.lego_r1cs,
        &artifacts.lego_pk,
        graph,
    )
    .map_err(|e| format!("prove_precompute_lego failed: {}", e))?;

    if !out.verified {
        return Err("precompute proof failed self-verification".into());
    }

    Ok(PrecomputeEntry {
        r_prime,
        link_v,
        proof: out.proof,
        joint_pk: shared_key.clone(),
    })
}

// ---- Formato binario v1 ------------------------------------------------------
//
//   "PPE1" | link_v (32 B) | len u32 LE + joint_pk canonico
//          | len u32 LE + r_prime canonico (Vec<Scalar>)
//          | len u32 LE + proof (JSON utf-8)
//
// La decodificacion es estricta (falla cerrado): magia, longitudes dentro del
// buffer, 52 escalares, punto de la curva valido (deserialize con chequeo) y
// sin bytes sobrantes.

const MAGIC: &[u8; 4] = b"PPE1";
/// Tope de una entrada codificada (la proof JSON ocupa ~2 KB).
pub const MAX_ENCODED_LEN: usize = 64 * 1024;

fn canonical<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    value
        .serialize(&mut buf)
        .map_err(|e| format!("serializacion canonica: {}", e))?;
    Ok(buf)
}

fn push_section(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// Bytes canonicos de una clave conjunta (los que el wasm exporta como clave
/// objetivo del pool y el prover nativo recibe).
pub fn encode_key(key: &PublicKey) -> Result<Vec<u8>, String> {
    canonical(key)
}

/// Inversa de `encode_key`: exige consumir todos los bytes y un punto valido.
pub fn decode_key(bytes: &[u8]) -> Result<PublicKey, String> {
    let mut reader = bytes;
    let key = PublicKey::deserialize(&mut reader).map_err(|e| format!("clave invalida: {}", e))?;
    if !reader.is_empty() {
        return Err("clave con bytes sobrantes".into());
    }
    Ok(key)
}

pub fn encode_entry(entry: &PrecomputeEntry) -> Result<Vec<u8>, String> {
    if entry.r_prime.len() != DECK_SIZE {
        return Err(format!("r_prime con {} escalares (se esperan {})", entry.r_prime.len(), DECK_SIZE));
    }
    let key = canonical(&entry.joint_pk)?;
    let r_prime = canonical(&entry.r_prime)?;
    let proof = serde_json::to_vec(&entry.proof).map_err(|e| format!("proof json: {}", e))?;
    let mut out = Vec::with_capacity(4 + 32 + 12 + key.len() + r_prime.len() + proof.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&entry.link_v);
    push_section(&mut out, &key);
    push_section(&mut out, &r_prime);
    push_section(&mut out, &proof);
    if out.len() > MAX_ENCODED_LEN {
        return Err("entrada codificada demasiado grande".into());
    }
    Ok(out)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("entrada truncada".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn section(&mut self) -> Result<&'a [u8], String> {
        let len = u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as usize;
        self.take(len)
    }
}

pub fn decode_entry(bytes: &[u8]) -> Result<PrecomputeEntry, String> {
    if bytes.len() > MAX_ENCODED_LEN {
        return Err("entrada codificada demasiado grande".into());
    }
    let mut cur = Cursor(bytes);
    if cur.take(4)? != MAGIC {
        return Err("formato de entrada desconocido".into());
    }
    let link_v: [u8; 32] = cur.take(32)?.try_into().expect("32 bytes");
    let joint_pk = decode_key(cur.section()?)?;

    let mut r_reader = cur.section()?;
    let r_prime = Vec::<Scalar>::deserialize(&mut r_reader)
        .map_err(|e| format!("r_prime invalido: {}", e))?;
    if !r_reader.is_empty() {
        return Err("r_prime con bytes sobrantes".into());
    }
    if r_prime.len() != DECK_SIZE {
        return Err(format!("r_prime con {} escalares (se esperan {})", r_prime.len(), DECK_SIZE));
    }

    let proof: LegoProofJson =
        serde_json::from_slice(cur.section()?).map_err(|e| format!("proof invalida: {}", e))?;
    if !cur.0.is_empty() {
        return Err("entrada con bytes sobrantes".into());
    }
    Ok(PrecomputeEntry { r_prime, link_v, proof, joint_pk })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::UniformRand;

    fn fake_proof() -> LegoProofJson {
        let g1 = serde_json::json!({ "x": "1", "y": "2" });
        serde_json::from_value(serde_json::json!({
            "a": g1, "c": g1, "d": g1, "link_d": g1, "link_pi": g1,
            "b": { "x_c1": "1", "x_c0": "2", "y_c1": "3", "y_c0": "4" },
            "pubs": ["5", "6", "7", "8"],
        }))
        .unwrap()
    }

    fn fake_entry() -> PrecomputeEntry {
        let mut rng = StdRng::seed_from_u64(7);
        let g = texas_holdem::generator();
        PrecomputeEntry {
            r_prime: (0..DECK_SIZE).map(|_| Scalar::rand(&mut rng)).collect(),
            link_v: rng.gen(),
            proof: fake_proof(),
            joint_pk: g.mul(Scalar::rand(&mut rng)).into_affine(),
        }
    }

    #[test]
    fn entry_round_trip() {
        let entry = fake_entry();
        let bytes = encode_entry(&entry).unwrap();
        let back = decode_entry(&bytes).unwrap();
        assert_eq!(back.r_prime, entry.r_prime);
        assert_eq!(back.link_v, entry.link_v);
        assert_eq!(back.proof, entry.proof);
        assert_eq!(back.joint_pk, entry.joint_pk);
        assert_eq!(encode_entry(&back).unwrap(), bytes);
    }

    #[test]
    fn key_round_trip() {
        let key = fake_entry().joint_pk;
        assert_eq!(decode_key(&encode_key(&key).unwrap()).unwrap(), key);
    }

    #[test]
    fn decode_fails_closed() {
        let bytes = encode_entry(&fake_entry()).unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(decode_entry(&bad_magic).is_err());

        assert!(decode_entry(&bytes[..bytes.len() - 1]).is_err());

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_entry(&trailing).is_err());

        let mut short = fake_entry();
        short.r_prime.pop();
        assert!(encode_entry(&short).is_err());

        // Clave que no es un punto de la curva: x = y = 1 cambiando bytes de la
        // seccion de la clave (justo tras magia + link_v + longitud).
        let mut bad_key = bytes.clone();
        for b in &mut bad_key[40..72] {
            *b = 0xff;
        }
        assert!(decode_entry(&bad_key).is_err());

        let mut bad_key_bytes = encode_key(&fake_entry().joint_pk).unwrap();
        bad_key_bytes.push(0);
        assert!(decode_key(&bad_key_bytes).is_err());
    }
}
