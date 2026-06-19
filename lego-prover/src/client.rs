//! API cliente: prove + verify de los circuitos lego desde el FULL witness en
//! decimales (lo que produce el `ark-circom` del wasm_client). PK + R1CS
//! embebidos. Es la frontera que consume zk-reshuffle (ark 0.5): entra un
//! `&[String]`, sale un `LegoProofJson`. Ningun tipo ark 0.4 cruza la firma.

use core::str::FromStr;

use ark_bn254::{Bn254, Fr};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use ark_ec::AffineRepr;

use crate::{
    compute_link_d, derive_alpha_beta, link_v_from_seed, load_pk, load_r1cs, make_link_gens,
    prove_with_link_v, verify, CircuitR1cs, G1Json, LegoProofJson, COMMIT_WITNESS_COUNT,
};
use legogroth16::ProvingKeyWithLink;

// Shuffle (residual con FS). PK ~677 KB, R1CS ~174 KB: se embeben.
static SHUFFLE_PK: &[u8] = include_bytes!("../artifacts/shuffle_pk.bin");
static SHUFFLE_R1CS: &[u8] = include_bytes!("../artifacts/shuffle_r1cs.bin");
// Reshuffle/cancellation (residual sin FS). PK ~4.7 MB, R1CS ~2.1 MB.
static RESHUFFLE_PK: &[u8] = include_bytes!("../artifacts/reshuffle_pk.bin");
static RESHUFFLE_R1CS: &[u8] = include_bytes!("../artifacts/reshuffle_r1cs.bin");

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
    r1cs: &CircuitR1cs,
    full_witness: &[String],
    link_v_seed: u64,
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

    let link_v = link_v_from_seed(link_v_seed);
    // RNG del blinding interno de Groth16 (v, s): independiente del link_v.
    let mut rng = StdRng::seed_from_u64(link_v_seed ^ 0x5EED_1E60);
    let proof = prove_with_link_v(pk, r1cs, wires, link_v, &mut rng);

    let verified = verify(pk, &proof, &public_inputs);
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
    link_v_seed: u64,
) -> ShuffleChallenges {
    let cw = parse_decimals(committed);
    let pubs_fr = parse_decimals(pubs);
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let link_v = link_v_from_seed(link_v_seed);
    let link_d_pt = compute_link_d(&link_gens.pedersen_gens, &cw, link_v);
    let (alpha, beta) = derive_alpha_beta(&link_d_pt, &pubs_fr);
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
/// challenges alpha/beta consistentes con `link_v_seed`).
pub fn prove_shuffle(full_witness: &[String], link_v_seed: u64) -> ProveOutput {
    let r1cs = load_r1cs(SHUFFLE_R1CS);
    let pk = load_pk(SHUFFLE_PK);
    prove_residual(&pk, &r1cs, full_witness, link_v_seed)
}

/// Prueba el residual del reshuffle/cancellation desde su FULL witness (sin FS).
pub fn prove_reshuffle(full_witness: &[String], link_v_seed: u64) -> ProveOutput {
    let r1cs = load_r1cs(RESHUFFLE_R1CS);
    let pk = load_pk(RESHUFFLE_PK);
    prove_residual(&pk, &r1cs, full_witness, link_v_seed)
}

/// Prueba el PRECOMPUTE (`rerandomization_precompute_52_lego`) desde su FULL
/// witness. A diferencia del shuffle/reshuffle, su PK (~20 MB) NO se embebe: se
/// pasa por bytes (load-on-demand en el navegador, capa 3.4b paso 3 — pool de
/// background). Comparte con el residual los MISMOS 208 committed witnesses
/// (r'_G||r'_H), asi que con el MISMO `link_v_seed` produce el MISMO `link_d`:
/// ese es el enlace cp_link entre la precompute de background y la residual del
/// turno. Sin Fiat-Shamir (num_public = 5: G[2], H[2]).
pub fn prove_precompute(
    pk_bytes: &[u8],
    r1cs_bytes: &[u8],
    full_witness: &[String],
    link_v_seed: u64,
) -> ProveOutput {
    let r1cs = load_r1cs(r1cs_bytes);
    let pk = load_pk(pk_bytes);
    prove_residual(&pk, &r1cs, full_witness, link_v_seed)
}

/// Verificacion P2P del precompute desde el bundle: solo cp_link contra sus
/// publics (G, H), sin Fiat-Shamir. La PK (~20 MB) se pasa por bytes
/// (load-on-demand). El enlace con la residual lo comprueba el caller exigiendo
/// `precompute.link_d == residual.link_d`.
pub fn verify_precompute_lego(proof: &LegoProofJson, pk_bytes: &[u8]) -> bool {
    let pk = load_pk(pk_bytes);
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) => p,
        None => return false,
    };
    verify(&pk, &ark_proof, &public_inputs)
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
pub fn verify_shuffle_lego(proof: &LegoProofJson) -> bool {
    let pk = load_pk(SHUFFLE_PK);
    verify_shuffle_lego_with_pk(&pk, proof)
}

fn verify_shuffle_lego_with_pk(pk: &ProvingKeyWithLink<Bn254>, proof: &LegoProofJson) -> bool {
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) if p.len() == SHUFFLE_NUM_PUBS => p,
        _ => return false,
    };
    if !verify(pk, &ark_proof, &public_inputs) {
        return false;
    }
    // Re-derivacion Fiat-Shamir desde el link_d de la propia proof.
    let fs_pubs = &public_inputs[..crate::NUM_FS_PUBLICS];
    let (alpha, beta) = derive_alpha_beta(&ark_proof.link_d, fs_pubs);
    alpha == public_inputs[crate::NUM_FS_PUBLICS] && beta == public_inputs[crate::NUM_FS_PUBLICS + 1]
}

/// Verificacion P2P del residual del RESHUFFLE/cancellation desde el bundle.
/// Sin Fiat-Shamir (remask posicional): solo la proof cp_link contra sus publics.
pub fn verify_reshuffle_lego(proof: &LegoProofJson) -> bool {
    let pk = load_pk(RESHUFFLE_PK);
    let ark_proof = match proof.to_proof() {
        Some(p) => p,
        None => return false,
    };
    let public_inputs = match proof.public_inputs() {
        Some(p) => p,
        None => return false,
    };
    verify(&pk, &ark_proof, &public_inputs)
}
