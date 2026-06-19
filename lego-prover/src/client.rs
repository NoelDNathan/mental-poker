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
