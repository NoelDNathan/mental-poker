//! GATE prove/verify del residual de reshuffle (`card_cancellation_lego`): la
//! PK + R1CS sin wasmer serializadas por el lab producen una proof valida con
//! el `ProverCircuit` de este crate. Sin Fiat-Shamir (remask posicional).
//!
//! Mas lento (la PK del reshuffle son ~4.7 MB): marcado #[ignore], se corre con
//! `cargo test --release -- --ignored`.

use ark_bn254::Fr;

use lego_prover::{
    compute_link_d, link_v_from_seed, load_pk, load_r1cs, parse_witness, prove_with_link_v, verify,
    LegoProofJson, RESHUFFLE,
};

const LINK_V_SEED: u64 = 0x714B;

static PK_BYTES: &[u8] = include_bytes!("../artifacts/reshuffle_pk.bin");
static R1CS_BYTES: &[u8] = include_bytes!("../artifacts/reshuffle_r1cs.bin");
static WITNESS_JSON: &str = include_str!("../artifacts/reshuffle_witness.json");

#[test]
#[ignore]
fn reshuffle_prove_verify() {
    let r1cs = load_r1cs(R1CS_BYTES);
    assert_eq!(r1cs.num_public as usize, RESHUFFLE.num_public);
    let pk = load_pk(PK_BYTES);

    let wires = parse_witness(WITNESS_JSON);
    let num_public = r1cs.num_public as usize;
    let public_inputs: Vec<Fr> = wires[1..num_public].to_vec();
    assert_eq!(public_inputs.len(), 536);

    let committed = wires[num_public..num_public + 208].to_vec();
    let link_v = link_v_from_seed(LINK_V_SEED);
    let link_d = compute_link_d(&pk.vk.link_bases, &committed, link_v);

    use ark_std::rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::seed_from_u64(0xCA11CE);
    let proof = prove_with_link_v(&pk, &r1cs, wires, link_v, &mut rng);

    assert_eq!(
        proof.link_d, link_d,
        "el link_d de la proof de reshuffle != el calculado fuera del prover"
    );
    assert!(verify(&pk, &proof, &public_inputs), "la proof de reshuffle no verifica");

    // LegoProofJson sobre la proof de reshuffle.
    let pubs_dec: Vec<String> = public_inputs.iter().map(|f| f.to_string()).collect();
    let json = LegoProofJson::from_proof(&proof, &pubs_dec);
    assert_eq!(json.pubs.len(), 536);
    let round = LegoProofJson::from_json_str(&json.to_json_string());
    assert_eq!(round, json);
}
