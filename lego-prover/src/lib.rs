//! Prover LegoGroth16 (cp_link) aislado en **arkworks 0.4** para el cliente de
//! poker. El `wasm_client` vive en ark 0.5; este crate expone una API por
//! BYTES/STRINGS (decimales de campo, hex de puntos) para que ningun tipo
//! `ark_*` 0.4 cruce la frontera. Reusa el codigo ya probado del lab
//! (`zk-bench/native-provers/legogroth16-{poc,circuit,wasm}`).
//!
//! Capa 3.1: NUMS gens + `compute_link_d` + setup/prove del residual (shuffle),
//! con el gate de que el `link_d` reproduce el del lab. La derivacion
//! Fiat-Shamir keccak (3.2) y los circuitos precompute/reshuffle se anaden
//! despues; aqui esta la maquinaria comun.

use core::str::FromStr;

use ark_bn254::{Bn254, Fr, G1Affine};
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};

use legogroth16::{
    create_random_proof_incl_cp_link, generate_random_parameters_incl_cp_link,
    prepare_verifying_key, verify_proof_incl_cp_link, ProofWithLink, ProvingKeyWithLink,
};

pub mod circuit;
pub mod circuits;
pub mod client;
pub mod fs;
pub mod link;
pub mod proof_json;

pub use client::{prove_reshuffle, prove_shuffle, shuffle_challenges, ProveOutput, ShuffleChallenges};

pub use circuit::{CircuitR1cs, ProverCircuit, R1csConstraint};
pub use circuits::{LegoCircuit, PRECOMPUTE, RESHUFFLE, SHUFFLE};
pub use fs::{derive_alpha_beta, NUM_FS_PUBLICS};
pub use link::{compute_link_d, make_link_gens, COMMIT_WITNESS_COUNT};
pub use proof_json::{G1Json, G2Json, LegoProofJson};

type E = Bn254;

/// Parsea un witness en formato circom (`Vec<String>` decimal) a campo.
pub fn parse_witness(witness_json: &str) -> Vec<Fr> {
    let decimals: Vec<String> = serde_json::from_str(witness_json).expect("witness json");
    decimals
        .iter()
        .map(|s| Fr::from_str(s).expect("field element"))
        .collect()
}

/// Deserializa el R1CS aplanado (formato propio sin wasmer, `CircuitR1cs`).
pub fn load_r1cs(r1cs_bytes: &[u8]) -> CircuitR1cs {
    CircuitR1cs::deserialize_compressed(r1cs_bytes).expect("deser r1cs")
}

/// Deserializa una proving key con link (uncompressed, artefacto de confianza).
pub fn load_pk(pk_bytes: &[u8]) -> ProvingKeyWithLink<E> {
    ProvingKeyWithLink::<E>::deserialize_uncompressed_unchecked(pk_bytes).expect("deser pk")
}

/// Las `COMMIT_WITNESS_COUNT` senales comprometidas: las que enlazan ambas
/// proofs (r_prime_G || r_prime_H). Estan justo despues de los publics.
pub fn committed_witnesses(wires: &[Fr], num_public: usize) -> Vec<Fr> {
    wires[num_public..num_public + COMMIT_WITNESS_COUNT as usize].to_vec()
}

/// Blinding `link_v` reproducible a partir de una seed. El flujo Fiat-Shamir es
/// commit (link_d) -> challenges -> prove, asi que link_v se fija ANTES de
/// derivar challenges y debe ser estable entre pasadas. Igual que el lab.
pub fn link_v_from_seed(seed: u64) -> Fr {
    Fr::rand(&mut StdRng::seed_from_u64(seed))
}

/// Setup de la proving key con link (fuera del camino critico). `wires = None`:
/// solo se usa la estructura del R1CS.
pub fn setup_pk(r1cs: &CircuitR1cs, rng: &mut StdRng) -> ProvingKeyWithLink<E> {
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let circuit = ProverCircuit {
        r1cs: r1cs.clone(),
        wires: None,
    };
    generate_random_parameters_incl_cp_link::<E, _, _>(
        circuit,
        link_gens,
        COMMIT_WITNESS_COUNT,
        rng,
    )
    .expect("setup pk")
}

/// Genera una proof cp_link con un `link_v` dado (compartido entre las dos
/// proofs enlazadas). `v` es el blinding interno de Groth16 (aleatorio).
pub fn prove_with_link_v(
    pk: &ProvingKeyWithLink<E>,
    r1cs: &CircuitR1cs,
    wires: Vec<Fr>,
    link_v: Fr,
    rng: &mut StdRng,
) -> ProofWithLink<E> {
    let v = Fr::rand(rng);
    let circuit = ProverCircuit {
        r1cs: r1cs.clone(),
        wires: Some(wires),
    };
    create_random_proof_incl_cp_link(circuit, v, link_v, pk, rng).expect("prove cp_link")
}

/// Verifica una proof cp_link contra la vk de la PK y unos public inputs.
pub fn verify(
    pk: &ProvingKeyWithLink<E>,
    proof: &ProofWithLink<E>,
    public_inputs: &[Fr],
) -> bool {
    let pvk = prepare_verifying_key::<E>(&pk.vk.groth16_vk);
    verify_proof_incl_cp_link(&pvk, &pk.vk, proof, public_inputs).is_ok()
}

/// Serializa una proof cp_link a hex (comprimida). La frontera con el
/// `wasm_client` es por bytes; el formato JSON con pubs/link llega en 3.2.
pub fn proof_to_hex(proof: &ProofWithLink<E>) -> String {
    let mut out = Vec::new();
    proof.serialize_compressed(&mut out).expect("ser proof");
    hex::encode(out)
}

/// Punto G1 como par de decimales (`x`, `y`), el encoding que consume el
/// verifier Solidity y el que el lab usa en sus exports JSON.
pub fn g1_to_decimal(p: &G1Affine) -> (String, String) {
    use ark_ec::AffineRepr;
    let (x, y) = p.xy().expect("punto no es identidad");
    (x.to_string(), y.to_string())
}
