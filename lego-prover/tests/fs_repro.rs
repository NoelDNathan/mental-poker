//! GATE de la capa 3.2: la derivacion Fiat-Shamir keccak (alpha/beta) de este
//! crate debe coincidir con la del verifier Solidity / el script del lab
//! (`zk-bench/scripts/derive-lego-fs-challenges.mjs`).
//!
//! El witness del lab (`shuffle_witness.json`) ya fue regenerado con los
//! alpha/beta reales: estan en `wires[421]` y `wires[422]` (los dos ultimos
//! publics). Si nuestra derivacion los reproduce desde `link_d` + los 420
//! publics, el encoding keccak es identico al on-chain.
//!
//! Estuvo `#[ignore]` desde #5 hasta 2026-09-18: el transcript FS de Rust lleva
//! SEPARACION DE DOMINIO (`domain_sep`, ver `fs::derive_alpha_beta`) y el
//! fixture era anterior. `derive-lego-fs-challenges.mjs` y
//! `VerifyShufflingLego.sol::deriveChallenges` ya la llevan, y
//! `shuffle_witness.json` es ahora el witness del lab regenerado con el contexto
//! de abajo (`fs_domain_separator(31337, b"game-fixture", 0, 0)` ==
//! `fs_domain_sep.json`). Si este test se pone rojo, el encoding Rust y el
//! on-chain han divergido: es el unico gate que lo vigila.

use ark_bn254::Fr;
use core::str::FromStr;

use lego_prover::{
    committed_witnesses, compute_link_d, derive_alpha_beta, fs_domain_separator, link_v_from_seed,
    load_r1cs, make_link_gens, parse_witness, COMMIT_WITNESS_COUNT, NUM_FS_PUBLICS,
};

const LINK_V_SEED: u64 = 0x714B;

static R1CS_BYTES: &[u8] = include_bytes!("../artifacts/shuffle_r1cs.bin");
static WITNESS_JSON: &str = include_str!("../artifacts/shuffle_witness.json");

#[test]
fn alpha_beta_reproduces_onchain_encoding() {
    let r1cs = load_r1cs(R1CS_BYTES);
    let num_public = r1cs.num_public as usize;
    let wires = parse_witness(WITNESS_JSON);

    // Los 420 publics que preceden a los challenges: wires[1..421].
    let pubs: Vec<Fr> = wires[1..1 + NUM_FS_PUBLICS].to_vec();
    assert_eq!(pubs.len(), NUM_FS_PUBLICS);

    // alpha/beta tal como los dejo el witness regenerado por el lab.
    let alpha_witness = wires[1 + NUM_FS_PUBLICS];
    let beta_witness = wires[2 + NUM_FS_PUBLICS];

    // num_public = 1 + 422 publics (420 + alpha + beta) = 423.
    assert_eq!(num_public, 3 + NUM_FS_PUBLICS, "num_public esperado 423");

    // link_d desde los NUMS + committed witnesses + link_v (ya probado en
    // link_d_repro que reproduce el del lab).
    let committed = committed_witnesses(&wires, num_public);
    assert_eq!(committed.len(), COMMIT_WITNESS_COUNT as usize);
    let link_gens = make_link_gens(COMMIT_WITNESS_COUNT + 1);
    let link_v = link_v_from_seed(LINK_V_SEED);
    let link_d = compute_link_d(&link_gens.pedersen_gens, &committed, link_v);

    // Contexto con el que se debera regenerar el fixture al portar #5 a Solidity.
    let domain_sep = fs_domain_separator(31337, b"game-fixture", 0, 0);
    let (alpha, beta) = derive_alpha_beta(&domain_sep, &link_d, &pubs);

    assert_eq!(
        alpha, alpha_witness,
        "alpha derivado != alpha del witness (encoding keccak distinto al on-chain)"
    );
    assert_eq!(
        beta, beta_witness,
        "beta derivado != beta del witness (encoding keccak distinto al on-chain)"
    );

    // Sanity: la derivacion no es trivialmente cero.
    assert_ne!(alpha, Fr::from_str("0").unwrap());
    assert_ne!(beta, Fr::from_str("0").unwrap());
}
