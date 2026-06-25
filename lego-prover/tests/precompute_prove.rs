//! GATE de la capa 3.4b paso 3 (pool de precompute): genera la proof de
//! PRECOMPUTE (`rerandomization_precompute_52_lego`) y exige que su `link_d`
//! coincida con el de la RESIDUAL del reshuffle bajo el MISMO `link_v_seed`.
//!
//! Ese enlace (`precompute.link_d == residual.link_d`) es el corazon del pool:
//! una precompute generada en background se puede combinar con la residual del
//! turno porque ambas comprometen los MISMOS 208 committed witnesses (r'_G||r'_H)
//! con el mismo link_v. Sin Fiat-Shamir en ninguna de las dos.
//!
//! La PK del precompute (~20 MB) NO se embebe (load-on-demand en produccion): el
//! test la lee del vendor de zk-bench. Lento (PK 20 MB): `#[ignore]`, se corre
//! con `cargo +stable-x86_64-pc-windows-msvc test -p lego-prover --release \
//!   --test precompute_prove -- --ignored --nocapture`.

use std::path::PathBuf;

use lego_prover::{prove_precompute, prove_reshuffle, verify_precompute_lego};

const LINK_V_SEED: [u8; 32] = [
    0x4b, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
];

fn vendor(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../zk-bench/public/vendor/legogroth16-lego-data")
        .join(file)
}

fn read_decimals(path: &PathBuf) -> Vec<String> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("witness.json debe ser un array de decimales")
}

#[test]
#[ignore]
fn precompute_links_to_residual() {
    // --- PRECOMPUTE: PK/R1CS load-on-demand desde el vendor + witness fixture ---
    let pk_path = vendor("precompute_pk.bin");
    let r1cs_path = vendor("precompute_r1cs.bin");
    let pk_bytes = std::fs::read(&pk_path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", pk_path.display()));
    let r1cs_bytes = std::fs::read(&r1cs_path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", r1cs_path.display()));

    let precompute_witness = read_decimals(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../zk-bench/public/artifacts/rerandomization_precompute_52_lego/witness.json"),
    );

    let pre = prove_precompute(&pk_bytes, &r1cs_bytes, &precompute_witness, &LINK_V_SEED);
    assert!(pre.verified, "la proof del precompute debe auto-verificar");
    // num_public del precompute = 5 (1 + G[2] + H[2]) -> 4 pubs en el JSON.
    assert_eq!(pre.proof.pubs.len(), 4, "publics del precompute (G,H)");

    // --- RESIDUAL del reshuffle con el MISMO seed (PK embebida) ---
    let reshuffle_witness = read_decimals(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/reshuffle_witness.json"),
    );
    let res = prove_reshuffle(&reshuffle_witness, &LINK_V_SEED);
    assert!(res.verified, "la proof del reshuffle debe auto-verificar");

    // --- EL ENLACE DEL POOL: mismo link_d ---
    // link_d = MSM(NUMS, committed || link_v) depende SOLO de los committed
    // witnesses + link_v -> identico en ambas. (link_pi NO: liga el `d` de cada
    // circuito, que difiere; por eso no se compara.)
    assert_eq!(
        pre.proof.link_d, res.proof.link_d,
        "precompute y residual deben compartir link_d bajo el mismo link_v_seed"
    );

    // --- Verificacion P2P del precompute (load-on-demand) + tamper ---
    assert!(
        verify_precompute_lego(&pre.proof, &pk_bytes),
        "verify_precompute_lego debe aceptar la proof valida"
    );
    let mut bad = pre.proof.clone();
    bad.pubs[0] = "123".to_string();
    assert!(
        !verify_precompute_lego(&bad, &pk_bytes),
        "un precompute manipulado debe rechazarse"
    );
}

/// #1: cada proof de Groth16 usa randomness (r, s) FRESCA e independiente. Dos
/// proofs del MISMO witness con el MISMO `link_v` deben:
///   (a) compartir `link_d` (el enlace cp_link depende solo de committed||link_v,
///       no de r,s) -> el pool sigue funcionando;
///   (b) NO ser identicas byte-a-byte -> ya no se deriva r,s de una seed fija.
/// Usa la PK del reshuffle (embebida, ~4.7 MB): no necesita el vendor de 20 MB.
#[test]
fn fresh_groth16_randomness_per_proof() {
    let reshuffle_witness = read_decimals(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("artifacts/reshuffle_witness.json"),
    );
    let a = prove_reshuffle(&reshuffle_witness, &LINK_V_SEED);
    let b = prove_reshuffle(&reshuffle_witness, &LINK_V_SEED);
    assert!(a.verified && b.verified, "ambas proofs deben auto-verificar");
    assert_eq!(
        a.proof.link_d, b.proof.link_d,
        "mismo link_v => mismo link_d (el enlace cp_link se preserva)"
    );
    assert_ne!(
        a.proof, b.proof,
        "cada proof debe usar randomness fresca (r,s) -> no identicas"
    );
}
