//! Entrada REAL del pool probada en nativo con los artefactos de produccion
//! (vhyb del frontend), codificada y decodificada: lo que hara el prover de
//! escritorio antes de entregarla al wasm. Lento (prove de ~1,5 s): #[ignore].
//!
//!   cargo test --release -p poker-precompute --test native_entry -- --ignored --nocapture
//!
//! Directorio de artefactos sobreescribible con DPC_PRECOMPUTE_DIR.

use std::path::PathBuf;
use std::time::Instant;

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::UniformRand;
use poker_precompute::{
    build_precompute_entry_parts, card_parameters, decode_entry, encode_entry, PrecomputeArtifacts,
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use texas_holdem::Scalar;

fn artifacts() -> PrecomputeArtifacts {
    let dir = std::env::var_os("DPC_PRECOMPUTE_DIR").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.wt-secure-frontend/public/precompute/vhyb")
    });
    let read = |f: &str| std::fs::read(dir.join(f)).unwrap_or_else(|e| panic!("{f}: {e}"));
    PrecomputeArtifacts {
        circom_wasm: read("precompute_circom.wasm"),
        circom_r1cs: read("precompute_circom.r1cs"),
        lego_pk: read("precompute_pk.bin"),
        lego_r1cs: read("precompute_lego.r1cs"),
        graph: read("precompute.graph"),
    }
}

#[test]
#[ignore]
fn native_entry_round_trip() {
    let artifacts = artifacts();
    let pp = card_parameters();
    let mut rng = StdRng::seed_from_u64(0xD0C);
    let joint_pk = texas_holdem::generator().mul(Scalar::rand(&mut rng)).into_affine();

    for i in 0..2 {
        let t = Instant::now();
        let entry = build_precompute_entry_parts(&pp, &joint_pk, &artifacts).expect("prove nativo");
        println!("[native-entry] {}: {} ms", i + 1, t.elapsed().as_millis());

        let bytes = encode_entry(&entry).unwrap();
        println!("[native-entry] codificada: {} B", bytes.len());
        let back = decode_entry(&bytes).unwrap();
        assert_eq!(back.joint_pk, joint_pk);
        assert_eq!(back.r_prime, entry.r_prime);
        assert_eq!(back.link_v, entry.link_v);
        assert_eq!(back.proof, entry.proof);
    }
}
