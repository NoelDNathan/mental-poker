//! Medicion NATIVA del prove de las 3 proofs LegoGroth16 de una mano de poker,
//! con los artefactos de PRODUCCION (Fase 0 del spike de escritorio/Tauri).
//!
//! Casos (1 warm-up que no cuenta + `LEGO_BENCH_RUNS` corridas, 5 por defecto;
//! todas deben auto-verificar):
//!   1. precompute vhyb  -> `prove_precompute` con la PK/r1cs de produccion del
//!      frontend (`.wt-secure-frontend/public/precompute/vhyb/`) y el witness del
//!      circuito shared_sound_hybrid de zk-bench (su r1cs circom es byte-identico
//!      al de vhyb, sha256 ac84c75a...).
//!   2. residual shuffle   -> `prove_shuffle` (PK embebida en el crate).
//!   3. residual reshuffle -> `prove_reshuffle` (PK embebida en el crate).
//! NO se mide la generacion de witness (en el navegador es por grafo, ~150 ms).
//!
//! Se compara bajo dos feature-sets:
//!   - `parallel`       -> solo ark-* paralelo (lo que va hoy a wasm).
//!   - `parallel-full`  -> ademas legogroth16/parallel (solo nativo, arrastra wasmer).
//!
//! Variables de entorno opcionales:
//!   LEGO_BENCH_RUNS         numero de corridas medidas (defecto 5)
//!   LEGO_BENCH_VHYB_DIR     carpeta con precompute_pk.bin y precompute_lego.r1cs
//!   LEGO_BENCH_VHYB_WITNESS ruta del witness.json del precompute
//!
//! Correr desde `.wt-secure-wasm/lego-prover`:
//!   cargo test --release --features parallel \
//!     --test bench_prove_native -- --ignored --nocapture
//!   cargo test --release --features parallel-full \
//!     --test bench_prove_native -- --ignored --nocapture

use std::path::PathBuf;
use std::time::Instant;

use lego_prover::{prove_precompute, prove_reshuffle, prove_shuffle, ProveOutput};

// Misma constante que tests/bench_precompute_native.rs.
const LINK_V_SEED: [u8; 32] = [
    0x4b, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
];

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_decimals(path: &PathBuf) -> Vec<String> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("no se pudo leer {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("el witness debe ser un array JSON de decimales")
}

/// Warm-up + `runs` corridas; devuelve los tiempos en ms y cuenta cuantas
/// auto-verificaron (se asserta al final de cada caso para no perder la medida).
fn bench(name: &str, runs: usize, mut f: impl FnMut() -> ProveOutput) -> usize {
    let warm = f();
    println!("[bench-native] {name}: warm-up verified={}", warm.verified);
    let mut fails = usize::from(!warm.verified);
    let mut times: Vec<u128> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t = Instant::now();
        let out = f();
        times.push(t.elapsed().as_millis());
        if !out.verified {
            fails += 1;
        }
    }
    let mut sorted = times.clone();
    sorted.sort_unstable();
    let median = sorted[sorted.len() / 2];
    let min = sorted[0];
    let max = *sorted.last().unwrap();
    println!(
        "[bench-native] {name}: mediana={median} ms | min={min} ms | max={max} ms | runs={times:?}"
    );
    fails
}

#[test]
#[ignore]
fn bench_prove_native() {
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    println!("[bench-native] hilos (available_parallelism) = {threads}");
    println!(
        "[bench-native] parallel-full = {}",
        cfg!(feature = "parallel-full")
    );
    let runs: usize = std::env::var("LEGO_BENCH_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    let mut total_fails = 0usize;

    // 1. precompute vhyb (artefactos de produccion).
    let vhyb_dir = std::env::var("LEGO_BENCH_VHYB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest().join("../../.wt-secure-frontend/public/precompute/vhyb"));
    let vhyb_witness = std::env::var("LEGO_BENCH_VHYB_WITNESS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            manifest().join(
                "../../zk-bench/public/artifacts/rerandomization_precompute_52_lego_shared_sound_hybrid/witness.json",
            )
        });
    let pk = std::fs::read(vhyb_dir.join("precompute_pk.bin")).expect("precompute_pk.bin");
    let r1cs = std::fs::read(vhyb_dir.join("precompute_lego.r1cs")).expect("precompute_lego.r1cs");
    let w = read_decimals(&vhyb_witness);
    println!(
        "[bench-native] precompute vhyb: pk={} B r1cs={} B witness={} wires",
        pk.len(),
        r1cs.len(),
        w.len()
    );
    total_fails += bench("precompute vhyb", runs, || {
        prove_precompute(&pk, &r1cs, &w, &LINK_V_SEED)
    });

    // 2. residual shuffle (PK embebida).
    let w = read_decimals(&manifest().join("artifacts/shuffle_witness.json"));
    total_fails += bench("residual shuffle", runs, || prove_shuffle(&w, &LINK_V_SEED));

    // 3. residual reshuffle (PK embebida).
    let w = read_decimals(&manifest().join("artifacts/reshuffle_witness.json"));
    total_fails += bench("residual reshuffle", runs, || {
        prove_reshuffle(&w, &LINK_V_SEED)
    });

    assert_eq!(total_fails, 0, "{total_fails} proof(s) no auto-verificaron");
}
