//! A/B NATIVO del techo de paralelismo (no es un gate, es una medida).
//!
//! Cronometra `prove_precompute` con los MISMOS fixtures que la app. La gracia
//! es compararlo bajo dos feature-sets:
//!   - `--features parallel`       -> solo ark-* paralelo (lo que va hoy a wasm);
//!                                    los cfg_iter! de legogroth16 quedan EN SERIE.
//!   - `--features parallel-full`  -> ademas legogroth16/parallel: cfg_iter! del
//!                                    prover + construccion a/b/c del QAP paralelos.
//!
//! Si parallel-full baja el prove de forma notable, el "premio" de parchear
//! legogroth16 (parallel sin std/wasmer) para wasm es real. Si no, el ~3x es el
//! suelo y no merece la pena el vendoring.
//!
//! Correr (toolchain con C toolchain para wasmer en parallel-full):
//!   cargo test -p lego-prover --release --features parallel \
//!     --test bench_precompute_native -- --ignored --nocapture
//!   cargo test -p lego-prover --release --features parallel-full \
//!     --test bench_precompute_native -- --ignored --nocapture

use std::path::PathBuf;
use std::time::Instant;

use lego_prover::{load_pk, prove_precompute};

const LINK_V_SEED: [u8; 32] = [
    0x4b, 0x71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1,
];
const RUNS: usize = 3;

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
fn bench_precompute_native() {
    let pk_bytes = std::fs::read(vendor("precompute_pk.bin")).expect("pk");
    let r1cs_bytes = std::fs::read(vendor("precompute_r1cs.bin")).expect("r1cs");
    let witness = read_decimals(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../zk-bench/public/artifacts/rerandomization_precompute_52_lego/witness.json"),
    );

    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0);
    println!("[bench-native] available_parallelism = {threads}");

    // Warm-up (no cuenta): primera vez paga TLB/caches/alloc del PK de 20 MB.
    let warm = prove_precompute(&pk_bytes, &r1cs_bytes, &witness, &LINK_V_SEED);
    assert!(warm.verified, "la proof debe auto-verificar");

    let mut times = Vec::with_capacity(RUNS);
    for i in 0..RUNS {
        let t = Instant::now();
        let out = prove_precompute(&pk_bytes, &r1cs_bytes, &witness, &LINK_V_SEED);
        let ms = t.elapsed().as_millis();
        assert!(out.verified, "la proof debe auto-verificar");
        times.push(ms);
        println!("[bench-native] run {}/{}: {} ms", i + 1, RUNS, ms);
    }
    let avg = times.iter().sum::<u128>() / times.len() as u128;
    let min = times.iter().min().copied().unwrap_or(0);
    println!("[bench-native] prove avg={avg} ms | min={min} ms | runs={times:?}");
}

/// #4 (antes/despues de la cache): mide el coste de DESERIALIZAR la PK lego, que
/// el camino antiguo pagaba en CADA `prove_precompute`/`verify` (N veces por pool
/// de N) y la cache ahora paga UNA sola vez por version. El ahorro al generar un
/// pool de N = (N-1) x este coste.
#[test]
#[ignore]
fn bench_pk_parse_cost() {
    let pk_bytes = std::fs::read(vendor("precompute_pk.bin")).expect("pk");
    println!("[bench-parse] PK = {} bytes", pk_bytes.len());
    let _ = load_pk(&pk_bytes); // warmup (TLB/alloc)
    let mut times = Vec::new();
    for i in 0..5 {
        let t = Instant::now();
        let pk = load_pk(&pk_bytes);
        let ms = t.elapsed().as_millis();
        std::hint::black_box(&pk);
        times.push(ms);
        println!("[bench-parse] load_pk {}/5: {} ms", i + 1, ms);
    }
    let avg = times.iter().sum::<u128>() / times.len() as u128;
    println!(
        "[bench-parse] load_pk avg = {avg} ms (coste que la cache elimina en cada \
         prove/verify tras el 1o; pool de N ahorra (N-1)x = {} ms para N=2)",
        avg
    );
}
