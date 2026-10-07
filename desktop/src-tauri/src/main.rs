// Spike de escritorio (Tauri v2): prover NATIVO del pool de precompute ZK.
//
// Papel unico: el frontend web (pagina REMOTA dentro del webview) llama a
// `precompute_fill(target_pk, n)` y recibe `n` entradas del pool ya codificadas
// (`encode_entry`), generadas con el prover nativo en vez del wasm. La app NO
// decide nada del juego: ni cartas, ni fondos, ni reglas (la fuente de verdad
// sigue siendo contrato = fondos, protocolo = cartas, UI = orquestacion).
//
// Las entradas contienen SECRETOS (`r_prime`, `link_v`): aqui nunca se imprimen
// ni se registran; solo tiempos y contadores.

// Spike: SIN `windows_subsystem = "windows"` a proposito, para que el stdout con
// los tiempos `[native][timing]` se vea (y se pueda redirigir) tambien en release.

mod origins;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use poker_precompute::{
    build_precompute_entry_parts, card_parameters, decode_key, encode_entry, PrecomputeArtifacts,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use texas_holdem::CardParameters;

/// Directorio por defecto de los artefactos (los mismos que sirve el lab web).
const DIR_ARTEFACTOS_POR_DEFECTO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../.wt-secure-frontend/public/precompute/vhyb"
);

/// Cota de entradas por llamada (el pool del frontend es pequeno).
const N_MAX: u32 = 5;

/// Cargado una sola vez, de forma perezosa, en la primera llamada.
struct Cargado {
    pp: CardParameters,
    artefactos: PrecomputeArtifacts,
    pool: ThreadPool,
    hilos: usize,
}

#[derive(Default)]
struct Interno {
    cargado: Mutex<Option<Arc<Cargado>>>,
    /// true mientras hay un relleno en vuelo (solo uno a la vez).
    ocupado: AtomicBool,
}

/// Estado gestionado por Tauri; el `Arc` permite moverlo al hilo bloqueante.
#[derive(Default)]
struct Estado(Arc<Interno>);

/// Libera `ocupado` al salir, tambien si el hilo hace panic.
struct GuardiaOcupado(Arc<Interno>);
impl Drop for GuardiaOcupado {
    fn drop(&mut self) {
        self.0.ocupado.store(false, Ordering::SeqCst);
    }
}

fn leer(dir: &Path, nombre: &str) -> Result<Vec<u8>, String> {
    let ruta = dir.join(nombre);
    std::fs::read(&ruta).map_err(|e| format!("no se pudo leer {}: {}", ruta.display(), e))
}

fn cargar() -> Result<Cargado, String> {
    let t0 = Instant::now();
    let dir = PathBuf::from(
        std::env::var("DPC_PRECOMPUTE_DIR").unwrap_or_else(|_| DIR_ARTEFACTOS_POR_DEFECTO.to_string()),
    );
    let artefactos = PrecomputeArtifacts {
        circom_wasm: leer(&dir, "precompute_circom.wasm")?,
        circom_r1cs: leer(&dir, "precompute_circom.r1cs")?,
        lego_pk: leer(&dir, "precompute_pk.bin")?,
        lego_r1cs: leer(&dir, "precompute_lego.r1cs")?,
        graph: leer(&dir, "precompute.graph")?,
    };
    let hilos = std::env::var("DPC_NATIVE_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&k| k > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|k| k.get()).unwrap_or(1));
    let pool = ThreadPoolBuilder::new()
        .num_threads(hilos)
        .thread_name(|i| format!("dpc-prove-{}", i))
        .stack_size(16 * 1024 * 1024)
        .build()
        .map_err(|e| format!("pool rayon: {}", e))?;
    let pp = card_parameters();
    println!(
        "[native][timing] artefactos cargados en {} ms (hilos={}, dir={})",
        t0.elapsed().as_millis(),
        hilos,
        dir.display()
    );
    Ok(Cargado { pp, artefactos, pool, hilos })
}

/// Devuelve los artefactos cargados, cargandolos si es la primera vez.
fn obtener(interno: &Interno) -> Result<Arc<Cargado>, String> {
    let mut g = interno.cargado.lock().map_err(|_| "estado envenenado".to_string())?;
    if let Some(c) = g.as_ref() {
        return Ok(c.clone());
    }
    let c = Arc::new(cargar()?);
    *g = Some(c.clone());
    Ok(c)
}

/// Genera `n` (1..=5) entradas del pool para la clave conjunta `target_pk`
/// (bytes de `encode_key`). Un solo relleno a la vez: si ya hay uno, `Err("busy")`.
/// Si una entrada falla, devuelve las ya hechas (si hay alguna) o el error.
#[tauri::command]
async fn precompute_fill(
    estado: tauri::State<'_, Estado>,
    target_pk: Vec<u8>,
    n: u32,
) -> Result<Vec<Vec<u8>>, String> {
    let n = n.clamp(1, N_MAX) as usize;
    let key = decode_key(&target_pk)?;

    let interno = estado.0.clone();
    if interno
        .ocupado
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err("busy".into());
    }
    // La guardia se mueve al hilo bloqueante y libera `ocupado` pase lo que pase.
    let guardia = GuardiaOcupado(interno.clone());

    tauri::async_runtime::spawn_blocking(move || {
        let _guardia = guardia;
        let c = obtener(&interno)?;
        // Todo el prove corre dentro del pool propio (rayon de arkworks lo hereda).
        c.pool.install(|| {
            let mut hechas: Vec<Vec<u8>> = Vec::with_capacity(n);
            for i in 1..=n {
                let t = Instant::now();
                let r = build_precompute_entry_parts(&c.pp, &key, &c.artefactos)
                    .and_then(|e| encode_entry(&e));
                match r {
                    Ok(bytes) => {
                        println!(
                            "[native][timing] precompute {}/{} {} ms (hilos={})",
                            i,
                            n,
                            t.elapsed().as_millis(),
                            c.hilos
                        );
                        hechas.push(bytes);
                    }
                    Err(e) => {
                        println!("[native][timing] precompute {}/{} fallo tras {} ms", i, n, t.elapsed().as_millis());
                        if hechas.is_empty() {
                            return Err(e);
                        }
                        break;
                    }
                }
            }
            Ok(hechas)
        })
    })
    .await
    .map_err(|e| format!("hilo de precompute: {}", e))?
}

/// Fase 2 / spike 2.0: comando trivial para comprobar QUE origen puede invocar
/// (la capability `engine` lo concede solo a `http://engine.localhost`).
#[tauri::command]
fn spike_ping() -> &'static str {
    println!("[spike] ipc: spike_ping invocado");
    "pong"
}

fn main() {
    let mut builder = tauri::Builder::default().manage(Estado::default());

    // DPC_SPIKE_ORIGINS=<dir con table/ y engine/>: mesa y nucleo por protocolos
    // propios (Fase 2, bloque 2.0). Sin la variable, el spike de la Fase 1 tal cual.
    let spike = std::env::var("DPC_SPIKE_ORIGINS").ok().map(PathBuf::from);
    if let Some(dir) = spike.clone() {
        let (table, engine) = (dir.join("table"), dir.join("engine"));
        builder = builder
            .register_uri_scheme_protocol("table", move |_ctx, req| origins::serve(&table, origins::Kind::Table, &req))
            .register_uri_scheme_protocol("engine", move |_ctx, req| origins::serve(&engine, origins::Kind::Engine, &req))
            .register_uri_scheme_protocol("prover", |_ctx, req| origins::prover(&req));
    }

    builder
        .invoke_handler(tauri::generate_handler![precompute_fill, spike_ping])
        .setup(move |app| {
            if spike.is_some() {
                use tauri::Manager;
                let w = app.get_webview_window("main").ok_or("sin ventana main")?;
                w.navigate(format!("{}/", origins::TABLE_ORIGIN).parse()?)?;
                println!("[spike] mesa en {}/", origins::TABLE_ORIGIN);
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error al ejecutar la app Tauri");
}
