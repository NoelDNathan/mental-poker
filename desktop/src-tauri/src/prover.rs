// Fase 2 / bloque 2.3: canal del NUCLEO al prover nativo del pool de precompute.
//
// El IPC de Tauri no sirve de frontera: cualquier protocolo propio cuenta
// como origen "local" y la mesa recibiria los mismos comandos que el nucleo
// (ver PLAN-FASE-2.md, "Resultado del spike 2.0"). Por eso el prover es un
// protocolo (`prover`, http://prover.localhost en WebView2) que solo atiende
// peticiones con `Origin: http://engine.localhost` exacto: el navegador pone
// esa cabecera y el JS de la mesa no puede falsificarla. Una peticion de otro
// origen se rechaza ANTES de hacer ningun trabajo, sin cabeceras CORS (no
// puede ni leer la respuesta).
//
// Rutas (todas POST):
//   /ping                      -> "pong"
//   /precompute?n=K, cuerpo = clave conjunta (bytes de `encode_key`)
//                              -> 200, K entradas enmarcadas: [u32 LE longitud][bytes]...
//                              -> 409 si ya hay un relleno en vuelo
//
// Las entradas llevan SECRETOS (`r_prime`, `link_v`): aqui nunca se imprimen
// ni se registran; solo tiempos y contadores.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use poker_precompute::{build_precompute_entry_parts, card_parameters, decode_key, encode_entry, PrecomputeArtifacts};
use rayon::{ThreadPool, ThreadPoolBuilder};
use tauri::http::{header, Request, Response, StatusCode};
use tauri::UriSchemeResponder;
use texas_holdem::CardParameters;

use crate::serve::common::ENGINE_ORIGIN;

/// Directorio de los artefactos: `DPC_PRECOMPUTE_DIR`, si no el de la carpeta de app
/// (`set_artifacts_dir`), si no los mismos que sirve el lab web.
static DIR_ARTEFACTOS: OnceLock<PathBuf> = OnceLock::new();

/// Fija el directorio de artefactos de la app (una vez, al arrancar).
pub fn set_artifacts_dir(dir: PathBuf) {
    let _ = DIR_ARTEFACTOS.set(dir);
}

const DIR_ARTEFACTOS_POR_DEFECTO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../frontend-production/public/precompute/vhyb"
);

/// Cota de entradas por peticion (el pool del nucleo es pequeno).
pub const N_MAX: u32 = 5;

/// Cota del cuerpo: la clave conjunta codificada son unas decenas de bytes.
const MAX_BODY: usize = 4096;

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

fn interno() -> Arc<Interno> {
    static I: OnceLock<Arc<Interno>> = OnceLock::new();
    I.get_or_init(|| Arc::new(Interno::default())).clone()
}

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
    let dir = std::env::var("DPC_PRECOMPUTE_DIR")
        .map(PathBuf::from)
        .ok()
        .or_else(|| DIR_ARTEFACTOS.get().cloned())
        .unwrap_or_else(|| PathBuf::from(DIR_ARTEFACTOS_POR_DEFECTO));
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
    println!("[native][timing] artefactos cargados en {} ms (hilos={}, dir={})", t0.elapsed().as_millis(), hilos, dir.display());
    Ok(Cargado { pp: card_parameters(), artefactos, pool, hilos })
}

fn obtener(i: &Interno) -> Result<Arc<Cargado>, String> {
    let mut g = i.cargado.lock().map_err(|_| "estado envenenado".to_string())?;
    if let Some(c) = g.as_ref() {
        return Ok(c.clone());
    }
    let c = Arc::new(cargar()?);
    *g = Some(c.clone());
    Ok(c)
}

/// Genera hasta `n` entradas para `key`. Si una falla, devuelve las ya hechas
/// (si hay alguna) o el error. Bloqueante: llamar fuera del hilo del webview.
fn fill(i: &Interno, key_bytes: &[u8], n: usize) -> Result<Vec<Vec<u8>>, String> {
    let key = decode_key(key_bytes)?;
    let c = obtener(i)?;
    c.pool.install(|| {
        let mut hechas = Vec::with_capacity(n);
        for k in 1..=n {
            let t = Instant::now();
            match build_precompute_entry_parts(&c.pp, &key, &c.artefactos).and_then(|e| encode_entry(&e)) {
                Ok(bytes) => {
                    println!("[native][timing] precompute {}/{} {} ms (hilos={})", k, n, t.elapsed().as_millis(), c.hilos);
                    hechas.push(bytes);
                }
                Err(e) => {
                    println!("[native][timing] precompute {}/{} fallo tras {} ms", k, n, t.elapsed().as_millis());
                    if hechas.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        Ok(hechas)
    })
}

/// Enmarca las entradas: [u32 LE longitud][bytes] por entrada.
pub fn frame(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.iter().map(|e| e.len() + 4).sum());
    for e in entries {
        out.extend_from_slice(&(e.len() as u32).to_le_bytes());
        out.extend_from_slice(e);
    }
    out
}

/// `n` de la query (`n=K`), acotado a 1..=N_MAX; por defecto 1.
pub fn parse_n(query: Option<&str>) -> usize {
    query
        .unwrap_or("")
        .split('&')
        .find_map(|kv| kv.strip_prefix("n="))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1)
        .clamp(1, N_MAX) as usize
}

/// ¿Viene del nucleo? Solo el `Origin` exacto del nucleo pasa.
pub fn from_engine(req: &Request<Vec<u8>>) -> bool {
    req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(ENGINE_ORIGIN)
}

fn reply(status: StatusCode, allowed: bool, content_type: &str, body: Vec<u8>) -> Response<Cow<'static, [u8]>> {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header("Cross-Origin-Resource-Policy", "cross-origin")
        .header(header::CACHE_CONTROL, "no-store");
    if allowed {
        b = b
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, ENGINE_ORIGIN)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST")
            .header(header::VARY, "Origin");
    }
    b.body(Cow::Owned(body)).unwrap()
}

fn text(status: StatusCode, allowed: bool, msg: &str) -> Response<Cow<'static, [u8]>> {
    reply(status, allowed, "text/plain; charset=utf-8", msg.as_bytes().to_vec())
}

/// Respuesta inmediata para lo que no requiere probar (o se rechaza); `None` = hay que probar.
pub fn triage(req: &Request<Vec<u8>>) -> Option<Response<Cow<'static, [u8]>>> {
    let allowed = from_engine(req);
    if !allowed {
        let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("-");
        println!("[prover] rechazado: origen {:?} {} {}", origin, req.method(), req.uri().path());
        return Some(text(StatusCode::FORBIDDEN, false, "origen no permitido"));
    }
    match (req.method().as_str(), req.uri().path()) {
        ("OPTIONS", _) => Some(text(StatusCode::NO_CONTENT, true, "")),
        ("POST", "/ping") => Some(text(StatusCode::OK, true, "pong")),
        ("POST", "/precompute") if req.body().is_empty() || req.body().len() > MAX_BODY => {
            Some(text(StatusCode::BAD_REQUEST, true, "clave ausente o demasiado grande"))
        }
        ("POST", "/precompute") => None,
        _ => Some(text(StatusCode::NOT_FOUND, true, "ruta desconocida")),
    }
}

/// Handler del protocolo `prover` (asincrono: probar tarda segundos).
pub fn handle(req: Request<Vec<u8>>, responder: UriSchemeResponder) {
    if let Some(resp) = triage(&req) {
        responder.respond(resp);
        return;
    }
    let n = parse_n(req.uri().query());
    let i = interno();
    if i.ocupado.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        responder.respond(text(StatusCode::CONFLICT, true, "busy"));
        return;
    }
    let guardia = GuardiaOcupado(i.clone());
    let key = req.into_body();
    tauri::async_runtime::spawn_blocking(move || {
        let _guardia = guardia;
        let resp = match fill(&i, &key, n) {
            Ok(entries) => reply(StatusCode::OK, true, "application/octet-stream", frame(&entries)),
            Err(e) => {
                // El error no lleva material secreto (clave publica invalida, artefactos, ...).
                println!("[prover] relleno fallido: {}", e);
                text(StatusCode::UNPROCESSABLE_ENTITY, true, &e)
            }
        };
        responder.respond(resp);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serve::common::TABLE_ORIGIN;

    fn req(method: &str, path: &str, origin: Option<&str>, body: &[u8]) -> Request<Vec<u8>> {
        let mut b = Request::builder().method(method).uri(format!("http://prover.localhost{path}"));
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(body.to_vec()).unwrap()
    }

    #[test]
    fn solo_el_nucleo_pasa_y_sin_cors_para_los_demas() {
        for o in [Some(TABLE_ORIGIN), Some("null"), Some("http://engine.localhost.evil"), None] {
            let r = triage(&req("POST", "/precompute?n=1", o, b"k")).expect("rechazo inmediato");
            assert_eq!(r.status(), StatusCode::FORBIDDEN, "{o:?}");
            assert!(r.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        }
        let ok = triage(&req("POST", "/ping", Some(ENGINE_ORIGIN), b"")).unwrap();
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(ok.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(), ENGINE_ORIGIN);
    }

    #[test]
    fn precompute_exige_clave_y_lo_demas_es_404() {
        assert!(triage(&req("POST", "/precompute", Some(ENGINE_ORIGIN), b"k")).is_none());
        assert_eq!(triage(&req("POST", "/precompute", Some(ENGINE_ORIGIN), b"")).unwrap().status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            triage(&req("POST", "/precompute", Some(ENGINE_ORIGIN), &[0u8; MAX_BODY + 1])).unwrap().status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(triage(&req("GET", "/precompute", Some(ENGINE_ORIGIN), b"k")).unwrap().status(), StatusCode::NOT_FOUND);
        assert_eq!(triage(&req("POST", "/otra", Some(ENGINE_ORIGIN), b"k")).unwrap().status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn n_acotado_y_marco() {
        assert_eq!(parse_n(None), 1);
        assert_eq!(parse_n(Some("n=3")), 3);
        assert_eq!(parse_n(Some("x=1&n=99")), N_MAX as usize);
        assert_eq!(parse_n(Some("n=0")), 1);
        assert_eq!(parse_n(Some("n=abc")), 1);
        assert_eq!(frame(&[vec![1, 2], vec![], vec![9]]), vec![2, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 9]);
    }

    #[test]
    fn clave_invalida_no_ocupa_ni_prueba() {
        let i = Interno::default();
        assert!(fill(&i, b"no es una clave", 1).is_err());
        assert!(i.cargado.lock().unwrap().is_none(), "decodifica la clave antes de cargar artefactos");
    }
}
