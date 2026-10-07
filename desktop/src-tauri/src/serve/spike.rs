// Modo spike (bloque 2.0), conservado como respaldo: DPC_SPIKE_ORIGINS=<dir con
// table/ y engine/> con ficheros planos; el nucleo se sirve en la raiz, sin ruta
// por contenido `/r/<hash>/`. NO es el servidor de produccion (ver `engine.rs`/`table.rs`).

use std::path::Path;

use tauri::http::{Request, StatusCode};

use super::common::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Table,
    Engine,
}

fn csp(kind: Kind) -> String {
    match kind {
        // Spike: la mesa puede hablar con el prover solo para comprobar que la rechaza.
        Kind::Table => format!(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' {PROVER_ORIGIN} ipc: http://ipc.localhost; frame-src {ENGINE_ORIGIN}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        ),
        Kind::Engine => format!(
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' {PROVER_ORIGIN} ipc: http://ipc.localhost; style-src 'self'; frame-ancestors {TABLE_ORIGIN}; base-uri 'none'; form-action 'none'; object-src 'none'"
        ),
    }
}

/// Sirve un fichero de `root` con las cabeceras de aislamiento del origen `kind`.
pub fn serve(root: &Path, kind: Kind, req: &Request<Vec<u8>>) -> Resp {
    let mut h = Headers::new();
    set(&mut h, "Cache-Control", "no-store, no-transform");
    if !method_allowed(req) {
        return plain(StatusCode::METHOD_NOT_ALLOWED, &h, "solo GET/HEAD", false);
    }
    let head = is_head(req);
    let mut rel = req.uri().path().to_string();
    if rel.ends_with('/') {
        rel.push_str("index.html");
    }
    let Some(path) = decode_join(root, &rel) else {
        return plain(StatusCode::NOT_FOUND, &h, "ruta no valida", head);
    };
    let corp = if kind == Kind::Engine { "cross-origin" } else { "same-origin" };
    set(&mut h, "Cross-Origin-Opener-Policy", "same-origin");
    set(&mut h, "Cross-Origin-Embedder-Policy", "require-corp");
    set(&mut h, "Cross-Origin-Resource-Policy", corp);
    set(&mut h, "Content-Security-Policy", csp(kind));
    set(&mut h, "X-Content-Type-Options", "nosniff");
    set(&mut h, "Referrer-Policy", "no-referrer");
    serve_file(&path, &h, head)
}
