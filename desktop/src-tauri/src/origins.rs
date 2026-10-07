// Fase 2 / bloque 2.0 (spike de origenes): la mesa y el nucleo servidos por
// protocolos propios de Tauri, cada uno en su origen. En WebView2 el esquema
// `table` se ve como `http://table.localhost` y `engine` como
// `http://engine.localhost`: dos origenes http serializables y distintos, que
// es lo que el Gate 7 necesita (vault, K y cartas solo en el del nucleo).
//
// `prover` es el plan B del canal al prover nativo: un endpoint que solo
// acepta peticiones cuyo `Origin` (cabecera que el JS no puede falsificar)
// sea el del nucleo.
//
// Spike: sirve ficheros de un directorio (DPC_SPIKE_ORIGINS/{table,engine}).
// El servidor de verdad (ruta por contenido /r/<sha256>/, manifiesto, MIME
// completos) es el bloque 2.2.

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

use tauri::http::{header, Request, Response, StatusCode};

pub const TABLE_ORIGIN: &str = "http://table.localhost";
pub const ENGINE_ORIGIN: &str = "http://engine.localhost";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Table,
    Engine,
}

/// Une `rel` a `root` sin salir de el (ni `..`, ni rutas absolutas, ni prefijos de unidad).
pub fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/');
    let mut out = root.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        _ => "application/octet-stream",
    }
}

fn csp(kind: Kind) -> String {
    match kind {
        // Spike: la mesa puede hablar con el prover solo para comprobar que la rechaza.
        Kind::Table => format!(
            "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' http://prover.localhost ipc: http://ipc.localhost; frame-src {ENGINE_ORIGIN}; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        ),
        Kind::Engine => format!(
            "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self' http://prover.localhost ipc: http://ipc.localhost; style-src 'self'; frame-ancestors {TABLE_ORIGIN}; base-uri 'none'; form-action 'none'; object-src 'none'"
        ),
    }
}

fn plain(status: StatusCode, body: &str) -> Response<Cow<'static, [u8]>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Cow::Owned(body.as_bytes().to_vec()))
        .unwrap()
}

/// Sirve un fichero de `root` con las cabeceras de aislamiento del origen `kind`.
pub fn serve(root: &Path, kind: Kind, req: &Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    if req.method() != "GET" && req.method() != "HEAD" {
        return plain(StatusCode::METHOD_NOT_ALLOWED, "solo GET/HEAD");
    }
    let mut rel = req.uri().path().to_string();
    if rel.ends_with('/') {
        rel.push_str("index.html");
    }
    let Some(path) = safe_join(root, &rel) else {
        return plain(StatusCode::BAD_REQUEST, "ruta no valida");
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return plain(StatusCode::NOT_FOUND, "no existe");
    };
    let corp = if kind == Kind::Engine { "cross-origin" } else { "same-origin" };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime(&path))
        .header("Cross-Origin-Opener-Policy", "same-origin")
        .header("Cross-Origin-Embedder-Policy", "require-corp")
        .header("Cross-Origin-Resource-Policy", corp)
        .header("Content-Security-Policy", csp(kind))
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(header::CACHE_CONTROL, "no-store, no-transform")
        .body(Cow::Owned(bytes))
        .unwrap()
}

/// Plan B del canal al prover: solo el origen del nucleo pasa.
pub fn prover(req: &Request<Vec<u8>>) -> Response<Cow<'static, [u8]>> {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let allowed = origin == ENGINE_ORIGIN;
    let mut b = Response::builder()
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("Cross-Origin-Resource-Policy", "cross-origin");
    if allowed {
        // CORS solo para el nucleo: cualquier otro origen ni siquiera puede leer la respuesta.
        b = b
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, ENGINE_ORIGIN)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST")
            .header(header::VARY, "Origin");
    }
    if req.method() == "OPTIONS" {
        return b.status(if allowed { StatusCode::NO_CONTENT } else { StatusCode::FORBIDDEN }).body(Cow::Borrowed(&[][..])).unwrap();
    }
    if !allowed {
        println!("[spike] prover: rechazado origen {:?}", origin);
        return b.status(StatusCode::FORBIDDEN).body(Cow::Borrowed(&b"origen no permitido"[..])).unwrap();
    }
    println!("[spike] prover: aceptado {} {}", req.method(), req.uri().path());
    b.status(StatusCode::OK).body(Cow::Borrowed(&b"pong"[..])).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_no_sale_de_la_raiz() {
        let root = Path::new("/raiz");
        assert_eq!(safe_join(root, "/a/b.js"), Some(PathBuf::from("/raiz/a/b.js")));
        assert_eq!(safe_join(root, "../secreto"), None);
        assert_eq!(safe_join(root, "/a/../../secreto"), None);
        assert_eq!(safe_join(root, "./a.js"), Some(PathBuf::from("/raiz/a.js")));
    }

    fn req(origin: Option<&str>) -> Request<Vec<u8>> {
        let mut b = Request::builder().method("POST").uri("http://prover.localhost/ping");
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(Vec::new()).unwrap()
    }

    #[test]
    fn prover_solo_acepta_el_origen_del_nucleo() {
        assert_eq!(prover(&req(Some(ENGINE_ORIGIN))).status(), StatusCode::OK);
        assert_eq!(prover(&req(Some(TABLE_ORIGIN))).status(), StatusCode::FORBIDDEN);
        assert_eq!(prover(&req(Some("null"))).status(), StatusCode::FORBIDDEN);
        assert_eq!(prover(&req(None)).status(), StatusCode::FORBIDDEN);
        assert!(prover(&req(Some(TABLE_ORIGIN))).headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
    }
}
