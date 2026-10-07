// Utilidades compartidas por los handlers de los protocolos `table` y `engine`
// (Fase 2, bloque 2.2): origenes, union segura de rutas, MIME, respuestas con
// `Content-Length` siempre y servicio de ficheros (GET/HEAD).

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tauri::http::{header, Method, Request, Response, StatusCode};

pub const TABLE_ORIGIN: &str = "http://table.localhost";
pub const ENGINE_ORIGIN: &str = "http://engine.localhost";
pub const PROVER_ORIGIN: &str = "http://prover.localhost";

pub type Resp = Response<Cow<'static, [u8]>>;
/// Cabeceras de una respuesta (orden de insercion; `set` reemplaza sin distinguir mayusculas).
pub type Headers = Vec<(&'static str, String)>;

/// Pone `k: v`, reemplazando una cabecera anterior del mismo nombre.
pub fn set(h: &mut Headers, k: &'static str, v: impl Into<String>) {
    h.retain(|(n, _)| !n.eq_ignore_ascii_case(k));
    h.push((k, v.into()));
}

/// SHA-256 en hex minuscula (64 caracteres).
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodifica `%XX` (como `decodeURIComponent`); `None` si esta mal formado o no es UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = (*b.get(i + 1)? as char).to_digit(16)?;
            let lo = (*b.get(i + 2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Nombres de dispositivo de Windows (`CON`, `NUL`, `COM1`...): abrirlos no es abrir un fichero.
fn es_dispositivo_windows(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or("").to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

/// Une `rel` a `root` sin poder salir de el. Rechaza (`None`): `..`, `\`, NUL, `:` (prefijo
/// de unidad `C:`, flujos alternativos NTFS), segmentos que acaban en `.` o espacio (Windows
/// los recorta: `...`) y nombres de dispositivo. Mas estricto que `server.mjs` a proposito:
/// aqui ni `..` que se queda dentro de la raiz se admite.
pub fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    let rel = rel.trim_start_matches('/');
    if rel.contains(|c| c == '\\' || c == '\0') {
        return None;
    }
    let mut out = root.to_path_buf();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => return None,
            s => {
                if s.contains(':') || s.ends_with('.') || s.ends_with(' ') || es_dispositivo_windows(s) {
                    return None;
                }
                out.push(s);
            }
        }
    }
    Some(out)
}

/// `safe_join` sobre una ruta de URL aun codificada (`%2e%2e`, `%5c`, `%2f` se resuelven
/// ANTES de validar).
pub fn decode_join(root: &Path, raw_path: &str) -> Option<PathBuf> {
    safe_join(root, &percent_decode(raw_path)?)
}

pub fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

pub fn is_head(req: &Request<Vec<u8>>) -> bool {
    req.method() == Method::HEAD
}

/// GET y HEAD son los unicos metodos admitidos.
pub fn method_allowed(req: &Request<Vec<u8>>) -> bool {
    req.method() == Method::GET || req.method() == Method::HEAD
}

/// Respuesta con `Content-Length = len` (el del cuerpo real aunque sea HEAD y `body` vaya vacio).
pub fn respond(status: StatusCode, headers: &Headers, content_type: &str, len: u64, body: Vec<u8>) -> Resp {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, len.to_string());
    for (k, v) in headers {
        b = b.header(*k, v.as_str());
    }
    b.body(Cow::Owned(body)).unwrap_or_else(|_| {
        // Un valor de cabecera invalido (no deberia pasar) falla cerrado.
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_LENGTH, "0")
            .body(Cow::Owned(Vec::new()))
            .expect("respuesta 500 estatica")
    })
}

/// Respuesta de texto plano con las cabeceras dadas.
pub fn plain(status: StatusCode, headers: &Headers, text: &str, head: bool) -> Resp {
    let body = if head { Vec::new() } else { text.as_bytes().to_vec() };
    respond(status, headers, "text/plain", text.len() as u64, body)
}

/// Sirve un fichero con las cabeceras dadas. No es fichero / no se lee: 404 "not found".
/// HEAD: solo metadatos (no lee el wasm de 101 MB).
// TODO(2.4+): streaming y `Range` para ficheros grandes; hoy `std::fs::read` entero.
pub fn serve_file(file: &Path, headers: &Headers, head: bool) -> Resp {
    let not_found = || plain(StatusCode::NOT_FOUND, headers, "not found", head);
    let Ok(meta) = std::fs::metadata(file) else { return not_found() };
    if !meta.is_file() {
        return not_found();
    }
    let body = if head {
        Vec::new()
    } else {
        match std::fs::read(file) {
            Ok(b) => b,
            Err(_) => return not_found(),
        }
    };
    let len = if head { meta.len() } else { body.len() as u64 };
    respond(StatusCode::OK, headers, mime(file), len, body)
}

/// Filtra fuentes de CSP (`connect-src`): solo `[A-Za-z0-9:/._\-\[\]*]`. Descarta lo demas
/// (evita inyectar `;`/directivas y arrastrar URLs con `?clave=`); NUNCA imprime el valor.
pub fn sanitize_sources(list: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, s) in list.iter().enumerate() {
        let s = s.trim();
        let ok = !s.is_empty()
            && s.chars().all(|c| c.is_ascii_alphanumeric() || ":/._-[]*".contains(c));
        if ok {
            out.push(s.to_string());
        } else {
            eprintln!("[serve] fuente de CSP #{} descartada (caracteres no permitidos)", i);
        }
    }
    out
}

#[cfg(test)]
pub mod testutil {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    /// Directorio temporal unico, borrado al soltarlo.
    pub struct TempDir(pub PathBuf);
    impl TempDir {
        pub fn new(name: &str) -> Self {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let p = std::env::temp_dir().join(format!(
                "dpc-serve-{}-{}-{}-{}",
                name,
                std::process::id(),
                t,
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn write(p: &Path, content: &[u8]) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub fn req(method: &str, host: &str, path: &str, origin: Option<&str>) -> Request<Vec<u8>> {
        let mut b = Request::builder().method(method).uri(format!("http://{host}{path}"));
        if let Some(o) = origin {
            b = b.header(header::ORIGIN, o);
        }
        b.body(Vec::new()).unwrap()
    }

    pub fn hdr<'a>(r: &'a Resp, k: &str) -> Option<&'a str> {
        r.headers().get(k).and_then(|v| v.to_str().ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vector_conocido() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn percent_decode_basico() {
        assert_eq!(percent_decode("/a%20b%2Fc").as_deref(), Some("/a b/c"));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%ff"), None); // no UTF-8
    }

    #[test]
    fn safe_join_rechaza_escapes() {
        let root = Path::new("/raiz");
        assert_eq!(safe_join(root, "/a/b.js"), Some(PathBuf::from("/raiz/a/b.js")));
        assert_eq!(safe_join(root, "./a.js"), Some(PathBuf::from("/raiz/a.js")));
        for mala in [
            "../x", "/a/../../x", "a/../b", "C:/x", "/C:/Windows", "a\\b", "..\\x", "a/...", "a/b ",
            "/NUL", "/con.txt", "a/x:y", "a\0b",
        ] {
            assert_eq!(safe_join(root, mala), None, "{mala:?}");
        }
        assert_eq!(decode_join(root, "/a/%2e%2e/x"), None);
        assert_eq!(decode_join(root, "/a%2f..%2fx"), None);
        assert_eq!(decode_join(root, "/a%5cb"), None);
        assert_eq!(decode_join(root, "/%43%3a/x"), None); // C:
    }

    #[test]
    fn sanitize_descarta_inyeccion() {
        let v = sanitize_sources(&[
            "ws://127.0.0.1:2796".into(),
            "http://rpc; script-src *".into(),
            "https://rpc.example/x?key=1".into(),
            "".into(),
        ]);
        assert_eq!(v, vec!["ws://127.0.0.1:2796".to_string()]);
    }
}
