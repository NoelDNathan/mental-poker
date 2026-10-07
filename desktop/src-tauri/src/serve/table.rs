// Fase 2 / bloque 2.2: protocolo `table` (http://table.localhost). Replica lo que en la
// web hacen `next.config.mjs` headers() y `src/proxy.ts` para la mesa, SIN el nonce por
// peticion: el build de escritorio exporta estatico (bloque 2.1) y deja en la raiz del
// directorio un `csp.txt` con la CSP completa (hashes de los scripts inline incluidos).
//
// - `/` y rutas que acaban en `/` o son un directorio -> `index.html`; una ruta sin
//   extension que no existe prueba `<ruta>.html` (export estatico de Next).
// - Cabeceras: COOP same-origin, COEP require-corp, X-Frame-Options DENY, nosniff,
//   Referrer-Policy no-referrer; `.wasm` con `Cache-Control: public, max-age=0,
//   no-transform` (ver el comentario de next.config sobre ERR_CACHE_WRITE_FAILURE).
// - HTML: `Content-Security-Policy` = contenido de `csp.txt` (se relee por peticion HTML;
//   es pequeno). Si falta o es invalido: FALLA CERRADO con `default-src 'none'` y aviso.
// - `/release-manifest.json` es un fichero mas del directorio de la mesa.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use tauri::http::{Request, StatusCode};

use super::common::*;

/// CSP cuando no hay `csp.txt` valido: la pagina no puede cargar nada.
const FAIL_CLOSED_CSP: &str = "default-src 'none'";

pub struct TableServer {
    dir: PathBuf,
    avisado: AtomicBool,
}

impl TableServer {
    // TODO(2.4): `dir` saldria de resource_dir de Tauri + `desktop-config.json`.
    pub fn new(dir: PathBuf) -> Self {
        TableServer { dir, avisado: AtomicBool::new(false) }
    }

    fn aviso(&self, motivo: &str) {
        if !self.avisado.swap(true, Ordering::Relaxed) {
            eprintln!("[serve] table: csp.txt {motivo}; sirviendo HTML con `{FAIL_CLOSED_CSP}` (falla cerrado)");
        }
    }

    /// CSP del documento: `csp.txt` normalizado a una linea; si no, fail-closed.
    fn csp(&self) -> String {
        match std::fs::read_to_string(self.dir.join("csp.txt")) {
            Ok(s) => {
                let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
                if !s.is_empty() && s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
                    return s;
                }
                self.aviso("vacio o con caracteres no validos");
            }
            Err(_) => self.aviso("ausente o ilegible"),
        }
        FAIL_CLOSED_CSP.to_string()
    }

    fn base() -> Headers {
        let mut h = Headers::new();
        set(&mut h, "Cross-Origin-Opener-Policy", "same-origin");
        set(&mut h, "Cross-Origin-Embedder-Policy", "require-corp");
        set(&mut h, "X-Frame-Options", "DENY");
        set(&mut h, "X-Content-Type-Options", "nosniff");
        set(&mut h, "Referrer-Policy", "no-referrer");
        set(&mut h, "Cache-Control", "no-store, no-transform");
        h
    }

    /// Resuelve la ruta pedida a un fichero existente de la mesa.
    fn resolve(&self, raw_path: &str) -> Option<PathBuf> {
        let mut path = raw_path.to_string();
        if path.ends_with('/') {
            path.push_str("index.html");
        }
        let f = decode_join(&self.dir, &path)?;
        if f.is_file() {
            return Some(f);
        }
        if f.is_dir() {
            let i = f.join("index.html");
            return i.is_file().then_some(i);
        }
        if f.extension().is_none() {
            let mut h = f.into_os_string();
            h.push(".html");
            let h = PathBuf::from(h);
            return h.is_file().then_some(h);
        }
        None
    }

    pub fn handle(&self, req: &Request<Vec<u8>>) -> Resp {
        let base = Self::base();
        if !method_allowed(req) {
            return plain(StatusCode::METHOD_NOT_ALLOWED, &base, "", false);
        }
        let head = is_head(req);
        let Some(file) = self.resolve(req.uri().path()) else {
            return plain(StatusCode::NOT_FOUND, &base, "not found", head);
        };
        let mut h = base;
        match file.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()).as_deref() {
            Some("wasm") => set(&mut h, "Cache-Control", "public, max-age=0, no-transform"),
            Some("html") => set(&mut h, "Content-Security-Policy", self.csp()),
            _ => {}
        }
        serve_file(&file, &h, head)
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::testutil::*;
    use super::*;

    const HOST: &str = "table.localhost";

    fn fx(csp: Option<&str>) -> (TempDir, TableServer) {
        let base = TempDir::new("table");
        let dir = base.0.join("out");
        write(&dir.join("index.html"), b"<html>mesa</html>");
        write(&dir.join("_next/static/app.js"), b"app");
        write(&dir.join("pkg/m.wasm"), &[0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]);
        write(&dir.join("release-manifest.json"), b"{}");
        write(&dir.join("sala.html"), b"<html>sala</html>");
        write(&base.0.join("secreto.txt"), b"TOP");
        if let Some(c) = csp {
            write(&dir.join("csp.txt"), c.as_bytes());
        }
        let srv = TableServer::new(dir);
        (base, srv)
    }

    #[test]
    fn html_con_csp_de_csp_txt() {
        let (_b, srv) = fx(Some("default-src 'self';\n script-src 'self' 'sha256-AAA=';\n"));
        for p in ["/", "/index.html", "/sala"] {
            let r = srv.handle(&req("GET", HOST, p, None));
            assert_eq!(r.status(), StatusCode::OK, "{p}");
            assert_eq!(
                hdr(&r, "content-security-policy"),
                Some("default-src 'self'; script-src 'self' 'sha256-AAA=';"),
                "{p}"
            );
            assert_eq!(hdr(&r, "content-type"), Some("text/html; charset=utf-8"));
            assert_eq!(hdr(&r, "cross-origin-opener-policy"), Some("same-origin"));
            assert_eq!(hdr(&r, "cross-origin-embedder-policy"), Some("require-corp"));
            assert_eq!(hdr(&r, "x-frame-options"), Some("DENY"));
            assert_eq!(hdr(&r, "x-content-type-options"), Some("nosniff"));
            assert_eq!(hdr(&r, "referrer-policy"), Some("no-referrer"));
        }
        // Recursos no HTML: sin CSP de documento.
        let r = srv.handle(&req("GET", HOST, "/_next/static/app.js", None));
        assert_eq!(r.status(), StatusCode::OK);
        assert!(hdr(&r, "content-security-policy").is_none());
        let r = srv.handle(&req("GET", HOST, "/release-manifest.json", None));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(hdr(&r, "content-type"), Some("application/json"));
    }

    #[test]
    fn sin_csp_txt_falla_cerrado() {
        let (_b, srv) = fx(None);
        let r = srv.handle(&req("GET", HOST, "/", None));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(hdr(&r, "content-security-policy"), Some("default-src 'none'"));
        // Vacio o con caracteres de control: igual.
        let (_b2, srv2) = fx(Some("  \n "));
        let r = srv2.handle(&req("GET", HOST, "/", None));
        assert_eq!(hdr(&r, "content-security-policy"), Some("default-src 'none'"));
        let (_b3, srv3) = fx(Some("default-src 'self'\u{7}"));
        let r = srv3.handle(&req("GET", HOST, "/", None));
        assert_eq!(hdr(&r, "content-security-policy"), Some("default-src 'none'"));
    }

    #[test]
    fn wasm_con_no_transform_y_mime() {
        let (_b, srv) = fx(Some("default-src 'self'"));
        let r = srv.handle(&req("GET", HOST, "/pkg/m.wasm", None));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(hdr(&r, "content-type"), Some("application/wasm"));
        assert_eq!(hdr(&r, "cache-control"), Some("public, max-age=0, no-transform"));
        assert_eq!(hdr(&r, "content-length"), Some("8"));
        assert_eq!(hdr(&r, "cross-origin-embedder-policy"), Some("require-corp"));
        assert!(hdr(&r, "content-security-policy").is_none());
        let h = srv.handle(&req("HEAD", HOST, "/pkg/m.wasm", None));
        assert!(h.body().is_empty());
        assert_eq!(hdr(&h, "content-length"), Some("8"));
        assert_eq!(hdr(&h, "cache-control"), Some("public, max-age=0, no-transform"));
    }

    #[test]
    fn traversal_imposible() {
        let (_b, srv) = fx(Some("default-src 'self'"));
        for p in [
            "/../secreto.txt",
            "/%2e%2e/secreto.txt",
            "/..%2fsecreto.txt",
            "/%2e%2e%5csecreto.txt",
            "/_next/../../secreto.txt",
            "/C:/Windows/win.ini",
            "/%43%3a/Windows/win.ini",
            "//secreto.txt/../../secreto.txt",
        ] {
            let r = srv.handle(&req("GET", HOST, p, None));
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{p}");
            assert!(!String::from_utf8_lossy(r.body()).contains("TOP"), "{p}");
        }
    }

    #[test]
    fn head_y_metodos() {
        let (_b, srv) = fx(Some("default-src 'self'"));
        let g = srv.handle(&req("GET", HOST, "/", None));
        let h = srv.handle(&req("HEAD", HOST, "/", None));
        assert!(h.body().is_empty());
        assert_eq!(hdr(&h, "content-length"), hdr(&g, "content-length"));
        assert_eq!(hdr(&h, "content-security-policy"), hdr(&g, "content-security-policy"));
        for m in ["POST", "PUT", "DELETE", "OPTIONS"] {
            let r = srv.handle(&req(m, HOST, "/", None));
            assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
            assert!(r.body().is_empty());
        }
        let r = srv.handle(&req("GET", HOST, "/no-existe.js", None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
