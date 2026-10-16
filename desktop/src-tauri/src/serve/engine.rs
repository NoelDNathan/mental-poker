// Fase 2 / bloque 2.2: protocolo `engine` (http://engine.localhost). Port fiel de
// `frontend-production/engine/server.mjs` (Gate 7): servidor ESTATICO del nucleo.
//
// - Ruta por contenido: `/r/<sha256 de engine.html>/...` solo se sirve si el hash
//   coincide con el de `engine-dist/engine.html` (otro hash: 404 "otra release").
//   El hash se calcula UNA vez al arrancar (en la web se releia por peticion; aqui los
//   ficheros de la release no cambian con la app en marcha).
// - Del directorio publico solo `PUBLIC_PREFIXES` y `PUBLIC_FILES`.
// - Cabeceras de `server.mjs`. Diferencias deliberadas (la mesa y el nucleo son
//   cross-site, `table.localhost` vs `engine.localhost`): CORP `cross-origin` en
//   engine.html y en `/r/<hash>/assets/` (en la web `same-site`/`same-origin`);
//   `frame-ancestors` = solo `http://table.localhost`; `connect-src` incluye
//   `http://prover.localhost` (canal al prover nativo, bloque 2.3).

use std::path::PathBuf;

use tauri::http::{Request, StatusCode};

use super::common::*;

/// Rutas del directorio publico que el nucleo necesita (nada mas se sirve).
const PUBLIC_PREFIXES: [&str; 2] = ["/pkg-rayon-native-20261016/", "/precompute/vhyb/"];
const PUBLIC_FILES: [&str; 1] = ["/release-manifest.json"];

const IMMUTABLE: &str = "public, max-age=31536000, immutable, no-transform";

pub struct EngineServer {
    dist: PathBuf,
    public: PathBuf,
    digest: Option<String>,
    csp: String,
}

/// `/r/<64 hex minuscula>/resto` -> (hash, "/resto").
fn parse_r(path: &str) -> Option<(&str, &str)> {
    let r = path.strip_prefix("/r/")?;
    let hash = r.get(..64)?;
    if !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let rest = &r[64..];
    rest.starts_with('/').then_some((hash, rest))
}

impl EngineServer {
    // TODO(2.4): `dist`/`public`/`connect` saldran de resource_dir de Tauri + `desktop-config.json`.
    pub fn new(dist: PathBuf, public: PathBuf, connect: &[String]) -> Self {
        let digest = std::fs::read(dist.join("engine.html")).ok().map(|b| sha256_hex(&b));
        if digest.is_none() {
            eprintln!("[serve] engine: sin engine.html en el directorio dist; /r/<hash>/ dara 404");
        }
        let mut sources = vec!["'self'".to_string()];
        sources.extend(sanitize_sources(connect));
        let prover = PROVER_ORIGIN.to_string();
        if !sources.contains(&prover) {
            sources.push(prover);
        }
        let csp = [
            "default-src 'none'".to_string(),
            // blob:: el glue del motor se ejecuta desde los bytes verificados
            // (modulo blob, #1 auditoria 2026-10), como en engine/server.mjs.
            "script-src 'self' 'wasm-unsafe-eval' blob:".to_string(),
            "worker-src 'self' blob:".to_string(),
            format!("connect-src {}", sources.join(" ")),
            "style-src 'self'".to_string(),
            "img-src 'self'".to_string(),
            format!("frame-ancestors {TABLE_ORIGIN}"),
            "base-uri 'none'".to_string(),
            "form-action 'none'".to_string(),
            "object-src 'none'".to_string(),
            "require-trusted-types-for 'script'".to_string(),
            "trusted-types default".to_string(),
        ]
        .join("; ");
        EngineServer { dist, public, digest, csp }
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }

    fn base() -> Headers {
        let mut h = Headers::new();
        set(&mut h, "Cross-Origin-Opener-Policy", "same-origin");
        set(&mut h, "Cross-Origin-Embedder-Policy", "require-corp");
        set(&mut h, "Cross-Origin-Resource-Policy", "same-origin");
        set(&mut h, "Origin-Agent-Cluster", "?1");
        set(&mut h, "X-Content-Type-Options", "nosniff");
        set(&mut h, "Referrer-Policy", "no-referrer");
        set(&mut h, "Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
        set(&mut h, "Cache-Control", "no-store, no-transform");
        h
    }

    fn immutable() -> Headers {
        let mut h = Self::base();
        set(&mut h, "Cache-Control", IMMUTABLE);
        set(&mut h, "Cross-Origin-Resource-Policy", "cross-origin");
        h
    }

    pub fn handle(&self, req: &Request<Vec<u8>>) -> Resp {
        let base = Self::base();
        if !method_allowed(req) {
            return plain(StatusCode::METHOD_NOT_ALLOWED, &base, "", false);
        }
        let head = is_head(req);
        let path = req.uri().path();

        if let Some((hash, rest)) = parse_r(path) {
            // Solo la release que hay en disco: otro hash es otra pagina (404).
            if Some(hash) != self.digest() {
                return plain(StatusCode::NOT_FOUND, &base, "otra release", head);
            }
            if rest == "/engine.html" {
                let origin = req.headers().get("origin").and_then(|v| v.to_str().ok()).unwrap_or("");
                let mut h = Self::immutable();
                set(&mut h, "Vary", "Origin");
                if origin == TABLE_ORIGIN {
                    set(&mut h, "Access-Control-Allow-Origin", TABLE_ORIGIN);
                }
                set(&mut h, "Content-Security-Policy", self.csp.as_str());
                return serve_file(&self.dist.join("engine.html"), &h, head);
            }
            if rest.starts_with("/assets/") {
                if let Some(f) = decode_join(&self.dist, rest) {
                    return serve_file(&f, &Self::immutable(), head);
                }
            }
        }

        let allowed = |p: &str| PUBLIC_FILES.contains(&p) || PUBLIC_PREFIXES.iter().any(|x| p.starts_with(x));
        if allowed(path) {
            // El permitido se comprueba tambien ya decodificado (`%2e`, `%2f`...).
            if let Some(dec) = percent_decode(path) {
                if allowed(&dec) {
                    if let Some(f) = safe_join(&self.public, &dec) {
                        return serve_file(&f, &base, head);
                    }
                }
            }
        }
        plain(StatusCode::NOT_FOUND, &base, "not found", head)
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::testutil::*;
    use super::*;

    const HOST: &str = "engine.localhost";

    struct Fx {
        _base: TempDir,
        srv: EngineServer,
        hash: String,
    }

    fn fx() -> Fx {
        let base = TempDir::new("engine");
        let dist = base.0.join("dist");
        let public = base.0.join("public");
        write(&dist.join("engine.html"), b"<html>engine</html>");
        write(&dist.join("assets/app.js"), b"console.log(1)");
        write(&public.join("pkg-rayon-native-20261016/glue.js"), b"glue");
        write(&public.join("pkg-rayon-native-20261016/m.wasm"), &[0, 0x61, 0x73, 0x6d]);
        write(&public.join("precompute/vhyb/a.bin"), b"abcdef");
        write(&public.join("release-manifest.json"), b"{}");
        write(&public.join("pkg-rayon-viejo/x.js"), b"viejo");
        write(&public.join("otro/secreto.json"), b"{}");
        write(&base.0.join("secreto.txt"), b"TOP");
        let srv = EngineServer::new(
            dist,
            public,
            &["ws://127.0.0.1:2796".to_string(), "http://127.0.0.1:8545".to_string()],
        );
        let hash = sha256_hex(b"<html>engine</html>");
        Fx { _base: base, srv, hash }
    }

    #[test]
    fn traversal_imposible() {
        let f = fx();
        let h = &f.hash;
        for p in [
            "/precompute/vhyb/../../../secreto.txt".to_string(),
            "/precompute/vhyb/%2e%2e/%2e%2e/%2e%2e/secreto.txt".to_string(),
            "/precompute/vhyb/..%2f..%2f..%2fsecreto.txt".to_string(),
            "/precompute/vhyb/..%5c..%5csecreto.txt".to_string(),
            "/precompute/vhyb/../../otro/secreto.json".to_string(),
            "//precompute/vhyb/a.bin/../../../secreto.txt".to_string(),
            "/precompute/vhyb/C:/Windows/win.ini".to_string(),
            "/precompute/vhyb/%43%3a/x".to_string(),
            "/C:/Windows/win.ini".to_string(),
            "//etc/passwd".to_string(),
            format!("/r/{h}/assets/../engine.html"),
            format!("/r/{h}/assets/%2e%2e/%2e%2e/secreto.txt"),
            format!("/r/{h}/assets/..%2f..%2fsecreto.txt"),
            format!("/r/{h}/assets/C:/x"),
        ] {
            let r = f.srv.handle(&req("GET", HOST, &p, None));
            assert_eq!(r.status(), StatusCode::NOT_FOUND, "{p}");
            assert!(!String::from_utf8_lossy(r.body()).contains("TOP"), "{p}");
        }
    }

    #[test]
    fn hash_equivocado_404_otra_release() {
        let f = fx();
        let mala = "0".repeat(64);
        let r = f.srv.handle(&req("GET", HOST, &format!("/r/{mala}/engine.html"), None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(r.body().as_ref(), b"otra release");
        // Hash en mayusculas: no es la ruta de contenido (404 "not found").
        let r = f.srv.handle(&req("GET", HOST, &format!("/r/{}/engine.html", f.hash.to_uppercase()), None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        assert_eq!(r.body().as_ref(), b"not found");
    }

    #[test]
    fn engine_html_con_csp_y_cors_solo_para_la_mesa() {
        let f = fx();
        let uri = format!("/r/{}/engine.html", f.hash);
        let r = f.srv.handle(&req("GET", HOST, &uri, Some(TABLE_ORIGIN)));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.body().as_ref(), b"<html>engine</html>");
        assert_eq!(hdr(&r, "access-control-allow-origin"), Some(TABLE_ORIGIN));
        assert_eq!(hdr(&r, "vary"), Some("Origin"));
        assert_eq!(hdr(&r, "cross-origin-resource-policy"), Some("cross-origin"));
        assert_eq!(hdr(&r, "cross-origin-opener-policy"), Some("same-origin"));
        assert_eq!(hdr(&r, "cross-origin-embedder-policy"), Some("require-corp"));
        assert_eq!(hdr(&r, "origin-agent-cluster"), Some("?1"));
        assert_eq!(hdr(&r, "x-content-type-options"), Some("nosniff"));
        assert_eq!(hdr(&r, "referrer-policy"), Some("no-referrer"));
        assert_eq!(hdr(&r, "cache-control"), Some(IMMUTABLE));
        assert_eq!(hdr(&r, "content-type"), Some("text/html; charset=utf-8"));
        assert_eq!(hdr(&r, "content-length"), Some("19"));
        let csp = hdr(&r, "content-security-policy").unwrap();
        for d in [
            "default-src 'none'",
            "script-src 'self' 'wasm-unsafe-eval' blob:",
            "worker-src 'self' blob:",
            "connect-src 'self' ws://127.0.0.1:2796 http://127.0.0.1:8545 http://prover.localhost",
            "style-src 'self'",
            "img-src 'self'",
            "frame-ancestors http://table.localhost",
            "base-uri 'none'",
            "form-action 'none'",
            "object-src 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types default",
        ] {
            assert!(csp.split("; ").any(|x| x == d), "falta {d} en {csp}");
        }
        // Otro origen, el del propio nucleo o sin Origin: Vary pero sin ACAO.
        for o in [Some("http://evil.localhost"), Some(ENGINE_ORIGIN), Some("null"), None] {
            let r = f.srv.handle(&req("GET", HOST, &uri, o));
            assert_eq!(r.status(), StatusCode::OK);
            assert!(hdr(&r, "access-control-allow-origin").is_none(), "{o:?}");
            assert_eq!(hdr(&r, "vary"), Some("Origin"));
        }
    }

    #[test]
    fn assets_inmutables_bajo_el_hash() {
        let f = fx();
        let r = f.srv.handle(&req("GET", HOST, &format!("/r/{}/assets/app.js", f.hash), None));
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(hdr(&r, "content-type"), Some("text/javascript; charset=utf-8"));
        assert_eq!(hdr(&r, "cache-control"), Some(IMMUTABLE));
        assert_eq!(hdr(&r, "cross-origin-resource-policy"), Some("cross-origin"));
        assert!(hdr(&r, "content-security-policy").is_none());
        // Subruta con hash bueno que no es engine.html ni assets/: 404.
        let r = f.srv.handle(&req("GET", HOST, &format!("/r/{}/otra.js", f.hash), None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn lista_blanca_de_prefijos_publicos() {
        let f = fx();
        for (p, ct, st) in [
            ("/pkg-rayon-native-20261016/glue.js", "text/javascript; charset=utf-8", 200),
            ("/pkg-rayon-native-20261016/m.wasm", "application/wasm", 200),
            ("/precompute/vhyb/a.bin", "application/octet-stream", 200),
            ("/release-manifest.json", "application/json", 200),
            ("/pkg-rayon-viejo/x.js", "", 404),
            ("/otro/secreto.json", "", 404),
            ("/release-manifest.json/../otro/secreto.json", "", 404),
            ("/precompute/otro.bin", "", 404),
            ("/", "", 404),
            ("/engine.html", "", 404),
        ] {
            let r = f.srv.handle(&req("GET", HOST, p, None));
            assert_eq!(r.status().as_u16(), st, "{p}");
            if st == 200 {
                assert_eq!(hdr(&r, "content-type"), Some(ct), "{p}");
                // Publico: cabeceras base (same-origin, no-store).
                assert_eq!(hdr(&r, "cross-origin-resource-policy"), Some("same-origin"));
                assert_eq!(hdr(&r, "cache-control"), Some("no-store, no-transform"));
                assert_eq!(hdr(&r, "permissions-policy"), Some("camera=(), microphone=(), geolocation=(), payment=()"));
            }
        }
    }

    #[test]
    fn head_sin_cuerpo_con_content_length() {
        let f = fx();
        for p in [
            format!("/r/{}/engine.html", f.hash),
            "/precompute/vhyb/a.bin".to_string(),
            "/otro/secreto.json".to_string(),
        ] {
            let g = f.srv.handle(&req("GET", HOST, &p, None));
            let h = f.srv.handle(&req("HEAD", HOST, &p, None));
            assert_eq!(h.status(), g.status(), "{p}");
            assert!(h.body().is_empty(), "{p}");
            assert_eq!(hdr(&h, "content-length"), hdr(&g, "content-length"), "{p}");
            assert_eq!(hdr(&g, "content-length"), Some(g.body().len().to_string().as_str()));
        }
        let h = f.srv.handle(&req("HEAD", HOST, "/precompute/vhyb/a.bin", None));
        assert_eq!(hdr(&h, "content-length"), Some("6"));
    }

    #[test]
    fn metodos_distintos_de_get_head_dan_405() {
        let f = fx();
        for m in ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
            let r = f.srv.handle(&req(m, HOST, &format!("/r/{}/engine.html", f.hash), Some(TABLE_ORIGIN)));
            assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED, "{m}");
            assert!(r.body().is_empty());
            assert_eq!(hdr(&r, "content-length"), Some("0"));
            assert!(hdr(&r, "access-control-allow-origin").is_none());
        }
    }

    #[test]
    fn sin_engine_html_todo_r_da_404() {
        let b = TempDir::new("engine-vacio");
        let srv = EngineServer::new(b.0.join("dist"), b.0.join("public"), &[]);
        assert!(srv.digest().is_none());
        let r = srv.handle(&req("GET", HOST, &format!("/r/{}/engine.html", "a".repeat(64)), None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn un_directorio_no_es_fichero() {
        let f = fx();
        let r = f.srv.handle(&req("GET", HOST, "/precompute/vhyb/", None));
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
    }
}
