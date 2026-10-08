// Fase 2 / bloque 2.2: handlers de los protocolos propios `table` y `engine` (sin
// servidor HTTP ni puerto: nada escucha). Portan `engine/server.mjs` y las cabeceras
// de `next.config.mjs`/`src/proxy.ts` de la mesa (ver `engine.rs` y `table.rs`).
//
// El modo `spike` (DPC_SPIKE_ORIGINS) sigue disponible como respaldo cuando no hay
// configuracion de escritorio.

pub mod common;
pub mod engine;
pub mod spike;
pub mod table;

use std::path::{Path, PathBuf};

pub use engine::EngineServer;
pub use table::TableServer;

/// Directorios y lista de conexion del modo escritorio.
///
/// Origen, por orden: variables `DPC_*` (desarrollo), `DPC_APP_DIR=<dir>` y la
/// carpeta `app/` junto al ejecutable (la app instalada; en Windows los recursos de
/// Tauri van junto al .exe). Una carpeta de app contiene `table/`, `engine/`,
/// `public/` y `desktop-config.json` (`{"engineConnect": ["ws://...", "https://..."]}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopDirs {
    /// `out/` del export estatico de la mesa (con `csp.txt` y `release-manifest.json`).
    pub table_dir: PathBuf,
    /// `engine-dist/` (engine.html + assets/).
    pub engine_dist: PathBuf,
    /// Equivalente a `public/`: `pkg-rayon-native-*`, `precompute/vhyb`, `release-manifest.json`.
    pub public_dir: PathBuf,
    /// Fuentes extra del `connect-src` del nucleo (separadas por espacios en la variable).
    pub engine_connect: Vec<String>,
}

impl DesktopDirs {
    /// Lee `DPC_TABLE_DIR`, `DPC_ENGINE_DIST`, `DPC_PUBLIC_DIR` y `DPC_ENGINE_CONNECT`.
    /// `Some` solo si estan las tres rutas; si faltan algunas (pero no todas) avisa y da `None`.
    pub fn from_env() -> Option<Self> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let var = |k: &str| get(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        let (t, e, p) = (var("DPC_TABLE_DIR"), var("DPC_ENGINE_DIST"), var("DPC_PUBLIC_DIR"));
        match (t, e, p) {
            (Some(t), Some(e), Some(p)) => Some(DesktopDirs {
                table_dir: PathBuf::from(t),
                engine_dist: PathBuf::from(e),
                public_dir: PathBuf::from(p),
                engine_connect: var("DPC_ENGINE_CONNECT")
                    .map(|c| c.split_whitespace().map(str::to_string).collect())
                    .unwrap_or_default(),
            }),
            (None, None, None) => None,
            _ => {
                eprintln!("[serve] configuracion incompleta: hacen falta DPC_TABLE_DIR, DPC_ENGINE_DIST y DPC_PUBLIC_DIR a la vez");
                None
            }
        }
    }

    /// Carpeta de app empaquetada (ver arriba). `None` si falta alguna pieza.
    pub fn from_app_dir(root: &Path) -> Option<Self> {
        let (table_dir, engine_dist, public_dir) = (root.join("table"), root.join("engine"), root.join("public"));
        if !table_dir.is_dir() || !engine_dist.is_dir() || !public_dir.is_dir() {
            return None;
        }
        let cfg = std::fs::read(root.join("desktop-config.json"))
            .map_err(|e| eprintln!("[serve] {}: sin desktop-config.json ({e})", root.display()))
            .ok()?;
        let cfg: serde_json::Value = serde_json::from_slice(&cfg)
            .map_err(|e| eprintln!("[serve] desktop-config.json invalido: {e}"))
            .ok()?;
        let engine_connect = cfg["engineConnect"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Some(DesktopDirs { table_dir, engine_dist, public_dir, engine_connect })
    }

    /// Variables `DPC_*`, si no `DPC_APP_DIR`, si no `app/` junto al ejecutable.
    pub fn discover() -> Option<Self> {
        if let Some(d) = Self::from_env() {
            return Some(d);
        }
        if let Ok(dir) = std::env::var("DPC_APP_DIR") {
            return Self::from_app_dir(Path::new(dir.trim()));
        }
        let exe = std::env::current_exe().ok()?;
        Self::from_app_dir(&exe.parent()?.join("app"))
    }

    /// Artefactos del prover nativo dentro de la carpeta publica.
    pub fn precompute_dir(&self) -> PathBuf {
        self.public_dir.join("precompute").join("vhyb")
    }

    /// Construye los dos handlers (calcula el hash de engine.html una sola vez).
    pub fn build(&self) -> (TableServer, EngineServer) {
        (
            TableServer::new(self.table_dir.clone()),
            EngineServer::new(self.engine_dist.clone(), self.public_dir.clone(), &self.engine_connect),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn dirs(pairs: &[(&str, &str)]) -> Option<DesktopDirs> {
        let m: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        DesktopDirs::from_vars(|k| m.get(k).cloned())
    }

    #[test]
    fn config_completa_parcial_o_vacia() {
        assert_eq!(dirs(&[]), None);
        assert_eq!(dirs(&[("DPC_TABLE_DIR", "/t")]), None);
        assert_eq!(dirs(&[("DPC_TABLE_DIR", "/t"), ("DPC_ENGINE_DIST", "  ")]), None);
        let d = dirs(&[
            ("DPC_TABLE_DIR", "/t"),
            ("DPC_ENGINE_DIST", "/e"),
            ("DPC_PUBLIC_DIR", "/p"),
            ("DPC_ENGINE_CONNECT", "ws://127.0.0.1:2796  http://127.0.0.1:8545"),
        ])
        .unwrap();
        assert_eq!(d.table_dir, PathBuf::from("/t"));
        assert_eq!(d.engine_connect, vec!["ws://127.0.0.1:2796", "http://127.0.0.1:8545"]);
        let d = dirs(&[("DPC_TABLE_DIR", "/t"), ("DPC_ENGINE_DIST", "/e"), ("DPC_PUBLIC_DIR", "/p")]).unwrap();
        assert!(d.engine_connect.is_empty());
    }

    #[test]
    fn carpeta_de_app() {
        let root = std::env::temp_dir().join(format!("dpc-appdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["table", "engine", "public"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        assert_eq!(DesktopDirs::from_app_dir(&root), None, "sin desktop-config.json");
        std::fs::write(root.join("desktop-config.json"), br#"{"engineConnect":["ws://127.0.0.1:2794","http://127.0.0.1:8545"]}"#).unwrap();
        let d = DesktopDirs::from_app_dir(&root).unwrap();
        assert_eq!(d.engine_dist, root.join("engine"));
        assert_eq!(d.engine_connect, vec!["ws://127.0.0.1:2794", "http://127.0.0.1:8545"]);
        assert_eq!(d.precompute_dir(), root.join("public").join("precompute").join("vhyb"));
        std::fs::remove_dir_all(root.join("engine")).unwrap();
        assert_eq!(DesktopDirs::from_app_dir(&root), None, "falta engine/");
        let _ = std::fs::remove_dir_all(&root);
    }
}
