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

use std::path::PathBuf;

pub use engine::EngineServer;
pub use table::TableServer;

/// Directorios y lista de conexion del modo escritorio.
///
/// TODO(2.4): sustituir las variables de entorno por `resource_dir` de Tauri + un
/// `desktop-config.json` empaquetado (las variables quedarian solo para desarrollo).
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
}
