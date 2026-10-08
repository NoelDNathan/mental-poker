// App de escritorio (Tauri v2, Windows/WebView2) — Fase 2.
//
// La mesa y el nucleo se sirven por protocolos propios, cada uno en su origen
// (`table` = http://table.localhost, `engine` = http://engine.localhost), con
// las mismas cabeceras de aislamiento que la web (Gate 7: vault, K y cartas
// solo en el origen del nucleo). El nucleo rellena su pool de precompute con el
// prover NATIVO por el protocolo `prover`, que solo atiende al origen del nucleo.
//
// La app NO decide nada del juego: contrato = fondos, protocolo = cartas,
// UI = orquestacion. Las entradas del pool llevan SECRETOS (`r_prime`,
// `link_v`): nunca se imprimen ni se registran; solo tiempos y contadores.
//
// Sin IPC: Tauri trata cualquier protocolo propio como origen "local", asi que
// un comando valdria igual para la mesa que para el nucleo. Las capabilities
// llevan `"local": false` y la app no registra comandos (PLAN-FASE-2.md,
// "Resultado del spike 2.0").

// SIN `windows_subsystem = "windows"` a proposito mientras dure el desarrollo:
// el stdout con los tiempos `[native][timing]` tiene que verse.

mod prover;
mod serve;

use std::path::PathBuf;
use std::sync::Arc;

use serve::common::TABLE_ORIGIN;

fn main() {
    let mut builder = tauri::Builder::default();

    // Mesa y nucleo desde la carpeta de app (`serve::DesktopDirs::discover`: la
    // instalada junto al .exe, o DPC_APP_DIR / DPC_* en desarrollo). Sin ella,
    // DPC_SPIKE_ORIGINS=<dir con table/ y engine/> mantiene el spike 2.0.
    let desktop = serve::DesktopDirs::discover();
    let spike = std::env::var("DPC_SPIKE_ORIGINS").ok().map(PathBuf::from);
    let origenes_propios = desktop.is_some() || spike.is_some();
    if let Some(dirs) = desktop {
        println!("[desktop] mesa {} | nucleo {}", dirs.table_dir.display(), dirs.engine_dist.display());
        prover::set_artifacts_dir(dirs.precompute_dir());
        let (table, engine) = dirs.build();
        let (table, engine) = (Arc::new(table), Arc::new(engine));
        builder = builder
            .register_uri_scheme_protocol("table", move |_ctx, req| table.handle(&req))
            .register_uri_scheme_protocol("engine", move |_ctx, req| engine.handle(&req));
    } else if let Some(dir) = spike {
        let (table, engine) = (dir.join("table"), dir.join("engine"));
        builder = builder
            .register_uri_scheme_protocol("table", move |_ctx, req| serve::spike::serve(&table, serve::spike::Kind::Table, &req))
            .register_uri_scheme_protocol("engine", move |_ctx, req| serve::spike::serve(&engine, serve::spike::Kind::Engine, &req));
    }
    if origenes_propios {
        builder = builder.register_asynchronous_uri_scheme_protocol("prover", |_ctx, req, responder| prover::handle(req, responder));
    }

    let jugador = parse_jugador(std::env::args().skip(1));
    builder
        .setup(move |app| {
            use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};
            // La ventana se crea aqui (no en tauri.conf) para poder darle una carpeta
            // de datos propia por jugador.
            let url = if origenes_propios {
                let u = match jugador {
                    Some(n) => format!("{TABLE_ORIGIN}/?dev={n}"),
                    None => format!("{TABLE_ORIGIN}/"),
                };
                println!("[desktop] mesa en {u}");
                WebviewUrl::External(u.parse()?)
            } else {
                WebviewUrl::App("index.html".into())
            };
            let mut w = WebviewWindowBuilder::new(app, "main", url).inner_size(1400.0, 900.0);
            w = match jugador {
                Some(n) => {
                    let dir = app.path().app_local_data_dir()?.join(format!("jugador-{n}"));
                    println!("[desktop] jugador {n}: datos en {}", dir.display());
                    w.title(format!("Dog Poker Club (lab) - Jugador {n}")).data_directory(dir)
                }
                None => w.title("Dog Poker Club (lab)"),
            };
            w.build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error al ejecutar la app Tauri");
}

/// Mayor indice de cuenta del nodo Hardhat (20 cuentas por defecto).
const MAX_JUGADOR: u32 = 19;

/// `--jugador N` o `--jugador=N` (lab): abre la mesa con la cuenta N de la wallet
/// dev (`?dev=N`, que la build de release ignora) y guarda vault, K y sesion en una
/// carpeta propia, para poder abrir varios jugadores en el mismo PC sin que se
/// pisen. Sin el argumento, `DPC_JUGADOR`.
fn parse_jugador(args: impl Iterator<Item = String>) -> Option<u32> {
    let args: Vec<String> = args.collect();
    let raw = args
        .iter()
        .enumerate()
        .find_map(|(i, a)| match a.strip_prefix("--jugador") {
            Some("") => args.get(i + 1).cloned(),
            Some(rest) => rest.strip_prefix('=').map(str::to_string),
            None => None,
        })
        .or_else(|| std::env::var("DPC_JUGADOR").ok())?;
    raw.trim().parse::<u32>().ok().filter(|n| *n <= MAX_JUGADOR)
}

#[cfg(test)]
mod tests {
    use super::parse_jugador;

    fn p(args: &[&str]) -> Option<u32> {
        parse_jugador(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn argumento_jugador() {
        assert_eq!(p(&["--jugador", "1"]), Some(1));
        assert_eq!(p(&["--jugador=0"]), Some(0));
        assert_eq!(p(&["x", "--jugador", "19"]), Some(19));
        assert_eq!(p(&["--jugador", "20"]), None);
        assert_eq!(p(&["--jugador", "-1"]), None);
        assert_eq!(p(&["--jugador", "uno"]), None);
        assert_eq!(p(&["--jugadorx=1"]), None);
    }
}
