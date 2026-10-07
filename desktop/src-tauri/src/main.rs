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

    // Con DPC_TABLE_DIR + DPC_ENGINE_DIST + DPC_PUBLIC_DIR (+ DPC_ENGINE_CONNECT)
    // sirven los handlers de `serve/` (port de engine/server.mjs y de las
    // cabeceras de la mesa). Sin ellas, DPC_SPIKE_ORIGINS=<dir con table/ y
    // engine/> mantiene el spike 2.0 (desktop/spike-origins).
    // TODO(2.4): dirs desde resource_dir de Tauri + `desktop-config.json` empaquetado.
    let desktop = serve::DesktopDirs::from_env();
    let spike = std::env::var("DPC_SPIKE_ORIGINS").ok().map(PathBuf::from);
    let origenes_propios = desktop.is_some() || spike.is_some();
    if let Some(dirs) = desktop {
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

    builder
        .setup(move |app| {
            if origenes_propios {
                use tauri::Manager;
                let w = app.get_webview_window("main").ok_or("sin ventana main")?;
                w.navigate(format!("{TABLE_ORIGIN}/").parse()?)?;
                println!("[desktop] mesa en {TABLE_ORIGIN}/");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error al ejecutar la app Tauri");
}
