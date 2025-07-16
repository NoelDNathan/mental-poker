use neon::prelude::*;
use std::sync::Arc;
use std::time::Duration;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // Exportamos la función JavaScript startLoop
    cx.export_function("startLoop", start_loop)?;
    Ok(())
}

// Función accesible desde JS: recibe un callback y arranca el bucle asíncrono
fn start_loop(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    // Obtener el callback de JS y anclarlo para no perderlo
    let js_cb = cx.argument::<JsFunction>(0)?;
    let callback = Arc::new(js_cb.root(&mut cx));
    // Crear el canal para comunicarse con el hilo principal de JS
    let channel = cx.channel();
    // Opcional: permitir que Node termine si no hay más eventos
    // channel.unref(&mut cx);

    // Lanzar un hilo separado (o Tokio) para el bucle asíncrono
    std::thread::spawn(move || {
        // Crear un runtime Tokio para el bucle
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let mut intervalo: tokio::time::Interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                intervalo.tick().await;
                // Obtenemos los datos a enviar (ejemplo: cadena simple)
                let message = "Mensaje desde Rust".to_string();
                let cb = callback.clone();
                // Enviar al hilo de JS usando el canal
                let _ = channel.send(move |mut cx| {
                    // Reconstruir el callback y llamar con el argumento
                    let this = cx.undefined();
                    let js_str = cx.string(message);
                    let args = vec![js_str.upcast::<JsValue>()];
                    cb.to_inner(&mut cx).call(&mut cx, this, args)?;
                    Ok(())
                });
                // Continuar el loop...
            }
        });
    });

    Ok(cx.undefined())
}
