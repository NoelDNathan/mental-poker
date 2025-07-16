use neon::prelude::*;

fn hello(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string("hello node"))
}

// Esta función recibe una función JS como argumento y la ejecuta
fn execute_callback(mut cx: FunctionContext) -> JsResult<JsValue> {
    // Extraer la función callback pasada como primer argumento
    let callback = cx.argument::<JsFunction>(0)?;

    // Opcionalmente, obtener más argumentos para pasar al callback
    let arg1 = cx.argument_opt(1);

    // Llamar a la función JavaScript
    let mut call = callback.call_with(&mut cx);
    if let Some(arg) = arg1 {
        call.arg(arg);
    }
    let result = call
        .apply(&mut cx)?;

    Ok(result)
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("hello", hello)?;
    cx.export_function("executeCallback", execute_callback)?;

    Ok(())
}
