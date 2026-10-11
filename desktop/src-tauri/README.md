# dpc-desktop (spike Tauri v2, Windows)

Spike de app de escritorio cuyo unico papel es generar en NATIVO las entradas del
pool de precompute ZK (`poker-precompute`) y devolverlas al frontend web, que corre
dentro del webview como pagina REMOTA (`http://localhost:3000`, el Next dev del lab).
No contiene logica de juego: contratos = fondos, protocolo/wasm = cartas, UI = orquestacion.

Las entradas llevan secretos (`r_prime`, `link_v`): la app solo imprime tiempos y
contadores (`[native][timing] precompute i/n {ms} ms (hilos=k)`), nunca su contenido.

## Comando IPC

`precompute_fill(target_pk: number[], n: number) -> number[][]`

- `target_pk`: bytes de `encode_key` de la clave conjunta. `n` se acota a 1..=5.
- Un solo relleno a la vez: si hay uno en vuelo devuelve `Err("busy")`.
- Si una entrada falla devuelve las ya generadas (si hay alguna) o el error.
- Desde la pagina: `window.__TAURI_INTERNALS__.invoke("precompute_fill", { targetPk, n })`
  (Tauri convierte `target_pk` a camelCase; pasa `Array.from(bytes)`, no un `Uint8Array`).

## Permisos

El comando esta declarado en un app manifest (`build.rs`), asi que NO es invocable
por defecto. `capabilities/default.json` concede a la ventana `main`, solo para
`http://localhost:3000/*` (remote), `core:default` y `allow-precompute-fill`.

## Compilar y lanzar

Paquete fuera del workspace raiz; su `Cargo.lock` es copia del raiz. Reutiliza el
target del workspace:

```bash
cd desktop/src-tauri
CARGO_TARGET_DIR="<raiz>/mental-poker-reshuffle/target" cargo build --release
# .exe: <target>/release/dpc-desktop.exe
```

Antes de lanzar hay que tener el frontend del lab sirviendo en `http://localhost:3000`
(no hay `frontendDist` empaquetado: ambas URLs de `tauri.conf.json` apuntan alli).

## Variables de entorno

- `DPC_PRECOMPUTE_DIR`: directorio con `precompute_circom.wasm`, `precompute_circom.r1cs`,
  `precompute_pk.bin`, `precompute_lego.r1cs` y `precompute.graph`. Por defecto
  `frontend-production/public/precompute/vhyb`. Se cargan una sola vez, en la primera llamada.
- `DPC_NATIVE_THREADS`: hilos del pool rayon propio (por defecto `available_parallelism`).

## Conducir el webview con Playwright

```powershell
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=9222"
.\dpc-desktop.exe
```

```js
const browser = await chromium.connectOverCDP("http://localhost:9222");
```
