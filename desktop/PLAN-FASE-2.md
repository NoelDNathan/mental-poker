# App de escritorio — Fase 2 (plan, 2026-10-08)

Fases 0 y 1 cerradas (ver `docs/escritorio-tauri-spike.md` en la raíz del
proyecto): el prover nativo del pool funciona en partida real (−17 % mano 1,
reparto 10→1,9 s). El spike carga la mesa de `http://localhost:3000` (Next dev
del lab), así que **no es distribuible**. La Fase 2 hace una app que funcione
sola, sin romper lo que ya garantiza la versión web (Gates 4–7, WALLET-01/B4).

## Qué dicen los datos (y qué NO se hace todavía)

- El residual de shuffle/reshuffle cuesta 0,1–0,4 s en nativo frente a ~1,8 s
  en wasm bajo carga. Las manos 2–4 las dominan la cadena y el P2P, no las
  pruebas. Portar el núcleo entero a Rust (separar `wasm_client` en lógica +
  transporte, `webrtc-rs`) son semanas con poca ganancia de rendimiento: queda
  como **decisión del usuario (D4)**, no se empieza.
- Lo que sí aporta la Fase 2: una app autocontenida, con el aislamiento del
  Gate 7 intacto, el prover nativo usado **solo por el núcleo** y un canal de
  actualización firmado y anclado al manifiesto del Gate 6.

## Inventario de bloqueos (resumen)

La mesa de Next es una sola página (`/`, sala en `?room=`): sin route
handlers, server actions ni rutas dinámicas. Bloquean `output: "export"`:

1. `src/app/layout.tsx:31` `await headers()` (solo para el nonce de la CSP) y
   `src/proxy.ts` (nonce por petición + CSP).
2. `next.config.mjs` `headers()` (COOP/COEP/CORP, `no-transform` del `.wasm`)
   y `rewrites()` de los workers de rayon (probablemente muertos: apuntan a
   `pkg-rayon`/`pkg-rayon-onchain`, que ya no existen).
3. Orígenes: `engineOrigin()` (`protocol.ts:235`), `originOf()` (`csp.ts:42`)
   y los chequeos de `ev.origin` (EngineClient, `engine/src/main.ts:80`)
   exigen orígenes http(s) serializables. Un esquema propio en macOS/Linux
   da origen `"null"`.
4. Wallet: `APP_WALLETS = [io.metamask]` (`src/constants/wallets.ts:10`). La
   extensión no existe en un webview.
5. `engine/server.mjs` (ruta por contenido `/r/<sha256>/`, cabeceras,
   CORS con eco de la mesa, CSP del núcleo) hay que replicarlo en Rust.
6. Tamaño: solo hacen falta `pkg-rayon-native-*` (wasm 101 MB),
   `precompute/vhyb` (40 MB), `engine-dist` y `release-manifest.json`. `public/`
   tiene ~800 MB de variantes antiguas y symlinks que no deben entrar.

## Arquitectura elegida (decisiones técnicas)

- **Windows primero** (WebView2 = Chromium: SharedArrayBuffer, WebRTC y
  Trusted Types como en Chrome). macOS/Linux = D2.
- **Dos protocolos propios de Tauri, dos orígenes**: `table` y `engine`. En
  WebView2 se sirven como `http://table.localhost` y `http://engine.localhost`,
  que son orígenes http serializables y distintos: el Gate 7 se mantiene
  (vault, K y cartas solo en el origen del núcleo). Sin servidor HTTP local:
  nada escucha en un puerto (no hay squatting de puerto ni otra app que lo
  lea).
- **Los handlers en Rust replican `engine/server.mjs` y `next.config` headers**:
  COOP/COEP/CORP, CSP del núcleo, `/r/<sha256>/` solo si coincide con
  `engine.html`, MIME, `no-transform`, sin path traversal, solo GET/HEAD.
  CORP del núcleo `cross-origin` (los dos `*.localhost` son cross-site) y
  `frame-ancestors http://table.localhost`.
- **CSP de la mesa sin nonce**: el build de escritorio exporta estático y un
  script calcula los SHA-256 de los scripts inline de `out/*.html`; el handler
  sirve la CSP con esos hashes. El build web sigue con nonce (sin cambios).
- **Prover nativo solo desde el núcleo**: el relleno del pool pasa del
  `LocalBackend` de la mesa al host del núcleo (`engine/`). La mesa no tiene
  ningún comando de Tauri. Mecanismo: el protocolo `prover`, que el núcleo llama con `fetch` y cuyo
  handler acepta solo `Origin: http://engine.localhost` (el IPC de Tauri no
  distingue orígenes propios: ver «Resultado del spike 2.0»).
- **Build "desktop"** de mesa y núcleo con su propio manifiesto (los
  orígenes entran en el build y cambian los hashes): se ancla on-chain igual
  que la web (`publishRelease`).

## Resultado del spike 2.0 (2026-10-08): PASA, con un cambio de diseño

App con `DPC_SPIKE_ORIGINS=desktop/spike-origins` y páginas mínimas
(`desktop/spike-origins/{table,engine}`), leída por CDP:

| Prueba | Resultado |
|---|---|
| Orígenes `http://table.localhost` y `http://engine.localhost` | distintos y serializables |
| `crossOriginIsolated` + `SharedArrayBuffer` en los dos | sí |
| Handshake `postMessage` (origen comprobado) + `MessageChannel` | sí |
| La mesa lee el DOM del núcleo | no (bloqueado) |
| Núcleo → protocolo `prover` | 200 |
| Mesa → protocolo `prover` | rechazado por `Origin` (403, sin CORS) |
| IPC de Tauri con capabilities por origen | **no sirve**: ver abajo |

**El IPC de Tauri no puede ser la frontera entre mesa y núcleo.** Tauri trata
como origen "local" cualquier protocolo propio registrado
(`tauri-2.12.1/src/webview/mod.rs:1979`, `is_local_url`), y una capability
con `remote.urls` sigue aplicándose a lo local salvo `local: false`. Con la
capability del núcleo, la mesa también pudo invocar el comando. Decisión:

- Todas las capabilities llevan `"local": false`: la mesa y el núcleo no
  tienen **ningún** comando de Tauri (comprobado: el comando de la app y
  `plugin:app|version` se rechazan por ACL desde los dos orígenes).
- El único canal al nativo es el protocolo `prover`, cuyo handler exige
  `Origin: http://engine.localhost` exacto (sin `Origin`, `null` u otro
  origen: 403 y sin cabeceras CORS). El JS no puede falsificar `Origin`.
- Efecto colateral: el modo de la Fase 1 (mesa en `localhost:3000` invocando
  `precompute_fill` por IPC) queda sin permiso a propósito; lo sustituye el
  bloque 2.3 (prover por el protocolo, desde el núcleo).

## Bloques

| # | Bloque | Quién | Depende de |
|---|---|---|---|
| 2.0 | **Spike de orígenes** (riesgo alto, primero): dos protocolos en WebView2; la mesa (página mínima) embebe el núcleo (página mínima) en iframe; `crossOriginIsolated` en los dos; handshake `postMessage` + `MessageChannel`; el núcleo llama al prover y la mesa NO puede. Compuerta: si falla, servidor HTTP local en puerto aleatorio como plan B | Opus | — |
| 2.1 | Export estático de la mesa con flag `DPC_DESKTOP=1`: `output:"export"`, sin `headers()` en layout, sin proxy; script de hashes CSP; `out/` sin variantes viejas | Sonnet, revisa Opus | 2.0 |
| 2.2 | Handlers Rust `table`/`engine` (port de `server.mjs` + headers de next.config), con tests unitarios (traversal, cabeceras, 404 otra release, MIME, rango/longitud del wasm de 101 MB) | Sonnet, revisa Opus | 2.0 |
| 2.3 | Prover nativo en el núcleo: `fillPrecomputePoolNative` al host del núcleo; capability solo para `engine`; quitar `NEXT_PUBLIC_NATIVE_PROVER` de la mesa y su `connect-src ipc:` | Opus | 2.0 |
| 2.4 | Build y empaquetado: script `desktop-build` (mesa export + núcleo vite con orígenes de escritorio + manifiesto + recursos), instalador NSIS sin firmar | Sonnet, revisa Opus | 2.1, 2.2 |
| 2.5 | E2E de escritorio: Playwright por CDP (como `desktop-native-perf.spec.ts`), mano completa con dos instancias empaquetadas contra el lab | Opus (diagnóstico), Sonnet (corridas) | 2.4 |
| 2.6 | Updater de Tauri firmado + verificación del manifiesto anclado antes de aplicar | Opus | 2.4, D3 |
| 2.7 | Residuales nativos (`prove_shuffle`/`prove_reshuffle` por el mismo canal del prover) — solo si 2.5 muestra que el turno pesa | Sonnet + Opus | 2.5 |

## Decisiones del usuario (2026-10-08)

| # | Decisión | Estado |
|---|---|---|
| D1 | Wallet | **Decidido el objetivo**: registrarse con email (o teléfono/Google) o con MetaMask y jugar sin pop-ups. Diseño en `.wt-secure-frontend/docs/security/CUENTAS-WALLETS-SIN-POPUPS.md`. No bloquea la Fase 2: mientras tanto, wallet dev en el lab |
| D2 | Plataformas | **Solo Windows** por ahora |
| D3 | Firma de código y del updater | Se repiensa más adelante. Mientras: instalador sin firmar, updater apagado |
| D4 | Núcleo nativo completo | Se repiensa más adelante. Mientras: no se empieza |
| D5 | K en el keychain del sistema | Se repiensa más adelante. Mientras: vault del núcleo |
| D6 | Distribución | Se repiensa más adelante. Mientras: solo builds locales |

## Wallet en el lab de escritorio

La wallet dev (`src/dev/gate.ts`) exige `NODE_ENV != production`, y un export
estático es un build de producción. Para probar la app empaquetada contra el
lab hace falta un build "desktop-lab" con la wallet dev. Se hará con un flag
de build propio que **además** exija la cadena del lab (chainId
123412341234), y el build de release lo rechazará (como el canal `lab` del
Gate 6). Es un cambio de seguridad: revisión de Opus y test que pruebe que el
build de release no la incluye.

## Reglas

- Sin push. Commits por bloque. Nada fuera del lab local sin preguntar.
- Fuente de verdad intacta: contrato = fondos, protocolo = cartas, UI =
  orquestación. Tauri no decide nada del juego.
- Nunca registrar `r_prime`, `link_v`, cartas sin revelar ni material de K.

## Estado (2026-10-08)

| Bloque | Estado | Commits |
|---|---|---|
| 2.0 | Hecho | wasm 519cca7 |
| 2.1 | Hecho: export de 6,3 MiB, CSP con 3 hashes | FE b611e7f |
| 2.2 | Hecho | wasm 43c1e10 |
| 2.3 | Hecho | wasm 43c1e10, FE 07a5c26 |
| 2.4 | Hecho: instalador NSIS sin firmar de 63 MiB (`npx @tauri-apps/cli@2.12.1 build` en desktop/src-tauri) | wasm d81160b |
| 2.5 | **VERDE**: `e2e/desktop-app-hand.spec.ts`, 2 instancias empaquetadas, 1 mano en 158 s, aislamiento comprobado, 14 entradas del pool nativas (9–15 s cada una con las dos instancias compitiendo por 8 hilos) | FE (ver git log) |

Cómo se monta (lab):
1. Variables de `desktop-lab.env` (ENGINE_ORIGIN=http://engine.localhost,
   DEV_WALLET=1, DESKTOP_LAB=1, CORE_BETTING=1, NATIVE_PROVER=1, canal lab,
   ENGINE_TABLE_ORIGINS=http://table.localhost, ENGINE_OUT_DIR=engine-dist-desktop).
2. FE: `npx vite build --config engine/vite.config.ts` y `npm run build:desktop-table` (~7 min).
3. `node desktop/scripts/stage-app.mjs --fe ../.wt-secure-frontend --table ../.wt-secure-frontend/out-desktop --engine ../.wt-secure-frontend/engine-dist-desktop --out desktop/stage/app --connect "ws://127.0.0.1:2794 http://127.0.0.1:8545"`.
4. Cada instancia: `DPC_APP_DIR=<stage/app> WEBVIEW2_USER_DATA_FOLDER=<dir propio> WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=922X dpc-desktop.exe`.

Pendiente menor: un 404 de un recurso al cargar la mesa (probablemente el favicon); el registro de seguridad ancla UN solo digest de release, así que web y escritorio no pueden estar anclados a la vez (habrá que anclar un manifiesto conjunto o uno por plataforma).

### 2026-10-11: app reconstruida con la auditoría 2026-10

- Línea segura con la auditoría fusionada (FE `2553e1d`, wasm `3e125f1`/WebRTC `4f7e3d8`).
- Arreglo propio de la app: CSP del núcleo con `blob:` (wasm `66c184b`), necesario desde el #1
  (glue del motor ejecutado desde los bytes verificados). Sin él: `Failed to fetch dynamically
  imported module: blob:...` y el núcleo no arranca.
- `desktop-app-hand` VERDE con dos instancias empaquetadas: mano en 61 s, aislamiento intacto.
  El ticket de sala del #3 (RoomJoin firmado por la wallet dev) funciona en la app.
- Instalador regenerado: `target/release/bundle/nsis/Dog Poker Club Lab_0.2.1_x64-setup.exe`
  (misma versión que el instalado; no se ha reinstalado en el PC).
- El 404 menor ya no aparece (0 respuestas >= 400 al cargar la mesa).
- **Variante LAN BLOQUEADA por el #20**: `networkManifest.ts` exige `http`/`ws` solo en loopback
  y la build LAN usa `http://192.168.1.90:8545` / `ws://...:2794` (el export de Next falla al
  prerender). Pendiente de decisión: permitir IP privadas solo en el canal `lab`, o servir el
  nodo y la señalización por TLS en la red local. El instalador LAN sigue siendo el del 2026-10-08.
- Pendiente de la limpieza de worktrees: si se quita `.wt-secure-*`, actualizar el fallback
  `DIR_ARTEFACTOS_POR_DEFECTO` de `src-tauri/src/prover.rs` y las rutas de este plan.

## Variante de red local (2026-10-08)

Para jugar con otra persona en la misma red: el nodo y la señalización corren
en un PC (Hardhat con `npx hardhat node --hostname 0.0.0.0`; la señalización
ya escucha en 0.0.0.0) y la build apunta a su IP de red.

1. Variables de `desktop-lab.env` cambiando `127.0.0.1` por la IP (p. ej.
   `192.168.1.90`) y `ENGINE_OUT_DIR=engine-dist-lan`; mismas builds de núcleo y mesa.
2. `stage-app.mjs ... --engine ../.wt-secure-frontend/engine-dist-lan --out desktop/stage/app-lan --connect "ws://<IP>:2794 http://<IP>:8545"`.
3. `npx @tauri-apps/cli@2.12.1 build --config tauri.lan.conf.json` → "Dog Poker Club LAN" (otro identificador: convive con la de lab).
4. En el PC del nodo, regla de firewall (admin) para 8545 y 2794 solo desde la subred local.

E2E (`E2E_WS_URL=ws://<IP>:2794`): mano en 51 s con dos instancias por la IP de red.
La IP va dentro de la build: si el router la cambia, hay que regenerarla.
