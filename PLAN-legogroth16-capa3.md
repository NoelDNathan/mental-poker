# Plan capa 3 — prover LegoGroth16 en el wasm_client (rama feature/legogroth16)

Estado: pendiente, sesión dedicada. Las capas 0-2 (lab + contratos) están
hechas y verificadas (smartcontracts: suite diamond 292/292). Este documento
es el plan para integrar el prover lego en el cliente Rust/wasm de WebRTC.

## Lo que hay hoy

- `wasm_client` (en `WebRTC-in-Rust/`) prueba con `CircomProver` del crate
  `zk-reshuffle` (`workspace-ark05/zk-reshuffle`), sobre **arkworks 0.5**
  (`ark-groth16` 0.5, `ark-circom`). Artefactos circom embebidos con
  `include_bytes!` (`new_embedded_shuffle`/`new_embedded_reshuffle`).
- `prove_shuffle(cards)` / `prove_reshuffle(cards)` → `ark_groth16::Proof`,
  serializada y enviada por WebRTC (`ZKProofShuffleProof`,
  `ZKProofRemoveAndRemaskProof`) en `handle_poker_messages.rs`
  (`shuffle_remask_and_send` ~L2019, remove+remask ~L2700).
- El frontend recibe esos bytes y arma la tx on-chain.

## Lo que pide la capa 3

Reemplazar la generación de proof por el flujo LegoGroth16 de DOS proofs
enlazadas (precompute en background + residual en el turno), produciendo el
calldata que esperan los facets nuevos:
`submitPrecompute` + `shufflingCards(_, _, _, LegoLink, pubs)`.

## HALLAZGOS de investigación (2026-06-12) — responden las 2 incógnitas

### Pregunta 1: ¿el witnesscalc soporta los .wasm lego? → SÍ, bajo riesgo. No hay que portar nada.

El prover activo del cliente (`zk_reshuffle::CircomProver`, lib.rs:135) NO usa
el formato `.graph` de witness_calc.rs (eso es código alternativo comentado).
Usa **`ark-circom`** (fork local `circom-compat`): carga el `.wasm` de circom
con `CircomConfig::new_from_bytes(WASM, R1CS)` + `CircomBuilder`, que ejecuta el
witness calculator wasm por su ABI estándar de circom 2.x.

Verificado: los 4 .wasm (shuffling/cancellation actuales del cliente y
shuffling_multiset_lego/card_cancellation_lego del lab) exponen `getVersion`
— el mismo runtime de circom 2.x. Los lego se compilaron con circom 2.2.1,
mismo formato de ABI que los actuales. Si ark-circom carga los de hoy, carga
los lego.

**Lo decisivo (diseño del lab confirmado):** el prover wasm del lab
(`legogroth16-wasm/src/lib.rs`) hace `prove(witness_json, seed)` — RECIBE el
witness ya calculado como JSON de decimales y solo hace el MSM/prove lego. El
witness es un `Vec<Fr>` (decimales), **idéntico en ark 0.4 y ark 0.5** (mismo
campo BN254). Es la frontera limpia entre stacks.

Arquitectura resultante (sin portar sintetizador):
1. el cliente calcula el witness del circuito lego con su ark-circom existente
   (extrayendo el FULL witness, no solo los public inputs);
2. lo serializa a `Vec<String>` decimal;
3. lo pasa al crate `lego-prover` (ark 0.4) que hace el prove cp_link.
Fallback si ark-circom no cargara algún .wasm (improbable): el
`witness_calculator.js` de circom (ya probado en `export-lego-witness.mjs`)
llamado desde Rust/wasm vía js_sys. Tampoco requiere portar nada.

### Pregunta 2: ProtocolMessage → cambio MÍNIMO, no estructural.

`ProtocolMessage` (handle_poker_messages.rs:103) lleva las proofs como
`Vec<u8>` OPACO, troceadas en chunks (`ZKProofShuffleChunk/Proof`,
`ZKProofRemoveAndRemaskChunk/Proof`). La estructura del enum NO depende del
contenido: hoy viaja una proof Groth16 serializada; mañana viajan los bytes
del `LegoLink + pubs`. Las variantes existentes sirven tal cual.

Lo que sí cambia:
- el contenido serializado dentro de esos `Vec<u8>` (de Groth16 plano a
  LegoLink+pubs+proof — definir un struct `serde` y serializar/deserializar);
- añadir el flujo de la PRECOMPUTE: necesita su propio par de mensajes
  (`ZKProofPrecomputeChunk/Proof`) o reusar un canal — DECISIÓN para el usuario;
- el cliente habla con el frontend por **callbacks JS** (`js_sys::Function`
  guardados en `PokerState`, p.ej. `s.set_initial_deck`), no por un enum de
  FrontendMessage. El puente para mandar la proof+link al frontend (para la tx
  on-chain) es un callback JS nuevo análogo a los existentes.

shared-protocol/src/lib.rs NO contiene ProtocolMessage (solo `SignalEnum` del
signalling) → **shared-protocol NO se toca**. Todo vive en wasm_client.

## El obstáculo central: choque de versiones arkworks

`legogroth16` (Dock) vive en **arkworks 0.4**; el cliente usa **0.5**. No se
pueden mezclar tipos `ark_*` de ambas en la misma firma. El repo YA convive
con varias versiones de ark (el Cargo.toml del wasm_client tiene
`ark-ff 0.3`, `ark-groth16 0.5`, y getrandom v2+v3), serializando por BYTES
entre fronteras. Misma estrategia aquí.

### Estrategia recomendada: crate aislado `lego-prover` (ark 0.4)

1. Nuevo crate `workspace-ark05/lego-prover` (o fuera, da igual) con
   **solo ark 0.4 + legogroth16 0.18 + legogroth16-circuit**. Reutiliza
   directamente el código ya probado del lab
   (`zk-bench/native-provers/legogroth16-poc` y `legogroth16-wasm`): NUMS
   gens, setup, prove de las dos proofs, `compute_link_d`, derivación FS.
2. API del crate por BYTES/strings (nada de tipos ark en la frontera):
   ```rust
   // PK + R1CS embebidos (como ya hace legogroth16-wasm con include_bytes!)
   pub fn prove_shuffle_lego(
       deck_old: &[String],   // Ca||Cb actuales (decimales)
       perm: &[u32],          // permutación secreta
       r_prime: &[String],    // escalares (compartidos con la precompute)
       link_v_seed: &[u8],    // blinding compartido entre las 2 proofs
   ) -> LegoProofJson         // {a,b,c,d,link_d,link_pi, pubs} en decimales

   pub fn prove_precompute_lego(r_prime, link_v_seed) -> LegoProofJson
   pub fn prove_reshuffle_lego(...) -> LegoProofJson  // 536 pubs, sin FS
   ```
3. El witness: el lab usa el witness calculator JS para circom y serializa el
   witness completo. En el cliente hay dos opciones:
   - (a) reusar el `witness_calc` que ya tiene `zk-reshuffle` (circom-witnesscalc
     nativo, sin wasmer) — preferible, ya compila a wasm.
   - (b) portar `ProverCircuit` (el sintetizador propio sin wasmer del lab) y
     calcular el witness en Rust desde el R1CS + inputs.
   Decisión en la sesión: empezar por (a) si el witnesscalc del repo soporta
   los circuitos lego nuevos (`shuffling_multiset_lego`, `card_cancellation_lego`).

### Fiat-Shamir del shuffle (α/β)

El shuffle lego necesita `α,β = keccak(tag, link_d, mazos)` ANTES de calcular
el witness (los challenges son inputs del circuito). Flujo commit-then-challenge
en el cliente:
1. calcular `link_d` (MSM de los committed witnesses con link_v) — el crate lo
   expone sin probar.
2. derivar α,β con keccak (usar el mismo orden de bytes que el verifier
   Solidity `deriveChallenges`: `abi.encodePacked(uint8(1), link_d.x, link_d.y,
   pubs)`). En Rust: `tiny-keccak` o `sha3`.
3. inyectar α,β en el input, calcular witness, probar.
El reshuffle NO necesita esto (remask posicional).

## Pasos concretos

- [ ] **3.1** Crear `lego-prover` (ark 0.4 aislado) reusando el código del lab.
  Embeber las 3 PK (shuffle, reshuffle, precompute) y R1CS con `include_bytes!`
  desde `zk-bench` (o copiarlos). Validar con un test nativo que reproduce el
  `link_d` del lab.
- [ ] **3.2** API por bytes + structs `serde` (LegoProofJson). FS keccak con el
  mismo encoding que el verifier on-chain (test cruzado: las pubs+link_d que
  produce deben verificar contra `VerifyShufflingLego`).
- [ ] **3.3** Witness: cablear el witnesscalc del repo a los circuitos lego, o
  portar `ProverCircuit`. Gate: proof generada en el cliente verifica nativa.
- [ ] **3.4** Integrar en `wasm_client`: sustituir `prover_shuffle`/`reshuffle`
  por el flujo lego; pool de precompute (generar la precompute en background al
  entrar en la sala, guardar su `LegoProofJson` cacheada localmente). Mensajes
  WebRTC: un único bundle por turno `{precomputeProof, residualProof, link_d,
  link_pi, pubs}` reutilizando `ZKProofShuffleChunk/Proof` y
  `ZKProofRemoveAndRemaskChunk/Proof` (sin canal nuevo para la precompute, ver
  "DECISIÓN CONFIRMADA"). Cada peer verifica el bundle completo (ZK) al
  recibirlo.
- [ ] **3.5** Build: `lego-prover` debe compilar a wasm32 (ark 0.4 con
  `default-features=false` + parallel en ark-ec/ff/poly, NO la feature `circom`
  de legogroth16 que arrastra wasmer — lección del lab, ver
  `zk-bench/native-provers/legogroth16-wasm`). Rebuild `wasm-pack` multihilo
  (receta: `WASM_PKG_RAYON_BUILD_AND_COPY.md`).
- [ ] **3.6** Medir prove en navegador real (regla del lab): shuffle ~300ms
  esperado, precompute (background) por medir.

## Riesgos / decisiones para preguntar

- ¿El `circom-witnesscalc` del repo soporta los .wasm de los circuitos lego
  nuevos? Si no, hay que portar `ProverCircuit` (más trabajo).
- Tamaño del binario wasm: 3 PK embebidas (la del shuffle son 677 KB; la
  precompute y reshuffle son mayores). Quizá cargar bajo demanda en vez de
  `include_bytes!` si el bundle crece demasiado.
- Confirmar con el usuario el formato exacto de los mensajes WebRTC nuevos
  (ProtocolMessage) — afecta a shared-protocol y al frontend (capa 4).

## DECISIÓN CONFIRMADA — filosofía del protocolo (2026-06-12)

Camino feliz **optimista on-chain** + **verificación ZK fuerte entre pares en
P2P** (se mantiene, no se sustituye por Barnett-Groth nativo por ahora) + la
cadena solo como **árbitro de disputa**. Confirmado por el usuario.

Reglas concretas para capa 3:

1. **P2P — un único bundle lego por barajado/remask**:
   `{precomputeProof, residualProof, link_d, link_pi, pubs/mazo resultante}`.
   La precompute se genera en background pero NO viaja por canal
   independiente — se envía junto con la residual cuando el jugador
   demuestra su movimiento. Sin canal `ZKProofPrecomputeChunk/Proof` separado.
   Cada peer verifica el bundle completo (ZK) igual que hoy con
   `verify_shuffle_remask2`, adaptado al formato lego.

2. **On-chain — camino feliz optimista (NUEVO, fuera del alcance de capa 2)**:
   publicar mazo resultante + firmas/confirmaciones de los jugadores, SIN
   verificar ZK. Análogo en espíritu a `setCommunityCardsOptimistic`, pero
   para el mazo de shuffle/reshuffle. Hoy no existe — es trabajo nuevo en
   `smartcontracts` (candidato a "capa 5", fuera del alcance de esta sesión
   de capa 3, pero a tener en cuenta para no romper compatibilidad).

3. **On-chain — camino de disputa (YA CONSTRUIDO en capa 2)**:
   `submitPrecompute` + `shufflingCards`/`reshufflingCards` (con
   verificación ZK + enlace `link_d`) = árbitro de disputa. No se tira, no
   se modifica; su rol pasa de "cada turno" a "solo cuando hay conflicto".
   El cliente debe mantener cacheadas localmente ambas proofs (precompute +
   residual) del propio jugador para poder usarlas si surge una disputa,
   aunque en el camino feliz no se suban a la cadena.

## ESTADO 3.1-3.4a HECHO (sesión 2026-06-19, gates nativos verdes)

El prover lego está completo y verificado nativo. Crate `lego-prover` (ark 0.4
aislado) + `zk-reshuffle/src/lego.rs` (witness con ark-circom). **ark 0.4 + 0.5
enlazan en el mismo binario** (validado). **Todo compila SOLO con toolchain
msvc** (ark-circom/wasmer no enlaza con gnu por dlltool).

Entry points listos para el wasm_client (zk-reshuffle, ya probados):
- `lego::prove_shuffle_lego_embedded(input: &Value, link_v_seed) -> ProveOutput`
  (doble pasada FS interna; `input` = el `input.json` del shuffle).
- `lego::prove_reshuffle_lego_embedded(input: &Value, link_v_seed) -> ProveOutput`.
- `ProveOutput { proof: LegoProofJson, verified: bool }`. LegoProofJson =
  `{a,b,c,d,link_d,link_pi,pubs}` en decimales (G2 orden EIP-197).

## 3.4b — construcción del input lego (REVERSE-ENGINEERED, listo para ejecutar)

El input del circuito `shuffling_multiset_lego` (de `prototype-lego-circuits.mjs`):
- Públicos: `G, H` (2 coords c/u), `Ca[104], Cb[104]` (52 cartas × 2 coords),
  `alpha, beta` (FS, los deriva el prover en la doble pasada — NO ponerlos).
- Privados: `r_prime_G[104], r_prime_H[104]`, `perm_Ca[104], perm_Cb[104]`.
- Lógica: `Ca_out[i] = perm_Ca[i] + r_prime_G[i]`, `Cb_out[i] = perm_Cb[i] +
  r_prime_H[i]` (remask posicional); multiset check `prod(alpha - cIn) ==
  prod(alpha - cMid)` con cIn de (Ca,Cb) y cMid de (perm_Ca,perm_Cb) prueba que
  perm_* es permutación de (Ca,Cb).

Mapeo desde los args de `shuffle_and_remask2` (barnett-smart-card-protocol,
`discrete_log_cards/mod.rs:562`), que YA computa casi todo:
- `G, H`: `pp.enc_parameters.generator`, `shared_key` → `to_hex` (igual que hoy).
- `Ca, Cb`: del `deck` (igual que hoy, `Ca_list`/`Cb_list`).
- `r_prime_G[i] = r'_i·G`, `r_prime_H[i] = r'_i·H`: YA se calculan hoy como
  `r_prime_G_precomputed`/`r_prime_H_precomputed`.
- `perm_Ca`/`perm_Cb`: NUEVO — aplicar la `permutation` a las listas Ca/Cb
  (`perm_Ca[pos] = Ca[π(pos)]`). El circuito viejo pasaba `permutations`
  (mapping) y permutaba dentro; el lego recibe el resultado permutado.
- NO pasar `r_prime` (escalar) ni `permutations`.

Pasos 3.4b:
1. [HECHO, 2026-06-19] `shuffle_and_remask2_lego` + `remask_for_reshuffle_lego`
   en barnett-smart (trait + impl `DLCards`). Construyen el `serde_json::Value`
   con el mapeo de arriba y delegan en `zk_reshuffle::lego::prove_*_lego_embedded`.
   Devuelven `zk_reshuffle::lego::ProveOutput` (`LegoProofJson` + verified).
   - `zk-reshuffle` re-exporta `ProveOutput`/`LegoProofJson` (frontera de strings).
   - Cargo.toml raíz: `exclude = ["lego-prover"]` (resuelve "multiple workspace
     roots" al construir barnett→zk-reshuffle→lego-prover; lego-prover declara su
     propio `[workspace]` para aislar ark 0.4).
   - GATE NATIVO verde: `tests/lego_shuffle.rs` monta un mazo babyjubjub real de
     52 cartas + permutación + r' y exige que la proof lego AUTO-VERIFIQUE (422
     publics). Valida el mapeo game-state→input, no solo el type-check.
   - Reshuffle (`card_cancellation_lego`): compila; campos cruzados contra el
     fixture real. Su self-verify nativo NO se hizo porque el circuito exige
     inputs CONSISTENTES de estado de juego real (sk/pk/m relacionados, no
     aleatorios) → se valida en navegador (misma tubería que el shuffle).
2. [PARCIAL — verifier-side HECHO y gateado nativo, 2026-06-19] Verificación P2P:
   - `lego-prover`: `LegoProofJson::to_proof()` + `verify_{shuffle,reshuffle}_lego`
     (cp_link + re-derivación FS para el shuffle; bool sin panic). Gate
     `tests/verify_lego.rs`: prove→JSON→verify y rechazo de tamper.
   - `barnett-smart`: `verify_shuffle_remask2_lego(pp, shared_key, previous_deck,
     proof)` verifica el bundle y RECONSTRUYE el mazo resultante desde Ca_out/Cb_out
     (mismo contrato que `verify_shuffle_remask2`). Gate en `tests/lego_shuffle.rs`:
     round-trip prover→verifier→52 cartas + tamper rechazado.
   - PENDIENTE (navegador, wasm_client es wasm32, no type-checkeable en host): el
     GLUE en handle_poker_messages.rs — sustituir las llamadas
     `shuffle_and_remask2`/`remask_for_reshuffle` por las _lego, serializar el
     `LegoProofJson` (`to_json_string`) y enviarlo reusando `ZKProofShuffleProof`/
     `ZKProofRemoveAndRemaskProof` (el bundle YA lleva los pubs dentro → no hacen
     falta los chunks de `public` separados), y en recepción
     (`handle_zk_proof_shuffle_proof_received` ~L1749) deserializar y llamar
     `verify_shuffle_remask2_lego`.
   - DECISIÓN PARA EL USUARIO (capa 4): el callback JS `verify_shuffling`
     (handle_poker_messages ~L2178, vía `format_proof_for_js`) alimenta al frontend
     para la tx on-chain. Con lego debe pasar el `LegoLink + pubs` (ABI nueva de
     capa 2), NO el Groth16. Cambiarlo acopla wasm_client↔frontend → hacerlo junto
     a capa 4.
3. Pool de precompute en background al entrar a la sala (PK 20 MB load-on-demand).
   El bundle confirmado es {precompute, residual, link_d, link_pi, pubs}; hoy solo
   se genera el residual.
4. 3.5 build wasm-pack multihilo; 3.6 medir.

## Capa 4 (depende de la 3)

Frontend Next.js (`frontend-production`): flujo de 2 transacciones
(`submitPrecompute` antes del turno + `shufflingCards`/`reshufflingCards`),
copiar el `pkg-rayon` nuevo, adaptar listeners y ABI (firmas nuevas con
`LegoLink`). Ver `frontend-production/WASM_PKG_RAYON_BUILD_AND_COPY.md`.
