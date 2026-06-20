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
   - [HECHO shuffle, 2026-06-19] GLUE del SHUFFLE en handle_poker_messages.rs,
     type-checkeado verde a wasm32 (`cargo +stable-msvc check --target
     wasm32-unknown-unknown -p wasm_client`, exit 0):
     * envío (`shuffle_remask_and_send`): `shuffle_and_remask2` →
       `shuffle_and_remask2_lego`; `link_v_seed` aleatorio por ahora (TODO pool
       precompute); self-verify; `to_json_string` → `ZKProofShuffleProof`. Se
       ELIMINÓ el troceado en `ZKProofShuffleChunk` (los pubs viajan dentro del
       bundle). Reconstrucción local con `verify_shuffle_remask2_lego`.
     * recepción (`handle_zk_proof_shuffle_proof_received`): marca
       `is_all_public_shuffle_bytes_received = true` (ya no llegan chunks) y
       dispara la verificación.
     * verificación (`process_shuffle_verification_body`): deserializa
       `LegoProofJson` sin panic (peer no confiable) + `verify_shuffle_remask2_lego`.
   - [HECHO reshuffle, 2026-06-19] VERIFICADOR NATIVO `verify_reshuffle_remask_lego`
     en barnett (trait lib.rs + impl discrete_log_cards/mod.rs). Mismo contrato que
     `verify_reshuffle_remask` clásico (comprueba pk_computed==pk_input==pk, H==
     shared_key, G==generador, las 2 cartas del jugador, m==m_list, Ca/Cb==
     previous_deck, y reconstruye el mazo desde Ca_out/Cb_out) pero desde un
     `LegoProofJson`; ZK vía `zk_reshuffle::lego::verify_reshuffle_lego` (cp_link,
     sin Fiat-Shamir). Layout de los 536 pubs (= verify_reshuffle_remask):
     pk_computed[2]||Ca_out[104]||Cb_out[104]||pk_input[2]||H[2]||G[2]||
     Ca1_player[2]||Cb1_player[2]||Ca2_player[2]||Cb2_player[2]||m[104]||Ca[104]||Cb[104].
     GATE NATIVO VERDE (release, 1.05s) `tests/lego_reshuffle.rs`: round-trip
     `remask_for_reshuffle_lego`→`verify_reshuffle_remask_lego` con mazo babyjubjub
     real → 52 cartas + tamper rechazado. CLAVE: la restricción dura del circuito
     `pk==BabyPbk(sk)` (base BASE8) se cumple porque `prime_subgroup_generator()`
     de este babyjubjub ES BASE8; las comprobaciones de m/cartas NO imponen
     igualdad dura (solo condicionan outputs) → un mazo válido cualquiera prueba.
   - [HECHO reshuffle, 2026-06-19] GLUE del RESHUFFLE en handle_poker_messages.rs,
     type-check wasm32 verde:
     * envío (`send_remask_for_reshuffle`): `remask_for_reshuffle`→`_lego`; devuelve
       el `LegoProofJson` y lo manda en `ZKProofRemoveAndRemaskProof` (sin chunks).
     * recepción (`handle_zk_proof_remove_and_remask_proof_received`): marca
       `is_all_public_reshuffle_bytes_received=true` y procesa.
     * `verify_remask_for_reshuffle`: deserializa el `LegoProofJson` sin panic +
       `verify_reshuffle_remask_lego`.
     * self-verify local en `process_reshuffle_verification` adaptado a `_lego`.
   - DECISIÓN PARA EL USUARIO (capa 4): el callback JS `verify_shuffling`
     (handle_poker_messages ~L2178, vía `format_proof_for_js`) alimenta al frontend
     para la tx on-chain. Con lego debe pasar el `LegoLink + pubs` (ABI nueva de
     capa 2), NO el Groth16. Cambiarlo acopla wasm_client↔frontend → hacerlo junto
     a capa 4.
3. Pool de precompute en background al entrar a la sala (PK 20 MB load-on-demand).
   El bundle confirmado es {precompute, residual, link_d, link_pi, pubs}; hoy solo
   se genera el residual.
   - [HECHO prover nativo, 2026-06-19] `lego_prover::prove_precompute(pk_bytes,
     r1cs_bytes, full_witness, link_v_seed)` + `verify_precompute_lego(proof,
     pk_bytes)` (PK ~20 MB NO embebida, se pasa por bytes = load-on-demand).
     Re-exportados en lego-prover/lib.rs. GATE `lego-prover/tests/precompute_prove.rs`
     (release, ok 8.40s): genera precompute (PK del vendor zk-bench) + residual
     reshuffle con el MISMO `link_v_seed` y EXIGE `precompute.link_d ==
     residual.link_d` (el enlace del pool) + self-verify + tamper rechazado.
     num_public precompute = 5 (G[2],H[2]) → 4 pubs en el JSON.
   - [HECHO a), 2026-06-19] `zk_reshuffle::lego::prove_precompute_lego(input,
        link_v_seed, circom_wasm, circom_r1cs, lego_r1cs, lego_pk)` — frontera
        ark0.5: input = {G,H,r_prime_G,r_prime_H,r_prime}; computa el FULL witness
        con ark-circom (circom .wasm + .r1cs del precompute) y delega en
        `lego_prover::prove_precompute`. NADA embebido (circom r1cs ~10.7 MB + PK
        lego ~20 MB → fetch JS load-on-demand). OJO dos r1cs distintos: el circom
        `.r1cs` (witnesscalc) y el lego `CircuitR1cs .bin` (cp_link). Compila verde
        nativo (msvc). Re-exporta `verify_precompute_lego`.
   - [HECHO c), 2026-06-19] FORMATO DE BUNDLE: struct `LegoBundle {precompute,
        residual}` en `lego-prover/proof_json.rs` (re-exportado por zk-reshuffle).
        `to_json_string` / `from_json_str` (fallible, sin panic para P2P) +
        `links_match()` (precompute.link_d == residual.link_d). Viaja en
        `ZKProofShuffleProof`/`ZKProofRemoveAndRemaskProof` (sin canal nuevo). El
        verificador P2P comprobará: residual verifica (barnett), precompute verifica
        (`verify_precompute_lego`, PK load-on-demand), y `links_match()`. GATE
        rápido verde `lego-prover/tests/bundle.rs` (serde round-trip + link match +
        rechazo de link_d distinto + entrada malformada → None).
   - [HECHO b), 2026-06-19/20, type-check wasm32 verde + build wasm-pack verde]:
        * barnett: `prove_precompute_lego(r_prime, pp, shared_key, link_v_seed,
          circom_wasm, circom_r1cs, lego_r1cs, lego_pk)` (trait + impl DLCards)
          construye el input {G,H,r_prime_G,r_prime_H,r_prime} y delega en
          zk_reshuffle. r_prime escalar→decimal vía parse_and_convert_to_decimal.
        * wasm_client: PokerState {precompute_pool, precompute_artifacts};
          wasm_bindgen `set_precompute_artifacts` + `generate_precompute`; la cripto
          en `build_precompute_entry` (compartida con el fallback en-caliente);
          consumo por turno con `take_or_make_precompute` (reutiliza r_prime+seed en
          shuffle/remask _lego); `LegoBundle{precompute,residual}` enviado en el
          mismo mensaje; verificador `verify_bundle_precompute` (links_match +
          verify_precompute_lego con PK cacheada). Deserializa sin panic.
4. 3.5 build wasm-pack multihilo [HECHO 2026-06-20]: `wasm-pack build --target web
   ... -F rayon` (nightly-2024-12-20, RUSTFLAGS atomics+bulk-memory+getrandom
   wasm_js) verde; exports presentes; copiado a frontend-production/public/pkg-rayon
   (wasm ~96 MB, sin cambio relevante de mi parte: la precompute es load-on-demand).
   3.6 medir [HECHO precompute + OPTIMIZADO, 2026-06-20]: bench dev
   `bench_precompute` (wasm_bindgen) mide la precompute SIN partida real
   (shared_key = generadora); `window.__benchPrecompute(n)` en el frontend.
   SPLIT witness/prove (instrumentado en zk-reshuffle/src/lego.rs) reveló que el
   cuello era el PROVE (MSM), no el witness:
     ANTES (MSM single-thread): witness 1.6 s | prove 15.1 s | total 16.8 s.
   CAUSA: la dependencia `lego-prover` en zk-reshuffle NO activaba su feature
   `parallel` (ark 0.4 ark-ec/ff/poly/std parallel) → la MSM no usaba el pool de
   rayon (que sí estaba inicializado). FIX: `features = ["parallel"]`.
     AHORA (8 hilos): witness 0.55 s | prove 4.85 s | total ~5.4 s (warm, estable).
   El prove cayó ~3.1× (no 8×: MSM memory-bound + cores compartidos VM cloud +
   overhead wasm-bindgen-rayon; en máquina dedicada bajará más). Residual: timing
   añadido (info! "[timing] residual {shuffle,reshuffle} prove"), se ve en partida
   real (necesita joint_pk). Fetch de los 4 artefactos (~43 MB): ~0.5 s.

### Fontanería del pool en el frontend [HECHO 2026-06-20] (parte de capa 4)
- `frontend-production/public/precompute/`: los 4 artefactos copiados (gitignored
  bajo `public`, ~43 MB): precompute_circom.wasm, precompute_circom.r1cs,
  precompute_pk.bin, precompute_lego.r1cs.
- `src/services/precompute/PrecomputePool.ts`: `loadPrecomputeArtifacts` (fetch
  paralelo + `set_precompute_artifacts`, memoizado), `fillPrecomputePool` (llama
  `generate_precompute` hasta target=2, cede el hilo entre proofs), `preparePool`.
- `src/hooks/usePokerWasm.ts`: dispara `preparePrecomputePool` en el callback
  `set_joint_pk` (se invoca para TODOS los jugadores justo al fijarse joint_pk,
  antes del turno de shuffle) + refill en `resetForNewGame`. `wasm.d.ts` extendido.
  tsc limpio en los archivos nuevos (los 10 errores de tsc son preexistentes en
  otros archivos).
- FALTA de capa 4: el callback `verify_shuffling` debe pasar `LegoLink + pubs`
  (ABI capa 2) al frontend para las 2 tx on-chain; medición en navegador (3.6).

## Capa 4 (depende de la 3)

Frontend Next.js (`frontend-production`): flujo de 2 transacciones
(`submitPrecompute` antes del turno + `shufflingCards`/`reshufflingCards`),
copiar el `pkg-rayon` nuevo, adaptar listeners y ABI (firmas nuevas con
`LegoLink`). Ver `frontend-production/WASM_PKG_RAYON_BUILD_AND_COPY.md`.
