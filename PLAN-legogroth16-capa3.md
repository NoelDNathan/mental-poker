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
  entrar en la sala, guardar su `LegoProofJson`). Mensajes WebRTC: la proof que
  viaja ahora es el `LegoLink` + pubs, no un Groth16 plano.
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

## Capa 4 (depende de la 3)

Frontend Next.js (`frontend-production`): flujo de 2 transacciones
(`submitPrecompute` antes del turno + `shufflingCards`/`reshufflingCards`),
copiar el `pkg-rayon` nuevo, adaptar listeners y ABI (firmas nuevas con
`LegoLink`). Ver `frontend-production/WASM_PKG_RAYON_BUILD_AND_COPY.md`.
