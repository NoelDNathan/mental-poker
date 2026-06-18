# lego-prover

Prover **LegoGroth16 (cp_link)** aislado en **arkworks 0.4** para el cliente de
poker. El `wasm_client` (WebRTC-in-Rust) vive en ark 0.5; este crate expone una
API por **bytes/strings** (decimales de campo, hex de puntos) para que ningun
tipo `ark_*` 0.4 cruce la frontera. Es la estrategia que ya usa el repo para
convivir con varias versiones de ark.

Reusa el codigo ya probado del lab
(`zk-bench/native-provers/legogroth16-{poc,circuit,wasm}`): NUMS hash-to-curve,
`compute_link_d`, `ProverCircuit` (sintetizador sin wasmer), setup/prove cp_link.

## Estado (capa 3 del PLAN-legogroth16-capa3.md)

- [x] **3.1** Maquinaria comun + circuito residual (shuffle). Gate: el `link_d`
  reproduce bit a bit el del lab (`tests/link_d_repro.rs`).
- [x] **3.2** Structs serde (`LegoProofJson`, frontera por bytes/decimales) +
  Fiat-Shamir keccak (`derive_alpha_beta`). Gate: alpha/beta reproducen el
  encoding del verifier Solidity / script del lab (`tests/fs_repro.rs`), y
  `LegoProofJson::from_proof` + round-trip JSON sobre una proof real.
- [ ] **3.3** Witness de los circuitos lego (witnesscalc del repo).
- [ ] **3.4** Integracion en `wasm_client`.
- [ ] **3.5** Build wasm32 multihilo.

## Artefactos (`artifacts/`)

Copiados del lab (formato propio sin wasmer):

- `shuffle_pk.bin` / `shuffle_r1cs.bin`: PK con link + R1CS aplanado del
  residual `shuffling_multiset_lego`.
- `shuffle_witness.json`: witness de ejemplo (para el gate).
- `shuffle_link_d_expected.json`: el `link_d` que exporto el lab
  (`zk-bench/bench-results/legogroth16/link_d.json`), objetivo del gate.

Faltan los del precompute (`rerandomization_precompute_52_lego`) y reshuffle
(`card_cancellation_lego`): se anaden en 3.2/3.3.

## Tests

```bash
cargo test                          # gate link_d (rapido)
cargo test --release -- --ignored   # setup + prove + verify completo
```

## Notas de build

- `legogroth16` con `default-features = false`: evita su feature `circom` ->
  wasmer, que no compila a wasm32 (leccion del lab).
- Workspace propio (no miembro del workspace-ark05): Cargo.lock aislado.
- Feature `parallel`: activa el `parallel` de arkworks (MSM/FFT), NO el de
  legogroth16.
