# Gate 0: reproducible WASM baseline

Date checked: 2026-09-23. The browser/runtime dependency graph is locked in
`Cargo.lock`, built with Rust `1.94.0` (defined in `rust-toolchain.toml`), and
all git dependencies are declared in `.gitmodules` so a clean checkout can
recreate the complete workspace.

## Evidence

- `cargo +stable check --locked -p wasm_client --target wasm32-unknown-unknown`
  completed successfully.
- `cargo +stable test --locked -p wasm_client --lib` completed successfully:
  60 passed, 0 failed.
- `cargo +stable check --locked -p signalling-server` completed successfully.
- `cargo +stable audit` loaded 1,264 current RustSec advisories and reported no
  vulnerabilities. `WebRTC-in-Rust/sbom/wasm-client.cdx.json` is the attached
  CycloneDX 1.5 browser-runtime SBOM (518 direct/transitive components).

## Residual dependency risk

The audit has ten non-vulnerability warnings inherited through legacy proving
and tooling dependencies: `async-std`, `atty` (also an unsoundness warning),
`bincode`, `derivative`, `number_prefix`, `paste`, `proc-macro-error2`,
`serde_cbor`, and `memmap2` (also an unsoundness warning). They do not make the
audit fail, but they are not accepted as harmless: Gate 1 records their exposure
and Gate 2 must remove, isolate, or explicitly constrain any package reachable
from the browser security boundary before a value-bearing deployment.

The vendor patches in the root `Cargo.toml` address `RUSTSEC-2025-0055` in the
Arkworks `tracing-subscriber` line. They are source-local compatibility shims,
kept in version control so review and reproduction do not depend on a mutable
registry resolution.
