// Sin comandos de app: el IPC de Tauri no distingue la mesa del nucleo (los
// dos son protocolos propios = origen "local"), asi que la app no expone
// ninguno. El canal al prover nativo es el protocolo `prover` (src/prover.rs).
fn main() {
    tauri_build::build()
}
