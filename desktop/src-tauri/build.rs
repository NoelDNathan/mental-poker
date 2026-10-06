// Declara el comando de la app en un app manifest: tauri-build genera los
// permisos `allow-precompute-fill` / `deny-precompute-fill`, de modo que el
// comando NO es invocable por defecto y la capability (capabilities/default.json)
// tiene que concederlo de forma explicita. Como la pagina es REMOTA
// (http://localhost:3000), esto es lo que acota lo que puede llamar al nativo.
fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(&["precompute_fill"])),
    )
    .expect("fallo en tauri-build");
}
