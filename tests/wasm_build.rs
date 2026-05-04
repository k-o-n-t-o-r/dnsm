//! Verifies the library compiles for wasm32-unknown-unknown.
//! Catches issues like missing imports in the #[cfg(target_arch = "wasm32")] module.

use std::process::Command;

#[test]
fn wasm_target_compiles() {
    let has_target = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("wasm32-unknown-unknown"))
        .unwrap_or(false);

    if !has_target {
        eprintln!("skipping: wasm32-unknown-unknown target not installed");
        return;
    }

    let status = Command::new("cargo")
        .args([
            "check",
            "--lib",
            "--target",
            "wasm32-unknown-unknown",
            "--no-default-features",
        ])
        .status()
        .expect("run cargo check");

    assert!(
        status.success(),
        "cargo check --lib --target wasm32-unknown-unknown failed"
    );
}
