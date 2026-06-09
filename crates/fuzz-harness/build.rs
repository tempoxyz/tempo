use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=TEMPO_GIT_REVISION");
    println!("cargo:rustc-check-cfg=cfg(tempo_fuzz_t1a)");

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("fuzz harness lives under crates/");

    let hardforks = repo_root.join("crates/chainspec/src/hardfork.rs");
    println!("cargo:rerun-if-changed={}", hardforks.display());
    if let Ok(source) = std::fs::read_to_string(&hardforks) {
        if source.contains("T1A") {
            println!("cargo:rustc-cfg=tempo_fuzz_t1a");
        }
    }
}
