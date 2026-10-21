use std::{env, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    if env::var_os("CARGO_FEATURE_RETH").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets the manifest directory"),
    );
    let root = manifest_dir
        .ancestors()
        .find(|dir| {
            dir.join("mainnet-network-identity.json").is_file()
                && dir.join("testnet-network-identity.json").is_file()
        })
        .expect("network identity files must exist at the repository root");

    println!("cargo::rustc-env=TEMPO_REPO_ROOT={}", root.display());
}
