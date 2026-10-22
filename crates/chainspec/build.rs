use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");

    if env::var_os("CARGO_FEATURE_RETH").is_none() {
        return;
    }

    let identities = [
        (
            "TEMPO_MAINNET_NETWORK_IDENTITY",
            "mainnet-network-identity.json",
        ),
        (
            "TEMPO_TESTNET_NETWORK_IDENTITY",
            "testnet-network-identity.json",
        ),
    ];
    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets the manifest directory"),
    );
    let root = manifest_dir
        .ancestors()
        .find(|dir| identities.iter().all(|(_, file)| dir.join(file).is_file()))
        .expect("network identity files must exist at the repository root");

    for (name, file) in identities {
        let path = root.join(file);
        println!("cargo::rerun-if-changed={}", path.display());
        let json = fs::read_to_string(path).expect("network identity file must be readable");
        // Cargo build directives must fit on a single line.
        let json = json.lines().collect::<String>();
        println!("cargo::rustc-env={name}={json}");
    }
}
