use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=TEMPO_GIT_REVISION");
    println!("cargo:rustc-check-cfg=cfg(tempo_fuzz_t5_channel_reserve)");
    println!("cargo:rustc-check-cfg=cfg(tempo_fuzz_t1a)");
    println!("cargo:rustc-check-cfg=cfg(tempo_fuzz_max_t4)");

    if env::var("TEMPO_GIT_REVISION")
        .is_ok_and(|revision| revision.starts_with("3d70f75485e684a4ed3cf23f140b60c1f7a02a19"))
    {
        println!("cargo:rustc-cfg=tempo_fuzz_max_t4");
    }

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

    for path in [
        "crates/precompiles/src/tip20_channel_reserve/dispatch.rs",
        "crates/contracts/src/precompiles/tip20_channel_reserve.rs",
    ] {
        let path = repo_root.join(path);
        println!("cargo:rerun-if-changed={}", path.display());
        if path.exists() {
            println!("cargo:rustc-cfg=tempo_fuzz_t5_channel_reserve");
            break;
        }
    }
}
