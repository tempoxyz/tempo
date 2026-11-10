//! Compiles the coverage shim. It is C, not Rust, so the sancov flags in RUSTFLAGS never
//! instrument the callbacks themselves.

fn main() {
    println!("cargo::rerun-if-changed=src/coverage.c");
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    cc::Build::new()
        .file("src/coverage.c")
        .opt_level(3)
        .compile("tempo_antithesis_coverage");
}
