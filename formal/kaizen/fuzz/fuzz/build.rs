//! The Lean runtime is a shared library: give the fuzz binary an rpath to it.
use std::{path::PathBuf, process::Command};

fn main() {
    let lean_dir = std::env::var("KAIZEN_LEAN_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/../..").to_string());
    let out = Command::new("lean")
        .arg("--print-prefix")
        .current_dir(&lean_dir)
        .output()
        .expect("lean");
    let prefix = PathBuf::from(String::from_utf8(out.stdout).unwrap().trim());
    println!(
        "cargo::rustc-link-arg=-Wl,-rpath,{}",
        prefix.join("lib/lean").display()
    );
}
