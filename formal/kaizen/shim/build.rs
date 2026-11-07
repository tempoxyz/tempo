//! Compiles the Lean-extracted follower core (Kaizen stage II output) and links the Lean runtime.
use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let lean_dir = PathBuf::from(
        env::var("KAIZEN_LEAN_DIR")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/..").to_string()),
    );
    println!("cargo::rerun-if-env-changed=KAIZEN_LEAN_DIR");
    println!("cargo::rerun-if-changed=glue.c");

    // Module closure of Kaizen.FFI restricted to this package (Init/Std come from libleanshared).
    let mut todo = vec!["Kaizen.FFI".to_string()];
    let mut mods: Vec<String> = Vec::new();
    while let Some(m) = todo.pop() {
        if mods.contains(&m) {
            continue;
        }
        let src = lean_dir.join(format!("{}.lean", m.replace('.', "/")));
        println!("cargo::rerun-if-changed={}", src.display());
        let text = fs::read_to_string(&src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
        for line in text.lines() {
            let line = line.trim_start_matches("public ").trim();
            if let Some(rest) = line.strip_prefix("import ") {
                for dep in rest.split_whitespace() {
                    assert!(
                        !dep.starts_with("Mathlib"),
                        "{m} imports {dep}: the FFI closure must stay Mathlib-free"
                    );
                    if dep.starts_with("Kaizen") {
                        todo.push(dep.to_string());
                    }
                }
            }
        }
        mods.push(m);
    }

    let targets: Vec<String> = mods.iter().map(|m| format!("+{m}:c")).collect();
    let status = Command::new("lake")
        .arg("build")
        .args(&targets)
        .current_dir(&lean_dir)
        .status()
        .expect("run lake");
    assert!(status.success(), "lake build of the Lean C targets failed");

    let prefix = String::from_utf8(
        Command::new("lean")
            .arg("--print-prefix")
            .current_dir(&lean_dir)
            .output()
            .expect("lean")
            .stdout,
    )
    .unwrap();
    let prefix = PathBuf::from(prefix.trim());

    let ffi_c = lean_dir.join(".lake/build/ir/Kaizen/FFI.c");
    let ffi_text = fs::read_to_string(&ffi_c).expect("FFI.c");
    let init_fn = ffi_text
        .lines()
        .find_map(|l| {
            let l = l.strip_prefix("LEAN_EXPORT lean_object* ")?;
            let name = l.split('(').next()?;
            (name.starts_with("initialize_") && name.ends_with("Kaizen_FFI"))
                .then(|| name.to_string())
        })
        .expect("FFI.c has a module initializer");

    let mut build = cc::Build::new();
    build
        .include(prefix.join("include"))
        .define("KZ_INIT_FN", init_fn.as_str())
        .flag("-w")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-unused-label")
        .flag("-Wno-unused-but-set-variable")
        .file("glue.c");
    for m in &mods {
        build.file(lean_dir.join(format!(".lake/build/ir/{}.c", m.replace('.', "/"))));
    }
    build.compile("kaizen_core");

    let libdir = prefix.join("lib/lean");
    println!("cargo::rustc-link-search=native={}", libdir.display());
    println!("cargo::rustc-link-lib=dylib=leanshared");
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", libdir.display());
}
