//! Checks generated conformance fixtures against the local fuzz harness.

use std::{
    env,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};

use tempo_fuzz_harness::{check_conformance_fixture, conformance_fixture_files};

fn main() {
    let fixture_dir = match env::args_os().nth(1) {
        Some(path) => PathBuf::from(path),
        None => workspace_root().join("fixtures").join("block"),
    };

    let fixtures = match conformance_fixture_files(&fixture_dir) {
        Ok(fixtures) => fixtures,
        Err(err) => {
            eprintln!(
                "failed to read conformance fixture directory {}: {err}",
                fixture_dir.display()
            );
            std::process::exit(1);
        }
    };

    if fixtures.is_empty() {
        eprintln!("no conformance fixtures found in {}", fixture_dir.display());
        std::process::exit(1);
    }

    eprintln!(
        "checking {} conformance fixture(s) in {}",
        fixtures.len(),
        fixture_dir.display()
    );

    let stderr_is_tty = io::stderr().is_terminal();
    let mut failures = Vec::new();
    for (index, path) in fixtures.iter().enumerate() {
        if let Err(error) = check_conformance_fixture(path) {
            failures.push((path.clone(), error));
        }
        report_progress(index + 1, fixtures.len(), failures.len(), stderr_is_tty);
    }
    if stderr_is_tty {
        eprintln!();
    }

    if failures.is_empty() {
        eprintln!("conformance fixtures passed");
        return;
    }

    eprintln!("{} conformance fixture(s) failed", failures.len());
    for (path, error) in failures.iter().take(20) {
        eprintln!("  {:?}: {}", error, path.display());
    }
    std::process::exit(1);
}

fn report_progress(checked: usize, total: usize, failures: usize, stderr_is_tty: bool) {
    if stderr_is_tty {
        eprint!("\rchecked {checked}/{total} fixture(s), failures={failures}");
        let _ = io::stderr().flush();
    } else if checked % 10_000 == 0 || checked == total {
        eprintln!("checked {checked}/{total} fixture(s), failures={failures}");
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("fuzz harness crate is under workspace crates/")
        .to_path_buf()
}
