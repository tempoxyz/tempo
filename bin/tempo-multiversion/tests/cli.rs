//! Exercise the actual native launcher, including process replacement. The input binaries
//! are native fixtures, not fork-specialized Tempo nodes.
#![cfg(target_os = "linux")]

use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt as _, process::ExitStatusExt as _},
    path::PathBuf,
    process::Command,
};
use tempo_hardfork::TempoHardfork;
use tempo_multiversion::Bundle;

const CLI: &str = env!("CARGO_BIN_EXE_tempo-multiversion");

struct Fixture {
    _dir: tempfile::TempDir,
    inputs: PathBuf,
    bundle: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let inputs = dir.path().join("inputs");
        fs::create_dir(&inputs).unwrap();
        // Native system executables keep these tests independent of a Rust compiler at runtime.
        // Distinct behavior for T12 lets the test detect accidental latest-version fallback.
        for fork in TempoHardfork::VARIANTS {
            let source = if *fork == TempoHardfork::T12 {
                "/bin/false"
            } else {
                "/bin/echo"
            };
            fs::copy(
                source,
                inputs.join(format!("tempo-{}", fork.to_string().to_ascii_lowercase())),
            )
            .unwrap();
        }
        let bundle = dir.path().join("tempo-bundle");
        Self {
            _dir: dir,
            inputs,
            bundle,
        }
    }

    fn pack(&self) -> std::process::Output {
        Command::new(CLI)
            .args(["pack", "--input-dir"])
            .arg(&self.inputs)
            .arg("--output")
            .arg(&self.bundle)
            .output()
            .unwrap()
    }
}

#[test]
fn packs_inspects_extracts_and_runs_real_executables() {
    let fixture = Fixture::new();
    let output = fixture.pack();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let inspect = Command::new(&fixture.bundle)
        .arg("inspect")
        .output()
        .unwrap();
    assert!(inspect.status.success());
    let listing = String::from_utf8(inspect.stdout).unwrap();
    assert_eq!(listing.lines().count(), TempoHardfork::VARIANTS.len());
    for fork in TempoHardfork::VARIANTS {
        let result = Command::new(&fixture.bundle)
            .args([
                "run",
                &fork.to_string(),
                "--",
                "one argument with spaces",
                "--literal-flag",
            ])
            .output()
            .unwrap();
        if *fork == TempoHardfork::T12 {
            assert_eq!(result.status.code(), Some(1));
        } else {
            assert!(result.status.success());
            assert_eq!(result.stdout, b"one argument with spaces --literal-flag\n");
        }
    }
    let extracted = fixture._dir.path().join("extracted");
    let output = Command::new(&fixture.bundle)
        .args(["extract", "T1B", "--output"])
        .arg(&extracted)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(fs::read(extracted).unwrap(), fs::read("/bin/echo").unwrap());
    // A bundle cannot be recursively wrapped in another bundle.
    let output = Command::new(&fixture.bundle)
        .args(["pack", "--input-dir"])
        .arg(&fixture.inputs)
        .arg("--output")
        .arg(fixture._dir.path().join("nested"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let nested_fixture = Fixture::new();
    fs::copy(&fixture.bundle, nested_fixture.inputs.join("tempo-t12")).unwrap();
    assert!(!nested_fixture.pack().status.success());
    assert!(!nested_fixture.bundle.exists());
}

#[test]
fn preserves_non_utf8_arguments_and_signal_exit() {
    let fixture = Fixture::new();
    // /bin/sh is itself a native ELF fixture; the launcher never interprets a shell command.
    fs::copy("/bin/sh", fixture.inputs.join("tempo-t1a")).unwrap();
    assert!(fixture.pack().status.success());
    let arg = std::ffi::OsStr::from_bytes(b"argument-\xff");
    let result = Command::new(&fixture.bundle)
        .args(["run", "T1", "--"])
        .arg(arg)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert_eq!(result.stdout, b"argument-\xff\n");
    let result = Command::new(&fixture.bundle)
        .args(["run", "T1A", "--", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    assert_eq!(result.status.signal(), Some(15));
}

#[test]
fn corrupt_payload_is_never_executed_or_published() {
    let fixture = Fixture::new();
    assert!(fixture.pack().status.success());
    let bundle = Bundle::open(File::open(&fixture.bundle).unwrap()).unwrap();
    let offset = bundle
        .entries()
        .iter()
        .find(|entry| entry.hardfork == TempoHardfork::T1)
        .unwrap()
        .offset;
    drop(bundle);
    let mut file = File::options()
        .read(true)
        .write(true)
        .open(&fixture.bundle)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&byte).unwrap();
    drop(file);
    let output = Command::new(&fixture.bundle)
        .args(["run", "T1", "--", "MUST-NOT-RUN"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("checksum mismatch"));
    let extracted = fixture._dir.path().join("corrupt");
    assert!(
        !Command::new(&fixture.bundle)
            .args(["extract", "T1", "--output"])
            .arg(&extracted)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!extracted.exists());
}

#[test]
fn rejects_missing_inputs_scripts_mixed_targets_and_existing_output() {
    let fixture = Fixture::new();
    let input = fixture.inputs.join("tempo-t1c");
    let original = fs::read(&input).unwrap();
    fs::remove_file(&input).unwrap();
    assert!(!fixture.pack().status.success());
    assert!(!fixture.bundle.exists());
    fs::write(&input, b"#!/bin/sh\necho not-a-native-executable\n").unwrap();
    assert!(!fixture.pack().status.success());
    assert!(!fixture.bundle.exists());
    let mut wrong_target = original.clone();
    wrong_target[18] ^= 1;
    fs::write(&input, wrong_target).unwrap();
    assert!(!fixture.pack().status.success());
    assert!(!fixture.bundle.exists());
    fs::write(input, original).unwrap();
    fs::write(&fixture.bundle, b"do not replace").unwrap();
    assert!(!fixture.pack().status.success());
    assert_eq!(fs::read(&fixture.bundle).unwrap(), b"do not replace");
}

#[test]
fn launcher_requires_an_explicit_known_fork() {
    let fixture = Fixture::new();
    assert!(fixture.pack().status.success());
    for args in [vec!["run"], vec!["run", "T13"], vec!["node"]] {
        assert!(
            !Command::new(&fixture.bundle)
                .args(args)
                .output()
                .unwrap()
                .status
                .success()
        );
    }
    assert!(
        !Command::new(CLI)
            .args(["run", "T12"])
            .output()
            .unwrap()
            .status
            .success()
    );
}
