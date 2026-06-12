//! Reads and verifies externally stored conformance fixture archives.

use std::{
    env,
    ffi::OsStr,
    fs,
    fs::File,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};

fn main() {
    if let Err(error) = run() {
        eprintln!("::error::{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os();
    let program = args
        .next()
        .and_then(|arg| PathBuf::from(arg).file_name().map(|name| name.to_owned()))
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| "conformance-fixture-archive".to_string());

    if args.next().as_deref() != Some(OsStr::new("verify-unpack")) {
        return Err(usage(&program).into());
    }

    let archive_ref = args
        .next()
        .and_then(|arg| arg.into_string().ok())
        .ok_or_else(|| usage(&program))?;
    let archive_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| usage(&program))?;
    if args.next().is_some() {
        return Err(usage(&program).into());
    }
    verify_and_unpack(&archive_ref, &archive_path, Path::new("."))?;

    Ok(())
}

fn usage(program: &str) -> String {
    format!("usage: {program} verify-unpack <archive-ref> <archive.tar.zst>")
}

fn verify_and_unpack(
    archive_ref: &str,
    archive_path: &Path,
    out_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_sha = archive_ref
        .strip_suffix(".tar.zst")
        .ok_or("fixture archive ref must end in .tar.zst")?;
    validate_sha256(expected_sha)?;

    let actual_sha = sha256_file(archive_path)?;
    if actual_sha != expected_sha {
        return Err(format!(
            "conformance fixture archive checksum mismatch: expected={expected_sha} actual={actual_sha}"
        )
        .into());
    }

    let fixture_dir = out_dir.join("fixtures").join("block");
    match fs::remove_dir_all(&fixture_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to remove existing fixture directory {}: {err}",
                fixture_dir.display()
            )
            .into());
        }
    }
    fs::create_dir_all(out_dir.join("fixtures"))?;

    let archive_file = File::open(archive_path)?;
    let decoder = zstd::Decoder::new(archive_file)?;
    let mut archive = tar::Archive::new(decoder);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        validate_archive_path(&entry_path)?;
        if is_metadata_file(&entry_path) {
            continue;
        }
        entry.unpack_in(out_dir)?;
    }

    if !fixture_dir.is_dir() {
        return Err("fixture archive did not create fixtures/block".into());
    }

    println!("verified conformance fixture archive");
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid fixture archive sha256: {value}").into());
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 64];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_archive_path(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(
                    format!("fixture archive contains unsafe path: {}", path.display()).into(),
                );
            }
        }
    }
    Ok(())
}

fn is_metadata_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("._") || name.starts_with('.'))
}
