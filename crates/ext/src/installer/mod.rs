//! Extension lifecycle management: install, update, and remove extensions.

mod error;
mod manifest;
mod platform;
mod skill;
mod verify;

pub(crate) use error::InstallerError;
pub(crate) use manifest::{fetch_manifest_version, is_secure_or_local_manifest_location};
pub(crate) use platform::{
    binary_candidates, check_dir_writable, default_local_bin, executable_name, resolve_from_path,
    set_executable_permissions,
};

use ed25519_dalek::VerifyingKey;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use manifest::{load_manifest, ReleaseBinary};
use platform::platform_binary_name;
use skill::{install_skill, remove_skill};
use verify::{decode_verifying_key, sha256_of_bytes, verify_signature};

pub(crate) fn debug_log(message: &str) {
    if env::var_os("TEMPO_DEBUG").is_some() {
        eprintln!("debug: {message}");
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InstallSource {
    pub(crate) manifest: Option<String>,
    pub(crate) public_key: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Installer {
    pub(crate) bin_dir: PathBuf,
}

#[derive(Debug)]
struct ResolvedInstall {
    src: PathBuf,
    dst: PathBuf,
    skill_url: Option<String>,
    skill_sha256: Option<String>,
    skill_signature: Option<String>,
    verifying_key: VerifyingKey,
    _download_dir: TempDir,
}

impl Installer {
    pub(crate) fn from_env(exe_dir: Option<&Path>) -> Result<Self, InstallerError> {
        let bin_dir = if let Some(home) = env::var_os("TEMPO_HOME") {
            PathBuf::from(home).join("bin")
        } else if let Some(dir) = exe_dir.filter(|d| d.is_dir() && check_dir_writable(d).is_ok())
        {
            dir.to_path_buf()
        } else {
            default_local_bin()?
        };

        Ok(Self { bin_dir })
    }

    pub(crate) fn install(
        &self,
        extension: &str,
        source: &InstallSource,
        dry_run: bool,
        quiet: bool,
    ) -> Result<(), InstallerError> {
        self.ensure_dirs(dry_run)?;

        let resolved = self.resolve_install(extension, source, dry_run, quiet)?;
        self.copy_binary(&resolved, dry_run, quiet)?;

        if let Some(skill_url) = &resolved.skill_url {
            install_skill(
                extension,
                skill_url,
                resolved.skill_sha256.as_deref(),
                resolved.skill_signature.as_deref(),
                &resolved.verifying_key,
                dry_run,
                quiet,
            );
        }

        Ok(())
    }

    pub(crate) fn remove(&self, extension: &str, dry_run: bool) -> Result<(), InstallerError> {
        let binary = format!("tempo-{extension}");
        self.remove_binary(&binary, dry_run)?;
        remove_skill(extension, dry_run);
        Ok(())
    }

    fn resolve_install(
        &self,
        extension: &str,
        source: &InstallSource,
        dry_run: bool,
        quiet: bool,
    ) -> Result<ResolvedInstall, InstallerError> {
        let binary = format!("tempo-{extension}");

        let manifest_loc = source
            .manifest
            .clone()
            .ok_or(InstallerError::MissingReleaseManifest)?;
        if !is_secure_or_local_manifest_location(&manifest_loc) {
            return Err(InstallerError::InsecureManifestUrl(manifest_loc));
        }
        let public_key = source
            .public_key
            .clone()
            .ok_or(InstallerError::MissingReleasePublicKey)?;

        let verifying_key = decode_verifying_key(&public_key)?;
        debug_log(&format!("fetching manifest from {manifest_loc}"));
        let manifest = load_manifest(&manifest_loc)?;
        if !quiet {
            println!("installing {binary} {}", manifest.version);
        }

        let platform_key = platform_binary_name(extension);
        debug_log(&format!("platform key: {platform_key}"));
        let metadata = manifest
            .binaries
            .get(&platform_key)
            .ok_or_else(|| InstallerError::ExtensionNotInManifest(platform_key.to_string()))?;

        let download_dir = TempDir::new()?;
        let src = download_extension(
            &binary,
            metadata,
            &verifying_key,
            download_dir.path(),
            dry_run,
        )?;
        let dst = self.bin_dir.join(executable_name(&binary));

        Ok(ResolvedInstall {
            src,
            dst,
            skill_url: manifest.skill.clone(),
            skill_sha256: manifest.skill_sha256.clone(),
            skill_signature: manifest.skill_signature.clone(),
            verifying_key,
            _download_dir: download_dir,
        })
    }

    fn copy_binary(
        &self,
        resolved: &ResolvedInstall,
        dry_run: bool,
        quiet: bool,
    ) -> Result<(), InstallerError> {
        if dry_run {
            println!(
                "dry-run: install {} -> {}",
                resolved.src.display(),
                resolved.dst.display()
            );
        } else {
            let tmp = resolved.dst.with_extension("tmp");
            fs::copy(&resolved.src, &tmp)?;
            set_executable_permissions(&tmp)?;
            fs::rename(&tmp, &resolved.dst)?;
            if !quiet {
                println!(
                    "installed {} -> {}",
                    resolved.src.display(),
                    resolved.dst.display()
                );
            }
        }

        Ok(())
    }

    fn remove_binary(&self, binary: &str, dry_run: bool) -> Result<(), InstallerError> {
        let path = self.bin_dir.join(executable_name(binary));

        if dry_run {
            println!("dry-run: remove {}", path.display());
        } else if path.exists() {
            fs::remove_file(&path)?;
            println!("removed {}", path.display());
        }

        Ok(())
    }

    fn ensure_dirs(&self, dry_run: bool) -> Result<(), InstallerError> {
        if dry_run {
            println!("dry-run: ensure dir {}", self.bin_dir.display());
            return Ok(());
        }

        fs::create_dir_all(&self.bin_dir)?;
        check_dir_writable(&self.bin_dir)?;
        Ok(())
    }
}

fn download_extension(
    binary: &str,
    metadata: &ReleaseBinary,
    verifying_key: &VerifyingKey,
    download_dir: &Path,
    dry_run: bool,
) -> Result<PathBuf, InstallerError> {
    let dst = download_dir.join(executable_name(binary));

    if dry_run {
        if metadata.signature.is_none() {
            return Err(InstallerError::SignatureMissing(binary.to_string()));
        }
        println!("dry-run: fetch {binary} from {}", metadata.url);
        println!("dry-run: verify signature for {binary}");
        return Ok(dst);
    }

    if metadata.url.starts_with("http://") {
        return Err(InstallerError::InsecureDownloadUrl(metadata.url.clone()));
    }

    if metadata.url.starts_with("https://") {
        let mut response = reqwest::blocking::get(&metadata.url)?.error_for_status()?;
        let mut file = fs::File::create(&dst)?;
        io::copy(&mut response, &mut file)?;
    } else if let Some(path) = metadata.url.strip_prefix("file://") {
        fs::copy(path, &dst)?;
    } else if metadata.url.contains("://") {
        return Err(InstallerError::InsecureDownloadUrl(metadata.url.clone()));
    } else {
        fs::copy(&metadata.url, &dst)?;
    }

    let bytes = fs::read(&dst)?;

    debug_log(&format!("verifying checksum for {binary}"));
    let actual = sha256_of_bytes(&bytes);
    let expected = metadata.sha256.to_lowercase();
    if actual != expected {
        let _ = fs::remove_file(&dst);
        return Err(InstallerError::ChecksumMismatch {
            binary: binary.to_string(),
            expected,
            actual,
        });
    }

    debug_log(&format!("checksum ok for {binary}"));

    let encoded_signature = metadata
        .signature
        .as_deref()
        .ok_or_else(|| InstallerError::SignatureMissing(binary.to_string()))?;
    debug_log(&format!("verifying signature for {binary}"));
    if let Err(err) = verify_signature(binary, &bytes, encoded_signature, verifying_key) {
        let _ = fs::remove_file(&dst);
        return Err(err);
    }

    debug_log(&format!("signature ok for {binary}"));

    Ok(dst)
}
