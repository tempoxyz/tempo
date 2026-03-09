//! Installer: manages extension lifecycle (add/remove), handles release
//! manifest fetching, and verifies downloads with SHA-256 checksums and
//! Ed25519 signatures.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

// Keep in sync with cli/install AGENT_SKILL_DIRS.
const AGENT_SKILL_DIRS: &[(&str, &str, &str)] = &[
    (".agents", ".agents/skills", "universal"),
    (".claude", ".claude/skills", "Claude Code"),
    (".config/agents", ".config/agents/skills", "Amp"),
    (".cursor", ".cursor/skills", "Cursor"),
    (".copilot", ".copilot/skills", "GitHub Copilot"),
    (".codex", ".codex/skills", "Codex"),
    (".gemini", ".gemini/skills", "Gemini CLI"),
    (".config/opencode", ".config/opencode/skills", "OpenCode"),
    (".config/goose", ".config/goose/skills", "Goose"),
    (".windsurf", ".windsurf/skills", "Windsurf"),
    (".codeium/windsurf", ".codeium/windsurf/skills", "Windsurf"),
    (".continue", ".continue/skills", "Continue"),
    (".roo", ".roo/skills", "Roo"),
    (".kiro", ".kiro/skills", "Kiro"),
    (".augment", ".augment/skills", "Augment"),
    (".trae", ".trae/skills", "Trae"),
];

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

#[derive(Debug)]
pub(crate) enum InstallerError {
    Io(io::Error),
    Json(serde_json::Error),
    Network(reqwest::Error),
    HomeDirMissing,
    MissingReleaseManifest,
    MissingReleasePublicKey,
    InsecureManifestUrl(String),
    ReleaseManifestNotFound(String),
    ExtensionNotInManifest(String),
    SignatureMissing(String),
    SignatureFormat {
        field: &'static str,
        details: String,
    },
    SignatureVerificationFailed(String),
    InsecureDownloadUrl(String),
    ChecksumMismatch {
        binary: String,
        expected: String,
        actual: String,
    },

}

impl fmt::Display for InstallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::Network(err) => write!(f, "network error: {err}"),
            Self::HomeDirMissing => write!(f, "home directory not found"),
            Self::MissingReleaseManifest => {
                write!(f, "missing release manifest: pass --release-manifest")
            }
            Self::MissingReleasePublicKey => {
                write!(f, "missing release public key: pass --release-public-key")
            }
            Self::InsecureManifestUrl(value) => {
                write!(
                    f,
                    "insecure release manifest URL: {value} (requires https://, file://, or local path)"
                )
            }
            Self::ReleaseManifestNotFound(value) => {
                write!(f, "release manifest not found: {value}")
            }
            Self::ExtensionNotInManifest(value) => {
                write!(f, "extension metadata missing in release manifest: {value}")
            }
            Self::SignatureMissing(binary) => {
                write!(f, "signature missing in release manifest for {binary}")
            }
            Self::SignatureFormat { field, details } => {
                write!(f, "invalid signature format for {field}: {details}")
            }
            Self::SignatureVerificationFailed(binary) => {
                write!(f, "signature verification failed for {binary}")
            }
            Self::InsecureDownloadUrl(value) => {
                write!(
                    f,
                    "insecure download URL: {value} (requires https://, file://, or local path)"
                )
            }
            Self::ChecksumMismatch {
                binary,
                expected,
                actual,
            } => write!(
                f,
                "checksum mismatch for {binary}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for InstallerError {}

impl From<io::Error> for InstallerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for InstallerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<reqwest::Error> for InstallerError {
    fn from(value: reqwest::Error) -> Self {
        Self::Network(value)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Installer {
    pub(crate) bin_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseManifest {
    version: String,
    binaries: HashMap<String, ReleaseBinary>,
    skill: Option<String>,
    skill_sha256: Option<String>,
    skill_signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReleaseBinary {
    url: String,
    sha256: String,
    signature: Option<String>,
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
    pub(crate) fn from_env() -> Result<Self, InstallerError> {
        let bin_dir = if let Some(home) = env::var_os("TEMPO_HOME") {
            PathBuf::from(home).join("bin")
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

/// Fetch a release manifest and return the version string.
pub(crate) fn fetch_manifest_version(manifest_url: &str) -> Result<String, InstallerError> {
    let manifest = load_manifest(manifest_url)?;
    Ok(manifest.version)
}

fn load_manifest(location: &str) -> Result<ReleaseManifest, InstallerError> {
    let body = if location.starts_with("https://") {
        reqwest::blocking::get(location)?
            .error_for_status()?
            .text()?
    } else if let Some(path) = location.strip_prefix("file://") {
        fs::read_to_string(path)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    } else {
        fs::read_to_string(location)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    };

    Ok(serde_json::from_str(&body)?)
}

pub(crate) fn is_secure_or_local_manifest_location(location: &str) -> bool {
    if location.starts_with("https://") {
        return true;
    }

    if location.starts_with("file://") {
        return true;
    }

    !location.contains("://")
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

fn decode_verifying_key(encoded_key: &str) -> Result<VerifyingKey, InstallerError> {
    let key_bytes =
        BASE64_STANDARD
            .decode(encoded_key)
            .map_err(|err| InstallerError::SignatureFormat {
                field: "release public key",
                details: err.to_string(),
            })?;
    let key_bytes: [u8; 32] =
        key_bytes
            .try_into()
            .map_err(|_| InstallerError::SignatureFormat {
                field: "release public key",
                details: "expected 32-byte Ed25519 key".to_string(),
            })?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|err| InstallerError::SignatureFormat {
        field: "release public key",
        details: err.to_string(),
    })
}

fn decode_signature(encoded_signature: &str) -> Result<Signature, InstallerError> {
    let signature_bytes = BASE64_STANDARD.decode(encoded_signature).map_err(|err| {
        InstallerError::SignatureFormat {
            field: "release signature",
            details: err.to_string(),
        }
    })?;
    let signature_bytes: [u8; 64] =
        signature_bytes
            .try_into()
            .map_err(|_| InstallerError::SignatureFormat {
                field: "release signature",
                details: "expected 64-byte Ed25519 signature".to_string(),
            })?;

    Ok(Signature::from_bytes(&signature_bytes))
}

fn verify_signature(
    binary: &str,
    data: &[u8],
    encoded_signature: &str,
    verifying_key: &VerifyingKey,
) -> Result<(), InstallerError> {
    let signature = decode_signature(encoded_signature)?;

    verifying_key
        .verify(data, &signature)
        .map_err(|_| InstallerError::SignatureVerificationFailed(binary.to_string()))
}

fn sha256_of_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

fn platform_binary_name(extension: &str) -> String {
    let (os, arch) = platform_tuple();
    format!("tempo-{extension}-{os}-{arch}")
}

pub(crate) fn platform_tuple() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86_64") {
        "amd64"
    } else {
        "unknown"
    };

    (os, arch)
}

pub(crate) fn resolve_from_path(binary: &str) -> Option<PathBuf> {
    let path_env = env::var_os("PATH")?;
    let candidates = binary_candidates(binary);

    for dir in env::split_paths(&path_env) {
        for name in &candidates {
            let path = dir.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
    }

    None
}

fn default_local_bin() -> Result<PathBuf, InstallerError> {
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .ok_or(InstallerError::HomeDirMissing)?;
    Ok(PathBuf::from(home).join(".local").join("bin"))
}

pub(crate) fn executable_name(binary: &str) -> String {
    #[cfg(windows)]
    {
        format!("{binary}.exe")
    }
    #[cfg(not(windows))]
    {
        binary.to_string()
    }
}

pub(crate) fn binary_candidates(base: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![format!("{base}.exe"), base.to_string()]
    }
    #[cfg(not(windows))]
    {
        vec![base.to_string()]
    }
}

fn check_dir_writable(dir: &Path) -> Result<(), InstallerError> {
    tempfile::NamedTempFile::new_in(dir).map_err(|err| {
        InstallerError::Io(std::io::Error::new(
            err.kind(),
            format!("directory not writable: {}: {err}", dir.display()),
        ))
    })?;
    Ok(())
}

pub(crate) fn set_executable_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)?;
    }

    Ok(())
}

fn install_skill(
    extension: &str,
    url: &str,
    expected_sha256: Option<&str>,
    encoded_signature: Option<&str>,
    verifying_key: &VerifyingKey,
    dry_run: bool,
    quiet: bool,
) {
    let skill_dir_name = format!("tempo-{extension}");

    if dry_run {
        println!("dry-run: install skill from {url}");
        return;
    }

    let content = match download_skill(url) {
        Ok(content) => content,
        Err(err) => {
            eprintln!("warn: skill download failed for tempo-{extension}: {err}");
            return;
        }
    };

    let skill_name = format!("tempo-{extension} skill");
    match encoded_signature {
        Some(sig) => {
            if let Err(err) = verify_signature(&skill_name, content.as_bytes(), sig, verifying_key)
            {
                eprintln!("warn: {err}, skipping skill install");
                return;
            }
            debug_log(&format!("skill signature ok for tempo-{extension}"));
        }
        None => {
            eprintln!(
                "warn: skill signature missing for tempo-{extension}, skipping skill install"
            );
            return;
        }
    }

    if let Some(expected) = expected_sha256 {
        let actual = sha256_of_bytes(content.as_bytes());
        if actual != expected {
            eprintln!("warn: skill checksum mismatch for tempo-{extension}, skipping");
            return;
        }
        debug_log(&format!("skill checksum ok for tempo-{extension}"));
    }

    let home = match env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        Some(h) => PathBuf::from(h),
        None => {
            eprintln!(
                "warn: skill install skipped for tempo-{extension}: home directory not found"
            );
            return;
        }
    };

    let mut installed_names: Vec<&str> = Vec::new();
    for &(parent_rel, skills_rel, agent_name) in AGENT_SKILL_DIRS {
        let parent = home.join(parent_rel);
        if !parent.is_dir() {
            continue;
        }
        let skill_dir = home.join(skills_rel).join(&skill_dir_name);
        if fs::create_dir_all(&skill_dir).is_err() {
            continue;
        }
        if fs::write(skill_dir.join("SKILL.md"), &content).is_ok() {
            installed_names.push(agent_name);
        }
    }

    if !quiet && !installed_names.is_empty() {
        println!(
            "installed tempo-{extension} skill to {} agent(s): {}",
            installed_names.len(),
            installed_names.join(", ")
        );
    }
}

fn download_skill(url: &str) -> Result<String, InstallerError> {
    debug_log(&format!("downloading skill from {url}"));

    if url.starts_with("https://") {
        Ok(reqwest::blocking::get(url)?.error_for_status()?.text()?)
    } else if let Some(path) = url.strip_prefix("file://") {
        Ok(fs::read_to_string(path)?)
    } else if !url.contains("://") {
        Ok(fs::read_to_string(url)?)
    } else {
        Err(InstallerError::InsecureDownloadUrl(url.to_string()))
    }
}

fn remove_skill(extension: &str, dry_run: bool) {
    let skill_dir_name = format!("tempo-{extension}");

    let home = match env::var_os("HOME").or_else(|| env::var_os("USERPROFILE")) {
        Some(h) => PathBuf::from(h),
        None => return,
    };

    for &(_, skills_rel, _) in AGENT_SKILL_DIRS {
        let skill_dir = home.join(skills_rel).join(&skill_dir_name);
        if skill_dir.is_dir() {
            if dry_run {
                println!("dry-run: remove skill {}", skill_dir.display());
            } else if fs::remove_dir_all(&skill_dir).is_ok() {
                debug_log(&format!("removed skill {}", skill_dir.display()));
            }
        }
    }
}
