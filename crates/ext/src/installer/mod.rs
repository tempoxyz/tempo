//! Extension lifecycle management: install, update, and remove extensions.

mod error;
mod manifest;
mod platform;
mod skill;
mod verify;

pub use error::InstallerError;
pub(crate) use manifest::is_allowed_manifest_url;
pub(crate) use platform::{binary_candidates, default_local_bin, find_in_path, home_dir};

use manifest::{ReleaseBinary, ReleaseManifest, load_manifest};
use platform::{
    check_dir_writable, executable_name, platform_binary_name, set_executable_permissions,
};
use skill::{install_skill, remove_skill};
use verify::{decode_public_key, sha256_hex, verify_signature};

use minisign_verify::PublicKey;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds an HTTP client with a 30-second timeout for manifest/binary fetches.
pub(super) fn http_client() -> Result<reqwest::blocking::Client, InstallerError> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()?)
}

/// Parses a `file://` URL into a local path using the `url` crate.
///
/// Returns `None` if the URL isn't a valid `file://` URL or can't be
/// converted to a platform path (e.g. `file://remote/share` on Windows).
pub(super) fn file_url_to_path(url_str: &str) -> Option<PathBuf> {
    url::Url::parse(url_str)
        .ok()
        .filter(|u| u.scheme() == "file")
        .and_then(|u| u.to_file_path().ok())
}

/// Where to fetch and verify an extension release from.
#[derive(Debug, Clone)]
pub(crate) struct InstallSource {
    /// URL (or `file://` path) of the signed release manifest JSON.
    pub(crate) manifest: Option<String>,
    /// Base64-encoded minisign public key for signature verification.
    pub(crate) public_key: Option<String>,
}

/// Handles downloading, verifying, and placing extension binaries.
#[derive(Debug, Clone)]
pub(crate) struct Installer {
    /// Directory where extension binaries are installed.
    pub(crate) bin_dir: PathBuf,
}

/// Returned after a successful install with the version and description
/// from the release manifest.
#[derive(Debug, Clone)]
pub(crate) struct InstallResult {
    /// Installed version string (e.g. `"1.0.0"`).
    pub(crate) version: String,
    /// Short description from the release manifest.
    pub(crate) description: String,
}

/// Fully resolved install plan: all paths and verification material ready.
#[derive(Debug)]
struct ResolvedInstall {
    /// Version from the release manifest.
    version: String,
    /// Short description from the release manifest.
    description: String,
    /// Path to the downloaded binary. `None` in dry-run mode.
    src: Option<PathBuf>,
    /// Final destination path in `bin_dir`.
    dst: PathBuf,
    /// Optional URL for the extension's Claude Code skill file.
    skill_url: Option<String>,
    /// Expected SHA-256 hex digest of the skill file.
    skill_sha256: Option<String>,
    /// Base64-encoded minisign signature of the skill file.
    skill_signature: Option<String>,
    /// Decoded public key used for signature verification.
    public_key: PublicKey,
    /// Temp directory holding the download; kept alive until install completes.
    _download_dir: TempDir,
}

impl Installer {
    pub(crate) fn from_env(exe_dir: Option<&Path>) -> Result<Self, InstallerError> {
        let bin_dir = if env::var_os("TEMPO_HOME").is_some() {
            fallback_bin_dir().expect("TEMPO_HOME is set")
        } else if let Some(dir) = exe_dir.filter(|d| d.is_dir() && check_dir_writable(d).is_ok()) {
            dir.to_path_buf()
        } else {
            default_local_bin()?
        };

        Ok(Self { bin_dir })
    }

    /// Installs an extension and returns the installed version and description.
    pub(crate) fn install(
        &self,
        extension: &str,
        source: &InstallSource,
        dry_run: bool,
        quiet: bool,
    ) -> Result<InstallResult, InstallerError> {
        self.install_inner(extension, source, None, dry_run, quiet)
    }

    /// Checks if a newer version is available without installing.
    /// Returns `Some(latest_version)` if the manifest version is strictly
    /// newer, `None` if already up to date.
    pub(crate) fn check_latest_version(
        source: &InstallSource,
        installed_version: Option<&str>,
    ) -> Result<Option<String>, InstallerError> {
        let manifest_loc = source
            .manifest
            .as_ref()
            .ok_or(InstallerError::MissingReleaseManifest)?;
        if !is_allowed_manifest_url(manifest_loc) {
            return Err(InstallerError::InsecureManifestUrl(manifest_loc.clone()));
        }

        let manifest = load_manifest(manifest_loc)?;
        if is_newer(&manifest.version, installed_version) {
            Ok(Some(manifest.version))
        } else {
            Ok(None)
        }
    }

    /// Installs an extension only if the manifest version is newer than
    /// `installed_version`. Returns `Some(result)` if an update was
    /// performed, `None` if already at the latest version.
    pub(crate) fn install_if_changed(
        &self,
        extension: &str,
        source: &InstallSource,
        installed_version: Option<&str>,
    ) -> Result<Option<InstallResult>, InstallerError> {
        let manifest_loc = source
            .manifest
            .as_ref()
            .ok_or(InstallerError::MissingReleaseManifest)?;
        if !is_allowed_manifest_url(manifest_loc) {
            return Err(InstallerError::InsecureManifestUrl(manifest_loc.clone()));
        }

        let manifest = load_manifest(manifest_loc)?;
        if !is_newer(&manifest.version, installed_version) {
            return Ok(None);
        }

        let result = self.install_inner(extension, source, Some(manifest), false, true)?;
        Ok(Some(result))
    }

    /// Shared implementation for `install` and `install_if_changed`.
    fn install_inner(
        &self,
        extension: &str,
        source: &InstallSource,
        manifest: Option<ReleaseManifest>,
        dry_run: bool,
        quiet: bool,
    ) -> Result<InstallResult, InstallerError> {
        self.ensure_dirs(dry_run)?;

        let resolved = self.resolve_install(extension, source, manifest, dry_run, quiet)?;
        let result = InstallResult {
            version: resolved.version.clone(),
            description: resolved.description.clone(),
        };
        self.copy_binary(&resolved, dry_run, quiet)?;

        if let Some(skill_url) = &resolved.skill_url {
            install_skill(
                extension,
                &resolved.version,
                skill_url,
                resolved.skill_sha256.as_deref(),
                resolved.skill_signature.as_deref(),
                &resolved.public_key,
                dry_run,
                quiet,
            );
        }

        Ok(result)
    }

    /// Removes an extension's binary and skill files.
    pub(crate) fn remove(&self, extension: &str, dry_run: bool) -> Result<(), InstallerError> {
        let binary = format!("tempo-{extension}");
        self.remove_binary(&binary, dry_run)?;
        remove_skill(extension, dry_run);
        Ok(())
    }

    /// Fetches the manifest, downloads the binary, and verifies checksums/signatures.
    fn resolve_install(
        &self,
        extension: &str,
        source: &InstallSource,
        pre_manifest: Option<ReleaseManifest>,
        dry_run: bool,
        quiet: bool,
    ) -> Result<ResolvedInstall, InstallerError> {
        let binary = format!("tempo-{extension}");

        let manifest_loc = source
            .manifest
            .clone()
            .ok_or(InstallerError::MissingReleaseManifest)?;
        if !is_allowed_manifest_url(&manifest_loc) {
            return Err(InstallerError::InsecureManifestUrl(manifest_loc));
        }
        let public_key = source
            .public_key
            .clone()
            .ok_or(InstallerError::MissingReleasePublicKey)?;

        let public_key_parsed = decode_public_key(&public_key)?;
        let manifest = match pre_manifest {
            Some(m) => m,
            None => {
                tracing::debug!("fetching manifest from {manifest_loc}");
                load_manifest(&manifest_loc)?
            }
        };
        if !quiet {
            println!("installing {binary} {}", manifest.version);
        }

        let platform_key = platform_binary_name(extension);
        tracing::debug!("platform key: {platform_key}");
        let metadata = manifest
            .binaries
            .get(&platform_key)
            .ok_or_else(|| InstallerError::ExtensionNotInManifest(platform_key.to_string()))?;

        let download_dir = TempDir::new()?;
        let src = download_extension(
            &binary,
            &platform_key,
            &manifest.version,
            metadata,
            &public_key_parsed,
            download_dir.path(),
            dry_run,
        )?;
        let dst = self.bin_dir.join(executable_name(&binary));

        Ok(ResolvedInstall {
            version: manifest.version.clone(),
            description: manifest.description.clone().unwrap_or_default(),
            src,
            dst,
            skill_url: manifest.skill.clone(),
            skill_sha256: manifest.skill_sha256.clone(),
            skill_signature: manifest.skill_signature.clone(),
            public_key: public_key_parsed,
            _download_dir: download_dir,
        })
    }

    /// Atomically places the downloaded binary at its destination path.
    fn copy_binary(
        &self,
        resolved: &ResolvedInstall,
        dry_run: bool,
        quiet: bool,
    ) -> Result<(), InstallerError> {
        if dry_run {
            println!("dry-run: install -> {}", resolved.dst.display());
            return Ok(());
        }

        let src = resolved
            .src
            .as_ref()
            .expect("src must exist after download");
        let dst_dir = resolved
            .dst
            .parent()
            .expect("dst must have a parent directory");
        let mut tmp = tempfile::Builder::new()
            .prefix(".tempo-install-")
            .tempfile_in(dst_dir)?;
        // Write through the open handle to avoid sharing violations on
        // Windows (fs::copy would try to re-open the file for writing).
        let mut src_file = fs::File::open(src)?;
        io::copy(&mut src_file, &mut tmp)?;
        drop(src_file);
        // Set permissions via the open handle before closing to avoid
        // TOCTOU between close and chmod-by-path.
        set_executable_permissions(tmp.as_file())?;
        // Close the file handle; TempPath auto-cleans on drop if
        // persist() is never reached.
        let tmp_path = tmp.into_temp_path();
        // persist() uses atomic rename on Unix and MoveFileEx with
        // MOVEFILE_REPLACE_EXISTING on Windows — handles overwrite on
        // all platforms.
        tmp_path.persist(&resolved.dst).map_err(|e| e.error)?;
        if !quiet {
            println!("installed {} -> {}", src.display(), resolved.dst.display());
        }

        Ok(())
    }

    /// Deletes the named binary from `bin_dir`.
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

    /// Creates `bin_dir` if it doesn't exist and verifies it is writable.
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

/// The fallback install directory: `TEMPO_HOME/bin` if set, else `~/.local/bin`.
pub(crate) fn fallback_bin_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("TEMPO_HOME") {
        Some(PathBuf::from(home).join("bin"))
    } else {
        default_local_bin().ok()
    }
}

/// Downloads an extension binary, verifies its checksum and signature, and
/// returns the path to the verified file in `download_dir`.
fn download_extension(
    binary: &str,
    platform_key: &str,
    version: &str,
    metadata: &ReleaseBinary,
    public_key: &PublicKey,
    download_dir: &Path,
    dry_run: bool,
) -> Result<Option<PathBuf>, InstallerError> {
    if dry_run {
        if metadata.signature.is_none() {
            return Err(InstallerError::SignatureMissing(binary.to_string()));
        }
        println!("dry-run: fetch {binary} from {}", metadata.url);
        println!("dry-run: verify signature for {binary}");
        return Ok(None);
    }

    let dst = download_dir.join(executable_name(binary));

    if metadata.url.starts_with("http://") {
        return Err(InstallerError::InsecureDownloadUrl(metadata.url.clone()));
    }

    if metadata.url.starts_with("https://") {
        let mut response = http_client()?
            .get(&metadata.url)
            .send()?
            .error_for_status()?;
        let mut file = fs::File::create(&dst)?;
        io::copy(&mut response, &mut file)?;
    } else if let Some(path) = file_url_to_path(&metadata.url) {
        fs::copy(path, &dst)?;
    } else {
        return Err(InstallerError::InsecureDownloadUrl(metadata.url.clone()));
    }

    let bytes = fs::read(&dst)?;

    tracing::debug!("verifying checksum for {binary}");
    let actual = sha256_hex(&bytes);
    let expected = metadata.sha256.to_lowercase();
    if actual != expected {
        let _ = fs::remove_file(&dst);
        return Err(InstallerError::ChecksumMismatch {
            binary: binary.to_string(),
            expected,
            actual,
        });
    }

    tracing::debug!("checksum ok for {binary}");

    let encoded_signature = metadata
        .signature
        .as_deref()
        .ok_or_else(|| InstallerError::SignatureMissing(binary.to_string()))?;
    tracing::debug!("verifying signature for {binary}");
    let file_comment = format!("file:{platform_key}");
    let version_comment = format!("version:{version}");
    if let Err(err) = verify_signature(
        binary,
        &bytes,
        encoded_signature,
        public_key,
        &[&file_comment, &version_comment],
    ) {
        let _ = fs::remove_file(&dst);
        return Err(err);
    }

    tracing::debug!("signature ok for {binary}");

    Ok(Some(dst))
}

/// Returns `true` if `manifest_version` is strictly newer than
/// `installed_version`. Uses semver comparison when both parse as
/// semver (with optional `v` prefix). For non-semver strings, returns
/// `true` unless they are identical.
fn is_newer(manifest_version: &str, installed_version: Option<&str>) -> bool {
    let Some(installed) = installed_version else {
        return true;
    };
    if let (Ok(installed_v), Ok(manifest_v)) = (
        semver::Version::parse(installed.strip_prefix('v').unwrap_or(installed)),
        semver::Version::parse(
            manifest_version
                .strip_prefix('v')
                .unwrap_or(manifest_version),
        ),
    ) {
        manifest_v > installed_v
    } else {
        // Non-semver fallback: only skip if identical.
        installed != manifest_version
    }
}

#[cfg(test)]
mod tests {
    use super::file_url_to_path;
    use std::path::Path;

    #[test]
    fn file_url_unix_absolute() {
        let path = file_url_to_path("file:///tmp/manifest.json").unwrap();
        assert_eq!(path, Path::new("/tmp/manifest.json"));
    }

    #[test]
    fn file_url_with_spaces() {
        let path = file_url_to_path("file:///tmp/my%20dir/manifest.json").unwrap();
        assert_eq!(path, Path::new("/tmp/my dir/manifest.json"));
    }

    #[test]
    fn https_url_returns_none() {
        assert!(file_url_to_path("https://example.com/manifest.json").is_none());
    }

    #[test]
    fn bare_path_returns_none() {
        assert!(file_url_to_path("/tmp/manifest.json").is_none());
    }

    #[test]
    fn relative_path_returns_none() {
        assert!(file_url_to_path("./manifest.json").is_none());
    }

    // NOTE: download_extension's URL scheme enforcement (rejecting http:// and
    // unknown schemes) requires a PublicKey and real file I/O, so it is
    // covered by integration tests rather than unit tests here.

    #[test]
    fn is_newer_no_installed_version() {
        assert!(super::is_newer("1.0.0", None));
    }

    #[test]
    fn is_newer_semver_upgrade() {
        assert!(super::is_newer("2.0.0", Some("1.0.0")));
    }

    #[test]
    fn is_newer_semver_same() {
        assert!(!super::is_newer("1.0.0", Some("1.0.0")));
    }

    #[test]
    fn is_newer_semver_downgrade() {
        assert!(!super::is_newer("1.0.0", Some("2.0.0")));
    }

    #[test]
    fn is_newer_strips_v_prefix() {
        assert!(!super::is_newer("1.0.0", Some("v1.0.0")));
        assert!(!super::is_newer("v1.0.0", Some("1.0.0")));
        assert!(super::is_newer("v2.0.0", Some("v1.0.0")));
    }

    #[test]
    fn is_newer_non_semver_same() {
        assert!(!super::is_newer(
            "nightly-2025-01-01",
            Some("nightly-2025-01-01")
        ));
    }

    #[test]
    fn is_newer_non_semver_different() {
        assert!(super::is_newer(
            "nightly-2025-03-09",
            Some("nightly-2025-01-01")
        ));
    }
}
