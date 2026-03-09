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

pub(super) fn http_client() -> Result<reqwest::blocking::Client, InstallerError> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()?)
}

/// Parse a `file://` URL into a local path using the `url` crate.
///
/// Returns `None` if the URL isn't a valid `file://` URL or can't be
/// converted to a platform path (e.g. `file://remote/share` on Windows).
pub(super) fn file_url_to_path(url_str: &str) -> Option<PathBuf> {
    url::Url::parse(url_str)
        .ok()
        .filter(|u| u.scheme() == "file")
        .and_then(|u| u.to_file_path().ok())
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
    /// Path to the downloaded binary. `None` in dry-run mode.
    src: Option<PathBuf>,
    dst: PathBuf,
    skill_url: Option<String>,
    skill_sha256: Option<String>,
    skill_signature: Option<String>,
    public_key: PublicKey,
    _download_dir: TempDir,
}

/// The fallback install directory: `TEMPO_HOME/bin` if set, else `~/.local/bin`.
pub(crate) fn fallback_bin_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("TEMPO_HOME") {
        Some(PathBuf::from(home).join("bin"))
    } else {
        default_local_bin().ok()
    }
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

    pub(crate) fn install(
        &self,
        extension: &str,
        source: &InstallSource,
        dry_run: bool,
        quiet: bool,
    ) -> Result<(), InstallerError> {
        self.install_inner(extension, source, None, dry_run, quiet)
    }

    /// Install an extension only if the manifest version is newer than
    /// `installed_version`. Returns `Some(new_version)` if an update was
    /// performed, `None` if already at the latest version.
    pub(crate) fn install_if_changed(
        &self,
        extension: &str,
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

        // Only update if the manifest version is strictly newer. This
        // prevents downgrade attacks where a stale manifest could force
        // installation of an older version with known vulnerabilities.
        if let Some(installed) = installed_version {
            if let (Ok(installed_v), Ok(manifest_v)) = (
                semver::Version::parse(installed.strip_prefix('v').unwrap_or(installed)),
                semver::Version::parse(
                    manifest
                        .version
                        .strip_prefix('v')
                        .unwrap_or(&manifest.version),
                ),
            ) {
                if manifest_v <= installed_v {
                    return Ok(None);
                }
            } else if installed == manifest.version {
                // Fallback for non-semver versions: only skip if identical.
                return Ok(None);
            }
        }

        let version = manifest.version.clone();
        self.install_inner(extension, source, Some(manifest), false, true)?;
        Ok(Some(version))
    }

    fn install_inner(
        &self,
        extension: &str,
        source: &InstallSource,
        manifest: Option<ReleaseManifest>,
        dry_run: bool,
        quiet: bool,
    ) -> Result<(), InstallerError> {
        self.ensure_dirs(dry_run)?;

        let resolved = self.resolve_install(extension, source, manifest, dry_run, quiet)?;
        self.copy_binary(&resolved, dry_run, quiet)?;

        if let Some(skill_url) = &resolved.skill_url {
            install_skill(
                extension,
                skill_url,
                resolved.skill_sha256.as_deref(),
                resolved.skill_signature.as_deref(),
                &resolved.public_key,
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
            metadata,
            &public_key_parsed,
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
            public_key: public_key_parsed,
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
            println!("dry-run: install -> {}", resolved.dst.display());
            return Ok(());
        }

        let src = resolved
            .src
            .as_ref()
            .expect("src must exist after download");
        let tmp = resolved.dst.with_extension("tmp");
        fs::copy(src, &tmp)?;
        if let Err(err) = set_executable_permissions(&tmp) {
            let _ = fs::remove_file(&tmp);
            return Err(err.into());
        }
        if let Err(err) = fs::rename(&tmp, &resolved.dst) {
            let _ = fs::remove_file(&tmp);
            return Err(err.into());
        }
        if !quiet {
            println!("installed {} -> {}", src.display(), resolved.dst.display());
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
    platform_key: &str,
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
    } else if metadata.url.contains("://") {
        return Err(InstallerError::InsecureDownloadUrl(metadata.url.clone()));
    } else {
        fs::copy(&metadata.url, &dst)?;
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
    let expected_comment = format!("file:{platform_key}");
    if let Err(err) = verify_signature(
        binary,
        &bytes,
        encoded_signature,
        public_key,
        Some(&expected_comment),
    ) {
        let _ = fs::remove_file(&dst);
        return Err(err);
    }

    tracing::debug!("signature ok for {binary}");

    Ok(Some(dst))
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
}
