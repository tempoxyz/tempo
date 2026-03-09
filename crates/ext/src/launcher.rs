//! Routes `tempo <extension>` to the right binary, handles auto-install
//! of missing extensions, and provides built-in commands (help, version,
//! add/update/remove).

use crate::installer::{
    InstallSource, Installer, InstallerError, binary_candidates, fallback_bin_dir, find_in_path,
};
use crate::state::State;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BASE_URL: &str = "https://cli.tempo.xyz";
const PUBLIC_KEY: &str = "bDpt6MpqpvjiIPBB2NroGZQ/2HrfV+roj2qUa2b+vjI=";

#[derive(Debug, thiserror::Error)]
pub enum LauncherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("installer error: {0}")]
    Installer(#[from] InstallerError),

    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
}

struct ManagementArgs {
    extension: String,
    version: Option<String>,
    source: InstallSource,
    dry_run: bool,
}

pub fn run(args: Vec<String>) -> Result<i32, LauncherError> {
    let exe_dir = env::current_exe()
        .ok()
        .as_deref()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let launcher = Launcher { exe_dir };

    let first = args.get(1).map(String::as_str).unwrap_or_default();

    match first {
        "add" | "update" | "remove" => launcher.handle_management(first, &args[2..]),
        extension => launcher.handle_extension(extension, &args[2..]),
    }
}

struct Launcher {
    exe_dir: Option<PathBuf>,
}

impl Launcher {
    fn handle_management(&self, action: &str, args: &[String]) -> Result<i32, LauncherError> {
        let parsed = parse_management_args(args)?;

        let installer = Installer::from_env(self.exe_dir.as_deref())?;

        match action {
            "add" | "update" => {
                let source = if parsed.source.manifest.is_none() {
                    InstallSource {
                        manifest: Some(manifest_url(&parsed.extension, parsed.version.as_deref())),
                        public_key: Some(release_public_key()),
                    }
                } else {
                    parsed.source
                };
                installer.install(&parsed.extension, &source, parsed.dry_run, false)?
            }
            "remove" => installer.remove(&parsed.extension, parsed.dry_run)?,
            _ => unreachable!(),
        };

        Ok(0)
    }

    fn handle_extension(
        &self,
        extension: &str,
        extension_args: &[String],
    ) -> Result<i32, LauncherError> {
        if !is_valid_extension_name(extension) {
            print_missing_install_hint(extension);
            return Ok(1);
        }
        tracing::debug!("extension={extension}");
        let binary_name = format!("tempo-{extension}");
        let display_name = format!("tempo {extension}");
        if let Some(binary) = self.find_binary(&binary_name) {
            tracing::debug!("extension found locally: {}", binary.display());
            self.maybe_auto_update(extension);
            return run_child(binary, extension_args, &display_name);
        }

        // Try to auto-install as an extension.
        tracing::debug!("attempting extension auto-install");
        match self.try_auto_install_extension(extension) {
            Ok(Some(binary)) => {
                return run_child(binary, extension_args, &display_name);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!("extension auto-install failed: {err}");
            }
        }

        print_missing_install_hint(extension);
        Ok(1)
    }

    fn try_auto_install_extension(
        &self,
        extension: &str,
    ) -> Result<Option<PathBuf>, LauncherError> {
        let manifest = manifest_url(extension, None);
        tracing::debug!("auto-install manifest={manifest}");

        let binary_name = format!("tempo-{extension}");

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        match installer.install(
            extension,
            &InstallSource {
                manifest: Some(manifest),
                public_key: Some(release_public_key()),
            },
            false,
            false,
        ) {
            Ok(()) => Ok(self.find_binary(&binary_name)),
            Err(InstallerError::ReleaseManifestNotFound(_))
            | Err(InstallerError::ExtensionNotInManifest(_)) => Ok(None),
            Err(InstallerError::Network(err))
                if err.status() == Some(reqwest::StatusCode::NOT_FOUND) =>
            {
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Check for extension updates and install if a newer version is available.
    ///
    /// Runs at most once every 6 hours per extension. Failures are silent —
    /// the existing binary is always used if the update check or install fails.
    fn maybe_auto_update(&self, extension: &str) {
        // TEMPO_HOME indicates a managed or test environment where updates
        // should be explicit (via `tempo update`), not automatic.
        if env::var_os("TEMPO_HOME").is_some() {
            return;
        }

        let mut state = State::load();
        if !state.needs_update_check(extension) {
            return;
        }

        let installed_version = state
            .extensions
            .get(extension)
            .map(|e| e.installed_version.as_str());

        let installer = match Installer::from_env(self.exe_dir.as_deref()) {
            Ok(i) => i,
            Err(_) => {
                state.touch_check(extension);
                state.save();
                return;
            }
        };

        let source = InstallSource {
            manifest: Some(manifest_url(extension, None)),
            public_key: Some(release_public_key()),
        };

        match installer.install_if_changed(extension, &source, installed_version) {
            Ok(Some(new_version)) => {
                if installed_version.is_some_and(|v| !v.is_empty()) {
                    eprintln!("Updated tempo-{extension} to {new_version}");
                }
                state.record_check(extension, &new_version);
            }
            Ok(None) => {
                state.touch_check(extension);
            }
            Err(err) => {
                tracing::debug!("auto-update: failed for {extension}: {err}");
                state.touch_check(extension);
            }
        }
        state.save();
    }

    fn find_binary(&self, binary: &str) -> Option<PathBuf> {
        let candidates = binary_candidates(binary);

        // 1. Check next to the running binary.
        if let Some(dir) = &self.exe_dir {
            for name in &candidates {
                let path = dir.join(name);
                if path.is_file() {
                    return Some(path);
                }
            }
        }

        // 2. Check the fallback install directory (~/.local/bin or
        //    TEMPO_HOME/bin) in case exe_dir wasn't writable when the
        //    extension was installed.
        if let Some(dir) = &fallback_bin_dir()
            && self.exe_dir.as_deref() != Some(dir.as_path())
        {
            for name in &candidates {
                let path = dir.join(name);
                if path.is_file() {
                    return Some(path);
                }
            }
        }

        // 3. Search PATH.
        find_in_path(binary)
    }
}

fn parse_management_args(args: &[String]) -> Result<ManagementArgs, LauncherError> {
    let mut extension = None;
    let mut version = None;
    let mut manifest = None;
    let mut public_key = None;
    let mut dry_run = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--release-manifest" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    LauncherError::InvalidArgs("--release-manifest requires a value".to_string())
                })?;
                manifest = Some(value.clone());
            }
            "--release-public-key" => {
                i += 1;
                let value = args.get(i).ok_or_else(|| {
                    LauncherError::InvalidArgs("--release-public-key requires a value".to_string())
                })?;
                public_key = Some(value.clone());
            }
            "--dry-run" => {
                dry_run = true;
            }
            value if value.starts_with("--") => {
                return Err(LauncherError::InvalidArgs(format!("unknown flag: {value}")));
            }
            name => {
                if extension.is_none() {
                    extension = Some(name.to_string());
                } else if version.is_none() {
                    version = Some(name.to_string());
                } else {
                    return Err(LauncherError::InvalidArgs(
                        "unexpected positional argument".to_string(),
                    ));
                }
            }
        }
        i += 1;
    }

    let extension = extension.ok_or_else(|| {
        LauncherError::InvalidArgs("extension name required (e.g., core, wallet)".to_string())
    })?;

    if !is_valid_extension_name(&extension) {
        return Err(LauncherError::InvalidArgs(format!(
            "invalid extension name: {extension} (only alphanumeric, hyphens, and underscores)"
        )));
    }

    Ok(ManagementArgs {
        extension,
        version,
        source: InstallSource {
            manifest,
            public_key,
        },
        dry_run,
    })
}

fn base_url() -> String {
    env::var("TEMPO_BASE_URL").unwrap_or_else(|_| BASE_URL.to_string())
}

fn release_public_key() -> String {
    env::var("TEMPO_RELEASE_PUBLIC_KEY").unwrap_or_else(|_| PUBLIC_KEY.to_string())
}

fn manifest_url(extension: &str, version: Option<&str>) -> String {
    let base = base_url();
    let base = base.trim_end_matches('/');
    match version {
        Some(v) => {
            let v = v.strip_prefix('v').unwrap_or(v);
            format!("{base}/tempo-{extension}/v{v}/manifest.json")
        }
        None => format!("{base}/tempo-{extension}/manifest.json"),
    }
}

fn run_child(binary: PathBuf, args: &[String], display_name: &str) -> Result<i32, LauncherError> {
    tracing::debug!("exec {} args={args:?}", binary.display());

    let mut cmd = Command::new(&binary);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0(display_name);
    }

    let status = cmd.args(args).status()?;
    let code = status.code().unwrap_or(1);
    Ok(code)
}

fn is_valid_extension_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn print_missing_install_hint(extension: &str) {
    eprintln!("Unknown command '{extension}' and no compatible extension found.");
    eprintln!("Run: tempo add {extension}");
}

#[cfg(test)]
mod tests {
    use super::{is_valid_extension_name, manifest_url, parse_management_args, LauncherError};
    use crate::installer::is_allowed_manifest_url;

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn runtime_manifest_url_policy_enforces_https_or_local() {
        assert!(is_allowed_manifest_url(
            "https://cli.tempo.xyz/tempo-wallet/manifest.json"
        ));
        assert!(is_allowed_manifest_url("file:///tmp/manifest.json"));
        assert!(is_allowed_manifest_url("./manifest.json"));
        assert!(is_allowed_manifest_url("/tmp/manifest.json"));
        assert!(!is_allowed_manifest_url(
            "http://insecure.example.com/manifest.json"
        ));
        assert!(!is_allowed_manifest_url("ftp://example.com/manifest.json"));
    }

    #[test]
    fn manifest_url_uses_expected_format() {
        assert_eq!(
            manifest_url("wallet", None),
            "https://cli.tempo.xyz/tempo-wallet/manifest.json"
        );

        assert_eq!(
            manifest_url("wallet", Some("0.2.0")),
            "https://cli.tempo.xyz/tempo-wallet/v0.2.0/manifest.json"
        );

        assert_eq!(
            manifest_url("wallet", Some("v0.2.0")),
            "https://cli.tempo.xyz/tempo-wallet/v0.2.0/manifest.json",
            "v-prefix should not be doubled"
        );
    }

    #[test]
    fn valid_extension_names() {
        assert!(is_valid_extension_name("wallet"));
        assert!(is_valid_extension_name("my-ext"));
        assert!(is_valid_extension_name("my_ext"));
        assert!(is_valid_extension_name("ext123"));
    }

    #[test]
    fn invalid_extension_names() {
        assert!(!is_valid_extension_name(""));
        assert!(!is_valid_extension_name("../evil"));
        assert!(!is_valid_extension_name("foo/bar"));
        assert!(!is_valid_extension_name("foo bar"));
        assert!(!is_valid_extension_name(".hidden"));
    }

    #[test]
    fn parse_args_extension_only() {
        let result = parse_management_args(&args(&["wallet"])).unwrap();
        assert_eq!(result.extension, "wallet");
        assert_eq!(result.version, None);
        assert!(!result.dry_run);
        assert!(result.source.manifest.is_none());
    }

    #[test]
    fn parse_args_extension_and_version() {
        let result = parse_management_args(&args(&["wallet", "1.0.0"])).unwrap();
        assert_eq!(result.extension, "wallet");
        assert_eq!(result.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn parse_args_with_dry_run() {
        let result = parse_management_args(&args(&["wallet", "--dry-run"])).unwrap();
        assert!(result.dry_run);
    }

    #[test]
    fn parse_args_with_manifest() {
        let result = parse_management_args(&args(&[
            "wallet",
            "--release-manifest",
            "https://example.com/m.json",
        ]))
        .unwrap();
        assert_eq!(
            result.source.manifest,
            Some("https://example.com/m.json".to_string())
        );
    }

    #[test]
    fn parse_args_with_public_key() {
        let result =
            parse_management_args(&args(&["wallet", "--release-public-key", "abc123"])).unwrap();
        assert_eq!(result.source.public_key, Some("abc123".to_string()));
    }

    #[test]
    fn parse_args_missing_extension() {
        let result = parse_management_args(&args(&[]));
        assert!(matches!(result, Err(LauncherError::InvalidArgs(_))));
    }

    #[test]
    fn parse_args_invalid_extension_name() {
        let result = parse_management_args(&args(&["../evil"]));
        assert!(matches!(result, Err(LauncherError::InvalidArgs(_))));
    }

    #[test]
    fn parse_args_unknown_flag() {
        let result = parse_management_args(&args(&["wallet", "--unknown"]));
        assert!(matches!(result, Err(LauncherError::InvalidArgs(_))));
    }

    #[test]
    fn parse_args_manifest_missing_value() {
        let result = parse_management_args(&args(&["wallet", "--release-manifest"]));
        assert!(matches!(result, Err(LauncherError::InvalidArgs(_))));
    }

    #[test]
    fn parse_args_too_many_positional() {
        let result = parse_management_args(&args(&["wallet", "1.0.0", "extra"]));
        assert!(matches!(result, Err(LauncherError::InvalidArgs(_))));
    }
}
