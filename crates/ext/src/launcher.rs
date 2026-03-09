//! Routes `tempo <extension>` to the right binary, handles auto-install
//! of missing extensions, and provides built-in commands (help, version,
//! add/update/remove).

use crate::installer::{
    binary_candidates, debug_log, executable_name, fetch_manifest_version, platform_tuple,
    set_executable_permissions, InstallSource, Installer, InstallerError,
};
use crate::state::State;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const BASE_URL: &str = "https://cli.tempo.xyz";
const PUBLIC_KEY: &str = "bDpt6MpqpvjiIPBB2NroGZQ/2HrfV+roj2qUa2b+vjI=";

#[derive(Debug)]
#[allow(unnameable_types, private_interfaces)]
pub enum LauncherError {
    Io(std::io::Error),
    Installer(InstallerError),
    InvalidArgs(String),
}

impl fmt::Display for LauncherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Installer(err) => write!(f, "installer error: {err}"),
            Self::InvalidArgs(err) => write!(f, "invalid arguments: {err}"),
        }
    }
}

impl Error for LauncherError {}

impl From<std::io::Error> for LauncherError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<InstallerError> for LauncherError {
    fn from(value: InstallerError) -> Self {
        Self::Installer(value)
    }
}

struct ManagementArgs {
    extension: String,
    version: Option<String>,
    source: InstallSource,
    dry_run: bool,
}

pub struct Launcher {
    version: String,
    exe_dir: Option<PathBuf>,
}

impl Launcher {
    pub fn new(version: String) -> Self {
        let exe_dir = env::current_exe()
            .ok()
            .as_deref()
            .and_then(|path| path.parent().map(Path::to_path_buf));
        Self { version, exe_dir }
    }

    pub fn run(&self, args: Vec<String>) -> Result<i32, LauncherError> {
        let Some(first) = args.get(1).map(String::as_str) else {
            return self.handle_no_args();
        };

        match first {
            "-h" | "--help" | "help" => {
                self.print_help();
                Ok(0)
            }
            "-V" | "--version" | "version" => {
                println!("tempo {}", self.version);
                Ok(0)
            }
            "add" | "update" | "remove" => self.handle_management(first, &args[2..]),
            extension => self.handle_extension(extension, &args[2..]),
        }
    }

    fn handle_management(&self, action: &str, args: &[String]) -> Result<i32, LauncherError> {
        // `tempo update` with no extension: self-update the tempo binary.
        if action == "update" && args.iter().all(|a| a.starts_with('-')) {
            let dry_run = args.iter().any(|a| a == "--dry-run");
            return self.self_update(dry_run);
        }

        let parsed = parse_management_args(args)?;

        let installer = Installer::from_env()?;

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

    /// Download the latest `tempo` binary from R2 and replace the current one.
    fn self_update(&self, dry_run: bool) -> Result<i32, LauncherError> {
        let (os, arch) = platform_tuple();
        let base = base_url();
        let base = base.trim_end_matches('/');
        let url = format!("{base}/tempo/tempo-{os}-{arch}");

        if dry_run {
            println!("dry-run: download tempo from {url}");
            return Ok(0);
        }

        debug_log(&format!("self-update: downloading from {url}"));
        let installer = Installer::from_env()?;

        let download_dir = tempfile::TempDir::new()?;
        let tmp_path = download_dir.path().join("tempo");

        let mut response = reqwest::blocking::get(&url)
            .map_err(InstallerError::from)?
            .error_for_status()
            .map_err(InstallerError::from)?;
        let mut file = fs::File::create(&tmp_path)?;
        std::io::copy(&mut response, &mut file)?;

        let dst = installer.bin_dir.join(executable_name("tempo"));
        let staging = dst.with_extension("tmp");
        fs::copy(&tmp_path, &staging)?;
        set_executable_permissions(&staging)?;
        fs::rename(&staging, &dst)?;

        println!("Updated tempo");
        Ok(0)
    }

    fn handle_no_args(&self) -> Result<i32, LauncherError> {
        self.print_help();
        Ok(0)
    }

    fn handle_extension(
        &self,
        extension: &str,
        extension_args: &[String],
    ) -> Result<i32, LauncherError> {
        debug_log(&format!("extension={extension}"));
        let binary_name = format!("tempo-{extension}");
        let display_name = format!("tempo {extension}");
        if let Some(binary) = self.find_binary(&binary_name) {
            debug_log(&format!("extension found locally: {}", binary.display()));
            self.maybe_auto_update(extension);
            return run_child(binary, extension_args, &display_name);
        }

        // Try to auto-install as an extension.
        debug_log("attempting extension auto-install");
        match self.try_auto_install_extension(extension) {
            Ok(Some(binary)) => {
                return run_child(binary, extension_args, &display_name);
            }
            Ok(None) => {}
            Err(err) => {
                debug_log(&format!("extension auto-install failed: {err}"));
            }
        }

        print_missing_install_hint(extension);
        Ok(1)
    }

    fn print_help(&self) {
        println!("Tempo CLI {}\n", self.version);
        println!("Usage: tempo <command> [args...]\n");
        println!("Management:");
        println!("  update          Update the tempo launcher itself");
        println!("  add <name>      Install an extension");
        println!("  update <name>   Update an extension");
        println!("  remove <name>   Remove an extension\n");
        println!("Run any installed extension as: tempo <name> [args...]");
        println!("Extensions are auto-installed on first use when available.");
        println!("Run 'tempo node --help' for node commands.");
    }

    fn try_auto_install_extension(
        &self,
        extension: &str,
    ) -> Result<Option<PathBuf>, LauncherError> {
        let manifest = manifest_url(extension, None);
        debug_log(&format!("auto-install manifest={manifest}"));

        let binary_name = format!("tempo-{extension}");

        let installer = Installer::from_env()?;
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

        let url = manifest_url(extension, None);
        let latest_version = match fetch_manifest_version(&url) {
            Ok(v) => v,
            Err(_) => {
                debug_log(&format!(
                    "auto-update: manifest fetch failed for {extension}"
                ));
                state.touch_check(extension);
                state.save();
                return;
            }
        };

        let installed_version = state
            .extensions
            .get(extension)
            .map(|e| e.installed_version.as_str());

        if installed_version != Some(latest_version.as_str()) {
            debug_log(&format!(
                "auto-update: {extension} {old} -> {latest_version}",
                old = installed_version.unwrap_or("(untracked)")
            ));
            if let Ok(installer) = Installer::from_env() {
                let source = InstallSource {
                    manifest: Some(url),
                    public_key: Some(release_public_key()),
                };
                if installer.install(extension, &source, false, true).is_ok()
                    && installed_version.is_some_and(|v| !v.is_empty())
                {
                    eprintln!("Updated tempo-{extension} to {latest_version}");
                }
            }
        }

        state.record_check(extension, &latest_version);
        state.save();
    }

    fn find_binary(&self, binary: &str) -> Option<PathBuf> {
        if let Some(dir) = &self.exe_dir {
            for candidate in &binary_candidates(binary) {
                let path = dir.join(candidate);
                if path.is_file() {
                    return Some(path);
                }
            }
        }

        crate::installer::resolve_from_path(binary)
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
    debug_log(&format!("exec {} args={args:?}", binary.display()));

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

fn print_missing_install_hint(extension: &str) {
    eprintln!("Unknown command '{extension}' and no compatible extension found.");
    eprintln!("Run: tempo add {extension}");
}

#[cfg(test)]
mod tests {
    use super::manifest_url;
    use crate::installer::is_secure_or_local_manifest_location;

    #[test]
    fn runtime_manifest_url_policy_enforces_https_or_local() {
        assert!(is_secure_or_local_manifest_location(
            "https://cli.tempo.xyz/tempo-wallet/manifest.json"
        ));
        assert!(is_secure_or_local_manifest_location(
            "file:///tmp/manifest.json"
        ));
        assert!(is_secure_or_local_manifest_location("./manifest.json"));
        assert!(!is_secure_or_local_manifest_location(
            "http://insecure.example.com/manifest.json"
        ));
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
}
