//! Routes `tempo <extension>` to the right binary, handles auto-install
//! of missing extensions, and provides built-in commands (add/update/remove).

use crate::{
    installer::{
        InstallSource, Installer, InstallerError, binary_candidates, fallback_bin_dir, find_in_path,
    },
    registry::Registry,
};
use clap::{Parser, Subcommand};
use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
};

const BASE_URL: &str = "https://cli.tempo.xyz";
const PUBLIC_KEY: &str = "RWTtoEUPuapAfh06rC7BZLjm1hG40/lsVAA/2afN88FZ8/Fdk97LzJDf";

#[derive(Debug, thiserror::Error)]
pub enum LauncherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("installer error: {0}")]
    Installer(#[from] InstallerError),

    #[error("invalid arguments: {0}")]
    InvalidArgs(String),
}

/// Extension manager for the Tempo CLI.
#[derive(Parser, Debug)]
#[command(
    name = "tempo",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install an extension.
    Add(ManagementArgs),

    /// Update tempo and/or extensions. Without arguments, updates tempo
    /// itself via tempoup and then updates all installed extensions.
    Update(UpdateArgs),

    /// Remove an extension.
    Remove(RemoveArgs),

    /// List installed extensions.
    List,

    /// External extension subcommand.
    #[command(external_subcommand)]
    Extension(Vec<OsString>),
}

#[derive(Parser, Debug)]
struct ManagementArgs {
    /// Extension name (e.g., wallet, mpp).
    extension: String,

    /// Version to install (e.g., 0.2.0).
    version: Option<String>,

    /// URL of the signed release manifest.
    #[arg(long = "release-manifest")]
    manifest: Option<String>,

    /// Base64-encoded public key for manifest verification.
    #[arg(long = "release-public-key")]
    public_key: Option<String>,

    /// Show what would be done without making changes.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser, Debug)]
struct UpdateArgs {
    /// Extension name. If omitted, updates tempo itself and all installed extensions.
    extension: Option<String>,

    /// Version to install (e.g., 0.2.0). Only valid with an extension name.
    version: Option<String>,

    /// URL of the signed release manifest.
    #[arg(long = "release-manifest")]
    manifest: Option<String>,

    /// Base64-encoded public key for manifest verification.
    #[arg(long = "release-public-key")]
    public_key: Option<String>,

    /// Show what would be done without making changes.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser, Debug)]
struct RemoveArgs {
    /// Extension name (e.g., wallet, mpp).
    extension: String,

    /// Show what would be done without making changes.
    #[arg(long)]
    dry_run: bool,
}

pub fn run<I, T>(args: I) -> Result<i32, LauncherError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let exe_dir = env::current_exe()
        .ok()
        .as_deref()
        .and_then(|path| path.parent().map(Path::to_path_buf));
    let launcher = Launcher { exe_dir };

    let cli =
        Cli::try_parse_from(args).map_err(|err| LauncherError::InvalidArgs(err.to_string()))?;

    match cli.command {
        Commands::Add(args) => launcher.handle_install(args),
        Commands::Update(args) => launcher.handle_update(args),
        Commands::Remove(args) => launcher.handle_remove(&args.extension, args.dry_run),
        Commands::List => launcher.handle_list(),
        Commands::Extension(ext_args) => launcher.handle_extension(ext_args),
    }
}

/// Run `tempoup` to update the tempo binary itself.
///
/// Passes `TEMPO_BIN_DIR` so tempoup installs into the same directory as the
/// running binary. If tempoup is not found on `PATH`, it is installed first
/// via `https://tempo.xyz/install`.
fn run_tempoup(bin_dir: &Path) -> Result<bool, LauncherError> {
    let status = match Command::new("tempoup")
        .env("TEMPO_BIN_DIR", bin_dir)
        .status()
    {
        Ok(s) => s,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            println!("tempoup not found, installing...");
            let install_status = Command::new("sh")
                .arg("-c")
                .arg("curl -fsSL https://tempo.xyz/install | bash")
                .status()?;
            if !install_status.success() {
                eprintln!("failed to install tempoup");
                return Ok(false);
            }
            Command::new("tempoup")
                .env("TEMPO_BIN_DIR", bin_dir)
                .status()?
        }
        Err(err) => return Err(LauncherError::Io(err)),
    };
    Ok(status.success())
}

struct Launcher {
    exe_dir: Option<PathBuf>,
}

impl Launcher {
    fn handle_install(&self, args: ManagementArgs) -> Result<i32, LauncherError> {
        if !is_valid_extension_name(&args.extension) {
            return Err(LauncherError::InvalidArgs(format!(
                "invalid extension name: {} (only alphanumeric, hyphens, and underscores)",
                args.extension
            )));
        }

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        let source = if args.manifest.is_none() {
            InstallSource {
                manifest: Some(manifest_url(&args.extension, args.version.as_deref())),
                public_key: Some(release_public_key()),
            }
        } else {
            InstallSource {
                manifest: args.manifest,
                public_key: args.public_key,
            }
        };
        let pinned = args.version.is_some();
        let version = installer.install(&args.extension, &source, args.dry_run, false)?;
        if !args.dry_run {
            let mut registry = Registry::load();
            registry.record_check(&args.extension, &version, pinned);
            registry.save();
        }
        Ok(0)
    }

    /// Handle `tempo update [extension]`.
    ///
    /// Without an extension name, updates tempo itself via `tempoup` and then
    /// updates all installed extensions. With an extension name, only updates
    /// that extension (and unpins it). With an explicit version, behaves like
    /// `add`.
    fn handle_update(&self, args: UpdateArgs) -> Result<i32, LauncherError> {
        let Some(extension) = args.extension else {
            return self.handle_update_all(args.dry_run);
        };

        if !is_valid_extension_name(&extension) {
            return Err(LauncherError::InvalidArgs(format!(
                "invalid extension name: {extension} (only alphanumeric, hyphens, and underscores)",
            )));
        }

        // Explicit version: user knows what they want, treat like `add`.
        if args.version.is_some() {
            return self.handle_install(ManagementArgs {
                extension,
                version: args.version,
                manifest: args.manifest,
                public_key: args.public_key,
                dry_run: args.dry_run,
            });
        }

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        let source = if args.manifest.is_none() {
            InstallSource {
                manifest: Some(manifest_url(&extension, None)),
                public_key: Some(release_public_key()),
            }
        } else {
            InstallSource {
                manifest: args.manifest,
                public_key: args.public_key,
            }
        };

        let registry = Registry::load();
        let installed_version = registry
            .extensions
            .get(&extension)
            .map(|e| e.installed_version.as_str());

        if args.dry_run {
            println!(
                "dry-run: update {extension} (installed: {})",
                installed_version.unwrap_or("none")
            );
            return Ok(0);
        }

        match installer.install_if_changed(&extension, &source, installed_version)? {
            Some(new_version) => {
                if installed_version.is_some_and(|v| !v.is_empty()) {
                    println!("Updated tempo-{extension} to {new_version}");
                } else {
                    println!("Installed tempo-{extension} {new_version}");
                }
                let mut registry = registry;
                registry.record_check(&extension, &new_version, false);
                registry.save();
            }
            None => {
                println!(
                    "tempo-{extension} is already at the latest version ({})",
                    installed_version.unwrap_or("unknown")
                );
                let mut registry = registry;
                registry.touch_check(&extension);
                registry.save();
            }
        }

        Ok(0)
    }

    /// Update tempo itself via `tempoup`, then update all installed extensions.
    fn handle_update_all(&self, dry_run: bool) -> Result<i32, LauncherError> {
        let installer = Installer::from_env(self.exe_dir.as_deref())?;

        // 1. Update tempo itself via tempoup.
        if dry_run {
            println!("dry-run: update tempo via tempoup");
        } else {
            println!("Updating tempo...");
            if !run_tempoup(&installer.bin_dir)? {
                eprintln!("tempo update failed");
            }
        }

        // 2. Update all installed extensions.
        let registry = Registry::load();
        let extensions: Vec<(String, String)> = registry
            .extensions
            .iter()
            .filter(|(_, state)| !state.installed_version.is_empty())
            .map(|(name, state)| (name.clone(), state.installed_version.clone()))
            .collect();

        if extensions.is_empty() {
            return Ok(0);
        }

        println!("Updating extensions...");
        let mut updated_registry = registry;

        for (name, installed_version) in &extensions {
            let source = InstallSource {
                manifest: Some(manifest_url(name, None)),
                public_key: Some(release_public_key()),
            };

            if dry_run {
                println!("dry-run: update {name} (installed: {installed_version})");
                continue;
            }

            match installer.install_if_changed(name, &source, Some(installed_version)) {
                Ok(Some(new_version)) => {
                    println!("Updated tempo-{name} to {new_version}");
                    updated_registry.record_check(name, &new_version, false);
                }
                Ok(None) => {
                    updated_registry.touch_check(name);
                }
                Err(err) => {
                    eprintln!("failed to update tempo-{name}: {err}");
                    updated_registry.touch_check(name);
                }
            }
        }

        if !dry_run {
            updated_registry.save();
        }

        Ok(0)
    }

    fn handle_remove(&self, extension: &str, dry_run: bool) -> Result<i32, LauncherError> {
        if !is_valid_extension_name(extension) {
            return Err(LauncherError::InvalidArgs(format!(
                "invalid extension name: {extension} (only alphanumeric, hyphens, and underscores)",
            )));
        }

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        installer.remove(extension, dry_run)?;
        Ok(0)
    }

    fn handle_list(&self) -> Result<i32, LauncherError> {
        let registry = Registry::load();
        let mut entries: Vec<_> = registry
            .extensions
            .iter()
            .filter(|(_, state)| !state.installed_version.is_empty())
            .collect();

        if entries.is_empty() {
            println!("No extensions installed.");
            return Ok(0);
        }

        entries.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (name, state) in &entries {
            let pin = if state.pinned { " (pinned)" } else { "" };
            println!("tempo-{name} {}{pin}", state.installed_version);
        }

        Ok(0)
    }

    /// Dispatch to an external extension binary.
    ///
    /// `ext_args` comes from clap's `external_subcommand` — the first element
    /// is the subcommand name, the rest are arguments to forward as-is.
    fn handle_extension(&self, ext_args: Vec<OsString>) -> Result<i32, LauncherError> {
        let extension = ext_args[0].to_string_lossy();
        if !is_valid_extension_name(&extension) {
            print_missing_install_hint(&extension);
            return Ok(1);
        }
        tracing::debug!("extension={extension}");

        let binary_name = format!("tempo-{extension}");
        let display_name = format!("tempo {extension}");
        let child_args = &ext_args[1..];

        if let Some(binary) = self.find_binary(&binary_name) {
            tracing::debug!("extension found locally: {}", binary.display());
            self.maybe_auto_update(&extension);
            return run_child(binary, child_args, &display_name);
        }

        // Try to auto-install as an extension.
        tracing::debug!("attempting extension auto-install");
        match self.try_auto_install_extension(&extension) {
            Ok(Some(binary)) => {
                return run_child(binary, child_args, &display_name);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::debug!("extension auto-install failed: {err}");
            }
        }

        print_missing_install_hint(&extension);
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
            Ok(version) => {
                let mut registry = Registry::load();
                registry.record_check(extension, &version, false);
                registry.save();
                Ok(self.find_binary(&binary_name))
            }
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

        let mut registry = Registry::load();
        if !registry.needs_update_check(extension) {
            return;
        }

        let installed_version = registry
            .extensions
            .get(extension)
            .map(|e| e.installed_version.as_str());

        let installer = match Installer::from_env(self.exe_dir.as_deref()) {
            Ok(i) => i,
            Err(_) => {
                registry.touch_check(extension);
                registry.save();
                return;
            }
        };

        let source = InstallSource {
            manifest: Some(manifest_url(extension, None)),
            public_key: Some(release_public_key()),
        };

        if registry.is_pinned(extension) {
            // Pinned to a specific version — check for updates but don't
            // install. Only fetch the manifest to compare versions.
            if let Ok(Some(new_version)) =
                Installer::check_latest_version(&source, installed_version)
            {
                eprintln!(
                    "tempo-{extension} {new_version} available (pinned to {}; run `tempo update {extension}` to upgrade)",
                    installed_version.unwrap_or("unknown")
                );
            }
            registry.touch_check(extension);
        } else {
            match installer.install_if_changed(extension, &source, installed_version) {
                Ok(Some(new_version)) => {
                    if installed_version.is_some_and(|v| !v.is_empty()) {
                        eprintln!("Updated tempo-{extension} to {new_version}");
                    }
                    registry.record_check(extension, &new_version, false);
                }
                Ok(None) => {
                    registry.touch_check(extension);
                }
                Err(err) => {
                    tracing::debug!("auto-update: failed for {extension}: {err}");
                    registry.touch_check(extension);
                }
            }
        }
        registry.save();
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

fn base_url() -> String {
    env::var("TEMPO_EXT_BASE_URL").unwrap_or_else(|_| BASE_URL.to_string())
}

fn release_public_key() -> String {
    // Allow overriding the release public key only in debug/test builds.
    // In release builds the key is always the compiled-in constant to
    // prevent environment-based signature bypass attacks.
    #[cfg(debug_assertions)]
    if let Ok(key) = env::var("TEMPO_EXT_PUBLIC_KEY") {
        return key;
    }
    PUBLIC_KEY.to_string()
}

fn manifest_url(extension: &str, version: Option<&str>) -> String {
    let base = base_url();
    let base = base.trim_end_matches('/');
    match version {
        Some(v) => {
            let v = v.strip_prefix('v').unwrap_or(v);
            format!("{base}/extensions/tempo-{extension}/v{v}/manifest.json")
        }
        None => format!("{base}/extensions/tempo-{extension}/manifest.json"),
    }
}

fn run_child(binary: PathBuf, args: &[OsString], display_name: &str) -> Result<i32, LauncherError> {
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
    use super::{
        BASE_URL, Cli, Commands, PUBLIC_KEY, base_url, is_valid_extension_name, manifest_url,
        release_public_key,
    };
    use crate::{installer::is_allowed_manifest_url, test_util::ENV_MUTEX};
    use clap::Parser;

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
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new("TEMPO_EXT_BASE_URL");
        assert_eq!(
            manifest_url("wallet", None),
            "https://cli.tempo.xyz/extensions/tempo-wallet/manifest.json"
        );

        assert_eq!(
            manifest_url("wallet", Some("0.2.0")),
            "https://cli.tempo.xyz/extensions/tempo-wallet/v0.2.0/manifest.json"
        );

        assert_eq!(
            manifest_url("wallet", Some("v0.2.0")),
            "https://cli.tempo.xyz/extensions/tempo-wallet/v0.2.0/manifest.json",
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

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).unwrap()
    }

    fn parse_err(args: &[&str]) -> clap::Error {
        Cli::try_parse_from(args).unwrap_err()
    }

    #[test]
    fn parse_add_extension_only() {
        let cli = parse(&["tempo", "add", "wallet"]);
        match cli.command {
            Commands::Add(ref args) => {
                assert_eq!(args.extension, "wallet");
                assert_eq!(args.version, None);
                assert!(!args.dry_run);
                assert!(args.manifest.is_none());
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn parse_add_extension_and_version() {
        let cli = parse(&["tempo", "add", "wallet", "1.0.0"]);
        match cli.command {
            Commands::Add(ref args) => {
                assert_eq!(args.extension, "wallet");
                assert_eq!(args.version, Some("1.0.0".to_string()));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn parse_add_with_dry_run() {
        let cli = parse(&["tempo", "add", "wallet", "--dry-run"]);
        match cli.command {
            Commands::Add(ref args) => assert!(args.dry_run),
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn parse_add_with_manifest() {
        let cli = parse(&[
            "tempo",
            "add",
            "wallet",
            "--release-manifest",
            "https://example.com/m.json",
        ]);
        match cli.command {
            Commands::Add(ref args) => {
                assert_eq!(
                    args.manifest,
                    Some("https://example.com/m.json".to_string())
                );
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn parse_add_with_public_key() {
        let cli = parse(&["tempo", "add", "wallet", "--release-public-key", "abc123"]);
        match cli.command {
            Commands::Add(ref args) => {
                assert_eq!(args.public_key, Some("abc123".to_string()));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn parse_list() {
        let cli = parse(&["tempo", "list"]);
        assert!(matches!(cli.command, Commands::List));
    }

    #[test]
    fn parse_remove() {
        let cli = parse(&["tempo", "remove", "wallet"]);
        assert!(matches!(cli.command, Commands::Remove(_)));
    }

    #[test]
    fn parse_update_with_extension() {
        let cli = parse(&["tempo", "update", "wallet"]);
        match cli.command {
            Commands::Update(ref args) => {
                assert_eq!(args.extension.as_deref(), Some("wallet"));
                assert_eq!(args.version, None);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_update_no_args() {
        let cli = parse(&["tempo", "update"]);
        match cli.command {
            Commands::Update(ref args) => {
                assert!(args.extension.is_none());
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn parse_add_missing_extension() {
        let _ = parse_err(&["tempo", "add"]);
    }

    #[test]
    fn parse_add_unknown_flag() {
        let _ = parse_err(&["tempo", "add", "wallet", "--unknown"]);
    }

    #[test]
    fn parse_add_manifest_missing_value() {
        let _ = parse_err(&["tempo", "add", "wallet", "--release-manifest"]);
    }

    #[test]
    fn parse_external_subcommand() {
        let cli = parse(&["tempo", "wallet", "--help"]);
        match cli.command {
            Commands::Extension(ref args) => {
                assert_eq!(args[0], "wallet");
                assert_eq!(args[1], "--help");
            }
            _ => panic!("expected Extension"),
        }
    }

    #[test]
    fn parse_external_subcommand_preserves_all_args() {
        let cli = parse(&["tempo", "wallet", "login", "--verbose", "extra"]);
        match cli.command {
            Commands::Extension(ref args) => {
                assert_eq!(args.len(), 4);
                assert_eq!(args[0], "wallet");
                assert_eq!(args[1], "login");
                assert_eq!(args[2], "--verbose");
                assert_eq!(args[3], "extra");
            }
            _ => panic!("expected Extension"),
        }
    }

    #[test]
    fn parse_add_too_many_positional() {
        let _ = parse_err(&["tempo", "add", "wallet", "1.0.0", "extra"]);
    }

    #[test]
    fn parse_remove_extension_only() {
        let cli = parse(&["tempo", "remove", "wallet"]);
        match cli.command {
            Commands::Remove(ref args) => {
                assert_eq!(args.extension, "wallet");
                assert!(!args.dry_run);
            }
            _ => panic!("expected Remove"),
        }
    }

    #[test]
    fn parse_remove_with_dry_run() {
        let cli = parse(&["tempo", "remove", "wallet", "--dry-run"]);
        match cli.command {
            Commands::Remove(ref args) => assert!(args.dry_run),
            _ => panic!("expected Remove"),
        }
    }

    #[test]
    fn parse_remove_rejects_manifest_flag() {
        let _ = parse_err(&["tempo", "remove", "wallet", "--release-manifest", "url"]);
    }

    #[test]
    fn parse_remove_rejects_version() {
        let _ = parse_err(&["tempo", "remove", "wallet", "1.0.0"]);
    }

    #[test]
    fn base_url_defaults_to_constant() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Clear any env override to test the default.
        let _guard = EnvGuard::new("TEMPO_EXT_BASE_URL");
        assert_eq!(base_url(), BASE_URL);
    }

    #[test]
    fn base_url_respects_env_override() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("TEMPO_EXT_BASE_URL", "https://custom.example.com");
        assert_eq!(base_url(), "https://custom.example.com");
    }

    #[test]
    fn release_public_key_defaults_to_constant() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::new("TEMPO_EXT_PUBLIC_KEY");
        assert_eq!(release_public_key(), PUBLIC_KEY);
    }

    #[test]
    fn release_public_key_respects_env_override() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("TEMPO_EXT_PUBLIC_KEY", "custom-key");
        assert_eq!(release_public_key(), "custom-key");
    }

    #[test]
    fn manifest_url_with_custom_base_url() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("TEMPO_EXT_BASE_URL", "https://custom.example.com/");
        assert_eq!(
            manifest_url("wallet", None),
            "https://custom.example.com/extensions/tempo-wallet/manifest.json"
        );
    }

    #[test]
    fn manifest_url_trims_trailing_slashes() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("TEMPO_EXT_BASE_URL", "https://example.com///");
        assert_eq!(
            manifest_url("wallet", None),
            "https://example.com/extensions/tempo-wallet/manifest.json"
        );
    }

    #[test]
    fn is_valid_extension_name_single_chars() {
        assert!(is_valid_extension_name("a"));
        assert!(is_valid_extension_name("-"));
        assert!(is_valid_extension_name("_"));
    }

    #[test]
    fn is_valid_extension_name_rejects_special() {
        assert!(!is_valid_extension_name("foo@bar"));
        assert!(!is_valid_extension_name("a b"));
        assert!(!is_valid_extension_name("foo\0bar"));
        assert!(!is_valid_extension_name("foo!bar"));
    }

    /// RAII guard that saves and restores an environment variable.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }

        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }
}
