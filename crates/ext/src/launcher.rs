//! Routes `tempo <extension>` to the right binary, handles auto-install
//! of missing extensions, and provides built-in commands (add/update/remove).

use crate::{
    installer::{
        InstallSource, Installer, InstallerError, ResolvedInstall, binary_candidates,
        fallback_bin_dir, find_in_path,
    },
    registry::{ExtensionState, Registry, RegistryLock},
};
use clap::{Parser, Subcommand};
use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const BASE_URL: &str = "https://cli.tempo.xyz";
const PUBLIC_KEY: &str = "RWTtoEUPuapAfh06rC7BZLjm1hG40/lsVAA/2afN88FZ8/Fdk97LzJDf";

/// Set to a non-empty value other than `0` or `false` to disable automatic
/// extension updates.
const NO_AUTO_UPDATE_ENV: &str = "TEMPO_EXT_NO_AUTO_UPDATE";

/// Hidden subcommand that runs a single extension update check in the
/// background process spawned by extension dispatch.
const AUTO_UPDATE_COMMAND: &str = "__auto-update";

#[derive(Debug, thiserror::Error)]
pub enum LauncherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("installer error: {0}")]
    Installer(#[from] InstallerError),

    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    #[error("{0}")]
    Registry(String),

    #[error("{0}")]
    Lock(String),
}

/// Parses arguments and dispatches to built-in commands (add/update/remove/list)
/// or extension subcommands. This is the entry point for the `tempo` CLI.
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

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            // Let clap handle --help and --version by printing and exiting.
            if matches!(
                err.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                err.exit();
            }
            return Err(LauncherError::InvalidArgs(err.to_string()));
        }
    };

    match cli.command {
        Commands::Add(args) => launcher.handle_install(args),
        Commands::Update(args) => launcher.handle_update(args),
        Commands::Remove(args) => launcher.handle_remove(&args.extension, args.dry_run),
        Commands::List => launcher.handle_list(),
        Commands::AutoUpdate { extension } => launcher.handle_auto_update(&extension),
        Commands::Extension(ext_args) => launcher.handle_extension(ext_args),
    }
}

/// Extension manager for the Tempo CLI.
#[derive(Parser, Debug)]
#[command(
    name = "tempo",
    disable_version_flag = true,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Install an extension (e.g., `tempo add wallet`).
    #[command(after_help = "Examples:\n  tempo add wallet\n  tempo add wallet 0.2.0")]
    Add(ManagementArgs),

    /// Update tempo and/or extensions. Without arguments, updates tempo
    /// itself via tempoup and then updates all installed extensions.
    #[command(
        after_help = "Examples:\n  tempo update          # update tempo + all extensions\n  tempo update wallet   # update a single extension"
    )]
    Update(UpdateArgs),

    /// Remove an extension.
    #[command(after_help = "Example: tempo remove wallet")]
    Remove(RemoveArgs),

    /// List installed extensions.
    List,

    /// Background update check for one extension (internal).
    #[command(name = AUTO_UPDATE_COMMAND, hide = true)]
    AutoUpdate { extension: String },

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

/// Runs `tempoup` to update the tempo binary itself.
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
                .env("TEMPO_BIN_DIR", bin_dir)
                .status()?;
            if !install_status.success() {
                tracing::error!("failed to install tempoup");
                return Ok(false);
            }

            return Ok(true);
        }
        Err(err) => return Err(LauncherError::Io(err)),
    };
    Ok(status.success())
}

/// Internal dispatcher that holds the directory of the running `tempo` binary
/// and implements all built-in and extension subcommands.
struct Launcher {
    /// Directory containing the `tempo` binary, used to co-locate extensions.
    exe_dir: Option<PathBuf>,
}

impl Launcher {
    /// Installs an extension, recording the result in the registry.
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
                public_key: Some(args.public_key.unwrap_or_else(release_public_key)),
            }
        };
        let pinned = args.version.is_some();
        let _lock = lock_registry(args.dry_run)?;
        let result = installer.install(&args.extension, &source, args.dry_run, false)?;
        if !args.dry_run {
            let mut registry = Registry::load().map_err(LauncherError::Registry)?;
            registry.record_check(
                &args.extension,
                &result.version,
                pinned,
                &result.description,
            );
            registry.save();
        }
        Ok(0)
    }

    /// Handles `tempo update [extension]`.
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
                public_key: Some(args.public_key.unwrap_or_else(release_public_key)),
            }
        };

        let _lock = lock_registry(args.dry_run)?;
        let registry = Registry::load().map_err(LauncherError::Registry)?;
        let installed_version = registry
            .extensions
            .get(&extension)
            .map(|e| e.installed_version.as_str());

        if args.dry_run {
            match Installer::check_latest_version(&source, installed_version) {
                Ok(Some(latest)) => {
                    println!(
                        "dry-run: would update tempo-{extension} from {} to {latest}",
                        installed_version.unwrap_or("none")
                    );
                }
                Ok(None) => {
                    println!(
                        "dry-run: tempo-{extension} is already at the latest version ({})",
                        installed_version.unwrap_or("unknown")
                    );
                }
                Err(err) => {
                    tracing::warn!("dry-run: failed to check for updates: {err}");
                }
            }
            return Ok(0);
        }

        match installer.install_if_changed(&extension, &source, installed_version)? {
            Some(result) => {
                if installed_version.is_some_and(|v| !v.is_empty()) {
                    println!("Updated tempo-{extension} to {}", result.version);
                } else {
                    println!("Installed tempo-{extension} {}", result.version);
                }
                let mut registry = registry;
                registry.record_check(&extension, &result.version, false, &result.description);
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

    /// Updates tempo itself via `tempoup`, then updates all installed extensions.
    fn handle_update_all(&self, dry_run: bool) -> Result<i32, LauncherError> {
        let installer = Installer::from_env(self.exe_dir.as_deref())?;

        // 1. Update tempo itself via tempoup.
        if dry_run {
            println!("dry-run: update tempo via tempoup");
        } else {
            println!("Updating tempo...");
            if !run_tempoup(&installer.bin_dir)? {
                tracing::error!("tempo update failed");
            }
        }

        // 2. Update all installed extensions (skip pinned ones).
        let _lock = lock_registry(dry_run)?;
        let registry = Registry::load().map_err(LauncherError::Registry)?;
        let extensions: Vec<(String, String, bool)> = registry
            .extensions
            .iter()
            .filter(|(_, state)| !state.installed_version.is_empty())
            .map(|(name, state)| (name.clone(), state.installed_version.clone(), state.pinned))
            .collect();

        if extensions.is_empty() {
            return Ok(0);
        }

        println!("Updating extensions...");
        let mut updated_registry = registry;

        for (name, installed_version, pinned) in &extensions {
            if *pinned {
                println!("Skipping tempo-{name} (pinned at {installed_version})");
                continue;
            }

            let source = InstallSource {
                manifest: Some(manifest_url(name, None)),
                public_key: Some(release_public_key()),
            };

            if dry_run {
                println!("dry-run: update {name} (installed: {installed_version})");
                continue;
            }

            match installer.install_if_changed(name, &source, Some(installed_version)) {
                Ok(Some(result)) => {
                    println!("Updated tempo-{name} to {}", result.version);
                    updated_registry.record_check(
                        name,
                        &result.version,
                        false,
                        &result.description,
                    );
                }
                Ok(None) => {
                    updated_registry.touch_check(name);
                }
                Err(err) => {
                    tracing::error!(extension = %name, "failed to update: {err}");
                    updated_registry.touch_check(name);
                }
            }
        }

        if !dry_run {
            updated_registry.save();
        }

        Ok(0)
    }

    /// Removes an extension's binary, skill files, and registry entry.
    fn handle_remove(&self, extension: &str, dry_run: bool) -> Result<i32, LauncherError> {
        if !is_valid_extension_name(extension) {
            return Err(LauncherError::InvalidArgs(format!(
                "invalid extension name: {extension} (only alphanumeric, hyphens, and underscores)",
            )));
        }

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        let _lock = lock_registry(dry_run)?;
        installer.remove(extension, dry_run)?;

        if !dry_run {
            let mut registry = Registry::load().map_err(LauncherError::Registry)?;
            registry.extensions.remove(extension);
            registry.save();
        }

        Ok(0)
    }

    /// Prints a table of installed extensions with version and metadata.
    fn handle_list(&self) -> Result<i32, LauncherError> {
        let registry = Registry::load().map_err(LauncherError::Registry)?;
        let mut entries: Vec<_> = registry
            .extensions
            .iter()
            .filter(|(_, state)| !state.installed_version.is_empty())
            .collect();

        if entries.is_empty() {
            println!("No extensions installed.");
            println!();
            println!("Run `tempo add <extension>` to install one.");
            return Ok(0);
        }

        entries.sort_by_key(|(a, _)| *a);

        println!();
        println!("  {:<22} {:<12}", "Extension", "Version");
        println!("  {:<22} {:<12}", "─────────", "───────");

        for (name, state) in &entries {
            let mut meta = Vec::new();
            if state.pinned {
                meta.push("pinned".to_string());
            }
            if !state.description.is_empty() {
                meta.push(state.description.clone());
            }
            let suffix = if meta.is_empty() {
                String::new()
            } else {
                meta.join(" · ")
            };
            println!("  {:<22} {:<12} {}", name, state.installed_version, suffix);
        }
        println!();

        Ok(0)
    }

    /// Dispatches to an external extension binary.
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
            self.warn_path_mismatch(&binary);
            let update = self.maybe_auto_update(&extension)?;
            let code = run_child(binary, child_args, &display_name)?;
            // Only once the extension has exited, so the update cannot replace
            // the binary while this invocation is still loading it.
            if update {
                spawn_auto_update(&extension);
            }
            return Ok(code);
        }

        // Try to auto-install as an extension.
        tracing::debug!("attempting extension auto-install");
        match self.try_auto_install_extension(&extension) {
            Ok(Some(binary)) => {
                return run_child(binary, child_args, &display_name);
            }
            Ok(None) => {}
            // A lock failure is not a missing extension; report it instead
            // of the install hint.
            Err(err @ LauncherError::Lock(_)) => return Err(err),
            Err(err) => {
                tracing::debug!("extension auto-install failed: {err}");
            }
        }

        print_missing_install_hint(&extension);
        Ok(1)
    }

    /// Attempts to install an unknown extension from the default manifest URL.
    /// Returns the binary path on success, `None` if the extension doesn't exist.
    fn try_auto_install_extension(
        &self,
        extension: &str,
    ) -> Result<Option<PathBuf>, LauncherError> {
        let manifest = manifest_url(extension, None);
        tracing::debug!("auto-install manifest={manifest}");

        let binary_name = format!("tempo-{extension}");

        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        let _lock = lock_registry(false)?;
        match installer.install(
            extension,
            &InstallSource {
                manifest: Some(manifest),
                public_key: Some(release_public_key()),
            },
            false,
            false,
        ) {
            Ok(result) => {
                let mut registry = Registry::load().map_err(LauncherError::Registry)?;
                registry.record_check(extension, &result.version, false, &result.description);
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

    /// Prints the notice left by the last background update check and
    /// returns `true` if a new check is due (at most once every 6 hours per
    /// extension). The caller starts it with [`spawn_auto_update`] once the
    /// extension has exited.
    ///
    /// Records nothing about the check itself: the background process claims
    /// it, so an invocation that is interrupted before spawning it leaves the
    /// check due for the next one. A corrupt registry is surfaced to the
    /// caller.
    fn maybe_auto_update(&self, extension: &str) -> Result<bool, LauncherError> {
        let disabled = auto_update_disabled(
            env::var_os(NO_AUTO_UPDATE_ENV).as_deref(),
            env::var_os("TEMPO_HOME").is_some(),
        );
        if disabled {
            return Ok(false);
        }

        let registry = Registry::load().map_err(LauncherError::Registry)?;
        let plan = AutoUpdatePlan::new(
            registry.needs_update_check(extension),
            registry.has_notice(extension),
            io::stderr().is_terminal(),
        );
        if plan.show_notice
            && let Some(notice) = take_notice(extension)
        {
            eprintln!("{notice}");
        }
        Ok(plan.check)
    }

    /// Handles the hidden `tempo __auto-update <extension>` command.
    ///
    /// Claims the due check under the registry lock, so concurrent updaters
    /// for one extension run it once. Then downloads and verifies a newer
    /// release without the lock and, under the lock again, installs it only
    /// if the registry entry is still the one the check started from, so a
    /// `tempo remove`, pin, or explicit install made meanwhile wins. A pinned
    /// extension is only checked. A found update leaves a notice for the next
    /// interactive invocation. Failures are silent: the existing binary stays
    /// in place.
    fn handle_auto_update(&self, extension: &str) -> Result<i32, LauncherError> {
        if !is_valid_extension_name(extension) {
            return Err(LauncherError::InvalidArgs(format!(
                "invalid extension name: {extension} (only alphanumeric, hyphens, and underscores)",
            )));
        }

        let Some(snapshot) = claim_update_check(extension)? else {
            return Ok(0);
        };
        let installed_version = Some(snapshot.installed_version.as_str());
        let installer = Installer::from_env(self.exe_dir.as_deref())?;
        let source = InstallSource {
            manifest: Some(manifest_url(extension, None)),
            public_key: Some(release_public_key()),
        };

        let found = if snapshot.pinned {
            Installer::check_latest_version(&source, installed_version)
                .map(|latest| latest.map(FoundUpdate::Available))
        } else {
            installer
                .prepare_update(extension, &source, installed_version)
                .map(|prepared| prepared.map(FoundUpdate::Prepared))
        };
        // The check is already recorded, so there is nothing to write if no
        // update was found.
        let found = match found {
            Ok(Some(found)) => found,
            Ok(None) => return Ok(0),
            Err(err) => {
                tracing::debug!("auto-update: check failed for {extension}: {err}");
                return Ok(0);
            }
        };

        let Some(_lock) = updater_lock() else {
            return Ok(0);
        };
        let mut registry = Registry::load().map_err(LauncherError::Registry)?;
        if !is_same_install(&snapshot, registry.extensions.get(extension)) {
            tracing::debug!("auto-update: tempo-{extension} changed during the check, skipping");
            return Ok(0);
        }

        let (version, pinned) = match found {
            FoundUpdate::Available(version) => (version, true),
            FoundUpdate::Prepared(prepared) => {
                let result = installer.commit(extension, &prepared)?;
                registry.record_check(extension, &result.version, false, &result.description);
                (result.version, false)
            }
        };
        if let Some(notice) = update_notice(extension, installed_version, &version, pinned) {
            registry.set_notice(extension, notice);
        }
        registry.save();
        Ok(0)
    }

    /// Warns if the binary we found is not in the directory where the
    /// installer would place new versions. This happens when exe_dir is
    /// read-only — updates go to `~/.local/bin` but `find_binary` keeps
    /// discovering the stale copy next to the running executable.
    fn warn_path_mismatch(&self, binary_path: &Path) {
        let binary_dir = match binary_path.parent() {
            Some(d) => d,
            None => return,
        };
        let install_dir = match Installer::from_env(self.exe_dir.as_deref()) {
            Ok(i) => i.bin_dir,
            Err(_) => return,
        };
        if binary_dir != install_dir {
            let name = binary_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            tracing::warn!(
                binary = %name,
                found_in = %binary_dir.display(),
                install_dir = %install_dir.display(),
                "extension binary found in a different directory than the install target; updates may not take effect",
            );
        }
    }

    /// Searches for an extension binary: exe_dir, fallback bin dir, then `PATH`.
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

/// Returns the base URL for extension manifests (`TEMPO_EXT_BASE_URL` or the default).
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

/// Builds the manifest URL for an extension, optionally pinned to a version.
///
/// Strips `tempo-` and `v` prefixes from the extension name and version respectively
/// to avoid double-prefixing (e.g. `tempo add tempo-wallet` resolves correctly).
fn manifest_url(extension: &str, version: Option<&str>) -> String {
    let base = base_url();
    let base = base.trim_end_matches('/');
    let extension = extension.strip_prefix("tempo-").unwrap_or(extension);
    match version {
        Some(v) => {
            let v = v.strip_prefix('v').unwrap_or(v);
            format!("{base}/extensions/tempo-{extension}/v{v}/manifest.json")
        }
        None => format!("{base}/extensions/tempo-{extension}/manifest.json"),
    }
}

/// Takes the registry lock for a command that writes the registry or the
/// install. Dry runs write nothing and skip it.
fn lock_registry(dry_run: bool) -> Result<Option<RegistryLock>, LauncherError> {
    if dry_run {
        return Ok(None);
    }
    Registry::lock().map(Some).map_err(LauncherError::Lock)
}

/// Returns `true` if automatic updates are disabled, either explicitly via
/// `TEMPO_EXT_NO_AUTO_UPDATE` or because `TEMPO_HOME` marks a managed or test
/// environment where updates should be explicit (via `tempo update`).
fn auto_update_disabled(no_auto_update: Option<&OsStr>, tempo_home_set: bool) -> bool {
    let opted_out = no_auto_update
        .is_some_and(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"));
    opted_out || tempo_home_set
}

/// A newer release found by a background update check.
enum FoundUpdate {
    /// Newer version of a pinned extension; reported, never installed.
    Available(String),
    /// Downloaded and verified release, not yet placed.
    Prepared(ResolvedInstall),
}

/// Returns `true` if the registry entry still describes the install a
/// background check started from. A removal, pin, or explicit install in
/// the meantime, even of the same version, changes it, and the check must
/// not override that.
fn is_same_install(snapshot: &ExtensionState, current: Option<&ExtensionState>) -> bool {
    current.is_some_and(|current| {
        current.generation == snapshot.generation
            && current.installed_version == snapshot.installed_version
            && current.pinned == snapshot.pinned
    })
}

/// Takes the registry lock for the background updater, which skips its work
/// rather than fail when the lock is unusable.
fn updater_lock() -> Option<RegistryLock> {
    Registry::lock()
        .inspect_err(|err| tracing::debug!("auto-update: {err}, skipping"))
        .ok()
}

/// Records a due update check for `extension` under the registry lock and
/// returns the entry it starts from. Returns `None`, so the updater does
/// nothing, if another updater already claimed the check, the lock is
/// unusable, or the registry has no entry for the extension (it was removed,
/// or was found on `PATH` and is only recorded now).
fn claim_update_check(extension: &str) -> Result<Option<ExtensionState>, LauncherError> {
    let Some(_lock) = updater_lock() else {
        return Ok(None);
    };
    let mut registry = Registry::load().map_err(LauncherError::Registry)?;
    if !registry.needs_update_check(extension) {
        return Ok(None);
    }
    let snapshot = registry.extensions.get(extension).cloned();
    registry.touch_check(extension);
    registry.save();
    Ok(snapshot)
}

/// Removes and returns the pending notice for `extension`. Returns `None`
/// without waiting if the registry lock is busy or unusable.
fn take_notice(extension: &str) -> Option<String> {
    let _lock = Registry::try_lock()?;
    let mut registry = Registry::load().ok()?;
    let notice = registry.take_notice(extension)?;
    registry.save();
    Some(notice)
}

/// What an extension invocation does about auto-update.
#[derive(Debug, PartialEq, Eq)]
struct AutoUpdatePlan {
    /// Start a background update check.
    check: bool,
    /// Print and clear the notice left by the previous check.
    show_notice: bool,
}

impl AutoUpdatePlan {
    /// Notices go to stderr only when it is a terminal, so scripts and agents
    /// never see them; the notice is kept for a later interactive run.
    fn new(due: bool, has_notice: bool, stderr_is_tty: bool) -> Self {
        Self {
            check: due,
            show_notice: has_notice && stderr_is_tty,
        }
    }
}

/// Builds the notice recorded after a background check found `new_version`.
/// A first install (no previously installed version) gets no notice.
fn update_notice(
    extension: &str,
    installed_version: Option<&str>,
    new_version: &str,
    pinned: bool,
) -> Option<String> {
    let installed = installed_version.filter(|v| !v.is_empty());
    if pinned {
        Some(format!(
            "tempo-{extension} {new_version} available (pinned to {}; run `tempo update {extension}` to upgrade)",
            installed.unwrap_or("unknown")
        ))
    } else {
        installed.map(|_| format!("updated tempo-{extension} to {new_version}"))
    }
}

/// Spawns `tempo __auto-update <extension>` as a detached process with all
/// stdio closed, so it can neither delay nor write to the current invocation.
fn spawn_auto_update(extension: &str) {
    let exe = match env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            tracing::debug!("auto-update: cannot locate tempo binary: {err}");
            return;
        }
    };

    let mut cmd = Command::new(exe);
    cmd.args([AUTO_UPDATE_COMMAND, extension])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Own process group, so a Ctrl-C aimed at the extension does not
    // interrupt the update.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    if let Err(err) = cmd.spawn() {
        tracing::debug!("auto-update: failed to spawn for {extension}: {err}");
    }
}

/// Executes the extension binary with the given arguments and returns the exit code.
fn run_child(binary: PathBuf, args: &[OsString], display_name: &str) -> Result<i32, LauncherError> {
    tracing::debug!("exec {} args={args:?}", binary.display());

    let mut cmd = Command::new(&binary);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.arg0(display_name);
    }

    let status = cmd.args(args).status()?;
    let code = status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                return 128 + sig;
            }
        }
        1
    });
    Ok(code)
}

/// Validates an extension name: non-empty, ASCII alphanumeric plus `-` and `_`.
fn is_valid_extension_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Prints a user-facing hint when an unknown subcommand has no matching extension.
fn print_missing_install_hint(extension: &str) {
    println!("Unknown command '{extension}' and no compatible extension found.");
    println!("Run: tempo add {extension}");
}

#[cfg(test)]
mod tests {
    use super::{
        AUTO_UPDATE_COMMAND, AutoUpdatePlan, BASE_URL, Cli, Commands, Launcher, NO_AUTO_UPDATE_ENV,
        PUBLIC_KEY, auto_update_disabled, base_url, is_same_install, is_valid_extension_name,
        manifest_url, release_public_key, update_notice,
    };
    use crate::{
        installer::is_allowed_manifest_url,
        registry::{ExtensionState, Registry, state_path},
        test_util::ENV_MUTEX,
    };
    use clap::Parser;
    use std::{ffi::OsStr, fs};

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

        assert_eq!(
            manifest_url("tempo-wallet", None),
            "https://cli.tempo.xyz/extensions/tempo-wallet/manifest.json",
            "tempo- prefix should not be doubled"
        );

        assert_eq!(
            manifest_url("tempo-wallet", Some("0.2.0")),
            "https://cli.tempo.xyz/extensions/tempo-wallet/v0.2.0/manifest.json",
            "tempo- prefix should not be doubled with version"
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

    #[test]
    fn auto_update_disabled_by_env() {
        // (TEMPO_EXT_NO_AUTO_UPDATE, TEMPO_HOME set, disabled)
        let cases: &[(Option<&str>, bool, bool)] = &[
            (None, false, false),
            (Some(""), false, false),
            (Some("0"), false, false),
            (Some("false"), false, false),
            (Some("FALSE"), false, false),
            (Some("1"), false, true),
            (Some("true"), false, true),
            (Some("yes"), false, true),
            (None, true, true),
            (Some("0"), true, true),
            (Some("1"), true, true),
        ];
        for &(value, tempo_home, disabled) in cases {
            assert_eq!(
                auto_update_disabled(value.map(OsStr::new), tempo_home),
                disabled,
                "TEMPO_EXT_NO_AUTO_UPDATE={value:?} TEMPO_HOME set={tempo_home}"
            );
        }
    }

    #[test]
    fn auto_update_plan() {
        // (due, has notice, stderr is tty, check, show notice)
        let cases = [
            (false, false, false, false, false),
            (false, false, true, false, false),
            (true, false, false, true, false),
            (true, false, true, true, false),
            (false, true, false, false, false),
            (false, true, true, false, true),
            (true, true, false, true, false),
            (true, true, true, true, true),
        ];
        for (due, has_notice, tty, check, show_notice) in cases {
            assert_eq!(
                AutoUpdatePlan::new(due, has_notice, tty),
                AutoUpdatePlan { check, show_notice },
                "due={due} has_notice={has_notice} tty={tty}"
            );
        }
    }

    #[test]
    fn update_notice_text() {
        // (installed, new, pinned, notice)
        let cases = [
            (
                Some("1.0.0"),
                "2.0.0",
                false,
                Some("updated tempo-wallet to 2.0.0"),
            ),
            (None, "2.0.0", false, None),
            (Some(""), "2.0.0", false, None),
            (
                Some("1.0.0"),
                "2.0.0",
                true,
                Some(
                    "tempo-wallet 2.0.0 available (pinned to 1.0.0; run `tempo update wallet` to upgrade)",
                ),
            ),
            (
                None,
                "2.0.0",
                true,
                Some(
                    "tempo-wallet 2.0.0 available (pinned to unknown; run `tempo update wallet` to upgrade)",
                ),
            ),
        ];
        for (installed, new, pinned, notice) in cases {
            assert_eq!(
                update_notice("wallet", installed, new, pinned).as_deref(),
                notice,
                "installed={installed:?} pinned={pinned}"
            );
        }
    }

    #[test]
    fn same_install_detects_changes_during_check() {
        let state = |version: &str, pinned: bool, generation: u64| ExtensionState {
            checked_at: 0,
            installed_version: version.to_string(),
            pinned,
            description: String::new(),
            notice: None,
            generation,
        };
        let snapshot = state("1.0.0", false, 7);
        // (current registry entry, still the same install)
        let cases = [
            (Some(state("1.0.0", false, 7)), true),
            (None, false),
            (Some(state("1.0.0", false, 8)), false),
            (Some(state("1.0.0", true, 7)), false),
            (Some(state("1.1.0", false, 7)), false),
            (Some(state("", false, 7)), false),
        ];
        for (current, same) in cases {
            assert_eq!(
                is_same_install(&snapshot, current.as_ref()),
                same,
                "current={current:?}"
            );
        }

        let mut touched = state("1.0.0", false, 7);
        touched.checked_at = 42;
        touched.notice = Some("notice".to_string());
        assert!(
            is_same_install(&snapshot, Some(&touched)),
            "check time and notice are not part of the install"
        );
    }

    #[test]
    fn dispatch_records_nothing_before_spawning_the_check() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        // Auto-update is only enabled without TEMPO_HOME, so point the
        // platform data directory into the temp dir instead.
        let _home = EnvGuard::set("HOME", tmp.path().to_str().unwrap());
        let _data = EnvGuard::set("XDG_DATA_HOME", tmp.path().to_str().unwrap());
        let _tempo_home = EnvGuard::new("TEMPO_HOME");
        let _opt_out = EnvGuard::new(NO_AUTO_UPDATE_ENV);
        assert!(state_path().unwrap().starts_with(tmp.path()));

        let mut registry = Registry::default();
        registry.record_check("wallet", "1.0.0", false, "");
        registry.extensions.get_mut("wallet").unwrap().checked_at = 0;
        registry.save();
        let before = fs::read(state_path().unwrap()).unwrap();

        let launcher = Launcher { exe_dir: None };
        assert!(
            launcher.maybe_auto_update("wallet").unwrap(),
            "check is due"
        );
        assert_eq!(
            fs::read(state_path().unwrap()).unwrap(),
            before,
            "the updater claims the check, so an interrupted run retries"
        );
    }

    #[test]
    fn parse_auto_update() {
        let cli = parse(&["tempo", AUTO_UPDATE_COMMAND, "wallet"]);
        match cli.command {
            Commands::AutoUpdate { ref extension } => assert_eq!(extension, "wallet"),
            _ => panic!("expected AutoUpdate"),
        }
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
