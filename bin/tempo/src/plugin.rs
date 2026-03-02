//! Git-style CLI plugin system.
//!
//! Intercepts subcommands before clap parsing and delegates to external
//! `tempo-<name>` binaries. For example, if `tempo-foo` exists on `$PATH`,
//! then `tempo foo arg1 arg2` execs into `tempo-foo arg1 arg2`.
//!
//! Binary resolution order:
//!   1. Same directory as the running `tempo` binary
//!   2. `$PATH`

use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    path::{Path, PathBuf},
    process::{self, Command},
};

/// Plugin binary name prefix.
const PLUGIN_PREFIX: &str = "tempo-";

/// Explicit route aliases for subcommands.
///
/// Use this to map a subcommand name to a specific binary, optionally
/// forwarding the subcommand name itself as an argument.
///
/// ```ignore
/// // Example (not currently active):
/// PluginRoute {
///     subcommand: "request",
///     binary: "tempo-wallet",
///     forward_subcommand: true,
/// }
/// // `tempo request https://...` → `tempo-wallet request https://...`
/// ```
const PLUGIN_ROUTES: &[PluginRoute] = &[];

struct PluginRoute {
    /// The subcommand name the user types (e.g. `wallet`).
    subcommand: &'static str,
    /// The external binary to exec into (e.g. `tempo-wallet`).
    binary: &'static str,
    /// Whether to forward the subcommand name itself as an arg.
    /// `true`:  `tempo request https://...` → `tempo-wallet request https://...`
    /// `false`: `tempo wallet send 1.0`    → `tempo-wallet send 1.0`
    forward_subcommand: bool,
}

/// Try to dispatch to an external plugin binary.
///
/// Must be called before `Cli::parse()`. Only checks `argv[1]` — the first
/// argument after the program name. This avoids ambiguity with global flags
/// that take values (e.g. `--log.stdout.filter debug`).
///
/// Resolution order:
///   1. Skip flags (anything starting with `-`)
///   2. Skip built-in clap subcommands
///   3. Check explicit [`PLUGIN_ROUTES`] aliases
///   4. Try generic `tempo-{name}` binary lookup
///
/// If a plugin matches and the binary exists, this function execs into it
/// and **never returns**. Otherwise returns `Ok(())` for normal CLI parsing.
pub(crate) fn try_dispatch(cli: &clap::Command) -> eyre::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();

    // Only look at argv[1] — the first arg after the program name.
    let Some(subcmd) = args.get(1) else {
        return Ok(());
    };

    // Don't intercept flags.
    if subcmd.to_string_lossy().starts_with('-') {
        return Ok(());
    }

    let subcmd_str = subcmd.to_string_lossy();

    // Never intercept built-in subcommands.
    if is_builtin_subcommand(cli, &subcmd_str) {
        return Ok(());
    }

    // Check explicit route aliases first.
    if let Some(route) = PLUGIN_ROUTES
        .iter()
        .find(|r| r.subcommand == subcmd_str.as_ref())
    {
        if let Some(bin_path) = find_binary(route.binary) {
            let forward_args = if route.forward_subcommand {
                &args[1..]
            } else {
                &args[2..]
            };
            exec_plugin(&bin_path, forward_args);
        }
    }

    // Generic lookup: `tempo foo` → `tempo-foo`.
    let bin_name = format!("{PLUGIN_PREFIX}{subcmd_str}");
    if let Some(bin_path) = find_binary(&bin_name) {
        exec_plugin(&bin_path, &args[2..]);
    }

    Ok(())
}

/// Format an `after_help` section listing discovered external subcommands.
///
/// Returns `None` if no plugins are found.
pub(crate) fn external_subcommands_help(cli: &clap::Command) -> Option<String> {
    let plugins = discover_plugins(cli);
    if plugins.is_empty() {
        return None;
    }

    let mut help = String::from("External subcommands (tempo-* binaries on PATH):\n");
    for name in &plugins {
        help.push_str(&format!("    {name}\n"));
    }
    Some(help)
}

/// Discover external `tempo-*` plugin binaries available on the system.
///
/// Returns sorted, deduplicated subcommand names (with the `tempo-` prefix
/// stripped). Excludes names that collide with built-in subcommands.
fn discover_plugins(cli: &clap::Command) -> Vec<String> {
    let mut plugins = BTreeSet::new();

    // Scan the directory containing the current executable.
    if let Some(dir) = self_dir() {
        scan_dir_for_plugins(&dir, &mut plugins);
    }

    // Scan each directory on $PATH.
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            scan_dir_for_plugins(&dir, &mut plugins);
        }
    }

    // Filter out anything that collides with a built-in subcommand.
    plugins
        .into_iter()
        .filter(|name| !is_builtin_subcommand(cli, name))
        .collect()
}

/// Returns `true` if `name` matches a built-in clap subcommand.
fn is_builtin_subcommand(cli: &clap::Command, name: &str) -> bool {
    cli.get_subcommands().any(|s| s.get_name() == name)
}

/// Find a binary by name, checking co-located directory first, then `$PATH`.
fn find_binary(name: &str) -> Option<PathBuf> {
    // 1. Check next to the current executable.
    if let Some(dir) = self_dir() {
        if let Some(path) = find_binary_in(&dir, name) {
            return Some(path);
        }
    }

    // 2. Search $PATH.
    if let Some(path_var) = env::var_os("PATH") {
        for dir in env::split_paths(&path_var) {
            if let Some(path) = find_binary_in(&dir, name) {
                return Some(path);
            }
        }
    }

    None
}

/// Look for a binary by name in a single directory.
fn find_binary_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if is_executable(&candidate) {
        return Some(candidate);
    }

    #[cfg(windows)]
    {
        let candidate = dir.join(format!("{name}.exe"));
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Directory containing the current executable.
fn self_dir() -> Option<PathBuf> {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(PathBuf::from))
}

/// Check if a path is an executable file.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.is_file()
            && path
                .metadata()
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
    }

    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Scan a directory for `tempo-*` binaries and insert their subcommand names.
fn scan_dir_for_plugins(dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Some(subcmd) = name_str.strip_prefix(PLUGIN_PREFIX) {
            // Strip .exe suffix on Windows.
            #[cfg(windows)]
            let subcmd = subcmd.strip_suffix(".exe").unwrap_or(subcmd);

            if !subcmd.is_empty() && is_executable(&entry.path()) {
                out.insert(subcmd.to_string());
            }
        }
    }
}

/// Exec into the plugin binary (never returns on success).
#[cfg(unix)]
fn exec_plugin(bin: &Path, args: &[OsString]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = Command::new(bin).args(args).exec();
    eprintln!("tempo: failed to exec `{}`: {err}", bin.display());
    process::exit(1);
}

#[cfg(not(unix))]
fn exec_plugin(bin: &Path, args: &[OsString]) -> ! {
    match Command::new(bin).args(args).status() {
        Ok(status) => process::exit(status.code().unwrap_or(1)),
        Err(err) => {
            eprintln!("tempo: failed to run `{}`: {err}", bin.display());
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Simulates the dispatch decision without actually exec'ing.
    /// Returns `Some((binary_name, forwarded_args))` if a plugin would match.
    fn dispatch_plan(cli: &clap::Command, argv: &[&str]) -> Option<(String, Vec<String>)> {
        let args: Vec<OsString> = argv.iter().map(OsString::from).collect();

        let subcmd = args.get(1)?;
        if subcmd.to_string_lossy().starts_with('-') {
            return None;
        }

        let subcmd_str = subcmd.to_string_lossy();
        if is_builtin_subcommand(cli, &subcmd_str) {
            return None;
        }

        // Check explicit routes.
        if let Some(route) = PLUGIN_ROUTES
            .iter()
            .find(|r| r.subcommand == subcmd_str.as_ref())
        {
            let forward: Vec<String> = if route.forward_subcommand {
                args[1..]
                    .iter()
                    .map(|s| s.to_string_lossy().into())
                    .collect()
            } else {
                args[2..]
                    .iter()
                    .map(|s| s.to_string_lossy().into())
                    .collect()
            };
            return Some((route.binary.to_string(), forward));
        }

        // Generic lookup.
        let bin_name = format!("{PLUGIN_PREFIX}{subcmd_str}");
        let forward: Vec<String> = args[2..]
            .iter()
            .map(|s| s.to_string_lossy().into())
            .collect();
        Some((bin_name, forward))
    }

    /// Minimal clap command with a few "built-in" subcommands for testing.
    fn test_cli() -> clap::Command {
        clap::Command::new("tempo")
            .subcommand(clap::Command::new("node"))
            .subcommand(clap::Command::new("db"))
            .subcommand(clap::Command::new("stage"))
    }

    #[test]
    fn generic_plugin_dispatch() {
        let cli = test_cli();
        let plan = dispatch_plan(&cli, &["tempo", "wallet", "send", "1.0"]).unwrap();
        assert_eq!(plan.0, "tempo-wallet");
        assert_eq!(plan.1, &["send", "1.0"]);
    }

    #[test]
    fn builtin_subcommand_not_dispatched() {
        let cli = test_cli();
        assert!(dispatch_plan(&cli, &["tempo", "node", "--chain", "moderato"]).is_none());
        assert!(dispatch_plan(&cli, &["tempo", "db", "stats"]).is_none());
        assert!(dispatch_plan(&cli, &["tempo", "stage", "run"]).is_none());
    }

    #[test]
    fn no_args_returns_none() {
        let cli = test_cli();
        assert!(dispatch_plan(&cli, &["tempo"]).is_none());
    }

    #[test]
    fn flag_not_dispatched() {
        let cli = test_cli();
        assert!(dispatch_plan(&cli, &["tempo", "--help"]).is_none());
        assert!(dispatch_plan(&cli, &["tempo", "-V"]).is_none());
    }

    #[test]
    fn unknown_subcommand_dispatches_generically() {
        let cli = test_cli();
        let plan = dispatch_plan(&cli, &["tempo", "cast", "call", "0x..."]).unwrap();
        assert_eq!(plan.0, "tempo-cast");
        assert_eq!(plan.1, &["call", "0x..."]);
    }

    #[test]
    fn discover_plugins_in_dir() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake plugin binaries.
        for name in ["tempo-foo", "tempo-bar"] {
            let path = dir.path().join(name);
            fs::write(&path, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        // Create a non-plugin binary (should be ignored).
        let non_plugin = dir.path().join("other-tool");
        fs::write(&non_plugin, "#!/bin/sh\n").unwrap();

        let mut found = BTreeSet::new();
        scan_dir_for_plugins(dir.path(), &mut found);
        assert_eq!(
            found,
            BTreeSet::from(["bar".to_string(), "foo".to_string()])
        );
    }

    #[test]
    fn discover_filters_builtins() {
        let dir = tempfile::tempdir().unwrap();

        // Create tempo-node (collides with built-in) and tempo-foo (doesn't).
        for name in ["tempo-node", "tempo-foo"] {
            let path = dir.path().join(name);
            fs::write(&path, "#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        let mut found = BTreeSet::new();
        scan_dir_for_plugins(dir.path(), &mut found);

        // scan_dir_for_plugins doesn't filter — discover_plugins does.
        assert!(found.contains("node"));
        assert!(found.contains("foo"));

        // But discover_plugins filters out builtins. We can't easily test
        // discover_plugins because it scans real PATH, but we can verify
        // the filtering logic directly.
        let cli = test_cli();
        let filtered: Vec<String> = found
            .into_iter()
            .filter(|name| !is_builtin_subcommand(&cli, name))
            .collect();
        assert_eq!(filtered, vec!["foo"]);
    }
}
