//! Git-style CLI plugin system.
//!
//! Unrecognized subcommands are caught by clap's `external_subcommand`
//! attribute and dispatched to `tempo-<name>` binaries. For example,
//! `tempo foo arg1 arg2` execs into `tempo-foo arg1 arg2`.
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

/// Dispatch an external subcommand caught by clap's `external_subcommand`.
///
/// `args[0]` is the subcommand name, `args[1..]` are its arguments.
/// Checks explicit [`PLUGIN_ROUTES`] first, then falls back to generic
/// `tempo-{name}` lookup.
pub(crate) fn dispatch_external(args: Vec<OsString>) -> eyre::Result<()> {
    let subcmd = args
        .first()
        .ok_or_else(|| eyre::eyre!("external subcommand received with no arguments"))?;
    let subcmd_str = subcmd.to_string_lossy();

    // Check explicit route aliases first.
    if let Some(route) = PLUGIN_ROUTES
        .iter()
        .find(|r| r.subcommand == subcmd_str.as_ref())
    {
        if let Some(bin_path) = find_binary(route.binary) {
            let forward_args = if route.forward_subcommand {
                &args[..]
            } else {
                &args[1..]
            };
            exec_plugin(&bin_path, forward_args);
        }
    }

    // Generic lookup: `tempo foo` → `tempo-foo`.
    let bin_name = format!("{PLUGIN_PREFIX}{subcmd_str}");
    match find_binary(&bin_name) {
        Some(bin_path) => exec_plugin(&bin_path, &args[1..]),
        None => Err(eyre::eyre!(
            "unknown command `{subcmd_str}`\n\n\
             No built-in command or `{bin_name}` binary found.\n\
             Install it or check your PATH."
        )),
    }
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

        // Verify the filtering logic: built-ins are excluded.
        let cli = clap::Command::new("tempo")
            .subcommand(clap::Command::new("node"))
            .subcommand(clap::Command::new("db"));
        let filtered: Vec<String> = found
            .into_iter()
            .filter(|name| !is_builtin_subcommand(&cli, name))
            .collect();
        assert_eq!(filtered, vec!["foo"]);
    }
}
