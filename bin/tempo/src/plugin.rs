//! Git-style CLI plugin system.
//!
//! Intercepts subcommands before clap parsing and delegates to external
//! `tempo-<name>` binaries. For example, `tempo wallet send 1.0` execs into
//! `tempo-wallet send 1.0`.
//!
//! Binary resolution order:
//!   1. Same directory as the running `tempo` binary
//!   2. `$PATH`

use std::{
    env,
    ffi::OsString,
    path::PathBuf,
    process::{self, Command},
};

/// Subcommands that map to external plugin binaries.
///
/// `tempo wallet ...` → `tempo-wallet ...`
/// `tempo request ...` → `tempo-wallet ...`
const PLUGIN_COMMANDS: &[PluginRoute] = &[
    PluginRoute {
        subcommand: "wallet",
        binary: "tempo-wallet",
        forward_subcommand: false,
    },
    PluginRoute {
        subcommand: "request",
        binary: "tempo-wallet",
        forward_subcommand: true,
    },
];

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
/// If `argv[1]` matches a known plugin subcommand, this function execs into the
/// plugin binary and **never returns**. If no plugin matches, returns `Ok(())`
/// and normal CLI parsing continues.
pub(crate) fn try_dispatch() -> eyre::Result<()> {
    let args: Vec<OsString> = env::args_os().collect();

    // Only look at argv[1] — the first arg after the program name.
    let Some(subcmd) = args.get(1) else {
        return Ok(());
    };

    let Some(route) = PLUGIN_COMMANDS.iter().find(|r| subcmd == r.subcommand) else {
        return Ok(());
    };

    let bin_path = resolve_plugin_binary(route.binary);

    // Build the forwarded args: everything after argv[1], optionally including
    // the subcommand itself.
    let forward_args: &[OsString] = if route.forward_subcommand {
        &args[1..]
    } else {
        &args[2..]
    };

    exec_plugin(&bin_path, forward_args);
}

/// Resolve the plugin binary path.
fn resolve_plugin_binary(name: &str) -> PathBuf {
    // 1. Check next to the current executable.
    if let Ok(self_path) = env::current_exe()
        && let Some(dir) = self_path.parent()
    {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
        // On Windows, try with .exe extension.
        #[cfg(windows)]
        {
            let candidate = dir.join(format!("{name}.exe"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    // 2. Fall back to $PATH lookup.
    PathBuf::from(name)
}

/// Exec into the plugin binary (never returns on success).
#[cfg(unix)]
fn exec_plugin(bin: &PathBuf, args: &[OsString]) -> ! {
    use std::os::unix::process::CommandExt;
    let err = Command::new(bin).args(args).exec();
    eprintln!("tempo: failed to exec `{}`: {err}", bin.display());
    process::exit(1);
}

#[cfg(not(unix))]
fn exec_plugin(bin: &PathBuf, args: &[OsString]) -> ! {
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

    /// Returns (binary, forward_args) if a plugin route matches argv[1].
    fn dispatch_plan(args: &[&str]) -> Option<(&'static str, Vec<String>)> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let subcmd = args.get(1)?;
        let route = PLUGIN_COMMANDS.iter().find(|r| subcmd == r.subcommand)?;
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
        Some((route.binary, forward))
    }

    #[test]
    fn wallet_strips_subcommand() {
        let plan = dispatch_plan(&["tempo", "wallet", "send", "1.0"]).unwrap();
        assert_eq!(plan.0, "tempo-wallet");
        assert_eq!(plan.1, &["send", "1.0"]);
    }

    #[test]
    fn request_forwards_subcommand() {
        let plan = dispatch_plan(&["tempo", "request", "https://api.x"]).unwrap();
        assert_eq!(plan.0, "tempo-wallet");
        assert_eq!(plan.1, &["request", "https://api.x"]);
    }

    #[test]
    fn unknown_subcommand_returns_none() {
        assert!(dispatch_plan(&["tempo", "node", "--chain", "moderato"]).is_none());
    }

    #[test]
    fn no_args_returns_none() {
        assert!(dispatch_plan(&["tempo"]).is_none());
    }

    #[test]
    fn flag_before_wallet_not_dispatched() {
        // `--help` at argv[1] should NOT dispatch to wallet plugin
        assert!(dispatch_plan(&["tempo", "--help", "wallet"]).is_none());
    }
}
