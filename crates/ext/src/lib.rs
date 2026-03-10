//! Extension dispatch and management for the Tempo CLI.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod installer;
mod launcher;
mod registry;

pub use installer::InstallerError;
pub use launcher::{LauncherError, run};

/// Returns installed extensions as `(name, description)` pairs, sorted alphabetically.
///
/// Returns an error if the registry file exists but cannot be read or parsed.
pub fn installed_extensions() -> Result<Vec<(String, String)>, String> {
    let reg = registry::Registry::load()?;
    let mut exts: Vec<(String, String)> = reg
        .extensions
        .into_iter()
        .filter(|(_, state)| !state.installed_version.is_empty())
        .map(|(name, state)| (name, state.description))
        .collect();
    exts.sort_by(|(a, _), (b, _)| a.cmp(b));
    Ok(exts)
}

#[cfg(test)]
pub(crate) mod test_util {
    /// Serialize all tests that mutate process-wide environment variables.
    /// Shared across modules to prevent cross-module races in `env::set_var`.
    pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
