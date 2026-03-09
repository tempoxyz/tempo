//! Extension dispatch and management for the Tempo CLI.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod installer;
mod launcher;
mod state;

pub use installer::InstallerError;
pub use launcher::{LauncherError, run};

#[cfg(test)]
pub(crate) mod test_util {
    /// Serialize all tests that mutate process-wide environment variables.
    /// Shared across modules to prevent cross-module races in `env::set_var`.
    pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
