//! Persistent state for the tempo CLI (update check timestamps, installed versions).

use crate::installer::home_dir;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs};

const UPDATE_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct State {
    #[serde(default)]
    pub(crate) extensions: HashMap<String, ExtensionState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtensionState {
    pub(crate) checked_at: u64,
    pub(crate) installed_version: String,
}

impl State {
    pub(crate) fn load() -> Self {
        let path = match state_path() {
            Some(p) => p,
            None => return Self::default(),
        };
        match fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub(crate) fn save(&self) {
        let path = match state_path() {
            Some(p) => p,
            None => return,
        };
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(err) => {
                tracing::warn!("state serialize failed: {err}");
                return;
            }
        };
        let tmp = path.with_extension("tmp");
        if let Err(err) = fs::write(&tmp, format!("{json}\n")) {
            tracing::warn!("state write failed: {}: {err}", tmp.display());
            return;
        }
        if let Err(err) = fs::rename(&tmp, &path) {
            tracing::warn!("state rename failed: {}: {err}", path.display());
        }
    }

    pub(crate) fn needs_update_check(&self, extension: &str) -> bool {
        let now = now_secs();
        match self.extensions.get(extension) {
            Some(ext) => now.saturating_sub(ext.checked_at) >= UPDATE_CHECK_INTERVAL_SECS,
            None => true,
        }
    }

    pub(crate) fn record_check(&mut self, extension: &str, version: &str) {
        self.extensions.insert(
            extension.to_string(),
            ExtensionState {
                checked_at: now_secs(),
                installed_version: version.to_string(),
            },
        );
    }

    /// Bump the check timestamp without changing the recorded version.
    /// Used on network failure to avoid retrying every invocation.
    pub(crate) fn touch_check(&mut self, extension: &str) {
        if let Some(ext) = self.extensions.get_mut(extension) {
            ext.checked_at = now_secs();
        } else {
            // No record at all — record with empty version so we don't
            // keep retrying on every launch during an outage.
            self.extensions.insert(
                extension.to_string(),
                ExtensionState {
                    checked_at: now_secs(),
                    installed_version: String::new(),
                },
            );
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_path() -> Option<PathBuf> {
    if let Some(home) = env::var_os("TEMPO_HOME") {
        Some(PathBuf::from(home).join("state.json"))
    } else {
        home_dir().map(|home| {
            let base = if cfg!(target_os = "macos") {
                home.join("Library/Application Support")
            } else {
                // XDG_STATE_HOME, defaulting to ~/.local/state
                env::var_os("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join(".local/state"))
            };
            base.join("tempo").join("state.json")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_check_when_no_record() {
        let state = State::default();
        assert!(state.needs_update_check("wallet"));
    }

    #[test]
    fn no_check_needed_after_recent_record() {
        let mut state = State::default();
        state.record_check("wallet", "v1.0.0");
        assert!(!state.needs_update_check("wallet"));
    }

    #[test]
    fn check_needed_after_stale_record() {
        let mut state = State::default();
        state.extensions.insert(
            "wallet".to_string(),
            ExtensionState {
                checked_at: now_secs() - UPDATE_CHECK_INTERVAL_SECS - 1,
                installed_version: "v1.0.0".to_string(),
            },
        );
        assert!(state.needs_update_check("wallet"));
    }

    #[test]
    fn touch_preserves_version() {
        let mut state = State::default();
        state.record_check("wallet", "v1.0.0");
        state.extensions.get_mut("wallet").unwrap().checked_at = 0;
        state.touch_check("wallet");
        assert_eq!(state.extensions["wallet"].installed_version, "v1.0.0");
        assert!(!state.needs_update_check("wallet"));
    }

    #[test]
    fn touch_creates_record_if_missing() {
        let mut state = State::default();
        state.touch_check("wallet");
        assert!(!state.needs_update_check("wallet"));
        assert_eq!(state.extensions["wallet"].installed_version, "");
    }

    #[test]
    fn roundtrip_serialize() {
        let mut state = State::default();
        state.record_check("wallet", "v1.0.0");
        let json = serde_json::to_string(&state).unwrap();
        let loaded: State = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "v1.0.0");
    }
}
