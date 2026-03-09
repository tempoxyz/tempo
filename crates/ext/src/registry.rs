//! Persistent registry of installed extensions (versions, update check timestamps).
//!
//! NOTE: load/save is not file-locked. Concurrent `tempo` invocations may
//! lose a write (last-writer-wins). This is acceptable today because the
//! data is limited to `checked_at` timestamps and `installed_version`
//! strings — the worst outcome is a redundant update check.

use crate::installer::home_dir;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const UPDATE_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Registry {
    #[serde(default)]
    pub(crate) extensions: HashMap<String, ExtensionState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtensionState {
    pub(crate) checked_at: u64,
    pub(crate) installed_version: String,
    /// When true, auto-update will not install newer versions — only
    /// log that an update is available. Set when the user installs a
    /// specific version via `tempo add <ext> <version>`.
    #[serde(default)]
    pub(crate) pinned: bool,
}

impl Registry {
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
                tracing::warn!("registry serialize failed: {err}");
                return;
            }
        };
        let tmp = path.with_extension("tmp");
        if let Err(err) = fs::write(&tmp, format!("{json}\n")) {
            tracing::warn!("registry write failed: {}: {err}", tmp.display());
            return;
        }
        if let Err(err) = fs::rename(&tmp, &path) {
            tracing::warn!("registry rename failed: {}: {err}", path.display());
        }
    }

    pub(crate) fn needs_update_check(&self, extension: &str) -> bool {
        let now = now_secs();
        match self.extensions.get(extension) {
            Some(ext) => now.saturating_sub(ext.checked_at) >= UPDATE_CHECK_INTERVAL_SECS,
            None => true,
        }
    }

    pub(crate) fn record_check(&mut self, extension: &str, version: &str, pinned: bool) {
        self.extensions.insert(
            extension.to_string(),
            ExtensionState {
                checked_at: now_secs(),
                installed_version: version.to_string(),
                pinned,
            },
        );
    }

    pub(crate) fn is_pinned(&self, extension: &str) -> bool {
        self.extensions
            .get(extension)
            .is_some_and(|e| e.pinned)
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
                    pinned: false,
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
        Some(PathBuf::from(home).join("extensions.json"))
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
            base.join("tempo").join("extensions.json")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_check_when_no_record() {
        let reg = Registry::default();
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn no_check_needed_after_recent_record() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false);
        assert!(!reg.needs_update_check("wallet"));
    }

    #[test]
    fn check_needed_after_stale_record() {
        let mut reg = Registry::default();
        reg.extensions.insert(
            "wallet".to_string(),
            ExtensionState {
                checked_at: now_secs() - UPDATE_CHECK_INTERVAL_SECS - 1,
                installed_version: "v1.0.0".to_string(),
                pinned: false,
            },
        );
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn touch_preserves_version() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false);
        reg.extensions.get_mut("wallet").unwrap().checked_at = 0;
        reg.touch_check("wallet");
        assert_eq!(reg.extensions["wallet"].installed_version, "v1.0.0");
        assert!(!reg.needs_update_check("wallet"));
    }

    #[test]
    fn touch_creates_record_if_missing() {
        let mut reg = Registry::default();
        reg.touch_check("wallet");
        assert!(!reg.needs_update_check("wallet"));
        assert_eq!(reg.extensions["wallet"].installed_version, "");
    }

    #[test]
    fn roundtrip_serialize() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false);
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "v1.0.0");
    }

    #[test]
    fn pinned_flag_recorded() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true);
        assert!(reg.is_pinned("wallet"));
    }

    #[test]
    fn not_pinned_by_default() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false);
        assert!(!reg.is_pinned("wallet"));
    }

    #[test]
    fn is_pinned_returns_false_for_unknown() {
        let reg = Registry::default();
        assert!(!reg.is_pinned("unknown"));
    }

    #[test]
    fn update_unpins() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true);
        assert!(reg.is_pinned("wallet"));
        reg.record_check("wallet", "2.0.0", false);
        assert!(!reg.is_pinned("wallet"));
    }

    #[test]
    fn roundtrip_serialize_pinned() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true);
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert!(loaded.is_pinned("wallet"));
    }

    #[test]
    fn deserialize_without_pinned_defaults_false() {
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0"}}}"#;
        let reg: Registry = serde_json::from_str(json).unwrap();
        assert!(!reg.is_pinned("wallet"));
    }
}
