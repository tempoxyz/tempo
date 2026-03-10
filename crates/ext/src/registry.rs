//! Persistent registry of installed extensions (versions, update check timestamps).
//!
//! NOTE: load/save is not file-locked. Concurrent `tempo` invocations may
//! lose a write (last-writer-wins). This is acceptable today because the
//! data is limited to `checked_at` timestamps and `installed_version`
//! strings — the worst outcome is a redundant update check.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const UPDATE_CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60; // 6 hours

/// On-disk state for all known extensions, keyed by extension name.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Registry {
    /// Map from extension name (e.g. `"wallet"`) to its recorded state.
    #[serde(default)]
    pub(crate) extensions: HashMap<String, ExtensionState>,
}

/// Persisted metadata for a single extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ExtensionState {
    /// Unix timestamp (seconds) of the last update check.
    pub(crate) checked_at: u64,
    /// Version string recorded at install time (e.g. `"1.0.0"`).
    pub(crate) installed_version: String,
    /// When true, auto-update will not install newer versions — only
    /// log that an update is available. Set when the user installs a
    /// specific version via `tempo add <ext> <version>`.
    #[serde(default)]
    pub(crate) pinned: bool,
    /// Short description from the release manifest.
    #[serde(default)]
    pub(crate) description: String,
}

impl Registry {
    /// Loads the registry from disk.
    ///
    /// Returns `Ok(Self::default())` when the file does not exist or no data
    /// directory can be determined. Returns an error if the file exists but
    /// cannot be read or parsed — the caller should surface this to the user.
    pub(crate) fn load() -> Result<Self, String> {
        let Some(path) = state_path() else {
            return Ok(Self::default());
        };
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => {
                return Err(format!(
                    "registry corrupt; to reset, run:\n  rm \"{}\"",
                    path.display()
                ));
            }
        };
        serde_json::from_str(&content).map_err(|_| {
            format!(
                "registry corrupt; to reset, run:\n  rm \"{}\"",
                path.display()
            )
        })
    }

    /// Persists the registry to disk via atomic rename.
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

    /// Returns `true` if the extension has never been checked or the last
    /// check was more than 6 hours ago.
    pub(crate) fn needs_update_check(&self, extension: &str) -> bool {
        let now = now_secs();
        match self.extensions.get(extension) {
            Some(ext) => now.saturating_sub(ext.checked_at) >= UPDATE_CHECK_INTERVAL_SECS,
            None => true,
        }
    }

    /// Records a successful install or update check for an extension.
    pub(crate) fn record_check(
        &mut self,
        extension: &str,
        version: &str,
        pinned: bool,
        description: &str,
    ) {
        self.extensions.insert(
            extension.to_string(),
            ExtensionState {
                checked_at: now_secs(),
                installed_version: version.to_string(),
                pinned,
                description: description.to_string(),
            },
        );
    }

    /// Returns `true` if the extension is pinned to a specific version.
    pub(crate) fn is_pinned(&self, extension: &str) -> bool {
        self.extensions.get(extension).is_some_and(|e| e.pinned)
    }

    /// Bumps the check timestamp without changing the recorded version.
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
                    description: String::new(),
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

/// Resolves the path to the registry file.
///
/// Uses `TEMPO_HOME/extensions.json` if set, otherwise the platform data
/// directory via `dirs_next` (e.g. `~/Library/Application Support/tempo` on
/// macOS, `$XDG_DATA_HOME/tempo` on Linux).
fn state_path() -> Option<PathBuf> {
    if let Some(home) = env::var_os("TEMPO_HOME") {
        Some(PathBuf::from(home).join("extensions.json"))
    } else {
        dirs_next::data_dir().map(|data| data.join("tempo").join("extensions.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::ENV_MUTEX;

    /// RAII guard that sets `TEMPO_HOME` to a temp directory and restores it
    /// on drop. Must be held alongside `ENV_MUTEX`.
    struct TempHome {
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }

    impl TempHome {
        fn new() -> Self {
            let tmp = tempfile::TempDir::new().unwrap();
            let prev = std::env::var("TEMPO_HOME").ok();
            unsafe { std::env::set_var("TEMPO_HOME", tmp.path()) };
            Self { prev, _tmp: tmp }
        }

        fn registry_path(&self) -> PathBuf {
            self._tmp.path().join("extensions.json")
        }
    }

    impl Drop for TempHome {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var("TEMPO_HOME", v) },
                None => unsafe { std::env::remove_var("TEMPO_HOME") },
            }
        }
    }

    #[test]
    fn load_returns_default_when_file_missing() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home = TempHome::new();
        let reg = Registry::load().unwrap();
        assert!(reg.extensions.is_empty());
    }

    #[test]
    fn load_returns_ok_for_valid_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0","pinned":false,"description":"test"}}}"#;
        fs::write(home.registry_path(), json).unwrap();
        let reg = Registry::load().unwrap();
        assert_eq!(reg.extensions["wallet"].installed_version, "1.0.0");
        assert_eq!(reg.extensions["wallet"].description, "test");
    }

    #[test]
    fn load_returns_error_for_invalid_json() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "NOT VALID JSON {{{").unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "expected 'registry corrupt', got: {err}"
        );
        assert!(err.contains("rm \""), "expected rm command, got: {err}");
    }

    #[test]
    fn load_returns_error_for_unreadable_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        // Create a directory where the file is expected — read_to_string
        // will fail with a non-NotFound IO error.
        fs::create_dir_all(home.registry_path()).unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "expected 'registry corrupt', got: {err}"
        );
    }

    #[test]
    fn load_error_message_contains_path() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "garbage").unwrap();
        let err = Registry::load().unwrap_err();
        let expected_path = home.registry_path().display().to_string();
        assert!(
            err.contains(&expected_path),
            "error should contain path '{expected_path}', got: {err}"
        );
    }

    #[test]
    fn save_then_load_roundtrip_on_disk() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _home = TempHome::new();
        let mut reg = Registry::default();
        reg.record_check("wallet", "2.0.0", true, "Tempo wallet");
        reg.save();
        let loaded = Registry::load().unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "2.0.0");
        assert!(loaded.is_pinned("wallet"));
        assert_eq!(loaded.extensions["wallet"].description, "Tempo wallet");
    }

    #[test]
    fn load_empty_file_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), "").unwrap();
        let err = Registry::load().unwrap_err();
        assert!(
            err.contains("registry corrupt"),
            "empty file should be corrupt, got: {err}"
        );
    }

    #[test]
    fn load_partial_json_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let home = TempHome::new();
        fs::write(home.registry_path(), r#"{"extensions":{"#).unwrap();
        let err = Registry::load().unwrap_err();
        assert!(err.contains("registry corrupt"));
    }

    #[test]
    fn needs_check_when_no_record() {
        let reg = Registry::default();
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn no_check_needed_after_recent_record() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false, "");
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
                description: String::new(),
            },
        );
        assert!(reg.needs_update_check("wallet"));
    }

    #[test]
    fn touch_preserves_version() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "v1.0.0", false, "");
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
        reg.record_check("wallet", "v1.0.0", false, "");
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.extensions["wallet"].installed_version, "v1.0.0");
    }

    #[test]
    fn pinned_flag_recorded() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true, "");
        assert!(reg.is_pinned("wallet"));
    }

    #[test]
    fn not_pinned_by_default() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "");
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
        reg.record_check("wallet", "1.0.0", true, "");
        assert!(reg.is_pinned("wallet"));
        reg.record_check("wallet", "2.0.0", false, "");
        assert!(!reg.is_pinned("wallet"));
    }

    #[test]
    fn roundtrip_serialize_pinned() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", true, "");
        let json = serde_json::to_string(&reg).unwrap();
        let loaded: Registry = serde_json::from_str(&json).unwrap();
        assert!(loaded.is_pinned("wallet"));
    }

    #[test]
    fn description_recorded() {
        let mut reg = Registry::default();
        reg.record_check("wallet", "1.0.0", false, "Tempo wallet");
        assert_eq!(reg.extensions["wallet"].description, "Tempo wallet");
    }

    #[test]
    fn deserialize_without_description_defaults_empty() {
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0","pinned":false}}}"#;
        let reg: Registry = serde_json::from_str(json).unwrap();
        assert_eq!(reg.extensions["wallet"].description, "");
    }

    #[test]
    fn deserialize_without_pinned_defaults_false() {
        let json = r#"{"extensions":{"wallet":{"checked_at":0,"installed_version":"1.0.0"}}}"#;
        let reg: Registry = serde_json::from_str(json).unwrap();
        assert!(!reg.is_pinned("wallet"));
    }
}
