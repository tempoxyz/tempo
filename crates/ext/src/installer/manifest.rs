//! Release manifest fetching and validation.

use crate::installer::{error::InstallerError, file_url_to_path, http_client};

use serde::Deserialize;
use std::{collections::HashMap, fs};

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ReleaseManifest {
    pub(super) version: String,
    pub(super) description: Option<String>,
    pub(super) binaries: HashMap<String, ReleaseBinary>,
    pub(super) skill: Option<String>,
    pub(super) skill_sha256: Option<String>,
    pub(super) skill_signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ReleaseBinary {
    pub(super) url: String,
    pub(super) sha256: String,
    pub(super) signature: Option<String>,
}

pub(super) fn load_manifest(location: &str) -> Result<ReleaseManifest, InstallerError> {
    let body = if location.starts_with("https://") {
        http_client()?
            .get(location)
            .send()?
            .error_for_status()?
            .text()?
    } else if let Some(path) = file_url_to_path(location) {
        fs::read_to_string(path)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    } else {
        fs::read_to_string(location)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    };

    Ok(serde_json::from_str(&body)?)
}

/// Returns `true` if `location` is an HTTPS URL, a `file://` URL, or a local
/// filesystem path (i.e. not a URL with some other scheme).
pub(crate) fn is_allowed_manifest_url(location: &str) -> bool {
    match url::Url::parse(location) {
        Ok(url) => matches!(url.scheme(), "https" | "file"),
        // Not a URL at all (e.g. `./manifest.json`) — treat as local path.
        Err(url::ParseError::RelativeUrlWithoutBase) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn deserialize_minimal_manifest() {
        let json = r#"{
            "version": "1.0.0",
            "binaries": {
                "wallet": {
                    "url": "https://example.com/wallet",
                    "sha256": "abc123"
                }
            }
        }"#;
        let manifest: ReleaseManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(
            manifest.binaries["wallet"].url,
            "https://example.com/wallet"
        );
        assert!(manifest.binaries["wallet"].signature.is_none());
        assert!(manifest.description.is_none());
        assert!(manifest.skill.is_none());
        assert!(manifest.skill_sha256.is_none());
        assert!(manifest.skill_signature.is_none());
    }

    #[test]
    fn deserialize_full_manifest() {
        let json = r#"{
            "version": "2.0.0",
            "description": "Tempo wallet extension",
            "binaries": {
                "wallet": {
                    "url": "https://example.com/wallet",
                    "sha256": "abc123",
                    "signature": "sig456"
                }
            },
            "skill": "https://example.com/skill.wasm",
            "skill_sha256": "skillhash",
            "skill_signature": "skillsig"
        }"#;
        let manifest: ReleaseManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, "2.0.0");
        assert_eq!(
            manifest.description.as_deref(),
            Some("Tempo wallet extension")
        );
        assert_eq!(manifest.binaries["wallet"].sha256, "abc123");
        assert_eq!(
            manifest.binaries["wallet"].signature.as_deref(),
            Some("sig456")
        );
        assert_eq!(
            manifest.skill.as_deref(),
            Some("https://example.com/skill.wasm")
        );
        assert_eq!(manifest.skill_sha256.as_deref(), Some("skillhash"));
        assert_eq!(manifest.skill_signature.as_deref(), Some("skillsig"));
    }

    #[test]
    fn deserialize_missing_version_fails() {
        let json = r#"{
            "binaries": {
                "wallet": {
                    "url": "https://example.com/wallet",
                    "sha256": "abc123"
                }
            }
        }"#;
        assert!(serde_json::from_str::<ReleaseManifest>(json).is_err());
    }

    #[test]
    fn deserialize_missing_binary_sha256_fails() {
        let json = r#"{
            "version": "1.0.0",
            "binaries": {
                "wallet": {
                    "url": "https://example.com/wallet"
                }
            }
        }"#;
        assert!(serde_json::from_str::<ReleaseManifest>(json).is_err());
    }

    #[test]
    fn load_manifest_from_file() {
        let json = r#"{
            "version": "3.0.0",
            "binaries": {
                "wallet": {
                    "url": "https://example.com/wallet",
                    "sha256": "abc123"
                }
            }
        }"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_str().unwrap();
        let manifest = load_manifest(path).unwrap();
        assert_eq!(manifest.version, "3.0.0");
    }

    #[test]
    fn load_manifest_missing_file() {
        let result = load_manifest("./nonexistent-test-manifest-12345.json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, InstallerError::ReleaseManifestNotFound(_)),
            "expected ReleaseManifestNotFound, got: {err:?}"
        );
    }

    #[test]
    fn load_manifest_from_file_url() {
        let json = r#"{
            "version": "4.0.0",
            "binaries": {}
        }"#;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(json.as_bytes()).unwrap();
        tmp.flush().unwrap();

        let url = format!("file://{}", tmp.path().display());
        let manifest = load_manifest(&url).unwrap();
        assert_eq!(manifest.version, "4.0.0");
    }

    #[test]
    fn load_manifest_invalid_json() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"not json").unwrap();
        tmp.flush().unwrap();

        let result = load_manifest(tmp.path().to_str().unwrap());
        assert!(matches!(result, Err(InstallerError::Json(_))));
    }

    #[test]
    fn is_allowed_rejects_http() {
        assert!(!is_allowed_manifest_url(
            "http://insecure.example.com/manifest.json"
        ));
    }

    #[test]
    fn is_allowed_rejects_ftp() {
        assert!(!is_allowed_manifest_url("ftp://example.com/manifest.json"));
    }

    #[test]
    fn is_allowed_rejects_data_url() {
        assert!(!is_allowed_manifest_url("data:text/plain,hello"));
    }

    #[test]
    fn is_allowed_rejects_javascript_url() {
        assert!(!is_allowed_manifest_url("javascript:alert(1)"));
    }

    #[test]
    fn is_allowed_accepts_absolute_path() {
        assert!(is_allowed_manifest_url("/tmp/manifest.json"));
    }

    #[test]
    fn is_allowed_accepts_relative_path() {
        assert!(is_allowed_manifest_url("./manifest.json"));
        assert!(is_allowed_manifest_url("../manifest.json"));
    }
}
