//! Release manifest fetching and validation.

use crate::installer::error::InstallerError;
use crate::installer::{file_url_to_path, http_client};

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ReleaseManifest {
    pub(super) version: String,
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

/// Fetch a release manifest and return the version string.
pub(crate) fn fetch_manifest_version(manifest_url: &str) -> Result<String, InstallerError> {
    let manifest = load_manifest(manifest_url)?;
    Ok(manifest.version)
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
pub(crate) fn is_secure_or_local_manifest_location(location: &str) -> bool {
    match url::Url::parse(location) {
        Ok(url) => matches!(url.scheme(), "https" | "file"),
        // Not a URL at all (e.g. `./manifest.json`) — treat as local path.
        Err(url::ParseError::RelativeUrlWithoutBase) => true,
        Err(_) => false,
    }
}
