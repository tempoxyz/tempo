//! Release manifest fetching and validation.

use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

use crate::installer::error::InstallerError;

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
        reqwest::blocking::get(location)?
            .error_for_status()?
            .text()?
    } else if let Some(path) = location.strip_prefix("file://") {
        fs::read_to_string(path)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    } else {
        fs::read_to_string(location)
            .map_err(|_| InstallerError::ReleaseManifestNotFound(location.to_string()))?
    };

    Ok(serde_json::from_str(&body)?)
}

pub(crate) fn is_secure_or_local_manifest_location(location: &str) -> bool {
    if location.starts_with("https://") {
        return true;
    }

    if location.starts_with("file://") {
        return true;
    }

    !location.contains("://")
}
