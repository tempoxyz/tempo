//! Error types for the extension installer.

use std::fmt;
use std::io;

#[derive(Debug)]
pub(crate) enum InstallerError {
    Io(io::Error),
    Json(serde_json::Error),
    Network(reqwest::Error),
    HomeDirMissing,
    MissingReleaseManifest,
    MissingReleasePublicKey,
    InsecureManifestUrl(String),
    ReleaseManifestNotFound(String),
    ExtensionNotInManifest(String),
    SignatureMissing(String),
    SignatureFormat {
        field: &'static str,
        details: String,
    },
    SignatureVerificationFailed(String),
    InsecureDownloadUrl(String),
    ChecksumMismatch {
        binary: String,
        expected: String,
        actual: String,
    },

}

impl fmt::Display for InstallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::Network(err) => write!(f, "network error: {err}"),
            Self::HomeDirMissing => write!(f, "home directory not found"),
            Self::MissingReleaseManifest => {
                write!(f, "missing release manifest: pass --release-manifest")
            }
            Self::MissingReleasePublicKey => {
                write!(f, "missing release public key: pass --release-public-key")
            }
            Self::InsecureManifestUrl(value) => {
                write!(
                    f,
                    "insecure release manifest URL: {value} (requires https://, file://, or local path)"
                )
            }
            Self::ReleaseManifestNotFound(value) => {
                write!(f, "release manifest not found: {value}")
            }
            Self::ExtensionNotInManifest(value) => {
                write!(f, "extension metadata missing in release manifest: {value}")
            }
            Self::SignatureMissing(binary) => {
                write!(f, "signature missing in release manifest for {binary}")
            }
            Self::SignatureFormat { field, details } => {
                write!(f, "invalid signature format for {field}: {details}")
            }
            Self::SignatureVerificationFailed(binary) => {
                write!(f, "signature verification failed for {binary}")
            }
            Self::InsecureDownloadUrl(value) => {
                write!(
                    f,
                    "insecure download URL: {value} (requires https://, file://, or local path)"
                )
            }
            Self::ChecksumMismatch {
                binary,
                expected,
                actual,
            } => write!(
                f,
                "checksum mismatch for {binary}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for InstallerError {}

impl From<io::Error> for InstallerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for InstallerError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<reqwest::Error> for InstallerError {
    fn from(value: reqwest::Error) -> Self {
        Self::Network(value)
    }
}
