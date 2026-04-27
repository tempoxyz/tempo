//! Error types for the extension installer.

use std::io;

/// Errors that can occur during extension install, update, or removal.
#[derive(Debug, thiserror::Error)]
pub enum InstallerError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("home directory not found")]
    HomeDirMissing,

    #[error("missing release manifest: pass --release-manifest")]
    MissingReleaseManifest,

    #[error("missing release public key: pass --release-public-key")]
    MissingReleasePublicKey,

    #[error("insecure release manifest URL: {0} (requires https://, file://, or local path)")]
    InsecureManifestUrl(String),

    #[error("release manifest not found: {0}")]
    ReleaseManifestNotFound(String),

    #[error("extension metadata missing in release manifest: {0}")]
    ExtensionNotInManifest(String),

    #[error("signature missing in release manifest for {0}")]
    SignatureMissing(String),

    #[error("invalid signature format for {field}: {details}")]
    SignatureFormat {
        field: &'static str,
        details: String,
    },

    #[error("signature verification failed for {0}")]
    SignatureVerificationFailed(String),

    #[error("insecure download URL: {0} (requires https://, file://, or local path)")]
    InsecureDownloadUrl(String),

    #[error("checksum mismatch for {binary}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        binary: String,
        expected: String,
        actual: String,
    },

    #[error("trusted comment mismatch for {artifact}: expected \"{expected}\", got \"{actual}\"")]
    TrustedCommentMismatch {
        artifact: String,
        expected: String,
        actual: String,
    },
}
