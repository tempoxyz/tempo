/// Errors from key handling and manifest signing.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Filesystem error on a specific path.
    #[error("failed to {operation}: {path}: {source}")]
    Io {
        /// What was being done.
        operation: &'static str,
        /// The path involved.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Minisign key or signature error.
    #[error("failed to {operation}: {source}")]
    Crypto {
        /// What was being done.
        operation: &'static str,
        /// The underlying minisign error.
        #[source]
        source: minisign::PError,
    },
    /// `skill` and `skill_file` must be given together.
    #[error(
        "skill URL and skill file must be set together; without both the installer skips the skill"
    )]
    IncompleteSkill,
    /// Manifest serialization error.
    #[error("failed to serialize manifest: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl SignError {
    pub(super) fn io(
        operation: &'static str,
        path: &std::path::Path,
        source: std::io::Error,
    ) -> Self {
        Self::Io {
            operation,
            path: path.display().to_string(),
            source,
        }
    }

    pub(super) fn crypto(operation: &'static str, source: minisign::PError) -> Self {
        Self::Crypto { operation, source }
    }
}
