use axum::http::StatusCode;
use tracing::{error, warn};

/// Errors during authorization token parsing/validation.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing X-Authorization-Token header")]
    Missing,
    #[error("invalid hex encoding")]
    InvalidHex,
    #[error("token too short")]
    TooShort,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("zone ID mismatch")]
    ZoneIdMismatch,
    #[error("chain ID mismatch")]
    ChainIdMismatch,
    #[error("expiresAt before issuedAt")]
    ExpiresBeforeIssued,
    #[error("validity window too large")]
    WindowTooLarge,
    #[error("authorization token expired")]
    Expired,
    #[error("issuedAt too far in the future")]
    IssuedInFuture,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("keychain key not authorized")]
    UnauthorizedKeychainKey,
    #[error("keychain key revoked")]
    RevokedKeychainKey,
    #[error("keychain key expired")]
    ExpiredKeychainKey,
    #[error("keychain signature type mismatch")]
    KeychainSignatureTypeMismatch,
}

/// Authentication failures split into invalid caller credentials vs server-side failures.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthenticateError {
    #[error(transparent)]
    Invalid(#[from] AuthError),
    #[error(transparent)]
    Internal(#[from] eyre::Report),
}

impl AuthenticateError {
    /// Returns true when the failure was caused by invalid caller credentials.
    pub(crate) fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid(_))
    }

    /// Map the authentication failure to the corresponding HTTP status code.
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            Self::Invalid(AuthError::Missing) => StatusCode::UNAUTHORIZED,
            Self::Invalid(_) => StatusCode::FORBIDDEN,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Log the authentication failure at the appropriate level for the transport.
    pub(crate) fn log(&self, transport: &str) {
        match self {
            Self::Invalid(cause) => {
                warn!(target: "zone::rpc", %transport, err = %cause, "auth failed");
            }
            Self::Internal(cause) => {
                error!(target: "zone::rpc", %transport, err = %cause, "auth failed");
            }
        }
    }
}
