//! Authorization token parsing and verification.

use std::time::{SystemTime, UNIX_EPOCH};

mod token;

pub use crate::error::AuthError;
pub use token::{
    AuthContext, AuthorizationToken, DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
    DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS, X_AUTHORIZATION_TOKEN, build_token_fields,
    parse_auth_header,
};

/// Current unix timestamp in seconds for authorization expiry checks and token generation.
pub(crate) fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_secs()
}
