use alloy_primitives::{Address, B256, hex, keccak256};
use std::time::Duration;

use super::now_unix_seconds;
use crate::error::AuthError;

/// Magic prefix: "TempoZoneRPC" followed by zero bytes to fill 32 bytes.
const TEMPO_ZONE_RPC_MAGIC: [u8; 32] = {
    let mut buf = [0u8; 32];
    let s = b"TempoZoneRPC";
    let mut i = 0;
    while i < s.len() {
        buf[i] = s[i];
        i += 1;
    }
    buf
};

/// Size of the fixed token fields (version + zoneId + chainId + issuedAt + expiresAt).
const TOKEN_FIELDS_LEN: usize = 1 + 4 + 8 + 8 + 8; // 29 bytes

/// HTTP header name for the authorization token.
pub const X_AUTHORIZATION_TOKEN: &str = "x-authorization-token";

/// Protocol default maximum validity window for authorization tokens.
pub const DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS: u64 = 2_592_000;

/// Protocol default maximum validity window for authorization tokens.
pub const DEFAULT_MAX_AUTH_TOKEN_VALIDITY: Duration =
    Duration::from_secs(DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS);

/// The authenticated caller context extracted from a valid authorization token.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The authenticated account address.
    pub caller: Address,
    /// Token expiry timestamp (unix seconds).
    pub expires_at: u64,
    /// Keychain key used for authentication, if this is a keychain token.
    pub keychain_key_id: Option<Address>,
}

/// Parsed authorization token fields (before signature verification).
///
/// The token is a hex-encoded blob: `<signature><version:1><zoneId:4><chainId:8><issuedAt:8><expiresAt:8>`.
/// The last 29 bytes are always the fixed fields; everything before is the variable-length signature.
///
/// See `docs/pages/protocol/privacy/rpc.md` — "Transport" and "Message" sections.
///
/// This type intentionally does not implement [`Debug`](std::fmt::Debug) because its signature is
/// an authentication credential that must not be exposed in logs.
#[derive(Clone)]
pub struct AuthorizationToken {
    /// Spec version (must be 0).
    pub version: u8,
    /// Zone ID (0 = unscoped, valid for any zone).
    pub zone_id: u32,
    /// Chain ID.
    pub chain_id: u64,
    /// Issuance timestamp (unix seconds).
    pub issued_at: u64,
    /// Expiry timestamp (unix seconds).
    pub expires_at: u64,
    /// The raw signature bytes (everything before the last 29 bytes).
    pub signature: Vec<u8>,
    /// The signing digest (keccak256 of the packed message).
    pub digest: B256,
}

impl AuthorizationToken {
    /// Parse the raw bytes of an authorization token blob.
    ///
    /// Does NOT verify the signature — call [`Self::validate`] and then recover the signer
    /// separately.
    pub fn parse(blob: &[u8]) -> Result<Self, AuthError> {
        if blob.len() < TOKEN_FIELDS_LEN + 1 {
            return Err(AuthError::TooShort);
        }

        let fields_start = blob.len() - TOKEN_FIELDS_LEN;
        let fields: &[u8; TOKEN_FIELDS_LEN] = blob[fields_start..]
            .try_into()
            .expect("token fields have a fixed length");
        let signature = blob[..fields_start].to_vec();

        let version = fields[0];
        let zone_id = u32::from_be_bytes(fields[1..5].try_into().unwrap());
        let chain_id = u64::from_be_bytes(fields[5..13].try_into().unwrap());
        let issued_at = u64::from_be_bytes(fields[13..21].try_into().unwrap());
        let expires_at = u64::from_be_bytes(fields[21..29].try_into().unwrap());

        let digest = token_digest(fields);

        Ok(Self {
            version,
            zone_id,
            chain_id,
            issued_at,
            expires_at,
            signature,
            digest,
        })
    }

    /// Validate token fields against the server's zone configuration.
    ///
    /// A `zone_id` of `0` is unscoped and accepted for any zone.
    pub fn validate(&self, expected_zone_id: u32, expected_chain_id: u64) -> Result<(), AuthError> {
        self.validate_with_max_auth_token_validity(
            expected_zone_id,
            expected_chain_id,
            DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        )
    }

    /// Validate token fields against the server's zone configuration and
    /// a caller-provided maximum validity window.
    pub fn validate_with_max_auth_token_validity(
        &self,
        expected_zone_id: u32,
        expected_chain_id: u64,
        max_auth_token_validity: Duration,
    ) -> Result<(), AuthError> {
        self.validate_at(
            expected_zone_id,
            expected_chain_id,
            max_auth_token_validity,
            now_unix_seconds(),
        )
    }

    fn validate_at(
        &self,
        expected_zone_id: u32,
        expected_chain_id: u64,
        max_auth_token_validity: Duration,
        now: u64,
    ) -> Result<(), AuthError> {
        if self.version != 0 {
            return Err(AuthError::UnsupportedVersion(self.version));
        }
        if self.zone_id != 0 && self.zone_id != expected_zone_id {
            return Err(AuthError::ZoneIdMismatch);
        }
        if self.chain_id != expected_chain_id {
            return Err(AuthError::ChainIdMismatch);
        }
        let validity = self
            .expires_at
            .checked_sub(self.issued_at)
            .ok_or(AuthError::ExpiresBeforeIssued)?;
        if validity > max_auth_token_validity.as_secs() {
            return Err(AuthError::WindowTooLarge);
        }

        if self.expires_at <= now {
            return Err(AuthError::Expired);
        }
        if self.issued_at > now + 60 {
            return Err(AuthError::IssuedInFuture);
        }

        Ok(())
    }
}

/// Build the unsigned token fields and their signing digest.
///
/// Returns `(fields, digest)` where `fields` is the 29-byte suffix
/// and `digest` is the keccak256 hash to be signed.
///
/// Pass `zone_id = 0` for an unscoped token valid for any zone.
pub fn build_token_fields(
    zone_id: u32,
    chain_id: u64,
    issued_at: u64,
    expires_at: u64,
) -> ([u8; TOKEN_FIELDS_LEN], B256) {
    let mut fields = [0u8; TOKEN_FIELDS_LEN];
    fields[0] = 0; // version
    fields[1..5].copy_from_slice(&zone_id.to_be_bytes());
    fields[5..13].copy_from_slice(&chain_id.to_be_bytes());
    fields[13..21].copy_from_slice(&issued_at.to_be_bytes());
    fields[21..29].copy_from_slice(&expires_at.to_be_bytes());

    let digest = token_digest(&fields);

    (fields, digest)
}

/// Build the signing digest from the canonical fixed-width token fields.
fn token_digest(fields: &[u8; TOKEN_FIELDS_LEN]) -> B256 {
    let mut msg = [0; TEMPO_ZONE_RPC_MAGIC.len() + TOKEN_FIELDS_LEN];
    msg[..TEMPO_ZONE_RPC_MAGIC.len()].copy_from_slice(&TEMPO_ZONE_RPC_MAGIC);
    msg[TEMPO_ZONE_RPC_MAGIC.len()..].copy_from_slice(fields);
    keccak256(msg)
}

/// Parse a hex-encoded authorization token from the header value.
pub fn parse_auth_header(header_value: &str) -> Result<AuthorizationToken, AuthError> {
    let hex_str = header_value.strip_prefix("0x").unwrap_or(header_value);
    let blob = hex::decode(hex_str).map_err(|_| AuthError::InvalidHex)?;
    AuthorizationToken::parse(&blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    const ZONE_ID: u32 = 42;
    const CHAIN_ID: u64 = 1_337;
    const NOW: u64 = 1_700_000_000;

    fn token(issued_at: u64, expires_at: u64) -> AuthorizationToken {
        let (fields, _) = build_token_fields(ZONE_ID, CHAIN_ID, issued_at, expires_at);
        let mut blob = vec![0u8; 65];
        blob.extend_from_slice(&fields);
        AuthorizationToken::parse(&blob).unwrap()
    }

    fn validate_at(token: &AuthorizationToken, now: u64) -> Result<(), AuthError> {
        token.validate_at(ZONE_ID, CHAIN_ID, DEFAULT_MAX_AUTH_TOKEN_VALIDITY, now)
    }

    #[test]
    fn digest_and_wire_format_remain_compatible() {
        let (fields, digest) = build_token_fields(
            0x0102_0304,
            0x0506_0708_090a_0b0c,
            0x0d0e_0f10_1112_1314,
            0x1516_1718_191a_1b1c,
        );

        assert_eq!(
            hex::encode(fields),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
        );
        assert_eq!(
            digest,
            b256!("0xf827387a933f40dfedece81ba4933feaef89e98a269f52f4f54dda2f1dac4171")
        );

        let mut blob = vec![0xabu8; 65];
        blob.extend_from_slice(&fields);
        let parsed = AuthorizationToken::parse(&blob).unwrap();
        assert_eq!(parsed.signature, vec![0xabu8; 65]);
        assert_eq!(parsed.digest, digest);
    }

    #[test]
    fn rejects_expiry_before_issuance() {
        let token = token(NOW + 1, NOW);
        assert!(matches!(
            validate_at(&token, NOW),
            Err(AuthError::ExpiresBeforeIssued)
        ));
    }

    #[test]
    fn zero_length_window_is_valid_until_its_expiry() {
        let timestamp = NOW + 1;
        let token = token(timestamp, timestamp);

        assert!(validate_at(&token, NOW).is_ok());
        assert!(matches!(
            validate_at(&token, timestamp),
            Err(AuthError::Expired)
        ));
    }

    #[test]
    fn accepts_maximum_validity_window() {
        let token = token(NOW, NOW + DEFAULT_MAX_AUTH_TOKEN_VALIDITY_SECS);
        assert!(validate_at(&token, NOW).is_ok());
    }

    #[test]
    fn enforces_future_issuance_skew_boundary() {
        let at_limit = token(NOW + 60, NOW + 61);
        assert!(validate_at(&at_limit, NOW).is_ok());

        let past_limit = token(NOW + 61, NOW + 62);
        assert!(matches!(
            validate_at(&past_limit, NOW),
            Err(AuthError::IssuedInFuture)
        ));
    }
}
