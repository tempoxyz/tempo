//! WebAuthn assertions: P256 signatures over authenticator and client data.

use super::verify_p256;
use crate::transaction::tt_signature::WebAuthnSignature;
use alloy_primitives::B256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Whether `signature` is a valid WebAuthn assertion over `hash`.
pub fn verify_webauthn(signature: &WebAuthnSignature, hash: &B256) -> bool {
    verify_webauthn_data_internal(&signature.webauthn_data, hash).is_ok_and(|digest| {
        verify_p256(
            &signature.r,
            &signature.s,
            &signature.pub_key_x,
            &signature.pub_key_y,
            &digest,
        )
    })
}

// Minimum authenticatorData is 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
const MIN_AUTH_DATA_LEN: usize = 37;

/// WebAuthn authenticator data flags (byte 32)
/// ref: <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
const UP: u8 = 0x01; // User Presence (bit 0)
const UV: u8 = 0x04; // User Verified (bit 2)
const AT: u8 = 0x40; // Attested credential data (bit 6)
const ED: u8 = 0x80; // Extension data present (bit 7)

/// Minimal struct to deserialize only the fields we need from clientDataJSON.
/// serde_json will ignore unknown fields and only parse `type` and `challenge`.
#[derive(serde::Deserialize)]
struct ClientDataJson<'a> {
    #[serde(rename = "type")]
    type_field: &'a str,
    challenge: &'a str,
}

/// Parses and validates WebAuthn data, returning the message hash for P256 verification.
/// ref: <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
///
/// 1. Parses authenticatorData and clientDataJSON
/// 2. Validates authenticatorData (min 37 bytes, UP flag set)
/// 3. Validates clientDataJSON (type="webauthn.get", challenge matches tx_hash)
/// 4. Computes message hash = sha256(authenticatorData || sha256(clientDataJSON))
pub(crate) fn verify_webauthn_data_internal(
    webauthn_data: &[u8],
    tx_hash: &B256,
) -> Result<B256, &'static str> {
    // Ensure that we have clientDataJSON after authenticatorData
    if webauthn_data.len() < MIN_AUTH_DATA_LEN + 32 {
        return Err("WebAuthn data too short");
    }

    // Check flags (byte 32)
    let flags = webauthn_data[32];
    let (up_flag, uv_flag, at_flag, ed_flag) = (flags & UP, flags & UV, flags & AT, flags & ED);

    // UP or UV flag MUST be set (UV implies user presence per WebAuthn spec)
    if up_flag == 0 && uv_flag == 0 {
        return Err("neither UP, nor UV flag set");
    }

    // AT flag must NOT be set for assertion signatures (`webauthn.get`)
    if at_flag != 0 {
        return Err("AT flag must not be set for assertion signatures");
    }

    // Determine authenticatorData length
    let auth_data_len = if ed_flag == 0 {
        // If ED flag is not set, exactly 37 bytes (no extensions)
        MIN_AUTH_DATA_LEN
    } else {
        // ED flag must NOT be set, as Tempo AA doesn't support extensions
        // NOTE: If we ever want to support extensions, we will have to parse CBOR data
        return Err("ED flag must not be set, as Tempo doesn't support extensions");
    };

    let authenticator_data = &webauthn_data[..auth_data_len];
    let client_data_json = &webauthn_data[auth_data_len..];

    // Parse clientDataJSON (only extracts type and challenge fields)
    // NOTE: Size is already bounded by MAX_WEBAUTHN_SIGNATURE_LENGTH (2KB) at signature parsing
    let client_data: ClientDataJson<'_> =
        serde_json::from_slice(client_data_json).map_err(|_| "clientDataJSON is not valid JSON")?;

    // Validate type field
    if client_data.type_field != "webauthn.get" {
        return Err("clientDataJSON type must be webauthn.get");
    }

    // Validate challenge matches tx_hash (Base64URL encoded)
    if client_data.challenge != URL_SAFE_NO_PAD.encode(tx_hash.as_slice()) {
        return Err("clientDataJSON challenge does not match transaction hash");
    }

    // Compute message hash according to spec:
    // messageHash = sha256(authenticatorData || sha256(clientDataJSON))
    let client_data_hash = Sha256::digest(client_data_json);

    let mut final_hasher = Sha256::new();
    final_hasher.update(authenticator_data);
    final_hasher.update(client_data_hash);
    let message_hash = final_hasher.finalize();

    Ok(B256::from_slice(&message_hash))
}
