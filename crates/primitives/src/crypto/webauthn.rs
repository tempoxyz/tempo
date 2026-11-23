//! WebAuthn assertions: P256 signatures over authenticator and client data.

use super::verify_p256;
use crate::transaction::tt_signature::WebAuthnSignature;
use alloy_primitives::B256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// Whether `signature` is a valid WebAuthn assertion over `hash`.
pub fn verify_webauthn(signature: &WebAuthnSignature, hash: &B256) -> bool {
    webauthn_digest(&signature.webauthn_data, hash).is_ok_and(|digest| {
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
pub(super) const MIN_AUTH_DATA_LEN: usize = 37;

/// WebAuthn authenticator data flags (byte 32)
/// ref: <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
pub(super) const UP: u8 = 0x01; // User Presence (bit 0)
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
/// 2. Validates authenticatorData (min 37 bytes, UP or UV set, no AT or ED)
/// 3. Validates clientDataJSON (type="webauthn.get", challenge matches tx_hash)
/// 4. Computes message hash = sha256(authenticatorData || sha256(clientDataJSON))
pub(crate) fn webauthn_digest(webauthn_data: &[u8], tx_hash: &B256) -> Result<B256, &'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::tt_signature::tests::build_webauthn_data;

    #[test]
    fn test_webauthn_data_verification_too_short() {
        // WebAuthn data must be at least 37 bytes (authenticatorData minimum)
        let short_data = vec![0u8; 36];
        let tx_hash = B256::ZERO;

        let result = webauthn_digest(&short_data, &tx_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "WebAuthn data too short");
    }

    #[test]
    fn test_webauthn_data_verification_missing_up_and_uv_flags() {
        let tx_hash = B256::ZERO;
        let client_data = b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";

        // Create valid authenticatorData without UV nor UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x00;
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let result = webauthn_digest(&webauthn_data, &tx_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "neither UP, nor UV flag set");

        // Create valid authenticatorData with UV flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x04;
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        assert!(webauthn_digest(&webauthn_data, &tx_hash).is_ok());
    }

    #[test]
    fn test_webauthn_data_verification_invalid_type() {
        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Add clientDataJSON with wrong type
        let client_data = b"{\"type\":\"webauthn.create\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = webauthn_digest(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "clientDataJSON type must be webauthn.get"
        );
    }

    #[test]
    fn test_webauthn_data_verification_invalid_challenge() {
        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Add clientDataJSON with wrong challenge
        let client_data =
            b"{\"type\":\"webauthn.get\",\"challenge\":\"wrong_challenge_value_here\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = webauthn_digest(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "clientDataJSON challenge does not match transaction hash"
        );
    }

    #[test]
    fn test_webauthn_data_verification_valid() {
        let tx_hash = B256::from_slice(&[0xAA; 32]);
        let webauthn_data = build_webauthn_data(0x01, None, &tx_hash); // UP flag

        let result = webauthn_digest(&webauthn_data, &tx_hash);
        assert!(
            result.is_ok(),
            "Valid WebAuthn data should verify successfully"
        );

        // Verify the computed message hash is correct
        let message_hash = result.unwrap();
        let auth_data = &webauthn_data[..37];
        let client_data = &webauthn_data[37..];

        let client_data_hash = Sha256::digest(client_data);
        let mut final_hasher = Sha256::new();
        final_hasher.update(auth_data);
        final_hasher.update(client_data_hash);
        let expected_hash = final_hasher.finalize();

        assert_eq!(message_hash.as_slice(), &expected_hash[..]);
    }

    #[test]
    fn test_webauthn_flag_validation() {
        let tx_hash = B256::ZERO;

        // AT flag must be rejected for assertion signatures
        let data = build_webauthn_data(0x41, None, &tx_hash); // UP + AT
        let err = webauthn_digest(&data, &tx_hash).unwrap_err();
        assert!(err.contains("AT flag"), "Should reject AT flag");

        // ED flag must be rejected, as extensions are not supported
        let data = build_webauthn_data(0x81, Some(&[0xa0]), &tx_hash); // UP + ED, empty map
        let err = webauthn_digest(&data, &tx_hash).unwrap_err();
        assert!(err.contains("ED flag"), "Should reject ED flag");

        // Valid with only UP flag set
        let data = build_webauthn_data(0x01, None, &tx_hash); // UP only
        assert!(
            webauthn_digest(&data, &tx_hash).is_ok(),
            "Should accept valid webauthn data with only UP flag"
        );
    }

    #[test]
    fn test_webauthn_rejects_challenge_injection() {
        let (tx_hash, attack_hash) = (B256::repeat_byte(0xAA), B256::repeat_byte(0xFF));
        let (challenge, attack_challenge) = (
            URL_SAFE_NO_PAD.encode(tx_hash.as_slice()),
            URL_SAFE_NO_PAD.encode(attack_hash.as_slice()),
        );

        // Ensure that the happy path works
        let valid_payload = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}"}}"#);

        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01;
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(valid_payload.as_bytes());

        let result = webauthn_digest(&webauthn_data, &tx_hash);
        assert!(result.is_ok());

        // Ensure that malicious payloads cannot pass validation
        let attack_variants = [
            format!(
                r#"{{"type":"webauthn.get","challenge":"{attack_challenge}","extra":{{"challenge":"{challenge}"}}}}"#
            ),
            format!(
                r#"{{"type":"webauthn.get","data":[{{"challenge":"{challenge}"}}],"challenge":"{attack_challenge}"}}"#
            ),
        ];

        for (i, attack_json) in attack_variants.iter().enumerate() {
            let mut auth_data = vec![0u8; 37];
            auth_data[32] = 0x01;
            let mut webauthn_data = auth_data;
            webauthn_data.extend_from_slice(attack_json.as_bytes());

            let result = webauthn_digest(&webauthn_data, &tx_hash);
            assert!(
                result.is_err(),
                "Attack variant {i} should be rejected: {attack_json}"
            );
        }
    }
}
