use super::account_abstraction::{
    MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH, SignatureType,
};
use alloy_primitives::{Address, B256, Bytes, Signature, keccak256};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::Verifier},
};
use sha2::{Digest, Sha256};

/// Signature type identifiers
/// Note: Secp256k1 has no identifier - detected by length (65 bytes)
pub const SIGNATURE_TYPE_P256: u8 = 0x01;
pub const SIGNATURE_TYPE_WEBAUTHN: u8 = 0x02;

/// AA transaction signature supporting multiple signature schemes
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum AASignature {
    /// Standard secp256k1 ECDSA signature (65 bytes: r, s, v)
    Secp256k1(Signature),

    /// P256 signature with embedded public key (129 bytes)
    P256 {
        r: B256,
        s: B256,
        pub_key_x: B256,
        pub_key_y: B256,
        pre_hash: bool,
    },

    /// WebAuthn signature with variable-length authenticator data
    WebAuthn {
        /// authenticatorData || clientDataJSON (variable length)
        webauthn_data: Bytes,
        r: B256,
        s: B256,
        pub_key_x: B256,
        pub_key_y: B256,
    },
}

impl AASignature {
    /// Parse signature from bytes with backward compatibility
    ///
    /// For backward compatibility with existing secp256k1 signatures:
    /// - If length is 65 bytes: treat as secp256k1 signature (no type identifier)
    /// - Otherwise: first byte is the signature type identifier
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("Signature data is empty");
        }

        // Backward compatibility: 65 bytes means secp256k1 without type identifier
        if data.len() == SECP256K1_SIGNATURE_LENGTH {
            let sig =
                Signature::try_from(data).map_err(|_| "Failed to parse secp256k1 signature")?;
            return Ok(Self::Secp256k1(sig));
        }

        // For all other lengths, first byte is the type identifier
        let type_id = data[0];
        let sig_data = &data[1..];

        match type_id {
            SIGNATURE_TYPE_P256 => {
                if sig_data.len() != P256_SIGNATURE_LENGTH {
                    return Err("Invalid P256 signature length");
                }
                Ok(Self::P256 {
                    r: B256::from_slice(&sig_data[0..32]),
                    s: B256::from_slice(&sig_data[32..64]),
                    pub_key_x: B256::from_slice(&sig_data[64..96]),
                    pub_key_y: B256::from_slice(&sig_data[96..128]),
                    pre_hash: sig_data[128] != 0,
                })
            }
            SIGNATURE_TYPE_WEBAUTHN => {
                let len = sig_data.len();
                if len < 128 || len > MAX_WEBAUTHN_SIGNATURE_LENGTH {
                    return Err("Invalid WebAuthn signature length");
                }
                Ok(Self::WebAuthn {
                    webauthn_data: Bytes::copy_from_slice(&sig_data[..len - 128]),
                    r: B256::from_slice(&sig_data[len - 128..len - 96]),
                    s: B256::from_slice(&sig_data[len - 96..len - 64]),
                    pub_key_x: B256::from_slice(&sig_data[len - 64..len - 32]),
                    pub_key_y: B256::from_slice(&sig_data[len - 32..]),
                })
            }
            _ => Err("Unknown signature type identifier"),
        }
    }

    /// Encode signature to bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: encoded WITHOUT type identifier (65 bytes)
    /// - P256/WebAuthn: encoded WITH type identifier prefix
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Secp256k1(sig) => {
                // Backward compatibility: no type identifier for secp256k1
                let mut bytes = Vec::with_capacity(65);
                bytes.extend_from_slice(&sig.r().to_be_bytes::<32>());
                bytes.extend_from_slice(&sig.s().to_be_bytes::<32>());
                bytes.push(27 + sig.v() as u8);
                Bytes::from(bytes)
            }
            Self::P256 {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash,
            } => {
                let mut bytes = Vec::with_capacity(1 + 129);
                bytes.push(SIGNATURE_TYPE_P256);
                bytes.extend_from_slice(r.as_slice());
                bytes.extend_from_slice(s.as_slice());
                bytes.extend_from_slice(pub_key_x.as_slice());
                bytes.extend_from_slice(pub_key_y.as_slice());
                bytes.push(if *pre_hash { 1 } else { 0 });
                Bytes::from(bytes)
            }
            Self::WebAuthn {
                webauthn_data,
                r,
                s,
                pub_key_x,
                pub_key_y,
            } => {
                let mut bytes = Vec::with_capacity(1 + webauthn_data.len() + 128);
                bytes.push(SIGNATURE_TYPE_WEBAUTHN);
                bytes.extend_from_slice(webauthn_data);
                bytes.extend_from_slice(r.as_slice());
                bytes.extend_from_slice(s.as_slice());
                bytes.extend_from_slice(pub_key_x.as_slice());
                bytes.extend_from_slice(pub_key_y.as_slice());
                Bytes::from(bytes)
            }
        }
    }

    /// Get the length of the encoded signature in bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: 65 bytes (no type identifier)
    /// - P256/WebAuthn: includes 1-byte type identifier prefix
    pub fn length(&self) -> usize {
        match self {
            Self::Secp256k1(_) => SECP256K1_SIGNATURE_LENGTH,
            Self::P256 { .. } => 1 + P256_SIGNATURE_LENGTH,
            Self::WebAuthn { webauthn_data, .. } => 1 + webauthn_data.len() + 128,
        }
    }

    /// Get signature type
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Secp256k1(_) => SignatureType::Secp256k1,
            Self::P256 { .. } => SignatureType::P256,
            Self::WebAuthn { .. } => SignatureType::WebAuthn,
        }
    }

    /// Recover the signer address from the signature
    ///
    /// This function verifies the signature and extracts the address based on signature type:
    /// - secp256k1: Uses standard ecrecover (signature verification + address recovery)
    /// - P256: Verifies P256 signature then derives address from public key
    /// - WebAuthn: Parses WebAuthn data, verifies P256 signature, derives address
    pub fn recover_signer(
        &self,
        sig_hash: &B256,
    ) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Secp256k1(sig) => {
                // Standard secp256k1 recovery using alloy's built-in methods
                // This simultaneously verifies the signature AND recovers the address
                Ok(sig.recover_address_from_prehash(sig_hash)?)
            }
            Self::P256 {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash,
            } => {
                // Prepare message hash for verification
                let message_hash = if *pre_hash {
                    // Some P256 implementations (like Web Crypto) require pre-hashing
                    B256::from_slice(&Sha256::digest(sig_hash.as_slice()))
                } else {
                    *sig_hash
                };

                // Verify P256 signature cryptographically
                verify_p256_signature_internal(
                    r.as_slice(),
                    s.as_slice(),
                    pub_key_x.as_slice(),
                    pub_key_y.as_slice(),
                    &message_hash,
                )
                .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Derive and return address
                Ok(derive_p256_address(pub_key_x, pub_key_y))
            }
            Self::WebAuthn {
                webauthn_data,
                r,
                s,
                pub_key_x,
                pub_key_y,
            } => {
                // Parse and verify WebAuthn data, compute challenge hash
                let message_hash = verify_webauthn_data_internal(webauthn_data, sig_hash)
                    .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Verify P256 signature over the computed message hash
                verify_p256_signature_internal(
                    r.as_slice(),
                    s.as_slice(),
                    pub_key_x.as_slice(),
                    pub_key_y.as_slice(),
                    &message_hash,
                )
                .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Derive and return address
                Ok(derive_p256_address(pub_key_x, pub_key_y))
            }
        }
    }
}

// ============================================================================
// Helper Functions for Signature Verification
// ============================================================================

/// Derives a P256 address from public key coordinates
pub fn derive_p256_address(pub_key_x: &B256, pub_key_y: &B256) -> Address {
    let hash = keccak256(&[pub_key_x.as_slice(), pub_key_y.as_slice()].concat());

    // Take last 20 bytes as address
    Address::from_slice(&hash[12..])
}

/// Verifies a P256 signature using the provided components
///
/// This performs actual cryptographic verification of the P256 signature
/// according to the spec. Called during `recover_signer()` to ensure only
/// valid signatures enter the mempool.
fn verify_p256_signature_internal(
    r: &[u8],
    s: &[u8],
    pub_key_x: &[u8],
    pub_key_y: &[u8],
    message_hash: &B256,
) -> Result<(), &'static str> {
    // Construct uncompressed public key point (0x04 || x || y)
    let mut pub_key_bytes = [0u8; 65];
    pub_key_bytes[0] = 0x04; // Uncompressed point marker
    pub_key_bytes[1..33].copy_from_slice(pub_key_x);
    pub_key_bytes[33..65].copy_from_slice(pub_key_y);

    // Parse public key
    let encoded_point =
        EncodedPoint::from_bytes(&pub_key_bytes).map_err(|_| "Invalid P256 public key encoding")?;

    let verifying_key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| "Invalid P256 public key")?;

    // Construct signature from r and s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0..32].copy_from_slice(r);
    sig_bytes[32..64].copy_from_slice(s);

    let signature = P256Signature::from_bytes(&sig_bytes.into())
        .map_err(|_| "Invalid P256 signature encoding")?;

    // Verify signature
    verifying_key
        .verify(message_hash.as_slice(), &signature)
        .map_err(|_| "P256 signature verification failed")
}

/// Parses and validates WebAuthn data, returning the message hash for P256 verification
///
/// According to the spec, this:
/// 1. Parses authenticatorData and clientDataJSON
/// 2. Validates authenticatorData (min 37 bytes, UP flag set)
/// 3. Validates clientDataJSON (type="webauthn.get", challenge matches tx_hash)
/// 4. Computes message hash = sha256(authenticatorData || sha256(clientDataJSON))
fn verify_webauthn_data_internal(
    webauthn_data: &[u8],
    tx_hash: &B256,
) -> Result<B256, &'static str> {
    // Minimum authenticatorData is 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
    if webauthn_data.len() < 37 {
        return Err("WebAuthn data too short");
    }

    // Find the split between authenticatorData and clientDataJSON
    // Strategy: Try to parse as JSON from different split points
    // authenticatorData is minimum 37 bytes, so start searching from there
    let mut auth_data_len = 37;
    let mut client_data_json = None;

    // Check if AT flag (bit 6) is set in flags byte (byte 32)
    let flags = webauthn_data[32];
    let at_flag_set = (flags & 0x40) != 0;

    if !at_flag_set {
        // Simple case: authenticatorData is exactly 37 bytes
        if webauthn_data.len() > 37 {
            let potential_json = &webauthn_data[37..];
            if let Ok(json_str) = core::str::from_utf8(potential_json) {
                if json_str.starts_with('{') && json_str.ends_with('}') {
                    client_data_json = Some(potential_json);
                    auth_data_len = 37;
                }
            }
        }
    } else {
        // AT flag is set, need to parse CBOR data (complex)
        // For now, try multiple split points and validate JSON
        for split_point in 37..webauthn_data.len().saturating_sub(20) {
            let potential_json = &webauthn_data[split_point..];
            if let Ok(json_str) = core::str::from_utf8(potential_json) {
                if json_str.starts_with('{') && json_str.ends_with('}') {
                    // Basic JSON validation - check for required fields
                    if json_str.contains("\"type\"") && json_str.contains("\"challenge\"") {
                        client_data_json = Some(potential_json);
                        auth_data_len = split_point;
                        break;
                    }
                }
            }
        }
    }

    let client_data_json =
        client_data_json.ok_or("Failed to parse clientDataJSON from WebAuthn data")?;
    let authenticator_data = &webauthn_data[..auth_data_len];

    // Validate authenticatorData
    if authenticator_data.len() < 37 {
        return Err("AuthenticatorData too short");
    }

    // Check UP flag (bit 0) is set
    let flags = authenticator_data[32];
    if (flags & 0x01) == 0 {
        return Err("User Presence (UP) flag not set in authenticatorData");
    }

    // Validate clientDataJSON
    let json_str =
        core::str::from_utf8(client_data_json).map_err(|_| "clientDataJSON is not valid UTF-8")?;

    // Check for required type field
    if !json_str.contains("\"type\":\"webauthn.get\"") {
        return Err("clientDataJSON missing required type field");
    }

    // Verify challenge matches tx_hash (Base64URL encoded)
    let challenge_b64url = URL_SAFE_NO_PAD.encode(tx_hash.as_slice());
    let challenge_property = format!("\"challenge\":\"{}\"", challenge_b64url);
    if !json_str.contains(&challenge_property) {
        return Err("clientDataJSON challenge does not match transaction hash");
    }

    // Compute message hash according to spec:
    // messageHash = sha256(authenticatorData || sha256(clientDataJSON))
    let client_data_hash = Sha256::digest(client_data_json);

    let mut final_hasher = Sha256::new();
    final_hasher.update(authenticator_data);
    final_hasher.update(&client_data_hash);
    let message_hash = final_hasher.finalize();

    Ok(B256::from_slice(&message_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;

    #[test]
    fn test_p256_signature_verification_invalid_pubkey() {
        // Invalid public key should fail
        let r = [0u8; 32];
        let s = [0u8; 32];
        let pub_key_x = [0u8; 32]; // Invalid: point not on curve
        let pub_key_y = [0u8; 32];
        let message_hash = B256::ZERO;

        let result = verify_p256_signature_internal(&r, &s, &pub_key_x, &pub_key_y, &message_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_p256_signature_verification_invalid_signature() {
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

        // Generate a valid key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Extract public key coordinates
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded_point.x().unwrap();
        let pub_key_y = encoded_point.y().unwrap();

        // Use invalid signature (all zeros)
        let r = [0u8; 32];
        let s = [0u8; 32];
        let message_hash = B256::ZERO;

        let result = verify_p256_signature_internal(
            &r,
            &s,
            pub_key_x.as_slice(),
            pub_key_y.as_slice(),
            &message_hash,
        );
        assert!(
            result.is_err(),
            "Invalid signature should fail verification"
        );
    }

    #[test]
    fn test_p256_signature_verification_valid() {
        use p256::{
            ecdsa::{SigningKey, signature::Signer},
            elliptic_curve::rand_core::OsRng,
        };
        use sha2::{Digest, Sha256};

        // Generate a valid key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create a message and sign it
        let message = b"test message";
        let message_hash = B256::from_slice(&Sha256::digest(message));

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(message_hash.as_slice());
        let sig_bytes = signature.to_bytes();
        let r = &sig_bytes[0..32];
        let s = &sig_bytes[32..64];

        // Extract public key coordinates
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = encoded_point.x().unwrap();
        let pub_key_y = encoded_point.y().unwrap();

        // Verify the signature
        let result = verify_p256_signature_internal(
            r,
            s,
            pub_key_x.as_slice(),
            pub_key_y.as_slice(),
            &message_hash,
        );
        assert!(
            result.is_ok(),
            "Valid P256 signature should verify successfully"
        );
    }

    #[test]
    fn test_webauthn_data_verification_too_short() {
        // WebAuthn data must be at least 37 bytes (authenticatorData minimum)
        let short_data = vec![0u8; 36];
        let tx_hash = B256::ZERO;

        let result = verify_webauthn_data_internal(&short_data, &tx_hash);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "WebAuthn data too short");
    }

    #[test]
    fn test_webauthn_data_verification_missing_up_flag() {
        // Create authenticatorData without UP flag set
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x00; // flags byte with UP flag not set

        // Add minimal clientDataJSON
        let client_data = b"{\"type\":\"webauthn.get\",\"challenge\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data);

        let tx_hash = B256::ZERO;
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "User Presence (UP) flag not set in authenticatorData"
        );
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
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "clientDataJSON missing required type field"
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
        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "clientDataJSON challenge does not match transaction hash"
        );
    }

    #[test]
    fn test_webauthn_data_verification_valid() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest, Sha256};

        // Create valid authenticatorData with UP flag
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // flags byte with UP flag set

        // Create a test transaction hash
        let tx_hash = B256::from_slice(&[0xAA; 32]);

        // Encode challenge as Base64URL
        let challenge_b64url = URL_SAFE_NO_PAD.encode(tx_hash.as_slice());

        // Create valid clientDataJSON with matching challenge
        let client_data = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}",
            challenge_b64url
        );
        let mut webauthn_data = auth_data.clone();
        webauthn_data.extend_from_slice(client_data.as_bytes());

        let result = verify_webauthn_data_internal(&webauthn_data, &tx_hash);
        assert!(
            result.is_ok(),
            "Valid WebAuthn data should verify successfully"
        );

        // Verify the computed message hash is correct
        let message_hash = result.unwrap();

        // Manually compute expected hash
        let client_data_hash = Sha256::digest(client_data.as_bytes());

        let mut final_hasher = Sha256::new();
        final_hasher.update(&auth_data);
        final_hasher.update(&client_data_hash);
        let expected_hash = final_hasher.finalize();

        assert_eq!(message_hash.as_slice(), expected_hash.as_slice());
    }

    #[test]
    fn test_p256_address_derivation() {
        let pub_key_x =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y =
            hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let addr1 = derive_p256_address(&pub_key_x, &pub_key_y);
        let addr2 = derive_p256_address(&pub_key_x, &pub_key_y);

        // Should be deterministic
        assert_eq!(addr1, addr2);

        // Should not be zero address
        assert_ne!(addr1, Address::ZERO);
    }

    #[test]
    fn test_p256_address_derivation_deterministic() {
        // Test that address derivation is deterministic
        let pub_key_x =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y =
            hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let addr1 = derive_p256_address(&pub_key_x, &pub_key_y);
        let addr2 = derive_p256_address(&pub_key_x, &pub_key_y);

        assert_eq!(addr1, addr2, "Address derivation should be deterministic");
    }

    #[test]
    fn test_p256_address_different_keys_different_addresses() {
        // Different keys should produce different addresses
        let pub_key_x1 =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();
        let pub_key_y1 =
            hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();

        let pub_key_x2 =
            hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321").into();
        let pub_key_y2 =
            hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").into();

        let addr1 = derive_p256_address(&pub_key_x1, &pub_key_y1);
        let addr2 = derive_p256_address(&pub_key_x2, &pub_key_y2);

        assert_ne!(
            addr1, addr2,
            "Different keys should produce different addresses"
        );
    }

    #[test]
    fn test_aa_signature_from_bytes_secp256k1() {
        use super::SECP256K1_SIGNATURE_LENGTH;

        // Secp256k1 signatures are detected by length (65 bytes), no type identifier
        let sig_bytes = vec![0u8; SECP256K1_SIGNATURE_LENGTH];
        let result = AASignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let AASignature::Secp256k1(_) = result.unwrap() {
            // Expected
        } else {
            panic!("Expected Secp256k1 variant");
        }
    }

    #[test]
    fn test_aa_signature_from_bytes_p256() {
        use super::{P256_SIGNATURE_LENGTH, SIGNATURE_TYPE_P256};

        let mut sig_bytes = vec![SIGNATURE_TYPE_P256];
        sig_bytes.extend_from_slice(&[0u8; P256_SIGNATURE_LENGTH]);
        let result = AASignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let AASignature::P256 { .. } = result.unwrap() {
            // Expected
        } else {
            panic!("Expected P256 variant");
        }
    }

    #[test]
    fn test_aa_signature_from_bytes_webauthn() {
        use super::SIGNATURE_TYPE_WEBAUTHN;

        let mut sig_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig_bytes.extend_from_slice(&[0u8; 200]); // 200 bytes of WebAuthn data
        let result = AASignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let AASignature::WebAuthn { .. } = result.unwrap() {
            // Expected
        } else {
            panic!("Expected WebAuthn variant");
        }
    }

    #[test]
    fn test_aa_signature_roundtrip() {
        use super::{
            P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH, SIGNATURE_TYPE_P256,
            SIGNATURE_TYPE_WEBAUTHN,
        };

        // Test secp256k1 (no type identifier, detected by 65-byte length)
        let sig1_bytes = vec![1u8; SECP256K1_SIGNATURE_LENGTH];
        let sig1 = AASignature::from_bytes(&sig1_bytes).unwrap();
        let encoded1 = sig1.to_bytes();
        assert_eq!(encoded1.len(), SECP256K1_SIGNATURE_LENGTH); // No type identifier
        // Verify roundtrip
        let decoded1 = AASignature::from_bytes(&encoded1).unwrap();
        assert_eq!(sig1, decoded1);

        // Test P256
        let mut sig2_bytes = vec![SIGNATURE_TYPE_P256];
        sig2_bytes.extend_from_slice(&[2u8; P256_SIGNATURE_LENGTH]);
        let sig2 = AASignature::from_bytes(&sig2_bytes).unwrap();
        let encoded2 = sig2.to_bytes();
        assert_eq!(encoded2.len(), 1 + P256_SIGNATURE_LENGTH);
        // Verify roundtrip
        let decoded2 = AASignature::from_bytes(&encoded2).unwrap();
        assert_eq!(sig2, decoded2);

        // Test WebAuthn
        let mut sig3_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig3_bytes.extend_from_slice(&[3u8; 200]);
        let sig3 = AASignature::from_bytes(&sig3_bytes).unwrap();
        let encoded3 = sig3.to_bytes();
        assert_eq!(encoded3.len(), 1 + 200);
        // Verify roundtrip
        let decoded3 = AASignature::from_bytes(&encoded3).unwrap();
        assert_eq!(sig3, decoded3);
    }
}
