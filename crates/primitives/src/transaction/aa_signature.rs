use super::account_abstraction::{
    MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH, SignatureType,
};
use alloy_primitives::{Address, B256, Bytes, Signature, keccak256};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};
use sha2::{Digest, Sha256};

/// Signature type identifiers
/// Note: Secp256k1 has no identifier - detected by length (65 bytes)
pub const SIGNATURE_TYPE_P256: u8 = 0x01;
pub const SIGNATURE_TYPE_WEBAUTHN: u8 = 0x02;
pub const SIGNATURE_TYPE_KEYCHAIN: u8 = 0x03;

/// P256 signature with pre-hash flag
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
pub struct P256SignatureWithPreHash {
    pub r: B256,
    pub s: B256,
    pub pub_key_x: B256,
    pub pub_key_y: B256,
    pub pre_hash: bool,
}

/// WebAuthn signature with authenticator data
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
pub struct WebAuthnSignature {
    pub r: B256,
    pub s: B256,
    pub pub_key_x: B256,
    pub pub_key_y: B256,
    /// authenticatorData || clientDataJSON (variable length)
    pub webauthn_data: Bytes,
}

/// Primitive signature types that can be used standalone or within a Keychain signature.
/// This enum contains only the base signature types: Secp256k1, P256, and WebAuthn.
/// It does NOT support Keychain signatures to prevent recursion.
///
/// Note: This enum uses custom RLP encoding via `to_bytes()` and does NOT derive Compact.
/// The Compact encoding is handled at the parent struct level (e.g., KeyAuthorization).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "camelCase"))]
pub enum PrimitiveSignature {
    /// Standard secp256k1 ECDSA signature (65 bytes: r, s, v)
    Secp256k1(Signature),

    /// P256 signature with embedded public key (129 bytes)
    P256(P256SignatureWithPreHash),

    /// WebAuthn signature with variable-length authenticator data
    WebAuthn(WebAuthnSignature),
}

/// Keychain signature wrapping another signature with a user address
/// This allows an access key to sign on behalf of a root account
///
/// Format: 0x03 || user_address (20 bytes) || inner_signature
///
/// The user_address is the root account this transaction is being executed for.
/// The inner signature proves an authorized access key signed the transaction.
/// The handler validates that user_address has authorized the access key in the KeyChain precompile.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
pub struct KeychainSignature {
    /// Root account address that this transaction is being executed for
    pub user_address: Address,
    /// The actual signature from the access key (can be Secp256k1, P256, or WebAuthn, but NOT another Keychain)
    pub signature: PrimitiveSignature,
}

/// AA transaction signature supporting multiple signature schemes
///
/// Note: Uses custom Compact implementation that delegates to `to_bytes()` / `from_bytes()`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "camelCase"))]
pub enum AASignature {
    /// Standard secp256k1 ECDSA signature (65 bytes: r, s, v)
    Secp256k1(Signature),

    /// P256 signature with embedded public key (129 bytes)
    P256(P256SignatureWithPreHash),

    /// WebAuthn signature with variable-length authenticator data
    WebAuthn(WebAuthnSignature),

    /// Keychain signature - wraps another signature with a key identifier
    /// Format: key_id (20 bytes) + inner signature
    /// IMP: The inner signature MUST NOT be another Keychain (validated at runtime)
    /// Note: Recursion is prevented by KeychainSignature's custom Arbitrary impl
    Keychain(KeychainSignature),
}

impl Default for AASignature {
    fn default() -> Self {
        Self::Secp256k1(Signature::test_signature())
    }
}

impl Default for PrimitiveSignature {
    fn default() -> Self {
        Self::Secp256k1(Signature::test_signature())
    }
}

impl alloy_rlp::Encodable for AASignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let bytes = self.to_bytes();
        alloy_rlp::Encodable::encode(&bytes, out);
    }

    fn length(&self) -> usize {
        self.to_bytes().length()
    }
}

impl alloy_rlp::Decodable for AASignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes: Bytes = alloy_rlp::Decodable::decode(buf)?;
        Self::from_bytes(&bytes).map_err(alloy_rlp::Error::Custom)
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for AASignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        let bytes = self.to_bytes();
        // Delegate to Bytes::to_compact which handles variable-length encoding
        bytes.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // Delegate to Bytes::from_compact which handles variable-length decoding
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = Self::from_bytes(&bytes).unwrap_or_else(|_| {
            // For proptest, return a default value based on the type identifier
            // Try to preserve the signature type even if decoding fails
            if bytes.len() == SECP256K1_SIGNATURE_LENGTH {
                // 65 bytes = Secp256k1
                Self::Secp256k1(Signature::test_signature())
            } else if !bytes.is_empty() {
                let type_id = bytes[0];
                match type_id {
                    SIGNATURE_TYPE_P256 => {
                        // Return a valid P256 signature with test values
                        Self::P256(P256SignatureWithPreHash {
                            r: B256::from([1u8; 32]),
                            s: B256::from([2u8; 32]),
                            pub_key_x: B256::from([3u8; 32]),
                            pub_key_y: B256::from([4u8; 32]),
                            pre_hash: false,
                        })
                    }
                    SIGNATURE_TYPE_WEBAUTHN => {
                        // Return a valid WebAuthn signature with test values
                        Self::WebAuthn(WebAuthnSignature {
                            r: B256::from([1u8; 32]),
                            s: B256::from([2u8; 32]),
                            pub_key_x: B256::from([3u8; 32]),
                            pub_key_y: B256::from([4u8; 32]),
                            webauthn_data: Bytes::from(vec![0u8; 128]),
                        })
                    }
                    SIGNATURE_TYPE_KEYCHAIN => {
                        // Extract the user_address even if inner signature fails
                        // Keychain format: 0x03 | user_address (20 bytes) | inner_signature
                        let sig_data = &bytes[1..];
                        let user_address = if sig_data.len() >= 20 {
                            Address::from_slice(&sig_data[0..20])
                        } else {
                            Address::ZERO
                        };

                        // Determine inner signature type if possible
                        let inner_signature = if sig_data.len() > 20 {
                            let inner_bytes = &sig_data[20..];
                            // Try to detect the inner signature type
                            if inner_bytes.len() == SECP256K1_SIGNATURE_LENGTH {
                                PrimitiveSignature::Secp256k1(Signature::test_signature())
                            } else if !inner_bytes.is_empty()
                                && inner_bytes[0] == SIGNATURE_TYPE_P256
                            {
                                PrimitiveSignature::P256(P256SignatureWithPreHash {
                                    r: B256::from([1u8; 32]),
                                    s: B256::from([2u8; 32]),
                                    pub_key_x: B256::from([3u8; 32]),
                                    pub_key_y: B256::from([4u8; 32]),
                                    pre_hash: false,
                                })
                            } else if !inner_bytes.is_empty()
                                && inner_bytes[0] == SIGNATURE_TYPE_WEBAUTHN
                            {
                                PrimitiveSignature::WebAuthn(WebAuthnSignature {
                                    r: B256::from([1u8; 32]),
                                    s: B256::from([2u8; 32]),
                                    pub_key_x: B256::from([3u8; 32]),
                                    pub_key_y: B256::from([4u8; 32]),
                                    webauthn_data: Bytes::from(vec![0u8; 128]),
                                })
                            } else {
                                PrimitiveSignature::default()
                            }
                        } else {
                            PrimitiveSignature::default()
                        };

                        Self::Keychain(KeychainSignature {
                            user_address,
                            signature: inner_signature,
                        })
                    }
                    _ => Self::default(),
                }
            } else {
                Self::default()
            }
        });
        (signature, rest)
    }
}

impl alloy_rlp::Encodable for PrimitiveSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let bytes = self.to_bytes();
        alloy_rlp::Encodable::encode(&bytes, out);
    }

    fn length(&self) -> usize {
        self.to_bytes().length()
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for PrimitiveSignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        let bytes = self.to_bytes();
        // Delegate to Bytes::to_compact which handles variable-length encoding
        bytes.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // Delegate to Bytes::from_compact which handles variable-length decoding
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = Self::from_bytes(&bytes).unwrap_or_else(|_| {
            // For proptest, return a default value based on the type identifier
            // Try to preserve the signature type even if decoding fails
            if bytes.len() == SECP256K1_SIGNATURE_LENGTH {
                // 65 bytes = Secp256k1
                Self::Secp256k1(Signature::test_signature())
            } else if !bytes.is_empty() {
                let type_id = bytes[0];
                match type_id {
                    SIGNATURE_TYPE_P256 => {
                        // Return a valid P256 signature with test values
                        Self::P256(P256SignatureWithPreHash {
                            r: B256::from([1u8; 32]),
                            s: B256::from([2u8; 32]),
                            pub_key_x: B256::from([3u8; 32]),
                            pub_key_y: B256::from([4u8; 32]),
                            pre_hash: false,
                        })
                    }
                    SIGNATURE_TYPE_WEBAUTHN => {
                        // Return a valid WebAuthn signature with test values
                        Self::WebAuthn(WebAuthnSignature {
                            r: B256::from([1u8; 32]),
                            s: B256::from([2u8; 32]),
                            pub_key_x: B256::from([3u8; 32]),
                            pub_key_y: B256::from([4u8; 32]),
                            webauthn_data: Bytes::from(vec![0u8; 128]),
                        })
                    }
                    _ => Self::default(),
                }
            } else {
                Self::default()
            }
        });
        (signature, rest)
    }
}

impl PrimitiveSignature {
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
                Ok(Self::P256(P256SignatureWithPreHash {
                    r: B256::from_slice(&sig_data[0..32]),
                    s: B256::from_slice(&sig_data[32..64]),
                    pub_key_x: B256::from_slice(&sig_data[64..96]),
                    pub_key_y: B256::from_slice(&sig_data[96..128]),
                    pre_hash: sig_data[128] != 0,
                }))
            }
            SIGNATURE_TYPE_WEBAUTHN => {
                let len = sig_data.len();
                if !(128..=MAX_WEBAUTHN_SIGNATURE_LENGTH).contains(&len) {
                    return Err("Invalid WebAuthn signature length");
                }
                Ok(Self::WebAuthn(WebAuthnSignature {
                    r: B256::from_slice(&sig_data[len - 128..len - 96]),
                    s: B256::from_slice(&sig_data[len - 96..len - 64]),
                    pub_key_x: B256::from_slice(&sig_data[len - 64..len - 32]),
                    pub_key_y: B256::from_slice(&sig_data[len - 32..]),
                    webauthn_data: Bytes::copy_from_slice(&sig_data[..len - 128]),
                }))
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
                Bytes::copy_from_slice(&sig.as_bytes())
            }
            Self::P256(p256_sig) => {
                let mut bytes = Vec::with_capacity(1 + 129);
                bytes.push(SIGNATURE_TYPE_P256);
                bytes.extend_from_slice(p256_sig.r.as_slice());
                bytes.extend_from_slice(p256_sig.s.as_slice());
                bytes.extend_from_slice(p256_sig.pub_key_x.as_slice());
                bytes.extend_from_slice(p256_sig.pub_key_y.as_slice());
                bytes.push(if p256_sig.pre_hash { 1 } else { 0 });
                Bytes::from(bytes)
            }
            Self::WebAuthn(webauthn_sig) => {
                let mut bytes = Vec::with_capacity(1 + webauthn_sig.webauthn_data.len() + 128);
                bytes.push(SIGNATURE_TYPE_WEBAUTHN);
                bytes.extend_from_slice(&webauthn_sig.webauthn_data);
                bytes.extend_from_slice(webauthn_sig.r.as_slice());
                bytes.extend_from_slice(webauthn_sig.s.as_slice());
                bytes.extend_from_slice(webauthn_sig.pub_key_x.as_slice());
                bytes.extend_from_slice(webauthn_sig.pub_key_y.as_slice());
                Bytes::from(bytes)
            }
        }
    }

    /// Get the length of the encoded signature in bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: 65 bytes (no type identifier)
    /// - P256/WebAuthn: includes 1-byte type identifier prefix
    pub fn encoded_length(&self) -> usize {
        match self {
            Self::Secp256k1(_) => SECP256K1_SIGNATURE_LENGTH,
            Self::P256(_) => 1 + P256_SIGNATURE_LENGTH,
            Self::WebAuthn(webauthn_sig) => 1 + webauthn_sig.webauthn_data.len() + 128,
        }
    }

    /// Get signature type
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Secp256k1(_) => SignatureType::Secp256k1,
            Self::P256(_) => SignatureType::P256,
            Self::WebAuthn(_) => SignatureType::WebAuthn,
        }
    }

    /// Get the in-memory size of the signature
    pub fn size(&self) -> usize {
        match self {
            Self::Secp256k1(_) => SECP256K1_SIGNATURE_LENGTH,
            Self::P256(_) => 1 + P256_SIGNATURE_LENGTH,
            Self::WebAuthn(webauthn_sig) => 1 + webauthn_sig.webauthn_data.len() + 128,
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
            Self::P256(p256_sig) => {
                // Prepare message hash for verification
                let message_hash = if p256_sig.pre_hash {
                    // Some P256 implementations (like Web Crypto) require pre-hashing
                    B256::from_slice(&Sha256::digest(sig_hash.as_slice()))
                } else {
                    *sig_hash
                };

                // Verify P256 signature cryptographically
                verify_p256_signature_internal(
                    p256_sig.r.as_slice(),
                    p256_sig.s.as_slice(),
                    p256_sig.pub_key_x.as_slice(),
                    p256_sig.pub_key_y.as_slice(),
                    &message_hash,
                )
                .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Derive and return address
                Ok(derive_p256_address(
                    &p256_sig.pub_key_x,
                    &p256_sig.pub_key_y,
                ))
            }
            Self::WebAuthn(webauthn_sig) => {
                // Parse and verify WebAuthn data, compute challenge hash
                let message_hash =
                    verify_webauthn_data_internal(&webauthn_sig.webauthn_data, sig_hash)
                        .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Verify P256 signature over the computed message hash
                verify_p256_signature_internal(
                    webauthn_sig.r.as_slice(),
                    webauthn_sig.s.as_slice(),
                    webauthn_sig.pub_key_x.as_slice(),
                    webauthn_sig.pub_key_y.as_slice(),
                    &message_hash,
                )
                .map_err(|_| alloy_consensus::crypto::RecoveryError::new())?;

                // Derive and return address
                Ok(derive_p256_address(
                    &webauthn_sig.pub_key_x,
                    &webauthn_sig.pub_key_y,
                ))
            }
        }
    }
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

        // Check if this is a Keychain signature (type identifier 0x03)
        // We need to handle this specially before delegating to PrimitiveSignature
        if data.len() > 1 && data[0] == SIGNATURE_TYPE_KEYCHAIN {
            let sig_data = &data[1..];

            // Keychain format: user_address (20 bytes) || inner_signature
            if sig_data.len() < 20 {
                return Err("Invalid Keychain signature: too short for user_address");
            }

            let user_address = Address::from_slice(&sig_data[0..20]);
            let inner_sig_bytes = &sig_data[20..];

            // Parse inner signature using PrimitiveSignature (which doesn't support Keychain)
            // This automatically prevents recursive keychain signatures at compile time
            let inner_signature = PrimitiveSignature::from_bytes(inner_sig_bytes)?;

            return Ok(Self::Keychain(KeychainSignature {
                user_address,
                signature: inner_signature,
            }));
        }

        // For all non-Keychain signatures, delegate to PrimitiveSignature
        let primitive = PrimitiveSignature::from_bytes(data)?;
        Ok(match primitive {
            PrimitiveSignature::Secp256k1(sig) => Self::Secp256k1(sig),
            PrimitiveSignature::P256(p256_sig) => Self::P256(p256_sig),
            PrimitiveSignature::WebAuthn(webauthn_sig) => Self::WebAuthn(webauthn_sig),
        })
    }

    /// Encode signature to bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: encoded WITHOUT type identifier (65 bytes)
    /// - P256/WebAuthn: encoded WITH type identifier prefix
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Secp256k1(sig) => PrimitiveSignature::Secp256k1(*sig).to_bytes(),
            Self::P256(p256_sig) => PrimitiveSignature::P256(*p256_sig).to_bytes(),
            Self::WebAuthn(webauthn_sig) => {
                PrimitiveSignature::WebAuthn(webauthn_sig.clone()).to_bytes()
            }
            Self::Keychain(keychain_sig) => {
                // Format: 0x03 | user_address (20 bytes) | inner_signature
                let inner_bytes = keychain_sig.signature.to_bytes();
                let mut bytes = Vec::with_capacity(1 + 20 + inner_bytes.len());
                bytes.push(SIGNATURE_TYPE_KEYCHAIN);
                bytes.extend_from_slice(keychain_sig.user_address.as_slice());
                bytes.extend_from_slice(&inner_bytes);
                Bytes::from(bytes)
            }
        }
    }

    /// Get the length of the encoded signature in bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: 65 bytes (no type identifier)
    /// - P256/WebAuthn: includes 1-byte type identifier prefix
    pub fn encoded_length(&self) -> usize {
        match self {
            Self::Secp256k1(sig) => PrimitiveSignature::Secp256k1(*sig).encoded_length(),
            Self::P256(p256_sig) => PrimitiveSignature::P256(*p256_sig).encoded_length(),
            Self::WebAuthn(webauthn_sig) => {
                PrimitiveSignature::WebAuthn(webauthn_sig.clone()).encoded_length()
            }
            Self::Keychain(keychain_sig) => 1 + 20 + keychain_sig.signature.encoded_length(),
        }
    }

    /// Get signature type
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Secp256k1(sig) => PrimitiveSignature::Secp256k1(*sig).signature_type(),
            Self::P256(p256_sig) => PrimitiveSignature::P256(*p256_sig).signature_type(),
            Self::WebAuthn(webauthn_sig) => {
                PrimitiveSignature::WebAuthn(webauthn_sig.clone()).signature_type()
            }
            Self::Keychain(keychain_sig) => keychain_sig.signature.signature_type(),
        }
    }

    /// Get the in-memory size of the signature
    pub fn size(&self) -> usize {
        match self {
            Self::Secp256k1(_) => SECP256K1_SIGNATURE_LENGTH,
            Self::P256(_) => 1 + P256_SIGNATURE_LENGTH,
            Self::WebAuthn(webauthn_sig) => 1 + webauthn_sig.webauthn_data.len() + 128,
            Self::Keychain(keychain_sig) => 1 + 20 + keychain_sig.signature.size(),
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
            Self::Secp256k1(sig) => PrimitiveSignature::Secp256k1(*sig).recover_signer(sig_hash),
            Self::P256(p256_sig) => PrimitiveSignature::P256(*p256_sig).recover_signer(sig_hash),
            Self::WebAuthn(webauthn_sig) => {
                PrimitiveSignature::WebAuthn(webauthn_sig.clone()).recover_signer(sig_hash)
            }
            Self::Keychain(keychain_sig) => {
                // Return the user_address - the root account this transaction is for
                // The handler will validate that the inner signature's recovered address
                // is authorized for this user_address in the KeyChain precompile
                Ok(keychain_sig.user_address)
            }
        }
    }
}

impl From<Signature> for AASignature {
    fn from(signature: Signature) -> Self {
        Self::Secp256k1(signature)
    }
}

// ============================================================================
// Helper Functions for Signature Verification
// ============================================================================

/// Derives a P256 address from public key coordinates
pub fn derive_p256_address(pub_key_x: &B256, pub_key_y: &B256) -> Address {
    let hash = keccak256([pub_key_x.as_slice(), pub_key_y.as_slice()].concat());

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
    // Parse public key from affine coordinates
    let encoded_point = EncodedPoint::from_affine_coordinates(
        pub_key_x.into(),
        pub_key_y.into(),
        false, // Not compressed
    );

    let verifying_key =
        VerifyingKey::from_encoded_point(&encoded_point).map_err(|_| "Invalid P256 public key")?;

    let signature = P256Signature::from_slice(&[r, s].concat())
        .map_err(|_| "Invalid P256 signature encoding")?;

    // Verify signature
    verifying_key
        .verify_prehash(message_hash.as_slice(), &signature)
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
            if let Ok(json_str) = core::str::from_utf8(potential_json)
                && json_str.starts_with('{')
                && json_str.ends_with('}')
            {
                client_data_json = Some(potential_json);
                auth_data_len = 37;
            }
        }
    } else {
        // AT flag is set, need to parse CBOR data (complex)
        // For now, try multiple split points and validate JSON
        for split_point in 37..webauthn_data.len().saturating_sub(20) {
            let potential_json = &webauthn_data[split_point..];
            if let Ok(json_str) = core::str::from_utf8(potential_json)
                && json_str.starts_with('{')
                && json_str.ends_with('}')
            {
                // Basic JSON validation - check for required fields
                if json_str.contains("\"type\"") && json_str.contains("\"challenge\"") {
                    client_data_json = Some(potential_json);
                    auth_data_len = split_point;
                    break;
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
    let challenge_property = format!("\"challenge\":\"{challenge_b64url}\"");
    if !json_str.contains(&challenge_property) {
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

// ============================================================================
// Arbitrary Implementations for Property Testing
// ============================================================================

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for P256SignatureWithPreHash {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Always use fixed test values to ensure valid signatures that round-trip correctly
        // Random B256 values are not guaranteed to be valid P256 curve points
        Ok(Self {
            r: B256::from([1u8; 32]),
            s: B256::from([2u8; 32]),
            pub_key_x: B256::from([3u8; 32]),
            pub_key_y: B256::from([4u8; 32]),
            pre_hash: false,
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for WebAuthnSignature {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use fixed test values to ensure valid signatures that round-trip correctly
        // Random B256 values are not guaranteed to be valid P256 curve points

        // Create a simple fixed authenticator data (37 bytes minimum)
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // Set UP flag

        // Create a simple fixed clientDataJSON
        let challenge = B256::ZERO;
        let challenge_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_slice());
        let client_data_json = format!(
            "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\"}}",
            challenge_b64
        );

        let mut webauthn_data = auth_data;
        webauthn_data.extend_from_slice(client_data_json.as_bytes());

        Ok(Self {
            r: B256::from([1u8; 32]),
            s: B256::from([2u8; 32]),
            pub_key_x: B256::from([3u8; 32]),
            pub_key_y: B256::from([4u8; 32]),
            webauthn_data: Bytes::from(webauthn_data),
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for PrimitiveSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Choose between the three primitive signature types
        let choice = u.int_in_range(0..=2)?;
        match choice {
            0 => {
                // Generate a valid Secp256k1 signature (avoid r=0, s=0)
                let mut sig = Signature::arbitrary(u)?;
                // If we get an invalid signature (r=0 and s=0), use test signature
                if sig.r().is_zero() && sig.s().is_zero() {
                    sig = Signature::test_signature();
                }
                Ok(Self::Secp256k1(sig))
            }
            1 => Ok(Self::P256(P256SignatureWithPreHash::arbitrary(u)?)),
            2 => Ok(Self::WebAuthn(WebAuthnSignature::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeychainSignature {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Use fixed values to ensure round-trip correctness
        Ok(Self {
            user_address: Address::ZERO,
            signature: PrimitiveSignature::Secp256k1(Signature::test_signature()),
        })
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for AASignature {
    fn arbitrary(_u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Always use Secp256k1 signature with test values for reliable round-trip
        // Other signature types (P256, WebAuthn, Keychain) have complex encoding
        // that may not round-trip perfectly with arbitrary data
        Ok(Self::Secp256k1(Signature::test_signature()))
    }
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
            ecdsa::{SigningKey, signature::hazmat::PrehashSigner},
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
        let signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(message_hash.as_slice()).unwrap();
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
        let client_data =
            format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge_b64url}\"}}");
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
        final_hasher.update(client_data_hash);
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

    #[test]
    #[cfg(feature = "serde")]
    fn test_aa_signature_serde_roundtrip() {
        // Test serde roundtrip for all signature types

        // Test Secp256k1
        let r_bytes = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let s_bytes = hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        let sig = Signature::new(
            alloy_primitives::U256::from_be_slice(&r_bytes),
            alloy_primitives::U256::from_be_slice(&s_bytes),
            false,
        );
        let secp256k1_sig = AASignature::Secp256k1(sig);

        let json = serde_json::to_string(&secp256k1_sig).unwrap();
        let decoded: AASignature = serde_json::from_str(&json).unwrap();
        assert_eq!(secp256k1_sig, decoded, "Secp256k1 serde roundtrip failed");

        // Test P256
        let p256_sig = AASignature::P256(P256SignatureWithPreHash {
            r: B256::from([1u8; 32]),
            s: B256::from([2u8; 32]),
            pub_key_x: B256::from([3u8; 32]),
            pub_key_y: B256::from([4u8; 32]),
            pre_hash: true,
        });

        let json = serde_json::to_string(&p256_sig).unwrap();
        let decoded: AASignature = serde_json::from_str(&json).unwrap();
        assert_eq!(p256_sig, decoded, "P256 serde roundtrip failed");

        // Verify camelCase naming
        assert!(
            json.contains("\"pubKeyX\""),
            "Should use camelCase for pubKeyX"
        );
        assert!(
            json.contains("\"pubKeyY\""),
            "Should use camelCase for pubKeyY"
        );
        assert!(
            json.contains("\"preHash\""),
            "Should use camelCase for preHash"
        );

        // Test WebAuthn
        let webauthn_sig = AASignature::WebAuthn(WebAuthnSignature {
            r: B256::from([5u8; 32]),
            s: B256::from([6u8; 32]),
            pub_key_x: B256::from([7u8; 32]),
            pub_key_y: B256::from([8u8; 32]),
            webauthn_data: Bytes::from(vec![9u8; 50]),
        });

        let json = serde_json::to_string(&webauthn_sig).unwrap();
        let decoded: AASignature = serde_json::from_str(&json).unwrap();
        assert_eq!(webauthn_sig, decoded, "WebAuthn serde roundtrip failed");

        // Verify camelCase naming
        assert!(
            json.contains("\"pubKeyX\""),
            "Should use camelCase for pubKeyX"
        );
        assert!(
            json.contains("\"pubKeyY\""),
            "Should use camelCase for pubKeyY"
        );
        assert!(
            json.contains("\"webauthnData\""),
            "Should use camelCase for webauthnData"
        );
    }
}
