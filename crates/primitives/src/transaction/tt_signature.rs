use super::tempo_transaction::{
    MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH, SignatureType,
};
use alloy_primitives::{Address, B256, Bytes, Signature, keccak256};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    EncodedPoint,
    ecdsa::{Signature as P256Signature, VerifyingKey, signature::hazmat::PrehashVerifier},
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Signature type identifiers
/// Note: Secp256k1 has no identifier - detected by length (65 bytes)
pub const SIGNATURE_TYPE_P256: u8 = 0x01;
pub const SIGNATURE_TYPE_WEBAUTHN: u8 = 0x02;
pub const SIGNATURE_TYPE_KEYCHAIN: u8 = 0x03;

// Minimum authenticatorData is 37 bytes (32 rpIdHash + 1 flags + 4 signCount)
const MIN_AUTH_DATA_LEN: usize = 37;

/// P256 signature with pre-hash flag
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
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
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
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
#[cfg_attr(
    all(test, feature = "reth-codec"),
    reth_codecs::add_arbitrary_tests(compact, rlp)
)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum PrimitiveSignature {
    /// Standard secp256k1 ECDSA signature (65 bytes: r, s, v)
    Secp256k1(Signature),

    /// P256 signature with embedded public key (129 bytes)
    P256(P256SignatureWithPreHash),

    /// WebAuthn signature with variable-length authenticator data
    WebAuthn(WebAuthnSignature),
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

        // Backward compatibility: exactly 65 bytes means secp256k1 without type identifier
        if data.len() == SECP256K1_SIGNATURE_LENGTH {
            let sig = Signature::try_from(data)
                .map_err(|_| "Failed to parse secp256k1 signature: invalid signature values")?;
            return Ok(Self::Secp256k1(sig));
        }

        // For all other lengths, first byte is the type identifier
        if data.len() < 2 {
            return Err("Signature data too short: expected type identifier + signature data");
        }

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
                // Ensure exactly 65 bytes by using a fixed-size buffer
                let sig_bytes = sig.as_bytes();
                assert_eq!(
                    sig_bytes.len(),
                    SECP256K1_SIGNATURE_LENGTH,
                    "Secp256k1 signature must be exactly 65 bytes"
                );
                Bytes::copy_from_slice(&sig_bytes)
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

impl Default for PrimitiveSignature {
    fn default() -> Self {
        Self::Secp256k1(Signature::test_signature())
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

impl alloy_rlp::Decodable for PrimitiveSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes: Bytes = alloy_rlp::Decodable::decode(buf)?;
        Self::from_bytes(&bytes).map_err(alloy_rlp::Error::Custom)
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
        let signature = Self::from_bytes(&bytes)
            .expect("Failed to decode PrimitiveSignature from compact encoding");
        (signature, rest)
    }
}

/// Keychain signature wrapping another signature with a user address
/// This allows an access key to sign on behalf of a root account
///
/// Format: 0x03 || user_address (20 bytes) || inner_signature
///
/// The user_address is the root account this transaction is being executed for.
/// The inner signature proves an authorized access key signed the transaction.
/// The handler validates that user_address has authorized the access key in the KeyChain precompile.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact))]
pub struct KeychainSignature {
    /// Root account address that this transaction is being executed for
    pub user_address: Address,
    /// The actual signature from the access key (can be Secp256k1, P256, or WebAuthn, but NOT another Keychain)
    pub signature: PrimitiveSignature,
    /// Cached access key ID recovered from the inner signature.
    /// This is an implementation detail - use `key_id()` to access.
    /// Uses OnceLock for thread-safe interior mutability.
    /// Note: Excluded from PartialEq, Eq, Hash, and Compact as it's a cache.
    #[cfg_attr(feature = "serde", serde(skip))]
    cached_key_id: OnceLock<Address>,
}

impl KeychainSignature {
    /// Create a new KeychainSignature
    pub fn new(user_address: Address, signature: PrimitiveSignature) -> Self {
        Self {
            user_address,
            signature,
            cached_key_id: OnceLock::new(),
        }
    }

    /// Get the access key ID for Keychain signatures.
    ///
    /// For Keychain signatures, this returns the access key address that signed the transaction.
    /// The key_id is recovered from the inner signature on first access and cached for
    /// subsequent calls. Returns None for non-Keychain signatures.
    ///
    /// This follows the pattern used in alloy for lazy hash computation.
    pub fn key_id(
        &self,
        sig_hash: &B256,
    ) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        // Check if already cached
        if let Some(cached) = self.cached_key_id.get() {
            return Ok(*cached);
        }

        // Not cached - recover and cache
        let key_id = self.signature.recover_signer(sig_hash)?;
        let _ = self.cached_key_id.set(key_id);
        Ok(key_id)
    }
}

// Manual implementations of PartialEq, Eq, and Hash that exclude cached_key_id
// since it's just a cache and doesn't affect the logical equality of signatures
impl PartialEq for KeychainSignature {
    fn eq(&self, other: &Self) -> bool {
        self.user_address == other.user_address && self.signature == other.signature
    }
}

impl Eq for KeychainSignature {}

impl core::hash::Hash for KeychainSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.user_address.hash(state);
        self.signature.hash(state);
    }
}

// Manual Compact implementation that excludes cached_key_id (cache field)
#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for KeychainSignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        // Only encode user_address and signature, skip cached_key_id
        let mut written = 0;
        written += self.user_address.to_compact(buf);
        written += self.signature.to_compact(buf);
        written
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        // Decode user_address and signature, initialize cached_key_id as empty
        let (user_address, rest) = Address::from_compact(buf, len);
        let remaining_len = len - (buf.len() - rest.len());
        let (signature, rest) = PrimitiveSignature::from_compact(rest, remaining_len);

        (
            Self {
                user_address,
                signature,
                cached_key_id: OnceLock::new(),
            },
            rest,
        )
    }
}

// Manual Arbitrary implementation that excludes cached_key_id (cache field)
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeychainSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            user_address: u.arbitrary()?,
            signature: u.arbitrary()?,
            cached_key_id: OnceLock::new(), // Always start with empty cache
        })
    }
}

/// AA transaction signature supporting multiple signature schemes
///
/// Note: Uses custom Compact implementation that delegates to `to_bytes()` / `from_bytes()`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged, rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub enum TempoSignature {
    /// Primitive signature types: Secp256k1, P256, or WebAuthn
    Primitive(PrimitiveSignature),

    /// Keychain signature - wraps another signature with a key identifier
    /// Format: key_id (20 bytes) + inner signature
    /// IMP: The inner signature MUST NOT be another Keychain (validated at runtime)
    /// Note: Recursion is prevented by KeychainSignature's custom Arbitrary impl
    Keychain(KeychainSignature),
}

impl TempoSignature {
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
        if data.len() > 1
            && data.len() != SECP256K1_SIGNATURE_LENGTH
            && data[0] == SIGNATURE_TYPE_KEYCHAIN
        {
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
                cached_key_id: OnceLock::new(),
            }));
        }

        // For all non-Keychain signatures, delegate to PrimitiveSignature
        let primitive = PrimitiveSignature::from_bytes(data)?;
        Ok(Self::Primitive(primitive))
    }

    /// Encode signature to bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: encoded WITHOUT type identifier (65 bytes)
    /// - P256/WebAuthn: encoded WITH type identifier prefix
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.to_bytes(),
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
            Self::Primitive(primitive_sig) => primitive_sig.encoded_length(),
            Self::Keychain(keychain_sig) => 1 + 20 + keychain_sig.signature.encoded_length(),
        }
    }

    /// Get signature type
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.signature_type(),
            Self::Keychain(keychain_sig) => keychain_sig.signature.signature_type(),
        }
    }

    /// Get the in-memory size of the signature
    pub fn size(&self) -> usize {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.size(),
            Self::Keychain(keychain_sig) => 1 + 20 + keychain_sig.signature.size(),
        }
    }

    /// Recover the signer address from the signature
    ///
    /// This function verifies the signature and extracts the address based on signature type:
    /// - secp256k1: Uses standard ecrecover (signature verification + address recovery)
    /// - P256: Verifies P256 signature then derives address from public key
    /// - WebAuthn: Parses WebAuthn data, verifies P256 signature, derives address
    /// - Keychain: Validates inner signature and returns user_address
    ///
    /// For Keychain signatures, this performs full validation of the inner signature.
    /// The access key address is cached in the KeychainSignature for later use.
    pub fn recover_signer(
        &self,
        sig_hash: &B256,
    ) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.recover_signer(sig_hash),
            Self::Keychain(keychain_sig) => {
                // Ensure validity of the keychain signature and cache the key id
                keychain_sig.key_id(sig_hash)?;

                // Return the user_address - the root account this transaction is for
                Ok(keychain_sig.user_address)
            }
        }
    }

    /// Check if this is a Keychain signature
    pub fn is_keychain(&self) -> bool {
        matches!(self, Self::Keychain(_))
    }

    /// Get the Keychain signature if this is a Keychain signature
    pub fn as_keychain(&self) -> Option<&KeychainSignature> {
        match self {
            Self::Keychain(keychain_sig) => Some(keychain_sig),
            _ => None,
        }
    }
}

impl Default for TempoSignature {
    fn default() -> Self {
        Self::Primitive(PrimitiveSignature::default())
    }
}

impl alloy_rlp::Encodable for TempoSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let bytes = self.to_bytes();
        alloy_rlp::Encodable::encode(&bytes, out);
    }

    fn length(&self) -> usize {
        self.to_bytes().length()
    }
}

impl alloy_rlp::Decodable for TempoSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes: Bytes = alloy_rlp::Decodable::decode(buf)?;
        Self::from_bytes(&bytes).map_err(alloy_rlp::Error::Custom)
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for TempoSignature {
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
        let signature = Self::from_bytes(&bytes)
            .expect("Failed to decode TempoSignature from compact encoding");
        (signature, rest)
    }
}

impl From<Signature> for TempoSignature {
    fn from(signature: Signature) -> Self {
        Self::Primitive(PrimitiveSignature::Secp256k1(signature))
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
/// ref: <https://www.w3.org/TR/webauthn-2/#sctn-authenticator-data>
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
    // Ensure that we have clientDataJSON after authenticatorData
    if webauthn_data.len() < MIN_AUTH_DATA_LEN + 32 {
        return Err("WebAuthn data too short");
    }

    // Check flags (byte 32): UP (bit 0), AT (bit 6), ED (bit 7)
    let flags = webauthn_data[32];
    let (up_flag, at_flag, ed_flag) = (flags & 0x01, flags & 0x40, flags & 0x80);

    // UP flag MUST be set
    if up_flag == 0 {
        return Err("User Presence (UP) flag not set in authenticatorData");
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

    // Validate clientDataJSON
    let json_str =
        core::str::from_utf8(client_data_json).map_err(|_| "clientDataJSON is not valid UTF-8")?;

    // Basic JSON structure validation
    if !json_str.starts_with('{') || !json_str.ends_with('}') {
        return Err("clientDataJSON is not valid JSON");
    }

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
    fn test_tempo_signature_from_bytes_secp256k1() {
        use super::SECP256K1_SIGNATURE_LENGTH;

        // Secp256k1 signatures are detected by length (65 bytes), no type identifier
        let sig_bytes = vec![0u8; SECP256K1_SIGNATURE_LENGTH];
        let result = TempoSignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let TempoSignature::Primitive(PrimitiveSignature::Secp256k1(_)) = result.unwrap() {
            // Expected
        } else {
            panic!("Expected Primitive(Secp256k1) variant");
        }
    }

    #[test]
    fn test_tempo_signature_from_bytes_p256() {
        use super::{P256_SIGNATURE_LENGTH, SIGNATURE_TYPE_P256};

        let mut sig_bytes = vec![SIGNATURE_TYPE_P256];
        sig_bytes.extend_from_slice(&[0u8; P256_SIGNATURE_LENGTH]);
        let result = TempoSignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let TempoSignature::Primitive(PrimitiveSignature::P256(_)) = result.unwrap() {
            // Expected
        } else {
            panic!("Expected Primitive(P256) variant");
        }
    }

    #[test]
    fn test_tempo_signature_from_bytes_webauthn() {
        use super::SIGNATURE_TYPE_WEBAUTHN;

        let mut sig_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig_bytes.extend_from_slice(&[0u8; 200]); // 200 bytes of WebAuthn data
        let result = TempoSignature::from_bytes(&sig_bytes);

        assert!(result.is_ok());
        if let TempoSignature::Primitive(PrimitiveSignature::WebAuthn(_)) = result.unwrap() {
            // Expected
        } else {
            panic!("Expected Primitive(WebAuthn) variant");
        }
    }

    #[test]
    fn test_tempo_signature_roundtrip() {
        use super::{
            P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH, SIGNATURE_TYPE_P256,
            SIGNATURE_TYPE_WEBAUTHN,
        };

        // Test secp256k1 (no type identifier, detected by 65-byte length)
        let sig1_bytes = vec![1u8; SECP256K1_SIGNATURE_LENGTH];
        let sig1 = TempoSignature::from_bytes(&sig1_bytes).unwrap();
        let encoded1 = sig1.to_bytes();
        assert_eq!(encoded1.len(), SECP256K1_SIGNATURE_LENGTH); // No type identifier
        // Verify roundtrip
        let decoded1 = TempoSignature::from_bytes(&encoded1).unwrap();
        assert_eq!(sig1, decoded1);

        // Test P256
        let mut sig2_bytes = vec![SIGNATURE_TYPE_P256];
        sig2_bytes.extend_from_slice(&[2u8; P256_SIGNATURE_LENGTH]);
        let sig2 = TempoSignature::from_bytes(&sig2_bytes).unwrap();
        let encoded2 = sig2.to_bytes();
        assert_eq!(encoded2.len(), 1 + P256_SIGNATURE_LENGTH);
        // Verify roundtrip
        let decoded2 = TempoSignature::from_bytes(&encoded2).unwrap();
        assert_eq!(sig2, decoded2);

        // Test WebAuthn
        let mut sig3_bytes = vec![SIGNATURE_TYPE_WEBAUTHN];
        sig3_bytes.extend_from_slice(&[3u8; 200]);
        let sig3 = TempoSignature::from_bytes(&sig3_bytes).unwrap();
        let encoded3 = sig3.to_bytes();
        assert_eq!(encoded3.len(), 1 + 200);
        // Verify roundtrip
        let decoded3 = TempoSignature::from_bytes(&encoded3).unwrap();
        assert_eq!(sig3, decoded3);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_tempo_signature_serde_roundtrip() {
        // Test serde roundtrip for all signature types

        // Test Secp256k1
        let r_bytes = hex!("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let s_bytes = hex!("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
        let sig = Signature::new(
            alloy_primitives::U256::from_be_slice(&r_bytes),
            alloy_primitives::U256::from_be_slice(&s_bytes),
            false,
        );
        let secp256k1_sig = TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sig));

        let json = serde_json::to_string(&secp256k1_sig).unwrap();
        let decoded: TempoSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(secp256k1_sig, decoded, "Secp256k1 serde roundtrip failed");

        // Test P256
        let p256_sig =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::from([1u8; 32]),
                s: B256::from([2u8; 32]),
                pub_key_x: B256::from([3u8; 32]),
                pub_key_y: B256::from([4u8; 32]),
                pre_hash: true,
            }));

        let json = serde_json::to_string(&p256_sig).unwrap();
        let decoded: TempoSignature = serde_json::from_str(&json).unwrap();
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
        let webauthn_sig =
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r: B256::from([5u8; 32]),
                s: B256::from([6u8; 32]),
                pub_key_x: B256::from([7u8; 32]),
                pub_key_y: B256::from([8u8; 32]),
                webauthn_data: Bytes::from(vec![9u8; 50]),
            }));

        let json = serde_json::to_string(&webauthn_sig).unwrap();
        let decoded: TempoSignature = serde_json::from_str(&json).unwrap();
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

    #[test]
    fn test_webauthn_flag_validation() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Helper to build webauthn data with given flags and optional extension bytes
        fn build_webauthn_data(flags: u8, extension: Option<&[u8]>, tx_hash: &B256) -> Vec<u8> {
            let mut data = vec![0u8; 32]; // rpIdHash
            data.push(flags);
            data.extend_from_slice(&[0u8; 4]); // signCount
            if let Some(ext) = extension {
                data.extend_from_slice(ext);
            }
            let challenge = URL_SAFE_NO_PAD.encode(tx_hash.as_slice());
            data.extend_from_slice(
                format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\"}}").as_bytes(),
            );
            data
        }

        let tx_hash = B256::ZERO;

        // AT flag must be rejected for assertion signatures
        let data = build_webauthn_data(0x41, None, &tx_hash); // UP + AT
        let err = verify_webauthn_data_internal(&data, &tx_hash).unwrap_err();
        assert!(err.contains("AT flag"), "Should reject AT flag");

        // ED flag must be rejected, as extensions are not supported
        let data = build_webauthn_data(0x81, Some(&[0xa0]), &tx_hash); // UP + ED, empty map
        let err = verify_webauthn_data_internal(&data, &tx_hash).unwrap_err();
        assert!(err.contains("ED flag"), "Should reject ED flag");

        // Valid with only UP flag set
        let data = build_webauthn_data(0x01, None, &tx_hash); // UP only
        assert!(
            verify_webauthn_data_internal(&data, &tx_hash).is_ok(),
            "Should accept valid webauthn data with only UP flag"
        );
    }
}
