use super::{
    configurable_account::{ConfigurableAccountSignature, SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT},
    tempo_transaction::{
        MAX_WEBAUTHN_SIGNATURE_LENGTH, P256_SIGNATURE_LENGTH, SECP256K1_SIGNATURE_LENGTH,
        SignatureType,
    },
};
use crate::{
    crypto,
    gas::{P256_VERIFY_GAS, SECP256K1_VERIFY_GAS, WEBAUTHN_VERIFY_GAS},
};
use alloc::vec::Vec;
use alloy_consensus::crypto::RecoveryError;
use alloy_eips::eip7623::{STANDARD_TOKEN_COST, tokens_in_calldata};
use alloy_primitives::{Address, B256, Bytes, Signature, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Error as RlpError, Header, decode_exact};
use sha2::{Digest, Sha256};

// Always mark `p256` as used to avoid `unused_crate_dependencies` warnings in `std` builds.
use p256 as _;

pub use crate::crypto::{P256_ORDER, P256N_HALF, derive_p256_address, normalize_p256_s};

#[cfg(not(feature = "std"))]
use once_cell::race::OnceBox as OnceLock;
#[cfg(feature = "std")]
use std::sync::OnceLock;

/// Signature type identifiers
/// Note: Secp256k1 has no identifier - detected by length (65 bytes)
pub const SIGNATURE_TYPE_P256: u8 = 0x01;
pub const SIGNATURE_TYPE_WEBAUTHN: u8 = 0x02;
pub const SIGNATURE_TYPE_KEYCHAIN: u8 = 0x03;
pub const SIGNATURE_TYPE_KEYCHAIN_V2: u8 = 0x04;

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

impl P256SignatureWithPreHash {
    /// The digest a P256 signature signs for `hash`: its SHA-256 if `pre_hash`, else `hash`.
    pub fn digest(hash: &B256, pre_hash: bool) -> B256 {
        if pre_hash {
            B256::from_slice(&Sha256::digest(hash))
        } else {
            *hash
        }
    }
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

fn split_p256_signature_fields(
    sig_data: &[u8; P256_SIGNATURE_LENGTH],
) -> (&[u8; 32], &[u8; 32], &[u8; 32], &[u8; 32], bool) {
    let (r, sig_data) = sig_data
        .split_first_chunk::<32>()
        .expect("P256 signature length checked");
    let (s, sig_data) = sig_data
        .split_first_chunk::<32>()
        .expect("P256 signature length checked");
    let (pub_key_x, sig_data) = sig_data
        .split_first_chunk::<32>()
        .expect("P256 signature length checked");
    let (pub_key_y, pre_hash) = sig_data
        .split_first_chunk::<32>()
        .expect("P256 signature length checked");
    (r, s, pub_key_x, pub_key_y, pre_hash[0] != 0)
}

/// Primitive signature types that can be used standalone or within a Keychain signature.
/// This enum contains only the base signature types: Secp256k1, P256, and WebAuthn.
/// It does NOT support Keychain signatures to prevent recursion.
///
/// Custom RLP and Compact encoding writes signature bytes directly through
/// [`Self::encode_bytes_into`], while decoding delegates to [`Self::from_bytes`].
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

        let (&type_id, sig_data) = data.split_first().expect("signature data length checked");

        match type_id {
            SIGNATURE_TYPE_P256 => {
                let sig_data: &[u8; P256_SIGNATURE_LENGTH] = sig_data
                    .try_into()
                    .map_err(|_| "Invalid P256 signature length")?;
                let (r, s, pub_key_x, pub_key_y, pre_hash) = split_p256_signature_fields(sig_data);
                Ok(Self::P256(P256SignatureWithPreHash {
                    r: B256::from_slice(r),
                    s: B256::from_slice(s),
                    pub_key_x: B256::from_slice(pub_key_x),
                    pub_key_y: B256::from_slice(pub_key_y),
                    pre_hash,
                }))
            }
            SIGNATURE_TYPE_WEBAUTHN => {
                let len = sig_data.len();
                if !(128..=MAX_WEBAUTHN_SIGNATURE_LENGTH).contains(&len) {
                    return Err("Invalid WebAuthn signature length");
                }
                let (webauthn_data, sig_data) = sig_data.split_at(len - 128);
                let (r, sig_data) = sig_data
                    .split_first_chunk::<32>()
                    .expect("WebAuthn signature length checked");
                let (s, sig_data) = sig_data
                    .split_first_chunk::<32>()
                    .expect("WebAuthn signature length checked");
                let (pub_key_x, pub_key_y) = sig_data
                    .split_first_chunk::<32>()
                    .expect("WebAuthn signature length checked");
                Ok(Self::WebAuthn(WebAuthnSignature {
                    r: B256::from_slice(r),
                    s: B256::from_slice(s),
                    pub_key_x: B256::from_slice(pub_key_x),
                    pub_key_y: B256::from_slice(pub_key_y),
                    webauthn_data: Bytes::copy_from_slice(webauthn_data),
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
        let mut bytes = Vec::with_capacity(self.encoded_length());
        self.encode_bytes_into(&mut bytes);
        Bytes::from(bytes)
    }

    /// Writes the raw signature bytes (the same bytes [`Self::to_bytes`] returns) into `out`
    /// without allocating an intermediate buffer.
    pub fn encode_bytes_into(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Secp256k1(sig) => {
                // Backward compatibility: no type identifier for secp256k1
                let sig_bytes: [u8; SECP256K1_SIGNATURE_LENGTH] = sig.as_bytes();
                out.put_slice(&sig_bytes);
            }
            Self::P256(p256_sig) => {
                out.put_u8(SIGNATURE_TYPE_P256);
                out.put_slice(p256_sig.r.as_slice());
                out.put_slice(p256_sig.s.as_slice());
                out.put_slice(p256_sig.pub_key_x.as_slice());
                out.put_slice(p256_sig.pub_key_y.as_slice());
                out.put_u8(if p256_sig.pre_hash { 1 } else { 0 });
            }
            Self::WebAuthn(webauthn_sig) => {
                out.put_u8(SIGNATURE_TYPE_WEBAUTHN);
                out.put_slice(&webauthn_sig.webauthn_data);
                out.put_slice(webauthn_sig.r.as_slice());
                out.put_slice(webauthn_sig.s.as_slice());
                out.put_slice(webauthn_sig.pub_key_x.as_slice());
                out.put_slice(webauthn_sig.pub_key_y.as_slice());
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
        size_of::<Self>()
            + match self {
                Self::Secp256k1(_) | Self::P256(_) => 0,
                Self::WebAuthn(webauthn_sig) => webauthn_sig.webauthn_data.len(),
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
                alloy_consensus::crypto::secp256k1::recover_signer(sig, *sig_hash)
            }
            Self::P256(p256_sig) => {
                // Some P256 implementations (like Web Crypto) require pre-hashing
                let message_hash = P256SignatureWithPreHash::digest(sig_hash, p256_sig.pre_hash);

                // Verify P256 signature cryptographically
                if !crypto::verify_p256(
                    &p256_sig.r,
                    &p256_sig.s,
                    &p256_sig.pub_key_x,
                    &p256_sig.pub_key_y,
                    &message_hash,
                ) {
                    return Err(RecoveryError::new());
                }

                // Derive and return address
                Ok(derive_p256_address(
                    &p256_sig.pub_key_x,
                    &p256_sig.pub_key_y,
                ))
            }
            Self::WebAuthn(webauthn_sig) => {
                if !crypto::verify_webauthn(webauthn_sig, sig_hash) {
                    return Err(RecoveryError::new());
                }

                // Derive and return address
                Ok(derive_p256_address(
                    &webauthn_sig.pub_key_x,
                    &webauthn_sig.pub_key_y,
                ))
            }
        }
    }

    /// Gas to verify the signature itself, excluding any calldata cost.
    pub const fn base_verification_gas(&self) -> u64 {
        match self {
            Self::Secp256k1(_) => SECP256K1_VERIFY_GAS,
            Self::P256(_) => P256_VERIFY_GAS,
            Self::WebAuthn(_) => WEBAUTHN_VERIFY_GAS,
        }
    }

    /// Full gas to verify the signature: [`Self::base_verification_gas`] plus, for `WebAuthn`,
    /// the calldata cost of `webauthn_data`.
    ///
    /// This does not subtract the ecrecover baseline already covered by ordinary intrinsic gas.
    pub fn verification_gas(&self) -> u64 {
        match self {
            Self::Secp256k1(_) | Self::P256(_) => self.base_verification_gas(),
            Self::WebAuthn(sig) => {
                self.base_verification_gas()
                    + tokens_in_calldata(&sig.webauthn_data) * STANDARD_TOKEN_COST
            }
        }
    }

    /// Verification gas a transaction signature adds on top of the base 21k, which already
    /// covers one secp256k1 verification:
    /// - Secp256k1: 0
    /// - P256: 5000
    /// - WebAuthn: 5000 + calldata cost of `webauthn_data`
    pub fn intrinsic_verification_gas(&self) -> u64 {
        // Every signature type costs at least a secp256k1 verification, so this cannot underflow.
        self.verification_gas() - SECP256K1_VERIFY_GAS
    }
}

impl Default for PrimitiveSignature {
    fn default() -> Self {
        Self::Secp256k1(Signature::test_signature())
    }
}

impl alloy_rlp::Encodable for PrimitiveSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .encode(out);
        self.encode_bytes_into(out);
    }

    fn length(&self) -> usize {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .length_with_payload()
    }
}

impl alloy_rlp::Decodable for PrimitiveSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        Self::from_bytes(bytes).map_err(alloy_rlp::Error::Custom)
    }
}

/// Keychain signature version.
///
/// Determines how the signature hash is computed for the inner signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum KeychainVersion {
    /// Legacy (V1): inner signature signs `sig_hash` directly.
    /// Deprecated at T1C.
    /// TODO(tanishk): change default to V2 after T1C
    #[default]
    V1,
    /// V2: inner signature signs `keccak256(0x04 || sig_hash || user_address)`.
    /// Binds the signature to the specific user account with a domain separator.
    V2,
}

impl KeychainVersion {
    /// The hash an access key signs for `user_address` over `sig_hash` under this version.
    pub fn signing_hash(self, sig_hash: B256, user_address: Address) -> B256 {
        match self {
            Self::V1 => sig_hash,
            Self::V2 => KeychainSignature::signing_hash(sig_hash, user_address),
        }
    }
}

/// Keychain version validation error.
///
/// Returned by [`TempoSignature::validate_version`] when a keychain
/// signature's version is incompatible with the current hardfork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainVersionError {
    /// Legacy V1 keychain signature used after T1C activation (permanently invalid).
    LegacyPostT1C,
    /// V2 keychain signature used before T1C activation (not yet valid).
    V2BeforeActivation,
}

/// Keychain signature wrapping another signature with a user address.
/// This allows an access key to sign on behalf of a root account.
/// V1 accepts only primitive signatures; V2 also accepts configurable account signatures.
/// Serde permits V1 + configurable account values; `key_id()` and execution validation reject them.
///
/// No `Compact` impl — always wrapped in [`TempoSignature`] whose `Compact` delegates
/// to `to_bytes()`/`from_bytes()` which encodes the version via the wire type byte
/// (`0x03` = V1, `0x04` = V2).
///
/// Format (V1): 0x03 || user_address (20 bytes) || inner_signature
/// Format (V2): 0x04 || user_address (20 bytes) || inner_signature
///
/// The user_address is the root account this transaction is being executed for.
/// The inner signature proves an authorized access key signed the transaction.
/// The handler validates that user_address has authorized the access key in the KeyChain precompile.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct KeychainSignature {
    /// Root account address that this transaction is being executed for
    pub user_address: Address,
    /// Direct primitive approval or configurable account owner quorum from the access key.
    pub signature: AccountSignature,
    /// Keychain signature version (V1 = legacy, V2 = includes user_address in sig hash)
    #[cfg_attr(feature = "serde", serde(default))]
    pub version: KeychainVersion,
    /// Cached access key ID recovered from the inner signature.
    /// This is an implementation detail - use `key_id()` to access.
    /// Uses OnceLock for thread-safe interior mutability.
    /// Note: Excluded from PartialEq, Eq, Hash, and Compact as it's a cache.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "serialize_once_lock",
            rename = "keyId",
            skip_deserializing,
        )
    )]
    cached_key_id: OnceLock<Address>,
}

impl KeychainSignature {
    /// Create a new V2 KeychainSignature (recommended).
    ///
    /// V2 signatures include the user_address in the signature hash.
    pub fn new(user_address: Address, signature: impl Into<AccountSignature>) -> Self {
        Self {
            user_address,
            signature: signature.into(),
            version: KeychainVersion::V2,
            cached_key_id: OnceLock::new(),
        }
    }

    /// Create a legacy V1 KeychainSignature.
    ///
    /// V1 signatures do NOT include the user_address in the signature hash
    /// and are deprecated at the T1C hardfork.
    pub fn new_v1(user_address: Address, signature: PrimitiveSignature) -> Self {
        Self {
            user_address,
            signature: signature.into(),
            version: KeychainVersion::V1,
            cached_key_id: OnceLock::new(),
        }
    }

    /// Compute the effective signature hash for key recovery.
    ///
    /// - V1: returns `sig_hash` directly (legacy, deprecated)
    /// - V2: returns `keccak256(0x04 || sig_hash || user_address)`
    fn effective_sig_hash(&self, sig_hash: &B256) -> B256 {
        self.version.signing_hash(*sig_hash, self.user_address)
    }

    /// Get the access key ID for Keychain signatures.
    ///
    /// Verifies a primitive approval or a configurable account delegate's owner quorum, caching
    /// its ID. A configurable account ID still requires account binding and state checks by the
    /// caller.
    ///
    /// This follows the pattern used in alloy for lazy hash computation.
    pub fn key_id(
        &self,
        sig_hash: &B256,
    ) -> Result<Address, alloy_consensus::crypto::RecoveryError> {
        if self.is_legacy() && self.signature.is_configurable_account() {
            return Err(RecoveryError::new());
        }
        // Check if already cached
        if let Some(cached) = self.cached_key_id.get() {
            return Ok(*cached);
        }

        // Not cached - recover and cache
        let effective_hash = self.effective_sig_hash(sig_hash);
        let key_id = self.signature.recover_account(&effective_hash)?;
        #[allow(clippy::useless_conversion)]
        let _ = self.cached_key_id.set(key_id.into());
        Ok(key_id)
    }

    /// Returns true if this is a legacy V1 keychain signature.
    pub fn is_legacy(&self) -> bool {
        self.version == KeychainVersion::V1
    }

    /// Compute the hash that an access key should sign for a V2 keychain transaction.
    ///
    /// Returns `keccak256(0x04 || sig_hash || user_address)`.
    /// The `0x04` domain separator ([`SIGNATURE_TYPE_KEYCHAIN_V2`]) prevents
    /// cross-scheme signature confusion, following the same pattern as
    /// EIP-7702 (`0x05`) and Tempo fee-payer signatures (`0x78`).
    pub fn signing_hash(sig_hash: B256, user_address: Address) -> B256 {
        let mut buf = [0u8; 53]; // 1 + 32 + 20
        buf[0] = SIGNATURE_TYPE_KEYCHAIN_V2;
        buf[1..33].copy_from_slice(sig_hash.as_slice());
        buf[33..].copy_from_slice(user_address.as_slice());
        keccak256(buf)
    }
}

// Manual implementations of PartialEq, Eq, and Hash that exclude cached_key_id
// since it's just a cache and doesn't affect the logical equality of signatures
impl PartialEq for KeychainSignature {
    fn eq(&self, other: &Self) -> bool {
        self.user_address == other.user_address
            && self.signature == other.signature
            && self.version == other.version
    }
}

impl Eq for KeychainSignature {}

impl core::hash::Hash for KeychainSignature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.user_address.hash(state);
        self.signature.hash(state);
        self.version.hash(state);
    }
}

// Manual Arbitrary implementation that excludes cached_key_id (cache field)
#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeychainSignature {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let version = u.arbitrary()?;
        Ok(Self {
            user_address: u.arbitrary()?,
            signature: if version == KeychainVersion::V1 {
                AccountSignature::Primitive(u.arbitrary()?)
            } else {
                u.arbitrary()?
            },
            version,
            cached_key_id: OnceLock::new(), // Always start with empty cache
        })
    }
}

/// Returns the leading type identifier of typed signature bytes.
///
/// The untyped 65-byte secp256k1 encoding and inputs without a payload have none.
fn type_identifier(data: &[u8]) -> Option<u8> {
    match data {
        [type_id, _, ..] if data.len() != SECP256K1_SIGNATURE_LENGTH => Some(*type_id),
        _ => None,
    }
}

/// Primitive or configurable account approval; excludes keychain envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub enum AccountSignature {
    /// An existing primitive approval.
    Primitive(PrimitiveSignature),
    /// An account's primitive-owner quorum.
    ConfigurableAccount(ConfigurableAccountSignature),
}

impl AccountSignature {
    /// Decodes a direct approval, rejecting recursive keychain envelopes.
    fn from_bytes(data: &[u8]) -> Result<Self, AccountSignatureError> {
        match type_identifier(data) {
            Some(SIGNATURE_TYPE_KEYCHAIN | SIGNATURE_TYPE_KEYCHAIN_V2) => {
                Err(AccountSignatureError::Keychain)
            }
            Some(SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT) => {
                decode_exact::<ConfigurableAccountSignature>(&data[1..])
                    .map(Self::ConfigurableAccount)
                    .map_err(|_| AccountSignatureError::InvalidConfigurableAccount)
            }
            _ => PrimitiveSignature::from_bytes(data)
                .map(Self::Primitive)
                .map_err(AccountSignatureError::Primitive),
        }
    }

    /// Writes the direct approval without allocating an intermediate buffer.
    fn encode_bytes_into(&self, out: &mut dyn BufMut) {
        match self {
            Self::Primitive(signature) => signature.encode_bytes_into(out),
            Self::ConfigurableAccount(signature) => signature.encode_bytes_into(out),
        }
    }

    /// Returns the encoded byte length.
    fn encoded_length(&self) -> usize {
        match self {
            Self::Primitive(signature) => signature.encoded_length(),
            Self::ConfigurableAccount(signature) => signature.encoded_length(),
        }
    }

    /// Returns the signature's access-key type, including configurable account.
    pub fn signature_type(&self) -> SignatureType {
        match self {
            Self::Primitive(signature) => signature.signature_type(),
            Self::ConfigurableAccount(_) => SignatureType::ConfigurableAccount,
        }
    }

    /// Returns the primitive algorithm, when applicable.
    pub fn primitive_signature_type(&self) -> Option<SignatureType> {
        match self {
            Self::Primitive(signature) => Some(signature.signature_type()),
            Self::ConfigurableAccount(_) => None,
        }
    }

    /// Returns the configurable account witness, when applicable.
    pub const fn as_configurable_account(&self) -> Option<&ConfigurableAccountSignature> {
        match self {
            Self::ConfigurableAccount(signature) => Some(signature),
            Self::Primitive(_) => None,
        }
    }

    /// Recovers a primitive signer or verifies a configurable account's owner quorum.
    ///
    /// A returned configurable account is untrusted until its commitment is checked against state.
    fn recover_account(&self, digest: &B256) -> Result<Address, RecoveryError> {
        match self {
            Self::Primitive(signature) => signature.recover_signer(digest),
            Self::ConfigurableAccount(signature) => signature.recover_account(*digest),
        }
    }

    /// Returns a heuristic in-memory size.
    pub(crate) fn size(&self) -> usize {
        match self {
            Self::Primitive(signature) => signature.size(),
            Self::ConfigurableAccount(signature) => signature.size(),
        }
    }

    /// Whether this is a configurable account approval.
    pub const fn is_configurable_account(&self) -> bool {
        matches!(self, Self::ConfigurableAccount(_))
    }

    /// Full gas to verify the approval: [`PrimitiveSignature::verification_gas`] or
    /// [`ConfigurableAccountSignature::verification_gas`].
    ///
    /// This does not subtract the ecrecover baseline already covered by ordinary intrinsic gas.
    /// Returns `None` if the cost overflows `u64`.
    pub fn verification_gas(&self) -> Option<u64> {
        match self {
            Self::Primitive(signature) => Some(signature.verification_gas()),
            Self::ConfigurableAccount(signature) => signature.verification_gas(),
        }
    }
}

impl From<Signature> for AccountSignature {
    fn from(signature: Signature) -> Self {
        Self::Primitive(PrimitiveSignature::Secp256k1(signature))
    }
}

impl From<PrimitiveSignature> for AccountSignature {
    fn from(signature: PrimitiveSignature) -> Self {
        Self::Primitive(signature)
    }
}

impl From<ConfigurableAccountSignature> for AccountSignature {
    fn from(signature: ConfigurableAccountSignature) -> Self {
        Self::ConfigurableAccount(signature)
    }
}

impl Encodable for AccountSignature {
    fn encode(&self, out: &mut dyn BufMut) {
        Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .encode(out);
        self.encode_bytes_into(out);
    }

    fn length(&self) -> usize {
        Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .length_with_payload()
    }
}

impl Decodable for AccountSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = Header::decode_bytes(buf, false)?;
        Self::from_bytes(bytes).map_err(|error| RlpError::Custom(error.as_str()))
    }
}

/// Why bytes are not a direct account approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountSignatureError {
    /// A keychain envelope where a direct approval is required.
    Keychain,
    /// A configurable account witness that does not decode.
    InvalidConfigurableAccount,
    /// A primitive signature that does not decode, with its message.
    Primitive(&'static str),
    /// A configurable account approval inside a keychain V1 envelope.
    ConfigurableAccountInKeychainV1,
}

impl AccountSignatureError {
    /// Returns the stable validation message for this error.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Keychain => "keychain signatures are not account signatures",
            Self::InvalidConfigurableAccount => "Invalid configurable account signature RLP",
            Self::Primitive(message) => message,
            Self::ConfigurableAccountInKeychainV1 => {
                "configurable account access keys require keychain V2"
            }
        }
    }
}

impl From<AccountSignatureError> for &'static str {
    fn from(error: AccountSignatureError) -> Self {
        error.as_str()
    }
}

/// AA transaction signature supporting multiple signature schemes
///
/// Custom RLP and Compact encoding writes signature bytes directly through
/// [`Self::encode_bytes_into`], while decoding delegates to [`Self::from_bytes`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged, rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub enum TempoSignature {
    /// Primitive signature types: Secp256k1, P256, or WebAuthn
    Primitive(PrimitiveSignature),

    /// Parent address plus a direct primitive or configurable account approval.
    /// The inner signature type and decoder exclude nested keychains.
    Keychain(KeychainSignature),

    /// Configurable account signature.
    ConfigurableAccount(ConfigurableAccountSignature),
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

        // Check if this is a Keychain signature before decoding a direct approval.
        if let Some(SIGNATURE_TYPE_KEYCHAIN | SIGNATURE_TYPE_KEYCHAIN_V2) = type_identifier(data) {
            let version = if data[0] == SIGNATURE_TYPE_KEYCHAIN {
                KeychainVersion::V1
            } else {
                KeychainVersion::V2
            };
            let sig_data = &data[1..];

            // Keychain format: user_address (20 bytes) || inner_signature
            if sig_data.len() < 20 {
                return Err("Invalid Keychain signature: too short for user_address");
            }

            let user_address = Address::from_slice(&sig_data[0..20]);
            let inner_sig_bytes = &sig_data[20..];

            // A bounded direct approval cannot contain another keychain.
            let inner_signature = AccountSignature::from_bytes(inner_sig_bytes)?;
            if version == KeychainVersion::V1 && inner_signature.is_configurable_account() {
                return Err(AccountSignatureError::ConfigurableAccountInKeychainV1.into());
            }

            return Ok(Self::Keychain(KeychainSignature {
                user_address,
                signature: inner_signature,
                version,
                cached_key_id: OnceLock::new(),
            }));
        }

        Ok(AccountSignature::from_bytes(data)?.into())
    }

    /// Encode signature to bytes
    ///
    /// For backward compatibility:
    /// - Secp256k1: encoded WITHOUT type identifier (65 bytes)
    /// - P256/WebAuthn: encoded WITH type identifier prefix
    pub fn to_bytes(&self) -> Bytes {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.to_bytes(),
            Self::Keychain(_) | Self::ConfigurableAccount(_) => {
                let mut bytes = Vec::with_capacity(self.encoded_length());
                self.encode_bytes_into(&mut bytes);
                Bytes::from(bytes)
            }
        }
    }

    /// Writes the raw signature bytes (the same bytes [`Self::to_bytes`] returns) into `out`
    /// without allocating an intermediate buffer.
    pub fn encode_bytes_into(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.encode_bytes_into(out),
            Self::Keychain(keychain_sig) => {
                // Format: type_byte | user_address (20 bytes) | inner_signature
                let type_byte = match keychain_sig.version {
                    KeychainVersion::V1 => SIGNATURE_TYPE_KEYCHAIN,
                    KeychainVersion::V2 => SIGNATURE_TYPE_KEYCHAIN_V2,
                };
                out.put_u8(type_byte);
                out.put_slice(keychain_sig.user_address.as_slice());
                keychain_sig.signature.encode_bytes_into(out);
            }
            Self::ConfigurableAccount(configurable_account_sig) => {
                configurable_account_sig.encode_bytes_into(out)
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
            Self::ConfigurableAccount(configurable_account_sig) => {
                configurable_account_sig.encoded_length()
            }
        }
    }

    /// Returns the primitive algorithm, including inside a keychain envelope, if applicable.
    pub fn primitive_signature_type(&self) -> Option<SignatureType> {
        match self {
            Self::Primitive(primitive_sig) => Some(primitive_sig.signature_type()),
            Self::Keychain(keychain_sig) => keychain_sig.signature.primitive_signature_type(),
            Self::ConfigurableAccount(_) => None,
        }
    }

    /// Get the in-memory size of the signature
    pub fn size(&self) -> usize {
        match self {
            Self::Primitive(primitive_sig) => primitive_sig.size(),
            Self::Keychain(keychain_sig) => 1 + 20 + keychain_sig.signature.size(),
            Self::ConfigurableAccount(configurable_account_sig) => {
                1 + configurable_account_sig.size()
            }
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
    /// For Keychain signatures, this verifies the inner primitive signature or configurable account
    /// delegate quorum.
    /// The access key address is cached in the KeychainSignature for later use.
    /// Note: This pattern has a big footgun, that someone using recover_signer, cannot assume
    /// that the signature is valid for the keychain. They also need to check the access key is authorized
    /// in the keychain precompile.
    /// We cannot check this here, as we don't have access to the keychain precompile.
    ///
    /// - Configurable account: verifies the owner quorum against the embedded config and returns the
    ///   named account. The config remains untrusted until stateful validation matches it to the
    ///   account's commitment or initial derivation.
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
            Self::ConfigurableAccount(configurable_account_sig) => {
                configurable_account_sig.recover_account(*sig_hash)
            }
        }
    }

    /// Check if this is a Keychain signature
    pub fn is_keychain(&self) -> bool {
        matches!(self, Self::Keychain(_))
    }

    /// Check if this is a legacy V1 Keychain signature (deprecated at T1C).
    pub fn is_legacy_keychain(&self) -> bool {
        matches!(self, Self::Keychain(k) if k.is_legacy())
    }

    /// Check if this is a V2 Keychain signature.
    pub fn is_v2_keychain(&self) -> bool {
        matches!(
            self,
            Self::Keychain(KeychainSignature {
                version: KeychainVersion::V2,
                ..
            })
        )
    }

    /// Validates keychain signature version compatibility with the current hardfork.
    ///
    /// - Post-T1C: legacy V1 keychain signatures are rejected.
    /// - Pre-T1C: V2 keychain signatures are rejected to prevent chain splits.
    pub fn validate_version(&self, is_t1c: bool) -> Result<(), KeychainVersionError> {
        if is_t1c && self.is_legacy_keychain() {
            return Err(KeychainVersionError::LegacyPostT1C);
        }
        if !is_t1c && self.is_v2_keychain() {
            return Err(KeychainVersionError::V2BeforeActivation);
        }
        Ok(())
    }

    /// Get the Keychain signature if this is a Keychain signature
    pub fn as_keychain(&self) -> Option<&KeychainSignature> {
        match self {
            Self::Keychain(keychain_sig) => Some(keychain_sig),
            _ => None,
        }
    }

    /// Get the configurable account signature if this is a configurable account signature.
    pub const fn as_configurable_account(&self) -> Option<&ConfigurableAccountSignature> {
        match self {
            Self::ConfigurableAccount(configurable_account_sig) => Some(configurable_account_sig),
            _ => None,
        }
    }

    /// Check if this is a configurable account signature.
    pub const fn is_configurable_account(&self) -> bool {
        matches!(self, Self::ConfigurableAccount(_))
    }

    /// Whether a configurable account signs, directly or inside a keychain envelope.
    pub fn is_or_wraps_configurable_account(&self) -> bool {
        self.primitive_signature_type().is_none()
    }
}

impl Default for TempoSignature {
    fn default() -> Self {
        Self::Primitive(PrimitiveSignature::default())
    }
}

impl alloy_rlp::Encodable for TempoSignature {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .encode(out);
        self.encode_bytes_into(out);
    }

    fn length(&self) -> usize {
        alloy_rlp::Header {
            list: false,
            payload_length: self.encoded_length(),
        }
        .length_with_payload()
    }
}

impl alloy_rlp::Decodable for TempoSignature {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let bytes = alloy_rlp::Header::decode_bytes(buf, false)?;
        Self::from_bytes(bytes).map_err(alloy_rlp::Error::Custom)
    }
}

impl From<Signature> for TempoSignature {
    fn from(signature: Signature) -> Self {
        Self::Primitive(PrimitiveSignature::Secp256k1(signature))
    }
}

impl From<AccountSignature> for TempoSignature {
    fn from(signature: AccountSignature) -> Self {
        match signature {
            AccountSignature::Primitive(signature) => Self::Primitive(signature),
            AccountSignature::ConfigurableAccount(signature) => {
                Self::ConfigurableAccount(signature)
            }
        }
    }
}

// ============================================================================
// Helper Functions for Signature Verification
// ============================================================================

/// Generates a random P256 signing key, returning it with its public key coordinates and the
/// address derived from them.
#[cfg(any(test, feature = "test-utils"))]
pub fn p256_keypair() -> (p256::ecdsa::SigningKey, B256, B256, Address) {
    let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let pub_key_x = B256::from_slice(point.x().expect("uncompressed point has x"));
    let pub_key_y = B256::from_slice(point.y().expect("uncompressed point has y"));
    let address = derive_p256_address(&pub_key_x, &pub_key_y);
    (signing_key, pub_key_x, pub_key_y, address)
}

#[cfg(feature = "serde")]
/// Helper function to serialize a [`OnceLock`] as an [`Option`] if it's initialized.
fn serialize_once_lock<S>(value: &OnceLock<Address>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(&value.get(), serializer)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::transaction::tt_authorization::tests::{generate_secp256k1_keypair, sign_hash};
    use alloy_primitives::{U256, hex};
    use alloy_rlp::{Decodable, Encodable};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{
        ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner},
        elliptic_curve::rand_core::OsRng,
    };
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use std::{
        collections::hash_map::DefaultHasher,
        hash::{Hash, Hasher},
    };
    use test_case::test_case;

    /// Generate P256 keypair, return (signing_key, pub_key_x, pub_key_y)
    pub(crate) fn generate_p256_keypair() -> (P256SigningKey, B256, B256) {
        let signing_key = P256SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let encoded_point = verifying_key.to_encoded_point(false);
        let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_ref());
        let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_ref());
        (signing_key, pub_key_x, pub_key_y)
    }

    /// Sign a message hash with P256, normalize s, return (r, s)
    pub(crate) fn sign_p256_normalized(key: &P256SigningKey, msg_hash: &B256) -> (B256, B256) {
        let signature: p256::ecdsa::Signature = key.sign_prehash(msg_hash.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        let r = B256::from_slice(&sig_bytes[0..32]);
        let s = normalize_p256_s(&sig_bytes[32..64]).expect("p256 crate produces valid s");
        (r, s)
    }

    /// Build webauthn data with given flags and optional extension bytes
    pub(crate) fn build_webauthn_data(
        flags: u8,
        extension: Option<&[u8]>,
        tx_hash: &B256,
    ) -> Vec<u8> {
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

    fn assert_rlp_encoding<T: Encodable + Decodable + PartialEq + core::fmt::Debug>(
        signature: &T,
        bytes: &Bytes,
    ) {
        let expected = alloy_rlp::encode(bytes);
        assert_eq!(signature.length(), expected.len());

        let mut encoded = vec![0xaa, 0xbb];
        signature.encode(&mut encoded);
        assert_eq!(&encoded[..2], &[0xaa, 0xbb]);
        assert_eq!(&encoded[2..], expected);

        encoded.extend_from_slice(&[0xcc, 0xdd]);
        let mut input = &encoded[2..];
        assert_eq!(&T::decode(&mut input).unwrap(), signature);
        assert_eq!(input, &[0xcc, 0xdd]);
    }

    proptest! {
        #[test]
        fn p256_address_matches_hash_and_truncate(x in any::<[u8; 32]>(), y in any::<[u8; 32]>()) {
            let hash = keccak256([x, y].concat());
            prop_assert_eq!(derive_p256_address(&B256::from(x), &B256::from(y)), Address::from_word(hash));
        }

        #[test]
        fn proptest_primitive_signature_rlp_encoding(signature in arb::<PrimitiveSignature>()) {
            let bytes = signature.to_bytes();
            let mut output = vec![0; signature.encoded_length()];
            let mut remaining = output.as_mut_slice();
            signature.encode_bytes_into(&mut remaining);
            prop_assert!(remaining.is_empty());
            prop_assert_eq!(output.as_slice(), bytes.as_ref());
            prop_assert_eq!(PrimitiveSignature::from_bytes(&output).unwrap(), signature.clone());
            assert_rlp_encoding(&signature, &bytes);
        }

        #[test]
        fn proptest_tempo_signature_rlp_encoding(signature in arb::<TempoSignature>()) {
            let bytes = signature.to_bytes();
            let mut output = vec![0; signature.encoded_length()];
            let mut remaining = output.as_mut_slice();
            signature.encode_bytes_into(&mut remaining);
            prop_assert!(remaining.is_empty());
            prop_assert_eq!(output.as_slice(), bytes.as_ref());
            prop_assert_eq!(TempoSignature::from_bytes(&output).unwrap(), signature.clone());
            assert_rlp_encoding(&signature, &bytes);
        }
    }

    #[test]
    fn test_signature_encoding_layout_and_webauthn_boundaries() {
        let fields = [
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            B256::repeat_byte(0x33),
            B256::repeat_byte(0x44),
        ];
        let [r, s, pub_key_x, pub_key_y] = fields;
        let field_bytes = fields.concat();
        let mut cases = Vec::new();
        for parity in [false, true] {
            let signature = Signature::new(r.into(), s.into(), parity);
            let mut expected = field_bytes[..64].to_vec();
            expected.push(27 + u8::from(parity));
            cases.push((PrimitiveSignature::Secp256k1(signature), expected));
        }
        for pre_hash in [false, true] {
            let mut expected = vec![SIGNATURE_TYPE_P256];
            expected.extend_from_slice(&field_bytes);
            expected.push(u8::from(pre_hash));
            cases.push((
                PrimitiveSignature::P256(P256SignatureWithPreHash {
                    r,
                    s,
                    pub_key_x,
                    pub_key_y,
                    pre_hash,
                }),
                expected,
            ));
        }
        // WebAuthn payloads cross 255 bytes at data length 127, or 106 inside a keychain.
        for len in [
            0,
            1,
            105,
            106,
            107,
            126,
            127,
            128,
            MAX_WEBAUTHN_SIGNATURE_LENGTH - 128,
        ] {
            let data = vec![0x55; len];
            let mut expected = vec![SIGNATURE_TYPE_WEBAUTHN];
            expected.extend_from_slice(&data);
            expected.extend_from_slice(&field_bytes);
            cases.push((
                PrimitiveSignature::WebAuthn(WebAuthnSignature {
                    r,
                    s,
                    pub_key_x,
                    pub_key_y,
                    webauthn_data: data.into(),
                }),
                expected,
            ));
        }

        let user = Address::repeat_byte(0x66);
        for (primitive, expected) in cases {
            assert_eq!(primitive.to_bytes().as_ref(), expected);
            assert_rlp_encoding(&primitive, &Bytes::copy_from_slice(&expected));
            for (signature, type_byte) in [
                (TempoSignature::Primitive(primitive.clone()), None),
                (
                    TempoSignature::Keychain(KeychainSignature::new_v1(user, primitive.clone())),
                    Some(SIGNATURE_TYPE_KEYCHAIN),
                ),
                (
                    TempoSignature::Keychain(KeychainSignature::new(user, primitive)),
                    Some(SIGNATURE_TYPE_KEYCHAIN_V2),
                ),
            ] {
                let mut bytes = Vec::new();
                if let Some(type_byte) = type_byte {
                    bytes.push(type_byte);
                    bytes.extend_from_slice(user.as_slice());
                }
                bytes.extend_from_slice(&expected);
                assert_eq!(signature.to_bytes().as_ref(), bytes);
                assert_eq!(signature.encoded_length(), bytes.len());
                assert_rlp_encoding(&signature, &Bytes::from(bytes));
            }
        }
    }

    #[test]
    fn test_p256_high_s_normalization() {
        // s < P256N_HALF → unchanged
        let low_s = U256::ONE;
        let low_s_bytes: [u8; 32] = low_s.to_be_bytes();
        assert_eq!(
            U256::from_be_slice(normalize_p256_s(&low_s_bytes).unwrap().as_slice()),
            low_s,
            "s < P256N_HALF should remain unchanged"
        );

        // s == P256N_HALF → unchanged
        let half_bytes: [u8; 32] = P256N_HALF.to_be_bytes();
        assert_eq!(
            U256::from_be_slice(normalize_p256_s(&half_bytes).unwrap().as_slice()),
            P256N_HALF,
            "s == P256N_HALF should remain unchanged"
        );

        // s == P256N_HALF + 1 → normalized to P256_ORDER - s
        let high_s = P256N_HALF + U256::ONE;
        let high_s_bytes: [u8; 32] = high_s.to_be_bytes();
        assert_eq!(
            U256::from_be_slice(normalize_p256_s(&high_s_bytes).unwrap().as_slice()),
            P256_ORDER - high_s,
            "s > P256N_HALF should be normalized"
        );

        // s == P256_ORDER - 1 → normalized to 1
        let max_s = P256_ORDER - U256::ONE;
        let max_s_bytes: [u8; 32] = max_s.to_be_bytes();
        assert_eq!(
            U256::from_be_slice(normalize_p256_s(&max_s_bytes).unwrap().as_slice()),
            U256::ONE,
            "s == P256_ORDER - 1 should normalize to 1"
        );

        // s == 0 → rejected
        let zero_bytes: [u8; 32] = U256::ZERO.to_be_bytes();
        assert!(
            normalize_p256_s(&zero_bytes).is_err(),
            "s == 0 should be rejected"
        );

        // s == P256_ORDER → rejected
        let order_bytes: [u8; 32] = P256_ORDER.to_be_bytes();
        assert!(
            normalize_p256_s(&order_bytes).is_err(),
            "s == P256_ORDER should be rejected"
        );

        // s == P256_ORDER + 1 → rejected
        let over_bytes: [u8; 32] = (P256_ORDER + U256::ONE).to_be_bytes();
        assert!(
            normalize_p256_s(&over_bytes).is_err(),
            "s > P256_ORDER should be rejected"
        );

        // s == U256::MAX → rejected
        let max_bytes: [u8; 32] = U256::MAX.to_be_bytes();
        assert!(
            normalize_p256_s(&max_bytes).is_err(),
            "s == U256::MAX should be rejected"
        );
    }

    #[test]
    fn test_tempo_signature_from_bytes_secp256k1() {
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
    fn test_tempo_signature_from_bytes_validation() {
        // Empty input
        assert_eq!(
            TempoSignature::from_bytes(&[]).unwrap_err(),
            "Signature data is empty"
        );
        assert_eq!(
            PrimitiveSignature::from_bytes(&[]).unwrap_err(),
            "Signature data is empty"
        );

        // Too short (1 byte, not secp256k1 length)
        assert_eq!(
            TempoSignature::from_bytes(&[0x01]).unwrap_err(),
            "Signature data too short: expected type identifier + signature data"
        );

        // Wrong length for P256 (should be 129 bytes after type byte)
        let mut bad_p256 = vec![SIGNATURE_TYPE_P256];
        bad_p256.extend_from_slice(&[0u8; 100]); // wrong length
        assert_eq!(
            TempoSignature::from_bytes(&bad_p256).unwrap_err(),
            "Invalid P256 signature length"
        );

        // Wrong length for WebAuthn (too short, < 128 bytes after type byte)
        let mut bad_webauthn = vec![SIGNATURE_TYPE_WEBAUTHN];
        bad_webauthn.extend_from_slice(&[0u8; 50]); // too short
        assert_eq!(
            TempoSignature::from_bytes(&bad_webauthn).unwrap_err(),
            "Invalid WebAuthn signature length"
        );

        // Invalid type identifier
        let mut unknown_type = vec![0xFF];
        unknown_type.extend_from_slice(&[0u8; 100]);
        assert_eq!(
            TempoSignature::from_bytes(&unknown_type).unwrap_err(),
            "Unknown signature type identifier"
        );
    }

    #[test]
    fn test_tempo_signature_roundtrip() {
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
        let secp256k1_sig = TempoSignature::from(sig);

        let json = serde_json::to_string(&secp256k1_sig).unwrap();
        let decoded: TempoSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(secp256k1_sig, decoded, "Secp256k1 serde roundtrip failed");

        // Test P256
        let p256_sig =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r: B256::repeat_byte(1u8),
                s: B256::repeat_byte(2u8),
                pub_key_x: B256::repeat_byte(3u8),
                pub_key_y: B256::repeat_byte(4u8),
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
                r: B256::repeat_byte(5u8),
                s: B256::repeat_byte(6u8),
                pub_key_x: B256::repeat_byte(7u8),
                pub_key_y: B256::repeat_byte(8u8),
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
    fn test_recover_signer_p256() {
        let (signing_key, pub_key_x, pub_key_y) = generate_p256_keypair();
        let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

        let sig_hash = B256::repeat_byte(0xAA);
        let (r, s) = sign_p256_normalized(&signing_key, &sig_hash);

        let p256_sig =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash: false,
            }));

        let recovered = p256_sig.recover_signer(&sig_hash).unwrap();
        assert_eq!(
            recovered, expected_address,
            "P256 recovery should match derived address"
        );
    }

    #[test]
    fn test_recover_signer_p256_with_prehash() {
        let (signing_key, pub_key_x, pub_key_y) = generate_p256_keypair();
        let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

        // For pre_hash=true, signature is over sha256(sig_hash)
        let sig_hash = B256::repeat_byte(0xBB);
        let prehashed = B256::from_slice(Sha256::digest(sig_hash).as_ref());
        let (r, s) = sign_p256_normalized(&signing_key, &prehashed);

        let p256_sig =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x,
                pub_key_y,
                pre_hash: true,
            }));

        let recovered = p256_sig.recover_signer(&sig_hash).unwrap();
        assert_eq!(
            recovered, expected_address,
            "P256 pre_hash recovery should match"
        );
    }

    #[test]
    fn test_recover_signer_p256_high_s_rejected() {
        let (signing_key, pub_key_x, pub_key_y) = generate_p256_keypair();
        let sig_hash = B256::repeat_byte(0xCD);
        let signature: p256::ecdsa::Signature =
            signing_key.sign_prehash(sig_hash.as_slice()).unwrap();
        let sig_bytes = signature.to_bytes();
        let r = B256::from_slice(&sig_bytes[..32]);
        let s_value = U256::from_be_slice(&sig_bytes[32..64]);
        let high_s = if s_value > P256N_HALF {
            s_value
        } else {
            P256_ORDER - s_value
        };

        let p256_sig =
            TempoSignature::Primitive(PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s: B256::from(high_s),
                pub_key_x,
                pub_key_y,
                pre_hash: false,
            }));

        assert!(
            p256_sig.recover_signer(&sig_hash).is_err(),
            "high-s P256 signatures must be rejected"
        );
    }

    #[test]
    fn test_recover_signer_webauthn() {
        let (signing_key, pub_key_x, pub_key_y) = generate_p256_keypair();
        let expected_address = derive_p256_address(&pub_key_x, &pub_key_y);

        let tx_hash = B256::repeat_byte(0xCC);
        let webauthn_data = build_webauthn_data(0x01, None, &tx_hash);

        let (auth_data, client_data) = webauthn_data.split_at(37);
        let message_hash = B256::from_slice(&Sha256::digest(
            [auth_data, Sha256::digest(client_data).as_slice()].concat(),
        ));

        let (r, s) = sign_p256_normalized(&signing_key, &message_hash);

        let webauthn_sig =
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x,
                pub_key_y,
                webauthn_data: Bytes::from(webauthn_data),
            }));

        let recovered = webauthn_sig.recover_signer(&tx_hash).unwrap();
        assert_eq!(
            recovered, expected_address,
            "WebAuthn recovery should match derived address"
        );
    }

    #[test]
    fn test_recover_signer_webauthn_invalid_payload_rejected() {
        let (signing_key, pub_key_x, pub_key_y) = generate_p256_keypair();
        let tx_hash = B256::repeat_byte(0xEF);
        let (r, s) = sign_p256_normalized(&signing_key, &B256::ZERO);

        let invalid_webauthn_sig =
            TempoSignature::Primitive(PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x,
                pub_key_y,
                webauthn_data: Bytes::from(build_webauthn_data(0x41, None, &tx_hash)),
            }));

        assert!(
            invalid_webauthn_sig.recover_signer(&tx_hash).is_err(),
            "invalid WebAuthn payloads must be rejected"
        );
    }

    #[test]
    fn test_recover_signer_keychain_v1() {
        let (signing_key, access_key_address) = generate_secp256k1_keypair();
        let user_address = Address::repeat_byte(0xDD);

        // V1: inner signature signs sig_hash directly
        let sig_hash = B256::repeat_byte(0x22);
        let inner_sig = sign_hash(&signing_key, &sig_hash);

        let keychain_sig = TempoSignature::Keychain(KeychainSignature::new_v1(
            user_address,
            match inner_sig {
                TempoSignature::Primitive(p) => p,
                _ => panic!("Expected primitive signature"),
            },
        ));

        // recover_signer returns user_address
        let recovered = keychain_sig.recover_signer(&sig_hash).unwrap();
        assert_eq!(
            recovered, user_address,
            "Keychain V1 recovery should return user_address"
        );

        // key_id should be cached and return access key address
        let keychain = keychain_sig.as_keychain().unwrap();
        let key_id = keychain.key_id(&sig_hash).unwrap();
        assert_eq!(
            key_id, access_key_address,
            "key_id should return access key address"
        );

        // V1 should be legacy
        assert!(keychain_sig.is_legacy_keychain());
    }

    #[test]
    fn test_recover_signer_keychain_v2() {
        let (signing_key, access_key_address) = generate_secp256k1_keypair();
        let user_address = Address::repeat_byte(0xDD);

        // V2: inner signature signs keccak256(0x04 || sig_hash || user_address)
        let sig_hash = B256::repeat_byte(0x22);
        let mut buf = [0u8; 53]; // 1 + 32 + 20
        buf[0] = SIGNATURE_TYPE_KEYCHAIN_V2;
        buf[1..33].copy_from_slice(sig_hash.as_slice());
        buf[33..].copy_from_slice(user_address.as_slice());
        let effective_hash = keccak256(buf);
        let inner_sig = sign_hash(&signing_key, &effective_hash);

        let keychain_sig = TempoSignature::Keychain(KeychainSignature::new(
            user_address,
            match inner_sig {
                TempoSignature::Primitive(p) => p,
                _ => panic!("Expected primitive signature"),
            },
        ));

        // recover_signer returns user_address
        let recovered = keychain_sig.recover_signer(&sig_hash).unwrap();
        assert_eq!(
            recovered, user_address,
            "Keychain V2 recovery should return user_address"
        );

        // key_id should be cached and return access key address
        let keychain = keychain_sig.as_keychain().unwrap();
        let key_id = keychain.key_id(&sig_hash).unwrap();
        assert_eq!(
            key_id, access_key_address,
            "key_id should return access key address"
        );

        // V2 should NOT be legacy
        assert!(!keychain_sig.is_legacy_keychain());
    }

    #[test]
    fn test_keychain_v2_binds_user_address() {
        let (signing_key, _access_key_address) = generate_secp256k1_keypair();
        let user_a = Address::repeat_byte(0xAA);
        let user_b = Address::repeat_byte(0xBB);

        // Sign for user_a with V2
        let sig_hash = B256::repeat_byte(0x22);
        let effective_hash = KeychainSignature::signing_hash(sig_hash, user_a);
        let inner_sig = sign_hash(&signing_key, &effective_hash);

        let inner_primitive = match inner_sig {
            TempoSignature::Primitive(p) => p,
            _ => panic!("Expected primitive signature"),
        };

        // Valid for user_a
        let sig_a =
            TempoSignature::Keychain(KeychainSignature::new(user_a, inner_primitive.clone()));
        let recovered_a = sig_a.recover_signer(&sig_hash).unwrap();
        assert_eq!(recovered_a, user_a);

        // Same inner signature but for user_b — key_id will differ
        // because user_address is part of the signed hash
        let sig_b = TempoSignature::Keychain(KeychainSignature::new(user_b, inner_primitive));
        let recovered_b = sig_b.recover_signer(&sig_hash).unwrap();
        assert_eq!(
            recovered_b, user_b,
            "recover_signer returns the claimed user_address"
        );

        // But the key_id recovered under user_b will be a garbage address (not the real access key)
        let key_id_a = sig_a.as_keychain().unwrap().key_id(&sig_hash).unwrap();
        let key_id_b = sig_b.as_keychain().unwrap().key_id(&sig_hash).unwrap();
        assert_ne!(
            key_id_a, key_id_b,
            "V2 should recover different key_ids for different user_addresses"
        );
    }

    #[test]
    fn test_signing_hash_properties() {
        let hash_a = B256::repeat_byte(0x11);
        let hash_b = B256::repeat_byte(0x22);
        let addr_a = Address::repeat_byte(0xAA);
        let addr_b = Address::repeat_byte(0xBB);

        // Different addresses produce different signing hashes
        assert_ne!(
            KeychainSignature::signing_hash(hash_a, addr_a),
            KeychainSignature::signing_hash(hash_a, addr_b),
        );

        // Different tx hashes produce different signing hashes
        assert_ne!(
            KeychainSignature::signing_hash(hash_a, addr_a),
            KeychainSignature::signing_hash(hash_b, addr_a),
        );

        // Deterministic: same inputs yield same output
        assert_eq!(
            KeychainSignature::signing_hash(hash_a, addr_a),
            KeychainSignature::signing_hash(hash_a, addr_a),
        );
    }

    #[test]
    fn test_keychain_signature_eq_same() {
        let sig = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let addr = Address::repeat_byte(0x01);
        let a = KeychainSignature::new(addr, sig.clone());
        let b = KeychainSignature::new(addr, sig);
        assert_eq!(a, b);
    }

    #[test]
    fn test_keychain_signature_eq_different_address() {
        let sig = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let a = KeychainSignature::new(Address::repeat_byte(0x01), sig.clone());
        let b = KeychainSignature::new(Address::repeat_byte(0x02), sig);
        assert_ne!(a, b);
    }

    #[test]
    fn test_keychain_signature_eq_different_signature() {
        let addr = Address::repeat_byte(0x01);
        let sig_a = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let sig_b = PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::repeat_byte(1u8),
            s: B256::repeat_byte(2u8),
            pub_key_x: B256::repeat_byte(3u8),
            pub_key_y: B256::repeat_byte(4u8),
            pre_hash: false,
        });
        let a = KeychainSignature::new(addr, sig_a);
        let b = KeychainSignature::new(addr, sig_b);
        assert_ne!(a, b);
    }

    #[test]
    fn test_keychain_signature_hash_differs_for_different_sigs() {
        let sig = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let a = KeychainSignature::new(Address::repeat_byte(0x01), sig.clone());
        let b = KeychainSignature::new(Address::repeat_byte(0x02), sig.clone());
        let c = KeychainSignature::new(Address::repeat_byte(0x01), sig);

        let hash = |k: &KeychainSignature| {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        };

        assert_ne!(
            hash(&a),
            hash(&b),
            "different address should produce different hash"
        );
        assert_eq!(hash(&a), hash(&c), "same fields should produce same hash");
    }

    #[test]
    fn test_primitive_signature_from_bytes_one_byte() {
        let result = PrimitiveSignature::from_bytes(&[0x01]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_tempo_signature_keychain_too_short_for_address() {
        for type_byte in [SIGNATURE_TYPE_KEYCHAIN, SIGNATURE_TYPE_KEYCHAIN_V2] {
            let mut data = vec![type_byte];
            data.extend_from_slice(&[0u8; 19]);
            let result = TempoSignature::from_bytes(&data);
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("too short"));
        }
    }

    #[test]
    fn test_tempo_signature_keychain_exactly_20_bytes_inner_empty() {
        let mut data = vec![SIGNATURE_TYPE_KEYCHAIN];
        data.extend_from_slice(&[0u8; 20]);
        let result = TempoSignature::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_keychain_returns_false_for_primitive() {
        let sig = TempoSignature::from(Signature::test_signature());
        assert!(!sig.is_keychain());
    }

    #[test]
    fn test_is_keychain_returns_true_for_keychain() {
        let inner = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let sig = TempoSignature::Keychain(KeychainSignature::new(Address::ZERO, inner));
        assert!(sig.is_keychain());
    }

    #[test]
    fn test_keychain_v1_v2_bytes_roundtrip_and_wire_format() {
        let inner = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let user = Address::repeat_byte(0xAA);

        // V1 round-trips and uses 0x03 wire byte
        let v1 = TempoSignature::Keychain(KeychainSignature::new_v1(user, inner.clone()));
        let v1_bytes = v1.to_bytes();
        assert_eq!(v1_bytes[0], SIGNATURE_TYPE_KEYCHAIN);
        let v1_decoded = TempoSignature::from_bytes(&v1_bytes).unwrap();
        assert_eq!(v1, v1_decoded);
        assert!(v1_decoded.is_legacy_keychain());

        // V2 round-trips and uses 0x04 wire byte
        let v2 = TempoSignature::Keychain(KeychainSignature::new(user, inner));
        let v2_bytes = v2.to_bytes();
        assert_eq!(v2_bytes[0], SIGNATURE_TYPE_KEYCHAIN_V2);
        let v2_decoded = TempoSignature::from_bytes(&v2_bytes).unwrap();
        assert_eq!(v2, v2_decoded);
        assert!(!v2_decoded.is_legacy_keychain());

        // V1 and V2 with same inner sig are NOT equal
        assert_ne!(v1, v2);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_keychain_serde_roundtrip_and_backward_compat() {
        let inner = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let user = Address::repeat_byte(0xBB);

        // V2 serde roundtrip preserves version
        let v2 = TempoSignature::Keychain(KeychainSignature::new(user, inner.clone()));
        let json = serde_json::to_string(&v2).unwrap();
        let decoded: TempoSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(v2, decoded);
        assert!(!decoded.is_legacy_keychain());

        // V1 serde roundtrip preserves version
        let v1 = TempoSignature::Keychain(KeychainSignature::new_v1(user, inner));
        let json_v1 = serde_json::to_string(&v1).unwrap();
        let decoded_v1: TempoSignature = serde_json::from_str(&json_v1).unwrap();
        assert_eq!(v1, decoded_v1);
        assert!(decoded_v1.is_legacy_keychain());

        // Backward compat: JSON without "version" field deserializes as V1
        let json_no_version = json_v1.replace(r#","version":"v1""#, "");
        assert!(
            !json_no_version.contains("version"),
            "version field should be stripped"
        );
        let decoded_no_version: TempoSignature = serde_json::from_str(&json_no_version).unwrap();
        assert!(decoded_no_version.is_legacy_keychain());
    }

    #[test_case(KeychainSignature::new_v1 => true)]
    #[test_case(KeychainSignature::new => false)]
    fn test_keychain_rlp_roundtrip_preserves_version(
        keychain: fn(Address, PrimitiveSignature) -> KeychainSignature,
    ) -> bool {
        let inner = PrimitiveSignature::Secp256k1(Signature::test_signature());
        let user = Address::repeat_byte(0xCC);

        let sig = TempoSignature::Keychain(keychain(user, inner));
        let buf = alloy_rlp::encode(&sig);
        let decoded = TempoSignature::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(sig, decoded);
        decoded.is_legacy_keychain()
    }
}

#[cfg(all(test, feature = "reth-codec"))]
mod compact_tests {

    use super::*;
    use alloy_primitives::{bytes, hex};
    use reth_codecs::Compact;

    /// Ensures backwards compatibility of compact bitflags.
    ///
    /// See reth's `HeaderExt` pattern:
    /// <https://github.com/paradigmxyz/reth-core/blob/0476d1bc4b71f3c3b080622be297edd91ee4e70c/crates/codecs/src/alloy/header.rs>
    #[test]
    fn compact_types_have_unused_bits() {
        assert_ne!(
            P256SignatureWithPreHash::bitflag_unused_bits(),
            0,
            "P256SignatureWithPreHash"
        );
    }

    #[test]
    fn p256_signature_compact_roundtrip() {
        let sig = P256SignatureWithPreHash {
            r: B256::repeat_byte(0x11),
            s: B256::repeat_byte(0x22),
            pub_key_x: B256::repeat_byte(0x33),
            pub_key_y: B256::repeat_byte(0x44),
            pre_hash: true,
        };

        let expected = hex!(
            "011111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444"
        );

        let mut buf = vec![];
        let len = sig.to_compact(&mut buf);
        assert_eq!(
            buf, expected,
            "P256SignatureWithPreHash compact encoding changed"
        );
        assert_eq!(len, expected.len());

        let (decoded, _) = P256SignatureWithPreHash::from_compact(&expected, expected.len());
        assert_eq!(decoded, sig);
    }

    #[test]
    fn webauthn_signature_compact_roundtrip() {
        let sig = WebAuthnSignature {
            r: B256::repeat_byte(0x11),
            s: B256::repeat_byte(0x22),
            pub_key_x: B256::repeat_byte(0x33),
            pub_key_y: B256::repeat_byte(0x44),
            webauthn_data: bytes!("aabbccdd"),
        };

        let expected = hex!(
            "1111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444aabbccdd"
        );

        let mut buf = vec![];
        let len = sig.to_compact(&mut buf);
        assert_eq!(buf, expected, "WebAuthnSignature compact encoding changed");
        assert_eq!(len, expected.len());

        let (decoded, _) = WebAuthnSignature::from_compact(&expected, expected.len());
        assert_eq!(decoded, sig);
    }
}
