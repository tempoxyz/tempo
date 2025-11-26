use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{EMPTY_STRING_CODE, Encodable, encode_list, list_length};
use core::mem;

/// Token spending limit for access keys
///
/// Defines a per-token spending limit for an access key provisioned via key_authorization.
/// This limit is enforced by the AccountKeychain precompile when the key is used.
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct TokenLimit {
    /// TIP20 token address
    pub token: Address,

    /// Maximum spending amount for this token (enforced over the key's lifetime)
    pub limit: U256,
}

/// Key authorization for provisioning access keys
///
/// Used in TxAA to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
///
/// RLP encoding: `[key_type, key_id, signature, expiry?, limits?]`
/// - Non-optional fields come first, followed by optional (trailing) fields
/// - `expiry`: `None` (omitted or 0x80) = key never expires, `Some(timestamp)` = expires at timestamp
/// - `limits`: `None` (omitted or 0x80) = unlimited spending, `Some([])` = no spending, `Some([...])` = specific limits
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[rlp(trailing)]
// TODO: Macro RLP tests don't work here because of the trailing flag.
pub struct KeyAuthorization {
    /// Chain ID for replay protection (0 = valid on any chain)
    pub chain_id: u64,

    /// Type of key being authorized (Secp256k1, P256, or WebAuthn)
    pub key_type: SignatureType,

    /// Key identifier, is the address derived from the public key of the key type.
    pub key_id: Address,

    /// Signature authorizing this key (signed by root key)
    pub signature: PrimitiveSignature,

    /// Unix timestamp when key expires.
    /// - `None` (RLP 0x80) = key never expires (stored as u64::MAX in precompile)
    /// - `Some(timestamp)` = key expires at this timestamp
    pub expiry: Option<u64>,

    /// TIP20 spending limits for this key.
    /// - `None` (RLP 0x80) = unlimited spending (no limits enforced)
    /// - `Some([])` = no spending allowed (enforce_limits=true but no tokens allowed)
    /// - `Some([TokenLimit{...}])` = specific limits enforced
    pub limits: Option<Vec<TokenLimit>>,
}

impl KeyAuthorization {
    /// Computes the authorization message hash for this key authorization.
    ///
    /// This is a convenience method that calls [`Self::authorization_message_hash`]
    /// with this instance's fields.
    pub fn sig_hash(&self) -> B256 {
        Self::authorization_message_hash(
            self.chain_id,
            self.key_type,
            self.key_id,
            self.expiry,
            self.limits.as_deref(),
        )
    }

    /// Computes the authorization message hash to be signed by the root key.
    ///
    /// The message format is: `keccak256(rlp([chain_id, key_type, key_id, expiry, limits]))`
    ///
    /// - `expiry`: `None` encodes as RLP empty (0x80), `Some(v)` encodes as the u64 value
    /// - `limits`: `None` encodes as RLP empty (0x80), `Some([])` encodes as empty list (0xc0),
    ///   `Some([...])` encodes as the list of TokenLimits
    ///
    /// Note: The signature field is NOT included in this hash, as it signs this hash.
    /// Note: chain_id of 0 allows replay on any chain (wildcard).
    pub fn authorization_message_hash(
        chain_id: u64,
        key_type: SignatureType,
        key_id: Address,
        expiry: Option<u64>,
        limits: Option<&[TokenLimit]>,
    ) -> B256 {
        let mut auth_message = Vec::new();
        let key_type_byte: u8 = key_type.into();

        // Calculate payload length
        // Option<u64>: None = 1 byte (EMPTY_STRING_CODE), Some(v) = v.length()
        let expiry_length = expiry.map_or(1, |v| v.length());
        // Option<&[TokenLimit]>: None = 1 byte (EMPTY_STRING_CODE), Some(v) = list_length(v)
        let limits_length = limits.map_or(1, list_length);

        let payload_length = chain_id.length()
            + key_type_byte.length()
            + key_id.length()
            + expiry_length
            + limits_length;

        // Encode outer list header
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(&mut auth_message);

        // Encode fields
        chain_id.encode(&mut auth_message);
        key_type_byte.encode(&mut auth_message);
        key_id.encode(&mut auth_message);

        // Encode expiry: None as EMPTY_STRING_CODE, Some(v) as the value
        match expiry {
            None => auth_message.push(EMPTY_STRING_CODE),
            Some(v) => v.encode(&mut auth_message),
        }

        // Encode limits: None as EMPTY_STRING_CODE, Some(v) as the list
        match limits {
            None => auth_message.push(EMPTY_STRING_CODE), // unlimited spending
            Some(v) => encode_list(v, &mut auth_message),
        }

        keccak256(&auth_message)
    }

    /// Returns whether this key has unlimited spending (limits is None)
    pub fn has_unlimited_spending(&self) -> bool {
        self.limits.is_none()
    }

    /// Returns whether this key never expires (expiry is None)
    pub fn never_expires(&self) -> bool {
        self.expiry.is_none()
    }

    /// Recover the signer of the [`KeyAuthorization`].
    pub fn recover_signer(&self) -> Result<Address, RecoveryError> {
        self.signature.recover_signer(&self.sig_hash())
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for KeyAuthorization {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        // Use RLP encoding for compact representation
        self.encode(buf);
        self.length()
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let item = alloy_rlp::Decodable::decode(&mut buf)
            .expect("Failed to decode KeyAuthorization from compact");
        (item, buf)
    }
}

impl reth_primitives_traits::InMemorySize for KeyAuthorization {
    fn size(&self) -> usize {
        mem::size_of::<u64>() + // chain_id
        mem::size_of::<u8>() + // key_type
        mem::size_of::<Option<u64>>() + // expiry
        mem::size_of::<Address>() + // key_id
        self.signature.size() + // signature
        self.limits.as_ref().map_or(0, |limits| {
            limits.iter().map(|_limit| {
                mem::size_of::<Address>() + mem::size_of::<U256>()
            }).sum::<usize>()
        })
    }
}
