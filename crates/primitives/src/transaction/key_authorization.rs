use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{Decodable, Encodable, Header, RlpDecodable, RlpEncodable};

/// Token spending limit for access keys (TIP-1011 extended)
///
/// Defines a per-token spending limit for an access key provisioned via key_authorization.
/// This limit is enforced by the AccountKeychain precompile when the key is used.
///
/// ## TIP-1011: Periodic Spending Limits
///
/// When `period > 0`, this represents a periodic spending limit that resets automatically:
/// - `limit`: The per-period spending cap
/// - `remaining_in_period`: Current remaining allowance (resets to `limit` when period ends)
/// - `period`: Duration in seconds between resets
/// - `period_end`: Timestamp when current period expires (next reset time)
///
/// When `period == 0`, this is a one-time lifetime limit (legacy behavior).
///
/// ## RLP Encoding
///
/// Supports version-tolerant decoding:
/// - V1 (2 fields): `[token, limit]` - legacy one-time limit
/// - V2 (5 fields): `[token, limit, remaining_in_period, period, period_end]` - periodic limit
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
pub struct TokenLimit {
    /// TIP20 token address
    pub token: Address,

    /// Maximum spending amount for this token.
    /// - When `period == 0`: Lifetime spending cap (legacy)
    /// - When `period > 0`: Per-period spending cap (TIP-1011)
    pub limit: U256,

    /// Remaining allowance in current period (TIP-1011).
    /// For legacy one-time limits, this equals `limit` initially and depletes permanently.
    /// For periodic limits, this resets to `limit` when `block.timestamp >= period_end`.
    #[cfg_attr(feature = "serde", serde(default))]
    pub remaining_in_period: U256,

    /// Period duration in seconds (TIP-1011).
    /// - `0`: One-time lifetime limit (legacy behavior)
    /// - `> 0`: Periodic limit that resets every `period` seconds
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub period: u64,

    /// Timestamp when current period expires (TIP-1011).
    /// When `block.timestamp >= period_end`, the period resets:
    /// - `remaining_in_period` is set to `limit`
    /// - `period_end` is set to `block.timestamp + period`
    #[cfg_attr(feature = "serde", serde(default))]
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub period_end: u64,
}

impl TokenLimit {
    /// Creates a new one-time (legacy) token limit.
    pub fn one_time(token: Address, limit: U256) -> Self {
        Self {
            token,
            limit,
            remaining_in_period: limit,
            period: 0,
            period_end: 0,
        }
    }

    /// Creates a new periodic token limit (TIP-1011).
    ///
    /// # Arguments
    /// * `token` - The TIP20 token address
    /// * `limit` - The per-period spending cap
    /// * `period` - Period duration in seconds (must be > 0)
    /// * `period_end` - Initial period end timestamp
    pub fn periodic(token: Address, limit: U256, period: u64, period_end: u64) -> Self {
        Self {
            token,
            limit,
            remaining_in_period: limit,
            period,
            period_end,
        }
    }

    /// Returns true if this is a periodic limit (TIP-1011).
    pub fn is_periodic(&self) -> bool {
        self.period > 0
    }
}

impl Encodable for TokenLimit {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        // Always encode as 5-field format for new transactions
        let list_len = self.token.length()
            + self.limit.length()
            + self.remaining_in_period.length()
            + self.period.length()
            + self.period_end.length();

        Header {
            list: true,
            payload_length: list_len,
        }
        .encode(out);

        self.token.encode(out);
        self.limit.encode(out);
        self.remaining_in_period.encode(out);
        self.period.encode(out);
        self.period_end.encode(out);
    }

    fn length(&self) -> usize {
        let list_len = self.token.length()
            + self.limit.length()
            + self.remaining_in_period.length()
            + self.period.length()
            + self.period_end.length();

        Header {
            list: true,
            payload_length: list_len,
        }
        .length()
            + list_len
    }
}

impl Decodable for TokenLimit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let started_len = buf.len();

        let token = Address::decode(buf)?;
        let limit = U256::decode(buf)?;

        // Check how many bytes we've consumed to determine field count
        let consumed = started_len - buf.len();
        let remaining_payload = header.payload_length - consumed;

        if remaining_payload == 0 {
            // V1 format: 2 fields [token, limit]
            // Legacy one-time limit: remaining_in_period = limit, period = 0
            Ok(Self {
                token,
                limit,
                remaining_in_period: limit,
                period: 0,
                period_end: 0,
            })
        } else {
            // V2 format: 5 fields [token, limit, remaining_in_period, period, period_end]
            let remaining_in_period = U256::decode(buf)?;
            let period = u64::decode(buf)?;
            let period_end = u64::decode(buf)?;

            Ok(Self {
                token,
                limit,
                remaining_in_period,
                period,
                period_end,
            })
        }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TokenLimit {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let token = u.arbitrary()?;
        let limit = u.arbitrary()?;
        let period: u64 = u.arbitrary()?;

        if period == 0 {
            // One-time limit
            Ok(Self::one_time(token, limit))
        } else {
            // Periodic limit
            let period_end = u.arbitrary()?;
            Ok(Self::periodic(token, limit, period, period_end))
        }
    }
}

/// Key authorization for provisioning access keys
///
/// Used in TempoTransaction to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
///
/// RLP encoding: `[chain_id, key_type, key_id, expiry?, limits?, allowed_destinations?]`
/// - Non-optional fields come first, followed by optional (trailing) fields
/// - `expiry`: `None` (omitted or 0x80) = key never expires, `Some(timestamp)` = expires at timestamp
/// - `limits`: `None` (omitted or 0x80) = unlimited spending, `Some([])` = no spending, `Some([...])` = specific limits
/// - `allowed_destinations` (TIP-1011): `None` = unrestricted, `Some([])` = unrestricted, `Some([addr, ...])` = restricted
#[derive(Clone, Debug, PartialEq, Eq, Hash, RlpEncodable, RlpDecodable)]
#[rlp(trailing)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct KeyAuthorization {
    /// Chain ID for replay protection (0 = valid on any chain)
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: u64,

    /// Type of key being authorized (Secp256k1, P256, or WebAuthn)
    pub key_type: SignatureType,

    /// Key identifier, is the address derived from the public key of the key type.
    pub key_id: Address,

    /// Unix timestamp when key expires.
    /// - `None` (RLP 0x80) = key never expires (stored as u64::MAX in precompile)
    /// - `Some(timestamp)` = key expires at this timestamp
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub expiry: Option<u64>,

    /// TIP20 spending limits for this key.
    /// - `None` (RLP 0x80) = unlimited spending (no limits enforced)
    /// - `Some([])` = no spending allowed (enforce_limits=true but no tokens allowed)
    /// - `Some([TokenLimit{...}])` = specific limits enforced
    pub limits: Option<Vec<TokenLimit>>,

    /// Allowed destination addresses for this key (TIP-1011).
    /// - `None` = unrestricted (can call any address)
    /// - `Some([])` = unrestricted (can call any address)
    /// - `Some([addr, ...])` = restricted to only these addresses
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_destinations: Option<Vec<Address>>,
}

impl KeyAuthorization {
    /// Computes the authorization message hash for this key authorization.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(&buf)
    }

    /// Returns whether this key has unlimited spending (limits is None)
    pub fn has_unlimited_spending(&self) -> bool {
        self.limits.is_none()
    }

    /// Returns whether this key never expires (expiry is None)
    pub fn never_expires(&self) -> bool {
        self.expiry.is_none()
    }

    /// Returns whether this key is unrestricted (can call any address).
    /// A key is unrestricted if `allowed_destinations` is None or an empty array.
    pub fn is_unrestricted(&self) -> bool {
        self.allowed_destinations
            .as_ref()
            .is_none_or(|dests| dests.is_empty())
    }

    /// Returns the allowed destinations for this key.
    /// Returns an empty slice if unrestricted.
    pub fn allowed_destinations(&self) -> &[Address] {
        self.allowed_destinations.as_deref().unwrap_or(&[])
    }

    /// Convert the key authorization into a [`SignedKeyAuthorization`] with a signature.
    pub fn into_signed(self, signature: PrimitiveSignature) -> SignedKeyAuthorization {
        SignedKeyAuthorization {
            authorization: self,
            signature,
        }
    }

    /// Calculates a heuristic for the in-memory size of the key authorization
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self
                .limits
                .as_ref()
                .map_or(0, |limits| limits.capacity() * size_of::<TokenLimit>())
            + self
                .allowed_destinations
                .as_ref()
                .map_or(0, |dests| dests.capacity() * size_of::<Address>())
    }
}

/// Signed key authorization that can be attached to a transaction.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    alloy_rlp::RlpEncodable,
    alloy_rlp::RlpDecodable,
    derive_more::Deref,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[rlp(trailing)]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(compact, rlp))]
pub struct SignedKeyAuthorization {
    /// Key authorization for provisioning access keys
    #[cfg_attr(feature = "serde", serde(flatten))]
    #[deref]
    pub authorization: KeyAuthorization,

    /// Signature authorizing this key (signed by root key)
    pub signature: PrimitiveSignature,
}

impl SignedKeyAuthorization {
    /// Recover the signer of the [`KeyAuthorization`].
    pub fn recover_signer(&self) -> Result<Address, RecoveryError> {
        self.signature
            .recover_signer(&self.authorization.signature_hash())
    }

    /// Calculates a heuristic for the in-memory size of the signed key authorization
    pub fn size(&self) -> usize {
        self.authorization.size() + self.signature.size()
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for SignedKeyAuthorization {
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

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeyAuthorization {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            chain_id: u.arbitrary()?,
            key_type: u.arbitrary()?,
            key_id: u.arbitrary()?,
            // Ensure that Some(0) is not generated as it's becoming `None` after RLP roundtrip.
            expiry: u.arbitrary::<Option<u64>>()?.filter(|v| *v != 0),
            limits: u.arbitrary()?,
            allowed_destinations: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        TempoSignature,
        tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
    };

    fn make_auth(expiry: Option<u64>, limits: Option<Vec<TokenLimit>>) -> KeyAuthorization {
        KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry,
            limits,
            allowed_destinations: None,
        }
    }

    #[test]
    fn test_signature_hash_and_recover_signer() {
        let (signing_key, expected_address) = generate_secp256k1_keypair();

        let auth = make_auth(Some(1000), None);

        // Hash determinism
        let hash1 = auth.signature_hash();
        let hash2 = auth.signature_hash();
        assert_eq!(hash1, hash2, "signature_hash should be deterministic");
        assert_ne!(hash1, B256::ZERO);

        // Different auth produces different hash
        let auth2 = make_auth(Some(2000), None);
        assert_ne!(auth.signature_hash(), auth2.signature_hash());

        // Sign and recover
        let signature = sign_hash(&signing_key, &auth.signature_hash());
        let inner_sig = match signature {
            TempoSignature::Primitive(p) => p,
            _ => panic!("Expected primitive signature"),
        };
        let signed = auth.clone().into_signed(inner_sig);

        // Recovery should succeed with correct address
        let recovered = signed.recover_signer();
        assert!(recovered.is_ok());
        assert_eq!(recovered.unwrap(), expected_address);

        // Wrong signature hash yields wrong address
        let wrong_sig = sign_hash(&signing_key, &B256::random());
        let wrong_inner = match wrong_sig {
            TempoSignature::Primitive(p) => p,
            _ => panic!("Expected primitive signature"),
        };
        let bad_signed = auth.into_signed(wrong_inner);
        let bad_recovered = bad_signed.recover_signer();
        assert!(bad_recovered.is_ok());
        assert_ne!(bad_recovered.unwrap(), expected_address);
    }

    #[test]
    fn test_spending_expiry_and_size() {
        // has_unlimited_spending: None = true, Some = false
        assert!(make_auth(None, None).has_unlimited_spending());
        assert!(!make_auth(None, Some(vec![])).has_unlimited_spending());
        assert!(
            !make_auth(
                None,
                Some(vec![TokenLimit::one_time(Address::ZERO, U256::from(100))])
            )
            .has_unlimited_spending()
        );

        // never_expires: None = true, Some = false
        assert!(make_auth(None, None).never_expires());
        assert!(!make_auth(Some(1000), None).never_expires());
        assert!(!make_auth(Some(0), None).never_expires()); // 0 is still Some
    }

    #[test]
    fn test_token_limit_rlp_roundtrip() {
        // Test V1 (2 fields) backward compatibility
        let legacy_limit = TokenLimit::one_time(Address::random(), U256::from(1000));
        let mut buf = Vec::new();
        legacy_limit.encode(&mut buf);
        let decoded = TokenLimit::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.token, legacy_limit.token);
        assert_eq!(decoded.limit, legacy_limit.limit);
        assert_eq!(decoded.remaining_in_period, legacy_limit.limit);
        assert_eq!(decoded.period, 0);
        assert_eq!(decoded.period_end, 0);

        // Test V2 (5 fields) periodic limit
        let periodic_limit = TokenLimit::periodic(
            Address::random(),
            U256::from(500),
            86400, // 1 day
            1704067200, // some future timestamp
        );
        buf.clear();
        periodic_limit.encode(&mut buf);
        let decoded = TokenLimit::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, periodic_limit);
        assert!(decoded.is_periodic());
    }

    #[test]
    fn test_key_authorization_destinations() {
        let mut auth = make_auth(None, None);
        assert!(auth.is_unrestricted());
        assert!(auth.allowed_destinations().is_empty());

        // Empty destinations = unrestricted
        auth.allowed_destinations = Some(vec![]);
        assert!(auth.is_unrestricted());

        // Non-empty destinations = restricted
        let dest = Address::random();
        auth.allowed_destinations = Some(vec![dest]);
        assert!(!auth.is_unrestricted());
        assert_eq!(auth.allowed_destinations(), &[dest]);
    }
}
