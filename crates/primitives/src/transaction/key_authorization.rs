use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// Token spending limit for access keys (TIP-1011)
///
/// Defines a per-token spending limit for an access key provisioned via key_authorization.
/// This limit is enforced by the AccountKeychain precompile when the key is used.
///
/// Supports both one-time limits (period = 0) and periodic limits that reset automatically.
///
/// RLP encoding:
/// - V1 (legacy): `[token, limit]` - decoded as one-time limit
/// - V2 (TIP-1011): `[token, limit, remaining_in_period, period, period_end]`
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct TokenLimit {
    /// TIP20 token address
    pub token: Address,

    /// Per-period limit when period > 0, one-time limit otherwise
    pub limit: U256,

    /// Remaining allowance in current period
    pub remaining_in_period: U256,

    /// Period duration in seconds (0 = one-time limit, >0 = periodic)
    pub period: u64,

    /// Timestamp when current period expires (0 if one-time limit)
    pub period_end: u64,
}

impl TokenLimit {
    /// Create a new one-time (non-periodic) token limit
    pub fn one_time(token: Address, limit: U256) -> Self {
        Self {
            token,
            limit,
            remaining_in_period: limit,
            period: 0,
            period_end: 0,
        }
    }

    /// Create a new periodic token limit
    pub fn periodic(token: Address, limit: U256, period: u64) -> Self {
        Self {
            token,
            limit,
            remaining_in_period: limit,
            period,
            period_end: 0, // Will be set on first use
        }
    }

    /// Returns true if this is a periodic limit
    pub fn is_periodic(&self) -> bool {
        self.period > 0
    }

    /// Returns true if this is a legacy one-time limit (V1 format)
    pub fn is_legacy(&self) -> bool {
        self.period == 0 && self.period_end == 0
    }
}

impl Encodable for TokenLimit {
    fn encode(&self, out: &mut dyn BufMut) {
        // Always encode as V2 (5 fields) for new transactions
        let payload_length = self.token.length()
            + self.limit.length()
            + self.remaining_in_period.length()
            + self.period.length()
            + self.period_end.length();

        Header {
            list: true,
            payload_length,
        }
        .encode(out);

        self.token.encode(out);
        self.limit.encode(out);
        self.remaining_in_period.encode(out);
        self.period.encode(out);
        self.period_end.encode(out);
    }

    fn length(&self) -> usize {
        let payload_length = self.token.length()
            + self.limit.length()
            + self.remaining_in_period.length()
            + self.period.length()
            + self.period_end.length();

        payload_length + Header { list: true, payload_length }.length()
    }
}

impl Decodable for TokenLimit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let start_len = buf.len();
        if header.payload_length > start_len {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        // Decode required fields
        let token = Address::decode(buf)?;
        let limit = U256::decode(buf)?;

        let consumed = start_len - buf.len();
        let remaining_payload = header.payload_length - consumed;

        // Version-tolerant decoding:
        // - If no more fields (V1): treat as legacy one-time limit
        // - If 3 more fields (V2): decode periodic limit fields
        if remaining_payload == 0 {
            // V1 (legacy): [token, limit]
            Ok(Self {
                token,
                limit,
                remaining_in_period: limit,
                period: 0,
                period_end: 0,
            })
        } else {
            // V2 (TIP-1011): [token, limit, remaining_in_period, period, period_end]
            let remaining_in_period = U256::decode(buf)?;
            let period = u64::decode(buf)?;
            let period_end = u64::decode(buf)?;

            // Verify we consumed exactly the payload
            let total_consumed = start_len - buf.len();
            if total_consumed != header.payload_length {
                return Err(alloy_rlp::Error::UnexpectedLength);
            }

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
        let token = Address::arbitrary(u)?;
        let limit = U256::arbitrary(u)?;
        let period = u64::arbitrary(u)?;

        Ok(if period == 0 {
            Self::one_time(token, limit)
        } else {
            Self {
                token,
                limit,
                remaining_in_period: U256::arbitrary(u)?,
                period,
                period_end: u64::arbitrary(u)?,
            }
        })
    }
}

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for TokenLimit {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: BufMut + AsMut<[u8]>,
    {
        // Use RLP encoding for compact representation (matches SignedKeyAuthorization pattern)
        self.encode(buf);
        self.length()
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let item =
            Decodable::decode(&mut buf).expect("Failed to decode TokenLimit from compact");
        (item, buf)
    }
}

/// Key authorization for provisioning access keys (TIP-1011, TIP-1013)
///
/// Used in TempoTransaction to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
///
/// RLP encoding: `[chain_id, key_type, key_id, expiry?, limits?, allowed_destinations?, valid_after?, activation_delay?]`
/// - Non-optional fields come first, followed by optional (trailing) fields
/// - `expiry`: `None` (omitted or 0x80) = key never expires, `Some(timestamp)` = expires at timestamp
/// - `limits`: `None` (omitted or 0x80) = unlimited spending, `Some([])` = no spending, `Some([...])` = specific limits
/// - `allowed_destinations`: `None` (omitted or 0x80) = unrestricted, `Some([])` = unrestricted, `Some([...])` = restricted
/// - `valid_after`: `None` (omitted or 0x80) = no absolute time constraint, `Some(timestamp)` = key cannot activate before this
/// - `activation_delay`: `None` (omitted or 0x80) = no delay, `Some(seconds)` = delay after authorization before key is usable
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
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
    /// - `None` (RLP 0x80) = unrestricted (can call any address)
    /// - `Some([])` = unrestricted (can call any address)
    /// - `Some([addr1, addr2, ...])` = restricted to only these addresses
    pub allowed_destinations: Option<Vec<Address>>,

    /// TIP-1013: Absolute timestamp before which key cannot be used.
    /// - `None` (RLP 0x80) = no absolute time constraint
    /// - `Some(timestamp)` = key cannot activate before this timestamp
    /// Combined with activation_delay: activatesAt = max(valid_after, auth_time + activation_delay)
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub valid_after: Option<u64>,

    /// TIP-1013: Seconds after authorization before key is usable.
    /// - `None` (RLP 0x80) = no delay (immediately usable after authorization)
    /// - `Some(seconds)` = key becomes usable `seconds` after on-chain authorization
    /// This guarantees a warning period for recovery guardian patterns.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub activation_delay: Option<u64>,
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

    /// Returns whether this key has destination restrictions
    pub fn has_destination_restrictions(&self) -> bool {
        self.allowed_destinations
            .as_ref()
            .is_some_and(|dests| !dests.is_empty())
    }

    /// Check if a destination is allowed for this key
    pub fn is_destination_allowed(&self, destination: &Address) -> bool {
        match &self.allowed_destinations {
            None => true,
            Some(dests) if dests.is_empty() => true,
            Some(dests) => dests.contains(destination),
        }
    }

    /// TIP-1013: Returns the valid_after timestamp (0 if not set)
    pub fn valid_after(&self) -> u64 {
        self.valid_after.unwrap_or(0)
    }

    /// TIP-1013: Returns the activation_delay in seconds (0 if not set)
    pub fn activation_delay(&self) -> u64 {
        self.activation_delay.unwrap_or(0)
    }

    /// TIP-1013: Compute the activation timestamp for this key
    ///
    /// Returns the timestamp when this key becomes usable:
    /// `activatesAt = max(valid_after, current_timestamp + activation_delay)`
    ///
    /// This ensures that:
    /// 1. The key cannot be used before `valid_after` (absolute constraint)
    /// 2. There is always at least `activation_delay` seconds of warning after authorization
    pub fn compute_activates_at(&self, current_timestamp: u64) -> u64 {
        let valid_after = self.valid_after();
        let activation_delay = self.activation_delay();
        let delay_based = current_timestamp.saturating_add(activation_delay);
        core::cmp::max(valid_after, delay_based)
    }

    /// TIP-1013: Returns true if this key has activation constraints
    pub fn has_activation_constraints(&self) -> bool {
        self.valid_after.is_some() || self.activation_delay.is_some()
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
            // TIP-1013: Ensure that Some(0) is not generated as it's becoming `None` after RLP roundtrip.
            valid_after: u.arbitrary::<Option<u64>>()?.filter(|v| *v != 0),
            activation_delay: u.arbitrary::<Option<u64>>()?.filter(|v| *v != 0),
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
            valid_after: None,
            activation_delay: None,
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
    fn test_token_limit_v1_rlp_decode() {
        // Simulate V1 (legacy) encoding: [token, limit]
        let token = Address::random();
        let limit = U256::from(1000);

        // Manually encode V1 format
        let mut buf = Vec::new();
        let payload_length = token.length() + limit.length();
        Header {
            list: true,
            payload_length,
        }
        .encode(&mut buf);
        token.encode(&mut buf);
        limit.encode(&mut buf);

        // Decode should succeed and fill defaults
        let decoded = TokenLimit::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.limit, limit);
        assert_eq!(decoded.remaining_in_period, limit); // defaults to limit
        assert_eq!(decoded.period, 0);
        assert_eq!(decoded.period_end, 0);
        assert!(!decoded.is_periodic());
        assert!(decoded.is_legacy());
    }

    #[test]
    fn test_token_limit_v2_rlp_roundtrip() {
        let original = TokenLimit {
            token: Address::random(),
            limit: U256::from(1000),
            remaining_in_period: U256::from(500),
            period: 86400, // 1 day
            period_end: 1700000000,
        };

        let mut buf = Vec::new();
        original.encode(&mut buf);

        let decoded = TokenLimit::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, original);
        assert!(decoded.is_periodic());
        assert!(!decoded.is_legacy());
    }

    #[test]
    fn test_token_limit_one_time_constructor() {
        let token = Address::random();
        let limit = U256::from(100);
        let tl = TokenLimit::one_time(token, limit);

        assert_eq!(tl.token, token);
        assert_eq!(tl.limit, limit);
        assert_eq!(tl.remaining_in_period, limit);
        assert_eq!(tl.period, 0);
        assert!(!tl.is_periodic());
    }

    #[test]
    fn test_token_limit_periodic_constructor() {
        let token = Address::random();
        let limit = U256::from(100);
        let period = 3600u64; // 1 hour
        let tl = TokenLimit::periodic(token, limit, period);

        assert_eq!(tl.token, token);
        assert_eq!(tl.limit, limit);
        assert_eq!(tl.remaining_in_period, limit);
        assert_eq!(tl.period, period);
        assert_eq!(tl.period_end, 0); // Set on first use
        assert!(tl.is_periodic());
    }

    #[test]
    fn test_destination_restrictions() {
        let dest1 = Address::random();
        let dest2 = Address::random();
        let other = Address::random();

        // No restrictions
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_destinations: None,
            valid_after: None,
            activation_delay: None,
        };
        assert!(!auth.has_destination_restrictions());
        assert!(auth.is_destination_allowed(&dest1));
        assert!(auth.is_destination_allowed(&other));

        // Empty list = unrestricted
        let auth = KeyAuthorization {
            allowed_destinations: Some(vec![]),
            ..auth.clone()
        };
        assert!(!auth.has_destination_restrictions());
        assert!(auth.is_destination_allowed(&dest1));

        // Restricted to specific destinations
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_destinations: Some(vec![dest1, dest2]),
            valid_after: None,
            activation_delay: None,
        };
        assert!(auth.has_destination_restrictions());
        assert!(auth.is_destination_allowed(&dest1));
        assert!(auth.is_destination_allowed(&dest2));
        assert!(!auth.is_destination_allowed(&other));
    }

    #[test]
    fn test_key_authorization_with_destinations_rlp_roundtrip() {
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: Some(1700000000),
            limits: Some(vec![TokenLimit::one_time(Address::random(), U256::from(100))]),
            allowed_destinations: Some(vec![Address::random(), Address::random()]),
            valid_after: None,
            activation_delay: None,
        };

        let mut buf = Vec::new();
        auth.encode(&mut buf);

        let decoded = KeyAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, auth);
    }

    #[test]
    fn test_key_authorization_with_activation_fields_rlp_roundtrip() {
        // Test with valid_after only
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: Some(1700000000),
            limits: None,
            allowed_destinations: None,
            valid_after: Some(1699900000),
            activation_delay: None,
        };

        let mut buf = Vec::new();
        auth.encode(&mut buf);
        let decoded = KeyAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, auth);

        // Test with activation_delay only
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_destinations: None,
            valid_after: None,
            activation_delay: Some(86400 * 30), // 30 days
        };

        let mut buf = Vec::new();
        auth.encode(&mut buf);
        let decoded = KeyAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, auth);

        // Test with both fields
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: Some(1800000000),
            limits: Some(vec![TokenLimit::one_time(Address::random(), U256::from(100))]),
            allowed_destinations: Some(vec![Address::random()]),
            valid_after: Some(1700000000),
            activation_delay: Some(604800), // 7 days
        };

        let mut buf = Vec::new();
        auth.encode(&mut buf);
        let decoded = KeyAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, auth);
    }

    #[test]
    fn test_compute_activates_at() {
        let current_timestamp = 1700000000u64;

        // No constraints: activates immediately
        let auth = make_auth(None, None);
        assert_eq!(auth.compute_activates_at(current_timestamp), current_timestamp);

        // valid_after only: activates at valid_after
        let mut auth = make_auth(None, None);
        auth.valid_after = Some(1700100000);
        assert_eq!(auth.compute_activates_at(current_timestamp), 1700100000);

        // activation_delay only: activates after delay
        let mut auth = make_auth(None, None);
        auth.activation_delay = Some(86400); // 1 day
        assert_eq!(
            auth.compute_activates_at(current_timestamp),
            current_timestamp + 86400
        );

        // Both fields, valid_after dominates
        let mut auth = make_auth(None, None);
        auth.valid_after = Some(1700200000);
        auth.activation_delay = Some(86400);
        assert_eq!(auth.compute_activates_at(current_timestamp), 1700200000);

        // Both fields, activation_delay dominates
        let mut auth = make_auth(None, None);
        auth.valid_after = Some(1700050000);
        auth.activation_delay = Some(86400);
        assert_eq!(
            auth.compute_activates_at(current_timestamp),
            current_timestamp + 86400
        );
    }

    #[test]
    fn test_has_activation_constraints() {
        let auth = make_auth(None, None);
        assert!(!auth.has_activation_constraints());

        let mut auth = make_auth(None, None);
        auth.valid_after = Some(1700000000);
        assert!(auth.has_activation_constraints());

        let mut auth = make_auth(None, None);
        auth.activation_delay = Some(86400);
        assert!(auth.has_activation_constraints());

        let mut auth = make_auth(None, None);
        auth.valid_after = Some(1700000000);
        auth.activation_delay = Some(86400);
        assert!(auth.has_activation_constraints());
    }
}
