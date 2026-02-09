use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, FixedBytes, U256, keccak256};
use alloy_rlp::{BufMut, Decodable, Encodable, Header};

/// 4-byte function selector type
pub type Selector = FixedBytes<4>;

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

/// Call scope for access keys (TIP-1011)
///
/// Defines an allowed (address, selector) pair for an access key.
/// This restricts which contract functions the key can call.
///
/// RLP encoding: `[target, selector]`
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct CallScope {
    /// Target contract address.
    /// - `Address::ZERO` = wildcard, matches any address
    /// - Any other address = only matches that specific address
    pub target: Address,

    /// Function selector (first 4 bytes of calldata).
    /// - `Selector::ZERO` = wildcard, matches any selector (including empty calldata/ETH transfers)
    /// - Any other selector = only matches calls with that selector
    pub selector: Selector,
}

impl CallScope {
    /// Create a call scope that allows any function on a specific address
    pub fn address_only(target: Address) -> Self {
        Self {
            target,
            selector: Selector::ZERO,
        }
    }

    /// Create a call scope that allows a specific function on a specific address
    pub fn address_and_selector(target: Address, selector: Selector) -> Self {
        Self { target, selector }
    }

    /// Create a call scope that allows a specific function on any address
    pub fn selector_only(selector: Selector) -> Self {
        Self {
            target: Address::ZERO,
            selector,
        }
    }

    /// Check if this scope matches the given (destination, selector) pair
    ///
    /// For calls with empty calldata (e.g., ETH transfers), pass `Selector::ZERO` as the selector.
    pub fn matches(&self, destination: Address, call_selector: Selector) -> bool {
        let target_matches = self.target == Address::ZERO || self.target == destination;
        let selector_matches = self.selector == Selector::ZERO || self.selector == call_selector;
        target_matches && selector_matches
    }

    /// Returns true if this is a wildcard scope (matches everything)
    pub fn is_wildcard(&self) -> bool {
        self.target == Address::ZERO && self.selector == Selector::ZERO
    }
}

/// Key authorization for provisioning access keys (TIP-1011)
///
/// Used in TempoTransaction to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
///
/// RLP encoding: `[chain_id, key_type, key_id, expiry?, limits?, allowed_calls?]`
/// - Non-optional fields come first, followed by optional (trailing) fields
/// - `expiry`: `None` (omitted or 0x80) = key never expires, `Some(timestamp)` = expires at timestamp
/// - `limits`: `None` (omitted or 0x80) = unlimited spending, `Some([])` = no spending, `Some([...])` = specific limits
/// - `allowed_calls`: `None` (omitted or 0x80) = unrestricted, `Some([])` = unrestricted, `Some([...])` = restricted
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

    /// Allowed call scopes (address + selector pairs) for this key (TIP-1011).
    /// - `None` (RLP 0x80) = unrestricted (can call any function on any address)
    /// - `Some([])` = unrestricted (can call any function on any address)
    /// - `Some([CallScope{...}])` = restricted to only matching (address, selector) pairs
    pub allowed_calls: Option<Vec<CallScope>>,
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
                .allowed_calls
                .as_ref()
                .map_or(0, |calls| calls.capacity() * size_of::<CallScope>())
    }

    /// Returns whether this key has call scope restrictions
    pub fn has_call_restrictions(&self) -> bool {
        self.allowed_calls
            .as_ref()
            .is_some_and(|calls| !calls.is_empty())
    }

    /// Check if a call is allowed for this key
    ///
    /// For calls with empty calldata (e.g., ETH transfers), pass `Selector::ZERO` as the selector.
    pub fn is_call_allowed(&self, destination: &Address, selector: Selector) -> bool {
        match &self.allowed_calls {
            None => true,
            Some(calls) if calls.is_empty() => true,
            Some(calls) => calls.iter().any(|scope| scope.matches(*destination, selector)),
        }
    }

    /// Extract the selector from calldata (first 4 bytes), or Selector::ZERO if calldata is too short
    pub fn extract_selector(calldata: &[u8]) -> Selector {
        if calldata.len() >= 4 {
            Selector::from_slice(&calldata[..4])
        } else {
            Selector::ZERO
        }
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
            allowed_calls: u.arbitrary()?,
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
            allowed_calls: None,
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
    fn test_call_scope_matching() {
        let target = Address::random();
        let selector = Selector::from([0xaa, 0xbb, 0xcc, 0xdd]);
        let other_target = Address::random();
        let other_selector = Selector::from([0x11, 0x22, 0x33, 0x44]);

        // Exact match (target + selector)
        let scope = CallScope::address_and_selector(target, selector);
        assert!(scope.matches(target, selector));
        assert!(!scope.matches(other_target, selector));
        assert!(!scope.matches(target, other_selector));
        assert!(!scope.matches(other_target, other_selector));

        // Address-only match (any selector on specific address)
        let scope = CallScope::address_only(target);
        assert!(scope.matches(target, selector));
        assert!(scope.matches(target, other_selector));
        assert!(scope.matches(target, Selector::ZERO)); // ETH transfer
        assert!(!scope.matches(other_target, selector));

        // Selector-only match (specific selector on any address)
        let scope = CallScope::selector_only(selector);
        assert!(scope.matches(target, selector));
        assert!(scope.matches(other_target, selector));
        assert!(!scope.matches(target, other_selector));

        // Wildcard (matches everything)
        let scope = CallScope {
            target: Address::ZERO,
            selector: Selector::ZERO,
        };
        assert!(scope.is_wildcard());
        assert!(scope.matches(target, selector));
        assert!(scope.matches(other_target, other_selector));
        assert!(scope.matches(Address::random(), Selector::ZERO));
    }

    #[test]
    fn test_call_restrictions() {
        let dest1 = Address::random();
        let dest2 = Address::random();
        let selector1 = Selector::from([0xaa, 0xbb, 0xcc, 0xdd]);
        let selector2 = Selector::from([0x11, 0x22, 0x33, 0x44]);
        let other = Address::random();

        // No restrictions
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_calls: None,
        };
        assert!(!auth.has_call_restrictions());
        assert!(auth.is_call_allowed(&dest1, selector1));
        assert!(auth.is_call_allowed(&other, Selector::ZERO));

        // Empty list = unrestricted
        let auth = KeyAuthorization {
            allowed_calls: Some(vec![]),
            ..auth.clone()
        };
        assert!(!auth.has_call_restrictions());
        assert!(auth.is_call_allowed(&dest1, selector1));

        // Restricted to specific (address, selector) pairs
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_calls: Some(vec![
                CallScope::address_and_selector(dest1, selector1),
                CallScope::address_only(dest2), // any function on dest2
            ]),
        };
        assert!(auth.has_call_restrictions());
        assert!(auth.is_call_allowed(&dest1, selector1));
        assert!(!auth.is_call_allowed(&dest1, selector2)); // wrong selector
        assert!(auth.is_call_allowed(&dest2, selector1)); // any selector on dest2
        assert!(auth.is_call_allowed(&dest2, selector2));
        assert!(!auth.is_call_allowed(&other, selector1)); // wrong address
    }

    #[test]
    fn test_extract_selector() {
        // Normal calldata
        let calldata = [0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03];
        assert_eq!(
            KeyAuthorization::extract_selector(&calldata),
            Selector::from([0xaa, 0xbb, 0xcc, 0xdd])
        );

        // Exactly 4 bytes
        let calldata = [0x11, 0x22, 0x33, 0x44];
        assert_eq!(
            KeyAuthorization::extract_selector(&calldata),
            Selector::from([0x11, 0x22, 0x33, 0x44])
        );

        // Empty calldata (ETH transfer)
        assert_eq!(KeyAuthorization::extract_selector(&[]), Selector::ZERO);

        // Short calldata
        assert_eq!(
            KeyAuthorization::extract_selector(&[0x01, 0x02]),
            Selector::ZERO
        );
    }

    #[test]
    fn test_key_authorization_with_call_scopes_rlp_roundtrip() {
        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: Some(1700000000),
            limits: Some(vec![TokenLimit::one_time(Address::random(), U256::from(100))]),
            allowed_calls: Some(vec![
                CallScope::address_and_selector(
                    Address::random(),
                    Selector::from([0xaa, 0xbb, 0xcc, 0xdd]),
                ),
                CallScope::address_only(Address::random()),
            ]),
        };

        let mut buf = Vec::new();
        auth.encode(&mut buf);

        let decoded = KeyAuthorization::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, auth);
    }

    #[test]
    fn test_call_scope_rlp_roundtrip() {
        let original = CallScope::address_and_selector(
            Address::random(),
            Selector::from([0x12, 0x34, 0x56, 0x78]),
        );

        let mut buf = Vec::new();
        original.encode(&mut buf);

        let decoded = CallScope::decode(&mut buf.as_slice()).unwrap();
        assert_eq!(decoded, original);
    }
}
