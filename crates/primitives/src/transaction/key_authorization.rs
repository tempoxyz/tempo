use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloc::vec::Vec;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::Encodable;
use core::num::NonZeroU64;

/// Token spending limit for access keys
///
/// Defines a per-token spending limit for an access key provisioned via key_authorization.
/// This limit is enforced by the AccountKeychain precompile when the key is used.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

    /// Period duration in seconds.
    ///
    /// `0` means one-time limit. `>0` means the limit resets periodically.
    #[cfg_attr(feature = "serde", serde(default, with = "alloy_serde::quantity"))]
    pub period: u64,
}

/// Per-target call scope for an access key.
///
/// `selector_rules` semantics:
/// - `[]` => allow any selector for this target
/// - `[rule1, ...]` => allow exactly the listed selector rules
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct CallScope {
    /// Target contract address.
    pub target: Address,
    /// Selector rules for this target. Empty means any selector is allowed.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub selector_rules: Vec<SelectorRule>,
}

impl CallScope {
    /// Returns the target contract address.
    pub fn target(&self) -> Address {
        self.target
    }

    /// Returns `true` when any call to this target is allowed (no selector restrictions).
    pub fn allows_all_selectors(&self) -> bool {
        self.selector_rules.is_empty()
    }

    /// Returns the selector rules for this target.
    pub fn selector_rules(&self) -> &[SelectorRule] {
        &self.selector_rules
    }

    fn heap_size(&self) -> usize {
        self.selector_rules.capacity() * size_of::<SelectorRule>()
            + self
                .selector_rules
                .iter()
                .map(SelectorRule::heap_size)
                .sum::<usize>()
    }
}

/// Selector-level rule within a [`CallScope`].
///
/// `recipients` semantics:
/// - `[]` => no recipient constraint
/// - `[a1, ...]` => first ABI address argument must be in this list
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct SelectorRule {
    /// 4-byte function selector.
    #[cfg_attr(feature = "serde", serde(with = "selector_hex_serde"))]
    pub selector: [u8; 4],
    /// Recipient allowlist. Empty means no recipient restriction.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Vec::is_empty")
    )]
    pub recipients: Vec<Address>,
}

impl SelectorRule {
    /// Returns the 4-byte function selector.
    pub fn selector(&self) -> [u8; 4] {
        self.selector
    }

    /// Returns the allowed recipients for this selector.
    pub fn recipients(&self) -> &[Address] {
        &self.recipients
    }

    /// Returns `true` when any recipient is allowed (no recipient restriction).
    pub fn allows_all_recipients(&self) -> bool {
        self.recipients.is_empty()
    }

    fn heap_size(&self) -> usize {
        self.recipients.capacity() * size_of::<Address>()
    }
}

use tempo_contracts::precompiles::IAccountKeychain::{
    CallScope as AbiCallScope, SelectorRule as AbiSelectorRule,
};

impl From<AbiCallScope> for CallScope {
    fn from(scope: AbiCallScope) -> Self {
        Self {
            target: scope.target,
            selector_rules: scope.selectorRules.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CallScope> for AbiCallScope {
    fn from(scope: CallScope) -> Self {
        Self {
            target: scope.target,
            selectorRules: scope.selector_rules.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<AbiSelectorRule> for SelectorRule {
    fn from(rule: AbiSelectorRule) -> Self {
        Self {
            selector: rule.selector.into(),
            recipients: rule.recipients,
        }
    }
}

impl From<SelectorRule> for AbiSelectorRule {
    fn from(rule: SelectorRule) -> Self {
        Self {
            selector: rule.selector.into(),
            recipients: rule.recipients,
        }
    }
}

/// Key authorization for provisioning access keys
///
/// Used in TempoTransaction to add a new key to the AccountKeychain precompile.
/// The transaction must be signed by the root key to authorize adding this access key.
///
/// RLP encoding: `[chain_id, key_type, key_id, expiry?, limits?, allowed_calls?]`
/// - Non-optional fields come first, followed by optional (trailing) fields
/// - `expiry`: `None` (omitted or 0x80) = key never expires, `Some(timestamp)` = expires at timestamp
/// - `limits`: `None` (omitted or 0x80) = unlimited spending, `Some([])` = no spending, `Some([...])` = specific limits
/// - `allowed_calls`: `None` (canonically omitted, explicit 0x80 accepted) = unrestricted,
///   `Some([])` = scoped with no allowed calls, `Some([...])` = scoped calls
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[rlp(trailing(canonical))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(test, reth_codecs::add_arbitrary_tests(rlp))]
pub struct KeyAuthorization {
    /// Chain ID for replay protection.
    /// Pre-T1C: 0 = valid on any chain (wildcard). T1C+: must match current chain.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: u64,

    /// Type of key being authorized (Secp256k1, P256, or WebAuthn)
    pub key_type: SignatureType,

    /// Key identifier, is the address derived from the public key of the key type.
    pub key_id: Address,

    /// Unix timestamp when key expires.
    /// - `None` (RLP 0x80) = key never expires (stored as u64::MAX in precompile)
    /// - `Some(timestamp)` = key expires at this timestamp
    ///
    /// This uses `Option<NonZeroU64>` so `Some(0)` is unrepresentable and cannot silently
    /// roundtrip into `None`.
    #[cfg_attr(feature = "serde", serde(with = "serde_nonzero_quantity_opt"))]
    pub expiry: Option<NonZeroU64>,

    /// TIP20 spending limits for this key.
    /// - `None` (RLP 0x80) = unlimited spending (no limits enforced)
    /// - `Some([])` = no spending allowed (enforce_limits=true but no tokens allowed)
    /// - `Some([TokenLimit{...}])` = specific limits enforced
    pub limits: Option<Vec<TokenLimit>>,

    /// Optional call scopes for this key.
    /// - `None` (canonically omitted, explicit 0x80 accepted) = unrestricted calls
    /// - `Some([])` = scoped mode with no allowed calls
    /// - `Some([CallScope{...}])` = explicit target/selector scope list
    pub allowed_calls: Option<Vec<CallScope>>,
}

impl KeyAuthorization {
    /// Create a fully unrestricted key authorization: no expiry, no spending limits, no call
    /// scopes.
    pub fn unrestricted(chain_id: u64, key_type: SignatureType, key_id: Address) -> Self {
        Self {
            chain_id,
            key_type,
            key_id,
            expiry: None,
            limits: None,
            allowed_calls: None,
        }
    }

    /// Set an expiry timestamp on this key authorization.
    pub fn with_expiry(mut self, expiry: u64) -> Self {
        self.expiry = NonZeroU64::new(expiry);
        self
    }

    /// Set token spending limits on this key authorization.
    pub fn with_limits(mut self, limits: Vec<TokenLimit>) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Set call-scope restrictions on this key authorization.
    pub fn with_allowed_calls(mut self, allowed_calls: Vec<CallScope>) -> Self {
        self.allowed_calls = Some(allowed_calls);
        self
    }

    /// Deny all spending (enforce limits with an empty allowlist).
    pub fn with_no_spending(mut self) -> Self {
        self.limits = Some(Vec::new());
        self
    }

    /// Deny all calls (scoped mode with an empty allowlist).
    pub fn with_no_calls(mut self) -> Self {
        self.allowed_calls = Some(Vec::new());
        self
    }

    /// Computes the authorization message hash for this key authorization.
    pub fn signature_hash(&self) -> B256 {
        let mut buf = Vec::new();
        self.encode(&mut buf);
        keccak256(&buf)
    }

    /// Returns whether any token limit uses periodic reset semantics.
    pub fn has_periodic_limits(&self) -> bool {
        self.limits
            .as_ref()
            .is_some_and(|limits| limits.iter().any(|limit| limit.period != 0))
    }

    /// Returns whether this authorization carries explicit call-scope restrictions.
    pub fn has_call_scopes(&self) -> bool {
        self.allowed_calls.is_some()
    }

    /// Returns whether this key has unlimited spending (limits is None)
    pub fn has_unlimited_spending(&self) -> bool {
        self.limits.is_none()
    }

    /// Returns whether this key never expires (expiry is None)
    pub fn never_expires(&self) -> bool {
        self.expiry.is_none()
    }

    /// Returns whether this authorization can be encoded with the legacy pre-T3 ABI.
    pub fn is_legacy_compatible(&self) -> bool {
        !(self.has_periodic_limits() || self.has_call_scopes())
    }

    /// Convert the key authorization into a [`SignedKeyAuthorization`] with a signature.
    pub fn into_signed(self, signature: PrimitiveSignature) -> SignedKeyAuthorization {
        SignedKeyAuthorization {
            authorization: self,
            signature,
        }
    }

    /// Validates that this key authorization's `chain_id` is compatible with `expected_chain_id`.
    ///
    /// - Post-T1C: `chain_id` must exactly match (wildcard `0` is no longer allowed).
    /// - Pre-T1C: `chain_id == 0` is a wildcard (valid on any chain), otherwise must match.
    pub fn validate_chain_id(
        &self,
        expected_chain_id: u64,
        is_t1c: bool,
    ) -> Result<(), KeyAuthorizationChainIdError> {
        if is_t1c {
            if self.chain_id != expected_chain_id {
                return Err(KeyAuthorizationChainIdError {
                    expected: expected_chain_id,
                    got: self.chain_id,
                });
            }
        } else if self.chain_id != 0 && self.chain_id != expected_chain_id {
            return Err(KeyAuthorizationChainIdError {
                expected: expected_chain_id,
                got: self.chain_id,
            });
        }
        Ok(())
    }

    /// Calculates a heuristic for the in-memory size of the key authorization
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self
                .limits
                .as_ref()
                .map_or(0, |limits| limits.capacity() * size_of::<TokenLimit>())
            + self.allowed_calls.as_ref().map_or(0, |scopes| {
                scopes.capacity() * size_of::<CallScope>()
                    + scopes.iter().map(CallScope::heap_size).sum::<usize>()
            })
    }
}

/// Error returned when a [`KeyAuthorization`]'s `chain_id` does not match the expected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyAuthorizationChainIdError {
    /// The expected chain ID (current chain).
    pub expected: u64,
    /// The chain ID from the KeyAuthorization.
    pub got: u64,
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

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for KeyAuthorization {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            chain_id: u.arbitrary()?,
            key_type: u.arbitrary()?,
            key_id: u.arbitrary()?,
            expiry: u.arbitrary()?,
            limits: u.arbitrary()?,
            allowed_calls: u.arbitrary()?,
        })
    }
}

#[cfg(feature = "serde")]
#[doc(hidden)]
pub mod serde_nonzero_quantity_opt {
    use core::num::NonZeroU64;

    use serde::{Deserializer, Serializer, de::Error as _};

    pub fn serialize<S>(value: &Option<NonZeroU64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        alloy_serde::quantity::opt::serialize(&value.map(NonZeroU64::get), serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<NonZeroU64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        alloy_serde::quantity::opt::deserialize(deserializer).and_then(|value: Option<u64>| {
            value
                .map(|value| {
                    NonZeroU64::new(value)
                        .ok_or_else(|| D::Error::custom("expected non-zero quantity"))
                })
                .transpose()
        })
    }
}

mod rlp {
    use super::*;
    use alloy_rlp::{Decodable, Encodable};

    #[derive(
        Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable,
    )]
    #[rlp(trailing(canonical))]
    struct TokenLimitWire {
        token: Address,
        limit: U256,
        period: Option<NonZeroU64>,
    }

    impl From<&TokenLimit> for TokenLimitWire {
        fn from(value: &TokenLimit) -> Self {
            let TokenLimit {
                token,
                limit,
                period,
            } = value;
            Self {
                token: *token,
                limit: *limit,
                period: NonZeroU64::new(*period),
            }
        }
    }

    impl From<TokenLimitWire> for TokenLimit {
        fn from(value: TokenLimitWire) -> Self {
            Self {
                token: value.token,
                limit: value.limit,
                period: value.period.map(|period| period.get()).unwrap_or(0),
            }
        }
    }

    impl Decodable for TokenLimit {
        fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
            Ok(TokenLimitWire::decode(buf)?.into())
        }
    }

    impl Encodable for TokenLimit {
        fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
            TokenLimitWire::from(self).encode(out)
        }

        fn length(&self) -> usize {
            TokenLimitWire::from(self).length()
        }
    }
}

#[cfg(feature = "serde")]
mod selector_hex_serde {
    use alloy_primitives::FixedBytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SelectorValue {
        Hex(FixedBytes<4>),
        Array([u8; 4]),
    }

    pub(super) fn serialize<S>(selector: &[u8; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FixedBytes::<4>::from(*selector).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match SelectorValue::deserialize(deserializer)? {
            SelectorValue::Hex(selector) => selector.into(),
            SelectorValue::Array(selector) => selector,
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
    use alloy_rlp::{Decodable, Encodable};

    fn nonzero(value: u64) -> NonZeroU64 {
        NonZeroU64::new(value).expect("test expiry must be non-zero")
    }

    fn make_auth(expiry: Option<u64>, limits: Option<Vec<TokenLimit>>) -> KeyAuthorization {
        KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: expiry.and_then(NonZeroU64::new),
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
                Some(vec![TokenLimit {
                    token: Address::ZERO,
                    limit: U256::from(100),
                    period: 0,
                }])
            )
            .has_unlimited_spending()
        );

        // never_expires: None = true, Some = false
        assert!(make_auth(None, None).never_expires());
        assert!(!make_auth(Some(1000), None).never_expires());
        assert_eq!(NonZeroU64::new(0), None);
    }

    #[test]
    fn test_size_does_not_double_count_call_scope_structs() {
        let recipients = vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        let mut rules = Vec::with_capacity(3);
        rules.push(SelectorRule {
            selector: [1, 2, 3, 4],
            recipients,
        });

        let mut scopes = Vec::with_capacity(2);
        scopes.push(CallScope {
            target: Address::repeat_byte(0x33),
            selector_rules: rules,
        });

        let auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x44))
                .with_allowed_calls(scopes);

        let scope_rules = auth.allowed_calls.as_ref().unwrap();
        let selector_rules = &scope_rules[0].selector_rules;
        let recipients = &selector_rules[0].recipients;

        let expected = size_of::<KeyAuthorization>()
            + scope_rules.capacity() * size_of::<CallScope>()
            + selector_rules.capacity() * size_of::<SelectorRule>()
            + recipients.capacity() * size_of::<Address>();

        assert_eq!(auth.size(), expected);
    }

    #[test]
    fn test_zero_expiry_is_unrepresentable() {
        assert_eq!(NonZeroU64::new(0), None);
        assert_eq!(Some(NonZeroU64::get(nonzero(1))), Some(1));
    }

    fn make_auth_with_chain_id(chain_id: u64) -> KeyAuthorization {
        KeyAuthorization {
            chain_id,
            key_type: SignatureType::Secp256k1,
            key_id: Address::random(),
            expiry: None,
            limits: None,
            allowed_calls: None,
        }
    }

    #[test]
    fn test_token_limit_legacy_decode_defaults_period_to_zero() {
        let token = Address::random();
        let limit = U256::from(42);

        // Legacy pre-T3 payloads encode TokenLimit as [token, limit].
        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: token.length() + limit.length(),
        }
        .encode(&mut encoded);
        token.encode(&mut encoded);
        limit.encode(&mut encoded);

        let decoded: TokenLimit =
            Decodable::decode(&mut encoded.as_slice()).expect("decode legacy token limit");
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.limit, limit);
        assert_eq!(decoded.period, 0);
    }

    #[test]
    fn test_token_limit_encoding_omits_zero_period() {
        let token_limit = TokenLimit {
            token: Address::random(),
            limit: U256::from(1234),
            period: 0,
        };

        let mut encoded = Vec::new();
        token_limit.encode(&mut encoded);

        let mut payload = &encoded[..];
        let header = alloy_rlp::Header::decode(&mut payload).expect("decode list header");
        assert!(header.list);
        assert_eq!(
            header.payload_length,
            token_limit.token.length() + token_limit.limit.length()
        );
    }

    #[test]
    fn test_token_limit_decode_accepts_explicit_zero_period_field() {
        let token = Address::random();
        let limit = U256::from(42);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: token.length() + limit.length(),
        }
        .encode(&mut encoded);
        token.encode(&mut encoded);
        limit.encode(&mut encoded);

        let decoded: TokenLimit =
            <TokenLimit as Decodable>::decode(&mut encoded.as_slice()).expect("decode token limit");
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.limit, limit);
        assert_eq!(decoded.period, 0);
    }

    #[test]
    fn test_key_authorization_roundtrip_preserves_explicit_nested_allow_all_lists() {
        let auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x11))
                .with_allowed_calls(vec![
                    CallScope {
                        target: Address::repeat_byte(0x22),
                        selector_rules: vec![],
                    },
                    CallScope {
                        target: Address::repeat_byte(0x33),
                        selector_rules: vec![SelectorRule {
                            selector: [0xaa, 0xbb, 0xcc, 0xdd],
                            recipients: vec![],
                        }],
                    },
                ]);

        let mut encoded = Vec::new();
        auth.encode(&mut encoded);

        let decoded =
            <KeyAuthorization as Decodable>::decode(&mut encoded.as_slice()).expect("decode auth");

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);

        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_call_scope_decode_rejects_omitted_selector_rules() {
        let target = Address::repeat_byte(0x11);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: target.length(),
        }
        .encode(&mut encoded);
        target.encode(&mut encoded);

        <CallScope as Decodable>::decode(&mut encoded.as_slice())
            .expect_err("omitted selector_rules should be rejected");
    }

    #[test]
    fn test_call_scope_explicit_empty_selector_rules_roundtrip() {
        let scope = CallScope {
            target: Address::repeat_byte(0x11),
            selector_rules: Vec::new(),
        };

        let mut encoded = Vec::new();
        scope.encode(&mut encoded);

        let mut payload = &encoded[..];
        let header = alloy_rlp::Header::decode(&mut payload).expect("decode list header");
        assert!(header.list);
        assert_eq!(
            header.payload_length,
            scope.target.length() + Vec::<SelectorRule>::new().length()
        );

        let decoded =
            <CallScope as Decodable>::decode(&mut encoded.as_slice()).expect("decode scope");
        assert_eq!(decoded, scope);
    }

    #[test]
    fn test_call_scope_decode_accepts_explicit_empty_selector_rules_list() {
        let target = Address::repeat_byte(0x11);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: target.length() + Vec::<SelectorRule>::new().length(),
        }
        .encode(&mut encoded);
        target.encode(&mut encoded);
        Vec::<SelectorRule>::new().encode(&mut encoded);

        let decoded =
            <CallScope as Decodable>::decode(&mut encoded.as_slice()).expect("decode scope");
        assert_eq!(decoded.target, target);
        assert!(decoded.selector_rules.is_empty());

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_selector_rule_decode_rejects_omitted_recipients() {
        let selector = [0xaa, 0xbb, 0xcc, 0xdd];

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: selector.length(),
        }
        .encode(&mut encoded);
        selector.encode(&mut encoded);

        <SelectorRule as Decodable>::decode(&mut encoded.as_slice())
            .expect_err("omitted recipients should be rejected");
    }

    #[test]
    fn test_selector_rule_empty_recipients_roundtrip() {
        let rule = SelectorRule {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            recipients: Vec::new(),
        };

        let mut encoded = Vec::new();
        rule.encode(&mut encoded);

        let mut payload = &encoded[..];
        let header = alloy_rlp::Header::decode(&mut payload).expect("decode list header");
        assert!(header.list);
        assert_eq!(
            header.payload_length,
            rule.selector.length() + Vec::<Address>::new().length()
        );

        let decoded =
            <SelectorRule as Decodable>::decode(&mut encoded.as_slice()).expect("decode rule");
        assert_eq!(decoded, rule);
    }

    #[test]
    fn test_selector_rule_decode_accepts_explicit_empty_recipient_list() {
        let selector = [0xaa, 0xbb, 0xcc, 0xdd];

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: selector.length() + Vec::<Address>::new().length(),
        }
        .encode(&mut encoded);
        selector.encode(&mut encoded);
        Vec::<Address>::new().encode(&mut encoded);

        let decoded =
            <SelectorRule as Decodable>::decode(&mut encoded.as_slice()).expect("decode rule");
        assert_eq!(decoded.selector, selector);
        assert!(decoded.recipients.is_empty());

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_selector_rule_roundtrip_preserves_non_empty_recipient_list() {
        let rule = SelectorRule {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            recipients: vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)],
        };

        let mut encoded = Vec::new();
        rule.encode(&mut encoded);

        let decoded =
            <SelectorRule as Decodable>::decode(&mut encoded.as_slice()).expect("decode rule");
        assert_eq!(decoded, rule);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_token_limit_json_defaults_period_to_zero() {
        let token = Address::repeat_byte(0x11);

        let decoded: TokenLimit = serde_json::from_value(serde_json::json!({
            "token": token,
            "limit": "0x2a",
        }))
        .expect("deserialize legacy JSON token limit");

        assert_eq!(decoded.token, token);
        assert_eq!(decoded.limit, U256::from(42));
        assert_eq!(decoded.period, 0);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_token_limit_json_serializes_period_as_quantity() {
        let value = serde_json::to_value(TokenLimit {
            token: Address::repeat_byte(0x11),
            limit: U256::from(42),
            period: 7,
        })
        .expect("serialize token limit");

        assert_eq!(value["period"], serde_json::json!("0x7"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_selector_rule_json_accepts_hex_selector() {
        let recipient = Address::repeat_byte(0x11);

        let decoded: SelectorRule = serde_json::from_value(serde_json::json!({
            "selector": "0xaabbccdd",
            "recipients": [recipient],
        }))
        .expect("deserialize selector rule with hex selector");

        assert_eq!(decoded.selector, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(decoded.recipients, vec![recipient]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_selector_rule_json_accepts_legacy_selector_array() {
        let decoded: SelectorRule = serde_json::from_value(serde_json::json!({
            "selector": [170, 187, 204, 221],
            "recipients": [],
        }))
        .expect("deserialize selector rule with legacy selector array");

        assert_eq!(decoded.selector, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(decoded.recipients.is_empty());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_selector_rule_json_serializes_selector_as_hex() {
        let value = serde_json::to_value(SelectorRule {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            recipients: Vec::new(),
        })
        .expect("serialize selector rule");

        assert_eq!(value["selector"], serde_json::json!("0xaabbccdd"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_key_authorization_json_rejects_zero_expiry() {
        let err = serde_json::from_value::<KeyAuthorization>(serde_json::json!({
            "chainId": "0x1",
            "keyType": "secp256k1",
            "keyId": Address::repeat_byte(0x11),
            "expiry": "0x0",
        }))
        .expect_err("zero expiry must be rejected");

        assert!(err.to_string().contains("expected non-zero quantity"));
    }

    #[test]
    fn test_key_authorization_decode_accepts_explicit_unrestricted_allowed_calls_field() {
        let chain_id = 1u64;
        let key_type = SignatureType::Secp256k1;
        let key_id = Address::random();

        let mut payload = Vec::new();
        chain_id.encode(&mut payload);
        key_type.encode(&mut payload);
        key_id.encode(&mut payload);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut encoded);
        encoded.extend_from_slice(&payload);

        let decoded =
            <KeyAuthorization as Decodable>::decode(&mut encoded.as_slice()).expect("decode auth");
        assert_eq!(decoded.chain_id, chain_id);
        assert_eq!(decoded.key_type, key_type);
        assert_eq!(decoded.key_id, key_id);
        assert_eq!(decoded.expiry, None);
        assert_eq!(decoded.limits, None);
        assert_eq!(decoded.allowed_calls, None);

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded.len(), encoded.len());
    }

    #[test]
    fn test_key_authorization_decode_accepts_explicit_deny_all_allowed_calls_field() {
        let chain_id = 1u64;
        let key_type = SignatureType::Secp256k1;
        let key_id = Address::random();

        let mut payload = Vec::new();
        chain_id.encode(&mut payload);
        key_type.encode(&mut payload);
        key_id.encode(&mut payload);
        payload.extend_from_slice(&[
            alloy_rlp::EMPTY_STRING_CODE,
            alloy_rlp::EMPTY_STRING_CODE,
            0xc0,
        ]);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut encoded);
        encoded.extend_from_slice(&payload);

        let decoded =
            <KeyAuthorization as Decodable>::decode(&mut encoded.as_slice()).expect("decode auth");
        assert_eq!(decoded.chain_id, chain_id);
        assert_eq!(decoded.key_type, key_type);
        assert_eq!(decoded.key_id, key_id);
        assert_eq!(decoded.expiry, None);
        assert_eq!(decoded.limits, None);
        assert_eq!(decoded.allowed_calls, Some(vec![]));

        let mut reencoded = Vec::new();
        decoded.encode(&mut reencoded);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn test_validate_chain_id_pre_t1c() {
        let expected = 42431;

        // Matching chain_id → ok
        assert!(
            make_auth_with_chain_id(expected)
                .validate_chain_id(expected, false)
                .is_ok()
        );

        // Wildcard chain_id=0 → ok pre-T1C
        assert!(
            make_auth_with_chain_id(0)
                .validate_chain_id(expected, false)
                .is_ok()
        );

        // Wrong chain_id → err
        let err = make_auth_with_chain_id(999)
            .validate_chain_id(expected, false)
            .unwrap_err();
        assert_eq!(err.expected, expected);
        assert_eq!(err.got, 999);
    }

    #[test]
    fn test_validate_chain_id_post_t1c() {
        let expected = 42431;

        // Matching chain_id → ok
        assert!(
            make_auth_with_chain_id(expected)
                .validate_chain_id(expected, true)
                .is_ok()
        );

        // Wildcard chain_id=0 → rejected post-T1C
        let err = make_auth_with_chain_id(0)
            .validate_chain_id(expected, true)
            .unwrap_err();
        assert_eq!(err.expected, expected);
        assert_eq!(err.got, 0);

        // Wrong chain_id → rejected
        let err = make_auth_with_chain_id(999)
            .validate_chain_id(expected, true)
            .unwrap_err();
        assert_eq!(err.expected, expected);
        assert_eq!(err.got, 999);
    }

    #[test]
    fn test_call_scope_accessors() {
        let target = Address::repeat_byte(0x11);
        let rule = SelectorRule {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            recipients: vec![Address::repeat_byte(0x22)],
        };
        let scope = CallScope {
            target,
            selector_rules: vec![rule],
        };

        assert_eq!(scope.target(), target);
        assert!(!scope.allows_all_selectors());
        assert_eq!(scope.selector_rules().len(), 1);
    }

    #[test]
    fn test_call_scope_allows_all_selectors_when_empty() {
        let scope = CallScope {
            target: Address::repeat_byte(0x11),
            selector_rules: vec![],
        };
        assert!(scope.allows_all_selectors());
    }

    #[test]
    fn test_selector_rule_accessors() {
        let selector = [0x12, 0x34, 0x56, 0x78];
        let recipients = vec![Address::repeat_byte(0x33), Address::repeat_byte(0x44)];
        let rule = SelectorRule {
            selector,
            recipients: recipients.clone(),
        };

        assert_eq!(rule.selector(), selector);
        assert_eq!(rule.recipients(), &recipients);
        assert!(!rule.allows_all_recipients());
    }

    #[test]
    fn test_selector_rule_allows_all_recipients_when_empty() {
        let rule = SelectorRule {
            selector: [0xaa, 0xbb, 0xcc, 0xdd],
            recipients: vec![],
        };
        assert!(rule.allows_all_recipients());
    }
}

#[cfg(all(test, feature = "reth-codec"))]
mod compact_tests {
    use super::*;
    use alloy_primitives::{address, hex};
    use reth_codecs::Compact;

    /// Ensures backwards compatibility of compact bitflags.
    ///
    /// See reth's `HeaderExt` pattern:
    /// <https://github.com/paradigmxyz/reth-core/blob/0476d1bc4b71f3c3b080622be297edd91ee4e70c/crates/codecs/src/alloy/header.rs>
    #[test]
    fn compact_types_have_unused_bits() {
        assert_ne!(TokenLimit::bitflag_unused_bits(), 0, "TokenLimit");
    }

    #[test]
    fn token_limit_compact_roundtrip() {
        let token_limit = TokenLimit {
            token: address!("0x0000000000000000000000000000000000000042"),
            limit: U256::from(1_000_000u64),
            period: 86400,
        };

        let expected = hex!("c30000000000000000000000000000000000000000420f4240015180");

        let mut buf = vec![];
        let len = token_limit.to_compact(&mut buf);
        assert_eq!(buf, expected, "TokenLimit compact encoding changed");
        assert_eq!(len, expected.len());

        let (decoded, _) = TokenLimit::from_compact(&expected, expected.len());
        assert_eq!(decoded, token_limit);
    }
}
