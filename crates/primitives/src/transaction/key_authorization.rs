use super::SignatureType;
use crate::transaction::PrimitiveSignature;
use alloc::vec::Vec;
use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_rlp::{Buf, Decodable, EMPTY_STRING_CODE, Encodable};

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

impl Decodable for TokenLimit {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let remaining = buf.len();
        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let mut fields = &buf[..header.payload_length];

        let token = Decodable::decode(&mut fields)?;
        let limit = Decodable::decode(&mut fields)?;
        // Backward-compatible decode: legacy payloads omit period and map to one-time limits.
        let period = if fields.is_empty() {
            0
        } else {
            let period: u64 = Decodable::decode(&mut fields)?;
            if period == 0 {
                return Err(alloy_rlp::Error::Custom(
                    "token limit period=0 must be encoded in legacy two-field form",
                ));
            }
            period
        };

        if !fields.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        buf.advance(header.payload_length);

        Ok(Self {
            token,
            limit,
            period,
        })
    }
}

impl Encodable for TokenLimit {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let payload_length = self.token.length()
            + self.limit.length()
            + if self.period == 0 {
                0
            } else {
                self.period.length()
            };

        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);

        self.token.encode(out);
        self.limit.encode(out);
        if self.period != 0 {
            self.period.encode(out);
        }
    }

    fn length(&self) -> usize {
        let payload_length = self.token.length()
            + self.limit.length()
            + if self.period == 0 {
                0
            } else {
                self.period.length()
            };

        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

/// Per-target call scope for an access key.
///
/// `selector_rules` uses tri-state semantics:
/// - `None` => allow any selector for this target
/// - `Some([])` => deny all selectors for this target
/// - `Some([..])` => allow exactly the listed selector rules
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[rlp(trailing)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct CallScope {
    /// Target contract address.
    pub target: Address,
    /// Optional selector rules for this target.
    pub selector_rules: Option<Vec<SelectorRule>>,
}

/// Selector-level rule within a [`CallScope`].
///
/// `recipients` semantics:
/// - `None` => no recipient constraint
/// - `Some([..])` => first ABI address argument must be in this list
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[rlp(trailing)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct SelectorRule {
    /// 4-byte function selector.
    pub selector: [u8; 4],
    /// Optional recipient allowlist.
    pub recipients: Option<Vec<Address>>,
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
/// - `allowed_calls`: `None` = unrestricted, `Some([])` = deny-all, `Some([...])` = scoped calls
#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable)]
#[rlp(trailing)]
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
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity::opt"))]
    pub expiry: Option<u64>,

    /// TIP20 spending limits for this key.
    /// - `None` (RLP 0x80) = unlimited spending (no limits enforced)
    /// - `Some([])` = no spending allowed (enforce_limits=true but no tokens allowed)
    /// - `Some([TokenLimit{...}])` = specific limits enforced
    pub limits: Option<Vec<TokenLimit>>,

    /// Optional call scopes for this key.
    /// - `None` (RLP 0x80) = unrestricted calls
    /// - `Some([])` = scoped mode with no allowed calls (deny-all)
    /// - `Some([CallScope{...}])` = explicit target/selector scope list
    pub allowed_calls: Option<Vec<CallScope>>,
}

impl Decodable for KeyAuthorization {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        fn decode_optional_field<T: Decodable>(fields: &mut &[u8]) -> alloy_rlp::Result<Option<T>> {
            if fields.is_empty() {
                return Ok(None);
            }
            if fields.first() == Some(&EMPTY_STRING_CODE) {
                fields.advance(1);
                return Ok(None);
            }

            Ok(Some(Decodable::decode(fields)?))
        }

        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }

        let remaining = buf.len();
        if header.payload_length > remaining {
            return Err(alloy_rlp::Error::InputTooShort);
        }

        let mut fields = &buf[..header.payload_length];

        let chain_id = Decodable::decode(&mut fields)?;
        let key_type = Decodable::decode(&mut fields)?;
        let key_id = Decodable::decode(&mut fields)?;

        let expiry: Option<u64> = decode_optional_field(&mut fields)?;
        let limits: Option<Vec<TokenLimit>> = decode_optional_field(&mut fields)?;

        let allowed_calls = if fields.is_empty() {
            None
        } else {
            if fields.first() == Some(&EMPTY_STRING_CODE) {
                return Err(alloy_rlp::Error::Custom(
                    "key authorization allowed_calls=None must be omitted on wire",
                ));
            }

            Some(Decodable::decode(&mut fields)?)
        };

        if !fields.is_empty() {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }

        buf.advance(header.payload_length);

        Ok(Self {
            chain_id,
            key_type,
            key_id,
            expiry,
            limits,
            allowed_calls,
        })
    }
}

impl KeyAuthorization {
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

    /// Returns the number of storage rows written for scoped-call state.
    ///
    /// This mirrors the writes performed by `authorize_key -> replace_allowed_calls ->
    /// upsert_target_scope` in the account keychain precompile.
    pub fn call_scope_storage_slots(&self) -> u64 {
        match self.allowed_calls.as_ref() {
            None => 0,
            Some(scopes) if scopes.is_empty() => 1,
            Some(scopes) => {
                let mut selectors = 0u64;
                let mut constrained_selectors = 0u64;
                let mut recipients = 0u64;

                for scope in scopes {
                    if let Some(rules) = scope.selector_rules.as_ref() {
                        selectors += rules.len() as u64;
                        for rule in rules {
                            if let Some(rule_recipients) = rule.recipients.as_ref() {
                                constrained_selectors += 1;
                                recipients += rule_recipients.len() as u64;
                            }
                        }
                    }
                }

                // Storage write accounting:
                // - account mode write: 1
                // - each target insertion + target mode write: 3 + 1
                // - each selector insertion + selector mode write: 3 + 1
                // - recipient-constrained selectors also write recipient set length: +1 per selector
                // - recipient set values+positions: +2 per recipient
                1 + scopes.len() as u64 * 4 + selectors * 4 + constrained_selectors + recipients * 2
            }
        }
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
                    + scopes
                        .iter()
                        .map(|scope| {
                            scope.selector_rules.as_ref().map_or(0, |rules| {
                                rules.capacity() * size_of::<SelectorRule>()
                                    + rules
                                        .iter()
                                        .map(|rule| {
                                            rule.recipients.as_ref().map_or(0, |recipients| {
                                                recipients.capacity() * size_of::<Address>()
                                            })
                                        })
                                        .sum::<usize>()
                            })
                        })
                        .sum::<usize>()
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
        assert!(!make_auth(Some(0), None).never_expires()); // 0 is still Some
    }

    #[test]
    fn test_size_does_not_double_count_call_scope_structs() {
        let recipients = vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        let mut rules = Vec::with_capacity(3);
        rules.push(SelectorRule {
            selector: [1, 2, 3, 4],
            recipients: Some(recipients),
        });

        let mut scopes = Vec::with_capacity(2);
        scopes.push(CallScope {
            target: Address::repeat_byte(0x33),
            selector_rules: Some(rules),
        });

        let auth = KeyAuthorization {
            chain_id: 1,
            key_type: SignatureType::Secp256k1,
            key_id: Address::repeat_byte(0x44),
            expiry: None,
            limits: None,
            allowed_calls: Some(scopes),
        };

        let scope_rules = auth.allowed_calls.as_ref().unwrap();
        let selector_rules = scope_rules[0].selector_rules.as_ref().unwrap();
        let recipients = selector_rules[0].recipients.as_ref().unwrap();

        let expected = size_of::<KeyAuthorization>()
            + scope_rules.capacity() * size_of::<CallScope>()
            + selector_rules.capacity() * size_of::<SelectorRule>()
            + recipients.capacity() * size_of::<Address>();

        assert_eq!(auth.size(), expected);
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
    fn test_token_limit_decode_rejects_explicit_zero_period_field() {
        let token = Address::random();
        let limit = U256::from(42);
        let period = 0u64;

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: token.length() + limit.length() + period.length(),
        }
        .encode(&mut encoded);
        token.encode(&mut encoded);
        limit.encode(&mut encoded);
        period.encode(&mut encoded);

        let err: alloy_rlp::Error =
            <TokenLimit as Decodable>::decode(&mut encoded.as_slice()).unwrap_err();
        assert!(matches!(err, alloy_rlp::Error::Custom(_)));
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

    #[test]
    fn test_key_authorization_decode_rejects_explicit_unrestricted_allowed_calls_field() {
        let chain_id = 1u64;
        let key_type = SignatureType::Secp256k1;
        let key_id = Address::random();

        let mut payload = Vec::new();
        chain_id.encode(&mut payload);
        key_type.encode(&mut payload);
        key_id.encode(&mut payload);
        payload.extend_from_slice(&[EMPTY_STRING_CODE, EMPTY_STRING_CODE, EMPTY_STRING_CODE]);

        let mut encoded = Vec::new();
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        }
        .encode(&mut encoded);
        encoded.extend_from_slice(&payload);

        let err: alloy_rlp::Error =
            <KeyAuthorization as Decodable>::decode(&mut encoded.as_slice()).unwrap_err();
        assert!(matches!(err, alloy_rlp::Error::Custom(_)));
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
}
