use core::fmt;

use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    IAccountKeychain::{
        KeyRestrictions as AbiKeyRestrictions, LegacyTokenLimit as AbiLegacyTokenLimit,
        TokenLimit as AbiTokenLimit, removeAllowedCallsCall, revokeKeyCall, setAllowedCallsCall,
        updateSpendingLimitCall,
    },
    ITIP20, authorizeKeyCall, legacyAuthorizeKeyCall,
};
use tempo_primitives::{
    SignatureType,
    transaction::{Call, CallScope, SelectorRule, TokenLimit},
};

/// SDK-level access-key restrictions used for AccountKeychain call builders.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyRestrictions {
    /// Unix timestamp when the key expires. `None` means never expires.
    expiry: Option<u64>,
    /// Optional token spending limits. `None` means unlimited spending.
    limits: Option<Vec<TokenLimit>>,
    /// Optional call scopes. `None` means unrestricted calls.
    allowed_calls: Option<Vec<CallScope>>,
}

impl KeyRestrictions {
    /// Set an expiry timestamp.
    pub fn with_expiry(mut self, expiry: u64) -> Self {
        self.expiry = Some(expiry);
        self
    }

    /// Set token spending limits.
    pub fn with_limits(mut self, limits: Vec<TokenLimit>) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Set call-scope restrictions.
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

    /// Returns `true` if calls are unrestricted (no call-scope allowlist set).
    pub fn is_unrestricted(&self) -> bool {
        self.allowed_calls.is_none()
    }

    /// Returns `true` if a call to `target` with the given `input` is allowed.
    ///
    /// Checks target, selector, and recipient restrictions in order:
    /// - No scopes configured → unrestricted, always allowed.
    /// - Target not in any scope → denied.
    /// - Scope has no selector rules → any call to that target is allowed.
    /// - Selector not in rules → denied.
    /// - Rule has no recipients → any recipient is allowed.
    /// - Otherwise the first ABI word after the selector must match an allowed recipient.
    pub fn is_call_allowed(&self, target: &Address, input: &[u8]) -> bool {
        (|| {
            let Some(scopes) = &self.allowed_calls else {
                return Some(true);
            };
            let scope = scopes.iter().find(|s| s.target == *target)?;

            if scope.selector_rules.is_empty() {
                return Some(true);
            }

            let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
            let rule = scope
                .selector_rules
                .iter()
                .find(|r| r.selector == selector)?;

            if rule.recipients.is_empty() {
                return Some(true);
            }

            let word: [u8; 32] = input.get(4..36)?.try_into().ok()?;
            Some(rule.recipients.contains(&Address::from_word(word.into())))
        })()
        .unwrap_or(false)
    }

    /// Returns the expiry timestamp, if one is set.
    pub fn expiry(&self) -> Option<u64> {
        self.expiry
    }

    /// Returns the token spending limits, if any.
    pub fn limits(&self) -> Option<&[TokenLimit]> {
        self.limits.as_deref()
    }

    /// Returns the call scope allowlist, if any.
    pub fn allowed_calls(&self) -> Option<&[CallScope]> {
        self.allowed_calls.as_deref()
    }

    fn has_periodic_limits(&self) -> bool {
        self.limits
            .as_ref()
            .is_some_and(|limits| limits.iter().any(|limit| limit.period != 0))
    }

    fn has_call_scopes(&self) -> bool {
        self.allowed_calls.is_some()
    }
}

impl From<KeyRestrictions> for AbiKeyRestrictions {
    fn from(restrictions: KeyRestrictions) -> Self {
        let KeyRestrictions {
            expiry,
            limits,
            allowed_calls,
        } = restrictions;

        Self {
            expiry: expiry.unwrap_or(u64::MAX),
            enforceLimits: limits.is_some(),
            limits: limits
                .unwrap_or_default()
                .into_iter()
                .map(|limit| AbiTokenLimit {
                    token: limit.token,
                    amount: limit.limit,
                    period: limit.period,
                })
                .collect(),
            allowAnyCalls: allowed_calls.is_none(),
            allowedCalls: allowed_calls
                .unwrap_or_default()
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

/// Builder for constructing a [`CallScope`] with ergonomic helpers for common TIP-20 selectors.
///
/// # Examples
///
/// ```ignore
/// use alloy_primitives::address;
/// use tempo_alloy::provider::keychain::CallScopeBuilder;
///
/// // Allow transfer and approve to any recipient on a specific token
/// let scope = CallScopeBuilder::new(PATH_USD)
///     .transfer(vec![])
///     .approve(vec![])
///     .build();
///
/// // Allow transfer only to a specific recipient
/// let scope = CallScopeBuilder::new(PATH_USD)
///     .transfer(vec![address!("0x1111111111111111111111111111111111111111")])
///     .build();
///
/// // Allow an arbitrary selector on a contract
/// let scope = CallScopeBuilder::new(MY_CONTRACT)
///     .with_selector([0xaa, 0xbb, 0xcc, 0xdd])
///     .build();
/// ```
#[derive(Clone, Debug)]
pub struct CallScopeBuilder {
    target: Address,
    selector_rules: Vec<SelectorRule>,
}

impl CallScopeBuilder {
    /// Create a new builder for the given target contract address.
    pub fn new(target: Address) -> Self {
        Self {
            target,
            selector_rules: Vec::new(),
        }
    }

    /// Allow calls matching an arbitrary 4-byte function selector.
    pub fn with_selector(mut self, selector: [u8; 4]) -> Self {
        self.selector_rules.push(SelectorRule {
            selector,
            recipients: vec![],
        });
        self
    }

    /// Allow `transfer(address,uint256)` calls, optionally restricted to the given recipients.
    pub fn transfer(mut self, recipients: Vec<Address>) -> Self {
        self.selector_rules.push(SelectorRule {
            selector: ITIP20::transferCall::SELECTOR,
            recipients,
        });
        self
    }

    /// Allow `transferWithMemo(address,uint256,bytes32)` calls, optionally restricted to the given recipients.
    pub fn transfer_with_memo(mut self, recipients: Vec<Address>) -> Self {
        self.selector_rules.push(SelectorRule {
            selector: ITIP20::transferWithMemoCall::SELECTOR,
            recipients,
        });
        self
    }

    /// Allow `approve(address,uint256)` calls, optionally restricted to the given spenders.
    pub fn approve(mut self, recipients: Vec<Address>) -> Self {
        self.selector_rules.push(SelectorRule {
            selector: ITIP20::approveCall::SELECTOR,
            recipients,
        });
        self
    }

    /// Consume the builder and produce a [`CallScope`].
    pub fn build(self) -> CallScope {
        CallScope {
            target: self.target,
            selector_rules: self.selector_rules,
        }
    }
}

/// Error raised when building AccountKeychain calls with incompatible restrictions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeychainBuildError {
    /// Legacy authorizeKey cannot encode periodic token limits.
    LegacyPeriodicLimits,
    /// Legacy authorizeKey cannot encode call-scope restrictions.
    LegacyCallScopes,
}

impl std::error::Error for KeychainBuildError {}
impl fmt::Display for KeychainBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::LegacyPeriodicLimits => {
                "legacy authorizeKey does not support periodic token limits"
            }
            Self::LegacyCallScopes => {
                "legacy authorizeKey does not support call-scope restrictions"
            }
        };
        write!(f, "{msg}")
    }
}

/// Build a pre-T3 `authorizeKey` call.
pub fn authorize_key_legacy(
    key_id: Address,
    signature_type: SignatureType,
    restrictions: KeyRestrictions,
) -> Result<Call, KeychainBuildError> {
    if restrictions.has_call_scopes() {
        return Err(KeychainBuildError::LegacyCallScopes);
    }
    if restrictions.has_periodic_limits() {
        return Err(KeychainBuildError::LegacyPeriodicLimits);
    }

    let KeyRestrictions {
        expiry,
        limits,
        allowed_calls: _,
    } = restrictions;
    let enforce_limits = limits.is_some();
    let limits = limits
        .unwrap_or_default()
        .into_iter()
        .map(|limit| AbiLegacyTokenLimit {
            token: limit.token,
            amount: limit.limit,
        })
        .collect();

    Ok(account_keychain_call(legacyAuthorizeKeyCall {
        keyId: key_id,
        signatureType: signature_type.into(),
        expiry: expiry.unwrap_or(u64::MAX),
        enforceLimits: enforce_limits,
        limits,
    }))
}

/// Build an `authorizeKey(address,uint8,KeyRestrictions)` precompile call.
pub fn authorize_key(
    key_id: Address,
    signature_type: SignatureType,
    restrictions: KeyRestrictions,
) -> Call {
    account_keychain_call(authorizeKeyCall {
        keyId: key_id,
        signatureType: signature_type.into(),
        config: restrictions.into(),
    })
}

/// Build a `revokeKey(address)` precompile call.
pub fn revoke_key(key_id: Address) -> Call {
    account_keychain_call(revokeKeyCall { keyId: key_id })
}

/// Build an `updateSpendingLimit(address,address,uint256)` precompile call.
pub fn update_spending_limit(key_id: Address, token: Address, new_limit: U256) -> Call {
    account_keychain_call(updateSpendingLimitCall {
        keyId: key_id,
        token,
        newLimit: new_limit,
    })
}

/// Build a `setAllowedCalls(address,CallScope[])` precompile call.
///
/// # Examples
///
/// ```ignore
/// use alloy_primitives::address;
/// use tempo_alloy::provider::keychain::{CallScopeBuilder, set_allowed_calls};
///
/// let key_id = address!("0x1111111111111111111111111111111111111111");
/// let token = address!("0x20c0000000000000000000000000000000000001");
///
/// let scope = CallScopeBuilder::new(token)
///     .transfer(vec![])
///     .approve(vec![])
///     .build();
///
/// let call = set_allowed_calls(key_id, vec![scope]);
/// ```
pub fn set_allowed_calls(key_id: Address, scopes: Vec<CallScope>) -> Call {
    account_keychain_call(setAllowedCallsCall {
        keyId: key_id,
        scopes: scopes.into_iter().map(Into::into).collect(),
    })
}

/// Build a `removeAllowedCalls(address,address)` precompile call.
///
/// # Examples
///
/// ```ignore
/// use alloy_primitives::address;
/// use tempo_alloy::provider::keychain::remove_allowed_calls;
///
/// let key_id = address!("0x1111111111111111111111111111111111111111");
/// let token = address!("0x20c0000000000000000000000000000000000001");
///
/// // Remove all call-scope rules targeting `token`
/// let call = remove_allowed_calls(key_id, token);
/// ```
pub fn remove_allowed_calls(key_id: Address, target: Address) -> Call {
    account_keychain_call(removeAllowedCallsCall {
        keyId: key_id,
        target,
    })
}

fn account_keychain_call(call: impl SolCall) -> Call {
    Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(call.abi_encode()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, uint};
    use tempo_contracts::precompiles::IAccountKeychain::{
        CallScope as AbiCallScope, SelectorRule as AbiSelectorRule,
        SignatureType as AbiSignatureType, removeAllowedCallsCall, revokeKeyCall,
        setAllowedCallsCall, updateSpendingLimitCall,
    };

    #[test]
    fn test_authorize_key_t3_defaults_to_unrestricted_never_expiring() {
        let call = authorize_key(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            KeyRestrictions::default(),
        );

        let decoded = authorizeKeyCall::abi_decode(&call.input).expect("decode authorizeKey");
        assert_eq!(
            decoded.keyId,
            address!("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(decoded.signatureType, AbiSignatureType::Secp256k1);
        assert_eq!(decoded.config.expiry, u64::MAX);
        assert!(!decoded.config.enforceLimits);
        assert!(decoded.config.limits.is_empty());
        assert!(decoded.config.allowAnyCalls);
        assert!(decoded.config.allowedCalls.is_empty());
    }

    #[test]
    fn test_authorize_key_t3_preserves_call_scopes() {
        let restrictions = KeyRestrictions::default()
            .with_expiry(123)
            .with_limits(vec![TokenLimit {
                token: address!("0x20c0000000000000000000000000000000000001"),
                limit: uint!(42_U256),
                period: 60,
            }])
            .with_allowed_calls(vec![CallScope {
                target: address!("0x20c0000000000000000000000000000000000002"),
                selector_rules: vec![SelectorRule {
                    selector: [0xaa, 0xbb, 0xcc, 0xdd],
                    recipients: vec![address!("0x3333333333333333333333333333333333333333")],
                }],
            }]);

        let call = authorize_key(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::P256,
            restrictions,
        );

        let decoded = authorizeKeyCall::abi_decode(&call.input).expect("decode authorizeKey");
        assert_eq!(decoded.signatureType, AbiSignatureType::P256);
        assert_eq!(decoded.config.expiry, 123);
        assert!(decoded.config.enforceLimits);
        assert_eq!(decoded.config.limits.len(), 1);
        assert!(!decoded.config.allowAnyCalls);
        assert_eq!(decoded.config.allowedCalls.len(), 1);
        assert_eq!(decoded.config.allowedCalls[0].selectorRules.len(), 1);
        assert_eq!(
            decoded.config.allowedCalls[0].selectorRules[0].selector,
            [0xaa_u8, 0xbb, 0xcc, 0xdd]
        );
    }

    #[test]
    fn test_authorize_key_legacy_rejects_t3_only_restrictions() {
        let scoped = authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            KeyRestrictions::default().with_no_calls(),
        )
        .expect_err("legacy ABI should reject call scopes");
        assert_eq!(scoped, KeychainBuildError::LegacyCallScopes);

        let periodic = authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            KeyRestrictions::default().with_limits(vec![TokenLimit {
                token: address!("0x20c0000000000000000000000000000000000001"),
                limit: U256::from(1),
                period: 1,
            }]),
        )
        .expect_err("legacy ABI should reject periodic limits");
        assert_eq!(periodic, KeychainBuildError::LegacyPeriodicLimits);
    }

    #[test]
    fn test_authorize_key_legacy_flattens_limits() {
        let call = authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::WebAuthn,
            KeyRestrictions::default()
                .with_expiry(999)
                .with_limits(vec![TokenLimit {
                    token: address!("0x20c0000000000000000000000000000000000001"),
                    limit: U256::from(7),
                    period: 0,
                }]),
        )
        .expect("legacy restrictions are compatible");

        let decoded =
            legacyAuthorizeKeyCall::abi_decode(&call.input).expect("decode legacy authorizeKey");
        assert_eq!(decoded.signatureType, AbiSignatureType::WebAuthn);
        assert_eq!(decoded.expiry, 999);
        assert!(decoded.enforceLimits);
        assert_eq!(decoded.limits.len(), 1);
        assert_eq!(decoded.limits[0].amount, U256::from(7));
    }

    #[test]
    fn test_call_scope_builder_tip20_selectors() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let recipient = address!("0x3333333333333333333333333333333333333333");

        let scope = CallScopeBuilder::new(token)
            .transfer(vec![recipient])
            .approve(vec![])
            .build();

        assert_eq!(scope.target, token);
        assert_eq!(scope.selector_rules.len(), 2);
        assert_eq!(
            scope.selector_rules[0].selector,
            ITIP20::transferCall::SELECTOR
        );
        assert_eq!(scope.selector_rules[0].recipients, vec![recipient]);

        assert_eq!(
            scope.selector_rules[1].selector,
            ITIP20::approveCall::SELECTOR
        );
        assert!(scope.selector_rules[1].recipients.is_empty());
    }

    #[test]
    fn test_roundtrip_abi_call_scope_conversion() {
        let scopes = vec![AbiCallScope {
            target: address!("0x20c0000000000000000000000000000000000002"),
            selectorRules: vec![AbiSelectorRule {
                selector: [0x12, 0x34, 0x56, 0x78].into(),
                recipients: vec![address!("0x3333333333333333333333333333333333333333")],
            }],
        }];

        let primitive: Vec<CallScope> = scopes.clone().into_iter().map(Into::into).collect();
        let roundtrip: Vec<AbiCallScope> = primitive.into_iter().map(Into::into).collect();
        assert_eq!(roundtrip, scopes);
    }

    #[test]
    fn test_revoke_key_encodes_correctly() {
        let key_id = address!("0x1111111111111111111111111111111111111111");
        let call = revoke_key(key_id);

        assert_eq!(call.to, TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        let decoded = revokeKeyCall::abi_decode(&call.input).expect("decode revokeKey");
        assert_eq!(decoded.keyId, key_id);
    }

    #[test]
    fn test_update_spending_limit_encodes_correctly() {
        let key_id = address!("0x1111111111111111111111111111111111111111");
        let token = address!("0x2222222222222222222222222222222222222222");
        let limit = uint!(1000_U256);
        let call = update_spending_limit(key_id, token, limit);

        assert_eq!(call.to, TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        let decoded =
            updateSpendingLimitCall::abi_decode(&call.input).expect("decode updateSpendingLimit");
        assert_eq!(decoded.keyId, key_id);
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.newLimit, limit);
    }

    #[test]
    fn test_set_allowed_calls_encodes_correctly() {
        let key_id = address!("0x1111111111111111111111111111111111111111");
        let scopes = vec![CallScope {
            target: address!("0x2222222222222222222222222222222222222222"),
            selector_rules: vec![SelectorRule {
                selector: [0xaa, 0xbb, 0xcc, 0xdd],
                recipients: vec![address!("0x3333333333333333333333333333333333333333")],
            }],
        }];
        let call = set_allowed_calls(key_id, scopes);

        assert_eq!(call.to, TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        let decoded = setAllowedCallsCall::abi_decode(&call.input).expect("decode setAllowedCalls");
        assert_eq!(decoded.keyId, key_id);
        assert_eq!(decoded.scopes.len(), 1);
        assert_eq!(decoded.scopes[0].selectorRules.len(), 1);
    }

    #[test]
    fn test_is_call_allowed_unrestricted() {
        let r = KeyRestrictions::default();
        let target = address!("0x2222222222222222222222222222222222222222");
        assert!(r.is_call_allowed(&target, &[]));
        assert!(r.is_call_allowed(&target, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    #[test]
    fn test_is_call_allowed_empty_scopes_denies_all() {
        let r = KeyRestrictions::default().with_no_calls();
        let target = address!("0x2222222222222222222222222222222222222222");
        assert!(!r.is_call_allowed(&target, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    #[test]
    fn test_is_call_allowed_target_not_in_scope() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let other = address!("0x3333333333333333333333333333333333333333");
        let r = KeyRestrictions::default()
            .with_allowed_calls(vec![CallScopeBuilder::new(token).build()]);
        assert!(!r.is_call_allowed(&other, &[0xaa, 0xbb, 0xcc, 0xdd]));
    }

    #[test]
    fn test_is_call_allowed_no_selector_rules_allows_any_call() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let r = KeyRestrictions::default()
            .with_allowed_calls(vec![CallScopeBuilder::new(token).build()]);
        assert!(r.is_call_allowed(&token, &[0xaa, 0xbb, 0xcc, 0xdd]));
        assert!(r.is_call_allowed(&token, &[]));
    }

    #[test]
    fn test_is_call_allowed_selector_match() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let r = KeyRestrictions::default().with_allowed_calls(vec![
            CallScopeBuilder::new(token)
                .with_selector([0xaa, 0xbb, 0xcc, 0xdd])
                .build(),
        ]);

        assert!(r.is_call_allowed(&token, &[0xaa, 0xbb, 0xcc, 0xdd]));
        assert!(!r.is_call_allowed(&token, &[0x11, 0x22, 0x33, 0x44]));
        assert!(!r.is_call_allowed(&token, &[0xaa, 0xbb]));
    }

    #[test]
    fn test_is_call_allowed_tip20_transfer_with_recipients() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let allowed = address!("0x4444444444444444444444444444444444444444");
        let denied = address!("0x5555555555555555555555555555555555555555");

        let r = KeyRestrictions::default().with_allowed_calls(vec![
            CallScopeBuilder::new(token).transfer(vec![allowed]).build(),
        ]);

        // Build valid transfer(address,uint256) calldata
        let mut input = Vec::new();
        input.extend_from_slice(&ITIP20::transferCall::SELECTOR);
        // recipient as ABI-encoded address (left-padded to 32 bytes)
        input.extend_from_slice(&[0u8; 12]);
        input.extend_from_slice(allowed.as_slice());
        // amount (unused for scope check, just pad)
        input.extend_from_slice(&[0u8; 32]);

        assert!(r.is_call_allowed(&token, &input));

        // Same selector but different recipient
        let mut bad_input = Vec::new();
        bad_input.extend_from_slice(&ITIP20::transferCall::SELECTOR);
        bad_input.extend_from_slice(&[0u8; 12]);
        bad_input.extend_from_slice(denied.as_slice());
        bad_input.extend_from_slice(&[0u8; 32]);

        assert!(!r.is_call_allowed(&token, &bad_input));
    }

    #[test]
    fn test_is_call_allowed_recipient_word_too_short() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let allowed = address!("0x4444444444444444444444444444444444444444");
        let r = KeyRestrictions::default().with_allowed_calls(vec![
            CallScopeBuilder::new(token).transfer(vec![allowed]).build(),
        ]);

        // Selector only, no recipient word
        let input = ITIP20::transferCall::SELECTOR.to_vec();
        assert!(!r.is_call_allowed(&token, &input));
    }

    #[test]
    fn test_is_call_allowed_no_recipients_allows_any() {
        let token = address!("0x20c0000000000000000000000000000000000001");
        let anyone = address!("0x9999999999999999999999999999999999999999");

        let r = KeyRestrictions::default()
            .with_allowed_calls(vec![CallScopeBuilder::new(token).transfer(vec![]).build()]);

        let mut input = Vec::new();
        input.extend_from_slice(&ITIP20::transferCall::SELECTOR);
        input.extend_from_slice(&[0u8; 12]);
        input.extend_from_slice(anyone.as_slice());
        input.extend_from_slice(&[0u8; 32]);

        assert!(r.is_call_allowed(&token, &input));
    }

    #[test]
    fn test_remove_allowed_calls_encodes_correctly() {
        let key_id = address!("0x1111111111111111111111111111111111111111");
        let target = address!("0x2222222222222222222222222222222222222222");
        let call = remove_allowed_calls(key_id, target);

        assert_eq!(call.to, TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        let decoded =
            removeAllowedCallsCall::abi_decode(&call.input).expect("decode removeAllowedCalls");
        assert_eq!(decoded.keyId, key_id);
        assert_eq!(decoded.target, target);
    }
}
