use core::fmt;

use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_sol_types::SolCall;
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    IAccountKeychain::{
        CallScope as AbiCallScope, KeyRestrictions as AbiKeyRestrictions,
        LegacyTokenLimit as AbiLegacyTokenLimit, SelectorRule as AbiSelectorRule,
        SignatureType as AbiSignatureType, TokenLimit as AbiTokenLimit, removeAllowedCallsCall,
        revokeKeyCall, setAllowedCallsCall, updateSpendingLimitCall,
    },
    authorizeKeyCall, legacyAuthorizeKeyCall,
};
use tempo_primitives::{
    SignatureType,
    transaction::{Call, CallScope, SelectorRule, TokenLimit},
};

/// SDK-level access-key restrictions used for AccountKeychain call builders.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountKeyRestrictions {
    /// Unix timestamp when the key expires. `None` means never expires.
    pub expiry: Option<u64>,
    /// Optional token spending limits. `None` means unlimited spending.
    pub limits: Option<Vec<TokenLimit>>,
    /// Optional call scopes. `None` means unrestricted calls.
    pub allowed_calls: Option<Vec<CallScope>>,
}

impl AccountKeyRestrictions {
    /// Create a new set of account-key restrictions.
    pub fn new(
        expiry: Option<u64>,
        limits: Option<Vec<TokenLimit>>,
        allowed_calls: Option<Vec<CallScope>>,
    ) -> Self {
        Self {
            expiry,
            limits,
            allowed_calls,
        }
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

/// High-level helpers for building AccountKeychain precompile calls from primitive SDK types.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccountKeychainCalls;

impl AccountKeychainCalls {
    /// Build a pre-T3 `authorizeKey` call.
    pub fn authorize_key_legacy(
        key_id: Address,
        signature_type: SignatureType,
        restrictions: AccountKeyRestrictions,
    ) -> Result<Call, KeychainBuildError> {
        if restrictions.has_call_scopes() {
            return Err(KeychainBuildError::LegacyCallScopes);
        }
        if restrictions.has_periodic_limits() {
            return Err(KeychainBuildError::LegacyPeriodicLimits);
        }

        let AccountKeyRestrictions {
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

        Ok(account_keychain_call(
            legacyAuthorizeKeyCall {
                keyId: key_id,
                signatureType: AbiSignatureType::try_from(signature_type as u8)
                    .expect("primitive and ABI SignatureType share the same discriminants"),
                expiry: expiry.unwrap_or(u64::MAX),
                enforceLimits: enforce_limits,
                limits,
            }
            .abi_encode(),
        ))
    }

    /// Build a `authorizeKey(address,uint8,KeyRestrictions)` precompile call (T3+).
    pub fn authorize_key(
        key_id: Address,
        signature_type: SignatureType,
        restrictions: AccountKeyRestrictions,
    ) -> Call {
        account_keychain_call(
            authorizeKeyCall {
                keyId: key_id,
                signatureType: AbiSignatureType::try_from(signature_type as u8)
                    .expect("primitive and ABI SignatureType share the same discriminants"),
                config: to_abi_key_restrictions(restrictions),
            }
            .abi_encode(),
        )
    }

    /// Build a `revokeKey(address)` precompile call.
    pub fn revoke_key(key_id: Address) -> Call {
        account_keychain_call(
            revokeKeyCall { keyId: key_id }
                .abi_encode(),
        )
    }

    /// Build an `updateSpendingLimit(address,address,uint256)` precompile call.
    pub fn update_spending_limit(key_id: Address, token: Address, new_limit: U256) -> Call {
        account_keychain_call(
            updateSpendingLimitCall {
                keyId: key_id,
                token,
                newLimit: new_limit,
            }
            .abi_encode(),
        )
    }

    /// Build a `setAllowedCalls(address,CallScope[])` precompile call.
    pub fn set_allowed_calls(key_id: Address, scopes: Vec<CallScope>) -> Call {
        account_keychain_call(
            setAllowedCallsCall {
                keyId: key_id,
                scopes: scopes.into_iter().map(abi_call_scope).collect(),
            }
            .abi_encode(),
        )
    }

    /// Build a `removeAllowedCalls(address,address)` precompile call.
    pub fn remove_allowed_calls(key_id: Address, target: Address) -> Call {
        account_keychain_call(
            removeAllowedCallsCall {
                keyId: key_id,
                target,
            }
            .abi_encode(),
        )
    }
}

pub(crate) fn to_primitive_call_scopes(scopes: Vec<AbiCallScope>) -> Vec<CallScope> {
    scopes
        .into_iter()
        .map(|scope| CallScope {
            target: scope.target,
            selector_rules: scope
                .selectorRules
                .into_iter()
                .map(|rule| SelectorRule {
                    selector: rule.selector.into(),
                    recipients: rule.recipients,
                })
                .collect(),
        })
        .collect()
}

fn to_abi_key_restrictions(restrictions: AccountKeyRestrictions) -> AbiKeyRestrictions {
    let AccountKeyRestrictions {
        expiry,
        limits,
        allowed_calls,
    } = restrictions;

    AbiKeyRestrictions {
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
            .map(abi_call_scope)
            .collect(),
    }
}

fn abi_call_scope(scope: CallScope) -> AbiCallScope {
    AbiCallScope {
        target: scope.target,
        selectorRules: scope
            .selector_rules
            .into_iter()
            .map(|rule| AbiSelectorRule {
                selector: rule.selector.into(),
                recipients: rule.recipients,
            })
            .collect(),
    }
}

fn account_keychain_call(input: Vec<u8>) -> Call {
    Call {
        to: TxKind::Call(ACCOUNT_KEYCHAIN_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, uint};

    #[test]
    fn test_authorize_key_t3_defaults_to_unrestricted_never_expiring() {
        let call = AccountKeychainCalls::authorize_key(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            AccountKeyRestrictions::default(),
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
        let restrictions = AccountKeyRestrictions::new(
            Some(123),
            Some(vec![TokenLimit {
                token: address!("0x20c0000000000000000000000000000000000001"),
                limit: uint!(42_U256),
                period: 60,
            }]),
            Some(vec![CallScope {
                target: address!("0x20c0000000000000000000000000000000000002"),
                selector_rules: vec![SelectorRule {
                    selector: [0xaa, 0xbb, 0xcc, 0xdd],
                    recipients: vec![address!("0x3333333333333333333333333333333333333333")],
                }],
            }]),
        );

        let call = AccountKeychainCalls::authorize_key(
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
        let scoped = AccountKeychainCalls::authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            AccountKeyRestrictions::new(None, None, Some(vec![])),
        )
        .expect_err("legacy ABI should reject call scopes");
        assert_eq!(scoped, KeychainBuildError::LegacyCallScopes);

        let periodic = AccountKeychainCalls::authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::Secp256k1,
            AccountKeyRestrictions::new(
                None,
                Some(vec![TokenLimit {
                    token: address!("0x20c0000000000000000000000000000000000001"),
                    limit: U256::from(1),
                    period: 1,
                }]),
                None,
            ),
        )
        .expect_err("legacy ABI should reject periodic limits");
        assert_eq!(periodic, KeychainBuildError::LegacyPeriodicLimits);
    }

    #[test]
    fn test_authorize_key_legacy_flattens_limits() {
        let call = AccountKeychainCalls::authorize_key_legacy(
            address!("0x1111111111111111111111111111111111111111"),
            SignatureType::WebAuthn,
            AccountKeyRestrictions::new(
                Some(999),
                Some(vec![TokenLimit {
                    token: address!("0x20c0000000000000000000000000000000000001"),
                    limit: U256::from(7),
                    period: 0,
                }]),
                None,
            ),
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
    fn test_roundtrip_abi_call_scope_conversion() {
        let scopes = vec![AbiCallScope {
            target: address!("0x20c0000000000000000000000000000000000002"),
            selectorRules: vec![AbiSelectorRule {
                selector: [0x12, 0x34, 0x56, 0x78].into(),
                recipients: vec![address!("0x3333333333333333333333333333333333333333")],
            }],
        }];

        let primitive = to_primitive_call_scopes(scopes.clone());
        let roundtrip: Vec<AbiCallScope> = primitive.into_iter().map(abi_call_scope).collect();
        assert_eq!(roundtrip, scopes);
    }
}
