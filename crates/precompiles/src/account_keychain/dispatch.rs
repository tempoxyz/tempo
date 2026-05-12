//! ABI dispatch for the [`AccountKeychain`] precompile.

use super::{AccountKeychain, KeyRestrictions, TokenLimit, authorizeKeyCall};
use crate::{Precompile, SelectorSchedule, charge_input_cost, dispatch_call, mutate_void, view};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::PrecompileResult;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::{
    AccountKeychainError,
    IAccountKeychain::{self, IAccountKeychainCalls},
};

const T3_ADDED: &[[u8; 4]] = &[
    authorizeKeyCall::SELECTOR,
    IAccountKeychain::setAllowedCallsCall::SELECTOR,
    IAccountKeychain::removeAllowedCallsCall::SELECTOR,
    IAccountKeychain::getRemainingLimitWithPeriodCall::SELECTOR,
    IAccountKeychain::getAllowedCallsCall::SELECTOR,
];
const T3_DROPPED: &[[u8; 4]] = &[IAccountKeychain::getRemainingLimitCall::SELECTOR];

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[SelectorSchedule::new(TempoHardfork::T3)
                .with_added(T3_ADDED)
                .with_dropped(T3_DROPPED)],
            IAccountKeychainCalls::abi_decode,
            |call| match call {
                IAccountKeychainCalls::authorizeKey_0(call) => {
                    if self.storage.spec().is_t3() {
                        return self.storage.error_result(
                            AccountKeychainError::legacy_authorize_key_selector_changed(
                                authorizeKeyCall::SELECTOR,
                            ),
                        );
                    }

                    let call = authorizeKeyCall {
                        keyId: call.keyId,
                        signatureType: call.signatureType,
                        config: KeyRestrictions {
                            expiry: call.expiry,
                            enforceLimits: call.enforceLimits,
                            limits: call
                                .limits
                                .into_iter()
                                .map(|limit| TokenLimit {
                                    token: limit.token,
                                    amount: limit.amount,
                                    period: 0,
                                })
                                .collect(),
                            allowAnyCalls: true,
                            allowedCalls: vec![],
                        },
                    };

                    mutate_void(call, msg_sender, |sender, c| self.authorize_key(sender, c))
                }
                IAccountKeychainCalls::authorizeKey_1(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.authorize_key(sender, c))
                }
                IAccountKeychainCalls::revokeKey(call) => {
                    mutate_void(call, msg_sender, |sender, c| self.revoke_key(sender, c))
                }
                IAccountKeychainCalls::updateSpendingLimit(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.update_spending_limit(sender, c)
                    })
                }
                IAccountKeychainCalls::setAllowedCalls(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_calls(sender, c)
                    })
                }
                IAccountKeychainCalls::removeAllowedCalls(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.remove_allowed_calls(sender, c)
                    })
                }
                IAccountKeychainCalls::getKey(call) => view(call, |c| self.get_key(c)),
                IAccountKeychainCalls::getRemainingLimit(call) => {
                    view(call, |c| self.get_remaining_limit(c))
                }
                IAccountKeychainCalls::getRemainingLimitWithPeriod(call) => {
                    view(call, |c| self.get_remaining_limit_with_period(c))
                }
                IAccountKeychainCalls::getAllowedCalls(call) => {
                    view(call, |c| self.get_allowed_calls(c))
                }
                IAccountKeychainCalls::getTransactionKey(call) => {
                    view(call, |c| self.get_transaction_key(c, msg_sender))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile,
        account_keychain::{getRemainingLimitCall, getRemainingLimitWithPeriodCall},
        storage::{Handler, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::U256,
        sol_types::{SolCall, SolError},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{UnknownFunctionSelector, legacyAuthorizeKeyCall};

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = AccountKeychain::new();
            let selectors: Vec<_> = IAccountKeychainCalls::SELECTORS
                .iter()
                .copied()
                .filter(|selector| *selector != getRemainingLimitCall::SELECTOR)
                .collect();

            let unsupported = check_selector_coverage(
                &mut fee_manager,
                &selectors,
                "IAccountKeychain",
                IAccountKeychainCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }

    #[test]
    fn test_legacy_authorize_key_selector_supported_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = legacyAuthorizeKeyCall {
                keyId: key_id,
                signatureType:
                    tempo_contracts::precompiles::IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![
                    tempo_contracts::precompiles::IAccountKeychain::LegacyTokenLimit {
                        token,
                        amount: U256::from(100),
                    },
                ],
            }
            .abi_encode();

            let _ = keychain.call(&calldata, account)?;

            let key = keychain.keys[account][key_id].read()?;
            assert_eq!(key.expiry, u64::MAX);

            let limit_key = AccountKeychain::spending_limit_key(account, key_id);
            let remaining = keychain.spending_limits[limit_key][token].read()?.remaining;
            assert_eq!(remaining, U256::from(100));

            Ok(())
        })
    }

    #[test]
    fn test_new_authorize_key_selector_rejected_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = authorizeKeyCall {
                keyId: Address::random(),
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                config: KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: true,
                    limits: vec![TokenLimit {
                        token: Address::random(),
                        amount: U256::from(100),
                        period: 0,
                    }],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(result.is_revert());

            Ok(())
        })
    }

    #[test]
    fn test_legacy_authorize_key_selector_rejected_post_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        let account = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = legacyAuthorizeKeyCall {
                keyId: Address::random(),
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: false,
                limits: vec![],
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(result.is_revert());
            let decoded =
                IAccountKeychain::LegacyAuthorizeKeySelectorChanged::abi_decode(&result.bytes)?;
            assert_eq!(decoded.newSelector, authorizeKeyCall::SELECTOR);

            Ok(())
        })
    }

    #[test]
    fn test_get_remaining_limit_uses_legacy_return_shape_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let authorize_calldata = legacyAuthorizeKeyCall {
                keyId: key_id,
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![IAccountKeychain::LegacyTokenLimit {
                    token,
                    amount: U256::from(123),
                }],
            }
            .abi_encode();
            let _ = keychain.call(&authorize_calldata, account)?;

            let get_limit_calldata = getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            }
            .abi_encode();

            let output = keychain.call(&get_limit_calldata, account)?;
            assert!(!output.is_revert());
            assert_eq!(
                output.bytes.len(),
                32,
                "pre-T3 should return legacy uint256"
            );

            let remaining = getRemainingLimitCall::abi_decode_returns(&output.bytes)?;
            assert_eq!(remaining, U256::from(123));

            Ok(())
        })
    }

    #[test]
    fn test_get_remaining_limit_with_period_rejected_pre_t3() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1C);
        let account = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = getRemainingLimitWithPeriodCall {
                account,
                keyId: Address::random(),
                token: Address::random(),
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(result.is_revert());

            Ok(())
        })
    }

    #[test]
    fn test_get_remaining_limit_returns_unknown_selector_post_t3() -> eyre::Result<()> {
        let account = Address::random();
        let key_id = Address::random();
        let token = Address::random();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            let calldata = getRemainingLimitCall {
                account,
                keyId: key_id,
                token,
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(
                result.is_revert(),
                "expected revert for dropped selector post-T3"
            );

            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(
                decoded.selector.as_slice(),
                &getRemainingLimitCall::SELECTOR,
            );

            Ok(())
        })
    }

    #[test]
    fn test_t3_selector_with_malformed_data_returns_unknown_selector_error() -> eyre::Result<()> {
        let selector = getRemainingLimitWithPeriodCall::SELECTOR;
        let calldata = selector.to_vec();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();

            let result = keychain.call(&calldata, Address::ZERO)?;
            assert!(result.is_revert(), "expected revert");

            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(decoded.selector.as_slice(), &selector);

            Ok(())
        })
    }
}
