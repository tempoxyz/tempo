//! ABI dispatch for the [`AccountKeychain`] precompile.

use super::{AccountKeychain, KeyRestrictions, TokenLimit, authorizeKeyCall};
use crate::{
    Precompile, dispatch_call, error::TempoPrecompileError, input_cost, mutate_void,
    unknown_selector, view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::{
    AccountKeychainError,
    IAccountKeychain::{IAccountKeychainCalls, removeAllowedCallsCall, setAllowedCallsCall},
};

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            IAccountKeychainCalls::abi_decode,
            |call| match call {
                IAccountKeychainCalls::authorizeKey_0(call) => {
                    if self.storage.spec().is_t3() {
                        return TempoPrecompileError::AccountKeychainError(
                            AccountKeychainError::legacy_authorize_key_selector_changed(
                                authorizeKeyCall::SELECTOR,
                            ),
                        )
                        .into_precompile_result(self.storage.gas_used());
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
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            authorizeKeyCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
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
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            setAllowedCallsCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_calls(sender, c)
                    })
                }
                IAccountKeychainCalls::removeAllowedCalls(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            removeAllowedCallsCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    mutate_void(call, msg_sender, |sender, c| {
                        self.remove_allowed_calls(sender, c)
                    })
                }
                IAccountKeychainCalls::getKey(call) => view(call, |c| self.get_key(c)),
                IAccountKeychainCalls::getRemainingLimit(call) => {
                    if self.storage.spec().is_t3() {
                        return unknown_selector(
                            tempo_contracts::precompiles::IAccountKeychain::getRemainingLimitCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    view(call, |c| self.get_remaining_limit(c))
                }
                IAccountKeychainCalls::getRemainingLimitWithPeriod(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            tempo_contracts::precompiles::getRemainingLimitWithPeriodCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
                    view(call, |c| self.get_remaining_limit_with_period(c))
                }
                IAccountKeychainCalls::getAllowedCalls(call) => {
                    if !self.storage.spec().is_t3() {
                        return unknown_selector(
                            tempo_contracts::precompiles::IAccountKeychain::getAllowedCallsCall::SELECTOR,
                            self.storage.gas_used(),
                        );
                    }
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
    use tempo_contracts::precompiles::legacyAuthorizeKeyCall;

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = AccountKeychain::new();

            let unsupported = check_selector_coverage(
                &mut fee_manager,
                IAccountKeychainCalls::SELECTORS,
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
                signatureType:
                    tempo_contracts::precompiles::IAccountKeychain::SignatureType::Secp256k1,
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
            assert!(result.reverted);

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
                signatureType:
                    tempo_contracts::precompiles::IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: false,
                limits: vec![],
            }
            .abi_encode();

            let result = keychain.call(&calldata, account)?;
            assert!(result.reverted);
            let decoded = tempo_contracts::precompiles::IAccountKeychain::LegacyAuthorizeKeySelectorChanged::abi_decode(&result.bytes)?;
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
                signatureType:
                    tempo_contracts::precompiles::IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: true,
                limits: vec![
                    tempo_contracts::precompiles::IAccountKeychain::LegacyTokenLimit {
                        token,
                        amount: U256::from(123),
                    },
                ],
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
            assert!(!output.reverted);
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
            assert!(result.reverted);

            Ok(())
        })
    }
}
