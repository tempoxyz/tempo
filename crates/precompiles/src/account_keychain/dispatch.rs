//! ABI dispatch for the [`AccountKeychain`] precompile.

use super::{AccountKeychain, KeyRestrictions, TokenLimit, authorizeKeyCall};
use crate::{Precompile, charge_input_cost, dispatch, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::{AccountKeychainError, IAccountKeychain};

impl Precompile for AccountKeychain {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAccountKeychain::IAccountKeychainCalls {
                    #[schedule(until = T11)]
                    authorizeKey_0(call) => {
                        if self.storage.spec().is_t3() {
                            return self.storage.error_result(
                                AccountKeychainError::legacy_authorize_key_selector_changed(
                                    authorizeKeyCall::SELECTOR.into(),
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

                        mutate_void(call, msg_sender, |sender, c| {
                            self.authorize_key(sender, c.keyId, c.signatureType, c.config, None)
                        })
                    },
                    #[schedule(since = T3, until = T11)]
                    authorizeKey_1(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.authorize_key(sender, c.keyId, c.signatureType, c.config, None)
                    }),
                    #[schedule(since = T5, until = T11)]
                    authorizeKey_2(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.authorize_key(sender, c.keyId, c.signatureType, c.config, Some(c.witness))
                    }),
                    #[schedule(since = T6, until = T11)]
                    authorizeAdminKey(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.authorize_admin_key(sender, c.keyId, c.signatureType, Some(c.witness))
                    }),
                    #[schedule(since = T5)]
                    burnKeyAuthorizationWitness(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.burn_key_authorization_witness(sender, c)
                    }),
                    revokeKey(call) => mutate_void(call, msg_sender, |sender, c| self.revoke_key(sender, c)),
                    updateSpendingLimit(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.update_spending_limit(sender, c)
                    }),
                    #[schedule(since = T3, until = T11)]
                    setAllowedCalls_0(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_calls(sender, c)
                    }),
                    #[schedule(since = T11)]
                    setAllowedCalls_1(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.set_allowed_calls_rlp(sender, c)
                    }),
                    #[schedule(since = T3)]
                    removeAllowedCalls(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.remove_allowed_calls(sender, c)
                    }),
                    getKey(call) => view(call, |c| self.get_key(c)),
                    #[schedule(until = T3)]
                    getRemainingLimit(call) => view(call, |c| self.get_remaining_limit(c)),
                    #[schedule(since = T3)]
                    getRemainingLimitWithPeriod(call) => view(call, |c| self.get_remaining_limit_with_period(c)),
                    #[schedule(since = T3)]
                    getAllowedCalls(call) => view(call, |c| self.get_allowed_calls(c)),
                    #[schedule(since = T5)]
                    isKeyAuthorizationWitnessBurned(call) => view(call, |c| self.is_key_authorization_witness_burned(c)),
                    #[schedule(since = T6)]
                    isAdminKey(call) => view(call, |c| self.is_admin_key(c.account, c.keyId)),
                    getTransactionKey(call) => view(call, |c| self.get_transaction_key(c, msg_sender))
                }
            }
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
        primitives::{B256, U256},
        sol_types::{SolCall, SolError},
    };
    use alloy_rlp::Encodable;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IAccountKeychain::IAccountKeychainCalls, UnknownFunctionSelector, legacyAuthorizeKeyCall,
        legacySetAllowedCallsCall, setAllowedCallsCall,
    };
    use tempo_primitives::transaction::{
        CallScope as RlpCallScope, SelectorRule as RlpSelectorRule,
    };

    #[test]
    fn test_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = AccountKeychain::new();
            let selectors: Vec<_> = IAccountKeychainCalls::SELECTORS
                .iter()
                .copied()
                .filter(|selector| *selector != getRemainingLimitCall::SELECTOR)
                .filter(|selector| *selector != setAllowedCallsCall::SELECTOR)
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
    fn test_t11_account_keychain_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            let disabled = [
                legacyAuthorizeKeyCall::SELECTOR,
                authorizeKeyCall::SELECTOR,
                IAccountKeychain::authorizeKey_2Call::SELECTOR,
                IAccountKeychain::authorizeAdminKeyCall::SELECTOR,
                legacySetAllowedCallsCall::SELECTOR,
                getRemainingLimitCall::SELECTOR,
            ];
            let selectors: Vec<_> = IAccountKeychainCalls::SELECTORS
                .iter()
                .copied()
                .filter(|selector| !disabled.contains(selector))
                .collect();

            let unsupported = check_selector_coverage(
                &mut keychain,
                &selectors,
                "IAccountKeychain T11",
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
    fn test_set_allowed_calls_limits_aliased_calldata_memory() -> eyre::Result<()> {
        fn word(value: usize) -> [u8; 32] {
            let mut out = [0_u8; 32];
            out[24..].copy_from_slice(&(value as u64).to_be_bytes());
            out
        }

        /// Builds the aliased calldata from the original Account Keychain decoder regression.
        fn aliased_set_allowed_calls_calldata(width: usize) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend(legacySetAllowedCallsCall::SELECTOR);

            // Function head: account and offset to CallScope[].
            data.extend(word(0));
            data.extend(word(64));

            // Every outer element aliases the same CallScope tail.
            data.extend(word(width));
            for _ in 0..width {
                data.extend(word(width * 32));
            }

            // Shared CallScope: target and offset to SelectorRule[].
            data.extend(word(1));
            data.extend(word(64));

            // Every rule aliases the same SelectorRule tail.
            data.extend(word(width));
            for _ in 0..width {
                data.extend(word(width * 32));
            }

            // Shared SelectorRule: selector and offset to address[].
            let mut selector = [0_u8; 32];
            selector[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            data.extend(selector);
            data.extend(word(64));

            // The only physical recipient array.
            data.extend(word(width));
            for i in 0..width {
                data.extend(word(i + 1));
            }

            assert_eq!(data.len(), 292 + 96 * width);
            data
        }

        let calldata = aliased_set_allowed_calls_calldata(500);
        assert_eq!(calldata.len(), 48_292);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            let output = keychain.call(&calldata, Address::ZERO)?;

            assert!(output.is_revert());
            assert!(output.bytes.is_empty());
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
    fn test_t5_witness_selectors_rejected_pre_t5() -> eyre::Result<()> {
        let account = Address::random();
        let witness = B256::repeat_byte(0x53);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T4);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            for (selector, calldata) in [
                (
                    IAccountKeychain::authorizeKey_2Call::SELECTOR,
                    IAccountKeychain::authorizeKey_2Call {
                        keyId: Address::random(),
                        signatureType: IAccountKeychain::SignatureType::Secp256k1,
                        config: KeyRestrictions {
                            expiry: u64::MAX,
                            enforceLimits: false,
                            limits: vec![],
                            allowAnyCalls: true,
                            allowedCalls: vec![],
                        },
                        witness,
                    }
                    .abi_encode(),
                ),
                (
                    IAccountKeychain::burnKeyAuthorizationWitnessCall::SELECTOR,
                    IAccountKeychain::burnKeyAuthorizationWitnessCall { witness }.abi_encode(),
                ),
                (
                    IAccountKeychain::isKeyAuthorizationWitnessBurnedCall::SELECTOR,
                    IAccountKeychain::isKeyAuthorizationWitnessBurnedCall { account, witness }
                        .abi_encode(),
                ),
            ] {
                let result = keychain.call(&calldata, account)?;
                assert!(result.is_revert(), "expected T5 selector to revert pre-T5");

                let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
                assert_eq!(decoded.selector.as_slice(), &selector);
            }

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

    #[test]
    fn test_t11_direct_authorization_selectors_are_disabled() -> eyre::Result<()> {
        let account = Address::random();
        let key_id = Address::random();
        let witness = B256::random();
        let config = KeyRestrictions {
            expiry: u64::MAX,
            enforceLimits: false,
            limits: vec![],
            allowAnyCalls: true,
            allowedCalls: vec![],
        };
        let calls = [
            legacyAuthorizeKeyCall {
                keyId: key_id,
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                expiry: u64::MAX,
                enforceLimits: false,
                limits: vec![],
            }
            .abi_encode(),
            authorizeKeyCall {
                keyId: key_id,
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                config: config.clone(),
            }
            .abi_encode(),
            IAccountKeychain::authorizeKey_2Call {
                keyId: key_id,
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                config,
                witness,
            }
            .abi_encode(),
            IAccountKeychain::authorizeAdminKeyCall {
                keyId: key_id,
                signatureType: IAccountKeychain::SignatureType::Secp256k1,
                witness,
            }
            .abi_encode(),
        ];

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;

            for calldata in calls {
                let expected: [u8; 4] = calldata[..4].try_into().expect("selector");
                let result = keychain.call(&calldata, account)?;
                let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
                assert_eq!(decoded.selector, expected);
            }
            assert_eq!(keychain.keys[account][key_id].read()?.expiry, 0);

            Ok(())
        })
    }

    #[test]
    fn test_t11_set_allowed_calls_uses_rlp() -> eyre::Result<()> {
        let account = Address::random();
        let key_id = Address::random();
        let target = Address::random();
        let selector = [0xaa, 0xbb, 0xcc, 0xdd];

        let scopes = vec![RlpCallScope {
            target,
            selector_rules: vec![RlpSelectorRule {
                selector,
                recipients: vec![],
            }],
        }];
        let mut encoded_scopes = Vec::new();
        scopes.encode(&mut encoded_scopes);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            keychain.initialize()?;
            keychain.set_transaction_key(Address::ZERO)?;
            keychain.set_tx_origin(account)?;
            keychain.authorize_key(
                account,
                key_id,
                IAccountKeychain::SignatureType::Secp256k1,
                KeyRestrictions {
                    expiry: u64::MAX,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
                None,
            )?;

            let old_calldata = legacySetAllowedCallsCall {
                keyId: key_id,
                scopes: vec![],
            }
            .abi_encode();
            let old_result = keychain.call(&old_calldata, account)?;
            let old_error = UnknownFunctionSelector::abi_decode(&old_result.bytes)?;
            assert_eq!(
                old_error.selector.as_slice(),
                &legacySetAllowedCallsCall::SELECTOR
            );

            let calldata = setAllowedCallsCall {
                keyId: key_id,
                scopes: encoded_scopes.into(),
            }
            .abi_encode();
            let result = keychain.call(&calldata, account)?;
            assert!(!result.is_revert());

            let stored = keychain.get_allowed_calls(IAccountKeychain::getAllowedCallsCall {
                account,
                keyId: key_id,
            })?;
            assert!(stored.isScoped);
            assert_eq!(stored.scopes.len(), 1);
            assert_eq!(stored.scopes[0].target, target);
            assert_eq!(stored.scopes[0].selectorRules[0].selector, selector);

            Ok(())
        })
    }

    #[test]
    fn test_rlp_set_allowed_calls_selector_is_disabled_pre_t11() -> eyre::Result<()> {
        let calldata = setAllowedCallsCall {
            keyId: Address::random(),
            scopes: vec![0xc0].into(),
        }
        .abi_encode();

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T10);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            let result = keychain.call(&calldata, Address::random())?;
            let decoded = UnknownFunctionSelector::abi_decode(&result.bytes)?;
            assert_eq!(decoded.selector.as_slice(), &setAllowedCallsCall::SELECTOR);
            Ok(())
        })
    }

    #[test]
    fn test_t11_set_allowed_calls_rejects_invalid_rlp() -> eyre::Result<()> {
        let key_id = Address::random();
        let mut valid_with_trailing = Vec::new();
        vec![RlpCallScope {
            target: Address::random(),
            selector_rules: vec![],
        }]
        .encode(&mut valid_with_trailing);
        valid_with_trailing.push(0x80);

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T11);
        StorageCtx::enter(&mut storage, || {
            let mut keychain = AccountKeychain::new();
            for scopes in [vec![], vec![0xc0], vec![0x80], valid_with_trailing] {
                let calldata = setAllowedCallsCall {
                    keyId: key_id,
                    scopes: scopes.into(),
                }
                .abi_encode();
                let result = keychain.call(&calldata, Address::random())?;
                IAccountKeychain::InvalidCallScope::abi_decode(&result.bytes)?;
            }
            Ok(())
        })
    }
}
