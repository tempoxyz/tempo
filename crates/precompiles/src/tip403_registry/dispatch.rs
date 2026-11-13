//! ABI dispatch for the [`TIP403Registry`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate,
    tip403_registry::{AuthRole, TIP403Registry},
    view,
};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::ITIP403Registry;

impl Precompile for TIP403Registry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                ITIP403Registry::ITIP403RegistryCalls {
                    policyIdCounter(call) => view(call, |_| self.policy_id_counter()),
                    policyExists(call) => view(call, |c| self.policy_exists(c)),
                    #[schedule(since = T9)]
                    tokenTransferPolicyId(call) => view(call, |c| self.token_transfer_policy_id(c)),
                    policyData(call) => view(call, |c| self.policy_data(c)),
                    isAuthorized(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Transfer)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedSender(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Sender)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedRecipient(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::Recipient)
                    }),
                    #[schedule(since = T2)]
                    isAuthorizedMintRecipient(call) => view(call, |c| {
                        self.is_authorized_as(c.policyId, c.user, AuthRole::MintRecipient)
                    }),
                    #[schedule(since = T2)]
                    compoundPolicyData(call) => view(call, |c| self.compound_policy_data(c)),
                    #[schedule(since = T6)]
                    receivePolicy(call) => view(call, |c| self.receive_policy(c.account)),
                    #[schedule(since = T6)]
                    validateReceivePolicy(call) => view(call, |c| {
                        let blocked_reason = self
                            .validate_receive_policy(c.token, c.sender, c.receiver)?
                            .unwrap_or(ITIP403Registry::BlockedReason::NONE);
                        Ok(ITIP403Registry::validateReceivePolicyReturn {
                            authorized: blocked_reason == ITIP403Registry::BlockedReason::NONE,
                            blockedReason: blocked_reason,
                        })
                    }),
                    #[schedule(since = T6)]
                    setReceivePolicy(call) => mutate(call, msg_sender, |sender, c| self.set_receive_policy(sender, c)),
                    #[schedule(since = T9)]
                    migrateTransferPolicyIds(call) => mutate(call, msg_sender, |_, c| {
                        self.migrate_transfer_policy_ids(c)
                    }),
                    createPolicy(call) => mutate(call, msg_sender, |sender, c| self.create_policy(sender, c)),
                    createPolicyWithAccounts(call) => mutate(call, msg_sender, |sender, c| {
                        self.create_policy_with_accounts(sender, c)
                    }),
                    setPolicyAdmin(call) => mutate(call, msg_sender, |sender, c| self.set_policy_admin(sender, c)),
                    modifyPolicyWhitelist(call) => mutate(call, msg_sender, |sender, c| self.modify_policy_whitelist(sender, c)),
                    modifyPolicyBlacklist(call) => mutate(call, msg_sender, |sender, c| self.modify_policy_blacklist(sender, c)),
                    #[schedule(since = T2)]
                    createCompoundPolicy(call) => mutate(call, msg_sender, |sender, c| self.create_compound_policy(sender, c))
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage, revert_bytes},
        tip403_registry::{ALLOW_ALL_POLICY_ID, ITIP403Registry},
    };
    use alloy::{
        primitives::U256,
        sol_types::{SolCall, SolError, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        ITIP403Registry::ITIP403RegistryCalls, UnknownFunctionSelector,
    };
    use tempo_primitives::test_utils::actors;

    /// Dispatches `call` from `sender`, unwrapping the success and its decoded return value.
    fn dispatch_call<C: SolCall>(
        registry: &mut TIP403Registry,
        sender: Address,
        call: C,
    ) -> C::Return {
        let output = registry.call(&call.abi_encode(), sender).unwrap();
        C::abi_decode_returns(output.bytes()).unwrap()
    }

    #[test]
    fn test_is_authorized_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 1 (always allow)
            assert!(dispatch_call(
                &mut registry,
                Address::ZERO,
                ITIP403Registry::isAuthorizedCall { policyId: 1, user }
            ));

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            );
            assert_eq!(policy_id, 2); // First created policy ID

            Ok(())
        })
    }

    #[test]
    fn test_policy_id_counter_initialization() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Counter starts at 2 (policies 0 and 1 are reserved)
            assert_eq!(
                dispatch_call(
                    &mut registry,
                    sender,
                    ITIP403Registry::policyIdCounterCall {}
                ),
                2
            );

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_with_accounts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, account1, account2, other_account] = actors();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::createPolicyWithAccountsCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                    accounts: vec![account1, account2],
                },
            );
            assert_eq!(policy_id, 2);

            // Listed accounts are authorized, other accounts are not
            for (user, expected) in [(account1, true), (account2, true), (other_account, false)] {
                let call = ITIP403Registry::isAuthorizedCall {
                    policyId: policy_id,
                    user,
                };
                assert_eq!(dispatch_call(&mut registry, admin, call), expected);
            }

            Ok(())
        })
    }

    #[test]
    fn test_blacklist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, blocked_account, allowed_account] = actors();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            );
            let is_authorized = |registry: &mut TIP403Registry, user| {
                dispatch_call(
                    registry,
                    admin,
                    ITIP403Registry::isAuthorizedCall {
                        policyId: policy_id,
                        user,
                    },
                )
            };

            // Initially, all accounts should be authorized (empty blacklist)
            assert!(is_authorized(&mut registry, blocked_account));

            // Blacklisting blocks only that account, and removing it restores access
            for restricted in [true, false] {
                dispatch_call(
                    &mut registry,
                    admin,
                    ITIP403Registry::modifyPolicyBlacklistCall {
                        policyId: policy_id,
                        account: blocked_account,
                        restricted,
                    },
                );
                assert_eq!(is_authorized(&mut registry, blocked_account), !restricted);
                assert!(is_authorized(&mut registry, allowed_account));
            }

            Ok(())
        })
    }

    #[test]
    fn test_modify_policy_whitelist() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, account1, account2] = actors();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            );
            let modify = |registry: &mut TIP403Registry, account, allowed| {
                dispatch_call(
                    registry,
                    admin,
                    ITIP403Registry::modifyPolicyWhitelistCall {
                        policyId: policy_id,
                        account,
                        allowed,
                    },
                );
            };
            let is_authorized = |registry: &mut TIP403Registry, user| {
                dispatch_call(
                    registry,
                    admin,
                    ITIP403Registry::isAuthorizedCall {
                        policyId: policy_id,
                        user,
                    },
                )
            };

            // Add multiple accounts to whitelist
            modify(&mut registry, account1, true);
            modify(&mut registry, account2, true);
            assert!(is_authorized(&mut registry, account1));
            assert!(is_authorized(&mut registry, account2));

            // Remove one account from whitelist
            modify(&mut registry, account1, false);
            assert!(!is_authorized(&mut registry, account1));
            assert!(is_authorized(&mut registry, account2));

            Ok(())
        })
    }

    #[test]
    fn test_set_policy_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let [admin, new_admin] = actors();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let policy_id = dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            );
            let policy_data_call = ITIP403Registry::policyDataCall {
                policyId: policy_id,
            };
            assert_eq!(
                dispatch_call(&mut registry, admin, policy_data_call.clone()).admin,
                admin
            );

            dispatch_call(
                &mut registry,
                admin,
                ITIP403Registry::setPolicyAdminCall {
                    policyId: policy_id,
                    admin: new_admin,
                },
            );
            assert_eq!(
                dispatch_call(&mut registry, admin, policy_data_call).admin,
                new_admin
            );

            Ok(())
        })
    }

    #[test]
    fn test_special_policy_ids() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Policy 0 always denies, policy 1 always allows
            for (policy_id, expected) in [(0, false), (1, true)] {
                let call = ITIP403Registry::isAuthorizedCall {
                    policyId: policy_id,
                    user,
                };
                assert_eq!(dispatch_call(&mut registry, Address::ZERO, call), expected);
            }

            Ok(())
        })
    }

    #[test]
    fn test_invalid_selector() -> eyre::Result<()> {
        let sender = Address::random();

        // T1: invalid selector returns reverted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = TIP403Registry::new();

            let result = registry.call(&[0x12, 0x34, 0x56, 0x78], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Revert(_))));

            // T1: insufficient data also returns reverted output
            let result = registry.call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Revert(_))));

            Ok(())
        })?;

        // Pre-T1 (T0): insufficient data returns halted output
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let result = TIP403Registry::new().call(&[0x12, 0x34], sender);
            assert!(matches!(result, Err(evm2::PrecompileError::Halt(_))));

            Ok(())
        })
    }

    #[test]
    fn test_create_multiple_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Policies of different types get sequential IDs
            for (policy_type, expected_id) in [
                (ITIP403Registry::PolicyType::WHITELIST, 2),
                (ITIP403Registry::PolicyType::BLACKLIST, 3),
            ] {
                let call = ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: policy_type,
                };
                assert_eq!(dispatch_call(&mut registry, admin, call), expected_id);
            }

            // Verify counter has been updated
            assert_eq!(
                dispatch_call(
                    &mut registry,
                    admin,
                    ITIP403Registry::policyIdCounterCall {}
                ),
                4
            );

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        // Use T9 to test all selectors, including TIP-1092 token policy lookups.
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let unsupported = check_selector_coverage(
                &mut registry,
                ITIP403RegistryCalls::SELECTORS,
                "ITIP403Registry",
                ITIP403RegistryCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }

    #[test]
    fn test_receive_policy_selectors_are_t6_gated() -> eyre::Result<()> {
        let account = Address::random();
        let receive_policy = ITIP403Registry::receivePolicyCall { account }.abi_encode();
        let validate_receive_policy = ITIP403Registry::validateReceivePolicyCall {
            token: Address::random(),
            sender: Address::random(),
            receiver: account,
        }
        .abi_encode();
        let set_receive_policy = ITIP403Registry::setReceivePolicyCall {
            senderPolicyId: 1,
            tokenFilterId: 1,
            recoveryAuthority: Address::ZERO,
        }
        .abi_encode();

        for calldata in [
            receive_policy.as_slice(),
            validate_receive_policy.as_slice(),
            set_receive_policy.as_slice(),
        ] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T5);
            StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
                let mut registry = TIP403Registry::new();
                let result = registry.call(calldata, account);
                assert!(UnknownFunctionSelector::abi_decode(revert_bytes(&result)).is_ok());
                Ok(())
            })?;
        }

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T6);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = TIP403Registry::new();
            for calldata in [
                receive_policy.as_slice(),
                validate_receive_policy.as_slice(),
                set_receive_policy.as_slice(),
            ] {
                registry
                    .call(calldata, account)
                    .map_err(|err| eyre::eyre!("{err:?}"))?;
            }
            Ok(())
        })
    }

    #[test]
    fn test_token_transfer_policy_selectors_are_t9_gated() -> eyre::Result<()> {
        let token = Address::random();
        let calls = [
            ITIP403Registry::tokenTransferPolicyIdCall { token }.abi_encode(),
            ITIP403Registry::migrateTransferPolicyIdsCall {
                tokens: vec![token],
            }
            .abi_encode(),
        ];

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T8);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = TIP403Registry::new();
            for calldata in &calls {
                let result = registry.call(calldata, Address::ZERO);
                assert!(UnknownFunctionSelector::abi_decode(revert_bytes(&result)).is_ok());
            }
            Ok(())
        })?;

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut registry = TIP403Registry::new();
            // The lookup selector is active, but an undeployed token is rejected.
            let result = registry.call(&calls[0], Address::ZERO);
            assert!(UnknownFunctionSelector::abi_decode(revert_bytes(&result)).is_err());

            // A registered token returns the binding state and policy ID together.
            let token = TIP20Setup::create("Token", "TKN", Address::random()).apply()?;
            let lookup = ITIP403Registry::tokenTransferPolicyIdCall {
                token: token.address(),
            }
            .abi_encode();
            let result = registry.call(&lookup, Address::ZERO)?;
            let lookup =
                ITIP403Registry::tokenTransferPolicyIdCall::abi_decode_returns(result.bytes())?;
            assert!(lookup.isSet);
            assert_eq!(lookup.policyId, ALLOW_ALL_POLICY_ID);

            // Batch migration recognizes the selector and skips the invalid token.
            let result = registry.call(&calls[1], Address::random())?;
            assert_eq!(U256::abi_decode(result.bytes())?, U256::ZERO);
            Ok(())
        })
    }
}
