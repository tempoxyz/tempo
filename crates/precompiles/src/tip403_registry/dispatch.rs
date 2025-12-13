use crate::{
    Precompile, fill_precompile_output, input_cost, mutate, mutate_void, unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

use crate::tip403_registry::{ITIP403Registry, TIP403Registry};

impl Precompile for TIP403Registry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address, is_static: bool) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".into())
            })?
            .try_into()
            .unwrap();

        let result = match selector {
            ITIP403Registry::policyIdCounterCall::SELECTOR => {
                view::<ITIP403Registry::policyIdCounterCall>(calldata, |_call| {
                    self.policy_id_counter()
                })
            }
            ITIP403Registry::policyDataCall::SELECTOR => {
                view::<ITIP403Registry::policyDataCall>(calldata, |call| self.policy_data(call))
            }
            ITIP403Registry::isAuthorizedCall::SELECTOR => {
                view::<ITIP403Registry::isAuthorizedCall>(calldata, |call| self.is_authorized(call))
            }
            ITIP403Registry::createPolicyCall::SELECTOR => {
                mutate::<ITIP403Registry::createPolicyCall>(
                    calldata,
                    msg_sender,
                    is_static,
                    |s, call| self.create_policy(s, call),
                )
            }
            ITIP403Registry::createPolicyWithAccountsCall::SELECTOR => {
                mutate::<ITIP403Registry::createPolicyWithAccountsCall>(
                    calldata,
                    msg_sender,
                    is_static,
                    |s, call| self.create_policy_with_accounts(s, call),
                )
            }
            ITIP403Registry::setPolicyAdminCall::SELECTOR => {
                mutate_void::<ITIP403Registry::setPolicyAdminCall>(
                    calldata,
                    msg_sender,
                    is_static,
                    |s, call| self.set_policy_admin(s, call),
                )
            }
            ITIP403Registry::modifyPolicyWhitelistCall::SELECTOR => {
                mutate_void::<ITIP403Registry::modifyPolicyWhitelistCall>(
                    calldata,
                    msg_sender,
                    is_static,
                    |s, call| self.modify_policy_whitelist(s, call),
                )
            }
            ITIP403Registry::modifyPolicyBlacklistCall::SELECTOR => {
                mutate_void::<ITIP403Registry::modifyPolicyBlacklistCall>(
                    calldata,
                    msg_sender,
                    is_static,
                    |s, call| self.modify_policy_blacklist(s, call),
                )
            }
            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|res| fill_precompile_output(res, &mut self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::sol_types::SolValue;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::ITIP403Registry::ITIP403RegistryCalls;

    #[test]
    fn test_is_authorized_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 1 (always allow)
            let call = ITIP403Registry::isAuthorizedCall { policyId: 1, user };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO, false);

            assert!(result.is_ok());
            let output = result.unwrap();
            let decoded: bool =
                ITIP403Registry::isAuthorizedCall::abi_decode_returns(&output.bytes).unwrap();
            assert!(decoded);

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin, false);

            assert!(result.is_ok());
            let output = result.unwrap();
            let decoded: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&output.bytes).unwrap();
            assert_eq!(decoded, 2); // First created policy ID

            Ok(())
        })
    }

    #[test]
    fn test_policy_id_counter_initialization() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Get initial counter
            let counter_call = ITIP403Registry::policyIdCounterCall {};
            let calldata = counter_call.abi_encode();
            let result = registry.call(&calldata, sender, false).unwrap();
            let counter = u64::abi_decode(&result.bytes).unwrap();
            assert_eq!(counter, 2); // Counter starts at 2 (policies 0 and 1 are reserved)

            Ok(())
        })
    }

    #[test]
    fn test_create_policy_with_accounts() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let account1 = Address::random();
        let account2 = Address::random();
        let other_account = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let accounts = vec![account1, account2];
            let call = ITIP403Registry::createPolicyWithAccountsCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
                accounts,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();

            let policy_id: u64 =
                ITIP403Registry::createPolicyWithAccountsCall::abi_decode_returns(&result.bytes)
                    .unwrap();
            assert_eq!(policy_id, 2);

            // Check that accounts are authorized
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account1,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account2,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            // Check that other accounts are not authorized
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: other_account,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            Ok(())
        })
    }

    #[test]
    fn test_blacklist_policy() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let blocked_account = Address::random();
        let allowed_account = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create blacklist policy
            let call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let policy_id: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&result.bytes).unwrap();

            // Initially, all accounts should be authorized (empty blacklist)
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: blocked_account,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            // Add account to blacklist
            let modify_call = ITIP403Registry::modifyPolicyBlacklistCall {
                policyId: policy_id,
                account: blocked_account,
                restricted: true,
            };
            let calldata = modify_call.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            // Now blocked account should not be authorized
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: blocked_account,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            // Other accounts should still be authorized
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: allowed_account,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            // Remove account from blacklist
            let modify_call = ITIP403Registry::modifyPolicyBlacklistCall {
                policyId: policy_id,
                account: blocked_account,
                restricted: false,
            };
            let calldata = modify_call.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            // Account should be authorized again
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: blocked_account,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            Ok(())
        })
    }

    #[test]
    fn test_modify_policy_whitelist() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let account1 = Address::random();
        let account2 = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create whitelist policy
            let call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let policy_id: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&result.bytes).unwrap();

            // Add multiple accounts to whitelist
            let modify_call1 = ITIP403Registry::modifyPolicyWhitelistCall {
                policyId: policy_id,
                account: account1,
                allowed: true,
            };
            let calldata = modify_call1.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            let modify_call2 = ITIP403Registry::modifyPolicyWhitelistCall {
                policyId: policy_id,
                account: account2,
                allowed: true,
            };
            let calldata = modify_call2.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            // Both accounts should be authorized
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account1,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account2,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            // Remove one account from whitelist
            let modify_call = ITIP403Registry::modifyPolicyWhitelistCall {
                policyId: policy_id,
                account: account1,
                allowed: false,
            };
            let calldata = modify_call.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            // Account1 should not be authorized, account2 should still be
            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account1,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            let is_auth_call = ITIP403Registry::isAuthorizedCall {
                policyId: policy_id,
                user: account2,
            };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            Ok(())
        })
    }

    #[test]
    fn test_set_policy_admin() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let new_admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create a policy
            let call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let policy_id: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&result.bytes).unwrap();

            // Get initial policy data
            let policy_data_call = ITIP403Registry::policyDataCall {
                policyId: policy_id,
            };
            let calldata = policy_data_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let policy_data =
                ITIP403Registry::policyDataCall::abi_decode_returns(&result.bytes).unwrap();
            assert_eq!(policy_data.admin, admin);

            // Change policy admin
            let set_admin_call = ITIP403Registry::setPolicyAdminCall {
                policyId: policy_id,
                admin: new_admin,
            };
            let calldata = set_admin_call.abi_encode();
            registry.call(&calldata, admin, false).unwrap();

            // Verify policy admin was changed
            let policy_data_call = ITIP403Registry::policyDataCall {
                policyId: policy_id,
            };
            let calldata = policy_data_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let policy_data =
                ITIP403Registry::policyDataCall::abi_decode_returns(&result.bytes).unwrap();
            assert_eq!(policy_data.admin, new_admin);

            Ok(())
        })
    }

    #[test]
    fn test_special_policy_ids() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 0 (always deny)
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policyId: 0, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            // Test policy 1 (always allow)
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policyId: 1, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO, false).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

            Ok(())
        })
    }

    #[test]
    fn test_invalid_selector() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test with invalid selector - should return Ok with reverted status
            let invalid_data = vec![0x12, 0x34, 0x56, 0x78];
            let result = registry.call(&invalid_data, sender, false);
            assert!(result.is_ok());
            assert!(result.unwrap().reverted);

            // Test with insufficient data
            let short_data = vec![0x12, 0x34];
            let result = registry.call(&short_data, sender, false);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_create_multiple_policies() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Create multiple policies with different types
            let whitelist_call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = whitelist_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let whitelist_id: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&result.bytes).unwrap();

            let blacklist_call = ITIP403Registry::createPolicyCall {
                admin,
                policyType: ITIP403Registry::PolicyType::BLACKLIST,
            };
            let calldata = blacklist_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let blacklist_id: u64 =
                ITIP403Registry::createPolicyCall::abi_decode_returns(&result.bytes).unwrap();

            // Verify IDs are sequential
            assert_eq!(whitelist_id, 2);
            assert_eq!(blacklist_id, 3);

            // Verify counter has been updated
            let counter_call = ITIP403Registry::policyIdCounterCall {};
            let calldata = counter_call.abi_encode();
            let result = registry.call(&calldata, admin, false).unwrap();
            let counter = u64::abi_decode(&result.bytes).unwrap();
            assert_eq!(counter, 4);

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
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
}
