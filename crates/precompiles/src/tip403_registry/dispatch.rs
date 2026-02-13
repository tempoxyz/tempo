use crate::{
    Precompile, dispatch_call, input_cost, mutate, mutate_void,
    tip403_registry::{AuthRole, Interface, TIP403Registry, abi::ITIP403Registry},
    unknown_selector, view,
};
use alloy::{
    primitives::Address,
    sol_types::{SolCall, SolInterface},
};
use revm::precompile::{PrecompileError, PrecompileResult};

impl Precompile for TIP403Registry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        use ITIP403Registry::{
            Calls, compoundPolicyDataCall, createCompoundPolicyCall, isAuthorizedMintRecipientCall,
            isAuthorizedRecipientCall, isAuthorizedSenderCall,
        };

        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(calldata, Calls::abi_decode, |call| match call {
            Calls::policyIdCounter(call) => view(call, |_| Interface::policy_id_counter(self)),
            Calls::policyExists(call) => {
                view(call, |c| Interface::policy_exists(self, c.policy_id))
            }
            Calls::policyData(call) => view(call, |c| Interface::policy_data(self, c.policy_id)),
            Calls::isAuthorized(call) => view(call, |c| {
                self.is_authorized_as(c.policy_id, c.user, AuthRole::Transfer)
            }),
            // TIP-1015: T2+ only
            Calls::isAuthorizedSender(call) => {
                if !self.storage.spec().is_t2() {
                    return unknown_selector(
                        isAuthorizedSenderCall::SELECTOR,
                        self.storage.gas_used(),
                    );
                }
                view(call, |c| {
                    self.is_authorized_as(c.policy_id, c.user, AuthRole::Sender)
                })
            }
            Calls::isAuthorizedRecipient(call) => {
                if !self.storage.spec().is_t2() {
                    return unknown_selector(
                        isAuthorizedRecipientCall::SELECTOR,
                        self.storage.gas_used(),
                    );
                }
                view(call, |c| {
                    self.is_authorized_as(c.policy_id, c.user, AuthRole::Recipient)
                })
            }
            Calls::isAuthorizedMintRecipient(call) => {
                if !self.storage.spec().is_t2() {
                    return unknown_selector(
                        isAuthorizedMintRecipientCall::SELECTOR,
                        self.storage.gas_used(),
                    );
                }
                view(call, |c| {
                    self.is_authorized_as(c.policy_id, c.user, AuthRole::MintRecipient)
                })
            }
            Calls::compoundPolicyData(call) => {
                if !self.storage.spec().is_t2() {
                    return unknown_selector(
                        compoundPolicyDataCall::SELECTOR,
                        self.storage.gas_used(),
                    );
                }
                view(call, |c| Interface::compound_policy_data(self, c.policy_id))
            }
            Calls::createPolicy(call) => mutate(call, msg_sender, |s, c| {
                Interface::create_policy(self, s, c.admin, c.policy_type)
            }),
            Calls::createPolicyWithAccounts(call) => mutate(call, msg_sender, |s, c| {
                Interface::create_policy_with_accounts(self, s, c.admin, c.policy_type, c.accounts)
            }),
            Calls::setPolicyAdmin(call) => mutate_void(call, msg_sender, |s, c| {
                Interface::set_policy_admin(self, s, c.policy_id, c.admin)
            }),
            Calls::modifyPolicyWhitelist(call) => mutate_void(call, msg_sender, |s, c| {
                Interface::modify_policy_whitelist(self, s, c.policy_id, c.account, c.allowed)
            }),
            Calls::modifyPolicyBlacklist(call) => mutate_void(call, msg_sender, |s, c| {
                Interface::modify_policy_blacklist(self, s, c.policy_id, c.account, c.restricted)
            }),
            // TIP-1015: T2+ only
            Calls::createCompoundPolicy(call) => {
                if !self.storage.spec().is_t2() {
                    return unknown_selector(
                        createCompoundPolicyCall::SELECTOR,
                        self.storage.gas_used(),
                    );
                }
                mutate(call, msg_sender, |s, c| {
                    Interface::create_compound_policy(
                        self,
                        s,
                        c.sender_policy_id,
                        c.recipient_policy_id,
                        c.mint_recipient_policy_id,
                    )
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
        tip403_registry::ITIP403Registry,
    };
    use alloy::sol_types::{SolCall, SolValue};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_is_authorized_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            // Test policy 1 (always allow)
            let call = ITIP403Registry::isAuthorizedCall { policy_id: 1, user };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO);

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
                policy_type: ITIP403Registry::PolicyType::WHITELIST,
            };
            let calldata = call.abi_encode();
            let result = registry.call(&calldata, admin);

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
            let result = registry.call(&calldata, sender).unwrap();
            let counter = u64::abi_decode(&result.bytes).unwrap();
            assert_eq!(counter, 2); // Counter starts at 2 (policies 0 and 1 are reserved)

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
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policy_id: 0, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(!is_authorized);

            // Test policy 1 (always allow)
            let is_auth_call = ITIP403Registry::isAuthorizedCall { policy_id: 1, user };
            let calldata = is_auth_call.abi_encode();
            let result = registry.call(&calldata, Address::ZERO).unwrap();
            let is_authorized = bool::abi_decode(&result.bytes).unwrap();
            assert!(is_authorized);

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

            let invalid_data = vec![0x12, 0x34, 0x56, 0x78];
            let result = registry.call(&invalid_data, sender)?;
            assert!(result.reverted);

            // T1: insufficient data also returns reverted output
            let short_data = vec![0x12, 0x34];
            let result = registry.call(&short_data, sender)?;
            assert!(result.reverted);

            Ok(())
        })?;

        // Pre-T1 (T0): insufficient data returns error
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T0);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let short_data = vec![0x12, 0x34];
            let result = registry.call(&short_data, sender);
            assert!(result.is_err());

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        use ITIP403Registry::Calls;

        // Use T2 to test all selectors including TIP-1015 compound policy functions
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        StorageCtx::enter(&mut storage, || {
            let mut registry = TIP403Registry::new();

            let unsupported = check_selector_coverage(
                &mut registry,
                Calls::SELECTORS,
                "ITIP403Registry",
                Calls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
