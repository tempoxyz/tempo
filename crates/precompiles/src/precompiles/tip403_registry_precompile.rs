use crate::{dispatch_mutating_call, dispatch_view_call, precompiles::Precompile};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

use crate::contracts::{
    storage::StorageProvider,
    tip403_registry::TIP403Registry,
    types::{ITIP403Registry, TIP403RegistryError},
};

mod gas_costs {
    pub const VIEW_FUNCTIONS: u64 = 100;
    pub const STATE_CHANGING_FUNCTIONS: u64 = 1000;
}

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TIP403Registry<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector = calldata.get(..4).ok_or_else(|| { PrecompileError::Other("Invalid input: missing function selector".to_string()) })?;

        // View functions
        dispatch_view_call!(self, selector, ITIP403Registry::policyIdCounterCall, policy_id_counter, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self, selector, ITIP403Registry::policyDataCall, policy_data, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self, selector, ITIP403Registry::isAuthorizedCall, is_authorized, calldata, gas_costs::VIEW_FUNCTIONS);

        // State-changing functions
        dispatch_mutating_call!(self, selector, ITIP403Registry::createPolicyCall, create_policy, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP403RegistryError, returns);
        dispatch_mutating_call!(self, selector, ITIP403Registry::createPolicyWithAccountsCall, create_policy_with_accounts, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP403RegistryError, returns);
        dispatch_mutating_call!(self, selector, ITIP403Registry::setPolicyAdminCall, set_policy_admin, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP403RegistryError);
        dispatch_mutating_call!(self, selector, ITIP403Registry::modifyPolicyWhitelistCall, modify_policy_whitelist, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP403RegistryError);
        dispatch_mutating_call!(self, selector, ITIP403Registry::modifyPolicyBlacklistCall, modify_policy_blacklist, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP403RegistryError);

        // If no selector matched, return error
        Err(PrecompileError::Other("Unknown function selector".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::contracts::HashMapStorageProvider;

    use super::*;

    #[test]
    fn test_is_authorized_precompile() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut precompile = TIP403Registry::new(&mut storage);
        let user = Address::from([1u8; 20]);

        // Test policy 1 (always allow)
        let call = ITIP403Registry::isAuthorizedCall { policyId: 1, user };
        let calldata = call.abi_encode();
        let result = precompile.call(&calldata, &Address::ZERO);

        assert!(result.is_ok());
        let output = result.unwrap();
        let decoded: bool =
            ITIP403Registry::isAuthorizedCall::abi_decode_returns(&output.bytes).unwrap();
        assert!(decoded);
    }

    #[test]
    fn test_create_policy_precompile() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut precompile = TIP403Registry::new(&mut storage);
        let admin = Address::from([1u8; 20]);

        let call = ITIP403Registry::createPolicyCall {
            adminPolicyId: 1,
            policyType: ITIP403Registry::PolicyType::WHITELIST,
        };
        let calldata = call.abi_encode();
        let result = precompile.call(&calldata, &admin);

        assert!(result.is_ok());
        let output = result.unwrap();
        let decoded: u64 =
            ITIP403Registry::createPolicyCall::abi_decode_returns(&output.bytes).unwrap();
        assert_eq!(decoded, 2); // First created policy ID
    }
}
