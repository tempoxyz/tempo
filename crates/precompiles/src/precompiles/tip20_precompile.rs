use crate::contracts::{
    storage::StorageProvider,
    tip20::TIP20Token,
    types::{IRolesAuth, ITIP20, RolesAuthError, TIP20Error},
};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

use crate::{dispatch_mutating_call, dispatch_view_call, precompiles::Precompile};

mod gas_costs {
    pub const METADATA: u64 = 50;
    pub const VIEW_FUNCTIONS: u64 = 100;
    pub const STATE_CHANGING_FUNCTIONS: u64 = 1000;
}

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TIP20Token<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector = calldata.get(..4).ok_or_else(|| { PrecompileError::Other("Invalid input: missing function selector".to_string()) })?;

        // Metadata
        dispatch_view_call!(self, selector, ITIP20::nameCall, name, gas_costs::METADATA);
        dispatch_view_call!(self, selector, ITIP20::symbolCall, symbol, gas_costs::METADATA);
        dispatch_view_call!(self, selector, ITIP20::decimalsCall, decimals, gas_costs::METADATA);
        dispatch_view_call!(self, selector, ITIP20::currencyCall, currency, gas_costs::METADATA);
        dispatch_view_call!(self, selector, ITIP20::totalSupplyCall, total_supply, gas_costs::METADATA);

        // View functions
        dispatch_view_call!(self, selector, ITIP20::balanceOfCall, balance_of, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self, selector, ITIP20::allowanceCall, allowance, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self, selector, ITIP20::noncesCall, nonces, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self, selector, ITIP20::saltsCall, salts, calldata, gas_costs::VIEW_FUNCTIONS);

        // State-changing functions (standard token)
        dispatch_mutating_call!(self, selector, ITIP20::transferFromCall, transfer_from, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error, returns);
        dispatch_mutating_call!(self, selector, ITIP20::transferCall, transfer, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error, returns);
        dispatch_mutating_call!(self, selector, ITIP20::approveCall, approve, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error, returns);
        dispatch_mutating_call!(self, selector, ITIP20::permitCall, permit, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);

        // State-changing functions (tip20 specific)
        dispatch_mutating_call!(self, selector, ITIP20::changeTransferPolicyIdCall, change_transfer_policy_id, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::setSupplyCapCall, set_supply_cap, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::pauseCall, pause, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::unpauseCall, unpause, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::mintCall, mint, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::burnCall, burn, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::burnBlockedCall, burn_blocked, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);
        dispatch_mutating_call!(self, selector, ITIP20::transferWithMemoCall, transfer_with_memo, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, TIP20Error);

        // RolesAuth functions
        dispatch_view_call!(self.get_roles_contract(), selector, IRolesAuth::hasRoleCall, has_role, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_view_call!(self.get_roles_contract(), selector, IRolesAuth::getRoleAdminCall, get_role_admin, calldata, gas_costs::VIEW_FUNCTIONS);
        dispatch_mutating_call!(self.get_roles_contract(), selector, IRolesAuth::grantRoleCall, grant_role, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, RolesAuthError);
        dispatch_mutating_call!(self.get_roles_contract(), selector, IRolesAuth::revokeRoleCall, revoke_role, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, RolesAuthError);
        dispatch_mutating_call!(self.get_roles_contract(), selector, IRolesAuth::renounceRoleCall, renounce_role, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, RolesAuthError);
        dispatch_mutating_call!(self.get_roles_contract(), selector, IRolesAuth::setRoleAdminCall, set_role_admin, calldata, msg_sender, gas_costs::STATE_CHANGING_FUNCTIONS, RolesAuthError);

        // If no selector matched, return error
        Err(PrecompileError::Other("Unknown function selector".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::contracts::{HashMapStorageProvider, types::IRolesAuth};
    use alloy::{primitives::U256, sol_types::SolValue};
    use alloy_primitives::Bytes;

    use super::*;

    #[test]
    fn test_function_selector_dispatch() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let sender = Address::from([1u8; 20]);

        // Test invalid selector
        let result = token.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));

        // Test insufficient calldata
        let result = token.call(&Bytes::from([0x12, 0x34]), &sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }
    #[test]
    fn test_balance_of_calldata_handling() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let account = Address::from([2u8; 20]);

        // Initialize token with admin
        token.initialize("Test", "TST", 18, "USD", &admin).unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = alloy::primitives::B256::from(keccak256(b"ISSUER_ROLE"));
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint to set the balance first
        let test_balance = U256::from(1000);
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: account,
                    amount: test_balance,
                },
            )
            .unwrap();

        // Valid balanceOf call
        let balance_of_call = ITIP20::balanceOfCall { account };
        let calldata = balance_of_call.abi_encode();

        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, gas_costs::VIEW_FUNCTIONS);

        // Verify we get the correct balance
        let decoded = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(decoded, test_balance);
    }

    #[test]
    fn test_mint_updates_storage() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let mint_amount = U256::from(500);

        // Initialize token with admin
        token.initialize("Test", "TST", 18, "USD", &admin).unwrap();

        // Grant ISSUER_ROLE to sender
        use alloy::primitives::keccak256;
        let issuer_role = alloy::primitives::B256::from(keccak256(b"ISSUER_ROLE"));
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: sender,
                },
            )
            .unwrap();

        // Check initial balance is zero
        let initial_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient });
        assert_eq!(initial_balance, U256::ZERO);

        // Create mint call
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();

        // Execute mint
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, gas_costs::STATE_CHANGING_FUNCTIONS);

        // Verify balance was updated in storage
        let final_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient });
        assert_eq!(final_balance, mint_amount);
    }

    #[test]
    fn test_transfer_updates_balances() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(300);
        let initial_sender_balance = U256::from(1000);

        // Initialize token with admin
        token.initialize("Test", "TST", 18, "USD", &admin).unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = alloy::primitives::B256::from(keccak256(b"ISSUER_ROLE"));
        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Set up initial balance for sender by minting
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: initial_sender_balance,
                },
            )
            .unwrap();

        // Check initial balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender }),
            initial_sender_balance
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            U256::ZERO
        );

        // Create transfer call
        let transfer_call = ITIP20::transferCall {
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_call.abi_encode();

        // Execute transfer
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, gas_costs::STATE_CHANGING_FUNCTIONS);

        // Decode the return value (should be true)
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances were updated correctly
        let final_sender_balance = token.balance_of(ITIP20::balanceOfCall { account: sender });
        let final_recipient_balance =
            token.balance_of(ITIP20::balanceOfCall { account: recipient });

        assert_eq!(
            final_sender_balance,
            initial_sender_balance - transfer_amount
        );
        assert_eq!(final_recipient_balance, transfer_amount);
    }
}
