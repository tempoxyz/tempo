use crate::{
    contracts::{
        storage::StorageProvider,
        tip20::TIP20Token,
        types::{IRolesAuth, ITIP20, RolesAuthError, TIP20Error},
    },
    precompiles::{Precompile, metadata, mutate, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: StorageProvider> Precompile for TIP20Token<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .unwrap();

        match selector {
            // Metadata
            ITIP20::nameCall::SELECTOR => metadata::<ITIP20::nameCall>(self.name()),
            ITIP20::symbolCall::SELECTOR => metadata::<ITIP20::symbolCall>(self.symbol()),
            ITIP20::decimalsCall::SELECTOR => metadata::<ITIP20::decimalsCall>(self.decimals()),
            ITIP20::currencyCall::SELECTOR => metadata::<ITIP20::currencyCall>(self.currency()),
            ITIP20::totalSupplyCall::SELECTOR => {
                metadata::<ITIP20::totalSupplyCall>(self.total_supply())
            }
            ITIP20::supplyCapCall::SELECTOR => metadata::<ITIP20::supplyCapCall>(self.supply_cap()),
            ITIP20::transferPolicyIdCall::SELECTOR => {
                metadata::<ITIP20::transferPolicyIdCall>(self.transfer_policy_id())
            }
            ITIP20::pausedCall::SELECTOR => metadata::<ITIP20::pausedCall>(self.paused()),

            // View functions
            ITIP20::balanceOfCall::SELECTOR => {
                view::<ITIP20::balanceOfCall>(calldata, |call| self.balance_of(call))
            }
            ITIP20::allowanceCall::SELECTOR => {
                view::<ITIP20::allowanceCall>(calldata, |call| self.allowance(call))
            }
            ITIP20::noncesCall::SELECTOR => {
                view::<ITIP20::noncesCall>(calldata, |call| self.nonces(call))
            }
            ITIP20::saltsCall::SELECTOR => {
                view::<ITIP20::saltsCall>(calldata, |call| self.salts(call))
            }
            ITIP20::linkingTokenCall::SELECTOR => {
                view::<ITIP20::linkingTokenCall>(calldata, |_| self.linking_token())
            }

            // State changing functions
            ITIP20::transferFromCall::SELECTOR => {
                mutate::<ITIP20::transferFromCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.transfer_from(s, call)
                })
            }
            ITIP20::transferCall::SELECTOR => {
                mutate::<ITIP20::transferCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.transfer(s, call)
                })
            }
            ITIP20::approveCall::SELECTOR => {
                mutate::<ITIP20::approveCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.approve(s, call)
                })
            }
            ITIP20::permitCall::SELECTOR => {
                mutate_void::<ITIP20::permitCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.permit(s, call)
                })
            }
            ITIP20::changeTransferPolicyIdCall::SELECTOR => {
                mutate_void::<ITIP20::changeTransferPolicyIdCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |s, call| self.change_transfer_policy_id(s, call),
                )
            }
            ITIP20::setSupplyCapCall::SELECTOR => {
                mutate_void::<ITIP20::setSupplyCapCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |s, call| self.set_supply_cap(s, call),
                )
            }
            ITIP20::pauseCall::SELECTOR => {
                mutate_void::<ITIP20::pauseCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.pause(s, call)
                })
            }
            ITIP20::unpauseCall::SELECTOR => {
                mutate_void::<ITIP20::unpauseCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.unpause(s, call)
                })
            }
            ITIP20::mintCall::SELECTOR => {
                mutate_void::<ITIP20::mintCall, _>(calldata, msg_sender, |s, call| {
                    self.mint(s, call)
                })
            }
            ITIP20::burnCall::SELECTOR => {
                mutate_void::<ITIP20::burnCall, TIP20Error>(calldata, msg_sender, |s, call| {
                    self.burn(s, call)
                })
            }
            ITIP20::burnBlockedCall::SELECTOR => {
                mutate_void::<ITIP20::burnBlockedCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |s, call| self.burn_blocked(s, call),
                )
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::transferWithMemoCall, TIP20Error>(
                    calldata,
                    msg_sender,
                    |s, call| self.transfer_with_memo(s, call),
                )
            }

            // RolesAuth functions
            IRolesAuth::hasRoleCall::SELECTOR => {
                view::<IRolesAuth::hasRoleCall>(calldata, |call| {
                    self.get_roles_contract().has_role(call)
                })
            }
            IRolesAuth::getRoleAdminCall::SELECTOR => {
                view::<IRolesAuth::getRoleAdminCall>(calldata, |call| {
                    self.get_roles_contract().get_role_admin(call)
                })
            }
            IRolesAuth::grantRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::grantRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |s, call| self.get_roles_contract().grant_role(s, call),
                )
            }
            IRolesAuth::revokeRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::revokeRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |s, call| self.get_roles_contract().revoke_role(s, call),
                )
            }
            IRolesAuth::renounceRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::renounceRoleCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |s, call| self.get_roles_contract().renounce_role(s, call),
                )
            }
            IRolesAuth::setRoleAdminCall::SELECTOR => {
                mutate_void::<IRolesAuth::setRoleAdminCall, RolesAuthError>(
                    calldata,
                    msg_sender,
                    |s, call| self.get_roles_contract().set_role_admin(s, call),
                )
            }

            _ => Err(PrecompileError::Other(
                "Unknown function selector".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        LINKING_USD_ADDRESS,
        contracts::{
            HashMapStorageProvider,
            types::{IRolesAuth, TIP20Error},
        },
        precompiles::{METADATA_GAS, MUTATE_FUNC_GAS, VIEW_FUNC_GAS, expect_precompile_error},
    };
    use alloy::{
        primitives::{Bytes, U256, keccak256},
        sol_types::SolValue,
    };

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
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
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
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

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
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to sender
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
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
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

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
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
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
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

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

    #[test]
    fn test_approve_and_transfer_from() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let approve_amount = U256::from(500);
        let transfer_amount = U256::from(300);
        let initial_owner_balance = U256::from(1000);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        let issuer_role = keccak256(b"ISSUER_ROLE");
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

        // Mint initial balance to owner
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: owner,
                    amount: initial_owner_balance,
                },
            )
            .unwrap();

        // Owner approves spender
        let approve_call = ITIP20::approveCall {
            spender,
            amount: approve_amount,
        };
        let calldata = approve_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &owner).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Check allowance
        let allowance = token.allowance(ITIP20::allowanceCall { owner, spender });
        assert_eq!(allowance, approve_amount);

        // Spender transfers from owner to recipient
        let transfer_from_call = ITIP20::transferFromCall {
            from: owner,
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_from_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &spender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: owner }),
            initial_owner_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            transfer_amount
        );

        // Verify allowance was reduced
        let remaining_allowance = token.allowance(ITIP20::allowanceCall { owner, spender });
        assert_eq!(remaining_allowance, approve_amount - transfer_amount);
    }

    #[test]
    fn test_pause_and_unpause() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let pauser = Address::from([1u8; 20]);
        let unpauser = Address::from([2u8; 20]);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant PAUSE_ROLE to pauser and UNPAUSE_ROLE to unpauser
        use alloy::primitives::keccak256;
        let pause_role = keccak256(b"PAUSE_ROLE");
        let unpause_role = keccak256(b"UNPAUSE_ROLE");

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: pause_role,
                    account: pauser,
                },
            )
            .unwrap();

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: unpause_role,
                    account: unpauser,
                },
            )
            .unwrap();

        // Verify initial state (not paused)
        assert!(!token.paused());

        // Pause the token
        let pause_call = ITIP20::pauseCall {};
        let calldata = pause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &pauser).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token is paused
        assert!(token.paused());

        // Unpause the token
        let unpause_call = ITIP20::unpauseCall {};
        let calldata = unpause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &unpauser).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token is unpaused
        assert!(!token.paused());
    }

    #[test]
    fn test_burn_functionality() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let burner = Address::from([1u8; 20]);
        let initial_balance = U256::from(1000);
        let burn_amount = U256::from(300);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin and burner
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

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

        token
            .get_roles_contract()
            .grant_role(
                &admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: burner,
                },
            )
            .unwrap();

        // Mint initial balance to burner
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: burner,
                    amount: initial_balance,
                },
            )
            .unwrap();

        // Check initial state
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner }),
            initial_balance
        );
        assert_eq!(token.total_supply(), initial_balance);

        // Burn tokens
        let burn_call = ITIP20::burnCall {
            amount: burn_amount,
        };
        let calldata = burn_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &burner).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify balances and total supply after burn
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner }),
            initial_balance - burn_amount
        );
        assert_eq!(token.total_supply(), initial_balance - burn_amount);
    }

    #[test]
    fn test_metadata_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let caller = Address::from([1u8; 20]);

        // Initialize token
        token
            .initialize("Test Token", "TEST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Test name()
        let name_call = ITIP20::nameCall {};
        let calldata = name_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let name = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(name, "Test Token");

        // Test symbol()
        let symbol_call = ITIP20::symbolCall {};
        let calldata = symbol_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let symbol = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(symbol, "TEST");

        // Test decimals()
        let decimals_call = ITIP20::decimalsCall {};
        let calldata = decimals_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let decimals = ITIP20::decimalsCall::abi_decode_returns(&result.bytes).unwrap();
        assert_eq!(decimals, 6);

        // Test currency()
        let currency_call = ITIP20::currencyCall {};
        let calldata = currency_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let currency = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(currency, "USD");

        // Test totalSupply()
        let total_supply_call = ITIP20::totalSupplyCall {};
        let calldata = total_supply_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &caller).unwrap();
        assert_eq!(result.gas_used, METADATA_GAS);
        let total_supply = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(total_supply, U256::ZERO);
    }

    #[test]
    fn test_supply_cap_enforcement() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let recipient = Address::from([1u8; 20]);
        let supply_cap = U256::from(1000);
        let mint_amount = U256::from(1001);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
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

        // Set supply cap
        let set_cap_call = ITIP20::setSupplyCapCall {
            newSupplyCap: supply_cap,
        };
        let calldata = set_cap_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Try to mint more than supply cap
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin);

        // Should fail due to supply cap
        expect_precompile_error(&result, TIP20Error::supply_cap_exceeded());
    }

    #[test]
    fn test_role_based_access_control() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let user2 = Address::from([2u8; 20]);
        let unauthorized = Address::from([3u8; 20]);

        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Grant a role to user1
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

        let grant_call = IRolesAuth::grantRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = grant_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Check that user1 has the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(has_role);

        // Check that user2 doesn't have the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user2,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(!has_role);

        // Test unauthorized mint (should fail)
        let mint_call = ITIP20::mintCall {
            to: user2,
            amount: U256::from(100),
        };
        let calldata = mint_call.abi_encode();
        let result = token.call(&Bytes::from(calldata.clone()), &unauthorized);
        expect_precompile_error(&result, TIP20Error::policy_forbids());

        // Test authorized mint (should succeed)
        let result = token.call(&Bytes::from(calldata), &user1).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);
    }

    #[test]
    fn test_transfer_with_memo() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(100);
        let initial_balance = U256::from(500);

        // Initialize and setup
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
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

        // Mint initial balance
        token
            .mint(
                &admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: initial_balance,
                },
            )
            .unwrap();

        // Transfer with memo
        let memo = alloy::primitives::B256::from([1u8; 32]);
        let transfer_call = ITIP20::transferWithMemoCall {
            to: recipient,
            amount: transfer_amount,
            memo,
        };
        let calldata = transfer_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &sender).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender }),
            initial_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient }),
            transfer_amount
        );
    }

    #[test]
    fn test_nonces_and_salts() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let user = Address::from([1u8; 20]);

        // Initialize token
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Test nonces (should start at 0)
        let nonces_call = ITIP20::noncesCall { owner: user };
        let calldata = nonces_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let nonce = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(nonce, U256::ZERO);

        // Test salts (should be false for unused salt)
        let salt = alloy::primitives::FixedBytes::<4>::from([1u8, 2u8, 3u8, 4u8]);
        let salts_call = ITIP20::saltsCall { owner: user, salt };
        let calldata = salts_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let is_used = bool::abi_decode(&result.bytes).unwrap();
        assert!(!is_used);
    }

    #[test]
    fn test_change_transfer_policy_id() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut token = TIP20Token::new(1, &mut storage);
        let admin = Address::from([0u8; 20]);
        let non_admin = Address::from([1u8; 20]);
        let new_policy_id = 42u64;

        // Initialize token
        token
            .initialize("Test", "TST", "USD", LINKING_USD_ADDRESS, &admin)
            .unwrap();

        // Admin can change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall {
            newPolicyId: new_policy_id,
        };
        let calldata = change_policy_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &admin).unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify policy ID was changed
        assert_eq!(token.transfer_policy_id(), new_policy_id);

        // Non-admin cannot change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall { newPolicyId: 100 };
        let calldata = change_policy_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), &non_admin);
        expect_precompile_error(&result, TIP20Error::policy_forbids());
    }
}
