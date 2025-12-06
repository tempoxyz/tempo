use super::ITIP20;
use crate::{
    Precompile, fill_precompile_output, input_cost, metadata, mutate, mutate_void,
    storage::PrecompileStorageProvider,
    tip20::{IRolesAuth, TIP20Token},
    unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: PrecompileStorageProvider> Precompile for TIP20Token<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
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
            // Metadata
            ITIP20::nameCall::SELECTOR => metadata::<ITIP20::nameCall>(|| self.name()),
            ITIP20::symbolCall::SELECTOR => metadata::<ITIP20::symbolCall>(|| self.symbol()),
            ITIP20::decimalsCall::SELECTOR => metadata::<ITIP20::decimalsCall>(|| self.decimals()),
            ITIP20::currencyCall::SELECTOR => metadata::<ITIP20::currencyCall>(|| self.currency()),
            ITIP20::totalSupplyCall::SELECTOR => {
                metadata::<ITIP20::totalSupplyCall>(|| self.total_supply())
            }
            ITIP20::supplyCapCall::SELECTOR => {
                metadata::<ITIP20::supplyCapCall>(|| self.supply_cap())
            }
            ITIP20::transferPolicyIdCall::SELECTOR => {
                metadata::<ITIP20::transferPolicyIdCall>(|| self.transfer_policy_id())
            }
            ITIP20::pausedCall::SELECTOR => metadata::<ITIP20::pausedCall>(|| self.paused()),

            // View functions
            ITIP20::balanceOfCall::SELECTOR => {
                view::<ITIP20::balanceOfCall>(calldata, |call| self.balance_of(call))
            }
            ITIP20::allowanceCall::SELECTOR => {
                view::<ITIP20::allowanceCall>(calldata, |call| self.allowance(call))
            }
            ITIP20::quoteTokenCall::SELECTOR => {
                view::<ITIP20::quoteTokenCall>(calldata, |_| self.quote_token())
            }
            ITIP20::nextQuoteTokenCall::SELECTOR => {
                view::<ITIP20::nextQuoteTokenCall>(calldata, |_| self.next_quote_token())
            }
            ITIP20::PAUSE_ROLECall::SELECTOR => {
                view::<ITIP20::PAUSE_ROLECall>(calldata, |_| Ok(Self::pause_role()))
            }
            ITIP20::UNPAUSE_ROLECall::SELECTOR => {
                view::<ITIP20::UNPAUSE_ROLECall>(calldata, |_| Ok(Self::unpause_role()))
            }
            ITIP20::ISSUER_ROLECall::SELECTOR => {
                view::<ITIP20::ISSUER_ROLECall>(calldata, |_| Ok(Self::issuer_role()))
            }
            ITIP20::BURN_BLOCKED_ROLECall::SELECTOR => {
                view::<ITIP20::BURN_BLOCKED_ROLECall>(calldata, |_| Ok(Self::burn_blocked_role()))
            }

            // State changing functions
            ITIP20::transferFromCall::SELECTOR => {
                mutate::<ITIP20::transferFromCall>(calldata, msg_sender, |s, call| {
                    self.transfer_from(s, call)
                })
            }
            ITIP20::transferCall::SELECTOR => {
                mutate::<ITIP20::transferCall>(calldata, msg_sender, |s, call| {
                    self.transfer(s, call)
                })
            }
            ITIP20::approveCall::SELECTOR => {
                mutate::<ITIP20::approveCall>(calldata, msg_sender, |s, call| self.approve(s, call))
            }
            ITIP20::changeTransferPolicyIdCall::SELECTOR => {
                mutate_void::<ITIP20::changeTransferPolicyIdCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.change_transfer_policy_id(s, call),
                )
            }
            ITIP20::setSupplyCapCall::SELECTOR => {
                mutate_void::<ITIP20::setSupplyCapCall>(calldata, msg_sender, |s, call| {
                    self.set_supply_cap(s, call)
                })
            }
            ITIP20::pauseCall::SELECTOR => {
                mutate_void::<ITIP20::pauseCall>(calldata, msg_sender, |s, call| {
                    self.pause(s, call)
                })
            }
            ITIP20::unpauseCall::SELECTOR => {
                mutate_void::<ITIP20::unpauseCall>(calldata, msg_sender, |s, call| {
                    self.unpause(s, call)
                })
            }
            ITIP20::setNextQuoteTokenCall::SELECTOR => {
                mutate_void::<ITIP20::setNextQuoteTokenCall>(calldata, msg_sender, |s, call| {
                    self.set_next_quote_token(s, call)
                })
            }
            ITIP20::completeQuoteTokenUpdateCall::SELECTOR => {
                mutate_void::<ITIP20::completeQuoteTokenUpdateCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.complete_quote_token_update(s, call),
                )
            }

            ITIP20::feeRecipientCall::SELECTOR => {
                if !self.storage.spec().is_allegretto() {
                    return unknown_selector(
                        selector,
                        self.storage.gas_used(),
                        self.storage.spec(),
                    );
                }
                view::<ITIP20::feeRecipientCall>(calldata, |_call| self.sload_fee_recipient())
            }
            ITIP20::setFeeRecipientCall::SELECTOR => {
                if !self.storage.spec().is_allegretto() {
                    return unknown_selector(
                        selector,
                        self.storage.gas_used(),
                        self.storage.spec(),
                    );
                }
                mutate_void::<ITIP20::setFeeRecipientCall>(calldata, msg_sender, |s, call| {
                    self.set_fee_recipient(s, call.newRecipient)
                })
            }

            ITIP20::mintCall::SELECTOR => {
                mutate_void::<ITIP20::mintCall>(calldata, msg_sender, |s, call| self.mint(s, call))
            }
            ITIP20::mintWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::mintWithMemoCall>(calldata, msg_sender, |s, call| {
                    self.mint_with_memo(s, call)
                })
            }
            ITIP20::burnCall::SELECTOR => {
                mutate_void::<ITIP20::burnCall>(calldata, msg_sender, |s, call| self.burn(s, call))
            }
            ITIP20::burnWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::burnWithMemoCall>(calldata, msg_sender, |s, call| {
                    self.burn_with_memo(s, call)
                })
            }
            ITIP20::burnBlockedCall::SELECTOR => {
                mutate_void::<ITIP20::burnBlockedCall>(calldata, msg_sender, |s, call| {
                    self.burn_blocked(s, call)
                })
            }
            ITIP20::transferWithMemoCall::SELECTOR => {
                mutate_void::<ITIP20::transferWithMemoCall>(calldata, msg_sender, |s, call| {
                    self.transfer_with_memo(s, call)
                })
            }
            ITIP20::transferFromWithMemoCall::SELECTOR => {
                mutate::<ITIP20::transferFromWithMemoCall>(calldata, msg_sender, |sender, call| {
                    self.transfer_from_with_memo(sender, call)
                })
            }
            ITIP20::startRewardCall::SELECTOR => {
                mutate::<ITIP20::startRewardCall>(calldata, msg_sender, |s, call| {
                    self.start_reward(s, call)
                })
            }
            ITIP20::setRewardRecipientCall::SELECTOR => {
                mutate_void::<ITIP20::setRewardRecipientCall>(calldata, msg_sender, |s, call| {
                    self.set_reward_recipient(s, call)
                })
            }
            ITIP20::cancelRewardCall::SELECTOR => {
                mutate::<ITIP20::cancelRewardCall>(calldata, msg_sender, |s, call| {
                    self.cancel_reward(s, call)
                })
            }
            ITIP20::claimRewardsCall::SELECTOR => {
                mutate::<ITIP20::claimRewardsCall>(calldata, msg_sender, |_, _| {
                    self.claim_rewards(msg_sender)
                })
            }

            ITIP20::finalizeStreamsCall::SELECTOR => {
                mutate_void::<ITIP20::finalizeStreamsCall>(calldata, msg_sender, |sender, call| {
                    self.finalize_streams(sender, call.timestamp as u128)
                })
            }

            ITIP20::totalRewardPerSecondCall::SELECTOR => {
                view::<ITIP20::totalRewardPerSecondCall>(calldata, |_call| {
                    self.get_total_reward_per_second()
                })
            }

            ITIP20::optedInSupplyCall::SELECTOR => {
                view::<ITIP20::optedInSupplyCall>(calldata, |_call| self.get_opted_in_supply())
            }

            ITIP20::getStreamCall::SELECTOR => view::<ITIP20::getStreamCall>(calldata, |call| {
                self.get_stream(call.id).map(|stream| stream.into())
            }),

            ITIP20::nextStreamIdCall::SELECTOR => {
                view::<ITIP20::nextStreamIdCall>(calldata, |_call| self.get_next_stream_id())
            }

            ITIP20::userRewardInfoCall::SELECTOR => {
                view::<ITIP20::userRewardInfoCall>(calldata, |call| {
                    self.get_user_reward_info(call.account)
                        .map(|info| info.into())
                })
            }

            // RolesAuth functions
            IRolesAuth::hasRoleCall::SELECTOR => {
                view::<IRolesAuth::hasRoleCall>(calldata, |call| self.has_role(call))
            }
            IRolesAuth::getRoleAdminCall::SELECTOR => {
                view::<IRolesAuth::getRoleAdminCall>(calldata, |call| self.get_role_admin(call))
            }
            IRolesAuth::grantRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::grantRoleCall>(calldata, msg_sender, |s, call| {
                    self.grant_role(s, call)
                })
            }
            IRolesAuth::revokeRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::revokeRoleCall>(calldata, msg_sender, |s, call| {
                    self.revoke_role(s, call)
                })
            }
            IRolesAuth::renounceRoleCall::SELECTOR => {
                mutate_void::<IRolesAuth::renounceRoleCall>(calldata, msg_sender, |s, call| {
                    self.renounce_role(s, call)
                })
            }
            IRolesAuth::setRoleAdminCall::SELECTOR => {
                mutate_void::<IRolesAuth::setRoleAdminCall>(calldata, msg_sender, |s, call| {
                    self.set_role_admin(s, call)
                })
            }

            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|res| fill_precompile_output(res, self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::hashmap::HashMapStorageProvider,
        tip20::{TIP20Token, tests::initialize_path_usd},
    };
    use alloy::{
        primitives::{Bytes, U256, keccak256},
        sol_types::{SolInterface, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{ITIP20, RolesAuthError, TIP20Error};

    #[test]
    fn test_function_selector_dispatch() {
        use tempo_chainspec::hardfork::TempoHardfork;
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let mut token = TIP20Token::new(1, &mut storage);
        let sender = Address::from([1u8; 20]);

        // Test invalid selector - should return Ok with reverted status
        let result = token.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), sender);
        assert!(result.is_ok());
        assert!(result.unwrap().reverted);

        // Test insufficient calldata
        let result = token.call(&Bytes::from([0x12, 0x34]), sender);
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }
    #[test]
    fn test_balance_of_calldata_handling() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let account = Address::from([2u8; 20]);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
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
                admin,
                ITIP20::mintCall {
                    to: account,
                    amount: test_balance,
                },
            )
            .unwrap();

        // Valid balanceOf call
        let balance_of_call = ITIP20::balanceOfCall { account };
        let calldata = balance_of_call.abi_encode();

        let result = token.call(&Bytes::from(calldata), sender).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);

        // Verify we get the correct balance
        let decoded = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(decoded, test_balance);
    }

    #[test]
    fn test_mint_updates_storage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let mint_amount = U256::from(500);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to sender
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: sender,
                },
            )
            .unwrap();

        // Check initial balance is zero
        let initial_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient })?;
        assert_eq!(initial_balance, U256::ZERO);

        // Create mint call
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();

        // Execute mint
        let result = token.call(&Bytes::from(calldata), sender).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify balance was updated in storage
        let final_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient })?;
        assert_eq!(final_balance, mint_amount);

        Ok(())
    }

    #[test]
    fn test_transfer_updates_balances() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(300);
        let initial_sender_balance = U256::from(1000);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Set up initial balance for sender by minting
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: sender,
                    amount: initial_sender_balance,
                },
            )
            .unwrap();

        // Check initial balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender })?,
            initial_sender_balance
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
            U256::ZERO
        );

        // Create transfer call
        let transfer_call = ITIP20::transferCall {
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_call.abi_encode();

        // Execute transfer
        let result = token.call(&Bytes::from(calldata), sender).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Decode the return value (should be true)
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances were updated correctly
        let final_sender_balance = token.balance_of(ITIP20::balanceOfCall { account: sender })?;
        let final_recipient_balance =
            token.balance_of(ITIP20::balanceOfCall { account: recipient })?;

        assert_eq!(
            final_sender_balance,
            initial_sender_balance - transfer_amount
        );
        assert_eq!(final_recipient_balance, transfer_amount);

        Ok(())
    }

    #[test]
    fn test_approve_and_transfer_from() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let approve_amount = U256::from(500);
        let transfer_amount = U256::from(300);
        let initial_owner_balance = U256::from(1000);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint initial balance to owner
        token
            .mint(
                admin,
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
        let result = token.call(&Bytes::from(calldata), owner).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Check allowance
        let allowance = token.allowance(ITIP20::allowanceCall { owner, spender })?;
        assert_eq!(allowance, approve_amount);

        // Spender transfers from owner to recipient
        let transfer_from_call = ITIP20::transferFromCall {
            from: owner,
            to: recipient,
            amount: transfer_amount,
        };
        let calldata = transfer_from_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), spender).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);
        let success = bool::abi_decode(&result.bytes).unwrap();
        assert!(success);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: owner })?,
            initial_owner_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
            transfer_amount
        );

        // Verify allowance was reduced
        let remaining_allowance = token.allowance(ITIP20::allowanceCall { owner, spender })?;
        assert_eq!(remaining_allowance, approve_amount - transfer_amount);

        Ok(())
    }

    #[test]
    fn test_pause_and_unpause() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let pauser = Address::from([1u8; 20]);
        let unpauser = Address::from([2u8; 20]);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant PAUSE_ROLE to pauser and UNPAUSE_ROLE to unpauser
        use alloy::primitives::keccak256;
        let pause_role = keccak256(b"PAUSE_ROLE");
        let unpause_role = keccak256(b"UNPAUSE_ROLE");

        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: pause_role,
                    account: pauser,
                },
            )
            .unwrap();

        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: unpause_role,
                    account: unpauser,
                },
            )
            .unwrap();

        // Verify initial state (not paused)
        assert!(!token.paused()?);

        // Pause the token
        let pause_call = ITIP20::pauseCall {};
        let calldata = pause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), pauser).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify token is paused
        assert!(token.paused()?);

        // Unpause the token
        let unpause_call = ITIP20::unpauseCall {};
        let calldata = unpause_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), unpauser).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify token is unpaused
        assert!(!token.paused()?);

        Ok(())
    }

    #[test]
    fn test_burn_functionality() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let burner = Address::from([1u8; 20]);
        let initial_balance = U256::from(1000);
        let burn_amount = U256::from(300);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to admin and burner
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: burner,
                },
            )
            .unwrap();

        // Mint initial balance to burner
        token
            .mint(
                admin,
                ITIP20::mintCall {
                    to: burner,
                    amount: initial_balance,
                },
            )
            .unwrap();

        // Check initial state
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner })?,
            initial_balance
        );
        assert_eq!(token.total_supply()?, initial_balance);

        // Burn tokens
        let burn_call = ITIP20::burnCall {
            amount: burn_amount,
        };
        let calldata = burn_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), burner).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify balances and total supply after burn
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: burner })?,
            initial_balance - burn_amount
        );
        assert_eq!(token.total_supply()?, initial_balance - burn_amount);

        Ok(())
    }

    #[test]
    fn test_metadata_functions() {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let caller = Address::from([1u8; 20]);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token
        token
            .initialize(
                "Test Token",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        // Test name()
        let name_call = ITIP20::nameCall {};
        let calldata = name_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), caller).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let name = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(name, "Test Token");

        // Test symbol()
        let symbol_call = ITIP20::symbolCall {};
        let calldata = symbol_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), caller).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let symbol = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(symbol, "TEST");

        // Test decimals()
        let decimals_call = ITIP20::decimalsCall {};
        let calldata = decimals_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), caller).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let decimals = ITIP20::decimalsCall::abi_decode_returns(&result.bytes).unwrap();
        assert_eq!(decimals, 6);

        // Test currency()
        let currency_call = ITIP20::currencyCall {};
        let calldata = currency_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), caller).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let currency = String::abi_decode(&result.bytes).unwrap();
        assert_eq!(currency, "USD");

        // Test totalSupply()
        let total_supply_call = ITIP20::totalSupplyCall {};
        let calldata = total_supply_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), caller).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let total_supply = U256::abi_decode(&result.bytes).unwrap();
        assert_eq!(total_supply, U256::ZERO);
    }

    #[test]
    fn test_supply_cap_enforcement() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let recipient = Address::from([1u8; 20]);
        let supply_cap = U256::from(1000);
        let mint_amount = U256::from(1001);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant ISSUER_ROLE to admin
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
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
        let result = token.call(&Bytes::from(calldata), admin).unwrap();

        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Try to mint more than supply cap
        let mint_call = ITIP20::mintCall {
            to: recipient,
            amount: mint_amount,
        };
        let calldata = mint_call.abi_encode();
        let output = token.call(&Bytes::from(calldata), admin)?;
        assert!(output.reverted);

        let expected: Bytes = TIP20Error::supply_cap_exceeded().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn test_role_based_access_control() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let user1 = Address::from([1u8; 20]);
        let user2 = Address::from([2u8; 20]);
        let unauthorized = Address::from([3u8; 20]);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token with admin
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Grant a role to user1
        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");

        let grant_call = IRolesAuth::grantRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = grant_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Check that user1 has the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user1,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin).unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(has_role);

        // Check that user2 doesn't have the role
        let has_role_call = IRolesAuth::hasRoleCall {
            role: issuer_role,
            account: user2,
        };
        let calldata = has_role_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin).unwrap();
        let has_role = bool::abi_decode(&result.bytes).unwrap();
        assert!(!has_role);

        // Test unauthorized mint (should fail)
        let mint_call = ITIP20::mintCall {
            to: user2,
            amount: U256::from(100),
        };
        let calldata = mint_call.abi_encode();
        let output = token.call(&Bytes::from(calldata.clone()), unauthorized)?;
        assert!(output.reverted);
        let expected: Bytes = RolesAuthError::unauthorized().selector().into();
        assert_eq!(output.bytes, expected);

        // Test authorized mint (should succeed)
        let result = token.call(&Bytes::from(calldata), user1).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        Ok(())
    }

    #[test]
    fn test_transfer_with_memo() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let sender = Address::from([1u8; 20]);
        let recipient = Address::from([2u8; 20]);
        let transfer_amount = U256::from(100);
        let initial_balance = U256::from(500);

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize and setup
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        use alloy::primitives::keccak256;
        let issuer_role = keccak256(b"ISSUER_ROLE");
        token
            .grant_role(
                admin,
                IRolesAuth::grantRoleCall {
                    role: issuer_role,
                    account: admin,
                },
            )
            .unwrap();

        // Mint initial balance
        token
            .mint(
                admin,
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
        let result = token.call(&Bytes::from(calldata), sender).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify balances
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: sender })?,
            initial_balance - transfer_amount
        );
        assert_eq!(
            token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
            transfer_amount
        );

        Ok(())
    }

    #[test]
    fn test_change_transfer_policy_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::from([0u8; 20]);
        let non_admin = Address::from([1u8; 20]);
        let new_policy_id = 42u64;

        initialize_path_usd(&mut storage, admin).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        // Initialize token
        token
            .initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, Address::ZERO)
            .unwrap();

        // Admin can change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall {
            newPolicyId: new_policy_id,
        };
        let calldata = change_policy_call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin).unwrap();
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify policy ID was changed
        assert_eq!(token.transfer_policy_id()?, new_policy_id);

        // Non-admin cannot change transfer policy ID
        let change_policy_call = ITIP20::changeTransferPolicyIdCall { newPolicyId: 100 };
        let calldata = change_policy_call.abi_encode();
        let output = token.call(&Bytes::from(calldata), non_admin)?;
        assert!(output.reverted);
        let expected: Bytes = RolesAuthError::unauthorized().selector().into();
        assert_eq!(output.bytes, expected);

        Ok(())
    }

    #[test]
    fn tip20_test_selector_coverage() {
        use crate::test_util::{assert_full_coverage, check_selector_coverage};
        use tempo_chainspec::hardfork::TempoHardfork;
        use tempo_contracts::precompiles::{IRolesAuth::IRolesAuthCalls, ITIP20::ITIP20Calls};

        // Use allegretto to cover hardfork-gated selectors (feeRecipient, setFeeRecipient)
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);

        initialize_path_usd(&mut storage, Address::ZERO).unwrap();
        let mut token = TIP20Token::new(1, &mut storage);
        token
            .initialize(
                "Test",
                "TST",
                "USD",
                PATH_USD_ADDRESS,
                Address::ZERO,
                Address::ZERO,
            )
            .unwrap();

        let itip20_unsupported =
            check_selector_coverage(&mut token, ITIP20Calls::SELECTORS, "ITIP20", |s| {
                ITIP20Calls::name_by_selector(s)
            });

        let roles_unsupported =
            check_selector_coverage(&mut token, IRolesAuthCalls::SELECTORS, "IRolesAuth", |s| {
                IRolesAuthCalls::name_by_selector(s)
            });

        assert_full_coverage([itip20_unsupported, roles_unsupported]);
    }

    #[test]
    fn test_fee_recipient_pre_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::from([0x01; 20]);
        initialize_path_usd(&mut storage, admin)?;
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize(
            "Test",
            "TST",
            "USD",
            PATH_USD_ADDRESS,
            admin,
            Address::from([0x11; 20]),
        )?;

        let call = ITIP20::feeRecipientCall {};
        let calldata = call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin);

        assert!(matches!(
            result,
            Err(revm::precompile::PrecompileError::Other(ref msg)) if msg.contains("Unknown function selector")
        ));

        Ok(())
    }

    #[test]
    fn test_fee_recipient_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let admin = Address::from([0x01; 20]);
        let fee_recipient = Address::from([0x11; 20]);
        initialize_path_usd(&mut storage, admin)?;
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, fee_recipient)?;

        let call = ITIP20::feeRecipientCall {};
        let calldata = call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin)?;

        assert!(!result.reverted);
        let recipient = ITIP20::feeRecipientCall::abi_decode_returns(&result.bytes)?;
        assert_eq!(recipient, fee_recipient);
        Ok(())
    }

    #[test]
    fn test_set_fee_recipient_pre_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let admin = Address::from([0x01; 20]);
        initialize_path_usd(&mut storage, admin)?;
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, admin)?;

        let call = ITIP20::setFeeRecipientCall {
            newRecipient: Address::from([0x33; 20]),
        };
        let calldata = call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin);

        assert!(matches!(
            result,
            Err(revm::precompile::PrecompileError::Other(ref msg)) if msg.contains("Unknown function selector")
        ));

        Ok(())
    }

    #[test]
    fn test_set_fee_recipient_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);
        let admin = Address::from([0x01; 20]);
        let new_recipient = Address::from([0x33; 20]);
        initialize_path_usd(&mut storage, admin)?;
        let mut token = TIP20Token::new(1, &mut storage);
        token.initialize("Test", "TST", "USD", PATH_USD_ADDRESS, admin, admin)?;

        let call = ITIP20::setFeeRecipientCall {
            newRecipient: new_recipient,
        };
        let calldata = call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin)?;

        assert!(!result.reverted);

        let call = ITIP20::feeRecipientCall {};
        let calldata = call.abi_encode();
        let result = token.call(&Bytes::from(calldata), admin)?;

        let recipient = ITIP20::feeRecipientCall::abi_decode_returns(&result.bytes)?;
        assert_eq!(recipient, new_recipient);

        Ok(())
    }
}
