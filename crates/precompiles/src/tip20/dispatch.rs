use super::ITIP20;
use crate::{
    Precompile, fill_precompile_output, input_cost, metadata, mutate, mutate_void,
    tip20::{IRolesAuth, TIP20Token},
    unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl Precompile for TIP20Token {
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
            ITIP20::distributeRewardCall::SELECTOR => {
                mutate_void::<ITIP20::distributeRewardCall>(calldata, msg_sender, |s, call| {
                    self.distribute_reward(s, call)
                })
            }
            ITIP20::setRewardRecipientCall::SELECTOR => {
                mutate_void::<ITIP20::setRewardRecipientCall>(calldata, msg_sender, |s, call| {
                    self.set_reward_recipient(s, call)
                })
            }
            ITIP20::claimRewardsCall::SELECTOR => {
                mutate::<ITIP20::claimRewardsCall>(calldata, msg_sender, |_, _| {
                    self.claim_rewards(msg_sender)
                })
            }

            ITIP20::optedInSupplyCall::SELECTOR => {
                view::<ITIP20::optedInSupplyCall>(calldata, |_call| self.get_opted_in_supply())
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

            _ => unknown_selector(selector, self.storage.gas_used()),
        };

        result.map(|res| fill_precompile_output(res, &mut self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::StorageCtx,
        test_util::{TIP20Setup, setup_storage},
        tip20::{ISSUER_ROLE, PAUSE_ROLE, UNPAUSE_ROLE},
        tip403_registry::{ITIP403Registry, TIP403Registry},
    };
    use alloy::{
        primitives::{Bytes, U256},
        sol_types::{SolInterface, SolValue},
    };
    use tempo_contracts::precompiles::{RolesAuthError, TIP20Error};

    #[test]
    fn test_function_selector_dispatch() -> eyre::Result<()> {
        let (mut storage, sender) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", sender).apply()?;

            // Test invalid selector - should return Ok with reverted status
            let result = token.call(&Bytes::from([0x12, 0x34, 0x56, 0x78]), sender)?;
            assert!(result.reverted);

            // Test insufficient calldata
            let result = token.call(&Bytes::from([0x12, 0x34]), sender);
            assert!(matches!(result, Err(PrecompileError::Other(_))));

            Ok(())
        })
    }

    #[test]
    fn test_balance_of_calldata_handling() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let sender = Address::random();
        let account = Address::random();
        let test_balance = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(account, test_balance)
                .apply()?;

            let balance_of_call = ITIP20::balanceOfCall { account };
            let calldata = balance_of_call.abi_encode();

            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let decoded = U256::abi_decode(&result.bytes)?;
            assert_eq!(decoded, test_balance);

            Ok(())
        })
    }

    #[test]
    fn test_mint_updates_storage() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let sender = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;

            let initial_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient })?;
            assert_eq!(initial_balance, U256::ZERO);

            let mint_amount = U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?;
            let mint_call = ITIP20::mintCall {
                to: recipient,
                amount: mint_amount,
            };
            let calldata = mint_call.abi_encode();

            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let final_balance = token.balance_of(ITIP20::balanceOfCall { account: recipient })?;
            assert_eq!(final_balance, mint_amount);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_updates_balances() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let sender = Address::random();
        let recipient = Address::random();
        let transfer_amount = U256::from(300);
        let initial_sender_balance = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, initial_sender_balance)
                .apply()?;

            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: sender })?,
                initial_sender_balance
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
                U256::ZERO
            );

            let transfer_call = ITIP20::transferCall {
                to: recipient,
                amount: transfer_amount,
            };
            let calldata = transfer_call.abi_encode();
            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let success = bool::abi_decode(&result.bytes)?;
            assert!(success);

            let final_sender_balance =
                token.balance_of(ITIP20::balanceOfCall { account: sender })?;
            let final_recipient_balance =
                token.balance_of(ITIP20::balanceOfCall { account: recipient })?;

            assert_eq!(
                final_sender_balance,
                initial_sender_balance - transfer_amount
            );
            assert_eq!(final_recipient_balance, transfer_amount);

            Ok(())
        })
    }

    #[test]
    fn test_approve_and_transfer_from() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let owner = Address::random();
        let spender = Address::random();
        let recipient = Address::random();
        let approve_amount = U256::from(500);
        let transfer_amount = U256::from(300);
        let initial_owner_balance = U256::from(1000);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(owner, initial_owner_balance)
                .apply()?;

            let approve_call = ITIP20::approveCall {
                spender,
                amount: approve_amount,
            };
            let calldata = approve_call.abi_encode();
            let result = token.call(&calldata, owner)?;
            assert_eq!(result.gas_used, 0);
            let success = bool::abi_decode(&result.bytes)?;
            assert!(success);

            let allowance = token.allowance(ITIP20::allowanceCall { owner, spender })?;
            assert_eq!(allowance, approve_amount);

            let transfer_from_call = ITIP20::transferFromCall {
                from: owner,
                to: recipient,
                amount: transfer_amount,
            };
            let calldata = transfer_from_call.abi_encode();
            let result = token.call(&calldata, spender)?;
            assert_eq!(result.gas_used, 0);
            let success = bool::abi_decode(&result.bytes)?;
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
        })
    }

    #[test]
    fn test_pause_and_unpause() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let pauser = Address::random();
        let unpauser = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_role(pauser, *PAUSE_ROLE)
                .with_role(unpauser, *UNPAUSE_ROLE)
                .apply()?;
            assert!(!token.paused()?);

            // Pause the token
            let pause_call = ITIP20::pauseCall {};
            let calldata = pause_call.abi_encode();
            let result = token.call(&calldata, pauser)?;
            assert_eq!(result.gas_used, 0);
            assert!(token.paused()?);

            // Unpause the token
            let unpause_call = ITIP20::unpauseCall {};
            let calldata = unpause_call.abi_encode();
            let result = token.call(&calldata, unpauser)?;
            assert_eq!(result.gas_used, 0);
            assert!(!token.paused()?);

            Ok(())
        })
    }

    #[test]
    fn test_burn_functionality() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let burner = Address::random();
        let initial_balance = U256::from(1000);
        let burn_amount = U256::from(300);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_role(burner, *ISSUER_ROLE)
                .with_mint(burner, initial_balance)
                .apply()?;

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
            let result = token.call(&calldata, burner)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: burner })?,
                initial_balance - burn_amount
            );
            assert_eq!(token.total_supply()?, initial_balance - burn_amount);

            Ok(())
        })
    }

    #[test]
    fn test_metadata_functions() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let caller = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test Token", "TEST", admin).apply()?;

            // Test name()
            let name_call = ITIP20::nameCall {};
            let calldata = name_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
            assert_eq!(result.gas_used, 0);
            let name = String::abi_decode(&result.bytes)?;
            assert_eq!(name, "Test Token");

            // Test symbol()
            let symbol_call = ITIP20::symbolCall {};
            let calldata = symbol_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let symbol = String::abi_decode(&result.bytes)?;
            assert_eq!(symbol, "TEST");

            // Test decimals()
            let decimals_call = ITIP20::decimalsCall {};
            let calldata = decimals_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let decimals = ITIP20::decimalsCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decimals, 6);

            // Test currency()
            let currency_call = ITIP20::currencyCall {};
            let calldata = currency_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let currency = String::abi_decode(&result.bytes)?;
            assert_eq!(currency, "USD");

            // Test totalSupply()
            let total_supply_call = ITIP20::totalSupplyCall {};
            let calldata = total_supply_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
            assert_eq!(result.gas_used, 0);
            let total_supply = U256::abi_decode(&result.bytes)?;
            assert_eq!(total_supply, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_supply_cap_enforcement() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let recipient = Address::random();
        let supply_cap = U256::from(1000);
        let mint_amount = U256::from(1001);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .apply()?;

            let set_cap_call = ITIP20::setSupplyCapCall {
                newSupplyCap: supply_cap,
            };
            let calldata = set_cap_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);

            let mint_call = ITIP20::mintCall {
                to: recipient,
                amount: mint_amount,
            };
            let calldata = mint_call.abi_encode();
            let output = token.call(&calldata, admin)?;
            assert!(output.reverted);

            let expected: Bytes = TIP20Error::supply_cap_exceeded().selector().into();
            assert_eq!(output.bytes, expected);

            Ok(())
        })
    }

    #[test]
    fn test_role_based_access_control() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let user1 = Address::random();
        let user2 = Address::random();
        let unauthorized = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_role(user1, *ISSUER_ROLE)
                .apply()?;

            let has_role_call = IRolesAuth::hasRoleCall {
                role: *ISSUER_ROLE,
                account: user1,
            };
            let calldata = has_role_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);
            let has_role = bool::abi_decode(&result.bytes)?;
            assert!(has_role);

            let has_role_call = IRolesAuth::hasRoleCall {
                role: *ISSUER_ROLE,
                account: user2,
            };
            let calldata = has_role_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            let has_role = bool::abi_decode(&result.bytes)?;
            assert!(!has_role);

            let mint_call = ITIP20::mintCall {
                to: user2,
                amount: U256::from(100),
            };
            let calldata = mint_call.abi_encode();
            let output = token.call(&Bytes::from(calldata.clone()), unauthorized)?;
            assert!(output.reverted);
            let expected: Bytes = RolesAuthError::unauthorized().selector().into();
            assert_eq!(output.bytes, expected);

            let result = token.call(&calldata, user1)?;
            assert_eq!(result.gas_used, 0);

            Ok(())
        })
    }

    #[test]
    fn test_transfer_with_memo() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let sender = Address::random();
        let recipient = Address::random();
        let transfer_amount = U256::from(100);
        let initial_balance = U256::from(500);

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(sender, initial_balance)
                .apply()?;

            let memo = alloy::primitives::B256::from([1u8; 32]);
            let transfer_call = ITIP20::transferWithMemoCall {
                to: recipient,
                amount: transfer_amount,
                memo,
            };
            let calldata = transfer_call.abi_encode();
            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: sender })?,
                initial_balance - transfer_amount
            );
            assert_eq!(
                token.balance_of(ITIP20::balanceOfCall { account: recipient })?,
                transfer_amount
            );

            Ok(())
        })
    }

    #[test]
    fn test_change_transfer_policy_id() -> eyre::Result<()> {
        let (mut storage, admin) = setup_storage();
        let non_admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            // Initialize TIP403 registry
            let mut registry = TIP403Registry::new();
            registry.initialize()?;

            // Create a valid policy
            let new_policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::WHITELIST,
                },
            )?;

            let change_policy_call = ITIP20::changeTransferPolicyIdCall {
                newPolicyId: new_policy_id,
            };
            let calldata = change_policy_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(token.transfer_policy_id()?, new_policy_id);

            // Create another valid policy for the unauthorized test
            let another_policy_id = registry.create_policy(
                admin,
                ITIP403Registry::createPolicyCall {
                    admin,
                    policyType: ITIP403Registry::PolicyType::BLACKLIST,
                },
            )?;

            let change_policy_call = ITIP20::changeTransferPolicyIdCall {
                newPolicyId: another_policy_id,
            };
            let calldata = change_policy_call.abi_encode();
            let output = token.call(&calldata, non_admin)?;
            assert!(output.reverted);
            let expected: Bytes = RolesAuthError::unauthorized().selector().into();
            assert_eq!(output.bytes, expected);

            Ok(())
        })
    }

    #[test]
    fn tip20_test_selector_coverage() -> eyre::Result<()> {
        use crate::test_util::{assert_full_coverage, check_selector_coverage};
        use tempo_contracts::precompiles::{IRolesAuth::IRolesAuthCalls, ITIP20::ITIP20Calls};

        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            let itip20_unsupported =
                check_selector_coverage(&mut token, ITIP20Calls::SELECTORS, "ITIP20", |s| {
                    ITIP20Calls::name_by_selector(s)
                });

            let roles_unsupported = check_selector_coverage(
                &mut token,
                IRolesAuthCalls::SELECTORS,
                "IRolesAuth",
                IRolesAuthCalls::name_by_selector,
            );

            assert_full_coverage([itip20_unsupported, roles_unsupported]);
            Ok(())
        })
    }
}
