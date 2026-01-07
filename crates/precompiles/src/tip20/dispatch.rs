use super::ITIP20;
use crate::{
    Precompile, dispatch_call, error::TempoPrecompileError, input_cost, metadata, mutate,
    mutate_void, tip20::TIP20Token, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::{IRolesAuth::IRolesAuthCalls, ITIP20::ITIP20Calls, TIP20Error};

/// Combined enum for dispatching to either ITIP20 or IRolesAuth
enum TIP20Call {
    TIP20(ITIP20Calls),
    RolesAuth(IRolesAuthCalls),
}

impl TIP20Call {
    fn decode(calldata: &[u8]) -> Result<Self, alloy::sol_types::Error> {
        match ITIP20Calls::abi_decode(calldata) {
            Ok(call) => return Ok(Self::TIP20(call)),
            Err(alloy::sol_types::Error::UnknownSelector { .. }) => {}
            Err(e) => return Err(e),
        }
        IRolesAuthCalls::abi_decode(calldata).map(Self::RolesAuth)
    }
}

impl Precompile for TIP20Token {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        // Ensure that the token is initialized (has bytecode)
        // Note that if the initialization check fails, this is treated as uninitialized
        if !self.is_initialized().unwrap_or(false) {
            return TempoPrecompileError::TIP20(TIP20Error::uninitialized())
                .into_precompile_result(self.storage.gas_used());
        }

        dispatch_call(calldata, TIP20Call::decode, |call| match call {
            // Metadata functions (no calldata decoding needed)
            TIP20Call::TIP20(ITIP20Calls::name(_)) => metadata::<ITIP20::nameCall>(|| self.name()),
            TIP20Call::TIP20(ITIP20Calls::symbol(_)) => {
                metadata::<ITIP20::symbolCall>(|| self.symbol())
            }
            TIP20Call::TIP20(ITIP20Calls::decimals(_)) => {
                metadata::<ITIP20::decimalsCall>(|| self.decimals())
            }
            TIP20Call::TIP20(ITIP20Calls::currency(_)) => {
                metadata::<ITIP20::currencyCall>(|| self.currency())
            }
            TIP20Call::TIP20(ITIP20Calls::totalSupply(_)) => {
                metadata::<ITIP20::totalSupplyCall>(|| self.total_supply())
            }
            TIP20Call::TIP20(ITIP20Calls::supplyCap(_)) => {
                metadata::<ITIP20::supplyCapCall>(|| self.supply_cap())
            }
            TIP20Call::TIP20(ITIP20Calls::transferPolicyId(_)) => {
                metadata::<ITIP20::transferPolicyIdCall>(|| self.transfer_policy_id())
            }
            TIP20Call::TIP20(ITIP20Calls::paused(_)) => {
                metadata::<ITIP20::pausedCall>(|| self.paused())
            }

            // View functions
            TIP20Call::TIP20(ITIP20Calls::balanceOf(call)) => view(call, |c| self.balance_of(c)),
            TIP20Call::TIP20(ITIP20Calls::allowance(call)) => view(call, |c| self.allowance(c)),
            TIP20Call::TIP20(ITIP20Calls::quoteToken(_)) => {
                view(ITIP20::quoteTokenCall {}, |_| self.quote_token())
            }
            TIP20Call::TIP20(ITIP20Calls::nextQuoteToken(_)) => {
                view(ITIP20::nextQuoteTokenCall {}, |_| self.next_quote_token())
            }
            TIP20Call::TIP20(ITIP20Calls::PAUSE_ROLE(_)) => {
                view(ITIP20::PAUSE_ROLECall {}, |_| Ok(Self::pause_role()))
            }
            TIP20Call::TIP20(ITIP20Calls::UNPAUSE_ROLE(_)) => {
                view(ITIP20::UNPAUSE_ROLECall {}, |_| Ok(Self::unpause_role()))
            }
            TIP20Call::TIP20(ITIP20Calls::ISSUER_ROLE(_)) => {
                view(ITIP20::ISSUER_ROLECall {}, |_| Ok(Self::issuer_role()))
            }
            TIP20Call::TIP20(ITIP20Calls::BURN_BLOCKED_ROLE(_)) => {
                view(ITIP20::BURN_BLOCKED_ROLECall {}, |_| {
                    Ok(Self::burn_blocked_role())
                })
            }

            // State changing functions
            TIP20Call::TIP20(ITIP20Calls::transferFrom(call)) => {
                mutate(call, msg_sender, |s, c| self.transfer_from(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::transfer(call)) => {
                mutate(call, msg_sender, |s, c| self.transfer(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::approve(call)) => {
                mutate(call, msg_sender, |s, c| self.approve(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::changeTransferPolicyId(call)) => {
                mutate_void(call, msg_sender, |s, c| {
                    self.change_transfer_policy_id(s, c)
                })
            }
            TIP20Call::TIP20(ITIP20Calls::setSupplyCap(call)) => {
                mutate_void(call, msg_sender, |s, c| self.set_supply_cap(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::pause(call)) => {
                mutate_void(call, msg_sender, |s, c| self.pause(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::unpause(call)) => {
                mutate_void(call, msg_sender, |s, c| self.unpause(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::setNextQuoteToken(call)) => {
                mutate_void(call, msg_sender, |s, c| self.set_next_quote_token(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::completeQuoteTokenUpdate(call)) => {
                mutate_void(call, msg_sender, |s, c| {
                    self.complete_quote_token_update(s, c)
                })
            }
            TIP20Call::TIP20(ITIP20Calls::mint(call)) => {
                mutate_void(call, msg_sender, |s, c| self.mint(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::mintWithMemo(call)) => {
                mutate_void(call, msg_sender, |s, c| self.mint_with_memo(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::burn(call)) => {
                mutate_void(call, msg_sender, |s, c| self.burn(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::burnWithMemo(call)) => {
                mutate_void(call, msg_sender, |s, c| self.burn_with_memo(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::burnBlocked(call)) => {
                mutate_void(call, msg_sender, |s, c| self.burn_blocked(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::transferWithMemo(call)) => {
                mutate_void(call, msg_sender, |s, c| self.transfer_with_memo(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::transferFromWithMemo(call)) => {
                mutate(call, msg_sender, |sender, c| {
                    self.transfer_from_with_memo(sender, c)
                })
            }
            TIP20Call::TIP20(ITIP20Calls::distributeReward(call)) => {
                mutate_void(call, msg_sender, |s, c| self.distribute_reward(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::setRewardRecipient(call)) => {
                mutate_void(call, msg_sender, |s, c| self.set_reward_recipient(s, c))
            }
            TIP20Call::TIP20(ITIP20Calls::claimRewards(_)) => {
                mutate(ITIP20::claimRewardsCall {}, msg_sender, |_, _| {
                    self.claim_rewards(msg_sender)
                })
            }
            TIP20Call::TIP20(ITIP20Calls::globalRewardPerToken(_)) => {
                view(ITIP20::globalRewardPerTokenCall {}, |_| {
                    self.get_global_reward_per_token()
                })
            }
            TIP20Call::TIP20(ITIP20Calls::optedInSupply(_)) => {
                view(ITIP20::optedInSupplyCall {}, |_| self.get_opted_in_supply())
            }
            TIP20Call::TIP20(ITIP20Calls::userRewardInfo(call)) => view(call, |c| {
                self.get_user_reward_info(c.account).map(|info| info.into())
            }),
            TIP20Call::TIP20(ITIP20Calls::getPendingRewards(call)) => {
                view(call, |c| self.get_pending_rewards(c.account))
            }

            // RolesAuth functions
            TIP20Call::RolesAuth(IRolesAuthCalls::hasRole(call)) => {
                view(call, |c| self.has_role(c))
            }
            TIP20Call::RolesAuth(IRolesAuthCalls::getRoleAdmin(call)) => {
                view(call, |c| self.get_role_admin(c))
            }
            TIP20Call::RolesAuth(IRolesAuthCalls::grantRole(call)) => {
                mutate_void(call, msg_sender, |s, c| self.grant_role(s, c))
            }
            TIP20Call::RolesAuth(IRolesAuthCalls::revokeRole(call)) => {
                mutate_void(call, msg_sender, |s, c| self.revoke_role(s, c))
            }
            TIP20Call::RolesAuth(IRolesAuthCalls::renounceRole(call)) => {
                mutate_void(call, msg_sender, |s, c| self.renounce_role(s, c))
            }
            TIP20Call::RolesAuth(IRolesAuthCalls::setRoleAdmin(call)) => {
                mutate_void(call, msg_sender, |s, c| self.set_role_admin(s, c))
            }
        })
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
        primitives::{Bytes, U256, address},
        sol_types::{SolCall, SolInterface, SolValue},
    };
    use tempo_contracts::precompiles::{IRolesAuth, RolesAuthError, TIP20Error};

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
    fn test_call_uninitialized_token_reverts() -> eyre::Result<()> {
        let (mut storage, _) = setup_storage();
        let caller = Address::random();

        StorageCtx::enter(&mut storage, || {
            let uninitialized_addr = address!("20C0000000000000000000000000000000000999");
            let mut token = TIP20Token::from_address(uninitialized_addr)?;

            let calldata = ITIP20::approveCall {
                spender: Address::random(),
                amount: U256::random(),
            }
            .abi_encode();
            let result = token.call(&calldata, caller)?;

            assert!(result.reverted);
            let expected: Bytes = TIP20Error::uninitialized().selector().into();
            assert_eq!(result.bytes, expected);

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
