#[cfg(test)]
mod tests {
    use crate::{
        dispatch::Precompile,
        storage::StorageCtx,
        test_util::{TIP20Setup, setup_storage},
        tip20::{
            TIP20Token,
            abi::{self as tip20, Error as TIP20Error},
            prelude::*,
        },
        tip403_registry::{PolicyType, TIP403Registry, traits::*},
    };
    use alloy::{
        primitives::{Address, Bytes, U256, address},
        sol_types::{SolCall, SolInterface, SolValue},
    };
    use revm::precompile::PrecompileError;

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

            let balance_of_call = tip20::balanceOfCall { account };
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

            let initial_balance = token.balance_of(recipient)?;
            assert_eq!(initial_balance, U256::ZERO);

            let mint_amount = U256::random().min(U256::from(u128::MAX)) % token.supply_cap()?;
            let mint_call = tip20::mintCall {
                to: recipient,
                amount: mint_amount,
            };
            let calldata = mint_call.abi_encode();

            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let final_balance = token.balance_of(recipient)?;
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

            assert_eq!(token.balance_of(sender)?, initial_sender_balance);
            assert_eq!(token.balance_of(recipient)?, U256::ZERO);

            let transfer_call = tip20::transferCall {
                to: recipient,
                amount: transfer_amount,
            };
            let calldata = transfer_call.abi_encode();
            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let success = bool::abi_decode(&result.bytes)?;
            assert!(success);

            let final_sender_balance = token.balance_of(sender)?;
            let final_recipient_balance = token.balance_of(recipient)?;

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

            let approve_call = tip20::approveCall {
                spender,
                amount: approve_amount,
            };
            let calldata = approve_call.abi_encode();
            let result = token.call(&calldata, owner)?;
            assert_eq!(result.gas_used, 0);
            let success = bool::abi_decode(&result.bytes)?;
            assert!(success);

            let allowance = token.allowance(owner, spender)?;
            assert_eq!(allowance, approve_amount);

            let transfer_from_call = tip20::transferFromCall {
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
                token.balance_of(owner)?,
                initial_owner_balance - transfer_amount
            );
            assert_eq!(token.balance_of(recipient)?, transfer_amount);

            // Verify allowance was reduced
            let remaining_allowance = token.allowance(owner, spender)?;
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
            let pause_call = tip20::pauseCall {};
            let calldata = pause_call.abi_encode();
            let result = token.call(&calldata, pauser)?;
            assert_eq!(result.gas_used, 0);
            assert!(token.paused()?);

            // Unpause the token
            let unpause_call = tip20::unpauseCall {};
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
            assert_eq!(token.balance_of(burner)?, initial_balance);
            assert_eq!(token.total_supply()?, initial_balance);

            // Burn tokens
            let burn_call = tip20::burnCall {
                amount: burn_amount,
            };
            let calldata = burn_call.abi_encode();
            let result = token.call(&calldata, burner)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(token.balance_of(burner)?, initial_balance - burn_amount);
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
            let name_call = tip20::nameCall {};
            let calldata = name_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
            assert_eq!(result.gas_used, 0);
            let name = String::abi_decode(&result.bytes)?;
            assert_eq!(name, "Test Token");

            // Test symbol()
            let symbol_call = tip20::symbolCall {};
            let calldata = symbol_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let symbol = String::abi_decode(&result.bytes)?;
            assert_eq!(symbol, "TEST");

            // Test decimals()
            let decimals_call = tip20::decimalsCall {};
            let calldata = decimals_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let decimals = tip20::decimalsCall::abi_decode_returns(&result.bytes)?;
            assert_eq!(decimals, 6);

            // Test currency()
            let currency_call = tip20::currencyCall {};
            let calldata = currency_call.abi_encode();
            let result = token.call(&calldata, caller)?;
            assert_eq!(result.gas_used, 0);
            let currency = String::abi_decode(&result.bytes)?;
            assert_eq!(currency, "USD");

            // Test totalSupply()
            let total_supply_call = tip20::totalSupplyCall {};
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

            let set_cap_call = tip20::setSupplyCapCall {
                new_supply_cap: supply_cap,
            };
            let calldata = set_cap_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);

            let mint_call = tip20::mintCall {
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

            let has_role_call = tip20::hasRoleCall {
                role: *ISSUER_ROLE,
                account: user1,
            };
            let calldata = has_role_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);
            let has_role = bool::abi_decode(&result.bytes)?;
            assert!(has_role);

            let has_role_call = tip20::hasRoleCall {
                role: *ISSUER_ROLE,
                account: user2,
            };
            let calldata = has_role_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            let has_role = bool::abi_decode(&result.bytes)?;
            assert!(!has_role);

            let mint_call = tip20::mintCall {
                to: user2,
                amount: U256::from(100),
            };
            let calldata = mint_call.abi_encode();
            let output = token.call(&Bytes::from(calldata.clone()), unauthorized)?;
            assert!(output.reverted);
            let expected: Bytes = TIP20Error::unauthorized().selector().into();
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
            let transfer_call = tip20::transferWithMemoCall {
                to: recipient,
                amount: transfer_amount,
                memo,
            };
            let calldata = transfer_call.abi_encode();
            let result = token.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(token.balance_of(sender)?, initial_balance - transfer_amount);
            assert_eq!(token.balance_of(recipient)?, transfer_amount);

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
            let new_policy_id = registry.create_policy(admin, admin, PolicyType::Whitelist)?;

            let change_policy_call = tip20::changeTransferPolicyIdCall { new_policy_id };
            let calldata = change_policy_call.abi_encode();
            let result = token.call(&calldata, admin)?;
            assert_eq!(result.gas_used, 0);
            assert_eq!(token.transfer_policy_id()?, new_policy_id);

            // Create another valid policy for the unauthorized test
            let another_policy_id = registry.create_policy(admin, admin, PolicyType::Blacklist)?;

            let change_policy_call = tip20::changeTransferPolicyIdCall {
                new_policy_id: another_policy_id,
            };
            let calldata = change_policy_call.abi_encode();
            let output = token.call(&calldata, non_admin)?;
            assert!(output.reverted);
            let expected: Bytes = TIP20Error::unauthorized().selector().into();
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

            let calldata = tip20::approveCall {
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

        let (mut storage, admin) = setup_storage();

        StorageCtx::enter(&mut storage, || {
            let mut token = TIP20Setup::create("Test", "TST", admin).apply()?;

            let token_unsupported = check_selector_coverage(
                &mut token,
                ITokenCalls::SELECTORS,
                "Token",
                ITokenCalls::name_by_selector,
            );

            let roles_unsupported = check_selector_coverage(
                &mut token,
                IRolesAuthCalls::SELECTORS,
                "RolesAuth",
                IRolesAuthCalls::name_by_selector,
            );

            let rewards_unsupported = check_selector_coverage(
                &mut token,
                IRewardsCalls::SELECTORS,
                "Rewards",
                IRewardsCalls::name_by_selector,
            );

            assert_full_coverage([token_unsupported, roles_unsupported, rewards_unsupported]);
            Ok(())
        })
    }
}
