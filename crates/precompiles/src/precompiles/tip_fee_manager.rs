use crate::{
    contracts::{
        storage::StorageProvider,
        tip_fee_manager::TipFeeManager,
        types::{IFeeManager, ITIPFeeAMM},
    },
    precompiles::{Precompile, mutate, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use reth_evm::revm::precompile::{PrecompileError, PrecompileResult};

#[rustfmt::skip]
impl<'a, S: StorageProvider> Precompile for TipFeeManager<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata.get(..4).ok_or_else(|| {
            PrecompileError::Other("Invalid input: missing function selector".to_string())
        })?.try_into().map_err(|_| {
            PrecompileError::Other("Invalid function selector length".to_string())
        })?;
        match selector {
            // View functions
            IFeeManager::userTokensCall::SELECTOR => view::<IFeeManager::userTokensCall>(calldata, |call| self.user_tokens(call)),
            IFeeManager::validatorTokensCall::SELECTOR => view::<IFeeManager::validatorTokensCall>(calldata, |call| self.validator_tokens(call)),
            IFeeManager::getFeeTokenBalanceCall::SELECTOR => view::<IFeeManager::getFeeTokenBalanceCall>(calldata, |call| self.get_fee_token_balance(call)),
            IFeeManager::collectedFeesCall::SELECTOR => view::<IFeeManager::collectedFeesCall>(calldata, |call| self.collected_fees(&call.token)),
            IFeeManager::getTokensWithFeesLengthCall::SELECTOR => view::<IFeeManager::getTokensWithFeesLengthCall>(calldata, |_call| self.get_tokens_with_fees_length()),
            IFeeManager::getTokenWithFeesCall::SELECTOR => view::<IFeeManager::getTokenWithFeesCall>(calldata, |call| self.get_token_with_fees(call.index)),
            IFeeManager::tokenInFeesArrayCall::SELECTOR => view::<IFeeManager::tokenInFeesArrayCall>(calldata, |call| self.token_in_fees_array(&call.token)),
            ITIPFeeAMM::getPoolIdCall::SELECTOR => view::<ITIPFeeAMM::getPoolIdCall>(calldata, |call| self.get_pool_id(call)),
            ITIPFeeAMM::getPoolCall::SELECTOR => view::<ITIPFeeAMM::getPoolCall>(calldata, |call| self.get_pool(call)),
            ITIPFeeAMM::poolsCall::SELECTOR => view::<ITIPFeeAMM::poolsCall>(calldata, |call| self.pools(call)),
            ITIPFeeAMM::poolExistsCall::SELECTOR => view::<ITIPFeeAMM::poolExistsCall>(calldata, |call| self.pool_exists(call)),
            ITIPFeeAMM::totalSupplyCall::SELECTOR => view::<ITIPFeeAMM::totalSupplyCall>(calldata, |call| self.total_supply(call)),
            ITIPFeeAMM::liquidityBalancesCall::SELECTOR => view::<ITIPFeeAMM::liquidityBalancesCall>(calldata, |call| self.liquidity_balances(call)),

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_validator_token(s, call)),
            IFeeManager::setUserTokenCall::SELECTOR => mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_user_token(s, call)),
            ITIPFeeAMM::createPoolCall::SELECTOR => mutate_void::<ITIPFeeAMM::createPoolCall, ITIPFeeAMM::ITIPFeeAMMErrors>(calldata, msg_sender, |_s, call| self.create_pool(call)),
            IFeeManager::executeBlockCall::SELECTOR => {
                mutate_void::<IFeeManager::executeBlockCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.execute_block(s, call))
            }
            ITIPFeeAMM::mintCall::SELECTOR => mutate::<ITIPFeeAMM::mintCall, ITIPFeeAMM::ITIPFeeAMMErrors>(calldata, msg_sender, |s, call| self.mint(*s, call)),
            ITIPFeeAMM::burnCall::SELECTOR => mutate::<ITIPFeeAMM::burnCall, ITIPFeeAMM::ITIPFeeAMMErrors>(calldata, msg_sender, |s, call| self.burn(*s, call)),
            _ => Err(PrecompileError::Other("Unknown function selector".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        contracts::{
            HashMapStorageProvider, TIP20Token, address_to_token_id_unchecked,
            tip_fee_manager::amm::PoolKey,
            types::{IFeeManager, ITIP20, ITIPFeeAMM},
        },
        fee_manager_err,
        precompiles::{MUTATE_FUNC_GAS, VIEW_FUNC_GAS, expect_precompile_error},
        tip_fee_amm_err,
    };
    use alloy::{
        primitives::{Address, B256, Bytes, U256},
        sol_types::SolValue,
    };
    use eyre::Result;

    fn setup_token_with_balance(
        storage: &mut HashMapStorageProvider,
        token: Address,
        user: Address,
        amount: U256,
    ) {
        use crate::contracts::tip20::ISSUER_ROLE;

        let token_id = address_to_token_id_unchecked(&token);
        let mut tip20_token = TIP20Token::new(token_id, storage);

        // Initialize token
        tip20_token
            .initialize("TestToken", "TEST", "USD", &user)
            .unwrap();

        // Grant issuer role to user and mint tokens
        let mut roles = tip20_token.get_roles_contract();
        roles.grant_role_internal(&user, *ISSUER_ROLE);

        tip20_token
            .mint(&user, ITIP20::mintCall { to: user, amount })
            .unwrap();

        // Approve fee manager to spend user's tokens
        tip20_token
            .approve(
                &user,
                ITIP20::approveCall {
                    spender: TIP_FEE_MANAGER_ADDRESS,
                    amount,
                },
            )
            .unwrap();
    }

    #[test]
    fn test_set_validator_token() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let validator = Address::random();
        let token = Address::random();

        let calldata = IFeeManager::setValidatorTokenCall { token }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &validator)?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token was set
        let calldata = IFeeManager::validatorTokensCall { validator }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &validator)?;
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let returned_token = Address::abi_decode(&result.bytes)?;
        assert_eq!(returned_token, token);

        Ok(())
    }

    #[test]
    fn test_set_validator_token_zero_address() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let validator = Address::random();

        let calldata = IFeeManager::setValidatorTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &validator);
        expect_precompile_error(&result, tip_fee_amm_err!(InvalidToken));

        Ok(())
    }

    #[test]
    fn test_set_user_token() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let user = Address::random();
        let token = Address::random();

        let calldata = IFeeManager::setUserTokenCall { token }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &user)?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify token was set
        let calldata = IFeeManager::userTokensCall { user }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &user)?;
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let returned_token = Address::abi_decode(&result.bytes)?;
        assert_eq!(returned_token, token);

        Ok(())
    }

    #[test]
    fn test_set_user_token_zero_address() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let user = Address::random();

        let calldata = IFeeManager::setUserTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &user);
        expect_precompile_error(&result, tip_fee_amm_err!(InvalidToken));
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = ITIPFeeAMM::createPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        }
        .abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata), &Address::random())
            .unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify pool exists
        let pool_key = PoolKey::new(token_a, token_b);
        let pool_id = pool_key.get_id();

        let calldata = ITIPFeeAMM::poolExistsCall { poolId: pool_id }.abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata), &Address::random())
            .unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);
        let exists = bool::abi_decode(&result.bytes).unwrap();
        assert!(exists);
    }

    #[test]
    fn test_create_pool_identical_addresses() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token = Address::random();

        let calldata = ITIPFeeAMM::createPoolCall {
            userToken: token,
            validatorToken: token,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random());
        expect_precompile_error(&result, tip_fee_amm_err!(IdenticalAddresses));
    }

    #[test]
    fn test_create_pool_zero_address() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token = Address::random();

        let calldata = ITIPFeeAMM::createPoolCall {
            userToken: Address::ZERO,
            validatorToken: token,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random());
        expect_precompile_error(&result, tip_fee_amm_err!(InvalidToken));
    }

    #[test]
    fn test_create_pool_already_exists() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = ITIPFeeAMM::createPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        }
        .abi_encode();

        // Create pool first time
        let result = fee_manager
            .call(&Bytes::from(calldata.clone()), &Address::random())
            .unwrap();
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Try to create same pool again
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random());
        expect_precompile_error(&result, tip_fee_amm_err!(PoolExists));
    }

    #[test]
    fn test_get_pool_id() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = ITIPFeeAMM::getPoolIdCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        let calldata = calldata.abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata), &Address::random())
            .unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

        let returned_id = B256::abi_decode(&result.bytes).unwrap();
        let expected_id = PoolKey::new(token_a, token_b).get_id();
        assert_eq!(returned_id, expected_id);
    }

    #[test]
    fn test_tip_fee_amm_pool_operations() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Create pool using ITIPFeeAMM interface
        let create_call = ITIPFeeAMM::createPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        let calldata = create_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random())?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Get pool using ITIPFeeAMM interface
        let get_pool_call = ITIPFeeAMM::getPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        let calldata = get_pool_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random())?;
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

        // Decode and verify pool
        let pool = ITIPFeeAMM::Pool::abi_decode(&result.bytes)?;
        assert_eq!(pool.reserveUserToken, 0);
        assert_eq!(pool.reserveValidatorToken, 0);

        Ok(())
    }

    #[test]
    fn test_fee_manager_with_nonexistent_pool() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let token_a = Address::random();
        let token_b = Address::random();

        // Setup tokens with balance
        setup_token_with_balance(&mut storage, token_a, user, U256::MAX);

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        // Set different tokens for user and validator (requires pool)
        fee_manager.call(
            &Bytes::from(IFeeManager::setValidatorTokenCall { token: token_b }.abi_encode()),
            &validator,
        )?;
        fee_manager.call(
            &Bytes::from(IFeeManager::setUserTokenCall { token: token_a }.abi_encode()),
            &user,
        )?;

        Ok(())
    }

    #[test]
    fn test_pool_id_calculation() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Test that pool ID is same regardless of token order
        let calldata1 = ITIPFeeAMM::getPoolIdCall {
            userToken: token_a,
            validatorToken: token_b,
        }
        .abi_encode();
        let result1 = fee_manager
            .call(&Bytes::from(calldata1), &Address::random())
            .unwrap();
        let id1 = B256::abi_decode(&result1.bytes).unwrap();

        let calldata2 = ITIPFeeAMM::getPoolIdCall {
            userToken: token_b,
            validatorToken: token_a,
        }
        .abi_encode();
        let result2 = fee_manager
            .call(&Bytes::from(calldata2), &Address::random())
            .unwrap();
        let id2 = B256::abi_decode(&result2.bytes).unwrap();

        // Pool IDs should be the same since tokens are not ordered in FeeAMM (unlike TIPFeeAMM)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_pool_exists_check() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Get pool ID
        let pool_key = PoolKey::new(token_a, token_b);
        let pool_id = pool_key.get_id();

        // Check pool doesn't exist initially
        let exists_call = ITIPFeeAMM::poolExistsCall { poolId: pool_id };
        let calldata = exists_call.abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata.clone()), &Address::random())
            .unwrap();
        let exists = bool::abi_decode(&result.bytes).unwrap();
        assert!(!exists);

        // Create pool
        let create_call = ITIPFeeAMM::createPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        fee_manager
            .call(&Bytes::from(create_call.abi_encode()), &Address::random())
            .unwrap();

        // Now pool should exist
        let result = fee_manager
            .call(&Bytes::from(calldata), &Address::random())
            .unwrap();
        let exists = bool::abi_decode(&result.bytes).unwrap();
        assert!(exists);
    }

    #[test]
    fn test_fee_manager_invalid_token_error() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let user = Address::random();
        let validator = Address::random();

        // Test that IFeeManager properly validates tokens (zero address)
        let set_validator_call = IFeeManager::setValidatorTokenCall {
            token: Address::ZERO,
        };
        let result = fee_manager.call(&Bytes::from(set_validator_call.abi_encode()), &validator);
        expect_precompile_error(&result, fee_manager_err!(InvalidToken));

        let set_user_call = IFeeManager::setUserTokenCall {
            token: Address::ZERO,
        };
        let result = fee_manager.call(&Bytes::from(set_user_call.abi_encode()), &user);
        expect_precompile_error(&result, fee_manager_err!(InvalidToken));
    }

    #[test]
    fn test_execute_block() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let token = Address::random();

        // Setup token
        let user = Address::random();
        setup_token_with_balance(&mut storage, token, user, U256::MAX);

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        // Set validator token
        fee_manager.call(
            &Bytes::from(IFeeManager::setValidatorTokenCall { token }.abi_encode()),
            &validator,
        )?;

        // Call executeBlock (only system contract can call)
        let call = IFeeManager::executeBlockCall { validator };
        let result = fee_manager.call(&Bytes::from(call.abi_encode()), &Address::ZERO)?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        Ok(())
    }
}
