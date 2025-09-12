use crate::{
    contracts::{
        storage::StorageProvider,
        tip_fee_manager::TipFeeManager,
        types::{IFeeManager, ITIPFeeAMM},
    },
    precompiles::{Precompile, mutate_void, view},
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
            ITIPFeeAMM::getPoolIdCall::SELECTOR => view::<ITIPFeeAMM::getPoolIdCall>(calldata, |call| self.get_pool_id(call)),
            ITIPFeeAMM::getPoolCall::SELECTOR => view::<ITIPFeeAMM::getPoolCall>(calldata, |call| self.get_pool(call)),
            ITIPFeeAMM::poolsCall::SELECTOR => view::<ITIPFeeAMM::poolsCall>(calldata, |call| self.pools(call)),
            ITIPFeeAMM::poolExistsCall::SELECTOR => view::<ITIPFeeAMM::poolExistsCall>(calldata, |call| self.pool_exists(call)),

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_validator_token(s, call)),
            IFeeManager::setUserTokenCall::SELECTOR => mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_user_token(s, call)),
            ITIPFeeAMM::createPoolCall::SELECTOR => mutate_void::<ITIPFeeAMM::createPoolCall, ITIPFeeAMM::ITIPFeeAMMErrors>(calldata, msg_sender, |_s, call| self.create_pool(call)),
            IFeeManager::collectFeeCall::SELECTOR => {
                mutate_void::<IFeeManager::collectFeeCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.collect_fee(s, call))
            }
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
            tip_fee_manager::PoolKey,
            tip20::ISSUER_ROLE,
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
    ) -> TIP20Token<'_, HashMapStorageProvider> {
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

        // Approve fee manager to transfer tokens
        tip20_token
            .approve(
                &user,
                ITIP20::approveCall {
                    spender: TIP_FEE_MANAGER_ADDRESS,
                    amount: U256::MAX,
                },
            )
            .unwrap();

        tip20_token
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
            tokenA: token_a,
            tokenB: token_b,
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
            tokenA: token,
            tokenB: token,
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
            tokenA: Address::ZERO,
            tokenB: token,
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
            tokenA: token_a,
            tokenB: token_b,
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

        let key = ITIPFeeAMM::PoolKey {
            token0: token_a,
            token1: token_b,
        };
        let calldata = ITIPFeeAMM::getPoolIdCall { key }.abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata), &Address::random())
            .unwrap();
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

        let returned_id = B256::abi_decode(&result.bytes).unwrap();
        let expected_id = PoolKey::new(token_a, token_b).get_id();
        assert_eq!(returned_id, expected_id);
    }

    #[test]
    fn test_collect_fee() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let token = Address::random();
        let amount = U256::from(1000);

        // Setup token with balance and approvals
        setup_token_with_balance(&mut storage, token, user, U256::MAX);

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);

        // Set fee tokens (same for user and validator)
        let set_validator_call = IFeeManager::setValidatorTokenCall { token };
        let set_validator_calldata = set_validator_call.abi_encode();
        fee_manager.call(&Bytes::from(set_validator_calldata), &validator)?;

        let set_user_call = IFeeManager::setUserTokenCall { token };
        let set_user_calldata = set_user_call.abi_encode();
        fee_manager.call(&Bytes::from(set_user_calldata), &user)?;

        // Collect fee (only system contract can call)
        let collect_call = IFeeManager::collectFeeCall {
            user,
            coinbase: validator,
            amount,
        };
        let collect_calldata = collect_call.abi_encode();

        let result = fee_manager.call(&Bytes::from(collect_calldata), &Address::ZERO)?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Verify fee balance was updated
        let balance_call = IFeeManager::getFeeTokenBalanceCall {
            validator: Address::ZERO,
            sender: user,
        };
        let balance_calldata = balance_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(balance_calldata), &user)?;
        let balance_result =
            IFeeManager::getFeeTokenBalanceCall::abi_decode_returns(&result.bytes)?;
        assert_eq!(balance_result._0, token);
        assert_eq!(balance_result._1, U256::MAX - amount);

        Ok(())
    }

    #[test]
    fn test_tip_fee_amm_pool_operations() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Create pool using ITIPFeeAMM interface
        let create_call = ITIPFeeAMM::createPoolCall {
            tokenA: token_a,
            tokenB: token_b,
        };
        let calldata = create_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random())?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        // Get pool using ITIPFeeAMM interface
        let pool_key = ITIPFeeAMM::PoolKey {
            token0: if token_a < token_b { token_a } else { token_b },
            token1: if token_a < token_b { token_b } else { token_a },
        };
        let get_pool_call = ITIPFeeAMM::getPoolCall { key: pool_key };
        let calldata = get_pool_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random())?;
        assert_eq!(result.gas_used, VIEW_FUNC_GAS);

        // Decode and verify pool
        let pool = ITIPFeeAMM::Pool::abi_decode(&result.bytes)?;
        assert_eq!(pool.reserve0, 0);
        assert_eq!(pool.reserve1, 0);

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

        // Try to collect fee without pool existing - should fail
        let collect_call = IFeeManager::collectFeeCall {
            user,
            coinbase: validator,
            amount: U256::from(100),
        };
        let result = fee_manager.call(&Bytes::from(collect_call.abi_encode()), &Address::ZERO);

        // Should fail with PoolDoesNotExist error
        expect_precompile_error(&result, fee_manager_err!(PoolDoesNotExist));

        Ok(())
    }

    #[test]
    fn test_pool_id_calculation() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Test that pool ID is same regardless of token order
        let key1 = ITIPFeeAMM::PoolKey {
            token0: token_a,
            token1: token_b,
        };
        let key2 = ITIPFeeAMM::PoolKey {
            token0: token_b,
            token1: token_a,
        };

        let calldata1 = ITIPFeeAMM::getPoolIdCall { key: key1 }.abi_encode();
        let result1 = fee_manager
            .call(&Bytes::from(calldata1), &Address::random())
            .unwrap();
        let id1 = B256::abi_decode(&result1.bytes).unwrap();

        let calldata2 = ITIPFeeAMM::getPoolIdCall { key: key2 }.abi_encode();
        let result2 = fee_manager
            .call(&Bytes::from(calldata2), &Address::random())
            .unwrap();
        let id2 = B256::abi_decode(&result2.bytes).unwrap();

        // Pool IDs should be the same since tokens are ordered internally
        assert_eq!(id1, id2);
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
            tokenA: token_a,
            tokenB: token_b,
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
    fn test_collect_fee_only_system_contract() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let user = Address::random();
        let validator = Address::random();
        let non_system = Address::random();

        let collect_call = IFeeManager::collectFeeCall {
            user,
            coinbase: validator,
            amount: U256::from(100),
        };

        // Non-system contract should fail
        let result = fee_manager.call(&Bytes::from(collect_call.abi_encode()), &non_system);
        expect_precompile_error(&result, fee_manager_err!(OnlySystemContract));
    }
}
