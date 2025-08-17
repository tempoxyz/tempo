use crate::{
    contracts::{storage::StorageProvider, tip_fee_manager::TipFeeManager, types::IFeeManager},
    precompiles::{Precompile, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use reth::revm::precompile::{PrecompileError, PrecompileResult};

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
            IFeeManager::getPoolIdCall::SELECTOR => view::<IFeeManager::getPoolIdCall>(calldata, |call| self.get_pool_id(call)),
            IFeeManager::getPoolCall::SELECTOR => view::<IFeeManager::getPoolCall>(calldata, |call| self.get_pool(call)),
            IFeeManager::poolsCall::SELECTOR => view::<IFeeManager::poolsCall>(calldata, |call| self.pools(call)),
            IFeeManager::poolExistsCall::SELECTOR => view::<IFeeManager::poolExistsCall>(calldata, |call| self.pool_exists(call)),

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_validator_token(s, call)),
            IFeeManager::setUserTokenCall::SELECTOR => mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |s, call| self.set_user_token(s, call)),
            IFeeManager::createPoolCall::SELECTOR => mutate_void::<IFeeManager::createPoolCall, IFeeManager::IFeeManagerErrors>(calldata, msg_sender, |_s, call| self.create_pool(call)),
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
            types::{IFeeManager, ITIP20},
        },
        fee_manager_err,
        precompiles::{MUTATE_FUNC_GAS, VIEW_FUNC_GAS, expect_precompile_error},
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
        expect_precompile_error(&result, fee_manager_err!(InvalidToken));

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
        expect_precompile_error(&result, fee_manager_err!(InvalidToken));
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = IFeeManager::createPoolCall {
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

        let calldata = IFeeManager::poolExistsCall { poolId: pool_id }.abi_encode();
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

        let calldata = IFeeManager::createPoolCall {
            tokenA: token,
            tokenB: token,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random());
        expect_precompile_error(&result, fee_manager_err!(IdenticalAddresses));
    }

    #[test]
    fn test_create_pool_zero_address() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token = Address::random();

        let calldata = IFeeManager::createPoolCall {
            tokenA: Address::ZERO,
            tokenB: token,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &Address::random());
        expect_precompile_error(&result, fee_manager_err!(InvalidToken));
    }

    #[test]
    fn test_create_pool_already_exists() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = IFeeManager::createPoolCall {
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
        expect_precompile_error(&result, fee_manager_err!(PoolExists));
    }

    #[test]
    fn test_get_pool_id() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let key = IFeeManager::PoolKey {
            token0: token_a,
            token1: token_b,
        };
        let calldata = IFeeManager::getPoolIdCall { key }.abi_encode();
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
        let balance_call = IFeeManager::getFeeTokenBalanceCall { sender: user };
        let balance_calldata = balance_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(balance_calldata), &user)?;
        let balance_result =
            IFeeManager::getFeeTokenBalanceCall::abi_decode_returns(&result.bytes)?;
        assert_eq!(balance_result._0, token);
        assert_eq!(balance_result._1, U256::MAX - amount);

        Ok(())
    }
}
