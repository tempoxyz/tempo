use crate::{
    contracts::{
        storage::StorageProvider,
        tip_fee_manager::TipFeeManager,
        types::{IFeeManager, ITIPFeeAMM},
    },
    precompiles::{Precompile, mutate, mutate_void, view},
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: StorageProvider> Precompile for TipFeeManager<'a, S> {
    fn call(&mut self, calldata: &[u8], msg_sender: &Address) -> PrecompileResult {
        let selector: [u8; 4] = calldata
            .get(..4)
            .ok_or_else(|| {
                PrecompileError::Other("Invalid input: missing function selector".to_string())
            })?
            .try_into()
            .map_err(|_| PrecompileError::Other("Invalid function selector length".to_string()))?;

        match selector {
            // View functions
            IFeeManager::userTokensCall::SELECTOR => {
                view::<IFeeManager::userTokensCall>(calldata, |call| self.user_tokens(call))
            }
            IFeeManager::validatorTokensCall::SELECTOR => {
                view::<IFeeManager::validatorTokensCall>(calldata, |call| {
                    self.validator_tokens(call)
                })
            }
            IFeeManager::getFeeTokenBalanceCall::SELECTOR => {
                view::<IFeeManager::getFeeTokenBalanceCall>(calldata, |call| {
                    self.get_fee_token_balance(call)
                })
            }
            ITIPFeeAMM::getPoolIdCall::SELECTOR => {
                view::<ITIPFeeAMM::getPoolIdCall>(calldata, |call| self.get_pool_id(call))
            }
            ITIPFeeAMM::getPoolCall::SELECTOR => {
                view::<ITIPFeeAMM::getPoolCall>(calldata, |call| self.get_pool(call))
            }
            ITIPFeeAMM::poolsCall::SELECTOR => {
                view::<ITIPFeeAMM::poolsCall>(calldata, |call| self.pools(call))
            }
            ITIPFeeAMM::totalSupplyCall::SELECTOR => {
                view::<ITIPFeeAMM::totalSupplyCall>(calldata, |call| self.total_supply(call))
            }
            ITIPFeeAMM::liquidityBalancesCall::SELECTOR => {
                view::<ITIPFeeAMM::liquidityBalancesCall>(calldata, |call| {
                    self.liquidity_balances(call)
                })
            }

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => {
                mutate_void::<IFeeManager::setValidatorTokenCall, IFeeManager::IFeeManagerErrors>(
                    calldata,
                    msg_sender,
                    |s, call| self.set_validator_token(s, call),
                )
            }
            IFeeManager::setUserTokenCall::SELECTOR => {
                mutate_void::<IFeeManager::setUserTokenCall, IFeeManager::IFeeManagerErrors>(
                    calldata,
                    msg_sender,
                    |s, call| self.set_user_token(s, call),
                )
            }
            IFeeManager::executeBlockCall::SELECTOR => {
                mutate_void::<IFeeManager::executeBlockCall, IFeeManager::IFeeManagerErrors>(
                    calldata,
                    msg_sender,
                    |s, _call| self.execute_block(s),
                )
            }
            ITIPFeeAMM::mintCall::SELECTOR => mutate::<
                ITIPFeeAMM::mintCall,
                ITIPFeeAMM::ITIPFeeAMMErrors,
            >(calldata, msg_sender, |s, call| {
                self.mint(*s, call)
            }),
            ITIPFeeAMM::burnCall::SELECTOR => mutate::<
                ITIPFeeAMM::burnCall,
                ITIPFeeAMM::ITIPFeeAMMErrors,
            >(calldata, msg_sender, |s, call| {
                self.burn(*s, call)
            }),
            ITIPFeeAMM::rebalanceSwapCall::SELECTOR => {
                mutate::<ITIPFeeAMM::rebalanceSwapCall, ITIPFeeAMM::ITIPFeeAMMErrors>(
                    calldata,
                    msg_sender,
                    |s, call| self.rebalance_swap(*s, call),
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
    use super::*;
    use crate::{
        LINKING_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS,
        contracts::{
            HashMapStorageProvider, TIP20Token, address_to_token_id_unchecked, fee_manager_err,
            tip_fee_manager::amm::PoolKey,
            token_id_to_address,
            types::{IFeeManager, ITIP20, ITIPFeeAMM, TIPFeeAMMError},
        },
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
    ) {
        use crate::contracts::tip20::ISSUER_ROLE;

        let token_id = address_to_token_id_unchecked(&token);
        let mut tip20_token = TIP20Token::new(token_id, storage);

        // Initialize token
        tip20_token
            .initialize("TestToken", "TEST", "USD", LINKING_USD_ADDRESS, &user)
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
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
        let validator = Address::random();
        let token = token_id_to_address(rand::random::<u64>());

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
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
        let validator = Address::random();

        let calldata = IFeeManager::setValidatorTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &validator);
        expect_precompile_error(&result, TIPFeeAMMError::invalid_token());

        Ok(())
    }

    #[test]
    fn test_set_user_token() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
        let user = Address::random();
        let token = token_id_to_address(rand::random::<u64>());

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
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
        let user = Address::random();

        let calldata = IFeeManager::setUserTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), &user);
        expect_precompile_error(&result, TIPFeeAMMError::invalid_token());
    }

    #[test]
    fn test_get_pool_id() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
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
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

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
    fn test_pool_id_calculation() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
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
    fn test_fee_manager_invalid_token_error() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager =
            TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, Address::random(), &mut storage);
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

        let mut fee_manager = TipFeeManager::new(TIP_FEE_MANAGER_ADDRESS, validator, &mut storage);

        // Call executeBlock (only system contract can call)
        let call = IFeeManager::executeBlockCall {};
        let result = fee_manager.call(&Bytes::from(call.abi_encode()), &Address::ZERO)?;
        assert_eq!(result.gas_used, MUTATE_FUNC_GAS);

        Ok(())
    }
}
