use crate::{
    Precompile, fill_precompile_output, input_cost, mutate, mutate_void,
    storage::Handler,
    tip_fee_manager::{
        IFeeManager, ITIPFeeAMM, TipFeeManager,
        amm::{M, MIN_LIQUIDITY, N, SCALE},
    },
    unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl Precompile for TipFeeManager {
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
            .map_err(|_| PrecompileError::Other("Invalid function selector length".into()))?;

        let result = match selector {
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
                view::<ITIPFeeAMM::getPoolIdCall>(calldata, |call| {
                    Ok(self.pool_id(call.userToken, call.validatorToken))
                })
            }
            ITIPFeeAMM::getPoolCall::SELECTOR => {
                view::<ITIPFeeAMM::getPoolCall>(calldata, |call| {
                    let pool = self.get_pool(call)?;

                    Ok(ITIPFeeAMM::Pool {
                        reserveUserToken: pool.reserve_user_token,
                        reserveValidatorToken: pool.reserve_validator_token,
                    })
                })
            }
            ITIPFeeAMM::poolsCall::SELECTOR => view::<ITIPFeeAMM::poolsCall>(calldata, |call| {
                let pool = self.pools.at(call.poolId).read()?;

                Ok(ITIPFeeAMM::Pool {
                    reserveUserToken: pool.reserve_user_token,
                    reserveValidatorToken: pool.reserve_validator_token,
                })
            }),
            ITIPFeeAMM::totalSupplyCall::SELECTOR => {
                view::<ITIPFeeAMM::totalSupplyCall>(calldata, |call| {
                    self.total_supply.at(call.poolId).read()
                })
            }
            ITIPFeeAMM::liquidityBalancesCall::SELECTOR => {
                view::<ITIPFeeAMM::liquidityBalancesCall>(calldata, |call| {
                    self.liquidity_balances.at(call.poolId).at(call.user).read()
                })
            }
            ITIPFeeAMM::MCall::SELECTOR => view::<ITIPFeeAMM::MCall>(calldata, |_call| Ok(M)),
            ITIPFeeAMM::NCall::SELECTOR => view::<ITIPFeeAMM::NCall>(calldata, |_call| Ok(N)),
            ITIPFeeAMM::SCALECall::SELECTOR => {
                view::<ITIPFeeAMM::SCALECall>(calldata, |_call| Ok(SCALE))
            }
            ITIPFeeAMM::MIN_LIQUIDITYCall::SELECTOR => {
                view::<ITIPFeeAMM::MIN_LIQUIDITYCall>(calldata, |_call| Ok(MIN_LIQUIDITY))
            }

            // State changing functions
            IFeeManager::setValidatorTokenCall::SELECTOR => {
                mutate_void::<IFeeManager::setValidatorTokenCall>(
                    calldata,
                    msg_sender,
                    |s, call| self.set_validator_token(s, call, self.storage.beneficiary()),
                )
            }
            IFeeManager::setUserTokenCall::SELECTOR => {
                mutate_void::<IFeeManager::setUserTokenCall>(calldata, msg_sender, |s, call| {
                    self.set_user_token(s, call)
                })
            }
            IFeeManager::distributeFeesCall::SELECTOR => {
                mutate_void::<IFeeManager::distributeFeesCall>(calldata, msg_sender, |_s, call| {
                    self.distribute_fees(call.validator)
                })
            }
            IFeeManager::collectedFeesByValidatorCall::SELECTOR => {
                view::<IFeeManager::collectedFeesByValidatorCall>(calldata, |call| {
                    self.collected_fees.at(call.validator).read()
                })
            }
            ITIPFeeAMM::mintCall::SELECTOR => {
                mutate::<ITIPFeeAMM::mintCall>(calldata, msg_sender, |s, call| {
                    self.mint(
                        s,
                        call.userToken,
                        call.validatorToken,
                        call.amountValidatorToken,
                        call.to,
                    )
                })
            }
            ITIPFeeAMM::burnCall::SELECTOR => {
                mutate::<ITIPFeeAMM::burnCall>(calldata, msg_sender, |s, call| {
                    let (amount_user_token, amount_validator_token) = self.burn(
                        s,
                        call.userToken,
                        call.validatorToken,
                        call.liquidity,
                        call.to,
                    )?;

                    Ok(ITIPFeeAMM::burnReturn {
                        amountUserToken: amount_user_token,
                        amountValidatorToken: amount_validator_token,
                    })
                })
            }
            ITIPFeeAMM::rebalanceSwapCall::SELECTOR => {
                mutate::<ITIPFeeAMM::rebalanceSwapCall>(calldata, msg_sender, |s, call| {
                    self.rebalance_swap(
                        s,
                        call.userToken,
                        call.validatorToken,
                        call.amountOut,
                        call.to,
                    )
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
        Precompile, expect_precompile_revert,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
        tip_fee_manager::{FeeManagerError, amm::PoolKey},
    };
    use alloy::{
        primitives::{Address, B256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_contracts::precompiles::{
        IFeeManager::IFeeManagerCalls, ITIPFeeAMM::ITIPFeeAMMCalls,
    };

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("TestToken", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let calldata = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            }
            .abi_encode();
            let result = fee_manager.call(&calldata, validator)?;
            assert_eq!(result.gas_used, 0);

            // Verify token was set
            let calldata = IFeeManager::validatorTokensCall { validator }.abi_encode();
            let result = fee_manager.call(&calldata, validator)?;
            assert_eq!(result.gas_used, 0);
            let returned_token = Address::abi_decode(&result.bytes)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token_zero_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            let calldata = IFeeManager::setValidatorTokenCall {
                token: Address::ZERO,
            }
            .abi_encode();
            let result = fee_manager.call(&calldata, validator);
            expect_precompile_revert(&result, FeeManagerError::invalid_token());

            Ok(())
        })
    }

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("TestToken", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let calldata = IFeeManager::setUserTokenCall {
                token: token.address(),
            }
            .abi_encode();
            let result = fee_manager.call(&calldata, user)?;
            assert_eq!(result.gas_used, 0);

            // Verify token was set
            let calldata = IFeeManager::userTokensCall { user }.abi_encode();
            let result = fee_manager.call(&calldata, user)?;
            assert_eq!(result.gas_used, 0);
            let returned_token = Address::abi_decode(&result.bytes)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_user_token_zero_address() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            let calldata = IFeeManager::setUserTokenCall {
                token: Address::ZERO,
            }
            .abi_encode();
            let result = fee_manager.call(&calldata, user);
            expect_precompile_revert(&result, FeeManagerError::invalid_token());

            Ok(())
        })
    }

    #[test]
    fn test_get_pool_id() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token_a = Address::random();
        let token_b = Address::random();
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            let calldata = ITIPFeeAMM::getPoolIdCall {
                userToken: token_a,
                validatorToken: token_b,
            }
            .abi_encode();
            let result = fee_manager.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let returned_id = B256::abi_decode(&result.bytes)?;
            let expected_id = PoolKey::new(token_a, token_b).get_id();
            assert_eq!(returned_id, expected_id);

            Ok(())
        })
    }

    #[test]
    fn test_tip_fee_amm_pool_operations() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token_a = Address::random();
        let token_b = Address::random();
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Get pool using ITIPFeeAMM interface
            let get_pool_call = ITIPFeeAMM::getPoolCall {
                userToken: token_a,
                validatorToken: token_b,
            };
            let calldata = get_pool_call.abi_encode();
            let result = fee_manager.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            // Decode and verify pool (should be empty initially)
            let pool = ITIPFeeAMM::Pool::abi_decode(&result.bytes)?;
            assert_eq!(pool.reserveUserToken, 0);
            assert_eq!(pool.reserveValidatorToken, 0);

            Ok(())
        })
    }

    #[test]
    fn test_pool_id_calculation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token_a = Address::random();
        let token_b = Address::random();
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Get pool ID with tokens in order (a, b)
            let calldata1 = ITIPFeeAMM::getPoolIdCall {
                userToken: token_a,
                validatorToken: token_b,
            }
            .abi_encode();
            let result1 = fee_manager.call(&calldata1, sender)?;
            let id1 = B256::abi_decode(&result1.bytes)?;

            // Get pool ID with tokens reversed (b, a)
            let calldata2 = ITIPFeeAMM::getPoolIdCall {
                userToken: token_b,
                validatorToken: token_a,
            }
            .abi_encode();
            let result2 = fee_manager.call(&calldata2, sender)?;
            let id2 = B256::abi_decode(&result2.bytes)?;

            // Pool IDs should be different since tokens are ordered
            assert_ne!(id1, id2);

            Ok(())
        })
    }

    #[test]
    fn test_fee_manager_invalid_token_error() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Test setValidatorToken with zero address
            let set_validator_call = IFeeManager::setValidatorTokenCall {
                token: Address::ZERO,
            };
            let result = fee_manager.call(&set_validator_call.abi_encode(), validator);
            expect_precompile_revert(&result, FeeManagerError::invalid_token());

            // Test setUserToken with zero address
            let set_user_call = IFeeManager::setUserTokenCall {
                token: Address::ZERO,
            };
            let result = fee_manager.call(&set_user_call.abi_encode(), user);
            expect_precompile_revert(&result, FeeManagerError::invalid_token());

            Ok(())
        })
    }

    #[test]
    fn test_tip_fee_manager_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            let fee_manager_unsupported = check_selector_coverage(
                &mut fee_manager,
                IFeeManagerCalls::SELECTORS,
                "IFeeManager",
                IFeeManagerCalls::name_by_selector,
            );

            let amm_unsupported = check_selector_coverage(
                &mut fee_manager,
                ITIPFeeAMMCalls::SELECTORS,
                "ITIPFeeAMM",
                ITIPFeeAMMCalls::name_by_selector,
            );

            assert_full_coverage([fee_manager_unsupported, amm_unsupported]);

            Ok(())
        })
    }
}
