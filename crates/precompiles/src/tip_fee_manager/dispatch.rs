use crate::{
    Precompile,
    error::TempoPrecompileError,
    fill_precompile_output, input_cost, mutate, mutate_void,
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
            IFeeManager::executeBlockCall::SELECTOR => {
                if self.storage.spec().is_allegro_moderato() {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
                } else {
                    mutate_void::<IFeeManager::executeBlockCall>(calldata, msg_sender, |s, _call| {
                        self.execute_block(s, self.storage.beneficiary())
                    })
                }
            }
            IFeeManager::distributeFeesCall::SELECTOR => {
                if self.storage.spec().is_allegro_moderato() {
                    mutate_void::<IFeeManager::distributeFeesCall>(calldata, msg_sender, |_s, call| {
                        self.distribute_fees(call.validator)
                    })
                } else {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
                }
            }
            IFeeManager::collectedFeesByValidatorCall::SELECTOR => {
                if self.storage.spec().is_allegro_moderato() {
                    view::<IFeeManager::collectedFeesByValidatorCall>(calldata, |call| {
                        self.collected_fees.at(call.validator).read()
                    })
                } else {
                    unknown_selector(selector, self.storage.gas_used(), self.storage.spec())
                }
            }
            ITIPFeeAMM::mintCall::SELECTOR => {
                mutate::<ITIPFeeAMM::mintCall>(calldata, msg_sender, |s, call| {
                    if self.storage.spec().is_moderato() {
                        Err(TempoPrecompileError::UnknownFunctionSelector(
                            ITIPFeeAMM::mintCall::SELECTOR,
                        ))
                    } else {
                        self.mint(
                            s,
                            call.userToken,
                            call.validatorToken,
                            call.amountUserToken,
                            call.amountValidatorToken,
                            call.to,
                        )
                    }
                })
            }
            ITIPFeeAMM::mintWithValidatorTokenCall::SELECTOR => {
                mutate::<ITIPFeeAMM::mintWithValidatorTokenCall>(calldata, msg_sender, |s, call| {
                    self.mint_with_validator_token(
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

            _ => unknown_selector(selector, self.storage.gas_used(), self.storage.spec()),
        };

        result.map(|res| fill_precompile_output(res, &mut self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Precompile, TIP_FEE_MANAGER_ADDRESS, expect_precompile_revert,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{TIP20Setup, assert_full_coverage, check_selector_coverage},
        tip_fee_manager::{
            FeeManagerError,
            amm::{MIN_LIQUIDITY, PoolKey},
        },
    };
    use alloy::{
        primitives::{Address, B256, Bytes, U256},
        sol_types::{SolCall, SolError, SolValue},
    };
    use revm::precompile::PrecompileError;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IFeeManager::IFeeManagerCalls, ITIPFeeAMM::ITIPFeeAMMCalls, UnknownFunctionSelector,
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
    fn test_execute_block() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Call executeBlock (only system contract can call, so sender = Address::ZERO)
            let call = IFeeManager::executeBlockCall {};
            let result = fee_manager.call(&call.abi_encode(), Address::ZERO)?;
            assert_eq!(result.gas_used, 0);

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

    #[test]
    fn test_mint_with_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(1000000_u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(1000000_u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Get pool ID first
            let pool_id_call = ITIPFeeAMM::getPoolIdCall {
                userToken: user_token.address(),
                validatorToken: validator_token.address(),
            };
            let pool_id_result = fee_manager.call(&pool_id_call.abi_encode(), user)?;
            let pool_id = B256::abi_decode(&pool_id_result.bytes)?;

            // Check initial total supply
            let initial_supply_call = ITIPFeeAMM::totalSupplyCall { poolId: pool_id };
            let initial_supply_result =
                fee_manager.call(&initial_supply_call.abi_encode(), user)?;
            let initial_supply = U256::abi_decode(&initial_supply_result.bytes)?;
            assert_eq!(initial_supply, U256::ZERO);

            // Mint with validator token only
            let amount_validator_token = U256::from(10000_u64);
            let call = ITIPFeeAMM::mintWithValidatorTokenCall {
                userToken: user_token.address(),
                validatorToken: validator_token.address(),
                amountValidatorToken: amount_validator_token,
                to: user,
            };
            let result = fee_manager.call(&call.abi_encode(), user)?;

            // For first mint with validator token only, liquidity should be (amount / 2) - MIN_LIQUIDITY
            // MIN_LIQUIDITY = 1000, so (10000 / 2) - 1000 = 4000
            let liquidity = U256::abi_decode(&result.bytes)?;
            assert_eq!(liquidity, U256::from(4000_u64));

            // Check total supply after mint = liquidity + MIN_LIQUIDITY
            let final_supply_call = ITIPFeeAMM::totalSupplyCall { poolId: pool_id };
            let final_supply_result = fee_manager.call(&final_supply_call.abi_encode(), user)?;
            let final_supply = U256::abi_decode(&final_supply_result.bytes)?;
            assert_eq!(final_supply, liquidity + MIN_LIQUIDITY);

            // Verify pool state
            let pool_call = ITIPFeeAMM::getPoolCall {
                userToken: user_token.address(),
                validatorToken: validator_token.address(),
            };
            let pool_result = fee_manager.call(&pool_call.abi_encode(), user)?;
            let pool = ITIPFeeAMM::Pool::abi_decode(&pool_result.bytes)?;
            assert_eq!(pool.reserveUserToken, 0);
            assert_eq!(pool.reserveValidatorToken, 10000);

            // Verify LP token balance
            let balance_call = ITIPFeeAMM::liquidityBalancesCall {
                poolId: pool_id,
                user,
            };
            let balance_result = fee_manager.call(&balance_call.abi_encode(), user)?;
            let balance = U256::abi_decode(&balance_result.bytes)?;
            assert_eq!(balance, liquidity);

            Ok(())
        })
    }

    #[test]
    fn test_unknown_selector_error_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Call with an unknown selector
            let unknown_selector = [0x12, 0x34, 0x56, 0x78];
            let calldata = Bytes::from(unknown_selector);
            let result = fee_manager.call(&calldata, sender);

            // Before Moderato: should return Err(PrecompileError::Other)
            assert!(result.is_err());
            assert!(matches!(result, Err(PrecompileError::Other(_))));

            Ok(())
        })
    }

    #[test]
    fn test_unknown_selector_error_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let sender = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut fee_manager = TipFeeManager::new();

            // Call with an unknown selector
            let unknown_selector = [0x12, 0x34, 0x56, 0x78];
            let calldata = Bytes::from(unknown_selector);
            let result = fee_manager.call(&calldata, sender);

            // After Moderato: should return Ok with reverted status
            assert!(result.is_ok());
            let output = result.unwrap();
            assert!(output.reverted);

            // Verify the error can be decoded as UnknownFunctionSelector
            let decoded_error = UnknownFunctionSelector::abi_decode(&output.bytes);
            assert!(
                decoded_error.is_ok(),
                "Should decode as UnknownFunctionSelector"
            );

            // Verify the selector matches what we sent
            let error = decoded_error.unwrap();
            assert_eq!(error.selector.as_slice(), &unknown_selector);

            Ok(())
        })
    }

    #[test]
    fn test_mint_deprecated_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
        let admin = Address::random();
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(1000000_u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(1000000_u64))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let call = ITIPFeeAMM::mintCall {
                userToken: user_token.address(),
                validatorToken: validator_token.address(),
                amountUserToken: U256::from(1000_u64),
                amountValidatorToken: U256::from(1000_u64),
                to: user,
            };

            let result = fee_manager.call(&call.abi_encode(), user);

            // Should return Ok with reverted status for unknown function selector
            assert!(result.is_ok());
            let output = result.unwrap();
            assert!(output.reverted);

            // Verify the error can be decoded as UnknownFunctionSelector
            let decoded_error = UnknownFunctionSelector::abi_decode(&output.bytes);
            assert!(
                decoded_error.is_ok(),
                "Should decode as UnknownFunctionSelector"
            );

            // Verify it's the mint selector
            let error = decoded_error.unwrap();
            assert_eq!(error.selector.as_slice(), &ITIPFeeAMM::mintCall::SELECTOR);

            Ok(())
        })
    }
}
