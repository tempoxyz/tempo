use crate::{
    Precompile,
    error::TempoPrecompileError,
    fill_precompile_output, input_cost, mutate, mutate_void,
    storage::PrecompileStorageProvider,
    tip_fee_manager::{
        IFeeManager, ITIPFeeAMM, TipFeeManager,
        amm::{M, MIN_LIQUIDITY, N, SCALE},
    },
    unknown_selector, view,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileError, PrecompileResult};

impl<'a, S: PrecompileStorageProvider> Precompile for TipFeeManager<'a, S> {
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
                let pool = self.sload_pools(call.poolId)?;

                Ok(ITIPFeeAMM::Pool {
                    reserveUserToken: pool.reserve_user_token,
                    reserveValidatorToken: pool.reserve_validator_token,
                })
            }),
            ITIPFeeAMM::totalSupplyCall::SELECTOR => {
                view::<ITIPFeeAMM::totalSupplyCall>(calldata, |call| {
                    self.sload_total_supply(call.poolId)
                })
            }
            ITIPFeeAMM::liquidityBalancesCall::SELECTOR => {
                view::<ITIPFeeAMM::liquidityBalancesCall>(calldata, |call| {
                    self.sload_liquidity_balances(call.poolId, call.user)
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
                mutate_void::<IFeeManager::executeBlockCall>(calldata, msg_sender, |s, _call| {
                    self.execute_block(s, self.storage.beneficiary())
                })
            }
            // Protocol-only functions - these are called directly by the protocol,
            // not through external transactions. Return error if called externally.
            IFeeManager::collectFeePreTxCall::SELECTOR => {
                mutate::<IFeeManager::collectFeePreTxCall>(calldata, msg_sender, |s, call| {
                    if s != Address::ZERO {
                        return Err(
                            crate::tip_fee_manager::FeeManagerError::only_system_contract().into(),
                        );
                    }
                    // Determine fee token from user preferences or default
                    let user_token = self.sload_user_tokens(call.user)?;
                    let fee_token = if user_token.is_zero() {
                        self.default_fee_token()
                    } else {
                        user_token
                    };
                    self.collect_fee_pre_tx(call.user, fee_token, call.maxAmount, call.feeRecipient)
                })
            }
            IFeeManager::collectFeePostTxCall::SELECTOR => {
                mutate_void::<IFeeManager::collectFeePostTxCall>(calldata, msg_sender, |s, call| {
                    if s != Address::ZERO {
                        return Err(
                            crate::tip_fee_manager::FeeManagerError::only_system_contract().into(),
                        );
                    }
                    self.collect_fee_post_tx(
                        call.user,
                        call.actualUsed,
                        call.maxAmount - call.actualUsed,
                        call.userToken,
                        call.feeRecipient,
                    )
                })
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

        result.map(|res| fill_precompile_output(res, self.storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS, expect_precompile_revert,
        storage::hashmap::HashMapStorageProvider,
        test_util::check_selector_coverage,
        tip_fee_manager::{
            TIPFeeAMMError, TipFeeManager,
            amm::{MIN_LIQUIDITY, PoolKey},
        },
        tip20::{ISSUER_ROLE, ITIP20, TIP20Token, tests::initialize_path_usd, token_id_to_address},
    };
    use alloy::{
        primitives::{Address, B256, Bytes, U256},
        sol_types::{SolError, SolValue},
    };
    use eyre::Result;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        IFeeManager::IFeeManagerCalls, ITIPFeeAMM::ITIPFeeAMMCalls, UnknownFunctionSelector,
    };

    fn setup_token_with_balance(
        storage: &mut HashMapStorageProvider,
        token: Address,
        user: Address,
        amount: U256,
    ) {
        initialize_path_usd(storage, user).unwrap();
        let mut tip20_token = TIP20Token::from_address(token, storage);

        // Initialize token
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                user,
                Address::ZERO,
            )
            .unwrap();

        // Grant issuer role to user and mint tokens
        tip20_token.grant_role_internal(user, *ISSUER_ROLE).unwrap();

        tip20_token
            .mint(user, ITIP20::mintCall { to: user, amount })
            .unwrap();

        // Approve fee manager to spend user's tokens
        tip20_token
            .approve(
                user,
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
        let validator = Address::random();
        let admin = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, admin).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        let calldata = IFeeManager::setValidatorTokenCall { token }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), validator)?;
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify token was set
        let calldata = IFeeManager::validatorTokensCall { validator }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), validator)?;
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let returned_token = Address::abi_decode(&result.bytes)?;
        assert_eq!(returned_token, token);

        Ok(())
    }

    #[test]
    fn test_set_validator_token_zero_address() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);
        let validator = Address::random();

        let calldata = IFeeManager::setValidatorTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), validator);
        expect_precompile_revert(&result, TIPFeeAMMError::invalid_token());

        Ok(())
    }

    #[test]
    fn test_set_user_token() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let admin = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, admin).unwrap();

        // Create a USD token to use as fee token
        let token = token_id_to_address(1);
        let mut tip20_token = TIP20Token::from_address(token, &mut storage);
        tip20_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut fee_manager = TipFeeManager::new(&mut storage);

        let calldata = IFeeManager::setUserTokenCall { token }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), user)?;
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        // Verify token was set
        let calldata = IFeeManager::userTokensCall { user }.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), user)?;
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);
        let returned_token = Address::abi_decode(&result.bytes)?;
        assert_eq!(returned_token, token);

        Ok(())
    }

    #[test]
    fn test_set_user_token_zero_address() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);
        let user = Address::random();

        let calldata = IFeeManager::setUserTokenCall {
            token: Address::ZERO,
        }
        .abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), user);
        expect_precompile_revert(&result, TIPFeeAMMError::invalid_token());
    }

    #[test]
    fn test_get_pool_id() {
        let mut storage = HashMapStorageProvider::new(1);

        let mut fee_manager = TipFeeManager::new(&mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        let calldata = ITIPFeeAMM::getPoolIdCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        let calldata = calldata.abi_encode();
        let result = fee_manager
            .call(&Bytes::from(calldata), Address::random())
            .unwrap();
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);

        let returned_id = B256::abi_decode(&result.bytes).unwrap();
        let expected_id = PoolKey::new(token_a, token_b).get_id();
        assert_eq!(returned_id, expected_id);
    }

    #[test]
    fn test_tip_fee_amm_pool_operations() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);

        let token_a = Address::random();
        let token_b = Address::random();

        // Get pool using ITIPFeeAMM interface
        let get_pool_call = ITIPFeeAMM::getPoolCall {
            userToken: token_a,
            validatorToken: token_b,
        };
        let calldata = get_pool_call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), Address::random())?;
        // HashMapStorageProvider does not do gas accounting, so we expect 0 here.
        assert_eq!(result.gas_used, 0);

        // Decode and verify pool
        let pool = ITIPFeeAMM::Pool::abi_decode(&result.bytes)?;
        assert_eq!(pool.reserveUserToken, 0);
        assert_eq!(pool.reserveValidatorToken, 0);

        Ok(())
    }

    #[test]
    fn test_pool_id_calculation() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);
        let token_a = Address::random();
        let token_b = Address::random();

        // Test that pool ID is same regardless of token order
        let calldata1 = ITIPFeeAMM::getPoolIdCall {
            userToken: token_a,
            validatorToken: token_b,
        }
        .abi_encode();
        let result1 = fee_manager
            .call(&Bytes::from(calldata1), Address::random())
            .unwrap();
        let id1 = B256::abi_decode(&result1.bytes).unwrap();

        let calldata2 = ITIPFeeAMM::getPoolIdCall {
            userToken: token_b,
            validatorToken: token_a,
        }
        .abi_encode();
        let result2 = fee_manager
            .call(&Bytes::from(calldata2), Address::random())
            .unwrap();
        let id2 = B256::abi_decode(&result2.bytes).unwrap();

        // Pool IDs should be the same since tokens are not ordered in FeeAMM (unlike TIPFeeAMM)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_fee_manager_invalid_token_error() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);
        let user = Address::random();
        let validator = Address::random();

        // Test that IFeeManager properly validates tokens (zero address)
        let set_validator_call = IFeeManager::setValidatorTokenCall {
            token: Address::ZERO,
        };
        let result = fee_manager.call(&Bytes::from(set_validator_call.abi_encode()), validator);
        expect_precompile_revert(&result, TIPFeeAMMError::invalid_token());

        let set_user_call = IFeeManager::setUserTokenCall {
            token: Address::ZERO,
        };
        let result = fee_manager.call(&Bytes::from(set_user_call.abi_encode()), user);
        expect_precompile_revert(&result, TIPFeeAMMError::invalid_token());
    }

    #[test]
    fn test_execute_block() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let token = Address::random();

        // Setup token
        let user = Address::random();
        setup_token_with_balance(&mut storage, token, user, U256::MAX);

        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Call executeBlock (only system contract can call)
        let call = IFeeManager::executeBlockCall {};
        let result = fee_manager.call(&Bytes::from(call.abi_encode()), Address::ZERO)?;
        // HashMapStorageProvider does not have gas accounting, so we expect 0
        assert_eq!(result.gas_used, 0);

        Ok(())
    }

    #[test]
    fn tip_fee_manager_test_selector_coverage() {
        use crate::test_util::assert_full_coverage;

        let mut storage = HashMapStorageProvider::new(1);
        let mut fee_manager = TipFeeManager::new(&mut storage);

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
    }

    #[test]
    fn test_mint_with_validator_token() -> Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let admin = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(&mut storage, admin)?;

        // Create two USD tokens
        let user_token = token_id_to_address(1);
        let validator_token = token_id_to_address(2);

        // Setup both tokens
        setup_token_with_balance(&mut storage, user_token, user, U256::from(1000000u64));
        setup_token_with_balance(&mut storage, validator_token, user, U256::from(1000000u64));

        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Get pool ID first
        let pool_id_call = ITIPFeeAMM::getPoolIdCall {
            userToken: user_token,
            validatorToken: validator_token,
        };
        let pool_id_result = fee_manager.call(&Bytes::from(pool_id_call.abi_encode()), user)?;
        let pool_id = B256::abi_decode(&pool_id_result.bytes)?;

        // Check initial total supply
        let initial_total_supply_call = ITIPFeeAMM::totalSupplyCall { poolId: pool_id };
        let initial_total_supply_result =
            fee_manager.call(&Bytes::from(initial_total_supply_call.abi_encode()), user)?;
        let initial_total_supply = U256::abi_decode(&initial_total_supply_result.bytes)?;
        assert_eq!(initial_total_supply, U256::ZERO);

        // Test minting with validator token only
        let amount_validator_token = U256::from(10000u64);
        let to = user;

        let call = ITIPFeeAMM::mintWithValidatorTokenCall {
            userToken: user_token,
            validatorToken: validator_token,
            amountValidatorToken: amount_validator_token,
            to,
        };

        let calldata = call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), user)?;

        // Should return liquidity amount
        let liquidity = U256::abi_decode(&result.bytes)?;

        // For first mint with validator token only, liquidity should be (amount / 2) - MIN_LIQUIDITY
        // MIN_LIQUIDITY = 1000, so (10000 / 2) - 1000 = 4000
        assert_eq!(liquidity, U256::from(4000u64));

        // Check total supply after mint should equal liquidity + MIN_LIQUIDITY
        let final_total_supply_call = ITIPFeeAMM::totalSupplyCall { poolId: pool_id };
        let final_total_supply_result =
            fee_manager.call(&Bytes::from(final_total_supply_call.abi_encode()), user)?;
        let final_total_supply = U256::abi_decode(&final_total_supply_result.bytes)?;

        let expected_total_supply = liquidity + MIN_LIQUIDITY;
        assert_eq!(final_total_supply, expected_total_supply);

        // Verify total supply increased by the expected amount
        let total_supply_increase = final_total_supply - initial_total_supply;
        assert_eq!(total_supply_increase, expected_total_supply);

        // Verify pool state
        let pool_call = ITIPFeeAMM::getPoolCall {
            userToken: user_token,
            validatorToken: validator_token,
        };
        let pool_result = fee_manager.call(&Bytes::from(pool_call.abi_encode()), user)?;
        let pool = ITIPFeeAMM::Pool::abi_decode(&pool_result.bytes)?;

        assert_eq!(pool.reserveUserToken, 0);
        assert_eq!(pool.reserveValidatorToken, 10000);

        // Verify LP token balance
        let balance_call = ITIPFeeAMM::liquidityBalancesCall {
            poolId: pool_id,
            user: to,
        };
        let balance_result = fee_manager.call(&Bytes::from(balance_call.abi_encode()), user)?;
        let balance = U256::abi_decode(&balance_result.bytes)?;

        assert_eq!(balance, liquidity);

        Ok(())
    }

    #[test]
    fn test_unknown_selector_error_pre_moderato() {
        use tempo_chainspec::hardfork::TempoHardfork;
        // Before Moderato: should return generic PrecompileError::Other
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Adagio);
        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Call with an unknown selector (0x12345678)
        let unknown_selector = [0x12, 0x34, 0x56, 0x78];
        let calldata = Bytes::from(unknown_selector);
        let result = fee_manager.call(&calldata, Address::random());

        // Should return Err(PrecompileError::Other)
        assert!(result.is_err());
        assert!(matches!(result, Err(PrecompileError::Other(_))));
    }

    #[test]
    fn test_unknown_selector_error_post_moderato() {
        use tempo_chainspec::hardfork::TempoHardfork;
        // After Moderato: should return ABI-encoded error with selector
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let mut fee_manager = TipFeeManager::new(&mut storage);

        // Call with an unknown selector (0x12345678)
        let unknown_selector = [0x12, 0x34, 0x56, 0x78];
        let calldata = Bytes::from(unknown_selector);
        let result = fee_manager.call(&calldata, Address::random());

        // Should return Ok with reverted status
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
    }

    #[test]
    fn test_mint_deprecated_post_moderato() {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::Moderato);
        let user = Address::random();
        let admin = Address::random();
        initialize_path_usd(&mut storage, admin).unwrap();

        let user_token = token_id_to_address(1);
        let validator_token = token_id_to_address(2);

        setup_token_with_balance(&mut storage, user_token, user, U256::from(1000000u64));
        setup_token_with_balance(&mut storage, validator_token, user, U256::from(1000000u64));

        let mut fee_manager = TipFeeManager::new(&mut storage);

        let call = ITIPFeeAMM::mintCall {
            userToken: user_token,
            validatorToken: validator_token,
            amountUserToken: U256::from(1000u64),
            amountValidatorToken: U256::from(1000u64),
            to: user,
        };

        let calldata = call.abi_encode();
        let result = fee_manager.call(&Bytes::from(calldata), user);

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
    }
}
