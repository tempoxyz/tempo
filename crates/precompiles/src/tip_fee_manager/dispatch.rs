use crate::{
    Precompile, dispatch_call, input_cost, mutate, mutate_void,
    storage::Handler,
    tip_fee_manager::{
        ITIPFeeAMM, TipFeeManager,
        amm::{M, MIN_LIQUIDITY, N, SCALE},
    },
    view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::{IFeeManager::IFeeManagerCalls, ITIPFeeAMM::ITIPFeeAMMCalls};

/// Combined enum for dispatching to either IFeeManager or ITIPFeeAMM
enum TipFeeManagerCall {
    FeeManager(IFeeManagerCalls),
    Amm(ITIPFeeAMMCalls),
}

impl TipFeeManagerCall {
    fn decode(calldata: &[u8]) -> Result<Self, alloy::sol_types::Error> {
        match IFeeManagerCalls::abi_decode(calldata) {
            Ok(call) => return Ok(Self::FeeManager(call)),
            Err(alloy::sol_types::Error::UnknownSelector { .. }) => {}
            Err(e) => return Err(e),
        }
        ITIPFeeAMMCalls::abi_decode(calldata).map(Self::Amm)
    }
}

impl Precompile for TipFeeManager {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(calldata, TipFeeManagerCall::decode, |call| match call {
            // IFeeManager functions
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::userTokens(call)) => {
                view(call, |c| self.user_tokens(c))
            }
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::validatorTokens(call)) => {
                view(call, |c| self.validator_tokens(c))
            }
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::setValidatorToken(call)) => {
                mutate_void(call, msg_sender, |s, c| {
                    let beneficiary = self.storage.beneficiary();
                    self.set_validator_token(s, c, beneficiary)
                })
            }
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::setUserToken(call)) => {
                mutate_void(call, msg_sender, |s, c| self.set_user_token(s, c))
            }
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::distributeFees(call)) => {
                mutate_void(call, msg_sender, |_, c| {
                    self.distribute_fees(c.validator, c.token)
                })
            }
            TipFeeManagerCall::FeeManager(IFeeManagerCalls::collectedFees(call)) => {
                view(call, |c| self.collected_fees[c.validator][c.token].read())
            }

            // ITIPFeeAMM functions
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::getPoolId(call)) => {
                view(call, |c| Ok(self.pool_id(c.userToken, c.validatorToken)))
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::getPool(call)) => view(call, |c| {
                let pool = self.get_pool(c)?;
                Ok(ITIPFeeAMM::Pool {
                    reserveUserToken: pool.reserve_user_token,
                    reserveValidatorToken: pool.reserve_validator_token,
                })
            }),
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::pools(call)) => view(call, |c| {
                let pool = self.pools[c.poolId].read()?;
                Ok(ITIPFeeAMM::Pool {
                    reserveUserToken: pool.reserve_user_token,
                    reserveValidatorToken: pool.reserve_validator_token,
                })
            }),
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::totalSupply(call)) => {
                view(call, |c| self.total_supply[c.poolId].read())
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::liquidityBalances(call)) => {
                view(call, |c| self.liquidity_balances[c.poolId][c.user].read())
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::M(call)) => view(call, |_| Ok(M)),
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::N(call)) => view(call, |_| Ok(N)),
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::SCALE(call)) => view(call, |_| Ok(SCALE)),
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::MIN_LIQUIDITY(call)) => {
                view(call, |_| Ok(MIN_LIQUIDITY))
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::mint(call)) => {
                mutate(call, msg_sender, |s, c| {
                    self.mint(
                        s,
                        c.userToken,
                        c.validatorToken,
                        c.amountValidatorToken,
                        c.to,
                    )
                })
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::burn(call)) => {
                mutate(call, msg_sender, |s, c| {
                    let (amount_user_token, amount_validator_token) =
                        self.burn(s, c.userToken, c.validatorToken, c.liquidity, c.to)?;
                    Ok(ITIPFeeAMM::burnReturn {
                        amountUserToken: amount_user_token,
                        amountValidatorToken: amount_validator_token,
                    })
                })
            }
            TipFeeManagerCall::Amm(ITIPFeeAMMCalls::rebalanceSwap(call)) => {
                mutate(call, msg_sender, |s, c| {
                    self.rebalance_swap(s, c.userToken, c.validatorToken, c.amountOut, c.to)
                })
            }
        })
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
        IFeeManager, IFeeManager::IFeeManagerCalls, ITIPFeeAMM, ITIPFeeAMM::ITIPFeeAMMCalls,
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
