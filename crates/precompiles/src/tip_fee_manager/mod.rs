pub mod amm;
pub mod dispatch;

use crate::{
    error::{Result, TempoPrecompileError},
    storage::{Handler, Mapping},
    tip_fee_manager::amm::{Pool, compute_amount_out},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
    tip20_factory::TIP20Factory,
};
use alloy::primitives::B256;
pub use tempo_contracts::precompiles::{
    DEFAULT_FEE_TOKEN, FeeManagerError, FeeManagerEvent, IFeeManager, ITIPFeeAMM,
    TIP_FEE_MANAGER_ADDRESS, TIPFeeAMMError, TIPFeeAMMEvent,
};
// Re-export PoolKey for backward compatibility with tests
use alloy::primitives::{Address, U256, uint};
use tempo_precompiles_macros::contract;

#[contract(addr = TIP_FEE_MANAGER_ADDRESS)]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, Mapping<Address, U256>>,
    pools: Mapping<B256, Pool>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,
    /// Reserved liquidity per pool - tracks pending fee swaps to prevent TOCTOU attacks.
    /// This is subtracted from available reserves when checking liquidity for burn/rebalance.
    reserved_liquidity: Mapping<B256, u128>,
}

impl TipFeeManager {
    // Constants
    pub const FEE_BPS: u64 = 25; // 0.25% fee
    pub const BASIS_POINTS: u64 = 10000;
    pub const MINIMUM_BALANCE: U256 = uint!(1_000_000_000_U256); // 1e9

    /// Initializes the contract
    ///
    /// This ensures the [`TipFeeManager`] isn't empty and prevents state clear.
    pub fn initialize(&mut self) -> Result<()> {
        self.__initialize()
    }

    pub fn get_validator_token(&self, beneficiary: Address) -> Result<Address> {
        let token = self.validator_tokens[beneficiary].read()?;

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    pub fn set_validator_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setValidatorTokenCall,
        beneficiary: Address,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Prevent changing within the validator's own block
        if sender == beneficiary {
            return Err(FeeManagerError::cannot_change_within_block().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        self.validator_tokens[sender].write(call.token)?;

        // Emit ValidatorTokenSet event
        self.emit_event(FeeManagerEvent::ValidatorTokenSet(
            IFeeManager::ValidatorTokenSet {
                validator: sender,
                token: call.token,
            },
        ))
    }

    pub fn set_user_token(
        &mut self,
        sender: Address,
        call: IFeeManager::setUserTokenCall,
    ) -> Result<()> {
        // Validate that the token is a valid deployed TIP20
        if !TIP20Factory::new().is_tip20(call.token)? {
            return Err(FeeManagerError::invalid_token().into());
        }

        // Validate that the fee token is USD
        validate_usd_currency(call.token)?;

        self.user_tokens[sender].write(call.token)?;

        // Emit UserTokenSet event
        self.emit_event(FeeManagerEvent::UserTokenSet(IFeeManager::UserTokenSet {
            user: sender,
            token: call.token,
        }))
    }

    /// Collects fees from user before transaction execution.
    ///
    /// Transfers max fee to fee manager and checks liquidity for swaps if user and validator tokens differ.
    /// After tx execution, collect_fee_post_tx refunds unused gas and executes the swap immediately.
    pub fn collect_fee_pre_tx(
        &mut self,
        fee_payer: Address,
        user_token: Address,
        max_amount: U256,
        beneficiary: Address,
    ) -> Result<Address> {
        // Get the validator's token preference
        let validator_token = self.get_validator_token(beneficiary)?;

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        // Ensure that user and FeeManager are authorized to interact with the token
        tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        if user_token != validator_token {
            self.check_sufficient_liquidity(user_token, validator_token, max_amount)?;
        }

        // Return the user's token preference
        Ok(user_token)
    }

    /// Finalizes fee collection after transaction execution.
    ///
    /// Refunds unused tokens to user, executes fee swap if needed, and accumulates fees for the validator.
    /// Validators call distribute_fees() to collect accumulated fees.
    pub fn collect_fee_post_tx(
        &mut self,
        fee_payer: Address,
        actual_spending: U256,
        refund_amount: U256,
        fee_token: Address,
        beneficiary: Address,
    ) -> Result<()> {
        // Refund unused tokens to user
        let mut tip20_token = TIP20Token::from_address(fee_token)?;
        tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;

        // Execute fee swap and track collected fees
        let validator_token = self.get_validator_token(beneficiary)?;

        if fee_token != validator_token {
            // Release the liquidity reservation made in collect_fee_pre_tx
            // max_amount = actual_spending + refund_amount
            let max_amount = actual_spending
                .checked_add(refund_amount)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.release_liquidity_reservation(fee_token, validator_token, max_amount)?;

            // Record the pool if there was a non-zero swap
            if !actual_spending.is_zero() {
                // Execute fee swap immediately and accumulate fees
                self.execute_fee_swap(fee_token, validator_token, actual_spending)?;
            }
        }

        let amount = if fee_token == validator_token {
            actual_spending
        } else {
            compute_amount_out(actual_spending)?
        };

        self.increment_collected_fees(beneficiary, validator_token, amount)?;

        Ok(())
    }

    /// Increment collected fees for a specific validator and token combination.
    fn increment_collected_fees(
        &mut self,
        validator: Address,
        token: Address,
        amount: U256,
    ) -> Result<()> {
        if amount.is_zero() {
            return Ok(());
        }

        let collected_fees = self.collected_fees[validator][token].read()?;
        self.collected_fees[validator][token].write(
            collected_fees
                .checked_add(amount)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(())
    }

    /// Transfers the validator's fee balance for a specific token to their address.
    pub fn distribute_fees(&mut self, validator: Address, token: Address) -> Result<()> {
        let amount = self.collected_fees[validator][token].read()?;
        if amount.is_zero() {
            return Ok(());
        }
        self.collected_fees[validator][token].write(U256::ZERO)?;

        // Transfer fees to validator
        let mut tip20_token = TIP20Token::from_address(token)?;
        tip20_token.transfer(
            self.address,
            ITIP20::transferCall {
                to: validator,
                amount,
            },
        )?;

        // Emit FeesDistributed event
        self.emit_event(FeeManagerEvent::FeesDistributed(
            IFeeManager::FeesDistributed {
                validator,
                token,
                amount,
            },
        ))?;

        Ok(())
    }

    pub fn user_tokens(&self, call: IFeeManager::userTokensCall) -> Result<Address> {
        self.user_tokens[call.user].read()
    }

    pub fn validator_tokens(&self, call: IFeeManager::validatorTokensCall) -> Result<Address> {
        let token = self.validator_tokens[call.validator].read()?;

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{ITIP20, TIP20Token},
    };

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;

            // TODO: loop through and deploy and set user token for some range

            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setUserTokenCall {
                token: token.address(),
            };
            let result = fee_manager.set_user_token(user, call);
            assert!(result.is_ok());

            let call = IFeeManager::userTokensCall { user };
            assert_eq!(fee_manager.user_tokens(call)?, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            };

            // Should fail when validator == beneficiary (same block check)
            let result = fee_manager.set_validator_token(validator, call.clone(), validator);
            assert_eq!(
                result,
                Err(TempoPrecompileError::FeeManagerError(
                    FeeManagerError::cannot_change_within_block()
                ))
            );

            // Should succeed with different beneficiary
            let result = fee_manager.set_validator_token(validator, call, beneficiary);
            assert!(result.is_ok());

            let query_call = IFeeManager::validatorTokensCall { validator };
            let returned_token = fee_manager.validator_tokens(query_call)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token_cannot_change_within_block() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let beneficiary = Address::random();
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let call = IFeeManager::setValidatorTokenCall {
                token: token.address(),
            };

            // Setting validator token when not beneficiary should succeed
            let result = fee_manager.set_validator_token(validator, call.clone(), beneficiary);
            assert!(result.is_ok());

            // But if validator is the beneficiary, should fail with CannotChangeWithinBlock
            let result = fee_manager.set_validator_token(validator, call, validator);
            assert_eq!(
                result,
                Err(TempoPrecompileError::FeeManagerError(
                    FeeManagerError::cannot_change_within_block()
                ))
            );

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let max_amount = U256::from(10000);

            let token = TIP20Setup::create("Test", "TST", user)
                .with_issuer(user)
                .with_mint(user, U256::from(u64::MAX))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator token (use beneficiary to avoid CannotChangeWithinBlock)
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                beneficiary,
            )?;

            // Set user token
            fee_manager.set_user_token(
                user,
                IFeeManager::setUserTokenCall {
                    token: token.address(),
                },
            )?;

            // Call collect_fee_pre_tx directly
            let result =
                fee_manager.collect_fee_pre_tx(user, token.address(), max_amount, validator);
            assert!(result.is_ok());
            assert_eq!(result?, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_post_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let admin = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            let actual_used = U256::from(6000);
            let refund_amount = U256::from(4000);

            // Mint to FeeManager (simulating collect_fee_pre_tx already happened)
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000000000000_u64))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator token (use beneficiary to avoid CannotChangeWithinBlock)
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                beneficiary,
            )?;

            // Set user token
            fee_manager.set_user_token(
                user,
                IFeeManager::setUserTokenCall {
                    token: token.address(),
                },
            )?;

            // Call collect_fee_post_tx directly
            let result = fee_manager.collect_fee_post_tx(
                user,
                actual_used,
                refund_amount,
                token.address(),
                validator,
            );
            assert!(result.is_ok());

            // Verify fees were tracked
            let tracked_amount = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(tracked_amount, actual_used);

            // Verify user got the refund
            let balance = token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(balance, refund_amount);

            Ok(())
        })
    }

    #[test]
    fn test_rejects_non_usd() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();
        let beneficiary = Address::random();
        StorageCtx::enter(&mut storage, || {
            // Create a non-USD token
            let non_usd_token = TIP20Setup::create("NonUSD", "EUR", admin)
                .currency("EUR")
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Try to set non-USD as user token - should fail
            let call = IFeeManager::setUserTokenCall {
                token: non_usd_token.address(),
            };
            let result = fee_manager.set_user_token(user, call);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            // Try to set non-USD as validator token - should also fail
            let call = IFeeManager::setValidatorTokenCall {
                token: non_usd_token.address(),
            };
            let result = fee_manager.set_validator_token(validator, call, beneficiary);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx with different tokens
    /// Verifies that liquidity is checked (not reserved) and no swap happens yet
    #[test]
    fn test_collect_fee_pre_tx_different_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Create two different tokens
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Setup pool with liquidity
            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            // Set validator's preferred token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);

            // Call collect_fee_pre_tx
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // With different tokens:
            // - Liquidity is checked (not reserved)
            // - No swap happens yet (swap happens in collect_fee_post_tx)
            // - collected_fees should be zero
            let collected =
                fee_manager.collected_fees[validator][validator_token.address()].read()?;
            assert_eq!(
                collected,
                U256::ZERO,
                "Different tokens: no fees accumulated in pre_tx (swap happens in post_tx)"
            );

            // Pool reserves should NOT be updated yet
            let pool = fee_manager.pools[pool_id].read()?;
            assert_eq!(
                pool.reserve_user_token, 10000,
                "Reserves unchanged in pre_tx"
            );
            assert_eq!(
                pool.reserve_validator_token, 10000,
                "Reserves unchanged in pre_tx"
            );

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_post_tx_immediate_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);
            let actual_spending = U256::from(800);
            let refund_amount = U256::from(200);

            // First call collect_fee_pre_tx (checks liquidity)
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Then call collect_fee_post_tx (executes swap immediately)
            fee_manager.collect_fee_post_tx(
                user,
                actual_spending,
                refund_amount,
                user_token.address(),
                validator,
            )?;

            // Expected output: 800 * 9970 / 10000 = 797
            let expected_fee_amount = (actual_spending * U256::from(9970)) / U256::from(10000);
            let collected =
                fee_manager.collected_fees[validator][validator_token.address()].read()?;
            assert_eq!(collected, expected_fee_amount);

            // Pool reserves should be updated
            let pool = fee_manager.pools[pool_id].read()?;
            assert_eq!(pool.reserve_user_token, 10000 + 800);
            assert_eq!(pool.reserve_validator_token, 10000 - 797);

            // User balance: started with 10000, paid 1000 in pre_tx, got 200 refund = 9200
            let tip20_token = TIP20Token::from_address(user_token.address())?;
            let user_balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(user_balance, U256::from(10000) - max_amount + refund_amount);

            Ok(())
        })
    }

    /// Test collect_fee_pre_tx fails with insufficient liquidity
    #[test]
    fn test_collect_fee_pre_tx_insufficient_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            // Pool with very little validator token liquidity
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 100,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // Try to collect fee that would require more liquidity than available
            // 1000 * 0.997 = 997 output needed, but only 100 available
            let max_amount = U256::from(1000);

            let result =
                fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator);

            assert!(result.is_err(), "Should fail with insufficient liquidity");

            Ok(())
        })
    }

    /// Test distribute_fees with zero balance is a no-op
    #[test]
    fn test_distribute_fees_zero_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("TestToken", "TEST", admin)
                .with_issuer(admin)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                Address::random(),
            )?;

            // collected_fees is zero by default
            let collected = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(collected, U256::ZERO);

            // distribute_fees should be a no-op
            let result = fee_manager.distribute_fees(validator, token.address());
            assert!(result.is_ok(), "Should succeed even with zero balance");

            // Validator balance should still be zero
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance = tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance, U256::ZERO);

            Ok(())
        })
    }

    /// Test distribute_fees transfers accumulated fees to validator
    #[test]
    fn test_distribute_fees() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Initialize token and give fee manager some tokens
            let token = TIP20Setup::create("TestToken", "TEST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(1000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Set validator's preferred token
            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: token.address(),
                },
                Address::random(), // beneficiary != validator
            )?;

            // Simulate accumulated fees
            let fee_amount = U256::from(500);
            fee_manager.collected_fees[validator][token.address()].write(fee_amount)?;

            // Check validator balance before
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_before =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_before, U256::ZERO);

            // Distribute fees
            let mut fee_manager = TipFeeManager::new();
            fee_manager.distribute_fees(validator, token.address())?;

            // Verify validator received the fees
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_after =
                tip20_token.balance_of(ITIP20::balanceOfCall { account: validator })?;
            assert_eq!(balance_after, fee_amount);

            // Verify collected fees cleared
            let fee_manager = TipFeeManager::new();
            let remaining = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(remaining, U256::ZERO);

            Ok(())
        })
    }

    /// Test that burn() respects reserved liquidity from pending fee swaps (T2+).
    /// This prevents the TOCTOU vulnerability where users drain liquidity between
    /// collect_fee_pre_tx and collect_fee_post_tx.
    #[test]
    fn test_burn_respects_reserved_liquidity_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();
        let lp_provider = Address::random();

        StorageCtx::enter(&mut storage, || {
            // Setup: Create tokens and pool
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(lp_provider, U256::from(100000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(lp_provider, U256::from(100000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Setup pool with limited liquidity
            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            // Give LP provider liquidity balance so they can burn
            fee_manager.total_supply[pool_id].write(U256::from(10000))?;
            fee_manager.liquidity_balances[pool_id][lp_provider].write(U256::from(10000))?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // User initiates a fee payment that needs 997 validator tokens output (1000 * 0.997)
            let max_amount = U256::from(1000);
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Now, LP provider tries to burn and drain all validator token liquidity
            // This should FAIL because 997 tokens are reserved for the pending fee swap
            let burn_result = fee_manager.burn(
                lp_provider,
                user_token.address(),
                validator_token.address(),
                U256::from(10000), // Try to burn all LP tokens
                lp_provider,
            );

            // The burn should fail because it would leave insufficient unreserved liquidity
            assert!(
                burn_result.is_err(),
                "Burn should fail when it would violate reserved liquidity"
            );

            Ok(())
        })
    }

    /// Test that reserved liquidity is tracked properly (T2+).
    #[test]
    fn test_reserved_liquidity_tracked_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            // Setup pool with limited liquidity
            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // User initiates a fee payment that needs ~997 validator tokens
            let max_amount = U256::from(1000);
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Swapper tries to rebalance_swap and drain all user tokens (receiving validator tokens as input)
            // rebalance_swap takes validator tokens IN and gives user tokens OUT
            // It reduces reserve_user_token, not reserve_validator_token, so this isn't the attack vector
            // The attack would be via burn() which reduces reserve_validator_token

            // Let's verify reserved liquidity is properly tracked
            let reserved = fee_manager.reserved_liquidity[pool_id].read()?;
            assert_eq!(
                reserved, 997,
                "Should reserve 997 validator tokens (1000 * 0.997)"
            );

            Ok(())
        })
    }

    /// Test that collect_fee_post_tx releases the reservation (T2+).
    #[test]
    fn test_post_tx_releases_reservation_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);
            let actual_spending = U256::from(800);
            let refund_amount = U256::from(200);

            // Pre-tx creates reservation
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            let reserved_before = fee_manager.reserved_liquidity[pool_id].read()?;
            assert!(reserved_before > 0, "Should have reserved liquidity");

            // Post-tx should release reservation
            fee_manager.collect_fee_post_tx(
                user,
                actual_spending,
                refund_amount,
                user_token.address(),
                validator,
            )?;

            let reserved_after = fee_manager.reserved_liquidity[pool_id].read()?;
            assert_eq!(
                reserved_after, 0,
                "Reservation should be released after post_tx"
            );

            Ok(())
        })
    }

    /// Test that pre-T2, burn() does NOT check reserved liquidity (old behavior).
    /// This verifies the TOCTOU vulnerability exists pre-T2 for backward compatibility.
    #[test]
    fn test_burn_ignores_reserved_liquidity_pre_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();
        let lp_provider = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(lp_provider, U256::from(100000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(lp_provider, U256::from(100000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.total_supply[pool_id].write(U256::from(10000))?;
            fee_manager.liquidity_balances[pool_id][lp_provider].write(U256::from(10000))?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            // User initiates a fee payment
            let max_amount = U256::from(1000);
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            // Pre-T2: reserved_liquidity should NOT be updated
            let reserved = fee_manager.reserved_liquidity[pool_id].read()?;
            assert_eq!(reserved, 0, "Pre-T2 should not reserve liquidity");

            // Pre-T2: LP provider CAN burn and drain liquidity (TOCTOU vulnerability exists)
            let burn_result = fee_manager.burn(
                lp_provider,
                user_token.address(),
                validator_token.address(),
                U256::from(10000),
                lp_provider,
            );

            assert!(
                burn_result.is_ok(),
                "Pre-T2: burn should succeed even with pending fee swap (TOCTOU vulnerable)"
            );

            Ok(())
        })
    }

    /// Test that pre-T2, no liquidity reservation is made during collect_fee_pre_tx.
    #[test]
    fn test_no_reservation_pre_t2() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let user = Address::random();
        let validator = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(user, U256::from(10000))
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(10000))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let pool_id = fee_manager.pool_id(user_token.address(), validator_token.address());
            fee_manager.pools[pool_id].write(crate::tip_fee_manager::amm::Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            fee_manager.set_validator_token(
                validator,
                IFeeManager::setValidatorTokenCall {
                    token: validator_token.address(),
                },
                Address::random(),
            )?;

            let max_amount = U256::from(1000);

            // Pre-tx should NOT create reservation in pre-T2
            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;

            let reserved = fee_manager.reserved_liquidity[pool_id].read()?;
            assert_eq!(reserved, 0, "Pre-T2: should NOT reserve liquidity");

            // Post-tx should work fine (no reservation to release)
            let actual_spending = U256::from(800);
            let refund_amount = U256::from(200);
            fee_manager.collect_fee_post_tx(
                user,
                actual_spending,
                refund_amount,
                user_token.address(),
                validator,
            )?;

            let reserved_after = fee_manager.reserved_liquidity[pool_id].read()?;
            assert_eq!(reserved_after, 0, "Pre-T2: reservation should remain zero");

            Ok(())
        })
    }
}
