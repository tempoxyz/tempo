pub mod amm;

use crate::storage::Mapping;
use alloy::primitives::{Address, B256, U256, uint};
use tempo_precompiles_macros::contract;

pub use crate::abi::{
    DEFAULT_FEE_TOKEN,
    ITipFeeManager::{Error, Event, IFeeManager, ITIPFeeAMM, Pool},
    TIP_FEE_MANAGER_ADDRESS,
    tip_fee_manager::abi,
};
use crate::{
    abi::{ITIP20::traits::IToken as _, ITipFeeManager},
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip_fee_manager::amm::{M, MIN_LIQUIDITY, N, SCALE, compute_amount_out},
    tip20::{TIP20Token, validate_usd_currency},
    tip20_factory::{TIP20Factory, abi::traits::IFactory as _},
};

#[contract(addr = TIP_FEE_MANAGER_ADDRESS, abi, dispatch)]
pub struct TipFeeManager {
    validator_tokens: Mapping<Address, Address>,
    user_tokens: Mapping<Address, Address>,
    collected_fees: Mapping<Address, Mapping<Address, U256>>,
    pools: Mapping<B256, Pool>,
    total_supply: Mapping<B256, U256>,
    liquidity_balances: Mapping<B256, Mapping<Address, U256>>,
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
        let validator_token = self.get_validator_token(beneficiary)?;

        let mut tip20_token = TIP20Token::from_address(user_token)?;

        tip20_token.ensure_transfer_authorized(fee_payer, self.address)?;
        tip20_token.transfer_fee_pre_tx(fee_payer, max_amount)?;

        if user_token != validator_token {
            self.check_sufficient_liquidity(user_token, validator_token, max_amount)?;
        }

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
        let mut tip20_token = TIP20Token::from_address(fee_token)?;
        tip20_token.transfer_fee_post_tx(fee_payer, refund_amount, actual_spending)?;

        // Execute fee swap and track collected fees
        let validator_token = self.get_validator_token(beneficiary)?;

        if fee_token != validator_token {
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
        tip20_token.transfer(self.address, validator, amount)?;

        self.emit_event(ITipFeeManager::Event::fees_distributed(
            validator, token, amount,
        ))
    }
}

impl IFeeManager for TipFeeManager {
    fn user_tokens(&self, user: Address) -> Result<Address> {
        self.user_tokens[user].read()
    }

    fn validator_tokens(&self, validator: Address) -> Result<Address> {
        let token = self.validator_tokens[validator].read()?;

        if token.is_zero() {
            Ok(DEFAULT_FEE_TOKEN)
        } else {
            Ok(token)
        }
    }

    fn collected_fees(&self, validator: Address, token: Address) -> Result<U256> {
        self.collected_fees[validator][token].read()
    }

    fn set_user_token(&mut self, msg_sender: Address, token: Address) -> Result<()> {
        if !TIP20Factory::new().is_tip20(token)? {
            return Err(ITipFeeManager::Error::invalid_token().into());
        }

        validate_usd_currency(token)?;

        self.user_tokens[msg_sender].write(token)?;

        self.emit_event(ITipFeeManager::Event::user_token_set(msg_sender, token))
    }

    fn set_validator_token(&mut self, msg_sender: Address, token: Address) -> Result<()> {
        if !TIP20Factory::new().is_tip20(token)? {
            return Err(ITipFeeManager::Error::invalid_token().into());
        }

        let beneficiary = self.storage.beneficiary();
        if msg_sender == beneficiary {
            return Err(ITipFeeManager::Error::cannot_change_within_block().into());
        }

        validate_usd_currency(token)?;

        self.validator_tokens[msg_sender].write(token)?;

        self.emit_event(ITipFeeManager::Event::validator_token_set(
            msg_sender, token,
        ))
    }

    fn distribute_fees(
        &mut self,
        _msg_sender: Address,
        validator: Address,
        token: Address,
    ) -> Result<()> {
        self._distribute_fees(validator, token)
    }
}

impl ITIPFeeAMM for TipFeeManager {
    fn m(&self) -> Result<U256> {
        Ok(M)
    }

    fn n(&self) -> Result<U256> {
        Ok(N)
    }

    fn scale(&self) -> Result<U256> {
        Ok(SCALE)
    }

    fn min_liquidity(&self) -> Result<U256> {
        Ok(MIN_LIQUIDITY)
    }

    fn get_pool_id(&self, user_token: Address, validator_token: Address) -> Result<B256> {
        Ok(self.pool_id(user_token, validator_token))
    }

    fn get_pool(&self, user_token: Address, validator_token: Address) -> Result<Pool> {
        let pool_id = self.pool_id(user_token, validator_token);
        self.pools[pool_id].read()
    }

    fn pools(&self, pool_id: B256) -> Result<Pool> {
        self.pools[pool_id].read()
    }

    fn total_supply(&self, pool_id: B256) -> Result<U256> {
        self.total_supply[pool_id].read()
    }

    fn liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256> {
        self.liquidity_balances[pool_id][user].read()
    }

    fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        self._mint(
            msg_sender,
            user_token,
            validator_token,
            amount_validator_token,
            to,
        )
    }

    fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256)> {
        self._burn(msg_sender, user_token, validator_token, liquidity, to)
    }

    fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_out: U256,
        to: Address,
    ) -> Result<U256> {
        self._rebalance_swap(msg_sender, user_token, validator_token, amount_out, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TIP_FEE_MANAGER_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip20::{InvalidCurrency, TIP20Error, TIP20Token},
    };

    #[test]
    fn test_set_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", user).apply()?;

            let mut fee_manager = TipFeeManager::new();

            let result = IFeeManager::set_user_token(&mut fee_manager, user, token.address());
            assert!(result.is_ok());

            assert_eq!(
                IFeeManager::user_tokens(&fee_manager, user)?,
                token.address()
            );

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let result =
                IFeeManager::set_validator_token(&mut fee_manager, validator, token.address());
            assert!(result.is_ok());

            let returned_token = IFeeManager::validator_tokens(&fee_manager, validator)?;
            assert_eq!(returned_token, token.address());

            Ok(())
        })
    }

    #[test]
    fn test_set_validator_token_cannot_change_within_block() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let validator = Address::random();
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut fee_manager = TipFeeManager::new();

            let result =
                IFeeManager::set_validator_token(&mut fee_manager, validator, token.address());
            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_collect_fee_pre_tx() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let user = Address::random();
        let validator = Address::random();
        StorageCtx::enter(&mut storage, || {
            let max_amount = U256::from(10000);

            let token = TIP20Setup::create("Test", "TST", user)
                .with_issuer(user)
                .with_mint(user, U256::from(u64::MAX))
                .with_approval(user, TIP_FEE_MANAGER_ADDRESS, U256::MAX)
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            IFeeManager::set_validator_token(&mut fee_manager, validator, token.address())?;
            IFeeManager::set_user_token(&mut fee_manager, user, token.address())?;

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
        StorageCtx::enter(&mut storage, || {
            let actual_used = U256::from(6000);
            let refund_amount = U256::from(4000);

            // Mint to FeeManager (simulating collect_fee_pre_tx already happened)
            let token = TIP20Setup::create("Test", "TST", admin)
                .with_issuer(admin)
                .with_mint(TIP_FEE_MANAGER_ADDRESS, U256::from(100000000000000_u64))
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            IFeeManager::set_validator_token(&mut fee_manager, validator, token.address())?;
            IFeeManager::set_user_token(&mut fee_manager, user, token.address())?;
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
            let balance = token.balance_of(user)?;
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
        StorageCtx::enter(&mut storage, || {
            let non_usd_token = TIP20Setup::create("NonUSD", "EUR", admin)
                .currency("EUR")
                .apply()?;

            let mut fee_manager = TipFeeManager::new();

            let result =
                IFeeManager::set_user_token(&mut fee_manager, user, non_usd_token.address());
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(
                    InvalidCurrency
                )))
            ));

            let result = IFeeManager::set_validator_token(
                &mut fee_manager,
                validator,
                non_usd_token.address(),
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(
                    InvalidCurrency
                )))
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
            fee_manager.pools[pool_id].write(Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            IFeeManager::set_validator_token(
                &mut fee_manager,
                validator,
                validator_token.address(),
            )?;

            let max_amount = U256::from(1000);
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
            fee_manager.pools[pool_id].write(Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 10000,
            })?;

            IFeeManager::set_validator_token(
                &mut fee_manager,
                validator,
                validator_token.address(),
            )?;

            let max_amount = U256::from(1000);
            let actual_spending = U256::from(800);
            let refund_amount = U256::from(200);

            fee_manager.collect_fee_pre_tx(user, user_token.address(), max_amount, validator)?;
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
            let user_balance = tip20_token.balance_of(user)?;
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
            fee_manager.pools[pool_id].write(Pool {
                reserve_user_token: 10000,
                reserve_validator_token: 100,
            })?;

            IFeeManager::set_validator_token(
                &mut fee_manager,
                validator,
                validator_token.address(),
            )?;

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

            IFeeManager::set_validator_token(&mut fee_manager, validator, token.address())?;

            let collected = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(collected, U256::ZERO);

            let result = IFeeManager::distribute_fees(
                &mut fee_manager,
                validator,
                validator,
                token.address(),
            );
            assert!(result.is_ok(), "Should succeed even with zero balance");

            // Validator balance should still be zero
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance = tip20_token.balance_of(validator)?;
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

            IFeeManager::set_validator_token(&mut fee_manager, validator, token.address())?;

            let fee_amount = U256::from(500);
            fee_manager.collected_fees[validator][token.address()].write(fee_amount)?;

            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_before = tip20_token.balance_of(validator)?;
            assert_eq!(balance_before, U256::ZERO);

            let mut fee_manager = TipFeeManager::new();
            IFeeManager::distribute_fees(&mut fee_manager, validator, validator, token.address())?;

            // Verify validator received the fees
            let tip20_token = TIP20Token::from_address(token.address())?;
            let balance_after = tip20_token.balance_of(validator)?;
            assert_eq!(balance_after, fee_amount);

            // Verify collected fees cleared
            let fee_manager = TipFeeManager::new();
            let remaining = fee_manager.collected_fees[validator][token.address()].read()?;
            assert_eq!(remaining, U256::ZERO);

            Ok(())
        })
    }
}
