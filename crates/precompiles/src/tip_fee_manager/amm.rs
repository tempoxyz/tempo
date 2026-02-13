pub use crate::tip_fee_manager::abi::IFeeAMM::{MIN_LIQUIDITY, Pool};

use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip_fee_manager::{
        IFeeAMM::{self, prelude::*},
        TipFeeManager,
    },
    tip20::{ITIP20::traits::*, TIP20Token, validate_usd_currency},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_precompiles_macros::Storable;

use Error as FeeAMMError;
use Event as FeeAMMEvent;

/// Compute amount out for a fee swap
#[inline]
pub fn compute_amount_out(amount_in: U256) -> Result<U256> {
    amount_in
        .checked_mul(M)
        .map(|product| product / SCALE)
        .ok_or(TempoPrecompileError::under_overflow())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Storable)]
pub struct PoolKey {
    pub user_token: Address,
    pub validator_token: Address,
}

// TODO(rusowsky): remove this and create a read-only wrapper that is callable from read-only ctx with db access
impl Pool {
    pub fn decode_from_slot(slot_value: U256) -> Self {
        use crate::storage::{LayoutCtx, Storable, packing::PackedSlot};

        // NOTE: fine to expect, as `StorageOps` on `PackedSlot` are infallible
        Self::load(&PackedSlot(slot_value), U256::ZERO, LayoutCtx::FULL)
            .expect("unable to decode Pool from slot")
    }
}

impl PoolKey {
    /// Creates a new pool key from user and validator token addresses.
    /// This key uniquely identifies a trading pair in the AMM.
    pub fn new(user_token: Address, validator_token: Address) -> Self {
        Self {
            user_token,
            validator_token,
        }
    }

    /// Generates a unique pool ID by hashing the token pair addresses.
    /// Uses keccak256 to create a deterministic identifier for this pool.
    pub fn get_id(&self) -> B256 {
        keccak256((self.user_token, self.validator_token).abi_encode())
    }
}

impl TipFeeManager {
    /// Gets the pool id for a given set of tokens. Note that the pool id is dependent on the
    /// ordering of the tokens ie. (token_a, token_b) results in a different pool id
    /// than (token_b, token_a)
    pub fn pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Ensures that pool has enough liquidity for a fee swap and reserves funds.
    /// Returns the amount out needed for the swap
    pub fn check_sufficient_liquidity(&mut self, pool_id: B256, max_amount: U256) -> Result<u128> {
        let amount_out_needed = compute_amount_out(max_amount)?;
        let pool = self.pools[pool_id].read()?;

        if amount_out_needed > U256::from(pool.reserve_validator_token) {
            return Err(FeeAMMError::insufficient_liquidity().into());
        }

        amount_out_needed
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())
    }

    /// Reserves pool liquidity in transient storage for a pending fee swap.
    #[inline]
    pub fn reserve_pool_liquidity(&mut self, pool_id: B256, amount: u128) -> Result<()> {
        self.pending_fee_swap_reservation[pool_id].t_write(amount)
    }
}

impl IFeeAMM::Interface for TipFeeManager {
    fn get_pool_id(&self, user_token: Address, validator_token: Address) -> Result<B256> {
        Ok(self.pool_id(user_token, validator_token))
    }

    /// Retrieves a pool for a given `pool_id` from storage
    fn get_pool(&self, user_token: Address, validator_token: Address) -> Result<Pool> {
        let pool_id = self.pool_id(user_token, validator_token);
        self.pools[pool_id].read()
    }

    /// Mint LP tokens
    fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        if user_token == validator_token {
            return Err(FeeAMMError::identical_addresses().into());
        }

        if amount_validator_token.is_zero() {
            return Err(FeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools[pool_id].read()?;
        let mut total_supply = self.total_supply(pool_id)?;

        let liquidity = if pool.reserve_user_token == 0 && pool.reserve_validator_token == 0 {
            let half_amount = amount_validator_token
                .checked_div(uint!(2_U256))
                .ok_or(TempoPrecompileError::under_overflow())?;

            if half_amount <= MIN_LIQUIDITY {
                return Err(FeeAMMError::insufficient_liquidity().into());
            }

            total_supply = total_supply
                .checked_add(MIN_LIQUIDITY)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_total_supply(pool_id, total_supply)?;

            half_amount
                .checked_sub(MIN_LIQUIDITY)
                .ok_or(FeeAMMError::insufficient_liquidity())?
        } else {
            // Subsequent deposits: mint as if user called rebalanceSwap then minted with both
            // liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
            let product = N
                .checked_mul(U256::from(pool.reserve_user_token))
                .and_then(|product| product.checked_div(SCALE))
                .ok_or(FeeAMMError::invalid_swap_calculation())?;

            let denom = U256::from(pool.reserve_validator_token)
                .checked_add(product)
                .ok_or(FeeAMMError::invalid_amount())?;

            if denom.is_zero() {
                return Err(FeeAMMError::division_by_zero().into());
            }

            amount_validator_token
                .checked_mul(total_supply)
                .and_then(|numerator| numerator.checked_div(denom))
                .ok_or(FeeAMMError::invalid_swap_calculation())?
        };

        if liquidity.is_zero() {
            return Err(FeeAMMError::insufficient_liquidity().into());
        }

        // Transfer validator tokens from user
        let _ = TIP20Token::from_address(validator_token)?.system_transfer_from(
            msg_sender,
            self.address,
            amount_validator_token,
        )?;

        // Update reserves
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(validator_amount)
            .ok_or(FeeAMMError::invalid_amount())?;

        self.pools[pool_id].write(pool)?;

        // Mint LP tokens
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        let balance = self.liquidity_balances(pool_id, to)?;
        self.set_liquidity_balances(
            pool_id,
            to,
            balance
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Emit Mint event
        self.emit_event(FeeAMMEvent::mint(
            msg_sender,
            to,
            user_token,
            validator_token,
            amount_validator_token,
            liquidity,
        ))?;

        Ok(liquidity)
    }

    /// Burn LP tokens for a given pool
    fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256)> {
        if user_token == validator_token {
            return Err(FeeAMMError::identical_addresses().into());
        }

        if liquidity.is_zero() {
            return Err(FeeAMMError::invalid_amount().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token)?;
        validate_usd_currency(validator_token)?;

        let pool_id = self.pool_id(user_token, validator_token);
        // Check user has sufficient liquidity
        let balance = self.liquidity_balances(pool_id, msg_sender)?;
        if balance < liquidity {
            return Err(FeeAMMError::insufficient_liquidity().into());
        }

        let mut pool = self.pools[pool_id].read()?;
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, pool_id, liquidity)?;

        // T2+: Check that burn leaves enough liquidity for pending fee swaps
        // Reservation is set by reserve_pool_liquidity() via check_sufficient_liquidity()
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;
        let available_after_burn = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(FeeAMMError::insufficient_reserves())?;
        if self.storage.spec().is_t2() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if available_after_burn < reserved {
                return Err(FeeAMMError::insufficient_liquidity().into());
            }
        }

        // Burn LP tokens
        self.set_liquidity_balances(
            pool_id,
            msg_sender,
            balance
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        let total_supply = self.total_supply(pool_id)?;
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Update reserves with underflow checks
        let user_amount: u128 = amount_user_token
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(user_amount)
            .ok_or(FeeAMMError::insufficient_reserves())?;
        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(FeeAMMError::insufficient_reserves())?;
        self.pools[pool_id].write(pool)?;

        // Transfer tokens to user
        let _ =
            TIP20Token::from_address(user_token)?.transfer(self.address, to, amount_user_token)?;

        let _ = TIP20Token::from_address(validator_token)?.transfer(
            self.address,
            to,
            amount_validator_token,
        )?;

        // Emit Burn event
        self.emit_event(FeeAMMEvent::burn(
            msg_sender,
            user_token,
            validator_token,
            amount_user_token,
            amount_validator_token,
            liquidity,
            to,
        ))?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Swap to rebalance a fee token pool
    fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_out: U256,
        to: Address,
    ) -> Result<U256> {
        if amount_out.is_zero() {
            return Err(FeeAMMError::invalid_amount().into());
        }

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools[pool_id].read()?;

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        let amount_in = amount_out
            .checked_mul(N)
            .and_then(|product| product.checked_div(SCALE))
            .and_then(|result| result.checked_add(U256::ONE))
            .ok_or(TempoPrecompileError::under_overflow())?;

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| FeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(amount_in)
            .ok_or(FeeAMMError::insufficient_reserves())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(amount_out)
            .ok_or(FeeAMMError::invalid_amount())?;

        if self.storage.spec().is_t2() {
            let reserved = self.pending_fee_swap_reservation[pool_id].t_read()?;
            if pool.reserve_validator_token < reserved {
                return Err(FeeAMMError::insufficient_liquidity().into());
            }
        }

        self.pools[pool_id].write(pool)?;

        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        TIP20Token::from_address(validator_token)?.system_transfer_from(
            msg_sender,
            self.address,
            amount_in,
        )?;

        TIP20Token::from_address(user_token)?.transfer(self.address, to, amount_out)?;

        self.emit_event(FeeAMMEvent::rebalance_swap(
            user_token,
            validator_token,
            msg_sender,
            amount_in,
            amount_out,
        ))?;

        Ok(amount_in)
    }
}

impl TipFeeManager {
    /// Executes a fee swap immediately, converting userToken to validatorToken at the fixed rate m = 0.9970.
    /// Called by FeeManager.collectFeePostTx during post-transaction fee collection.
    pub fn execute_fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<U256> {
        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools[pool_id].read()?;

        // Calculate output at fixed price m = 0.9970
        let amount_out = compute_amount_out(amount_in)?;

        // Check if there's enough validatorToken available
        if amount_out > U256::from(pool.reserve_validator_token) {
            return Err(FeeAMMError::insufficient_liquidity().into());
        }

        // Update reserves
        let amount_in_u128: u128 = amount_in
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;
        let amount_out_u128: u128 = amount_out
            .try_into()
            .map_err(|_| TempoPrecompileError::under_overflow())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_add(amount_in_u128)
            .ok_or(TempoPrecompileError::under_overflow())?;
        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_sub(amount_out_u128)
            .ok_or(TempoPrecompileError::under_overflow())?;

        self.pools[pool_id].write(pool)?;

        Ok(amount_out)
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &self,
        pool: &Pool,
        pool_id: B256,
        liquidity: U256,
    ) -> Result<(U256, U256)> {
        let total_supply = self.total_supply[pool_id].read()?;
        let amount_user_token = liquidity
            .checked_mul(U256::from(pool.reserve_user_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;
        let amount_validator_token = liquidity
            .checked_mul(U256::from(pool.reserve_validator_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: B256, total_supply: U256) -> Result<()> {
        self.total_supply[pool_id].write(total_supply)
    }

    /// Set user's LP token balance
    fn set_liquidity_balances(
        &mut self,
        pool_id: B256,
        user: Address,
        balance: U256,
    ) -> Result<()> {
        self.liquidity_balances[pool_id][user].write(balance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TempoHardfork,
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip_fee_manager::abi::IFeeAMM::traits::*,
        tip20::TIP20Error,
    };

    /// Integer square root using the Babylonian method
    fn sqrt(x: U256) -> U256 {
        if x == U256::ZERO {
            return U256::ZERO;
        }
        let mut z = (x + U256::ONE) / uint!(2_U256);
        let mut y = x;
        while z < y {
            y = z;
            z = (x / z + z) / uint!(2_U256);
        }
        y
    }

    /// Sets up a pool with initial liquidity for testing
    fn setup_pool_with_liquidity(
        amm: &mut TipFeeManager,
        user_token: Address,
        validator_token: Address,
        user_amount: U256,
        validator_amount: U256,
    ) -> Result<B256> {
        let pool_id = amm.pool_id(user_token, validator_token);
        let pool = Pool {
            reserve_user_token: user_amount.try_into().unwrap(),
            reserve_validator_token: validator_amount.try_into().unwrap(),
        };
        amm.pools[pool_id].write(pool)?;
        let liquidity = sqrt(user_amount * validator_amount);
        amm.total_supply[pool_id].write(liquidity)?;
        Ok(pool_id)
    }

    #[test]
    fn test_mint_identical_addresses() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut amm = TipFeeManager::new();
            let result = amm.mint(
                admin,
                token.address(),
                token.address(),
                U256::from(1000),
                admin,
            );
            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::identical_addresses().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_burn_identical_addresses() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut amm = TipFeeManager::new();
            let result = amm.burn(
                admin,
                token.address(),
                token.address(),
                U256::from(1000),
                admin,
            );
            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::identical_addresses().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap_insufficient_funds() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let to = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                amount,
                amount,
            )?;

            let result = amm.rebalance_swap(
                admin,
                user_token.address(),
                validator_token.address(),
                amount + U256::ONE,
                to,
            );
            assert_eq!(result.unwrap_err(), FeeAMMError::invalid_amount().into());
            Ok(())
        })
    }

    #[test]
    fn test_mint_rejects_non_usd_user_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let eur_token = TIP20Setup::create("EuroToken", "EUR", admin)
                .currency("EUR")
                .apply()?;
            let usd_token = TIP20Setup::create("USDToken", "USD", admin).apply()?;
            let mut amm = TipFeeManager::new();

            let result = amm.mint(
                admin,
                eur_token.address(),
                usd_token.address(),
                U256::from(1000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            let result = amm.mint(
                admin,
                usd_token.address(),
                eur_token.address(),
                U256::from(1000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_burn_rejects_non_usd_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let eur_token = TIP20Setup::create("EuroToken", "EUR", admin)
                .currency("EUR")
                .apply()?;
            let usd_token = TIP20Setup::create("USDToken", "USD", admin).apply()?;
            let mut amm = TipFeeManager::new();

            let result = amm.burn(
                admin,
                eur_token.address(),
                usd_token.address(),
                U256::from(1000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            let result = amm.burn(
                admin,
                usd_token.address(),
                eur_token.address(),
                U256::from(1000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_mint_insufficient_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;
            let mut amm = TipFeeManager::new();

            // MIN_LIQUIDITY = 1000, amount/2 must be > 1000, so 2000 should fail
            let insufficient = uint!(2000_U256);
            let result = amm.mint(
                admin,
                user_token.address(),
                validator_token.address(),
                insufficient,
                admin,
            );
            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::insufficient_liquidity().into()
            );
            Ok(())
        })
    }

    #[test]
    fn test_add_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(10000000_U256);
            let token1 = TIP20Setup::create("Token1", "TK1", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let token2 = TIP20Setup::create("Token2", "TK2", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();
            let amount = uint!(10000_U256);
            let result = amm.mint(admin, token1, token2, amount, admin)?;
            let expected_mean = amount / uint!(2_U256);
            let expected_liquidity = expected_mean - MIN_LIQUIDITY;

            assert_eq!(result, expected_liquidity,);

            Ok(())
        })
    }

    /// Test execute_fee_swap executes swap immediately and updates reserves
    #[test]
    fn test_execute_fee_swap_immediate() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            // Setup pool with 1000 tokens each
            let liquidity_amount = uint!(1000_U256);
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                liquidity_amount,
                liquidity_amount,
            )?;

            // Execute fee swap for 100 tokens
            let amount_in = uint!(100_U256);
            let expected_out = (amount_in * M) / SCALE; // 100 * 9970 / 10000 = 99

            let amount_out = amm.execute_fee_swap(user_token, validator_token, amount_in)?;

            assert_eq!(amount_out, expected_out);

            // Verify reserves updated immediately
            let pool = amm.pools[pool_id].read()?;
            assert_eq!(
                U256::from(pool.reserve_user_token),
                liquidity_amount + amount_in
            );
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                liquidity_amount - expected_out
            );

            Ok(())
        })
    }

    /// Test execute_fee_swap fails with insufficient liquidity
    #[test]
    fn test_execute_fee_swap_insufficient_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            // Setup pool with only 100 tokens each
            let small_liquidity = uint!(100_U256);
            setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                small_liquidity,
                small_liquidity,
            )?;

            // Try to swap 200 tokens (would need ~199 output, but only 100 available)
            let too_large_amount = uint!(200_U256);

            let result = amm.execute_fee_swap(user_token, validator_token, too_large_amount);

            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::insufficient_liquidity().into()
            );

            Ok(())
        })
    }

    /// Test fee swap rounding consistency across multiple swaps
    #[test]
    fn test_fee_swap_rounding_consistency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                liquidity,
                liquidity,
            )?;

            let amount_in = uint!(10000_U256) * uint!(10_U256).pow(U256::from(6));
            let expected_out = (amount_in * M) / SCALE;

            let actual_out = amm.execute_fee_swap(user_token, validator_token, amount_in)?;
            assert_eq!(actual_out, expected_out, "Output should match expected");

            let pool = amm.pools[pool_id].read()?;
            assert_eq!(
                U256::from(pool.reserve_user_token),
                liquidity + amount_in,
                "User reserve should increase"
            );
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                liquidity - actual_out,
                "Validator reserve should decrease"
            );

            Ok(())
        })
    }

    /// Test multiple consecutive fee swaps update reserves correctly
    #[test]
    fn test_multiple_consecutive_fee_swaps() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();
            let initial = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id =
                setup_pool_with_liquidity(&mut amm, user_token, validator_token, initial, initial)?;

            let swap1 = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
            let swap2 = uint!(2000_U256) * uint!(10_U256).pow(U256::from(6));
            let swap3 = uint!(3000_U256) * uint!(10_U256).pow(U256::from(6));

            let out1 = amm.execute_fee_swap(user_token, validator_token, swap1)?;
            let out2 = amm.execute_fee_swap(user_token, validator_token, swap2)?;
            let out3 = amm.execute_fee_swap(user_token, validator_token, swap3)?;

            let total_in = swap1 + swap2 + swap3;
            let total_out = out1 + out2 + out3;

            // Each swap output should be amount_in * M / SCALE
            assert_eq!(out1, (swap1 * M) / SCALE);
            assert_eq!(out2, (swap2 * M) / SCALE);
            assert_eq!(out3, (swap3 * M) / SCALE);

            let pool = amm.pools[pool_id].read()?;
            assert_eq!(U256::from(pool.reserve_user_token), initial + total_in);
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                initial - total_out
            );

            Ok(())
        })
    }

    /// Test check_sufficient_liquidity boundary condition
    #[test]
    fn test_check_sufficient_liquidity_boundary() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                liquidity,
                liquidity,
            )?;

            // Exactly at boundary should succeed (100 * 0.997 = 99.7, which is < 100)
            let ok_amount = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
            assert!(amm.check_sufficient_liquidity(pool_id, ok_amount).is_ok());

            // Just over boundary should fail (101 * 0.997 = 100.697, which is > 100)
            let too_much = uint!(101_U256) * uint!(10_U256).pow(U256::from(6));
            assert!(amm.check_sufficient_liquidity(pool_id, too_much).is_err());

            Ok(())
        })
    }

    /// Test zero liquidity burn
    #[test]
    fn test_burn_zero_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let result = amm.burn(admin, user_token, validator_token, U256::ZERO, admin);

            assert_eq!(result.unwrap_err(), FeeAMMError::invalid_amount().into());

            Ok(())
        })
    }

    /// Test zero amount validator token
    #[test]
    fn test_mint_zero_amount_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let result = amm.mint(admin, user_token, validator_token, U256::ZERO, admin);

            assert_eq!(result.unwrap_err(), FeeAMMError::invalid_amount().into());

            Ok(())
        })
    }

    #[test]
    fn test_rebalance_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(10000000_U256);
            let mut amm = TipFeeManager::new();
            let amm_address = amm.address;

            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .with_mint(amm_address, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let liquidity = uint!(100000_U256);
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                liquidity,
                liquidity,
            )?;

            let amount_out = uint!(1000_U256);
            let expected_in = (amount_out * N) / SCALE + U256::ONE;

            let amount_in =
                amm.rebalance_swap(admin, user_token, validator_token, amount_out, recipient)?;

            assert_eq!(amount_in, expected_in);

            let pool = amm.pools[pool_id].read()?;
            assert_eq!(U256::from(pool.reserve_user_token), liquidity - amount_out);
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                liquidity + amount_in
            );

            Ok(())
        })
    }

    #[test]
    fn test_mint_subsequent_deposit() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let second_user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .with_mint(second_user, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .with_mint(second_user, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let initial_amount = uint!(100000_U256);
            let first_liquidity =
                amm.mint(admin, user_token, validator_token, initial_amount, admin)?;

            let expected_first_liquidity = initial_amount / uint!(2_U256) - MIN_LIQUIDITY;
            assert_eq!(first_liquidity, expected_first_liquidity);

            let pool_id = amm.pool_id(user_token, validator_token);
            let total_supply_after_first = amm.total_supply(pool_id)?;
            assert_eq!(total_supply_after_first, first_liquidity + MIN_LIQUIDITY);

            let pool_after_first = amm.pools[pool_id].read()?;
            let reserve_val = U256::from(pool_after_first.reserve_validator_token);

            let second_amount = uint!(50000_U256);
            let second_liquidity = amm.mint(
                second_user,
                user_token,
                validator_token,
                second_amount,
                second_user,
            )?;

            let expected_second_liquidity = second_amount * total_supply_after_first / reserve_val;
            assert_eq!(second_liquidity, expected_second_liquidity);

            let total_supply_after_second = amm.total_supply(pool_id)?;
            assert_eq!(
                total_supply_after_second,
                total_supply_after_first + second_liquidity
            );

            let admin_balance = amm.liquidity_balances(pool_id, admin)?;
            let second_user_balance = amm.liquidity_balances(pool_id, second_user)?;
            assert_eq!(admin_balance, first_liquidity);
            assert_eq!(second_user_balance, second_liquidity);

            Ok(())
        })
    }

    #[test]
    fn test_burn() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;

            let expected_liquidity = deposit_amount / uint!(2_U256) - MIN_LIQUIDITY;
            assert_eq!(liquidity, expected_liquidity);

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool_before = amm.pools[pool_id].read()?;
            let total_supply_before = amm.total_supply(pool_id)?;

            let burn_amount = liquidity / uint!(2_U256);
            let (amount_user, amount_validator) =
                amm.burn(admin, user_token, validator_token, burn_amount, recipient)?;

            let expected_user =
                burn_amount * U256::from(pool_before.reserve_user_token) / total_supply_before;
            let expected_validator =
                burn_amount * U256::from(pool_before.reserve_validator_token) / total_supply_before;
            assert_eq!(amount_user, expected_user);
            assert_eq!(amount_validator, expected_validator);

            let pool_after = amm.pools[pool_id].read()?;
            let total_supply_after = amm.total_supply(pool_id)?;

            assert_eq!(total_supply_after, total_supply_before - burn_amount);

            let admin_balance = amm.liquidity_balances(pool_id, admin)?;
            assert_eq!(admin_balance, liquidity - burn_amount);

            assert_eq!(
                U256::from(pool_after.reserve_user_token),
                U256::from(pool_before.reserve_user_token) - amount_user
            );
            assert_eq!(
                U256::from(pool_after.reserve_validator_token),
                U256::from(pool_before.reserve_validator_token) - amount_validator
            );

            Ok(())
        })
    }

    #[test]
    fn test_burn_insufficient_balance() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let other_user = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;

            let result = amm.burn(
                other_user,
                user_token,
                validator_token,
                liquidity,
                other_user,
            );

            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::insufficient_liquidity().into()
            );

            Ok(())
        })
    }

    // Test zero amount rebalance swap
    #[test]
    fn test_rebalance_swap_zero_amount_out() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let to = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let result = amm.rebalance_swap(admin, user_token, validator_token, U256::ZERO, to);

            assert_eq!(result.unwrap_err(), FeeAMMError::invalid_amount().into());

            Ok(())
        })
    }

    #[test]
    fn test_t2_reserve_pool_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(10000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100000_U256);
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token,
                validator_token,
                liquidity,
                liquidity,
            )?;

            let max_amount = uint!(10000_U256);
            let amount_out = amm.check_sufficient_liquidity(pool_id, max_amount)?;
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            let reserved = amm.pending_fee_swap_reservation[pool_id].t_read()?;
            let expected_reserved: u128 = compute_amount_out(max_amount)?.try_into().unwrap();
            assert_eq!(reserved, expected_reserved);

            Ok(())
        })
    }

    #[test]
    fn test_t2_burn_respects_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool = amm.pools[pool_id].read()?;

            // Reserve most of the validator token liquidity
            let reserve_amount = U256::from(pool.reserve_validator_token) - uint!(100_U256);
            let amount_out = amm.check_sufficient_liquidity(pool_id, reserve_amount)?;
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            let result = amm.burn(admin, user_token, validator_token, liquidity, recipient);
            assert_eq!(
                result.unwrap_err(),
                FeeAMMError::insufficient_liquidity().into()
            );

            Ok(())
        })
    }

    #[test]
    fn test_t2_partial_burn_with_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let small_reserve = uint!(1000_U256);
            let amount_out = amm.check_sufficient_liquidity(pool_id, small_reserve)?;
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            let small_burn = liquidity / uint!(10_U256);
            let result = amm.burn(admin, user_token, validator_token, small_burn, recipient);

            assert!(result.is_ok());

            Ok(())
        })
    }

    #[test]
    fn test_t2_rebalance_swap_respects_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2);
        let admin = Address::random();
        let to = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let mut amm = TipFeeManager::new();
            let amm_address = amm.address;
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .with_mint(amm_address, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let liq = uint!(100000_U256);
            let pool_id =
                setup_pool_with_liquidity(&mut amm, user_token, validator_token, liq, liq)?;

            let amount_out = amm.check_sufficient_liquidity(pool_id, uint!(50000_U256))?;
            amm.reserve_pool_liquidity(pool_id, amount_out)?;

            amm.rebalance_swap(admin, user_token, validator_token, uint!(5000_U256), to)?;
            let pool = amm.pools[pool_id].read()?;
            let reserved = amm.pending_fee_swap_reservation[pool_id].t_read()?;
            assert!(pool.reserve_validator_token >= reserved);

            Ok(())
        })
    }

    #[test]
    fn test_pre_t2_rebalance_swap_skips_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let to = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let mut amm = TipFeeManager::new();
            let amm_address = amm.address;
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .with_mint(amm_address, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let liq = uint!(100000_U256);
            let pool_id =
                setup_pool_with_liquidity(&mut amm, user_token, validator_token, liq, liq)?;
            amm.check_sufficient_liquidity(pool_id, uint!(90000_U256))?;
            assert!(
                amm.rebalance_swap(admin, user_token, validator_token, uint!(5000_U256), to)
                    .is_ok()
            );

            Ok(())
        })
    }

    #[test]
    fn test_pre_t2_no_reservation() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T1);
        let admin = Address::random();
        let recipient = Address::random();

        StorageCtx::enter(&mut storage, || {
            let mint_amount = uint!(100000000_U256);
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                .with_mint(admin, mint_amount)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let deposit_amount = uint!(100000_U256);
            let liquidity = amm.mint(admin, user_token, validator_token, deposit_amount, admin)?;

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool = amm.pools[pool_id].read()?;
            let reserve_amount = U256::from(pool.reserve_validator_token) - uint!(100_U256);
            amm.check_sufficient_liquidity(pool_id, reserve_amount)?;

            let result = amm.burn(admin, user_token, validator_token, liquidity, recipient);
            assert!(result.is_ok());

            Ok(())
        })
    }
}
