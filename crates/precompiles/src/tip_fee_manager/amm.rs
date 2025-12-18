use crate::{
    error::{Result, TempoPrecompileError},
    storage::Handler,
    tip_fee_manager::{ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent, TipFeeManager},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_precompiles_macros::Storable;

/// Constants from the Solidity reference implementation
pub const M: U256 = uint!(9970_U256); // m = 0.9970 (scaled by 10000)
pub const N: U256 = uint!(9985_U256);
pub const SCALE: U256 = uint!(10000_U256);
pub const SQRT_SCALE: U256 = uint!(100000_U256);
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Compute amount out for a fee swap
#[inline]
pub fn compute_amount_out(amount_in: U256) -> Result<U256> {
    amount_in
        .checked_mul(M)
        .map(|product| product / SCALE)
        .ok_or(TempoPrecompileError::under_overflow())
}

/// Pool structure matching the Solidity implementation
#[derive(Debug, Clone, Default, Storable)]
pub struct Pool {
    pub reserve_user_token: u128,
    pub reserve_validator_token: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(value: Pool) -> Self {
        Self {
            reserveUserToken: value.reserve_user_token,
            reserveValidatorToken: value.reserve_validator_token,
        }
    }
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

    /// Retrieves a pool for a given `pool_id` from storage
    pub fn get_pool(&self, call: ITIPFeeAMM::getPoolCall) -> Result<Pool> {
        let pool_id = self.pool_id(call.userToken, call.validatorToken);
        self.pools.at(pool_id).read()
    }

    /// Ensures that pool has enough liquidity for a fee swap and reserve that liquidity in `pending_fee_swap_in`.
    pub fn reserve_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
    ) -> Result<()> {
        let pool_id = PoolKey::new(user_token, validator_token).get_id();
        let current_pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id)?;

        // Add the `max_amount` to the pending amount in and check that the resulting
        // total output is within the pools current reserves
        let new_total_pending = current_pending_fee_swap_in
            .checked_add(
                max_amount
                    .try_into()
                    .map_err(|_| TempoPrecompileError::under_overflow())?,
            )
            .ok_or(TempoPrecompileError::under_overflow())?;

        let total_out_needed = compute_amount_out(U256::from(new_total_pending))?;

        let pool = self.pools.at(pool_id).read()?;
        if total_out_needed > U256::from(pool.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        self.set_pending_fee_swap_in(pool_id, new_total_pending)?;

        Ok(())
    }

    /// Ensures that pool has enough liquidity for a fee swap
    pub fn check_sufficient_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
    ) -> Result<()> {
        let pool_id = PoolKey::new(user_token, validator_token).get_id();
        let amount_out_needed = compute_amount_out(max_amount)?;
        let pool = self.pools.at(pool_id).read()?;
        if amount_out_needed > U256::from(pool.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        Ok(())
    }

    /// Calculate validator token reserve minus pending swaps
    fn get_effective_validator_reserve(&self, pool_id: B256) -> Result<U256> {
        let pool = self.pools.at(pool_id).read()?;
        let pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id)?;
        let pending_out = compute_amount_out(U256::from(pending_fee_swap_in))?;

        U256::from(pool.reserve_validator_token)
            .checked_sub(pending_out)
            .ok_or(TempoPrecompileError::under_overflow())
    }

    /// Calculate user token reserve plus pending swaps
    fn get_effective_user_reserve(&self, pool_id: B256) -> Result<U256> {
        let pool = self.pools.at(pool_id).read()?;
        let pending_fee_swap_in = U256::from(self.get_pending_fee_swap_in(pool_id)?);

        U256::from(pool.reserve_user_token)
            .checked_add(pending_fee_swap_in)
            .ok_or(TempoPrecompileError::under_overflow())
    }

    /// Releases `refund_amount` of liquidity that was locked by `reserve_liquidity`
    pub fn release_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        refund_amount: U256,
    ) -> Result<()> {
        let pool_id = self.pool_id(user_token, validator_token);
        let current_pending = self.get_pending_fee_swap_in(pool_id)?;
        self.set_pending_fee_swap_in(
            pool_id,
            current_pending
                .checked_sub(
                    refund_amount
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(())
    }

    /// Swap to rebalance a fee token pool
    pub fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_out: U256,
        to: Address,
    ) -> Result<U256> {
        // Validate both tokens are USD currency
        validate_usd_currency(user_token, self.storage)?;
        validate_usd_currency(validator_token, self.storage)?;

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools.at(pool_id).read()?;

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        let amount_in = amount_out
            .checked_mul(N)
            .and_then(|product| product.checked_div(SCALE))
            .and_then(|result| result.checked_add(U256::ONE))
            .ok_or(TempoPrecompileError::under_overflow())?;

        let amount_in: u128 = amount_in
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let amount_out: u128 = amount_out
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(amount_in)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(amount_out)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        self.pools.at(pool_id).write(pool)?;

        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        TIP20Token::from_address(validator_token)?.system_transfer_from(
            msg_sender,
            self.address,
            amount_in,
        )?;

        TIP20Token::from_address(user_token)?.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_out,
            },
        )?;

        self.emit_event(TIPFeeAMMEvent::RebalanceSwap(ITIPFeeAMM::RebalanceSwap {
            userToken: user_token,
            validatorToken: validator_token,
            swapper: msg_sender,
            amountIn: amount_in,
            amountOut: amount_out,
        }))?;

        Ok(amount_in)
    }

    /// Mint LP tokens for a given pool
    pub fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_user_token: U256,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token, self.storage)?;
        validate_usd_currency(validator_token, self.storage)?;

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools.at(pool_id).read()?;
        let total_supply = self.get_total_supply(pool_id)?;

        let liquidity = if total_supply.is_zero() {
            // Use checked math for multiplication and division
            let mean = if self.storage.spec().is_moderato() {
                amount_user_token
                    .checked_add(amount_validator_token)
                    .map(|product| product / uint!(2_U256))
                    .ok_or(TIPFeeAMMError::invalid_amount())?
            } else {
                amount_user_token
                    .checked_mul(amount_validator_token)
                    .map(|product| product / uint!(2_U256))
                    .ok_or(TIPFeeAMMError::invalid_amount())?
            };
            if mean <= MIN_LIQUIDITY {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }
            self.set_total_supply(pool_id, MIN_LIQUIDITY)?;
            mean.checked_sub(MIN_LIQUIDITY)
                .ok_or(TIPFeeAMMError::insufficient_liquidity())?
        } else {
            let liquidity_user = if pool.reserve_user_token > 0 {
                amount_user_token
                    .checked_mul(total_supply)
                    .and_then(|numerator| {
                        numerator.checked_div(U256::from(pool.reserve_user_token))
                    })
                    .ok_or(TIPFeeAMMError::invalid_amount())?
            } else {
                U256::MAX
            };

            let liquidity_validator = if pool.reserve_validator_token > 0 {
                amount_validator_token
                    .checked_mul(total_supply)
                    .and_then(|numerator| {
                        numerator.checked_div(U256::from(pool.reserve_validator_token))
                    })
                    .ok_or(TIPFeeAMMError::invalid_amount())?
            } else {
                U256::MAX
            };

            liquidity_user.min(liquidity_validator)
        };

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        // Transfer tokens from user to contract
        let _ = TIP20Token::from_address(user_token)?.system_transfer_from(
            msg_sender,
            self.address,
            amount_user_token,
        )?;

        let _ = TIP20Token::from_address(validator_token)?.system_transfer_from(
            msg_sender,
            self.address,
            amount_validator_token,
        )?;

        // Update reserves with overflow checks
        let user_amount: u128 = amount_user_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_add(user_amount)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(validator_amount)
            .ok_or(TIPFeeAMMError::invalid_amount())?;
        self.pools.at(pool_id).write(pool)?;

        // Mint LP tokens
        let current_total_supply = self.get_total_supply(pool_id)?;
        self.set_total_supply(
            pool_id,
            current_total_supply
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        let balance = self.get_liquidity_balances(pool_id, to)?;
        self.set_liquidity_balances(
            pool_id,
            to,
            balance
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Emit Mint event
        self.emit_event(TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
            sender: msg_sender,
            userToken: user_token,
            validatorToken: validator_token,
            amountUserToken: amount_user_token,
            amountValidatorToken: amount_validator_token,
            liquidity,
        }))?;

        Ok(liquidity)
    }

    /// Mint LP tokens using only validator tokens
    pub fn mint_with_validator_token(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token, self.storage)?;
        validate_usd_currency(validator_token, self.storage)?;

        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools.at(pool_id).read()?;
        let mut total_supply = self.get_total_supply(pool_id)?;

        let liquidity = if pool.reserve_user_token == 0 && pool.reserve_validator_token == 0 {
            let half_amount = amount_validator_token
                .checked_div(uint!(2_U256))
                .ok_or(TempoPrecompileError::under_overflow())?;

            if half_amount <= MIN_LIQUIDITY {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }

            total_supply = total_supply
                .checked_add(MIN_LIQUIDITY)
                .ok_or(TempoPrecompileError::under_overflow())?;
            self.set_total_supply(pool_id, total_supply)?;

            half_amount
                .checked_sub(MIN_LIQUIDITY)
                .ok_or(TIPFeeAMMError::insufficient_liquidity())?
        } else {
            // Subsequent deposits: mint as if user called rebalanceSwap then minted with both
            // liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
            let product = N
                .checked_mul(U256::from(pool.reserve_user_token))
                .and_then(|product| product.checked_div(SCALE))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?;

            let denom = U256::from(pool.reserve_validator_token)
                .checked_add(product)
                .ok_or(TIPFeeAMMError::invalid_amount())?;

            if denom.is_zero() {
                return Err(TIPFeeAMMError::division_by_zero().into());
            }

            amount_validator_token
                .checked_mul(total_supply)
                .and_then(|numerator| numerator.checked_div(denom))
                .ok_or(TIPFeeAMMError::invalid_swap_calculation())?
        };

        if liquidity.is_zero() {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
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
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_add(validator_amount)
            .ok_or(TIPFeeAMMError::invalid_amount())?;

        self.pools.at(pool_id).write(pool)?;

        // Mint LP tokens
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        let balance = self.get_liquidity_balances(pool_id, to)?;
        self.set_liquidity_balances(
            pool_id,
            to,
            balance
                .checked_add(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Emit Mint event
        self.emit_event(TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
            sender: msg_sender,
            userToken: user_token,
            validatorToken: validator_token,
            amountUserToken: U256::ZERO,
            amountValidatorToken: amount_validator_token,
            liquidity,
        }))?;

        Ok(liquidity)
    }

    /// Burn LP tokens for a given pool
    pub fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256)> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses().into());
        }

        // Validate both tokens are USD currency
        validate_usd_currency(user_token, self.storage)?;
        validate_usd_currency(validator_token, self.storage)?;

        let pool_id = self.pool_id(user_token, validator_token);
        // Check user has sufficient liquidity
        let balance = self.get_liquidity_balances(pool_id, msg_sender)?;
        if balance < liquidity {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let mut pool = self.pools.at(pool_id).read()?;
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, pool_id, liquidity)?;

        // Burn LP tokens
        self.set_liquidity_balances(
            pool_id,
            msg_sender,
            balance
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;
        let total_supply = self.get_total_supply(pool_id)?;
        self.set_total_supply(
            pool_id,
            total_supply
                .checked_sub(liquidity)
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        // Update reserves with underflow checks
        let user_amount: u128 = amount_user_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        let validator_amount: u128 = amount_validator_token
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_sub(user_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        pool.reserve_validator_token = pool
            .reserve_validator_token
            .checked_sub(validator_amount)
            .ok_or(TIPFeeAMMError::insufficient_reserves())?;
        self.pools.at(pool_id).write(pool)?;

        // Transfer tokens to user
        let _ = TIP20Token::from_address(user_token)?.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_user_token,
            },
        )?;

        let _ = TIP20Token::from_address(validator_token)?.transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_validator_token,
            },
        )?;

        // Emit Burn event
        self.emit_event(TIPFeeAMMEvent::Burn(ITIPFeeAMM::Burn {
            sender: msg_sender,
            userToken: user_token,
            validatorToken: validator_token,
            amountUserToken: amount_user_token,
            amountValidatorToken: amount_validator_token,
            liquidity,
            to,
        }))?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &self,
        pool: &Pool,
        pool_id: B256,
        liquidity: U256,
    ) -> Result<(U256, U256)> {
        let total_supply = self.get_total_supply(pool_id)?;
        let amount_user_token = liquidity
            .checked_mul(U256::from(pool.reserve_user_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;
        let amount_validator_token = liquidity
            .checked_mul(U256::from(pool.reserve_validator_token))
            .and_then(|product| product.checked_div(total_supply))
            .ok_or(TempoPrecompileError::under_overflow())?;

        if !self.storage.spec().is_allegretto() {
            if amount_user_token.is_zero() || amount_validator_token.is_zero() {
                return Err(TIPFeeAMMError::insufficient_liquidity().into());
            }

            let available_user_token = self.get_effective_user_reserve(pool_id)?;
            if amount_user_token > available_user_token {
                return Err(TIPFeeAMMError::insufficient_reserves().into());
            }
        }

        // Check that withdrawal does not violate pending swaps
        let available_validator_token = self.get_effective_validator_reserve(pool_id)?;
        if amount_validator_token > available_validator_token {
            return Err(TIPFeeAMMError::insufficient_reserves().into());
        }

        Ok((amount_user_token, amount_validator_token))
    }

    /// Executes a fee swap immediately, converting userToken to validatorToken at the fixed rate m = 0.9970.
    /// Called by FeeManager.collectFeePostTx during post-transaction fee collection.
    pub fn execute_fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<U256> {
        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools.at(pool_id).read()?;

        // Calculate output at fixed price m = 0.9970
        let amount_out = compute_amount_out(amount_in)?;

        // Check if there's enough validatorToken available
        if amount_out > U256::from(pool.reserve_validator_token) {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
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

        self.pools.at(pool_id).write(pool)?;

        Ok(amount_out)
    }

    /// Execute all pending fee swaps for a pool
    pub fn execute_pending_fee_swaps(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<U256> {
        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.pools.at(pool_id).read()?;

        let amount_in = U256::from(self.get_pending_fee_swap_in(pool_id)?);
        let pending_out = compute_amount_out(amount_in)?;

        // Use checked math for these operations
        let new_user_reserve = U256::from(pool.reserve_user_token)
            .checked_add(amount_in)
            .ok_or(TempoPrecompileError::under_overflow())?;
        let new_validator_reserve = U256::from(pool.reserve_validator_token)
            .checked_sub(pending_out)
            .ok_or(TempoPrecompileError::under_overflow())?;

        pool.reserve_user_token = new_user_reserve
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        pool.reserve_validator_token = new_validator_reserve
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        self.pools.at(pool_id).write(pool)?;
        self.pending_fee_swap_in.at(pool_id).delete()?;

        self.emit_event(TIPFeeAMMEvent::FeeSwap(ITIPFeeAMM::FeeSwap {
            userToken: user_token,
            validatorToken: validator_token,
            amountIn: amount_in,
            amountOut: pending_out,
        }))?;

        Ok(pending_out)
    }

    /// Get total supply of LP tokens for a pool
    pub fn get_total_supply(&self, pool_id: B256) -> Result<U256> {
        self.total_supply.at(pool_id).read()
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: B256, total_supply: U256) -> Result<()> {
        self.total_supply.at(pool_id).write(total_supply)
    }

    /// Get user's LP token balance
    pub fn get_liquidity_balances(&self, pool_id: B256, user: Address) -> Result<U256> {
        self.liquidity_balances.at(pool_id).at(user).read()
    }

    /// Set user's LP token balance
    fn set_liquidity_balances(
        &mut self,
        pool_id: B256,
        user: Address,
        balance: U256,
    ) -> Result<()> {
        self.liquidity_balances.at(pool_id).at(user).write(balance)
    }

    /// Get pending fee swap amount for a pool
    pub fn get_pending_fee_swap_in(&self, pool_id: B256) -> Result<u128> {
        self.pending_fee_swap_in.at(pool_id).read()
    }

    /// Set pending fee swap amount for a pool
    fn set_pending_fee_swap_in(&mut self, pool_id: B256, amount: u128) -> Result<()> {
        self.pending_fee_swap_in.at(pool_id).write(amount)
    }
}

/// Calculate integer square rootu
pub fn sqrt(x: U256) -> U256 {
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

#[cfg(test)]
mod tests {
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::TIP20Error;

    use super::*;
    use crate::{
        error::TempoPrecompileError,
        storage::{ContractStorage, StorageCtx, hashmap::HashMapStorageProvider},
        test_util::TIP20Setup,
        tip_fee_manager::TIPFeeAMMError,
    };
    use alloy::primitives::Address;

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
        amm.pools.at(pool_id).write(pool)?;
        let liquidity = sqrt(user_amount * validator_amount);
        amm.total_supply.at(pool_id).write(liquidity)?;
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
                U256::from(1000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::IdenticalAddresses(_)
                ))
            ));
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
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::IdenticalAddresses(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_fee_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                liquidity,
                liquidity,
            )?;

            let amount_in = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
            amm.reserve_liquidity(user_token.address(), validator_token.address(), amount_in)?;

            let pending_in = amm.get_pending_fee_swap_in(pool_id)?;
            assert_eq!(
                pending_in,
                amount_in.try_into().unwrap(),
                "Pending input should match amount in"
            );

            let expected_out = (amount_in * M) / SCALE;
            assert_eq!(expected_out, amount_in * M / SCALE);
            Ok(())
        })
    }

    #[test]
    fn test_fee_swap_insufficient_liquidity() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let small_liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
            setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                small_liquidity,
                small_liquidity,
            )?;

            // Try to swap 201 tokens (output ~200.7, but only 100 available)
            let too_large = uint!(201_U256) * uint!(10_U256).pow(U256::from(6));
            let result =
                amm.reserve_liquidity(user_token.address(), validator_token.address(), too_large);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InsufficientLiquidity(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_fee_swap_rounding_consistency() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                liquidity,
                liquidity,
            )?;

            let amount_in = uint!(10000_U256) * uint!(10_U256).pow(U256::from(6));
            amm.reserve_liquidity(user_token.address(), validator_token.address(), amount_in)?;

            let expected_out = (amount_in * M) / SCALE;
            let actual_out =
                amm.execute_pending_fee_swaps(user_token.address(), validator_token.address())?;
            assert_eq!(actual_out, expected_out, "Output should match expected");

            let pool = amm.pools.at(pool_id).read()?;
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

    #[test]
    fn test_execute_pending_fee_swaps() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let initial = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                initial,
                initial,
            )?;

            let swap1 = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
            let swap2 = uint!(2000_U256) * uint!(10_U256).pow(U256::from(6));
            let swap3 = uint!(3000_U256) * uint!(10_U256).pow(U256::from(6));

            amm.reserve_liquidity(user_token.address(), validator_token.address(), swap1)?;
            amm.reserve_liquidity(user_token.address(), validator_token.address(), swap2)?;
            amm.reserve_liquidity(user_token.address(), validator_token.address(), swap3)?;

            let total_pending = swap1 + swap2 + swap3;
            assert_eq!(
                amm.get_pending_fee_swap_in(pool_id)?,
                total_pending.try_into().unwrap()
            );

            let total_out =
                amm.execute_pending_fee_swaps(user_token.address(), validator_token.address())?;
            let expected_out = (total_pending * M) / SCALE;
            assert_eq!(total_out, expected_out);
            assert_eq!(amm.get_pending_fee_swap_in(pool_id)?, 0);

            let pool = amm.pools.at(pool_id).read()?;
            assert_eq!(U256::from(pool.reserve_user_token), initial + total_pending);
            assert_eq!(
                U256::from(pool.reserve_validator_token),
                initial - total_out
            );
            Ok(())
        })
    }

    #[test]
    #[ignore = "Overflow in calculateLiquidity when called during rebalanceSwap (same as Solidity disabled test)"]
    fn test_rebalance_swap() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let to = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let initial_liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
            let pool_id = setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                initial_liquidity,
                initial_liquidity,
            )?;

            // Imbalance the pool via fee swap
            let user_token_in = uint!(20000_U256) * uint!(10_U256).pow(U256::from(6));
            amm.reserve_liquidity(
                user_token.address(),
                validator_token.address(),
                user_token_in,
            )?;
            amm.execute_pending_fee_swaps(user_token.address(), validator_token.address())?;

            let pool_before = amm.pools.at(pool_id).read()?;
            let x_before = U256::from(pool_before.reserve_user_token);
            let y_before = U256::from(pool_before.reserve_validator_token);

            // Execute rebalancing swap
            let swap_amount = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
            let amount_in = amm.rebalance_swap(
                admin,
                user_token.address(),
                validator_token.address(),
                swap_amount,
                to,
            )?;

            assert!(!amount_in.is_zero(), "Should provide validator tokens");

            let pool_after = amm.pools.at(pool_id).read()?;
            let x_after = U256::from(pool_after.reserve_user_token);
            let y_after = U256::from(pool_after.reserve_validator_token);

            // Rebalance: validator tokens in, user tokens out
            assert!(x_after < x_before, "User token reserve should decrease");
            assert!(
                y_after > y_before,
                "Validator token reserve should increase"
            );
            assert_eq!(
                y_after - y_before,
                amount_in,
                "Amount in should equal validator reserve increase"
            );

            // Verify imbalance reduced
            let imbalance_before = if x_before > y_before {
                x_before - y_before
            } else {
                y_before - x_before
            };
            let imbalance_after = if x_after > y_after {
                x_after - y_after
            } else {
                y_after - x_after
            };
            assert!(
                imbalance_after < imbalance_before,
                "Swap should reduce imbalance"
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
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InvalidAmount(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_reserve_liquidity_boundary() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;

            let mut amm = TipFeeManager::new();
            let liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
            setup_pool_with_liquidity(
                &mut amm,
                user_token.address(),
                validator_token.address(),
                liquidity,
                liquidity,
            )?;

            let ok_amount = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
            assert!(
                amm.reserve_liquidity(user_token.address(), validator_token.address(), ok_amount)
                    .is_ok()
            );

            let too_much = uint!(101_U256) * uint!(10_U256).pow(U256::from(6));
            assert!(
                amm.reserve_liquidity(user_token.address(), validator_token.address(), too_much)
                    .is_err()
            );
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
    fn test_rebalance_swap_rejects_non_usd_tokens() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let to = Address::random();
        StorageCtx::enter(&mut storage, || {
            let eur_token = TIP20Setup::create("EuroToken", "EUR", admin)
                .currency("EUR")
                .apply()?;
            let usd_token = TIP20Setup::create("USDToken", "USD", admin).apply()?;
            let mut amm = TipFeeManager::new();

            let result = amm.rebalance_swap(
                admin,
                eur_token.address(),
                usd_token.address(),
                U256::from(1000),
                to,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));

            let result = amm.rebalance_swap(
                admin,
                usd_token.address(),
                eur_token.address(),
                U256::from(1000),
                to,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_mint_with_validator_token_identical_addresses() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let token = TIP20Setup::create("Test", "TST", admin).apply()?;
            let mut amm = TipFeeManager::new();
            let result = amm.mint_with_validator_token(
                admin,
                token.address(),
                token.address(),
                U256::from(10000),
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::IdenticalAddresses(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_mint_with_validator_token_insufficient_amount() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin).apply()?;
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin).apply()?;
            let mut amm = TipFeeManager::new();

            // MIN_LIQUIDITY = 1000, amount/2 must be > 1000, so 2000 should fail
            let insufficient = uint!(2000_U256);
            let result = amm.mint_with_validator_token(
                admin,
                user_token.address(),
                validator_token.address(),
                insufficient,
                admin,
            );
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InsufficientLiquidity(_)
                ))
            ));
            Ok(())
        })
    }

    #[test]
    fn test_mint_with_validator_token() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let admin = Address::random();
        let user = Address::random();
        let user2 = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .with_issuer(admin)
                // Mint tokens to user
                .with_mint(user, uint!(1000000_U256))
                // Test subsequent liquidity with a different user
                .with_mint(user2, uint!(1000000_U256))
                .apply()?
                .address();
            let mut amm = TipFeeManager::new();
            let pool_id = amm.pool_id(user_token, validator_token);

            // Test initial liquidity
            let amount_validator_1 = uint!(10000_U256);
            let liquidity_1 = amm.mint_with_validator_token(
                user,
                user_token,
                validator_token,
                amount_validator_1,
                user,
            )?;

            // For first mint iquidity = (amount / 2) - MIN_LIQUIDITY = 5000 - 1000 = 4000
            assert_eq!(liquidity_1, uint!(4000_U256));

            // Verify pool state after first mint
            let pool_1 = amm.pools.at(pool_id).read()?;
            assert_eq!(pool_1.reserve_user_token, 0);
            assert_eq!(pool_1.reserve_validator_token, 10000);

            // Verify total supply after first mint
            let total_supply_1 = amm.get_total_supply(pool_id)?;
            assert_eq!(
                total_supply_1,
                uint!(5000_U256),
                "Total supply should be liquidity + MIN_LIQUIDITY"
            );

            // Verify LP balance after first mint
            let lp_balance_1 = amm.liquidity_balances.at(pool_id).at(user).read()?;
            assert_eq!(lp_balance_1, liquidity_1);

            // Verify validator token balance transferred
            let validator_balance = TIP20Token::from_address(validator_token)?
                .balance_of(ITIP20::balanceOfCall { account: user })?;
            assert_eq!(
                validator_balance,
                uint!(990000_U256),
                "Validator tokens should be transferred"
            );

            let amount_validator_2 = uint!(5000_U256);
            let liquidity_2 = amm.mint_with_validator_token(
                user2,
                user_token,
                validator_token,
                amount_validator_2,
                user2,
            )?;

            // For second mint:
            // liquidity = amountValidatorToken * totalSupply / (reserveValidatorToken + N * reserveUserToken / SCALE)
            // reserveUserToken = 0, so term N*U/SCALE = 0
            // liquidity = 5000 * 5000 / 10000 = 2500
            assert_eq!(liquidity_2, uint!(2500_U256));

            // Verify pool state after second mint
            let pool_2 = amm.pools.at(pool_id).read()?;
            assert_eq!(pool_2.reserve_user_token, 0,);
            assert_eq!(
                pool_2.reserve_validator_token, 15000,
                "Validator reserve should be 10000 + 5000"
            );

            // Verify total supply increased
            let total_supply_2 = amm.get_total_supply(pool_id)?;
            assert_eq!(
                total_supply_2,
                total_supply_1 + liquidity_2,
                "Total supply should increase by liquidity"
            );

            // Verify first user's LP balance unchanged
            let lp_balance_1_after = amm.liquidity_balances.at(pool_id).at(user).read()?;
            assert_eq!(lp_balance_1_after, liquidity_1,);

            // Verify second user's LP balance
            let lp_balance_2 = amm.liquidity_balances.at(pool_id).at(user2).read()?;
            assert_eq!(lp_balance_2, liquidity_2);

            // Verify events emitted
            amm.assert_emitted_events(vec![
                TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                    sender: user,
                    userToken: user_token,
                    validatorToken: validator_token,
                    amountUserToken: U256::ZERO,
                    amountValidatorToken: amount_validator_1,
                    liquidity: lp_balance_1,
                }),
                TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                    sender: user2,
                    userToken: user_token,
                    validatorToken: validator_token,
                    amountUserToken: U256::ZERO,
                    amountValidatorToken: amount_validator_2,
                    liquidity: lp_balance_2,
                }),
            ]);

            Ok(())
        })
    }

    /// Tests the mean calculation in add_liquidity for pre-Moderato hardfork
    /// Pre-Moderato: mean = (amount_user_token * amount_validator_token) / 2
    #[test]
    fn test_add_liquidity_pre_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Adagio);
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

            let amount1 = uint!(2000_U256);
            let amount2 = uint!(3000_U256);

            let result = amm.mint(admin, token1, token2, amount1, amount2, admin)?;

            // Pre-Moderato: mean = (2000 * 3000) / 2 = 3,000,000
            // Expected liquidity = mean - MIN_LIQUIDITY = 3,000,000 - 1000 = 2,999,000
            let expected_mean = (amount1 * amount2) / uint!(2_U256);
            let expected_liquidity = expected_mean - MIN_LIQUIDITY;

            assert_eq!(
                result, expected_liquidity,
                "Pre-Moderato should use multiplication: mean = (a * b) / 2"
            );

            Ok(())
        })
    }

    /// Tests the mean calculation in add_liquidity for post-Moderato hardfork
    /// Post-Moderato: mean = (amount_user_token + amount_validator_token) / 2
    #[test]
    fn test_add_liquidity_post_moderato() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);
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

            let amount1 = uint!(2000_U256);
            let amount2 = uint!(3000_U256);

            let result = amm.mint(admin, token1, token2, amount1, amount2, admin)?;

            // Post-Moderato: mean = (2000 + 3000) / 2 = 2,500
            // Expected liquidity = mean - MIN_LIQUIDITY = 2,500 - 1000 = 1,500
            let expected_mean = (amount1 + amount2) / uint!(2_U256);
            let expected_liquidity = expected_mean - MIN_LIQUIDITY;

            assert_eq!(
                result, expected_liquidity,
                "Post-Moderato should use addition: mean = (a + b) / 2"
            );

            Ok(())
        })
    }

    /// Tests calculate_burn_amounts pre-Allegretto rejects zero amounts
    #[test]
    fn test_calculate_burn_amounts_pre_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Moderato);

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();

            // Create a pool with very large total supply to make burn amounts round to zero
            let pool = Pool {
                reserve_user_token: 1000,
                reserve_validator_token: 1000,
            };
            let pool_id = B256::ZERO;
            amm.set_total_supply(pool_id, uint!(1000000000000000_U256))?;

            // Burning tiny liquidity should result in zero amounts
            let liquidity = uint!(1_U256);
            let result = amm.calculate_burn_amounts(&pool, pool_id, liquidity);

            // Pre-Allegretto: should reject if amounts are zero
            assert!(result.is_err(),);
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InsufficientLiquidity(_)
                ))
            ),);

            Ok(())
        })
    }

    /// Tests calculate_burn_amounts post-Allegretto allows zero amounts
    #[test]
    fn test_calculate_burn_amounts_post_allegretto() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1).with_spec(TempoHardfork::Allegretto);

        StorageCtx::enter(&mut storage, || {
            let mut amm = TipFeeManager::new();

            let pool = Pool {
                reserve_user_token: 1000,
                reserve_validator_token: 1000,
            };
            let pool_id = B256::ZERO;
            amm.set_total_supply(pool_id, uint!(1000000000000000_U256))?;

            let liquidity = uint!(1_U256);
            let result = amm.calculate_burn_amounts(&pool, pool_id, liquidity);

            // Post-Allegretto should allow zero amounts
            assert!(result.is_ok(), "Post-Allegretto should allow zero amounts");
            let (amount_user, amount_validator) = result?;
            assert_eq!(amount_user, U256::ZERO);
            assert_eq!(amount_validator, U256::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_reserve_liquidity_checks_total_pending() -> eyre::Result<()> {
        let reserve_validator_token = 627;

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::AllegroModerato);
        let admin = Address::random();

        StorageCtx::enter(&mut storage, || {
            let user_token = TIP20Setup::create("UserToken", "UTK", admin)
                .apply()?
                .address();
            let validator_token = TIP20Setup::create("ValidatorToken", "VTK", admin)
                .apply()?
                .address();

            let mut amm = TipFeeManager::new();

            let pool_id = amm.pool_id(user_token, validator_token);
            let pool = Pool {
                reserve_user_token: 1000,
                reserve_validator_token,
            };
            amm.pools.at(pool_id).write(pool)?;

            amm.reserve_liquidity(user_token, validator_token, U256::from(210))?;
            amm.reserve_liquidity(user_token, validator_token, U256::from(210))?;

            let result = amm.reserve_liquidity(user_token, validator_token, U256::from(210));
            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InsufficientLiquidity(_)
                ))
            ));

            assert_eq!(amm.get_pending_fee_swap_in(pool_id)?, 420);

            let amount_out = amm.execute_pending_fee_swaps(user_token, validator_token)?;
            assert_eq!(amount_out, U256::from(418));

            let pool_after = amm.pools.at(pool_id).read()?;
            assert_eq!(
                pool_after.reserve_validator_token,
                reserve_validator_token - 418
            );
            assert_eq!(pool_after.reserve_user_token, 1000 + 420);

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
            let pool = amm.pools.at(pool_id).read()?;
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

            assert!(matches!(
                result,
                Err(TempoPrecompileError::TIPFeeAMMError(
                    TIPFeeAMMError::InsufficientLiquidity(_)
                ))
            ));

            Ok(())
        })
    }
}
