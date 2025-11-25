use crate::{
    error::{Result, TempoPrecompileError},
    storage::PrecompileStorageProvider,
    tip_fee_manager::{ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent, TipFeeManager},
    tip20::{ITIP20, TIP20Token, validate_usd_currency},
};
use alloy::{
    primitives::{Address, B256, IntoLogData, U256, keccak256, uint},
    sol_types::SolValue,
};
use tempo_precompiles_macros::Storable;

/// Constants from the Solidity reference implementation
pub const M: U256 = uint!(9970_U256); // m = 0.9970 (scaled by 10000)
pub const N: U256 = uint!(9985_U256);
pub const SCALE: U256 = uint!(10000_U256);
pub const SQRT_SCALE: U256 = uint!(100000_U256);
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub user_token: Address,
    pub validator_token: Address,
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

impl<'a, S: PrecompileStorageProvider> TipFeeManager<'a, S> {
    /// Gets the pool id for a given set of tokens. Note that the pool id is dependent on the
    /// ordering of the tokens ie. (token_a, token_b) results in a different pool id
    /// than (token_b, token_a)
    pub fn pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Retrieves a pool for a given `pool_id` from storage
    pub fn get_pool(&mut self, call: ITIPFeeAMM::getPoolCall) -> Result<Pool> {
        let pool_id = self.pool_id(call.userToken, call.validatorToken);
        self.sload_pools(pool_id)
    }

    /// Ensures that pool has enough liquidity for a fee swap and reserve that liquidity in `pending_fee_swap_in`.
    pub fn reserve_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        max_amount: U256,
    ) -> Result<()> {
        let pool_id = PoolKey::new(user_token, validator_token).get_id();
        let amount_out = max_amount
            .checked_mul(M)
            .map(|product| product / SCALE)
            .ok_or(TempoPrecompileError::under_overflow())?;
        let available_validator_token = self.get_effective_validator_reserve(pool_id)?;

        if amount_out > available_validator_token {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        let current_pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id)?;
        self.set_pending_fee_swap_in(
            pool_id,
            current_pending_fee_swap_in
                .checked_add(
                    max_amount
                        .try_into()
                        .map_err(|_| TempoPrecompileError::under_overflow())?,
                )
                .ok_or(TempoPrecompileError::under_overflow())?,
        )?;

        Ok(())
    }

    /// Calculate validator token reserve minus pending swaps
    fn get_effective_validator_reserve(&mut self, pool_id: B256) -> Result<U256> {
        let pool = self.sload_pools(pool_id)?;
        let pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id)?;
        let pending_out = U256::from(pending_fee_swap_in)
            .checked_mul(M)
            .and_then(|product| product.checked_div(SCALE))
            .ok_or(TempoPrecompileError::under_overflow())?;

        U256::from(pool.reserve_validator_token)
            .checked_sub(pending_out)
            .ok_or(TempoPrecompileError::under_overflow())
    }

    /// Calculate user token reserve plus pending swaps
    fn get_effective_user_reserve(&mut self, pool_id: B256) -> Result<U256> {
        let pool = self.sload_pools(pool_id)?;
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
        let mut pool = self.sload_pools(pool_id)?;

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

        self.sstore_pools(pool_id, pool)?;

        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        TIP20Token::from_address(validator_token, self.storage).system_transfer_from(
            msg_sender,
            self.address,
            amount_in,
        )?;

        TIP20Token::from_address(user_token, self.storage).transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_out,
            },
        )?;

        self.storage.emit_event(
            self.address,
            TIPFeeAMMEvent::RebalanceSwap(ITIPFeeAMM::RebalanceSwap {
                userToken: user_token,
                validatorToken: validator_token,
                swapper: msg_sender,
                amountIn: amount_in,
                amountOut: amount_out,
            })
            .into_log_data(),
        )?;

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
        let mut pool = self.sload_pools(pool_id)?;
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
        let _ = TIP20Token::from_address(user_token, self.storage).system_transfer_from(
            msg_sender,
            self.address,
            amount_user_token,
        )?;

        let _ = TIP20Token::from_address(validator_token, self.storage).system_transfer_from(
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
        self.sstore_pools(pool_id, pool)?;

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
        self.storage.emit_event(
            self.address,
            TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                sender: msg_sender,
                userToken: user_token,
                validatorToken: validator_token,
                amountUserToken: amount_user_token,
                amountValidatorToken: amount_validator_token,
                liquidity,
            })
            .into_log_data(),
        )?;

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
        let mut pool = self.sload_pools(pool_id)?;
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
            //  liquidity = amountValidatorToken * _totalSupply / (V + n * U), with n = N / SCALE
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
        let _ = TIP20Token::from_address(validator_token, self.storage).system_transfer_from(
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

        self.sstore_pools(pool_id, pool)?;

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
        self.storage.emit_event(
            self.address,
            TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                sender: msg_sender,
                userToken: user_token,
                validatorToken: validator_token,
                amountUserToken: U256::ZERO,
                amountValidatorToken: amount_validator_token,
                liquidity,
            })
            .into_log_data(),
        )?;

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

        let mut pool = self.sload_pools(pool_id)?;
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
        self.sstore_pools(pool_id, pool)?;

        // Transfer tokens to user
        let _ = TIP20Token::from_address(user_token, self.storage).transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_user_token,
            },
        )?;

        let _ = TIP20Token::from_address(validator_token, self.storage).transfer(
            self.address,
            ITIP20::transferCall {
                to,
                amount: amount_validator_token,
            },
        )?;

        // Emit Burn event
        self.storage.emit_event(
            self.address,
            TIPFeeAMMEvent::Burn(ITIPFeeAMM::Burn {
                sender: msg_sender,
                userToken: user_token,
                validatorToken: validator_token,
                amountUserToken: amount_user_token,
                amountValidatorToken: amount_validator_token,
                liquidity,
                to,
            })
            .into_log_data(),
        )?;

        Ok((amount_user_token, amount_validator_token))
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &mut self,
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

        if amount_user_token.is_zero() || amount_validator_token.is_zero() {
            return Err(TIPFeeAMMError::insufficient_liquidity().into());
        }

        // Check that withdrawal does not violate pending swaps
        let available_user_token = self.get_effective_user_reserve(pool_id)?;
        let available_validator_token = self.get_effective_validator_reserve(pool_id)?;

        if amount_user_token > available_user_token {
            return Err(TIPFeeAMMError::insufficient_reserves().into());
        }

        if amount_validator_token > available_validator_token {
            return Err(TIPFeeAMMError::insufficient_reserves().into());
        }

        Ok((amount_user_token, amount_validator_token))
    }

    /// Execute all pending fee swaps for a pool
    pub fn execute_pending_fee_swaps(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<U256> {
        let pool_id = self.pool_id(user_token, validator_token);
        let mut pool = self.sload_pools(pool_id)?;

        let amount_in = U256::from(self.get_pending_fee_swap_in(pool_id)?);
        let pending_out = amount_in
            .checked_mul(M)
            .and_then(|product| product.checked_div(SCALE))
            .ok_or(TempoPrecompileError::under_overflow())?;

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

        self.sstore_pools(pool_id, pool)?;
        self.clear_pending_fee_swap_in(pool_id)?;

        self.storage.emit_event(
            self.address,
            TIPFeeAMMEvent::FeeSwap(ITIPFeeAMM::FeeSwap {
                userToken: user_token,
                validatorToken: validator_token,
                amountIn: amount_in,
                amountOut: pending_out,
            })
            .into_log_data(),
        )?;

        Ok(pending_out)
    }

    /// Get total supply of LP tokens for a pool
    pub fn get_total_supply(&mut self, pool_id: B256) -> Result<U256> {
        self.sload_total_supply(pool_id)
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: B256, total_supply: U256) -> Result<()> {
        self.sstore_total_supply(pool_id, total_supply)
    }

    /// Get user's LP token balance
    pub fn get_liquidity_balances(&mut self, pool_id: B256, user: Address) -> Result<U256> {
        self.sload_liquidity_balances(pool_id, user)
    }

    /// Set user's LP token balance
    fn set_liquidity_balances(
        &mut self,
        pool_id: B256,
        user: Address,
        balance: U256,
    ) -> Result<()> {
        self.sstore_liquidity_balances(pool_id, user, balance)
    }

    /// Get pending fee swap amount for a pool
    pub fn get_pending_fee_swap_in(&mut self, pool_id: B256) -> Result<u128> {
        self.sload_pending_fee_swap_in(pool_id)
    }

    /// Set pending fee swap amount for a pool
    fn set_pending_fee_swap_in(&mut self, pool_id: B256, amount: u128) -> Result<()> {
        self.sstore_pending_fee_swap_in(pool_id, amount)
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
    use super::*;
    use crate::{
        PATH_USD_ADDRESS,
        error::TempoPrecompileError,
        storage::{ContractStorage, hashmap::HashMapStorageProvider},
        tip20::{TIP20Token, tests::initialize_path_usd, token_id_to_address},
    };
    use alloy::primitives::{Address, uint};
    use tempo_contracts::precompiles::TIP20Error;

    #[test]
    fn test_mint_identical_addresses() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TipFeeManager::new(&mut storage);

        let msg_sender = Address::random();
        let token = Address::random();
        let amount = U256::from(1000);
        let to = Address::random();

        let result = amm.mint(msg_sender, token, token, amount, amount, to);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::IdenticalAddresses(_)
            ))
        ));
    }

    #[test]
    fn test_burn_identical_addresses() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TipFeeManager::new(&mut storage);

        let msg_sender = Address::random();
        let token = Address::random();
        let liquidity = U256::from(1000);
        let to = Address::random();

        let result = amm.burn(msg_sender, token, token, liquidity, to);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::IdenticalAddresses(_)
            ))
        ));
    }

    fn setup_test_amm() -> (
        TipFeeManager<'static, HashMapStorageProvider>,
        Address,
        Address,
        Address,
    ) {
        let storage = Box::leak(Box::new(HashMapStorageProvider::new(1)));
        let admin = Address::random();

        // Initialize PathUSD first
        initialize_path_usd(storage, admin).unwrap();

        // Create USD tokens for user and validator
        let user_token = token_id_to_address(1);
        let mut user_tip20 = TIP20Token::from_address(user_token, storage);
        user_tip20
            .initialize(
                "UserToken",
                "UTK",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let validator_token = token_id_to_address(2);
        let mut validator_tip20 = TIP20Token::from_address(validator_token, storage);
        validator_tip20
            .initialize(
                "ValidatorToken",
                "VTK",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let amm = TipFeeManager::new(storage);
        (amm, Address::ZERO, user_token, validator_token)
    }

    fn setup_pool_with_liquidity(
        amm: &mut TipFeeManager<'_, impl PrecompileStorageProvider>,
        user_token: Address,
        validator_token: Address,
        user_amount: U256,
        validator_amount: U256,
    ) -> Result<B256> {
        let pool_id = amm.pool_id(user_token, validator_token);
        let pool = Pool {
            reserve_user_token: user_amount.to::<u128>(),
            reserve_validator_token: validator_amount.to::<u128>(),
        };
        amm.sstore_pools(pool_id, pool)?;

        // Set initial liquidity supply
        let liquidity = if user_amount == validator_amount {
            // Simplified: for equal amounts, liquidity ~= amount
            user_amount
        } else {
            // Use geometric mean for unequal amounts
            sqrt(user_amount * validator_amount)
        };
        amm.set_total_supply(pool_id, liquidity)?;

        Ok(pool_id)
    }

    /// Test basic fee swap functionality
    /// Corresponds to testFeeSwap in StableAMM.t.sol
    #[test]
    fn test_fee_swap() -> eyre::Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100,000 tokens each
        let liquidity_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            liquidity_amount,
            liquidity_amount,
        )?;

        // Execute fee swap for 1000 tokens
        let amount_in = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));

        // Calculate expected output: amountIn * 0.9975
        let expected_out = (amount_in * M) / SCALE;

        // Execute fee swap
        amm.reserve_liquidity(user_token, validator_token, amount_in)?;

        // Check pending swaps updated
        let pending_in = amm.get_pending_fee_swap_in(pool_id)?;
        assert_eq!(
            pending_in,
            amount_in.to::<u128>(),
            "Pending input should match amount in"
        );

        // Verify the expected output calculation
        assert_eq!(expected_out, amount_in * M / SCALE);

        Ok(())
    }

    /// Test fee swap with insufficient liquidity
    /// Corresponds to testFeeSwapInsufficientLiquidity in StableAMM.t.sol
    #[test]
    fn test_fee_swap_insufficient_liquidity() {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with only 100 tokens each
        let small_liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
        setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            small_liquidity,
            small_liquidity,
        )
        .unwrap();

        // Try to swap 201 tokens (would output ~200.7 tokens, but only 100 available)
        let too_large_amount = uint!(201_U256) * uint!(10_U256).pow(U256::from(6));

        // Execute fee swap - should fail
        let result = amm.reserve_liquidity(user_token, validator_token, too_large_amount);

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::InsufficientLiquidity(_)
            ))
        ))
    }

    /// Test fee swap rounding consistency
    /// Corresponds to testFeeSwapRoundingConsistency in StableAMM.t.sol
    #[test]
    fn test_fee_swap_rounding_consistency() -> eyre::Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100,000 tokens each
        let liquidity_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            liquidity_amount,
            liquidity_amount,
        )?;

        // Test with a clean input amount
        let amount_in = uint!(10000_U256) * uint!(10_U256).pow(U256::from(6));

        // Execute fee swap
        amm.reserve_liquidity(user_token, validator_token, amount_in)?;

        // Calculate expected output using integer division (rounds down)
        let expected_out = (amount_in * M) / SCALE;

        // Execute pending swaps and verify reserves
        let actual_out = amm.execute_pending_fee_swaps(user_token, validator_token)?;
        assert_eq!(actual_out, expected_out, "Output should match expected");

        // Check reserves updated correctly
        let pool = amm.sload_pools(pool_id)?;
        assert_eq!(
            U256::from(pool.reserve_user_token),
            liquidity_amount + amount_in,
            "User token reserve should increase by input"
        );
        assert_eq!(
            U256::from(pool.reserve_validator_token),
            liquidity_amount - actual_out,
            "Validator token reserve should decrease by output"
        );

        Ok(())
    }

    /// Test execute pending fee swaps
    #[test]
    fn test_execute_pending_fee_swaps() -> Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool
        let initial_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            initial_amount,
            initial_amount,
        )?;

        // Execute multiple fee swaps
        let swap1 = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
        let swap2 = uint!(2000_U256) * uint!(10_U256).pow(U256::from(6));
        let swap3 = uint!(3000_U256) * uint!(10_U256).pow(U256::from(6));

        amm.reserve_liquidity(user_token, validator_token, swap1)?;
        amm.reserve_liquidity(user_token, validator_token, swap2)?;
        amm.reserve_liquidity(user_token, validator_token, swap3)?;

        // Check total pending
        let total_pending = swap1 + swap2 + swap3;
        assert_eq!(
            amm.get_pending_fee_swap_in(pool_id)
                .expect("Could not get fee swap in"),
            total_pending.to::<u128>()
        );

        // Execute all pending swaps
        let total_out = amm.execute_pending_fee_swaps(user_token, validator_token)?;
        let expected_total_out = (total_pending * M) / SCALE;
        assert_eq!(total_out, expected_total_out);

        // Verify pending cleared
        assert_eq!(
            amm.get_pending_fee_swap_in(pool_id)
                .expect("Could not get fee swap in"),
            0
        );

        // Verify reserves updated
        let pool = amm.sload_pools(pool_id)?;
        assert_eq!(
            U256::from(pool.reserve_user_token),
            initial_amount + total_pending
        );
        assert_eq!(
            U256::from(pool.reserve_validator_token),
            initial_amount - total_out
        );

        Ok(())
    }

    /// Test rebalance swap in correct direction
    /// Corresponds to disabled_testRebalanceSwapTowardBalance in StableAMM.t.sol
    #[test]
    #[ignore = "Overflow in calculateLiquidity when called during rebalanceSwap (same as Solidity disabled test)"]
    fn test_rebalance_swap() -> Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Add balanced liquidity first (using same decimals as Solidity test)
        let initial_liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6)); // 100000 * 1e6
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            initial_liquidity,
            initial_liquidity,
        )?;

        // Make the pool imbalanced by executing a fee swap
        let user_token_in = uint!(20000_U256) * uint!(10_U256).pow(U256::from(6)); // 20000 * 1e6
        amm.reserve_liquidity(user_token, validator_token, user_token_in)?;
        amm.execute_pending_fee_swaps(user_token, validator_token)?;

        let pool_before = amm.sload_pools(pool_id)?;
        let x_before = U256::from(pool_before.reserve_user_token);
        let y_before = U256::from(pool_before.reserve_validator_token);

        // Execute rebalancing swap using the actual function
        let swap_amount = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6)); // 1000 * 1e6
        let msg_sender = Address::random();
        let to = Address::random();
        let amount_in =
            amm.rebalance_swap(msg_sender, user_token, validator_token, swap_amount, to)?;

        // Verify the swap input
        assert!(amount_in > 0, "Should provide validator tokens");

        // Get updated pool state
        let pool_after = amm.sload_pools(pool_id)?;
        let x_after = U256::from(pool_after.reserve_user_token);
        let y_after = U256::from(pool_after.reserve_validator_token);

        // For rebalance swap: validator tokens go in, user tokens come out
        assert!(x_after < x_before, "User token reserve should decrease");
        assert!(
            y_after > y_before,
            "Validator token reserve should increase"
        );

        // The amount_in returned is the validator tokens provided
        assert_eq!(
            y_after - y_before,
            amount_in,
            "Amount in should equal increase in validator reserve"
        );

        // Verify the swap reduces imbalance
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
    }

    /// Test rebalance swap with insufficient user funds
    #[test]
    fn test_rebalance_swap_insufficient_funds() -> eyre::Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup balanced pool
        let amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id =
            setup_pool_with_liquidity(&mut amm, user_token, validator_token, amount, amount)?;

        let pool = amm.sload_pools(pool_id)?;
        assert_eq!(pool.reserve_user_token, pool.reserve_validator_token,);

        let msg_sender = Address::random();
        let to = Address::random();
        let result = amm.rebalance_swap(
            msg_sender,
            user_token,
            validator_token,
            amount + U256::ONE,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::InvalidAmount(_)
            )),
        ));

        Ok(())
    }

    /// Test has_liquidity function
    #[test]
    fn test_has_liquidity() -> eyre::Result<()> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100 tokens
        let liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
        setup_pool_with_liquidity(&mut amm, user_token, validator_token, liquidity, liquidity)?;

        // Test with amount that would work
        let ok_amount = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
        assert!(
            amm.reserve_liquidity(user_token, validator_token, ok_amount)
                .is_ok(),
            "Should have liquidity for 100 tokens"
        );

        // Test with amount that would fail
        let too_much = uint!(101_U256) * uint!(10_U256).pow(U256::from(6));
        assert!(
            amm.reserve_liquidity(user_token, validator_token, too_much)
                .is_err(),
            "Should not have liquidity for 101 tokens"
        );

        Ok(())
    }

    #[test]
    fn test_mint_rejects_non_usd_user_token() {
        let mut storage = HashMapStorageProvider::new(1);
        let amount = U256::from(1000);

        let admin = Address::random();
        let msg_sender = Address::random();
        let to = Address::random();

        // Init Linking USD, user token and validator tokens
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage);
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut user_token = TIP20Token::new(1, &mut storage);
        user_token
            .initialize(
                "TestToken",
                "TEST",
                "EUR",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let user_token_address = user_token.address();

        let mut validator_token = TIP20Token::new(2, &mut storage);
        validator_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let validator_token_address = validator_token.address();

        let mut amm = TipFeeManager::new(&mut storage);
        let result = amm.mint(
            msg_sender,
            user_token_address,
            validator_token_address,
            amount,
            amount,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        // Test the inverse tokens
        let result = amm.mint(
            msg_sender,
            validator_token_address,
            user_token_address,
            amount,
            amount,
            to,
        );
        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));
    }

    #[test]
    fn test_burn_rejects_non_usd_tokens() {
        let mut storage = HashMapStorageProvider::new(1);
        let liquidity = U256::from(1000);

        let admin = Address::random();
        let msg_sender = Address::random();
        let to = Address::random();

        // Init Linking USD, user token and validator tokens
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage);
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut user_token = TIP20Token::new(1, &mut storage);
        user_token
            .initialize(
                "TestToken",
                "TEST",
                "EUR",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let user_token_address = user_token.address();

        let mut validator_token = TIP20Token::new(2, &mut storage);
        validator_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let validator_token_address = validator_token.address();

        let mut amm = TipFeeManager::new(&mut storage);
        let result = amm.burn(
            msg_sender,
            user_token_address,
            validator_token_address,
            liquidity,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        // Test the inverse tokens
        let result = amm.burn(
            msg_sender,
            validator_token_address,
            user_token_address,
            liquidity,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));
    }
    #[test]
    fn test_rebalance_swap_rejects_non_usd_tokens() {
        let mut storage = HashMapStorageProvider::new(1);

        let admin = Address::random();
        let msg_sender = Address::random();
        let amount_out = U256::from(1000);
        let to = Address::random();

        // Init Linking USD, user token and validator tokens
        let mut path_usd = TIP20Token::from_address(PATH_USD_ADDRESS, &mut storage);
        path_usd
            .initialize(
                "PathUSD",
                "LUSD",
                "USD",
                Address::ZERO,
                admin,
                Address::ZERO,
            )
            .unwrap();

        let mut user_token = TIP20Token::new(1, &mut storage);
        user_token
            .initialize(
                "TestToken",
                "TEST",
                "EUR",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let user_token_address = user_token.address();

        let mut validator_token = TIP20Token::new(2, &mut storage);
        validator_token
            .initialize(
                "TestToken",
                "TEST",
                "USD",
                PATH_USD_ADDRESS,
                admin,
                Address::ZERO,
            )
            .unwrap();
        let validator_token_address = validator_token.address();

        let mut amm = TipFeeManager::new(&mut storage);
        let result = amm.rebalance_swap(
            msg_sender,
            user_token_address,
            validator_token_address,
            amount_out,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));

        // Test the inverse tokens
        let mut amm = TipFeeManager::new(&mut storage);
        let result = amm.rebalance_swap(
            msg_sender,
            validator_token_address,
            user_token_address,
            amount_out,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIP20(TIP20Error::InvalidCurrency(_)))
        ));
    }

    #[test]
    fn test_mint_with_validator_token_identical_addresses() {
        let (mut amm, _, user_token, _) = setup_test_amm();
        let msg_sender = Address::random();
        let to = Address::random();
        let amount = uint!(10000_U256);

        // Try to mint with identical user and validator tokens
        let result = amm.mint_with_validator_token(
            msg_sender, user_token, user_token, // Same as user_token
            amount, to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::IdenticalAddresses(_)
            ))
        ));
    }

    #[test]
    fn test_mint_with_validator_token_insufficient_amount() {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();
        let msg_sender = Address::random();
        let to = Address::random();

        // Try to mint with amount that would result in insufficient liquidity
        // MIN_LIQUIDITY is 1000, so amount/2 must be > 1000, meaning amount must be > 2000
        let insufficient_amount = uint!(2000_U256); // This equals MIN_LIQUIDITY when divided by 2

        let result = amm.mint_with_validator_token(
            msg_sender,
            user_token,
            validator_token,
            insufficient_amount,
            to,
        );

        assert!(matches!(
            result,
            Err(TempoPrecompileError::TIPFeeAMMError(
                TIPFeeAMMError::InsufficientLiquidity(_)
            ))
        ));
    }
}
