use crate::contracts::{
    address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip20::TIP20Token,
    types::{ITIP20, ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use alloy_primitives::IntoLogData;

/// Constants from the Solidity reference implementation
pub const M: U256 = uint!(9975_U256);
pub const SQRT_M: U256 = uint!(99874921_U256); // sqrt(0.9975) scaled by 100000
pub const SCALE: U256 = uint!(10000_U256);
pub const SQRT_SCALE: U256 = uint!(100000_U256);
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Pool structure matching the Solidity implementation
#[derive(Debug, Clone, Default)]
pub struct Pool {
    pub reserve_user_token: u128,
    pub reserve_validator_token: u128,
    pub pending_fee_swap_in: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(value: Pool) -> Self {
        Self {
            reserveUserToken: value.reserve_user_token,
            reserveValidatorToken: value.reserve_validator_token,
            pendingFeeSwapIn: value.pending_fee_swap_in,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub user_token: Address,
    pub validator_token: Address,
}

impl PoolKey {
    pub fn new(user_token: Address, validator_token: Address) -> Self {
        Self {
            user_token,
            validator_token,
        }
    }

    pub fn get_id(&self) -> B256 {
        keccak256((self.user_token, self.validator_token).abi_encode())
    }
}

/// Storage slots for FeeAMM
pub mod slots {
    use crate::contracts::storage::slots::{double_mapping_slot, mapping_slot};
    use alloy::primitives::{U256, uint};
    use alloy_primitives::{Address, B256};

    // FeeAMM storage slots
    pub const POOLS: U256 = uint!(0_U256);
    pub const TOTAL_SUPPLY: U256 = uint!(1_U256);
    pub const BALANCE_OF: U256 = uint!(2_U256);
    pub const POOL_EXISTS: U256 = uint!(3_U256);

    /// Get storage slot for pool data
    pub fn pool_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, POOLS)
    }

    /// Get storage slot for total supply of LP tokens
    pub fn total_supply_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, TOTAL_SUPPLY)
    }

    /// Get storage slot for user's LP token balance
    pub fn balance_of_slot(pool_id: &B256, user: &Address) -> U256 {
        double_mapping_slot(pool_id, user, BALANCE_OF)
    }

    /// Get storage slot for pool existence flag
    pub fn pool_exists_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, POOL_EXISTS)
    }
}

pub struct TIPFeeAMM<'a, S: StorageProvider> {
    pub contract_address: Address,
    pub storage: &'a mut S,
}

impl<'a, S: StorageProvider> TIPFeeAMM<'a, S> {
    /// Create new FeeAMM instance
    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    /// Create a new pool for the given token pair
    pub fn create_pool(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<(), TIPFeeAMMError> {
        if user_token == validator_token {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::IdenticalAddresses(
                ITIPFeeAMM::IdenticalAddresses {},
            ));
        }
        if user_token == Address::ZERO || validator_token == Address::ZERO {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidToken(
                ITIPFeeAMM::InvalidToken {},
            ));
        }

        let pool_id = self.get_pool_id(user_token, validator_token);
        if self.pool_exists(&pool_id) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolExists(
                ITIPFeeAMM::PoolExists {},
            ));
        }

        // Initialize empty pool
        self.set_pool(&pool_id, &Pool::default());
        self.set_pool_exists(&pool_id);

        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::PoolCreated(ITIPFeeAMM::PoolCreated {
                    userToken: user_token,
                    validatorToken: validator_token,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Get pool ID for a token pair
    pub fn get_pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Get pool data for the given pool ID
    pub fn get_pool(&mut self, pool_id: &B256) -> Pool {
        let slot = slots::pool_slot(pool_id);
        let reserves = self.sload(slot);
        let reserve_user_token = (reserves & U256::from(u128::MAX)).to::<u128>();
        let reserve_validator_token = reserves.wrapping_shr(128).to::<u128>();

        let slot = slots::pool_slot(pool_id);
        let pending_fee_swap_in = self.sload(slot + U256::ONE).to::<u128>();

        Pool {
            reserve_user_token,
            reserve_validator_token,
            pending_fee_swap_in,
        }
    }

    /// Execute a pending fee swaps
    pub fn execute_pending_fee_swaps(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<U256, TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        self.ensure_pool_exists(&pool_id)?;

        let mut pool = self.get_pool(&pool_id);
        let pending_out = (U256::from(pool.pending_fee_swap_in) * M) / SCALE;

        pool.reserve_user_token = pool
            .reserve_user_token
            .checked_add(pool.pending_fee_swap_in)
            .expect("TODO: handle overflow");

        let amount_out = pool.reserve_validator_token - pending_out.to::<u128>();
        pool.reserve_validator_token = amount_out;

        // Clear pending swap
        pool.pending_fee_swap_in = 0;
        self.set_pool(&pool_id, &pool);

        Ok(U256::from(amount_out))
    }

    /// Execute a rebalancing swap
    pub fn rebalance_swap(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
        to: Address,
    ) -> Result<U256, TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        self.ensure_pool_exists(&pool_id)?;

        let mut pool = self.get_pool(&pool_id);

        let amount_out = self.execute_rebalance_swap(&mut pool, amount_in)?;

        // Transfer tokens
        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let _ = TIP20Token::new(validator_token_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: amount_in,
                },
            )
            .expect("TODO: handle error");

        let user_token_id = address_to_token_id_unchecked(&user_token);
        let _ = TIP20Token::new(user_token_id, self.storage)
            .transfer(
                &self.contract_address,
                ITIP20::transferCall {
                    to,
                    amount: amount_out,
                },
            )
            .expect("TODO: handle error");

        self.set_pool(&pool_id, &pool);

        // Emit RebalanceSwap event
        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::RebalanceSwap(ITIPFeeAMM::RebalanceSwap {
                    userToken: user_token,
                    validatorToken: validator_token,
                    swapper: msg_sender,
                    amountIn: amount_in,
                    amountOut: amount_out,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(amount_out)
    }

    /// Execute rebalance swap implementation
    fn execute_rebalance_swap(
        &mut self,
        pool: &mut Pool,
        amount_in: U256,
    ) -> Result<U256, TIPFeeAMMError> {
        // Use current reserves for pricing
        let x = U256::from(pool.reserve_user_token);
        let y = U256::from(pool.reserve_validator_token);

        // For rebalancing, we are adding validatorToken (y), removing userToken (x)
        // This is valid only when y < x
        if y >= x {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidRebalanceState(
                ITIPFeeAMM::InvalidRebalanceState {},
            ));
        }

        // Calculate dynamic liquidity L based on current reserves
        let l = self.calculate_liquidity(x, y);
        let y_1 = y + amount_in;
        let x_1 = self.calculate_new_reserve(y_1, l)?;

        if x_1 >= x {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidRebalanceDirection(
                ITIPFeeAMM::InvalidRebalanceDirection {},
            ));
        }

        if y_1 > x_1 {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidNewReserves(
                ITIPFeeAMM::InvalidNewReserves {},
            ));
        }

        // Check that the new reserves can support pending fee swaps
        if !self.can_support_pending_swap(pool, y_1) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::CannotSupportPendingSwaps(
                ITIPFeeAMM::CannotSupportPendingSwaps {},
            ));
        }

        // Update pool reserves
        pool.reserve_user_token = x_1.to::<u128>();
        pool.reserve_validator_token = y_1.to::<u128>();

        Ok(x - x_1)
    }

    /// Calculate liquidity based on reserves
    pub fn calculate_liquidity(&self, x: U256, y: U256) -> U256 {
        //  L = (y + sqrt(m)*x + sqrt(y^2 + m*x^2 + (4-2*sqrt(m))*x*y)) / (2*(1-sqrt(m)))
        let sqrt_m_x = (SQRT_M * x) / SQRT_SCALE;
        let m_x2 = (M * x * x) / SCALE;
        let y2 = y * y;

        let coefficient = uint!(4_U256) * SQRT_SCALE - uint!(2_U256) * SQRT_M;
        let coeff_xy = (coefficient * x * y) / SQRT_SCALE;
        let under_sqrt = y2 + m_x2 + coeff_xy;

        let sqrt_term = sqrt(under_sqrt);
        let numerator = y + sqrt_m_x + sqrt_term;
        let denominator = uint!(2_U256) * (SQRT_SCALE - SQRT_M);

        (numerator * SQRT_SCALE) / denominator
    }

    /// Calculate new reserve after swap
    pub fn calculate_new_reserve(
        &self,
        known_validator_reserve: U256,
        l: U256,
    ) -> Result<U256, TIPFeeAMMError> {
        // From the invariant: (x + L)(y + L*sqrt(m)) = L^2
        // For rebalancing swaps (validatorToken → userToken), we know new y, solve for new x:
        // x = L^2 / (y + L*sqrt(m)) - L

        let l_sqrt_m = (l * SQRT_M) / SQRT_SCALE;
        let l2 = l * l;
        let denominator = known_validator_reserve + l_sqrt_m;

        if denominator.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::DivisionByZero(
                ITIPFeeAMM::DivisionByZero {},
            ));
        }

        let result = l2 / denominator;
        if result <= l {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidNewReserves(
                ITIPFeeAMM::InvalidNewReserves {},
            ));
        }

        Ok(result - l)
    }

    /// Mint liquidity tokens
    pub fn mint(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        amount_user_token: U256,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256, TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        self.ensure_pool_exists(&pool_id)?;

        let mut pool = self.get_pool(&pool_id);
        let total_supply = self.get_total_supply(&pool_id);

        // TODO: ensure min balance
        let liquidity = if total_supply.is_zero() {
            let mean = (amount_user_token + amount_validator_token) / uint!(2_U256);
            if mean <= MIN_LIQUIDITY {
                return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                    ITIPFeeAMM::InsufficientLiquidity {},
                ));
            }
            self.set_total_supply(&pool_id, MIN_LIQUIDITY);
            mean - MIN_LIQUIDITY
        } else {
            let liquidity_user = if pool.reserve_user_token > 0 {
                (amount_user_token * total_supply) / U256::from(pool.reserve_user_token)
            } else {
                U256::MAX
            };

            let liquidity_validator = if pool.reserve_validator_token > 0 {
                (amount_validator_token * total_supply) / U256::from(pool.reserve_validator_token)
            } else {
                U256::MAX
            };

            liquidity_user.min(liquidity_validator)
        };

        if liquidity.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        // Transfer tokens from user to contract
        let user_token_id = address_to_token_id_unchecked(&user_token);
        let _ = TIP20Token::new(user_token_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: amount_user_token,
                },
            )
            .expect("TODO: handle error");

        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let _ = TIP20Token::new(validator_token_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: amount_validator_token,
                },
            )
            .expect("TODO: handle error");

        // Update reserves
        pool.reserve_user_token += amount_user_token.to::<u128>();
        pool.reserve_validator_token += amount_validator_token.to::<u128>();
        self.set_pool(&pool_id, &pool);

        // Mint LP tokens
        let current_total_supply = self.get_total_supply(&pool_id);
        self.set_total_supply(&pool_id, current_total_supply + liquidity);
        let balance = self.get_balance_of(&pool_id, &to);
        self.set_balance_of(&pool_id, &to, balance + liquidity);

        // Emit Mint event
        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                    sender: msg_sender,
                    userToken: user_token,
                    validatorToken: validator_token,
                    amountUserToken: amount_user_token,
                    amountValidatorToken: amount_validator_token,
                    liquidity,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(liquidity)
    }

    /// Burn liquidity tokens
    pub fn burn(
        &mut self,
        msg_sender: Address,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256), TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        self.ensure_pool_exists(&pool_id)?;

        // Check user has sufficient liquidity
        let balance = self.get_balance_of(&pool_id, &to);
        if balance < liquidity {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        let mut pool = self.get_pool(&pool_id);
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, &pool_id, liquidity)?;

        // Burn LP tokens
        self.set_balance_of(&pool_id, &to, balance - liquidity);
        let total_supply = self.get_total_supply(&pool_id);
        self.set_total_supply(&pool_id, total_supply - liquidity);

        // Update reserves
        pool.reserve_user_token -= amount_user_token.to::<u128>();
        pool.reserve_validator_token -= amount_validator_token.to::<u128>();
        self.set_pool(&pool_id, &pool);

        // Transfer tokens to user
        let user_token_id = address_to_token_id_unchecked(&user_token);
        let _ = TIP20Token::new(user_token_id, self.storage)
            .transfer(
                &self.contract_address,
                ITIP20::transferCall {
                    to,
                    amount: amount_user_token,
                },
            )
            .expect("TODO: handle error");

        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let _ = TIP20Token::new(validator_token_id, self.storage)
            .transfer(
                &self.contract_address,
                ITIP20::transferCall {
                    to,
                    amount: amount_validator_token,
                },
            )
            .expect("TODO: handle error");

        // Emit Burn event
        self.storage
            .emit_event(
                self.contract_address,
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
            )
            .expect("TODO: handle error");

        Ok((amount_user_token, amount_validator_token))
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &mut self,
        pool: &Pool,
        pool_id: &B256,
        liquidity: U256,
    ) -> Result<(U256, U256), TIPFeeAMMError> {
        let total_supply = self.get_total_supply(pool_id);
        let amount_user_token = (liquidity * U256::from(pool.reserve_user_token)) / total_supply;
        let amount_validator_token =
            (liquidity * U256::from(pool.reserve_validator_token)) / total_supply;

        if amount_user_token.is_zero() || amount_validator_token.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        // Check that withdrawal does not violate pending swaps

        let available_user_token = self.get_effective_user_reserve(pool);
        let available_validator_token = self.get_effective_validator_reserve(pool);

        if amount_user_token > available_user_token {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientReserves(
                ITIPFeeAMM::InsufficientReserves {},
            ));
        }

        if amount_validator_token > available_validator_token {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientReserves(
                ITIPFeeAMM::InsufficientReserves {},
            ));
        }

        Ok((amount_user_token, amount_validator_token))
    }

    /// Get total pending swaps for a specific pool
    pub fn get_total_pending_swaps(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> U256 {
        let pool_id = self.get_pool_id(user_token, validator_token);
        let pool = self.get_pool(&pool_id);
        U256::from(pool.pending_fee_swap_in)
    }

    /// Get effective user token reserve
    // NOTE: this function will be used for swap logic
    fn get_effective_user_reserve(&self, pool: &Pool) -> U256 {
        U256::from(pool.reserve_user_token + pool.pending_fee_swap_in)
    }

    /// Get effective validator token reserve (current - pending out)
    fn get_effective_validator_reserve(&self, pool: &Pool) -> U256 {
        let pending_out = (U256::from(pool.pending_fee_swap_in) * M) / SCALE;
        U256::from(pool.reserve_validator_token) - pending_out
    }

    /// Check if swap can be supported by current reserves
    fn can_support_pending_swap(&self, pool: &Pool, new_validator_reserve: U256) -> bool {
        // Check if new reserves can support all pending fee swaps
        let pending_out = (U256::from(pool.pending_fee_swap_in) * M) / SCALE;

        // userToken will increase by pendingFeeSwapIn
        // validatorToken will decrease by pendingOut
        new_validator_reserve >= pending_out
    }

    /// Set pool data in storage
    pub fn set_pool(&mut self, pool_id: &B256, pool: &Pool) {
        let slot = slots::pool_slot(pool_id);
        let packed =
            U256::from(pool.reserve_user_token) | (U256::from(pool.reserve_validator_token) << 128);
        self.sstore(slot, packed);
        self.sstore(slot + U256::ONE, U256::from(pool.pending_fee_swap_in));
    }

    /// Check if pool exists
    pub fn pool_exists(&mut self, pool_id: &B256) -> bool {
        let slot = slots::pool_exists_slot(pool_id);
        self.sload(slot) != U256::ZERO
    }

    /// Set pool existence flag
    fn set_pool_exists(&mut self, pool_id: &B256) {
        let slot = slots::pool_exists_slot(pool_id);
        self.sstore(slot, U256::ONE);
    }

    /// Ensure pool exists, returning error if it doesn't
    fn ensure_pool_exists(&mut self, pool_id: &B256) -> Result<(), TIPFeeAMMError> {
        if !self.pool_exists(pool_id) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolDoesNotExist(
                ITIPFeeAMM::PoolDoesNotExist {},
            ));
        }
        Ok(())
    }

    /// Get total supply of LP tokens for a pool
    pub fn get_total_supply(&mut self, pool_id: &B256) -> U256 {
        let slot = slots::total_supply_slot(pool_id);
        self.sload(slot)
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: &B256, total_supply: U256) {
        let slot = slots::total_supply_slot(pool_id);
        self.sstore(slot, total_supply);
    }

    /// Get user's LP token balance
    pub fn get_balance_of(&mut self, pool_id: &B256, user: &Address) -> U256 {
        let slot = slots::balance_of_slot(pool_id, user);
        self.sload(slot)
    }

    /// Set user's LP token balance
    fn set_balance_of(&mut self, pool_id: &B256, user: &Address, balance: U256) {
        let slot = slots::balance_of_slot(pool_id, user);
        self.sstore(slot, balance);
    }
}

/// Integer square root
pub fn sqrt(x: U256) -> U256 {
    if x == U256::ZERO {
        return U256::ZERO;
    }
    let mut z = (x + U256::from(1)) / U256::from(2);
    let mut y = x;
    while z < y {
        y = z;
        z = (x / z + z) / U256::from(2);
    }
    y
}

impl<'a, S: StorageProvider> StorageOps for TIPFeeAMM<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.contract_address, slot, value)
            .expect("Storage operation failed");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.contract_address, slot)
            .expect("Storage operation failed")
    }
}
