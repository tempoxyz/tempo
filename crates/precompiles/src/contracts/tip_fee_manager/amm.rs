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
pub const M: U256 = uint!(9970_U256); // m = 0.9970 (scaled by 10000)
pub const N: U256 = uint!(9985_U256);
pub const SCALE: U256 = uint!(10000_U256);
pub const SQRT_SCALE: U256 = uint!(100000_U256);
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Pool structure matching the Solidity implementation
#[derive(Debug, Clone, Default)]
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

/// Storage slots for FeeAMM
pub mod slots {
    use crate::contracts::storage::slots::{double_mapping_slot, mapping_slot};
    use alloy::primitives::{U256, uint};
    use alloy_primitives::{Address, B256};

    // FeeAMM storage slots
    pub const POOLS: U256 = uint!(0_U256);
    pub const PENDING_FEE_SWAP_IN: U256 = uint!(1_U256);
    pub const TOTAL_SUPPLY: U256 = uint!(2_U256);
    pub const BALANCE_OF: U256 = uint!(3_U256);

    /// Get storage slot for pool data
    pub fn pool_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, POOLS)
    }

    /// Get storage slot for pending fee swap in amount
    pub fn pending_fee_swap_in_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, PENDING_FEE_SWAP_IN)
    }

    /// Get storage slot for total supply of LP tokens
    pub fn total_supply_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, TOTAL_SUPPLY)
    }

    /// Get storage slot for user's LP token balance
    pub fn balance_of_slot(pool_id: &B256, user: &Address) -> U256 {
        double_mapping_slot(pool_id, user, BALANCE_OF)
    }
}

pub struct TIPFeeAMM<'a, S: StorageProvider> {
    pub contract_address: Address,
    pub storage: &'a mut S,
}

impl<'a, S: StorageProvider> TIPFeeAMM<'a, S> {
    /// Creates a new TIPFeeAMM instance with the given contract address and storage provider.
    /// This is the main entry point for interacting with the AMM contract.
    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    /// Gets the pool id for a given set of tokens. Note that the pool id is dependent on the
    /// ordering of the tokens ie. (token_a, token_b) results in a different pool id
    /// than (token_b, token_a)
    pub fn get_pool_id(&self, user_token: Address, validator_token: Address) -> B256 {
        PoolKey::new(user_token, validator_token).get_id()
    }

    /// Retrieves a pool for a given `pool_id` from storage
    pub fn get_pool(&mut self, pool_id: &B256) -> Pool {
        let slot = slots::pool_slot(pool_id);
        let reserves = self.sload(slot);
        let reserve_user_token = (reserves & U256::from(u128::MAX)).to::<u128>();
        let reserve_validator_token = reserves.wrapping_shr(128).to::<u128>();

        Pool {
            reserve_user_token,
            reserve_validator_token,
        }
    }

    /// Checks if pool has enough liquidity for a fee swap
    pub fn has_liquidity(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> bool {
        let pool_id = PoolKey::new(user_token, validator_token).get_id();
        let amount_out = (amount_in * M) / SCALE;
        let available_validator_token = self.get_effective_validator_reserve(&pool_id);
        amount_out <= available_validator_token
    }

    /// Calculate validator token reserve minus pending swaps
    fn get_effective_validator_reserve(&mut self, pool_id: &B256) -> U256 {
        let pool = self.get_pool(pool_id);
        let pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id);
        let pending_out = (pending_fee_swap_in * M) / SCALE;

        U256::from(pool.reserve_validator_token) - pending_out
    }

    /// Calculate user token reserve plus pending swaps
    fn get_effective_user_reserve(&mut self, pool_id: &B256) -> U256 {
        let pool = self.get_pool(pool_id);
        let pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id);

        U256::from(pool.reserve_user_token) + pending_fee_swap_in
    }

    /// Execute a swap from one fee token to another
    pub fn fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
    ) -> Result<(), TIPFeeAMMError> {
        if !self.has_liquidity(user_token, validator_token, amount_in) {
            return Err(TIPFeeAMMError::insufficient_liquidity());
        }

        let pool_id = self.get_pool_id(user_token, validator_token);
        let current_pending = self.get_pending_fee_swap_in(&pool_id);
        self.set_pending_fee_swap_in(&pool_id, current_pending + amount_in);

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
    ) -> Result<U256, TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        let mut pool = self.get_pool(&pool_id);

        // Rebalancing swaps are always from validatorToken to userToken
        // Calculate input and update reserves
        let amount_in = (amount_out * N) / SCALE + U256::ONE;

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

        if !self.can_support_pending_swaps(&pool_id, U256::from(pool.reserve_validator_token)) {
            return Err(TIPFeeAMMError::insufficient_liquidity_for_pending());
        }
        self.set_pool(&pool_id, &pool);

        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let amount_in = U256::from(amount_in);
        let amount_out = U256::from(amount_out);
        TIP20Token::new(validator_token_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: amount_in,
                },
            )
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

        let user_token_id = address_to_token_id_unchecked(&user_token);
        TIP20Token::new(user_token_id, self.storage)
            .transfer(
                &self.contract_address,
                ITIP20::transferCall {
                    to,
                    amount: amount_out,
                },
            )
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

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
            .map_err(|_| TIPFeeAMMError::internal_error())?;

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
    ) -> Result<U256, TIPFeeAMMError> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses());
        }

        let pool_id = self.get_pool_id(user_token, validator_token);
        let mut pool = self.get_pool(&pool_id);
        let total_supply = self.get_total_supply(&pool_id);

        let liquidity = if total_supply.is_zero() {
            // TODO: checked math
            let mean = (amount_user_token * amount_validator_token) / uint!(2_U256);
            if mean <= MIN_LIQUIDITY {
                return Err(TIPFeeAMMError::insufficient_liquidity());
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
            return Err(TIPFeeAMMError::insufficient_liquidity());
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
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

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
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

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
            .map_err(|_| TIPFeeAMMError::internal_error())?;

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
    ) -> Result<(U256, U256), TIPFeeAMMError> {
        if user_token == validator_token {
            return Err(TIPFeeAMMError::identical_addresses());
        }

        let pool_id = self.get_pool_id(user_token, validator_token);
        // Check user has sufficient liquidity
        let balance = self.get_balance_of(&pool_id, &msg_sender);
        if balance < liquidity {
            return Err(TIPFeeAMMError::insufficient_liquidity());
        }

        let mut pool = self.get_pool(&pool_id);
        // Calculate amounts to return
        let (amount_user_token, amount_validator_token) =
            self.calculate_burn_amounts(&pool, &pool_id, liquidity)?;

        // Burn LP tokens
        self.set_balance_of(&pool_id, &msg_sender, balance - liquidity);
        let total_supply = self.get_total_supply(&pool_id);
        self.set_total_supply(&pool_id, total_supply - liquidity);

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
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let _ = TIP20Token::new(validator_token_id, self.storage)
            .transfer(
                &self.contract_address,
                ITIP20::transferCall {
                    to,
                    amount: amount_validator_token,
                },
            )
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

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
            .map_err(|_| TIPFeeAMMError::internal_error())?;

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
            return Err(TIPFeeAMMError::insufficient_liquidity());
        }

        // Check that withdrawal does not violate pending swaps
        let available_user_token = self.get_effective_user_reserve(pool_id);
        let available_validator_token = self.get_effective_validator_reserve(pool_id);

        if amount_user_token > available_user_token {
            return Err(TIPFeeAMMError::insufficient_reserves());
        }

        if amount_validator_token > available_validator_token {
            return Err(TIPFeeAMMError::insufficient_reserves());
        }

        Ok((amount_user_token, amount_validator_token))
    }

    /// Execute all pending fee swaps for a pool
    pub fn execute_pending_fee_swaps(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<U256, TIPFeeAMMError> {
        let pool_id = self.get_pool_id(user_token, validator_token);
        let mut pool = self.get_pool(&pool_id);

        let amount_in = self.get_pending_fee_swap_in(&pool_id);
        let pending_out = (amount_in * M) / SCALE;

        // Use checked math for these operations
        let new_user_reserve = U256::from(pool.reserve_user_token) + amount_in;
        let new_validator_reserve = U256::from(pool.reserve_validator_token) - pending_out;

        pool.reserve_user_token = new_user_reserve
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;
        pool.reserve_validator_token = new_validator_reserve
            .try_into()
            .map_err(|_| TIPFeeAMMError::invalid_amount())?;

        self.set_pool(&pool_id, &pool);
        self.set_pending_fee_swap_in(&pool_id, U256::ZERO);

        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::FeeSwap(ITIPFeeAMM::FeeSwap {
                    userToken: user_token,
                    validatorToken: validator_token,
                    amountIn: amount_in,
                    amountOut: pending_out,
                })
                .into_log_data(),
            )
            .map_err(|_| TIPFeeAMMError::internal_error())?;

        Ok(pending_out)
    }

    /// Set pool data in storage
    pub fn set_pool(&mut self, pool_id: &B256, pool: &Pool) {
        let slot = slots::pool_slot(pool_id);
        let packed =
            U256::from(pool.reserve_user_token) | (U256::from(pool.reserve_validator_token) << 128);
        self.sstore(slot, packed);
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

    /// Get pending fee swap amount for a pool
    pub fn get_pending_fee_swap_in(&mut self, pool_id: &B256) -> U256 {
        let slot = slots::pending_fee_swap_in_slot(pool_id);
        self.sload(slot)
    }

    /// Set pending fee swap amount for a pool
    fn set_pending_fee_swap_in(&mut self, pool_id: &B256, amount: U256) {
        let slot = slots::pending_fee_swap_in_slot(pool_id);
        self.sstore(slot, amount);
    }

    /// Check if new validator reserve can support pending swaps
    fn can_support_pending_swaps(&mut self, pool_id: &B256, new_validator_reserve: U256) -> bool {
        let pending_fee_swap_in = self.get_pending_fee_swap_in(pool_id);
        let pending_out = (pending_fee_swap_in * M) / SCALE;

        new_validator_reserve >= pending_out
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

impl<'a, S: StorageProvider> StorageOps for TIPFeeAMM<'a, S> {
    /// Store value in contract storage
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.contract_address, slot, value)
            .expect("Storage operation failed");
    }

    /// Load value from contract storage
    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.contract_address, slot)
            .expect("Storage operation failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{HashMapStorageProvider, types::TIPFeeAMMError};

    #[test]
    fn test_mint_identical_addresses() {
        let mut storage = HashMapStorageProvider::new(1);
        let contract_address = Address::random();
        let mut amm = TIPFeeAMM::new(contract_address, &mut storage);

        let msg_sender = Address::random();
        let token = Address::random();
        let amount = U256::from(1000);
        let to = Address::random();

        let result = amm.mint(msg_sender, token, token, amount, amount, to);

        assert!(matches!(result, Err(TIPFeeAMMError::IdenticalAddresses(_))));
    }

    #[test]
    fn test_burn_identical_addresses() {
        let mut storage = HashMapStorageProvider::new(1);
        let contract_address = Address::random();
        let mut amm = TIPFeeAMM::new(contract_address, &mut storage);

        let msg_sender = Address::random();
        let token = Address::random();
        let liquidity = U256::from(1000);
        let to = Address::random();

        let result = amm.burn(msg_sender, token, token, liquidity, to);

        assert!(matches!(result, Err(TIPFeeAMMError::IdenticalAddresses(_))));
    }
}
