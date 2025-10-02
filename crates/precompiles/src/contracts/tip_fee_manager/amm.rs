use crate::contracts::{
    address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip20::TIP20Token,
    types::{ITIP20, ITIPFeeAMM, TIPFeeAMMError, TIPFeeAMMEvent},
};
use alloy::{
    primitives::{Address, B256, IntoLogData, U256, keccak256, uint},
    sol_types::SolValue,
};

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
    use alloy::primitives::{Address, B256, U256, uint};

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
            .system_transfer_from(msg_sender, self.contract_address, amount_in)
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
            .system_transfer_from(msg_sender, self.contract_address, amount_user_token)
            .map_err(|_| TIPFeeAMMError::token_transfer_failed())?;

        let validator_token_id = address_to_token_id_unchecked(&validator_token);
        let _ = TIP20Token::new(validator_token_id, self.storage)
            .system_transfer_from(msg_sender, self.contract_address, amount_validator_token)
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
    use crate::contracts::{HashMapStorageProvider, token_id_to_address, types::TIPFeeAMMError};
    use alloy::primitives::{Address, uint};

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

    fn setup_test_amm() -> (
        TIPFeeAMM<'static, HashMapStorageProvider>,
        Address,
        Address,
        Address,
    ) {
        let storage = Box::leak(Box::new(HashMapStorageProvider::new(1)));
        let user_token = token_id_to_address(1);
        let validator_token = token_id_to_address(2);
        let amm = TIPFeeAMM::new(Address::ZERO, storage);
        (amm, Address::ZERO, user_token, validator_token)
    }

    fn setup_pool_with_liquidity(
        amm: &mut TIPFeeAMM<'_, impl StorageProvider>,
        user_token: Address,
        validator_token: Address,
        user_amount: U256,
        validator_amount: U256,
    ) -> B256 {
        let pool_id = amm.get_pool_id(user_token, validator_token);
        let pool = Pool {
            reserve_user_token: user_amount.to::<u128>(),
            reserve_validator_token: validator_amount.to::<u128>(),
        };
        amm.set_pool(&pool_id, &pool);

        // Set initial liquidity supply
        let liquidity = if user_amount == validator_amount {
            // Simplified: for equal amounts, liquidity ~= amount
            user_amount
        } else {
            // Use geometric mean for unequal amounts
            sqrt(user_amount * validator_amount)
        };
        amm.set_total_supply(&pool_id, liquidity);

        pool_id
    }

    /// Test basic fee swap functionality
    /// Corresponds to testFeeSwap in StableAMM.t.sol
    #[test]
    fn test_fee_swap() -> Result<(), TIPFeeAMMError> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100,000 tokens each
        let liquidity_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            liquidity_amount,
            liquidity_amount,
        );

        // Execute fee swap for 1000 tokens
        let amount_in = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));

        // Calculate expected output: amountIn * 0.9975
        let expected_out = (amount_in * M) / SCALE;

        // Execute fee swap
        amm.fee_swap(user_token, validator_token, amount_in)?;

        // Check pending swaps updated
        let pending_in = amm.get_pending_fee_swap_in(&pool_id);
        assert_eq!(
            pending_in, amount_in,
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
        );

        // Try to swap 201 tokens (would output ~200.7 tokens, but only 100 available)
        let too_large_amount = uint!(201_U256) * uint!(10_U256).pow(U256::from(6));

        // Execute fee swap - should fail
        let result = amm.fee_swap(user_token, validator_token, too_large_amount);

        assert!(matches!(
            result,
            Err(TIPFeeAMMError::InsufficientLiquidity(_))
        ))
    }

    /// Test fee swap rounding consistency
    /// Corresponds to testFeeSwapRoundingConsistency in StableAMM.t.sol
    #[test]
    fn test_fee_swap_rounding_consistency() -> Result<(), TIPFeeAMMError> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100,000 tokens each
        let liquidity_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            liquidity_amount,
            liquidity_amount,
        );

        // Test with a clean input amount
        let amount_in = uint!(10000_U256) * uint!(10_U256).pow(U256::from(6));

        // Execute fee swap
        amm.fee_swap(user_token, validator_token, amount_in)?;

        // Calculate expected output using integer division (rounds down)
        let expected_out = (amount_in * M) / SCALE;

        // Execute pending swaps and verify reserves
        let actual_out = amm.execute_pending_fee_swaps(user_token, validator_token)?;
        assert_eq!(actual_out, expected_out, "Output should match expected");

        // Check reserves updated correctly
        let pool = amm.get_pool(&pool_id);
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
    fn test_execute_pending_fee_swaps() -> Result<(), TIPFeeAMMError> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool
        let initial_amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            initial_amount,
            initial_amount,
        );

        // Execute multiple fee swaps
        let swap1 = uint!(1000_U256) * uint!(10_U256).pow(U256::from(6));
        let swap2 = uint!(2000_U256) * uint!(10_U256).pow(U256::from(6));
        let swap3 = uint!(3000_U256) * uint!(10_U256).pow(U256::from(6));

        amm.fee_swap(user_token, validator_token, swap1)?;
        amm.fee_swap(user_token, validator_token, swap2)?;
        amm.fee_swap(user_token, validator_token, swap3)?;

        // Check total pending
        let total_pending = swap1 + swap2 + swap3;
        assert_eq!(amm.get_pending_fee_swap_in(&pool_id), total_pending);

        // Execute all pending swaps
        let total_out = amm.execute_pending_fee_swaps(user_token, validator_token)?;
        let expected_total_out = (total_pending * M) / SCALE;
        assert_eq!(total_out, expected_total_out);

        // Verify pending cleared
        assert_eq!(amm.get_pending_fee_swap_in(&pool_id), U256::ZERO);

        // Verify reserves updated
        let pool = amm.get_pool(&pool_id);
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
    fn test_rebalance_swap() -> Result<(), TIPFeeAMMError> {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Add balanced liquidity first (using same decimals as Solidity test)
        let initial_liquidity = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6)); // 100000 * 1e6
        let pool_id = setup_pool_with_liquidity(
            &mut amm,
            user_token,
            validator_token,
            initial_liquidity,
            initial_liquidity,
        );

        // Make the pool imbalanced by executing a fee swap
        let user_token_in = uint!(20000_U256) * uint!(10_U256).pow(U256::from(6)); // 20000 * 1e6
        amm.fee_swap(user_token, validator_token, user_token_in)?;
        amm.execute_pending_fee_swaps(user_token, validator_token)?;

        let pool_before = amm.get_pool(&pool_id);
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
        let pool_after = amm.get_pool(&pool_id);
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
    fn test_rebalance_swap_insufficient_funds() {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup balanced pool
        let amount = uint!(100000_U256) * uint!(10_U256).pow(U256::from(6));
        let pool_id =
            setup_pool_with_liquidity(&mut amm, user_token, validator_token, amount, amount);

        let pool = amm.get_pool(&pool_id);
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

        assert!(matches!(result, Err(TIPFeeAMMError::InvalidAmount(_))),);
    }

    /// Test has_liquidity function
    #[test]
    fn test_has_liquidity() {
        let (mut amm, _, user_token, validator_token) = setup_test_amm();

        // Setup pool with 100 tokens
        let liquidity = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
        setup_pool_with_liquidity(&mut amm, user_token, validator_token, liquidity, liquidity);

        // Test with amount that would work
        let ok_amount = uint!(100_U256) * uint!(10_U256).pow(U256::from(6));
        assert!(
            amm.has_liquidity(user_token, validator_token, ok_amount),
            "Should have liquidity for 100 tokens"
        );

        // Test with amount that would fail
        let too_much = uint!(101_U256) * uint!(10_U256).pow(U256::from(6));
        assert!(
            !amm.has_liquidity(user_token, validator_token, too_much),
            "Should not have liquidity for 101 tokens"
        );
    }
}
