use crate::contracts::{
    address_to_token_id_unchecked,
    storage::{
        StorageOps, StorageProvider,
        slots::{double_mapping_slot, mapping_slot},
    },
    tip_fee_manager::pool::PoolKey,
    tip20::TIP20Token,
    types::{ITIP20, ITIPFeeAMM, TIPFeeAMMError},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use alloy_primitives::FixedBytes;

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

/// FeeAMM implementation matching the Solidity reference
pub struct FeeAMM<'a, S: StorageProvider> {
    pub contract_address: Address,
    pub storage: &'a mut S,
}

impl<'a, S: StorageProvider> FeeAMM<'a, S> {
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
        let pending_fee_swap_in = self.sload(slot).to::<u128>();

        Pool {
            reserve_user_token,
            reserve_validator_token,
            pending_fee_swap_in,
        }
    }

    /// Execute a fee swap (protocol only)
    pub fn fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
        to: Address,
    ) -> Result<U256, &'static str> {
        todo!("Implement fee_swap")
    }

    /// Execute a rebalancing swap
    pub fn rebalance_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_in: U256,
        to: Address,
    ) -> Result<U256, &'static str> {
        todo!("Implement rebalance_swap")
    }

    /// Calculate liquidity based on reserves
    pub fn calculate_liquidity(&self, x: U256, y: U256) -> U256 {
        todo!("Implement calculate_liquidity")
    }

    /// Calculate new reserve after swap
    pub fn calculate_new_reserve(&self, new_y: U256, l: U256) -> U256 {
        todo!("Implement calculate_new_reserve")
    }

    /// Mint liquidity tokens
    pub fn mint(
        &mut self,
        user_token: Address,
        validator_token: Address,
        amount_user_token: U256,
        amount_validator_token: U256,
        to: Address,
    ) -> Result<U256, &'static str> {
        todo!("Implement mint")
    }

    /// Burn liquidity tokens
    pub fn burn(
        &mut self,
        user_token: Address,
        validator_token: Address,
        liquidity: U256,
        to: Address,
    ) -> Result<(U256, U256), &'static str> {
        todo!("Implement burn")
    }

    /// Execute pending fee swap
    pub fn execute_pending_fee_swap(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> Result<U256, &'static str> {
        todo!("Implement execute_pending_fee_swap")
    }

    /// Get pending user token amount for fee swap
    pub fn get_pending_user_token(
        &mut self,
        user_token: Address,
        validator_token: Address,
    ) -> U256 {
        todo!("Implement get_pending_user_token")
    }

    /// Check if swap can be supported by current reserves
    fn can_support_swap(&self, new_user_reserve: U256, new_validator_reserve: U256) -> bool {
        todo!("Implement can_support_swap")
    }

    /// Execute rebalance swap implementation
    fn execute_rebalance_swap(&mut self, pool: &mut Pool, amount_in: U256) -> U256 {
        todo!("Implement execute_rebalance_swap")
    }

    /// Calculate burn amounts for liquidity withdrawal
    fn calculate_burn_amounts(
        &mut self,
        pool: &Pool,
        liquidity: U256,
        total_supply: U256,
    ) -> Result<(U256, U256), &'static str> {
        todo!("Implement calculate_burn_amounts")
    }

    /// Get effective user token reserve (current + pending)
    fn get_effective_user_reserve(&self, pool: &Pool) -> U256 {
        todo!("Implement get_effective_user_reserve")
    }

    /// Get effective validator token reserve (current - pending out)
    fn get_effective_validator_reserve(&self, pool: &Pool) -> U256 {
        todo!("Implement get_effective_validator_reserve")
    }

    /// Set pool data in storage
    fn set_pool(&mut self, pool_id: &B256, pool: &Pool) {
        let slot = slots::pool_slot(pool_id);
        // Pack pool data: pending_fee_swap_in (128) | reserve_validator_token (128) | reserve_user_token (128)
        let packed = U256::from(pool.reserve_user_token)
            | (U256::from(pool.reserve_validator_token) << 128)
            | (U256::from(pool.pending_fee_swap_in) << 256);
        self.sstore(slot, packed);
    }

    /// Check if pool exists
    fn pool_exists(&mut self, pool_id: &B256) -> bool {
        let slot = slots::pool_exists_slot(pool_id);
        self.sload(slot) != U256::ZERO
    }

    /// Set pool existence flag
    fn set_pool_exists(&mut self, pool_id: &B256) {
        let slot = slots::pool_exists_slot(pool_id);
        self.sstore(slot, U256::ONE);
    }

    /// Get total supply of LP tokens for a pool
    fn get_total_supply(&mut self, pool_id: &B256) -> U256 {
        let slot = slots::total_supply_slot(pool_id);
        self.sload(slot)
    }

    /// Set total supply of LP tokens for a pool
    fn set_total_supply(&mut self, pool_id: &B256, total_supply: U256) {
        let slot = slots::total_supply_slot(pool_id);
        self.sstore(slot, total_supply);
    }

    /// Get user's LP token balance
    fn get_balance_of(&mut self, pool_id: &B256, user: &Address) -> U256 {
        let slot = slots::balance_of_slot(pool_id, user);
        self.sload(slot)
    }

    /// Set user's LP token balance
    fn set_balance_of(&mut self, pool_id: &B256, user: &Address, balance: U256) {
        let slot = slots::balance_of_slot(pool_id, user);
        self.sstore(slot, balance);
    }

    /// Integer square root implementation
    fn sqrt(&self, x: U256) -> U256 {
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
}

impl<'a, S: StorageProvider> StorageOps for FeeAMM<'a, S> {
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
