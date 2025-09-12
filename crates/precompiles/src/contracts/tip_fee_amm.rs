use crate::contracts::{
    storage::{StorageProvider, slots::mapping_slot},
    types::ITIPFeeAMM,
};
use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol_types::SolValue,
};

/// Storage slots for TIPFeeAMM
///
/// IMPORTANT: These slots are shared with FeeManager when it inherits from TIPFeeAMM.
/// FeeManager uses the same slots (0-3) for AMM functionality and adds its own slots (4+).
/// This allows FeeManager to operate as a full TIPFeeAMM while extending it with fee capabilities.
pub mod slots {
    use alloy::primitives::{U256, uint};

    // Base AMM storage slots (also used by FeeManager)
    pub const POOLS: U256 = U256::ZERO; // Slot 0: Pool reserves mapping
    pub const POOL_EXISTS: U256 = uint!(2_U256); // Slot 2: Pool existence mapping
    // Slot 3 would be for additional AMM data (liquidity, etc.)
    // Slots 4+ are reserved for FeeManager-specific data
}

/// Represents a liquidity pool
#[derive(Debug, Clone)]
pub struct Pool {
    pub reserve0: u128,
    pub reserve1: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(pool: Pool) -> Self {
        Self {
            reserve0: pool.reserve0,
            reserve1: pool.reserve1,
        }
    }
}

/// Pool key with ordered tokens
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: Address,
    pub token1: Address,
}

impl PoolKey {
    pub fn new(token_a: Address, token_b: Address) -> Self {
        let (token0, token1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        Self { token0, token1 }
    }

    pub fn get_id(&self) -> B256 {
        keccak256((self.token0, self.token1).abi_encode())
    }
}

impl From<PoolKey> for ITIPFeeAMM::PoolKey {
    fn from(key: PoolKey) -> Self {
        Self {
            token0: key.token0,
            token1: key.token1,
        }
    }
}

impl From<ITIPFeeAMM::PoolKey> for PoolKey {
    fn from(key: ITIPFeeAMM::PoolKey) -> Self {
        Self::new(key.token0, key.token1)
    }
}

/// TIPFeeAMM implementation - Base AMM contract for stablecoin pools.
///
/// INHERITANCE MODEL:
/// - TIPFeeAMM serves as the base contract providing core AMM functionality
/// - FeeManager inherits from TIPFeeAMM, extending it with fee management capabilities
/// - Both contracts share the same storage space when FeeManager is deployed
///
/// STORAGE SHARING:
/// - When FeeManager creates a TIPFeeAMM instance, it passes its own contract address
/// - This means both FeeManager and TIPFeeAMM operate on the same storage slots
/// - TIPFeeAMM uses slots 0-3, FeeManager extends with slots 4+
///
/// This design allows FeeManager to be a full-featured AMM while adding fee-specific logic.
pub struct TIPFeeAMM<'a, S: StorageProvider> {
    pub contract_address: Address,
    pub storage: &'a mut S,
}

impl<'a, S: StorageProvider> TIPFeeAMM<'a, S> {
    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    // Storage slot helpers
    fn get_pool_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::POOLS)
    }

    fn get_pool_exists_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::POOL_EXISTS)
    }

    /// Create a new liquidity pool
    pub fn create_pool(
        &mut self,
        call: ITIPFeeAMM::createPoolCall,
    ) -> Result<(), ITIPFeeAMM::ITIPFeeAMMErrors> {
        if call.tokenA == call.tokenB {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::IdenticalAddresses(
                ITIPFeeAMM::IdenticalAddresses {},
            ));
        }

        if call.tokenA == Address::ZERO || call.tokenB == Address::ZERO {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InvalidToken(
                ITIPFeeAMM::InvalidToken {},
            ));
        }

        let pool_key = PoolKey::new(call.tokenA, call.tokenB);
        let pool_id = pool_key.get_id();

        // Check if pool already exists
        let exists_slot = self.get_pool_exists_slot(&pool_id);
        if self
            .storage
            .sload(self.contract_address, exists_slot)
            .expect("TODO: handle error")
            != U256::ZERO
        {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolExists(
                ITIPFeeAMM::PoolExists {},
            ));
        }

        let pool_slot = self.get_pool_slot(&pool_id);
        // Store as packed uint128 values. reserve1 in high 128 bits, reserve0 in low 128 bits
        self.storage
            .sstore(self.contract_address, pool_slot, U256::ZERO)
            .expect("TODO: handle error");

        // Mark pool as existing
        self.storage
            .sstore(self.contract_address, exists_slot, U256::ONE)
            .expect("TODO: handle error");

        // TODO: emit event

        Ok(())
    }

    /// Get pool ID for a given key
    pub fn get_pool_id(&mut self, call: ITIPFeeAMM::getPoolIdCall) -> B256 {
        let pool_key = PoolKey::from(call.key);
        pool_key.get_id()
    }

    /// Get pool data
    pub fn get_pool(&mut self, call: ITIPFeeAMM::getPoolCall) -> ITIPFeeAMM::Pool {
        let pool_key = PoolKey::from(call.key);
        let pool_id = pool_key.get_id();
        let pool_slot = self.get_pool_slot(&pool_id);

        let pool_value = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        // Unpack: reserve1 in high 128 bits, reserve0 in low 128 bits
        let reserve0 = (pool_value & U256::from(u128::MAX)).to::<u128>();
        let reserve1 = pool_value.wrapping_shr(128).to::<u128>();

        ITIPFeeAMM::Pool { reserve0, reserve1 }
    }

    /// Get pool data by ID
    pub fn pools(&mut self, call: ITIPFeeAMM::poolsCall) -> ITIPFeeAMM::Pool {
        let pool_slot = self.get_pool_slot(&call.poolId);
        let combined = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        let reserve0 = combined.to_be_bytes::<32>()[16..32]
            .try_into()
            .map(u128::from_be_bytes)
            .expect("TODO: handle error");
        let reserve1 = combined.to_be_bytes::<32>()[0..16]
            .try_into()
            .map(u128::from_be_bytes)
            .expect("TODO: handle error");

        ITIPFeeAMM::Pool { reserve0, reserve1 }
    }

    /// Check if pool exists
    pub fn pool_exists(&mut self, call: ITIPFeeAMM::poolExistsCall) -> bool {
        let exists_slot = self.get_pool_exists_slot(&call.poolId);
        self.storage
            .sload(self.contract_address, exists_slot)
            .expect("TODO: handle error")
            != U256::ZERO
    }

    /// Check if pool exists by key
    pub fn pool_exists_for_tokens(&mut self, token0: Address, token1: Address) -> bool {
        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();
        let exists_slot = self.get_pool_exists_slot(&pool_id);

        self.storage
            .sload(self.contract_address, exists_slot)
            .expect("TODO: handle error")
            != U256::ZERO
    }

    /// Get pool reserves for validation
    pub fn get_pool_reserves(&mut self, pool_id: &B256) -> (U256, U256) {
        let pool_slot = self.get_pool_slot(pool_id);
        let pool_value = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        let reserve0 = U256::from((pool_value & U256::from(u128::MAX)).to::<u128>());
        let reserve1 = U256::from(pool_value.wrapping_shr(128).to::<u128>());

        (reserve0, reserve1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::HashMapStorageProvider;

    #[test]
    fn test_pool_key_ordering() {
        let addr1 = Address::from([1u8; 20]);
        let addr2 = Address::from([2u8; 20]);

        let key1 = PoolKey::new(addr1, addr2);
        let key2 = PoolKey::new(addr2, addr1);

        assert_eq!(key1.token0, addr1);
        assert_eq!(key1.token1, addr2);
        assert_eq!(key1, key2);
        assert_eq!(key1.get_id(), key2.get_id());
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let contract_address = Address::random();
        let mut amm = TIPFeeAMM::new(contract_address, &mut storage);

        let token_a = Address::random();
        let token_b = Address::random();

        let call = ITIPFeeAMM::createPoolCall {
            tokenA: token_a,
            tokenB: token_b,
        };

        assert!(amm.create_pool(call).is_ok());

        // Verify pool exists
        let pool_key = PoolKey::new(token_a, token_b);
        let pool_id = pool_key.get_id();
        let exists_call = ITIPFeeAMM::poolExistsCall { poolId: pool_id };
        assert!(amm.pool_exists(exists_call));
    }
}
