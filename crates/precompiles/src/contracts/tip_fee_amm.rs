use crate::contracts::{
    address_to_token_id_unchecked,
    storage::{
        StorageProvider,
        slots::{double_mapping_slot, mapping_slot},
    },
    tip20::TIP20Token,
    types::{ITIP20, ITIPFeeAMM, TIPFeeAMMEvent},
};
use alloy::{
    primitives::{Address, B256, U256, keccak256, uint},
    sol_types::SolValue,
};
use alloy_primitives::IntoLogData;

pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);

/// Storage slots for TIPFeeAMM
///
/// IMPORTANT: These slots are shared with FeeManager when it inherits from TIPFeeAMM.
/// FeeManager uses the same slots (0-3) for AMM functionality and adds its own slots (4+).
/// This allows FeeManager to operate as a full TIPFeeAMM while extending it with fee capabilities.
pub mod slots {
    use alloy::primitives::{U256, uint};

    // Base AMM storage slots (also used by FeeManager)
    pub const POOLS: U256 = U256::ZERO; // Slot 0: Pool reserves mapping
    pub const TOTAL_SUPPLY: U256 = uint!(1_U256); // Slot 1: Pool total supply mapping
    pub const POOL_EXISTS: U256 = uint!(2_U256); // Slot 2: Pool existence mapping
    pub const LIQUIDITY_BALANCES: U256 = uint!(3_U256); // Slot 3: Nested mapping for LP balances
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

/// Square root function using Newton's method
fn sqrt(x: U256) -> U256 {
    if x == U256::ZERO {
        return U256::ZERO;
    }
    let mut z = (x + U256::ONE) / U256::from(2);
    let mut y = x;
    while z < y {
        y = z;
        z = (x / z + z) / U256::from(2);
    }
    y
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

    fn get_total_supply_slot(&self, pool_id: &B256) -> U256 {
        mapping_slot(pool_id, slots::TOTAL_SUPPLY)
    }

    fn get_liquidity_balance_slot(&self, pool_id: &B256, user: &Address) -> U256 {
        double_mapping_slot(pool_id, user, slots::LIQUIDITY_BALANCES)
    }

    fn get_liquidity_balance(&mut self, pool_id: &B256, user: Address) -> U256 {
        let slot = double_mapping_slot(pool_id, user, slots::LIQUIDITY_BALANCES);

        self.storage
            .sload(self.contract_address, slot)
            .expect("TODO: handle error ")
    }

    fn set_liquidity_balance(&mut self, pool_id: &B256, user: Address, balance: U256) {
        let slot = double_mapping_slot(pool_id, user, slots::LIQUIDITY_BALANCES);
        self.storage
            .sstore(self.contract_address, slot, balance)
            .expect("TODO: handle error");
    }

    fn pool_exists(&mut self, pool_id: &B256) -> bool {
        let exists_slot = self.get_pool_exists_slot(&pool_id);
        let exists = self
            .storage
            .sload(self.contract_address, exists_slot)
            .expect("TODO: handle error");

        exists.to::<bool>()
    }

    fn get_total_supply(&mut self, pool_id: &B256) -> U256 {
        let total_supply_slot = self.get_total_supply_slot(&pool_id);
        let total_supply = self
            .storage
            .sload(self.contract_address, total_supply_slot)
            .expect("TODO: handle error");

        total_supply
    }

    fn set_total_supply(&mut self, pool_id: &B256, total_supply: U256) {
        let total_supply_slot = self.get_total_supply_slot(&pool_id);
        self.storage
            .sstore(self.contract_address, total_supply_slot, total_supply)
            .expect("TODO: handle error");
    }

    fn get_reserves(&mut self, pool_id: &B256) -> (U256, U256) {
        let pool_slot = self.get_pool_slot(&pool_id);
        let pool = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");
        let reserve_0 = pool & U256::from(u128::MAX);
        let reserve_1 = pool.wrapping_shr(128);

        (reserve_0, reserve_1)
    }

    fn mint_lp_tokens(&mut self, pool_id: &B256, to: Address, amount: U256) {
        // TODO: this could be more efficient since we have already loaded total supply when
        // minting
        let total_supply = self.get_total_supply(pool_id);
        self.set_total_supply(pool_id, total_supply + amount);

        let balance = self.get_liquidity_balance(pool_id, to);
        self.set_liquidity_balance(pool_id, to, amount + balance);
    }

    // TODO: update to u128
    fn set_reserves(&mut self, pool_id: &B256, reserve_0: U256, reserve_1: U256) -> (U256, U256) {
        let pool_slot = self.get_pool_slot(&pool_id);
        //TODO:

        todo!()
    }

    fn transfer_from_user(
        &mut self,
        token: Address,
        from: &Address,
        amount: U256,
    ) -> Result<(), ITIPFeeAMM::ITIPFeeAMMErrors> {
        let mut token_contract = TIP20Token {
            token_address: token,
            storage: self.storage,
        };

        let call = ITIP20::transferFromCall {
            from: *from,
            to: self.contract_address,
            amount,
        };

        token_contract
            .transfer_from(from, call)
            .expect("TODO: handle error");

        Ok(())
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

    // TODO: Liq functions

    /// Mint liquidity tokens
    pub fn mint(
        &mut self,
        msg_sender: Address,
        call: ITIPFeeAMM::mintCall,
    ) -> Result<U256, ITIPFeeAMM::ITIPFeeAMMErrors> {
        let pool_key = PoolKey::from(call.key);
        let pool_id = pool_key.get_id();
        if !self.pool_exists(&pool_id) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolDoesNotExist(
                ITIPFeeAMM::PoolDoesNotExist {},
            ));
        }

        let total_supply = self.get_total_supply(&pool_id);
        let (reserve_0, reserve_1) = self.get_reserves(&pool_id);

        let liquidity = if total_supply.is_zero() {
            self.set_total_supply(&pool_id, MIN_LIQUIDITY);
            sqrt(call.amount0 * call.amount1) - MIN_LIQUIDITY
        } else {
            let liquidity_0 = (call.amount0 * total_supply) / reserve_0;
            let liquidity_1 = (call.amount1 * total_supply) / reserve_1;
            liquidity_0.min(liquidity_1)
        };

        if liquidity.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        // Transfer tokens from user to contract
        let token_0_id = address_to_token_id_unchecked(&call.token0);
        TIP20Token::new(token_0_id, self.storage).transfer_from(
            &msg_sender,
            ITIP20::transferFromCall {
                from: msg_sender,
                to: self.contract_address,
                amount: call.amount0,
            },
        );

        let token_1_id = address_to_token_id_unchecked(&call.token1);
        TIP20Token::new(token_1_id, self.storage).transfer_from(
            &msg_sender,
            ITIP20::transferFromCall {
                from: msg_sender,
                to: self.contract_address,
                amount: call.amount1,
            },
        );

        self.set_reserves(&pool_id, reserve_0 + call.amount0, reserve_1 + call.amount1);
        self.mint_lp_tokens(&pool_id, msg_sender, liquidity);

        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
                    sender: msg_sender,
                    token0: call.token0,
                    token1: call.token1,
                    amount0: call.amount0,
                    amount1: call.amount1,
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
        call: ITIPFeeAMM::burnCall,
    ) -> Result<(U256, U256), ITIPFeeAMM::ITIPFeeAMMErrors> {
        let pool_key = PoolKey::from(call.key);
        let pool_id = pool_key.get_id();
        if !self.pool_exists(&pool_id) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolDoesNotExist(
                ITIPFeeAMM::PoolDoesNotExist {},
            ));
        }

        if self.get_liquidity_balance(&pool_id, msg_sender) >= call.liquidity {
            // TODO: return InsufficientLiquidity
        }

        todo!()
    }

    /// Get total supply of LP tokens for a pool
    pub fn total_supply(&mut self, call: ITIPFeeAMM::totalSupplyCall) -> U256 {
        let total_supply_slot = self.get_total_supply_slot(&call.poolId);
        self.storage
            .sload(self.contract_address, total_supply_slot)
            .expect("TODO: handle error")
    }

    /// Get liquidity balance of a user for a pool
    pub fn liquidity_balances(&mut self, call: ITIPFeeAMM::liquidityBalancesCall) -> U256 {
        let balance_slot = self.get_liquidity_balance_slot(&call.poolId, &call.user);
        self.storage
            .sload(self.contract_address, balance_slot)
            .expect("TODO: handle error")
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

    // TODO: test mint

    // TODO: test burn
}
