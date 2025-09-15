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
// 0.9975 fee multiplier (scaled by 10000)
pub const FEE_MULTIPLIER: U256 = uint!(9975_U256);
//  Factor for fee calculations
pub const FEE_SCALE: U256 = uint!(10000_U256);

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
    pub pending_amount_in_0: u128,
    pub pending_amount_in_1: u128,
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

    pub fn pool_exists(&mut self, pool_id: &B256) -> bool {
        let exists_slot = self.get_pool_exists_slot(pool_id);
        let exists = self
            .storage
            .sload(self.contract_address, exists_slot)
            .expect("TODO: handle error");

        exists.to::<bool>()
    }

    pub fn get_pool(&mut self, pool_id: &B256) -> Pool {
        let pool_slot = self.get_pool_slot(pool_id);
        let reserves = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        let reserve_0 = (reserves & U256::from(u128::MAX)).to::<u128>();
        let reserve_1 = reserves.wrapping_shr(128).to::<u128>();

        let pending = self
            .storage
            .sload(self.contract_address, pool_slot + U256::ONE)
            .expect("TODO: handle error");

        let pending_0 = (pending & U256::from(u128::MAX)).to::<u128>();
        let pending_1 = pending.wrapping_shr(128).to::<u128>();

        Pool {
            reserve0: reserve_0,
            reserve1: reserve_1,
            pending_amount_in_0: pending_0,
            pending_amount_in_1: pending_1,
        }
    }

    pub fn get_reserves(&mut self, pool_id: &B256) -> (U256, U256) {
        let pool_slot = self.get_pool_slot(pool_id);
        let reserves = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        let reserve_0 = reserves & U256::from(u128::MAX);
        let reserve_1 = reserves.wrapping_shr(128);

        (reserve_0, reserve_1)
    }

    pub fn get_effective_reserves(&mut self, pool: &Pool) -> (U256, U256) {
        let pending_0_out = (U256::from(pool.pending_amount_in_0) * FEE_MULTIPLIER) / FEE_SCALE;
        let pending_1_out = (U256::from(pool.pending_amount_in_1) * FEE_MULTIPLIER) / FEE_SCALE;

        let effective_reserve_0 =
            U256::from(pool.reserve0) + U256::from(pool.pending_amount_in_1) - pending_0_out;

        let effective_reserve_1 =
            U256::from(pool.reserve1) + U256::from(pool.pending_amount_in_0) - pending_1_out;

        (effective_reserve_0, effective_reserve_1)
    }

    fn get_total_supply(&mut self, pool_id: &B256) -> U256 {
        let total_supply_slot = self.get_total_supply_slot(pool_id);
        self.storage
            .sload(self.contract_address, total_supply_slot)
            .expect("TODO: handle error")
    }

    fn set_total_supply(&mut self, pool_id: &B256, total_supply: U256) {
        let total_supply_slot = self.get_total_supply_slot(pool_id);
        self.storage
            .sstore(self.contract_address, total_supply_slot, total_supply)
            .expect("TODO: handle error");
    }

    fn mint_lp_tokens(&mut self, pool_id: &B256, to: Address, amount: U256) {
        // TODO: this could be more efficient since we have already loaded total supply when
        // minting
        let total_supply = self.get_total_supply(pool_id);
        self.set_total_supply(pool_id, total_supply + amount);

        let balance = self.get_liquidity_balance(pool_id, to);
        self.set_liquidity_balance(pool_id, to, amount + balance);
    }

    fn set_reserves(&mut self, pool_id: &B256, reserve_0: U256, reserve_1: U256) {
        let pool_slot = self.get_pool_slot(pool_id);
        // Pack reserves: reserve1 in high 128 bits, reserve0 in low 128 bits
        let packed = (reserve_1.wrapping_shl(128)) | (reserve_0 & U256::from(u128::MAX));
        self.storage
            .sstore(self.contract_address, pool_slot, packed)
            .expect("TODO: handle error");
    }

    /// Calculate amounts to return when burning liquidity
    fn calculate_burn_amounts(
        &mut self,
        pool_id: &B256,
        liquidity: U256,
    ) -> Result<(U256, U256), ITIPFeeAMM::ITIPFeeAMMErrors> {
        let total_supply = self.get_total_supply(pool_id);
        if total_supply.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        let pool = self.get_pool(pool_id);
        let amount_0 = (liquidity * U256::from(pool.reserve0)) / total_supply;
        let amount_1 = (liquidity * U256::from(pool.reserve1)) / total_supply;

        if amount_0.is_zero() || amount_1.is_zero() {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        // Check that withdrawal does not violate pending swaps
        let (reserve_0, reserve_1) = self.get_effective_reserves(&pool);
        if amount_0 > reserve_0 {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }
        if amount_1 > reserve_1 {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        Ok((amount_0, amount_1))
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
        let _ = TIP20Token::new(token_0_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: call.amount0,
                },
            )
            .expect("TODO: handle err");

        let token_1_id = address_to_token_id_unchecked(&call.token1);
        let _ = TIP20Token::new(token_1_id, self.storage)
            .transfer_from(
                &self.contract_address,
                ITIP20::transferFromCall {
                    from: msg_sender,
                    to: self.contract_address,
                    amount: call.amount1,
                },
            )
            .expect("TODO: handle err");

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

    /// Burn liquidity tokens and return proportional amounts
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

        // Check user has sufficient liquidity
        let user_balance = self.get_liquidity_balance(&pool_id, msg_sender);
        if user_balance < call.liquidity {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::InsufficientLiquidity(
                ITIPFeeAMM::InsufficientLiquidity {},
            ));
        }

        // Calculate burn amounts
        let (amount_0, amount_1) = self.calculate_burn_amounts(&pool_id, call.liquidity)?;

        // Burn LP Tokens
        let balance = self.get_liquidity_balance(&pool_id, msg_sender);
        self.set_liquidity_balance(&pool_id, msg_sender, balance - call.liquidity);
        let total_supply = self.get_total_supply(&pool_id);
        self.set_total_supply(&pool_id, total_supply - call.liquidity);

        // Update reserves
        let pool = self.get_pool(&pool_id);
        self.set_reserves(
            &pool_id,
            U256::from(pool.reserve0) - amount_0,
            U256::from(pool.reserve1) - amount_1,
        );

        // Transfer tokens to user
        let token_0_id = address_to_token_id_unchecked(&pool_key.token0);
        let _ = TIP20Token::new(token_0_id, self.storage).transfer(
            &self.contract_address,
            ITIP20::transferCall {
                to: call.to,
                amount: amount_0,
            },
        );

        let token_1_id = address_to_token_id_unchecked(&pool_key.token1);
        let _ = TIP20Token::new(token_1_id, self.storage).transfer(
            &self.contract_address,
            ITIP20::transferCall {
                to: call.to,
                amount: amount_1,
            },
        );

        // Emit burn event
        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::Burn(ITIPFeeAMM::Burn {
                    sender: msg_sender,
                    token0: pool_key.token0,
                    token1: pool_key.token1,
                    amount0: amount_0,
                    amount1: amount_1,
                    liquidity: call.liquidity,
                    to: call.to,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok((amount_0, amount_1))
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
    use crate::contracts::{
        HashMapStorageProvider,
        tip20::{ISSUER_ROLE, TIP20Token},
        tip20_factory::TIP20Factory,
        types::ITIP20,
    };

    #[test]
    fn test_pool_key_ordering() {
        let addr1 = Address::random();
        let addr2 = Address::random();

        let key1 = PoolKey::new(addr1, addr2);
        let key2 = PoolKey::new(addr2, addr1);

        assert_eq!(key1, key2);
        assert_eq!(key1.get_id(), key2.get_id());
    }

    #[test]
    fn test_create_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TIPFeeAMM::new(Address::random(), &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();

        let result = amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token0,
            tokenB: token1,
        });

        assert!(result.is_ok());

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();
        assert!(amm.pool_exists(&pool_id));
    }

    #[test]
    fn test_get_pool() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TIPFeeAMM::new(Address::random(), &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();

        amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token0,
            tokenB: token1,
        })
        .unwrap();

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();
        let pool = amm.get_pool(&pool_id);

        assert_eq!(pool.reserve0, 0);
        assert_eq!(pool.reserve1, 0);
    }

    #[test]
    fn test_reserves() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TIPFeeAMM::new(Address::random(), &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();

        amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token0,
            tokenB: token1,
        })
        .unwrap();

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();
        let reserve_0 = U256::from(rand::random::<u128>());
        let reserve_1 = U256::from(rand::random::<u128>());

        amm.set_reserves(&pool_id, reserve_0, reserve_1);
        let reserves = amm.get_reserves(&pool_id);

        assert_eq!(reserves, (reserve_0, reserve_1));
    }

    #[test]
    fn test_effective_reserves() {
        todo!()
    }

    #[test]
    fn test_calculate_burn_amounts() {
        todo!()
    }

    #[test]
    fn test_liquidity_balances() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TIPFeeAMM::new(Address::random(), &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();
        let user = Address::random();

        amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token0,
            tokenB: token1,
        })
        .unwrap();

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();

        let amount = U256::random();
        amm.set_liquidity_balance(&pool_id, user, amount);
        let balance = amm.get_liquidity_balance(&pool_id, user);

        assert_eq!(balance, amount);
    }

    #[test]
    fn test_mint_lp_tokens() {
        let mut storage = HashMapStorageProvider::new(1);
        let mut amm = TIPFeeAMM::new(Address::random(), &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();
        let user = Address::random();

        amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token0,
            tokenB: token1,
        })
        .unwrap();

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();

        let amount = U256::random();
        amm.mint_lp_tokens(&pool_id, user, amount);

        let balance = amm.get_liquidity_balance(&pool_id, user);
        let total_supply = amm.get_total_supply(&pool_id);

        assert_eq!(balance, amount);
        assert_eq!(total_supply, amount);
    }

    fn setup_test_tokens(
        storage: &mut HashMapStorageProvider,
        user: Address,
        spender: Address,
        amount_0: U256,
        amount_1: U256,
    ) -> (Address, Address) {
        let mut factory = TIP20Factory::new(storage);
        factory.initialize().unwrap();

        let token_0_id = factory
            .create_token(
                &user,
                crate::contracts::types::ITIP20Factory::createTokenCall {
                    name: "Token0".to_string(),
                    symbol: "TK0".to_string(),
                    currency: "USD".to_string(),
                    admin: user,
                },
            )
            .unwrap()
            .to::<u64>();

        let token_1_id = factory
            .create_token(
                &user,
                crate::contracts::types::ITIP20Factory::createTokenCall {
                    name: "Token1".to_string(),
                    symbol: "TK1".to_string(),
                    currency: "USD".to_string(),
                    admin: user,
                },
            )
            .unwrap()
            .to::<u64>();

        let mut token_0 = TIP20Token::new(token_0_id, storage);
        token_0
            .initialize("Token0", "TK0", "USD", &user)
            .expect("Could not init token");

        let mut roles = token_0.get_roles_contract();
        roles.grant_role_internal(&user, *ISSUER_ROLE);

        token_0
            .mint(
                &user,
                ITIP20::mintCall {
                    to: user,
                    amount: amount_0,
                },
            )
            .expect("Could not mint token 0");

        token_0
            .approve(
                &user,
                ITIP20::approveCall {
                    spender,
                    amount: amount_0,
                },
            )
            .expect("Could not approve token 0");

        let token_0_addr = token_0.token_address;

        let mut token_1 = TIP20Token::new(token_1_id, storage);
        token_1
            .initialize("Token1", "TK1", "USD", &user)
            .expect("Could not init token");

        let mut roles = token_1.get_roles_contract();
        roles.grant_role_internal(&user, *ISSUER_ROLE);

        token_1
            .mint(
                &user,
                ITIP20::mintCall {
                    to: user,
                    amount: amount_1,
                },
            )
            .expect("Could not mint token 1");

        token_1
            .approve(
                &user,
                ITIP20::approveCall {
                    spender,
                    amount: amount_1,
                },
            )
            .expect("Could not approve token 1");

        let token_1_addr = token_1.token_address;

        (token_0_addr, token_1_addr)
    }

    #[test]
    fn test_mint() {
        let mut storage = HashMapStorageProvider::new(1);
        let amm_addr = Address::random();
        let user = Address::random();

        let amount_0 = U256::from(rand::random::<u128>());
        let amount_1 = U256::from(rand::random::<u128>());
        let (token_0_addr, token_1_addr) =
            setup_test_tokens(&mut storage, user, amm_addr, amount_0, amount_1);

        let pool_key = PoolKey::new(token_0_addr, token_1_addr);
        let pool_id = pool_key.get_id();

        let mut amm = TIPFeeAMM::new(amm_addr, &mut storage);
        amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token_0_addr,
            tokenB: token_1_addr,
        })
        .expect("Could not create pool");

        // Mint liquidity
        let liquidity = amm
            .mint(
                user,
                ITIPFeeAMM::mintCall {
                    to: user,
                    key: pool_key.into(),
                    token0: token_0_addr,
                    token1: token_1_addr,
                    amount0: amount_0,
                    amount1: amount_1,
                },
            )
            .expect("Could not mint");

        // Check expected liquidity
        let expected_liquidity = sqrt(amount_0 * amount_1) - MIN_LIQUIDITY;
        assert_eq!(liquidity, expected_liquidity);

        // Check LP token balance
        let lp_balance = amm.get_liquidity_balance(&pool_id, user);
        assert_eq!(lp_balance, liquidity);

        // Check total supply
        let total_supply = amm.get_total_supply(&pool_id);
        assert_eq!(total_supply, liquidity + MIN_LIQUIDITY);

        // Check pool reserves
        let (reserve0, reserve1) = amm.get_reserves(&pool_id);
        assert_eq!(reserve0, amount_0);
        assert_eq!(reserve1, amount_1);

        // Assert balances after
        let mut token_0 =
            TIP20Token::new(address_to_token_id_unchecked(&token_0_addr), &mut storage);
        let user_token_0_bal = token_0.balance_of(ITIP20::balanceOfCall { account: user });
        let fee_amm_token_0_bal = token_0.balance_of(ITIP20::balanceOfCall { account: amm_addr });
        assert_eq!(user_token_0_bal, U256::ZERO);
        assert_eq!(fee_amm_token_0_bal, amount_0);

        let mut token_1 =
            TIP20Token::new(address_to_token_id_unchecked(&token_1_addr), &mut storage);
        let user_token_1_bal = token_1.balance_of(ITIP20::balanceOfCall { account: user });
        assert_eq!(user_token_1_bal, U256::ZERO);
        let fee_amm_token_1_bal = token_1.balance_of(ITIP20::balanceOfCall { account: amm_addr });
        assert_eq!(fee_amm_token_1_bal, amount_1);

        // Assert event emission
        let events = storage.events.get(&amm_addr).expect("Events should exist");
        assert_eq!(events.len(), 1);
        
        let expected_event = TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
            sender: user,
            token0: token_0_addr,
            token1: token_1_addr,
            amount0: amount_0,
            amount1: amount_1,
            liquidity,
        });
        assert_eq!(events[0], expected_event.into_log_data());
    }

    #[test]
    fn test_burn() {
        todo!()
    }
}
