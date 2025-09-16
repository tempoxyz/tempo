use crate::contracts::{
    address_to_token_id_unchecked,
    storage::{StorageOps, StorageProvider},
    tip_fee_manager::{
        amm::slots::{
            get_liquidity_balance_slot, get_pool_exists_slot, get_pool_slot, get_total_supply_slot,
        },
        pool::{Pool, PoolKey},
    },
    tip20::TIP20Token,
    types::{ITIP20, ITIPFeeAMM, TIPFeeAMMEvent},
};
use alloy::primitives::{Address, B256, U256, uint};
use alloy_primitives::IntoLogData;

/// Minimum liquidity locked to prevent division by zero
pub const MIN_LIQUIDITY: U256 = uint!(1000_U256);
/// Fee multiplier of 0.9975 (99.75%) scaled by 10000
pub const FEE_MULTIPLIER: U256 = uint!(9975_U256);
/// Scaling factor for percentage calculations
pub const FEE_SCALE: U256 = uint!(10000_U256);

/// Storage slots for TIPFeeAMM
///
/// IMPORTANT: These slots are shared with FeeManager when it inherits from TIPFeeAMM.
/// FeeManager uses the same slots (0-3) for AMM functionality and adds its own slots (4+).
/// This allows FeeManager to operate as a full TIPFeeAMM while extending it with fee capabilities.
pub mod slots {
    use alloy::primitives::{U256, uint};
    use alloy_primitives::{Address, B256};

    use crate::contracts::storage::slots::{double_mapping_slot, mapping_slot};

    // Base AMM storage slots (also used by FeeManager)
    pub const POOLS: U256 = U256::ZERO;
    pub const TOTAL_SUPPLY: U256 = uint!(1_U256);
    pub const POOL_EXISTS: U256 = uint!(2_U256);
    pub const LIQUIDITY_BALANCES: U256 = uint!(3_U256);
    // Slots 4+ are reserved for FeeManager-specific data
    //
    pub fn get_pool_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, POOLS)
    }

    /// Get storage slot for pool existence flag
    pub fn get_pool_exists_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, POOL_EXISTS)
    }

    /// Get storage slot for LP token total supply
    pub fn get_total_supply_slot(pool_id: &B256) -> U256 {
        mapping_slot(pool_id, TOTAL_SUPPLY)
    }

    /// Get storage slot for user's LP token balance
    pub fn get_liquidity_balance_slot(pool_id: &B256, user: &Address) -> U256 {
        double_mapping_slot(pool_id, user, LIQUIDITY_BALANCES)
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
/// AMM for stablecoin trading with fee management
pub struct TIPFeeAMM<'a, S: StorageProvider> {
    /// Contract address for storage operations
    pub contract_address: Address,
    /// Storage provider interface
    pub storage: &'a mut S,
}

impl<'a, S: StorageProvider> StorageOps for TIPFeeAMM<'a, S> {
    fn sstore(&mut self, slot: U256, value: U256) {
        self.storage
            .sstore(self.contract_address, slot, value)
            .expect("TODO: handle error");
    }

    fn sload(&mut self, slot: U256) -> U256 {
        self.storage
            .sload(self.contract_address, slot)
            .expect("TODO: handle error")
    }
}

/// Calculate integer square root using Newton's method
pub fn sqrt(x: U256) -> U256 {
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
    /// Create new AMM instance
    pub fn new(contract_address: Address, storage: &'a mut S) -> Self {
        Self {
            contract_address,
            storage,
        }
    }

    /// Create new liquidity pool for token pair
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
        if self.pool_exists(&pool_id) {
            return Err(ITIPFeeAMM::ITIPFeeAMMErrors::PoolExists(
                ITIPFeeAMM::PoolExists {},
            ));
        }

        // Init the pool
        self.set_reserves(&pool_id, U256::ZERO, U256::ZERO);
        self.set_pending_reserves(&pool_id, U256::ZERO, U256::ZERO);
        self.set_pool_exists(&pool_id);

        // Emit PoolCreated event
        self.storage
            .emit_event(
                self.contract_address,
                TIPFeeAMMEvent::PoolCreated(ITIPFeeAMM::PoolCreated {
                    token0: pool_key.token0,
                    token1: pool_key.token1,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(())
    }

    /// Mint LP tokens by providing liquidity
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
        let token_0_id = address_to_token_id_unchecked(&pool_key.token0);
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

        let token_1_id = address_to_token_id_unchecked(&pool_key.token1);
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
                    token0: pool_key.token0,
                    token1: pool_key.token1,
                    amount0: call.amount0,
                    amount1: call.amount1,
                    liquidity,
                })
                .into_log_data(),
            )
            .expect("TODO: handle error");

        Ok(liquidity)
    }

    /// Mint LP tokens to user and update total supply
    fn mint_lp_tokens(&mut self, pool_id: &B256, to: Address, amount: U256) {
        // TODO: this could be more efficient since we have already loaded total supply when
        // minting
        let total_supply = self.get_total_supply(pool_id);
        self.set_total_supply(pool_id, total_supply + amount);

        let balance = self.get_liquidity_balance(pool_id, to);
        self.set_liquidity_balance(pool_id, to, amount + balance);
    }

    /// Burn LP tokens and withdraw proportional token amounts
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

    /// Calculate token amounts to return when burning LP tokens
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

    /// Get user's LP token balance for pool
    fn get_liquidity_balance(&mut self, pool_id: &B256, user: Address) -> U256 {
        let slot = get_liquidity_balance_slot(pool_id, &user);
        self.sload(slot)
    }

    /// Set user's LP token balance for pool
    fn set_liquidity_balance(&mut self, pool_id: &B256, user: Address, balance: U256) {
        let slot = get_liquidity_balance_slot(pool_id, &user);
        self.sstore(slot, balance);
    }

    /// Get complete pool data including reserves and pending amounts
    pub fn get_pool(&mut self, pool_id: &B256) -> Pool {
        let pool_slot = get_pool_slot(pool_id);
        let reserves = self.sload(pool_slot);
        let reserve_0 = (reserves & U256::from(u128::MAX)).to::<u128>();
        let reserve_1 = reserves.wrapping_shr(128).to::<u128>();

        let pending = self.sload(pool_slot + U256::ONE);
        let pending_0 = (pending & U256::from(u128::MAX)).to::<u128>();
        let pending_1 = pending.wrapping_shr(128).to::<u128>();

        Pool {
            reserve0: reserve_0,
            reserve1: reserve_1,
            pending_reserve_0: pending_0,
            pending_reserve_1: pending_1,
        }
    }

    /// Get current pool reserves
    pub fn get_reserves(&mut self, pool_id: &B256) -> (U256, U256) {
        let pool_slot = get_pool_slot(pool_id);
        let reserves = self
            .storage
            .sload(self.contract_address, pool_slot)
            .expect("TODO: handle error");

        let reserve_0 = reserves & U256::from(u128::MAX);
        let reserve_1 = reserves.wrapping_shr(128);

        (reserve_0, reserve_1)
    }

    /// Update pool reserves in storage
    fn set_reserves(&mut self, pool_id: &B256, reserve_0: U256, reserve_1: U256) {
        let slot = get_pool_slot(pool_id);
        // Pack reserves: reserve1 in high 128 bits, reserve0 in low 128 bits
        let packed = (reserve_1.wrapping_shl(128)) | (reserve_0 & U256::from(u128::MAX));
        self.sstore(slot, packed);
    }

    /// Calculate effective reserves accounting for pending swaps and fees
    pub fn get_effective_reserves(&mut self, pool: &Pool) -> (U256, U256) {
        let pending_0_out = (U256::from(pool.pending_reserve_0) * FEE_MULTIPLIER) / FEE_SCALE;
        let pending_1_out = (U256::from(pool.pending_reserve_1) * FEE_MULTIPLIER) / FEE_SCALE;

        let effective_reserve_0 =
            U256::from(pool.reserve0) + U256::from(pool.pending_reserve_0) - pending_1_out;

        let effective_reserve_1 =
            U256::from(pool.reserve1) + U256::from(pool.pending_reserve_1) - pending_0_out;

        (effective_reserve_0, effective_reserve_1)
    }

    /// Update pending reserves from incomplete swaps
    fn set_pending_reserves(
        &mut self,
        pool_id: &B256,
        pending_reserve_0: U256,
        pending_reserve_1: U256,
    ) {
        let slot = get_pool_slot(pool_id) + U256::ONE;
        // Pack reserves: reserve1 in high 128 bits, reserve0 in low 128 bits
        let packed =
            (pending_reserve_1.wrapping_shl(128)) | (pending_reserve_0 & U256::from(u128::MAX));
        self.sstore(slot, packed);
    }

    /// Get total supply of LP tokens for pool
    fn get_total_supply(&mut self, pool_id: &B256) -> U256 {
        let slot = get_total_supply_slot(pool_id);
        self.sload(slot)
    }

    /// Set total supply of LP tokens for pool
    fn set_total_supply(&mut self, pool_id: &B256, total_supply: U256) {
        let slot = get_total_supply_slot(pool_id);
        self.sstore(slot, total_supply);
    }

    /// Mark pool as existing in storage
    fn set_pool_exists(&mut self, pool_id: &B256) {
        let slot = get_pool_exists_slot(pool_id);
        self.sstore(slot, U256::from(true));
    }

    /// Check if pool with the provided pool ID exists
    pub fn pool_exists(&mut self, pool_id: &B256) -> bool {
        let slot = get_pool_exists_slot(pool_id);
        self.sload(slot).to::<bool>()
    }

    /// Get pool ID for given token pair
    pub fn get_pool_id(&mut self, call: ITIPFeeAMM::getPoolIdCall) -> B256 {
        let pool_key = PoolKey::from(call.key);
        pool_key.get_id()
    }

    /// Get pool data by pool ID
    pub fn pools(&mut self, call: ITIPFeeAMM::poolsCall) -> ITIPFeeAMM::Pool {
        let pool = self.get_pool(&call.poolId);
        pool.into()
    }

    /// Get total supply of LP tokens for pool
    pub fn total_supply(&mut self, call: ITIPFeeAMM::totalSupplyCall) -> U256 {
        let slot = get_total_supply_slot(&call.poolId);
        self.sload(slot)
    }

    /// Get user's LP token balance for pool
    pub fn liquidity_balances(&mut self, call: ITIPFeeAMM::liquidityBalancesCall) -> U256 {
        let slot = get_liquidity_balance_slot(&call.poolId, &call.user);
        self.sload(slot)
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
        let amm_addr = Address::random();
        let mut amm = TIPFeeAMM::new(amm_addr, &mut storage);
        let token0 = Address::random();
        let token1 = Address::random();

        let result = amm.create_pool(ITIPFeeAMM::createPoolCall {
            tokenA: token1,
            tokenB: token0,
        });

        assert!(result.is_ok());

        let pool_key = PoolKey::new(token0, token1);
        let pool_id = pool_key.get_id();
        assert!(amm.pool_exists(&pool_id));

        // Assert PoolCreated event emission
        let events = storage.events.get(&amm_addr).expect("Events should exist");
        assert_eq!(events.len(), 1);

        let expected_event = TIPFeeAMMEvent::PoolCreated(ITIPFeeAMM::PoolCreated {
            token0: pool_key.token0,
            token1: pool_key.token1,
        });
        assert_eq!(events[0], expected_event.into_log_data());
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
        assert_eq!(events.len(), 2);

        let expected_event = TIPFeeAMMEvent::Mint(ITIPFeeAMM::Mint {
            sender: user,
            token0: token_0_addr,
            token1: token_1_addr,
            amount0: amount_0,
            amount1: amount_1,
            liquidity,
        });
        assert_eq!(events[1], expected_event.into_log_data());
    }

    #[test]
    fn test_burn() {
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

        let liquidity = amm
            .mint(
                user,
                ITIPFeeAMM::mintCall {
                    to: user,
                    key: pool_key.clone().into(),
                    amount0: amount_0,
                    amount1: amount_1,
                },
            )
            .expect("Could not mint");

        let lp_balance = amm.get_liquidity_balance(&pool_id, user);
        let total_supply = amm.get_total_supply(&pool_id);
        let (reserve_0, reserve_1) = amm.get_reserves(&pool_id);

        // Burn half of the liquidity
        let burn_amount = liquidity / U256::from(2);
        let (amount_0_out, amount_1_out) = amm
            .burn(
                user,
                ITIPFeeAMM::burnCall {
                    key: pool_key.into(),
                    liquidity: burn_amount,
                    to: user,
                },
            )
            .expect("Could not burn amount");

        // Calculate expected amounts and assert state changes
        let expected_amount_0 = (burn_amount * reserve_0) / total_supply;
        let expected_amount_1 = (burn_amount * reserve_1) / total_supply;
        assert_eq!(amount_0_out, expected_amount_0);
        assert_eq!(amount_1_out, expected_amount_1);

        let final_lp_balance = amm.get_liquidity_balance(&pool_id, user);
        assert_eq!(final_lp_balance, lp_balance - burn_amount);

        let final_total_supply = amm.get_total_supply(&pool_id);
        assert_eq!(final_total_supply, total_supply - burn_amount);

        let (final_reserve_0, final_reserve_1) = amm.get_reserves(&pool_id);
        assert_eq!(final_reserve_0, reserve_0 - amount_0_out);
        assert_eq!(final_reserve_1, reserve_1 - amount_1_out);

        // Assert token balances
        let mut token_0 =
            TIP20Token::new(address_to_token_id_unchecked(&token_0_addr), &mut storage);
        let user_token_0_bal = token_0.balance_of(ITIP20::balanceOfCall { account: user });
        assert_eq!(user_token_0_bal, amount_0_out);
        let fee_amm_token_0_bal = token_0.balance_of(ITIP20::balanceOfCall { account: amm_addr });
        assert_eq!(fee_amm_token_0_bal, reserve_0 - amount_0_out);

        let mut token_1 =
            TIP20Token::new(address_to_token_id_unchecked(&token_1_addr), &mut storage);
        let user_token_1_bal = token_1.balance_of(ITIP20::balanceOfCall { account: user });
        assert_eq!(user_token_1_bal, amount_1_out);
        let fee_amm_token_1_bal = token_1.balance_of(ITIP20::balanceOfCall { account: amm_addr });
        assert_eq!(fee_amm_token_1_bal, reserve_1 - amount_1_out);

        // Assert event emission
        let events = storage.events.get(&amm_addr).expect("Events should exist");
        assert_eq!(events.len(), 3);

        let expected_burn_event = TIPFeeAMMEvent::Burn(ITIPFeeAMM::Burn {
            sender: user,
            token0: token_0_addr,
            token1: token_1_addr,
            amount0: amount_0_out,
            amount1: amount_1_out,
            liquidity: burn_amount,
            to: user,
        });
        assert_eq!(events[2], expected_burn_event.into_log_data());
    }

    #[test]
    fn test_sqrt() {
        for _ in 0..1000 {
            let val = rand::random::<u64>();
            let expected = (val as f64).sqrt().floor() as u64;
            let result = sqrt(U256::from(val)).to::<u64>();

            assert_eq!(result, expected);
        }
    }
}
