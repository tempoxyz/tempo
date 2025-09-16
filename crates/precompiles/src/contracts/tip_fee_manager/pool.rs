use crate::contracts::types::ITIPFeeAMM;
use alloy::{
    primitives::{Address, B256, keccak256},
    sol_types::SolValue,
};

/// Liquidity pool with current and pending reserves
#[derive(Debug, Clone)]
pub struct Pool {
    /// Current reserve of token0
    pub reserve0: u128,
    /// Current reserve of token1
    pub reserve1: u128,
    /// Pending reserve of token0 from incomplete swaps
    pub pending_reserve_0: u128,
    /// Pending reserve of token1 from incomplete swaps
    pub pending_reserve_1: u128,
}

impl From<Pool> for ITIPFeeAMM::Pool {
    fn from(pool: Pool) -> Self {
        Self {
            reserve0: pool.reserve0,
            reserve1: pool.reserve1,
            pendingReserve0: pool.pending_reserve_0,
            pendingReserve1: pool.pending_reserve_1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub token0: Address,
    pub token1: Address,
}

impl PoolKey {
    /// Create pool key with deterministic token ordering
    pub fn new(token_a: Address, token_b: Address) -> Self {
        let (token0, token1) = if token_a < token_b {
            (token_a, token_b)
        } else {
            (token_b, token_a)
        };

        Self { token0, token1 }
    }

    /// Generate unique pool ID from token addresses
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
