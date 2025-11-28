use std::{collections::HashMap, sync::Arc};

use alloy_primitives::{Address, U256};
use parking_lot::RwLock;
use reth_provider::{ProviderError, StateProvider};
use tempo_precompiles::{
    TIP_FEE_MANAGER_ADDRESS,
    storage::mapping_slot,
    tip_fee_manager::{
        amm::{Pool, PoolKey, compute_amount_out},
        slots,
    },
    tip20::{address_to_token_id_unchecked, token_id_to_address},
};

#[derive(Debug, Default)]
struct AmmLiquidityCacheInner {
    /// Cache for (user_token, validator_token) -> liquidity
    cache: HashMap<(u64, u64), U256>,

    /// Reverse index for mapping AMM slot to a pool.
    slot_to_pool: HashMap<U256, (u64, u64)>,

    /// Latest observed validator tokens.
    validator_tokens: Vec<Address>,
}

#[derive(Debug, Clone, Default)]
pub struct AmmLiquidityCache {
    inner: Arc<RwLock<AmmLiquidityCacheInner>>,
}

impl AmmLiquidityCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks whether there's enough liquidity in at least one of the AMM pools 
    /// used by recent validators for the given fee token and fee amount
    pub fn has_enough_liquidity(
        &self,
        user_token: Address,
        fee: U256,
        state_provider: &impl StateProvider,
    ) -> Result<bool, ProviderError> {
        let user_id = address_to_token_id_unchecked(user_token);
        let amount_out = compute_amount_out(fee).map_err(ProviderError::other)?;

        let inner = self.inner.read();
        let mut missing_in_cache = Vec::new();

        // search through latest observed validator tokens and find any cached pools that have enough liquidity
        for token in &inner.validator_tokens {
            let validator_id = address_to_token_id_unchecked(*token);

            if let Some(validator_reserve) = inner.cache.get(&(user_id, validator_id)) {
                if *validator_reserve >= amount_out {
                    return Ok(true);
                }
            } else {
                missing_in_cache.push(validator_id);
            }
        }

        // If no cache misses were hit, just return false
        if missing_in_cache.is_empty() {
            return Ok(false);
        }

        // Otherwise, load pools that weren't found in cache and check if they have enough liquidity
        let mut inner = self.inner.write();
        for token in missing_in_cache {
            // There's a race condition here so check the cache again before loading the pool
            if let Some(validator_reserve) = inner.cache.get(&(user_id, token))
                && *validator_reserve >= amount_out
            {
                return Ok(true);
            }

            let pool_key =
                PoolKey::new(token_id_to_address(user_id), token_id_to_address(token)).get_id();
            let slot = mapping_slot(pool_key, slots::POOLS);
            let pool = state_provider
                .storage(TIP_FEE_MANAGER_ADDRESS, slot.into())?
                .unwrap_or_default();
            let reserve = U256::from(Pool::from_slot(pool).reserve_validator_token);

            inner.cache.insert((user_id, token), reserve);
            inner.slot_to_pool.insert(slot, (user_id, token));

            // If the pool has enough liquidity, short circuit and return true
            if reserve >= amount_out {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
