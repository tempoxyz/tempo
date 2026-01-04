use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use alloy_primitives::{Address, U256};
use parking_lot::RwLock;
use reth_primitives_traits::{BlockHeader, SealedHeader};
use reth_provider::{
    BlockReader, ChainSpecProvider, ExecutionOutcome, ProviderError, ProviderResult, StateProvider,
    StateProviderFactory,
};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardforks};
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS,
    tip_fee_manager::{
        TipFeeManager,
        amm::{Pool, PoolKey, compute_amount_out},
    },
    tip20::{address_to_token_id_unchecked, token_id_to_address},
};
use tempo_primitives::TempoReceipt;
use tempo_revm::IntoAddress;

/// Number of recent validator tokens to track.
const LAST_SEEN_TOKENS_WINDOW: usize = 100;

#[derive(Debug, Clone)]
pub struct AmmLiquidityCache {
    inner: Arc<RwLock<AmmLiquidityCacheInner>>,
}

impl AmmLiquidityCache {
    /// Creates a new [`AmmLiquidityCache`] and pre-populates the cache with
    /// validator fee tokens of the latest blocks.
    pub fn new<Client>(client: Client) -> ProviderResult<Self>
    where
        Client: StateProviderFactory + BlockReader + ChainSpecProvider<ChainSpec = TempoChainSpec>,
    {
        let this = Self {
            inner: Default::default(),
        };
        let tip = client.best_block_number()?;

        for header in client
            .sealed_headers_range(tip.saturating_sub(LAST_SEEN_TOKENS_WINDOW as u64 + 1)..=tip)?
        {
            this.on_new_block(&header, &client)?;
        }

        Ok(this)
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

        let mut missing_in_cache = Vec::new();

        // search through latest observed validator tokens and find any cached pools that have enough liquidity
        {
            let inner = self.inner.read();
            for token in &inner.unique_tokens {
                // If user token matches one of the recently seen validator tokens,
                // short circuit and return true. We assume that validators are willing to
                // accept transactions that pay fees in their token directly.
                if token == &user_token {
                    return Ok(true);
                }

                let validator_id = address_to_token_id_unchecked(*token);

                if let Some(validator_reserve) = inner.cache.get(&(user_id, validator_id)) {
                    if *validator_reserve >= amount_out {
                        return Ok(true);
                    }
                } else {
                    missing_in_cache.push(validator_id);
                }
            }
        }

        // If no cache misses were hit, just return false
        if missing_in_cache.is_empty() {
            return Ok(false);
        }

        // Otherwise, load pools that weren't found in cache and check if they have enough liquidity
        for token in missing_in_cache {
            // This might race other fetches but we're OK with it.
            let pool_key =
                PoolKey::new(token_id_to_address(user_id), token_id_to_address(token)).get_id();
            let slot = TipFeeManager::new().pools[pool_key].base_slot();
            let pool = state_provider
                .storage(TIP_FEE_MANAGER_ADDRESS, slot.into())?
                .unwrap_or_default();
            let reserve = U256::from(Pool::decode_from_slot(pool).reserve_validator_token);

            let mut inner = self.inner.write();
            inner.cache.insert((user_id, token), reserve);
            inner.slot_to_pool.insert(slot, (user_id, token));

            // If the pool has enough liquidity, short circuit and return true
            if reserve >= amount_out {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Processes a new [`ExecutionOutcome`] and caches new validator
    /// fee token preferences and AMM pool liquidity changes.
    pub fn on_new_state(&self, execution_outcome: &ExecutionOutcome<TempoReceipt>) {
        let Some(storage) = execution_outcome
            .account_state(&TIP_FEE_MANAGER_ADDRESS)
            .map(|acc| &acc.storage)
        else {
            return;
        };

        let mut inner = self.inner.write();

        // Process all FeeManager slot changes and update the cache.
        for (slot, value) in storage.iter() {
            if let Some(pool) = inner.slot_to_pool.get(slot).copied() {
                // Update AMM pools
                let validator_reserve =
                    U256::from(Pool::decode_from_slot(value.present_value).reserve_validator_token);
                inner.cache.insert(pool, validator_reserve);
            } else if let Some(validator) = inner.slot_to_validator.get(slot).copied() {
                // Update validator fee token preferences
                inner
                    .validator_preferences
                    .insert(validator, value.present_value().into_address());
            }
        }
    }

    /// Processes a new block and record the validator's fee token used in the block.
    pub fn on_new_block<P>(
        &self,
        header: &SealedHeader<impl BlockHeader>,
        state: P,
    ) -> ProviderResult<()>
    where
        P: StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        let beneficiary = header.beneficiary();
        let validator_token_slot = TipFeeManager::new().validator_tokens[beneficiary].slot();

        let cached_preference = self
            .inner
            .read()
            .validator_preferences
            .get(&beneficiary)
            .copied();

        let preference = if let Some(cached) = cached_preference {
            cached
        } else {
            // If no cached preference, load from state
            state
                .state_by_block_hash(header.hash())?
                .storage(TIP_FEE_MANAGER_ADDRESS, validator_token_slot.into())?
                .unwrap_or_default()
                .into_address()
        };

        // Get the actual fee token, accounting for defaults.
        let fee_token = if preference.is_zero() {
            DEFAULT_FEE_TOKEN
        } else {
            preference
        };

        let mut inner = self.inner.write();

        // Track the new fee token preference, if any
        if cached_preference.is_none() {
            inner.validator_preferences.insert(beneficiary, preference);
            inner
                .slot_to_validator
                .insert(validator_token_slot, beneficiary);
        }

        // Track the new observed fee token
        inner.last_seen_tokens.push_back(fee_token);
        if inner.last_seen_tokens.len() > LAST_SEEN_TOKENS_WINDOW {
            inner.last_seen_tokens.pop_front();
        }

        // Update the unique tokens list
        inner.unique_tokens = inner.last_seen_tokens.iter().copied().collect();

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AmmLiquidityCacheInner {
    /// Cache for (user_token, validator_token) -> liquidity
    cache: HashMap<(u64, u64), U256>,

    /// Reverse index for mapping AMM slot to a pool.
    slot_to_pool: HashMap<U256, (u64, u64)>,

    /// Latest observed validator tokens.
    last_seen_tokens: VecDeque<Address>,

    /// Unique tokens that have been seen in the last_seen_tokens.
    ///
    /// Ordered by the number of times they've been seen.
    unique_tokens: Vec<Address>,

    /// cache for validator fee token preferences configured in the fee manager
    validator_preferences: HashMap<Address, Address>,

    /// Reverse index for mapping validator preference slot to validator address.
    slot_to_validator: HashMap<U256, Address>,
}
