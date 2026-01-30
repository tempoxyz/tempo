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
};
use tempo_primitives::TempoReceipt;
use tempo_revm::IntoAddress;

/// Number of recent validators/tokens to track.
const LAST_SEEN_WINDOW: usize = 10;

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

        for header in
            client.sealed_headers_range(tip.saturating_sub(LAST_SEEN_WINDOW as u64 + 1)..=tip)?
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
        let amount_out = compute_amount_out(fee).map_err(ProviderError::other)?;

        let mut missing_in_cache = Vec::new();

        // search through latest observed validator tokens and find any cached pools that have enough liquidity
        {
            let inner = self.inner.read();
            for validator_token in &inner.unique_tokens {
                // If user token matches one of the recently seen validator tokens,
                // short circuit and return true. We assume that validators are willing to
                // accept transactions that pay fees in their token directly.
                if validator_token == &user_token {
                    return Ok(true);
                }

                if let Some(validator_reserve) = inner.cache.get(&(user_token, *validator_token)) {
                    if *validator_reserve >= amount_out {
                        return Ok(true);
                    }
                } else {
                    missing_in_cache.push(*validator_token);
                }
            }
        }

        // If no cache misses were hit, just return false
        if missing_in_cache.is_empty() {
            return Ok(false);
        }

        // Otherwise, load pools that weren't found in cache and check if they have enough liquidity
        for validator_token in missing_in_cache {
            // This might race other fetches but we're OK with it.
            let pool_key = PoolKey::new(user_token, validator_token).get_id();
            let slot = TipFeeManager::new().pools[pool_key].base_slot();
            let pool = state_provider
                .storage(TIP_FEE_MANAGER_ADDRESS, slot.into())?
                .unwrap_or_default();
            let reserve = U256::from(Pool::decode_from_slot(pool).reserve_validator_token);

            let mut inner = self.inner.write();
            inner.cache.insert((user_token, validator_token), reserve);
            inner
                .slot_to_pool
                .insert(slot, (user_token, validator_token));

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
        if inner.last_seen_tokens.len() > LAST_SEEN_WINDOW {
            inner.last_seen_tokens.pop_front();
        }
        inner.unique_tokens = inner.last_seen_tokens.iter().copied().collect();

        // Track the new observed validator (block producer)
        inner.last_seen_validators.push_back(beneficiary);
        if inner.last_seen_validators.len() > LAST_SEEN_WINDOW {
            inner.last_seen_validators.pop_front();
        }
        inner.unique_validators = inner.last_seen_validators.iter().copied().collect();

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AmmLiquidityCacheInner {
    /// Cache for (user_token, validator_token) -> liquidity
    cache: HashMap<(Address, Address), U256>,

    /// Reverse index for mapping AMM slot to a pool.
    slot_to_pool: HashMap<U256, (Address, Address)>,

    /// Latest observed validator tokens.
    last_seen_tokens: VecDeque<Address>,

    /// Unique tokens that have been seen in the last_seen_tokens.
    unique_tokens: Vec<Address>,

    /// Latest observed validators (block producers).
    last_seen_validators: VecDeque<Address>,

    /// Unique validators that have produced recent blocks.
    unique_validators: Vec<Address>,

    /// cache for validator fee token preferences configured in the fee manager
    validator_preferences: HashMap<Address, Address>,

    /// Reverse index for mapping validator preference slot to validator address.
    slot_to_validator: HashMap<U256, Address>,
}

impl AmmLiquidityCache {
    /// Returns true if the given address is a validator that has produced recent blocks.
    ///
    /// Use this to filter validator token change events: only process changes from
    /// validators who actually produce blocks. This prevents permissionless
    /// `setValidatorToken` calls from triggering mass pending transaction eviction.
    pub fn is_active_validator(&self, validator: &Address) -> bool {
        self.inner.read().unique_validators.contains(validator)
    }

    /// Returns true if the given token is in the unique_tokens list (tokens used
    /// by recent block producers as their preferred fee token).
    pub fn is_active_validator_token(&self, token: &Address) -> bool {
        self.inner.read().unique_tokens.contains(token)
    }
}

#[cfg(any(test, feature = "test-utils"))]
impl AmmLiquidityCache {
    /// Creates a new [`AmmLiquidityCache`] with pre-populated unique tokens for testing.
    pub fn with_unique_tokens(unique_tokens: Vec<Address>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens,
                ..Default::default()
            })),
        }
    }

    /// Creates a new [`AmmLiquidityCache`] with pre-populated unique validators for testing.
    pub fn with_unique_validators(unique_validators: Vec<Address>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_validators,
                ..Default::default()
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_mock_provider;
    use alloy_primitives::address;

    // ============================================
    // has_enough_liquidity tests (using MockEthProvider)
    // ============================================

    #[test]
    fn test_has_enough_liquidity_user_token_matches_validator_token() {
        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens: vec![address!("1111111111111111111111111111111111111111")],
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let state = provider.latest().unwrap();

        let user_token = address!("1111111111111111111111111111111111111111");
        let result = cache.has_enough_liquidity(user_token, U256::from(100), &state);

        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Should return true when user token matches validator token"
        );
    }

    #[test]
    fn test_has_enough_liquidity_cached_pool_sufficient() {
        let user_token = address!("2222222222222222222222222222222222222222");
        let validator_token = address!("3333333333333333333333333333333333333333");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens: vec![validator_token],
                cache: {
                    let mut m = HashMap::default();
                    m.insert((user_token, validator_token), U256::MAX);
                    m
                },
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let state = provider.latest().unwrap();

        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &state);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Should return true for sufficient cached reserve"
        );
    }

    #[test]
    fn test_has_enough_liquidity_cached_pool_insufficient() {
        let user_token = address!("2222222222222222222222222222222222222222");
        let validator_token = address!("3333333333333333333333333333333333333333");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens: vec![validator_token],
                cache: {
                    let mut m = HashMap::default();
                    m.insert((user_token, validator_token), U256::ZERO);
                    m
                },
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let state = provider.latest().unwrap();

        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &state);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should return false for insufficient cached reserve"
        );
    }

    #[test]
    fn test_has_enough_liquidity_no_unique_tokens() {
        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner::default())),
        };

        let provider = create_mock_provider();
        let state = provider.latest().unwrap();

        let user_token = address!("1111111111111111111111111111111111111111");
        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &state);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should return false when no unique tokens"
        );
    }

    #[test]
    fn test_has_enough_liquidity_cache_miss_insufficient() {
        let user_token = address!("2222222222222222222222222222222222222222");
        let validator_token = address!("3333333333333333333333333333333333333333");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens: vec![validator_token],
                cache: HashMap::default(),
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let state = provider.latest().unwrap();

        // Provider returns default (zero) storage values
        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &state);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should return false for insufficient reserve"
        );
    }

    // ============================================
    // on_new_state tests
    // ============================================

    #[test]
    fn test_on_new_state_early_return_no_fee_manager_account() {
        use reth_provider::ExecutionOutcome;
        use tempo_primitives::TempoReceipt;

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner::default())),
        };

        let execution_outcome: ExecutionOutcome<TempoReceipt> = ExecutionOutcome::default();
        cache.on_new_state(&execution_outcome);

        let inner = cache.inner.read();
        assert!(inner.cache.is_empty());
        assert!(inner.validator_preferences.is_empty());
    }

    // ============================================
    // Sliding window tests
    // ============================================

    #[test]
    fn test_sliding_window_max_size() {
        let mut inner = AmmLiquidityCacheInner::default();

        for i in 0..LAST_SEEN_WINDOW {
            let token = Address::new([i as u8; 20]);
            inner.last_seen_tokens.push_back(token);
        }

        assert_eq!(inner.last_seen_tokens.len(), LAST_SEEN_WINDOW);

        let new_token = Address::new([0xFF; 20]);
        inner.last_seen_tokens.push_back(new_token);
        if inner.last_seen_tokens.len() > LAST_SEEN_WINDOW {
            inner.last_seen_tokens.pop_front();
        }

        assert_eq!(inner.last_seen_tokens.len(), LAST_SEEN_WINDOW);
        assert_eq!(inner.last_seen_tokens.back(), Some(&new_token));
        assert_eq!(inner.last_seen_tokens.front(), Some(&Address::new([1; 20])));
    }

    #[test]
    fn test_sliding_window_validators() {
        let mut inner = AmmLiquidityCacheInner::default();

        for i in 0..LAST_SEEN_WINDOW {
            let validator = Address::new([i as u8; 20]);
            inner.last_seen_validators.push_back(validator);
        }

        assert_eq!(inner.last_seen_validators.len(), LAST_SEEN_WINDOW);

        let new_validator = Address::new([0xFF; 20]);
        inner.last_seen_validators.push_back(new_validator);
        if inner.last_seen_validators.len() > LAST_SEEN_WINDOW {
            inner.last_seen_validators.pop_front();
        }

        assert_eq!(inner.last_seen_validators.len(), LAST_SEEN_WINDOW);
        assert_eq!(inner.last_seen_validators.back(), Some(&new_validator));
        assert_eq!(
            inner.last_seen_validators.front(),
            Some(&Address::new([1; 20]))
        );

        inner.unique_validators = inner.last_seen_validators.iter().copied().collect();
        assert!(inner.unique_validators.contains(&new_validator));
    }

    #[test]
    fn test_unique_tokens_updated_from_last_seen() {
        let mut inner = AmmLiquidityCacheInner::default();

        let token_a = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let token_b = address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        inner.last_seen_tokens.push_back(token_a);
        inner.last_seen_tokens.push_back(token_b);
        inner.last_seen_tokens.push_back(token_a);

        inner.unique_tokens = inner.last_seen_tokens.iter().copied().collect();

        assert!(inner.unique_tokens.contains(&token_a));
        assert!(inner.unique_tokens.contains(&token_b));
    }

    // ============================================
    // AmmLiquidityCacheInner direct manipulation tests
    // ============================================

    #[test]
    fn test_cache_insert_and_lookup() {
        let mut inner = AmmLiquidityCacheInner::default();

        let user_token = address!("1111111111111111111111111111111111111111");
        let validator_token = address!("2222222222222222222222222222222222222222");
        let reserve = U256::from(5000);

        inner.cache.insert((user_token, validator_token), reserve);

        assert_eq!(
            inner.cache.get(&(user_token, validator_token)),
            Some(&reserve)
        );
    }

    #[test]
    fn test_slot_to_pool_mapping() {
        let mut inner = AmmLiquidityCacheInner::default();

        let user_token = address!("1111111111111111111111111111111111111111");
        let validator_token = address!("2222222222222222222222222222222222222222");
        let slot = U256::from(12345);

        inner
            .slot_to_pool
            .insert(slot, (user_token, validator_token));

        assert_eq!(
            inner.slot_to_pool.get(&slot),
            Some(&(user_token, validator_token))
        );
    }

    #[test]
    fn test_validator_preferences_mapping() {
        let mut inner = AmmLiquidityCacheInner::default();

        let validator = address!("3333333333333333333333333333333333333333");
        let fee_token = address!("4444444444444444444444444444444444444444");

        inner.validator_preferences.insert(validator, fee_token);

        assert_eq!(
            inner.validator_preferences.get(&validator),
            Some(&fee_token)
        );
    }

    #[test]
    fn test_slot_to_validator_mapping() {
        let mut inner = AmmLiquidityCacheInner::default();

        let validator = address!("3333333333333333333333333333333333333333");
        let slot = U256::from(67890);

        inner.slot_to_validator.insert(slot, validator);

        assert_eq!(inner.slot_to_validator.get(&slot), Some(&validator));
    }

    #[test]
    fn test_is_active_validator() {
        let active = address!("1111111111111111111111111111111111111111");
        let inactive = address!("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF");

        let cases = [
            (vec![active], active, true, "active validator in set"),
            (
                vec![active],
                inactive,
                false,
                "inactive validator not in set",
            ),
            (vec![], active, false, "empty set"),
        ];

        for (unique_validators, query, expected, desc) in cases {
            let cache = AmmLiquidityCache::with_unique_validators(unique_validators);
            assert_eq!(cache.is_active_validator(&query), expected, "{desc}");
        }
    }
}
