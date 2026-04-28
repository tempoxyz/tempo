use std::{collections::VecDeque, sync::Arc};

use alloy_consensus::BlockHeader;
use alloy_primitives::{
    Address, U256,
    map::{AddressMap, HashMap, U256Map},
};
use itertools::Itertools;
use parking_lot::RwLock;
use reth_primitives_traits::SealedHeader;
use reth_provider::{
    ChainSpecProvider, ExecutionOutcome, HeaderProvider, ProviderError, ProviderResult,
    StateProvider, StateProviderFactory,
};
use tempo_chainspec::{
    TempoChainSpec,
    hardfork::{TempoHardfork, TempoHardforks},
};
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    DEFAULT_FEE_TOKEN, TIP_FEE_MANAGER_ADDRESS,
    error::Result as TempoResult,
    tip_fee_manager::{
        TipFeeManager,
        amm::{FeeSwapPlan, Pool, SwapInfo, compute_amount_out},
    },
    tip20,
};
use tempo_primitives::{TempoHeader, TempoReceipt};
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
        Client: StateProviderFactory
            + HeaderProvider<Header = TempoHeader>
            + ChainSpecProvider<ChainSpec = TempoChainSpec>,
    {
        let this = Self {
            inner: Default::default(),
        };
        this.repopulate(&client)?;

        Ok(this)
    }

    /// Checks whether there's enough liquidity in at least one of the AMM pools used by recent
    /// validators for the given fee token and fee amount. On T5+, as per [TIP-1033], considers
    /// the two-hop fallback through an intermediate `userToken.quoteToken()`.
    ///
    /// [TIP-1033]: <https://docs.tempo.xyz/protocol/tips/tip-1033>
    pub fn has_enough_liquidity(
        &self,
        user_token: Address,
        fee: U256,
        state_provider: &mut impl StateProvider,
    ) -> Result<bool, ProviderError> {
        let amount_out = compute_amount_out(fee).map_err(ProviderError::other)?;

        let mut deferred = Vec::new();
        let current_fork;

        // Hot path: decide each `(user, validator)` pair entirely from the primitive cache.
        {
            let inner = self.inner.read();
            current_fork = inner.current_fork;
            for &validator_token in &inner.unique_tokens {
                // Validators always accept fees in their own token.
                if validator_token == user_token {
                    return Ok(true);
                }

                let direct = inner
                    .pool_cache
                    .get(&(user_token, validator_token))
                    .copied();
                if matches!(direct, Some(r) if r >= amount_out) {
                    return Ok(true);
                }

                if current_fork.is_t5() {
                    match inner.quote_token_cache.get(&user_token).copied() {
                        Some(h) if !h.is_zero() && h != validator_token => {
                            let r1 = inner.pool_cache.get(&(user_token, h)).copied();
                            let r2 = inner.pool_cache.get(&(h, validator_token)).copied();
                            let out1 = amount_out;
                            let out2 = compute_amount_out(out1).map_err(ProviderError::other)?;
                            match (r1, r2) {
                                (Some(r1), Some(r2)) if r1 >= out1 && r2 >= out2 => {
                                    return Ok(true);
                                }
                                (Some(_), Some(_)) => {} // Both cached and not enough liquidity.
                                _ => {
                                    // A leg's reserve is missing: defer.
                                    deferred.push(validator_token);
                                    continue;
                                }
                            }
                        }
                        Some(_) => {} // Cached as zero / equal to validator: no two-hop path possible.
                        None => {
                            deferred.push(validator_token);
                            continue;
                        }
                    }
                }

                // Direct unknown and (pre-T5 || two-hop ruled out): defer.
                if direct.is_none() {
                    deferred.push(validator_token);
                }
            }
        }

        if deferred.is_empty() {
            return Ok(false);
        }

        // Slow path: check `plan_fee_swap` for deferred checks. This might race other fetches but we're OK with it.
        state_provider
            .with_read_only_storage_ctx(current_fork, || -> TempoResult<bool> {
                let manager = TipFeeManager::new();
                for validator_token in deferred {
                    let attempt = manager.plan_fee_swap(user_token, validator_token, fee)?;
                    {
                        let mut inner = self.inner.write();
                        let cache_pool =
                            |inner: &mut AmmLiquidityCacheInner,
                             pair: (Address, Address),
                             swap: &SwapInfo| {
                                let slot = manager.pools[swap.pool_id].base_slot();
                                inner.pool_cache.insert(pair, U256::from(swap.reserves));
                                inner.slot_to_pool.insert(slot, pair);
                            };

                        if let Some(swap) = attempt.direct_check() {
                            cache_pool(&mut inner, (user_token, validator_token), swap);
                        }
                        if let Some(FeeSwapPlan::TwoHop {
                            intermediate,
                            swap1,
                            swap2,
                        }) = &attempt.plan
                        {
                            inner.quote_token_cache.insert(user_token, *intermediate);
                            cache_pool(&mut inner, (user_token, *intermediate), swap1);
                            cache_pool(&mut inner, (*intermediate, validator_token), swap2);
                        }
                    }
                    // If there is enough liquidity, short circuit and return `true`
                    if attempt.is_sufficient() {
                        return Ok(true);
                    }
                }

                Ok(false)
            })
            .map_err(ProviderError::other)
    }

    /// Clears all cached state. Used on reorg to invalidate stale entries
    /// from orphaned blocks.
    pub fn clear(&self) {
        *self.inner.write() = AmmLiquidityCacheInner::default();
    }

    /// Clears all cached state and repopulates from the current canonical chain.
    ///
    /// This should be called on reorg to ensure stale entries from orphaned
    /// blocks are replaced with data from the new canonical chain.
    pub fn repopulate<Client>(&self, client: &Client) -> ProviderResult<()>
    where
        Client: StateProviderFactory
            + HeaderProvider<Header = TempoHeader>
            + ChainSpecProvider<ChainSpec = TempoChainSpec>,
    {
        self.clear();
        let tip = client.best_block_number()?;
        let headers =
            client.sealed_headers_range(tip.saturating_sub(LAST_SEEN_WINDOW as u64 + 1)..=tip)?;
        self.on_new_blocks(headers.iter(), client)
    }

    /// Processes a new [`ExecutionOutcome`] and caches new validator
    /// fee token preferences and AMM pool liquidity changes.
    ///
    /// On T5+ also invalidates `AmmLiquidityCacheInner::quote_token_cache` entries for TIP-20
    /// tokens whose `quoteToken` storage slot was written.
    pub fn on_new_state(&self, execution_outcome: &ExecutionOutcome<TempoReceipt>) {
        let mut inner = self.inner.write();

        // Process FeeManager slot changes: update pool reserves and validator preferences.
        if let Some(storage) = execution_outcome
            .account_state(&TIP_FEE_MANAGER_ADDRESS)
            .map(|acc| &acc.storage)
        {
            for (slot, value) in storage.iter() {
                if let Some(pool) = inner.slot_to_pool.get(slot).copied() {
                    // Update AMM pools
                    let validator_reserve = U256::from(
                        Pool::decode_from_slot(value.present_value).reserve_validator_token,
                    );
                    inner.pool_cache.insert(pool, validator_reserve);
                } else if let Some(validator) = inner.slot_to_validator.get(slot).copied() {
                    // Update validator fee token preferences
                    inner
                        .validator_preferences
                        .insert(validator, value.present_value().into_address());
                }
            }
        }

        // Process TIP-20 quote token updates: invalidate stale entries.
        inner.quote_token_cache.retain(|token, _| {
            execution_outcome
                .account_state(token)
                .and_then(|acc| acc.storage.get(&tip20::slots::QUOTE_TOKEN))
                .is_none()
        });
    }

    /// Processes new blocks and records recent validators and their fee token preferences in the cache.
    pub fn on_new_blocks<'a, P>(
        &self,
        headers: impl IntoIterator<Item = &'a SealedHeader<TempoHeader>>,
        client: P,
    ) -> ProviderResult<()>
    where
        P: StateProviderFactory + ChainSpecProvider<ChainSpec: TempoHardforks>,
    {
        let headers = headers.into_iter().collect::<Vec<_>>();
        let (latest_hash, latest_timestamp) = if let Some(header) = headers.last() {
            (header.hash(), header.timestamp())
        } else {
            return Ok(());
        };

        let mut state = None;

        for header in headers {
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

                // Lazily initialize the state provider for the latest block in the set
                if state.is_none() {
                    state = Some(client.state_by_block_hash(latest_hash)?);
                }

                state
                    .as_mut()
                    .expect("initialized above")
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
            inner.unique_tokens = inner.last_seen_tokens.iter().copied().unique().collect();

            // Track the new observed validator (block producer)
            inner.last_seen_validators.push_back(beneficiary);
            if inner.last_seen_validators.len() > LAST_SEEN_WINDOW {
                inner.last_seen_validators.pop_front();
            }
            inner.unique_validators = inner
                .last_seen_validators
                .iter()
                .copied()
                .unique()
                .collect();
        }

        // Refresh the cached active hardfork from the latest seen header.
        self.inner.write().current_fork = client.chain_spec().tempo_hardfork_at(latest_timestamp);

        Ok(())
    }
}

#[derive(Debug, Default)]
struct AmmLiquidityCacheInner {
    /// Hardfork active at the most recently observed canonical header.
    current_fork: TempoHardfork,

    /// Cache for (user_token, validator_token) -> liquidity
    pool_cache: HashMap<(Address, Address), U256>,

    /// Cached `userToken.quoteToken()` lookups.
    quote_token_cache: AddressMap<Address>,

    /// Reverse index from a FeeManager pool slot to its `(user_token, validator_token)` key.
    slot_to_pool: U256Map<(Address, Address)>,

    /// Latest observed validator tokens.
    last_seen_tokens: VecDeque<Address>,

    /// Unique tokens that have been seen in the last_seen_tokens.
    unique_tokens: Vec<Address>,

    /// Latest observed validators (block producers).
    last_seen_validators: VecDeque<Address>,

    /// Unique validators that have produced recent blocks.
    unique_validators: Vec<Address>,

    /// cache for validator fee token preferences configured in the fee manager
    validator_preferences: AddressMap<Address>,

    /// Reverse index for mapping validator preference slot to validator address.
    slot_to_validator: U256Map<Address>,
}

impl AmmLiquidityCache {
    /// Returns `true` if the given address is a validator that has produced recent blocks.
    ///
    /// Use this to filter validator token change events: only process changes from
    /// validators who actually produce blocks. This prevents permissionless
    /// `setValidatorToken` calls from triggering mass pending transaction eviction.
    pub fn is_active_validator(&self, validator: &Address) -> bool {
        self.inner.read().unique_validators.contains(validator)
    }

    /// Returns `true` if the given token is in the `unique_tokens` list (tokens used
    /// by recent block producers as their preferred fee token).
    pub fn is_active_validator_token(&self, token: &Address) -> bool {
        self.inner.read().unique_tokens.contains(token)
    }

    /// Injects tokens into `unique_tokens` so `has_enough_liquidity` sees them.
    /// Returns `true` if any of the input tokens is added to the `unique_tokens` list.
    ///
    /// NOTE: Bridges the gap between `setValidatorToken` events and the next block
    /// produced by that validator. Cleaned up on the next `on_new_block` call.
    pub fn track_tokens(&self, tokens: &[Address]) -> bool {
        let mut updated = false;
        if tokens.is_empty() {
            return updated;
        }

        let mut inner = self.inner.write();
        for &token in tokens {
            if !inner.unique_tokens.contains(&token) {
                inner.unique_tokens.push(token);
                updated = true;
            }
        }
        updated
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
        let mut state = provider.latest().unwrap();

        let user_token = address!("1111111111111111111111111111111111111111");
        let result = cache.has_enough_liquidity(user_token, U256::from(100), &mut state);

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
                pool_cache: {
                    let mut m = HashMap::default();
                    m.insert((user_token, validator_token), U256::MAX);
                    m
                },
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let mut state = provider.latest().unwrap();

        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &mut state);
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
                pool_cache: {
                    let mut m = HashMap::default();
                    m.insert((user_token, validator_token), U256::ZERO);
                    m
                },
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let mut state = provider.latest().unwrap();

        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &mut state);
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
        let mut state = provider.latest().unwrap();

        let user_token = address!("1111111111111111111111111111111111111111");
        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &mut state);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should return false when no unique tokens"
        );
    }

    #[test]
    fn test_has_enough_liquidity_two_hop_cached() {
        let user = address!("1111111111111111111111111111111111111111");
        let hop = address!("2222222222222222222222222222222222222222");
        let validator = address!("3333333333333333333333333333333333333333");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                current_fork: TempoHardfork::T5,
                unique_tokens: vec![validator],
                pool_cache: {
                    let mut m = HashMap::default();
                    // Reserves easily cover floor(100*M) and floor(99*M) sequentially.
                    m.insert((user, hop), U256::from(1_000_000));
                    m.insert((hop, validator), U256::from(1_000_000));
                    m
                },
                quote_token_cache: {
                    let mut m = AddressMap::default();
                    m.insert(user, hop);
                    m
                },
                ..Default::default()
            })),
        };

        // Provider would return zero for any storage read; if the slow path runs we'd see
        // either a `false` result or a panic from the missing TIP-20 prefix on `user`.
        let provider = create_mock_provider();
        let mut state = provider.latest().unwrap();

        let result = cache.has_enough_liquidity(user, U256::from(100), &mut state);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "two-hop primitives cached should resolve from hot path",
        );
    }

    #[test]
    fn test_has_enough_liquidity_cache_miss_insufficient() {
        let user_token = address!("2222222222222222222222222222222222222222");
        let validator_token = address!("3333333333333333333333333333333333333333");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                unique_tokens: vec![validator_token],
                pool_cache: HashMap::default(),
                ..Default::default()
            })),
        };

        let provider = create_mock_provider();
        let mut state = provider.latest().unwrap();

        // Provider returns default (zero) storage values
        let result = cache.has_enough_liquidity(user_token, U256::from(1000), &mut state);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should return false for insufficient reserve"
        );

        // Slow-path checks must populate `pool_cache` even when no plan was viable, so the
        // next admission resolves from the hot path without re-issuing SLOADs.
        let inner = cache.inner.read();
        assert_eq!(
            inner.pool_cache.get(&(user_token, validator_token)),
            Some(&U256::ZERO),
            "failed direct check should still warm pool_cache",
        );
        assert!(
            !inner.slot_to_pool.is_empty(),
            "slot_to_pool reverse index should be populated for the check pool",
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
        assert!(inner.pool_cache.is_empty());
        assert!(inner.quote_token_cache.is_empty());
        assert!(inner.validator_preferences.is_empty());
    }

    #[test]
    fn test_on_new_state_invalidates_stale_quote_token_cache() {
        use reth_provider::ExecutionOutcome;
        use revm::database::{AccountStatus, BundleAccount, BundleState, states::StorageSlot};
        use tempo_primitives::TempoReceipt;

        // TIP-20-prefixed addresses so `from_address_unchecked`'s debug_assert holds.
        let user_token = address!("20c0000000000000000000000000000000000001");
        let hop_old = address!("20c0000000000000000000000000000000000002");
        let hop_new = address!("20c0000000000000000000000000000000000003");
        let other_user = address!("20c0000000000000000000000000000000000099");

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                quote_token_cache: {
                    let mut m = AddressMap::default();
                    m.insert(user_token, hop_old);
                    m.insert(other_user, hop_old);
                    m
                },
                ..Default::default()
            })),
        };

        // Build a bundle where `user_token`'s `quoteToken` slot was rewritten to `hop_new`.
        let mut storage = HashMap::default();
        storage.insert(
            tip20::slots::QUOTE_TOKEN,
            StorageSlot::new_changed(hop_old.into_word().into(), hop_new.into_word().into()),
        );
        let mut bundle_state = AddressMap::default();
        bundle_state.insert(
            user_token,
            BundleAccount::new(None, None, storage, AccountStatus::Changed),
        );
        let bundle = BundleState {
            state: bundle_state,
            ..Default::default()
        };
        let execution_outcome: ExecutionOutcome<TempoReceipt> = ExecutionOutcome {
            bundle,
            ..Default::default()
        };

        cache.on_new_state(&execution_outcome);

        let inner = cache.inner.read();
        assert!(
            !inner.quote_token_cache.contains_key(&user_token),
            "stale quote_token_cache entry must be dropped on slot write",
        );
        assert_eq!(
            inner.quote_token_cache.get(&other_user),
            Some(&hop_old),
            "untouched user tokens must keep their cached intermediate",
        );
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

        inner.unique_validators = inner
            .last_seen_validators
            .iter()
            .copied()
            .unique()
            .collect();
        assert!(inner.unique_validators.contains(&new_validator));
    }

    #[test]
    fn test_unique_tokens_deduplication() {
        let mut inner = AmmLiquidityCacheInner::default();

        let token_a = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let token_b = address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        inner.last_seen_tokens.push_back(token_a);
        inner.last_seen_tokens.push_back(token_b);
        inner.last_seen_tokens.push_back(token_b);
        inner.last_seen_tokens.push_back(token_b);

        inner.unique_tokens = inner.last_seen_tokens.iter().copied().unique().collect();

        assert_eq!(inner.unique_tokens.len(), 2, "duplicates must be removed");
        assert_eq!(inner.unique_tokens[0], token_a);
        assert_eq!(inner.unique_tokens[1], token_b);
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

        inner
            .pool_cache
            .insert((user_token, validator_token), reserve);

        assert_eq!(
            inner.pool_cache.get(&(user_token, validator_token)),
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
    fn test_clear_resets_all_state() {
        let user_token = Address::random();
        let validator_token = Address::random();
        let validator = Address::random();

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                pool_cache: {
                    let mut m = HashMap::default();
                    m.insert((user_token, validator_token), U256::from(1000));
                    m
                },
                quote_token_cache: {
                    let mut m = AddressMap::default();
                    m.insert(user_token, validator_token);
                    m
                },
                slot_to_pool: {
                    let mut m = U256Map::default();
                    m.insert(U256::from(1), (user_token, validator_token));
                    m
                },
                last_seen_tokens: VecDeque::from(vec![validator_token]),
                unique_tokens: vec![validator_token],
                last_seen_validators: VecDeque::from(vec![validator]),
                unique_validators: vec![validator],
                validator_preferences: {
                    let mut m = AddressMap::default();
                    m.insert(validator, validator_token);
                    m
                },
                slot_to_validator: {
                    let mut m = U256Map::default();
                    m.insert(U256::from(2), validator);
                    m
                },
                ..Default::default()
            })),
        };

        cache.clear();

        let inner = cache.inner.read();
        assert!(
            inner.pool_cache.is_empty(),
            "pools should be empty after clear"
        );
        assert!(
            inner.quote_token_cache.is_empty(),
            "quote_tokens should be empty after clear"
        );
        assert!(
            inner.slot_to_pool.is_empty(),
            "slot_to_pool should be empty after clear"
        );
        assert!(
            inner.last_seen_tokens.is_empty(),
            "last_seen_tokens should be empty after clear"
        );
        assert!(
            inner.unique_tokens.is_empty(),
            "unique_tokens should be empty after clear"
        );
        assert!(
            inner.last_seen_validators.is_empty(),
            "last_seen_validators should be empty after clear"
        );
        assert!(
            inner.unique_validators.is_empty(),
            "unique_validators should be empty after clear"
        );
        assert!(
            inner.validator_preferences.is_empty(),
            "validator_preferences should be empty after clear"
        );
        assert!(
            inner.slot_to_validator.is_empty(),
            "slot_to_validator should be empty after clear"
        );
    }

    #[test]
    fn test_repopulate_clears_stale_data_and_rebuilds_from_canonical_chain() {
        use alloy_consensus::Header;

        let stale_validator = Address::random();
        let stale_token = Address::random();
        let stale_user_token = Address::random();

        let cache = AmmLiquidityCache {
            inner: Arc::new(RwLock::new(AmmLiquidityCacheInner {
                pool_cache: {
                    let mut m = HashMap::default();
                    m.insert((stale_user_token, stale_token), U256::from(9999));
                    m
                },
                slot_to_pool: {
                    let mut m = U256Map::default();
                    m.insert(U256::from(42), (stale_user_token, stale_token));
                    m
                },
                last_seen_tokens: VecDeque::from(vec![stale_token]),
                unique_tokens: vec![stale_token],
                last_seen_validators: VecDeque::from(vec![stale_validator]),
                unique_validators: vec![stale_validator],
                validator_preferences: {
                    let mut m = AddressMap::default();
                    m.insert(stale_validator, stale_token);
                    m
                },
                slot_to_validator: {
                    let mut m = U256Map::default();
                    m.insert(U256::from(99), stale_validator);
                    m
                },
                ..Default::default()
            })),
        };

        {
            let inner = cache.inner.read();
            assert!(inner.unique_validators.contains(&stale_validator));
            assert!(inner.unique_tokens.contains(&stale_token));
            assert_eq!(
                inner.pool_cache.get(&(stale_user_token, stale_token)),
                Some(&U256::from(9999))
            );
        }

        let new_validator = Address::random();
        let provider = create_mock_provider();
        for i in 0..3u64 {
            let header = TempoHeader {
                inner: Header {
                    number: i,
                    beneficiary: new_validator,
                    ..Default::default()
                },
                ..Default::default()
            };
            provider.add_header(alloy_primitives::B256::random(), header);
        }

        cache
            .repopulate(&provider)
            .expect("repopulate should succeed");

        let inner = cache.inner.read();

        assert!(
            !inner.unique_validators.contains(&stale_validator),
            "stale validator should be gone after repopulate"
        );
        assert!(
            !inner.unique_tokens.contains(&stale_token),
            "stale token should be gone after repopulate"
        );
        assert!(
            !inner
                .pool_cache
                .contains_key(&(stale_user_token, stale_token)),
            "stale liquidity entry should be gone after repopulate"
        );
        assert!(
            inner.slot_to_pool.is_empty(),
            "stale slot_to_pool should be gone after repopulate"
        );

        assert!(
            inner.unique_validators.contains(&new_validator),
            "new canonical validator should be present after repopulate"
        );
        assert_eq!(
            inner.last_seen_validators.len(),
            3,
            "should have 3 validators from new canonical headers"
        );
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

    #[test]
    fn test_track_tokens() {
        let token_a = address!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let token_b = address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

        // Empty slice is a no-op
        let cache = AmmLiquidityCache::with_unique_tokens(vec![]);
        assert!(!cache.track_tokens(&[]));
        assert!(cache.inner.read().unique_tokens.is_empty());

        // New token is inserted
        let cache = AmmLiquidityCache::with_unique_tokens(vec![token_a]);
        assert!(cache.track_tokens(&[token_b]));
        assert_eq!(cache.inner.read().unique_tokens, vec![token_a, token_b]);

        // Already-tracked token returns false
        let cache = AmmLiquidityCache::with_unique_tokens(vec![token_a]);
        assert!(!cache.track_tokens(&[token_a]));
        assert_eq!(cache.inner.read().unique_tokens.len(), 1);

        // Duplicate input is deduplicated
        let cache = AmmLiquidityCache::with_unique_tokens(vec![token_a]);
        assert!(cache.track_tokens(&[token_b, token_b]));
        assert_eq!(cache.inner.read().unique_tokens.len(), 2);
    }
}
