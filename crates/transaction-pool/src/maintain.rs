//! Transaction pool maintenance tasks.

use crate::{
    RevokedKeys, SpendingLimitUpdates, TempoTransactionPool,
    metrics::TempoPoolMaintenanceMetrics,
    paused::{PausedEntry, PausedFeeTokenPool},
    transaction::TempoPooledTransaction,
};
use alloy_primitives::{
    Address, B256, Log, TxHash,
    map::{AddressMap, AddressSet, B256Map, B256Set},
};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use itertools::{Either, Itertools};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, Chain, HeaderProvider};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{AllPoolTransactions, PoolTransaction, TransactionPool};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    time::Instant,
};
use tempo_chainspec::hardfork::TempoHardforks;
use tempo_contracts::precompiles::{IAccountKeychain, IFeeManager, ITIP20, ITIP403Registry};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, TIP_FEE_MANAGER_ADDRESS, TIP403_REGISTRY_ADDRESS,
};
use tempo_primitives::{TempoAddressExt, TempoHeader, TempoPrimitives};
use tracing::{debug, error};

/// Evict transactions this many seconds before they expire to reduce propagation
/// of near-expiry transactions that are likely to fail validation on peers.
const EVICTION_BUFFER_SECS: u64 = 3;

/// Maximum number of new-transaction events to receive in a single maintenance wakeup
/// before yielding back to the event loop. Bounds the per-wakeup work so a sustained
/// burst of new transactions cannot starve block-commit processing.
const NEW_TX_DRAIN_LIMIT: usize = 4096;

/// Aggregated block-level invalidation events for the transaction pool.
///
/// Collects all invalidation events from a block into a single structure,
/// allowing efficient batch processing of pool updates.
#[derive(Debug, Default)]
pub struct TempoPoolUpdates {
    /// Revoked keychain keys.
    /// Indexed by account for efficient lookup.
    pub revoked_keys: RevokedKeys,
    /// Inline key authorization target-key status changes.
    ///
    /// A pending inline authorization for `(account, key)` is stale once another transaction
    /// authorizes, admin-authorizes, or revokes that same key.
    pub key_authorization_target_changes: RevokedKeys,
    /// Spending limit changes.
    /// When a spending limit changes, transactions from that key paying with that token
    /// may become unexecutable if the new limit is below their value.
    /// Indexed by account for efficient lookup.
    pub spending_limit_changes: SpendingLimitUpdates,
    /// Validator token preference changes: validator to new_token (last-write-wins).
    /// Uses `AddressMap` to deduplicate by validator, preventing resource amplification
    /// when a validator emits multiple `ValidatorTokenSet` events in the same block.
    pub validator_token_changes: AddressMap<Address>,
    /// User token preference changes.
    /// When a user changes their fee token preference via `setUserToken()`, pending
    /// transactions from that user that don't have an explicit fee_token set may now
    /// resolve to a different token at execution time, causing fee payment failures.
    /// Uses a set since a user can emit multiple events in the same block; we only need to
    /// process each user once. No cleanup needed as this is ephemeral per-block data.
    pub user_token_changes: AddressSet,
    /// TIP403 blacklist additions: (policy_id, account).
    pub blacklist_additions: Vec<(u64, Address)>,
    /// TIP403 whitelist removals: (policy_id, account).
    pub whitelist_removals: Vec<(u64, Address)>,
    /// Fee token pause state changes: (token, is_paused).
    pub pause_events: Vec<(Address, bool)>,
    /// Tokens whose transfer policy was changed via `changeTransferPolicyId()`.
    /// Pending transactions using these tokens as fee tokens need to be re-validated
    /// because the new policy may forbid the fee payer or fee manager.
    pub transfer_policy_updates: AddressSet,
    /// Tokens whose `quoteToken` was updated via `completeQuoteTokenUpdate()`.
    /// Pending transactions paying in these tokens need to be re-validated because the new
    /// quote token may invalidate the old route.
    pub quote_token_updates: AddressSet,
    /// Fee token balance changes keyed by token.
    ///
    /// We only track the debited `from` account from TIP20 `Transfer` logs because credits to the
    /// `to` account cannot make an already-admitted transaction newly invalid.
    pub fee_balance_changes: AddressMap<AddressSet>,
    /// Spending-limit spends emitted by the account keychain during execution.
    ///
    /// We record the exact `(account, key_id, token)` triples emitted by `AccessKeySpend`
    /// events. During eviction, the pool re-reads the remaining limit from state for these
    /// triples and compares against pending tx fee costs. This keeps maintenance aligned
    /// with the runtime's actual spending-limit decrements instead of inferring them from
    /// the mined transaction body.
    pub spending_limit_spends: SpendingLimitUpdates,
    /// TIP-1053 key-authorization witness burns.
    ///
    /// Pending AA transactions carrying the same `(account, witness)` key authorization are no
    /// longer executable once the account explicitly burns that witness.
    pub key_authorization_witness_burns: AddressMap<B256Set>,
}

impl TempoPoolUpdates {
    /// Creates a new empty `TempoPoolUpdates`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are no updates to process.
    pub fn is_empty(&self) -> bool {
        self.revoked_keys.is_empty()
            && self.key_authorization_target_changes.is_empty()
            && self.spending_limit_changes.is_empty()
            && self.validator_token_changes.is_empty()
            && self.user_token_changes.is_empty()
            && self.blacklist_additions.is_empty()
            && self.whitelist_removals.is_empty()
            && self.pause_events.is_empty()
            && self.transfer_policy_updates.is_empty()
            && self.quote_token_updates.is_empty()
            && self.fee_balance_changes.is_empty()
            && self.spending_limit_spends.is_empty()
            && self.key_authorization_witness_burns.is_empty()
    }

    /// Extracts pool updates from a committed chain segment.
    ///
    /// Parses receipts for relevant events (key revocations, validator token changes,
    /// blacklist additions, pause events).
    pub fn from_chain(chain: &Chain<TempoPrimitives>) -> Self {
        let mut updates = Self::new();

        // Parse events from receipts
        for log in chain
            .execution_outcome()
            .receipts()
            .iter()
            .flatten()
            .flat_map(|receipt| &receipt.logs)
        {
            // Fee token pause events and balance changes.
            //
            // Checked first because TIP-20 `Transfer` logs dominate block receipts; this avoids
            // three address comparisons per transfer before reaching the matching branch.
            if log.address.is_tip20() {
                match Tip20PoolEvent::decode(log) {
                    Some(Tip20PoolEvent::PauseStateUpdate(event)) => {
                        updates.pause_events.push((log.address, event.isPaused));
                    }
                    Some(Tip20PoolEvent::TransferPolicyUpdate) => {
                        updates.transfer_policy_updates.insert(log.address);
                    }
                    Some(Tip20PoolEvent::QuoteTokenUpdate) => {
                        updates.quote_token_updates.insert(log.address);
                    }
                    Some(Tip20PoolEvent::Transfer { from }) => {
                        updates
                            .fee_balance_changes
                            .entry(log.address)
                            .or_default()
                            .insert(from);
                    }
                    None => {}
                }
            }
            // Key revocations and spending limit changes
            else if log.address == ACCOUNT_KEYCHAIN_ADDRESS {
                match AccountKeychainPoolEvent::decode(log) {
                    Some(AccountKeychainPoolEvent::KeyRevoked(event)) => {
                        updates.revoked_keys.insert(event.account, event.publicKey);
                        updates
                            .key_authorization_target_changes
                            .insert(event.account, event.publicKey);
                    }
                    Some(AccountKeychainPoolEvent::KeyAuthorized(event)) => {
                        updates
                            .key_authorization_target_changes
                            .insert(event.account, event.publicKey);
                    }
                    Some(AccountKeychainPoolEvent::AdminKeyAuthorized(event)) => {
                        updates
                            .key_authorization_target_changes
                            .insert(event.account, event.publicKey);
                    }
                    Some(AccountKeychainPoolEvent::SpendingLimitUpdated(event)) => {
                        updates.spending_limit_changes.insert(
                            event.account,
                            event.publicKey,
                            Some(event.token),
                        );
                    }
                    Some(AccountKeychainPoolEvent::AccessKeySpend(event)) => {
                        updates.spending_limit_spends.insert(
                            event.account,
                            event.publicKey,
                            Some(event.token),
                        );
                    }
                    Some(AccountKeychainPoolEvent::KeyAuthorizationWitnessBurned(event)) => {
                        updates
                            .key_authorization_witness_burns
                            .entry(event.account)
                            .or_default()
                            .insert(event.witness);
                    }
                    None => {}
                }
            }
            // Validator and user token changes
            else if log.address == TIP_FEE_MANAGER_ADDRESS {
                match FeeManagerPoolEvent::decode(log) {
                    Some(FeeManagerPoolEvent::ValidatorTokenSet(event)) => {
                        updates
                            .validator_token_changes
                            .insert(event.validator, event.token);
                    }
                    Some(FeeManagerPoolEvent::UserTokenSet(event)) => {
                        updates.user_token_changes.insert(event.user);
                    }
                    None => {}
                }
            }
            // TIP403 blacklist additions and whitelist removals
            else if log.address == TIP403_REGISTRY_ADDRESS {
                match Tip403PoolEvent::decode(log) {
                    Some(Tip403PoolEvent::BlacklistUpdated(event)) if event.restricted => {
                        updates
                            .blacklist_additions
                            .push((event.policyId, event.account));
                    }
                    Some(Tip403PoolEvent::WhitelistUpdated(event)) if !event.allowed => {
                        updates
                            .whitelist_removals
                            .push((event.policyId, event.account));
                    }
                    Some(_) | None => {}
                }
            }
        }

        updates
    }

    /// Returns true if there are any invalidation events that require scanning the pool.
    pub fn has_invalidation_events(&self) -> bool {
        self.has_keychain_subject_updates()
            || !self.key_authorization_target_changes.is_empty()
            || !self.validator_token_changes.is_empty()
            || !self.user_token_changes.is_empty()
            || !self.blacklist_additions.is_empty()
            || !self.whitelist_removals.is_empty()
            || !self.fee_balance_changes.is_empty()
            || !self.key_authorization_witness_burns.is_empty()
    }

    /// Returns true if updates may invalidate keychain-signature transactions.
    pub fn has_keychain_subject_updates(&self) -> bool {
        !self.revoked_keys.is_empty()
            || !self.spending_limit_changes.is_empty()
            || !self.spending_limit_spends.is_empty()
    }
}

/// Transaction-pool relevant subset of `IAccountKeychain::IAccountKeychainEvents`.
enum AccountKeychainPoolEvent {
    /// [`IAccountKeychain::KeyAuthorized`] log.
    KeyAuthorized(IAccountKeychain::KeyAuthorized),
    /// [`IAccountKeychain::AdminKeyAuthorized`] log.
    AdminKeyAuthorized(IAccountKeychain::AdminKeyAuthorized),
    /// [`IAccountKeychain::KeyRevoked`] log.
    KeyRevoked(IAccountKeychain::KeyRevoked),
    /// [`IAccountKeychain::SpendingLimitUpdated`] log.
    SpendingLimitUpdated(IAccountKeychain::SpendingLimitUpdated),
    /// [`IAccountKeychain::AccessKeySpend`] log.
    AccessKeySpend(IAccountKeychain::AccessKeySpend),
    /// [`IAccountKeychain::KeyAuthorizationWitnessBurned`] log.
    KeyAuthorizationWitnessBurned(IAccountKeychain::KeyAuthorizationWitnessBurned),
}

impl AccountKeychainPoolEvent {
    /// Decodes only account-keychain events used by transaction-pool maintenance.
    fn decode(log: &Log) -> Option<Self> {
        match first_topic(log)? {
            IAccountKeychain::KeyAuthorized::SIGNATURE_HASH => {
                decode_event(log).map(Self::KeyAuthorized)
            }
            IAccountKeychain::AdminKeyAuthorized::SIGNATURE_HASH => {
                decode_event(log).map(Self::AdminKeyAuthorized)
            }
            IAccountKeychain::KeyRevoked::SIGNATURE_HASH => decode_event(log).map(Self::KeyRevoked),
            IAccountKeychain::SpendingLimitUpdated::SIGNATURE_HASH => {
                decode_event(log).map(Self::SpendingLimitUpdated)
            }
            IAccountKeychain::AccessKeySpend::SIGNATURE_HASH => {
                decode_event(log).map(Self::AccessKeySpend)
            }
            IAccountKeychain::KeyAuthorizationWitnessBurned::SIGNATURE_HASH => {
                decode_event(log).map(Self::KeyAuthorizationWitnessBurned)
            }
            _ => None,
        }
    }
}

/// Transaction-pool relevant subset of `IFeeManager::IFeeManagerEvents`.
enum FeeManagerPoolEvent {
    /// [`IFeeManager::ValidatorTokenSet`] log.
    ValidatorTokenSet(IFeeManager::ValidatorTokenSet),
    /// [`IFeeManager::UserTokenSet`] log.
    UserTokenSet(IFeeManager::UserTokenSet),
}

impl FeeManagerPoolEvent {
    /// Decodes only fee-manager events used by transaction-pool maintenance.
    fn decode(log: &Log) -> Option<Self> {
        match first_topic(log)? {
            IFeeManager::ValidatorTokenSet::SIGNATURE_HASH => {
                decode_event(log).map(Self::ValidatorTokenSet)
            }
            IFeeManager::UserTokenSet::SIGNATURE_HASH => decode_event(log).map(Self::UserTokenSet),
            _ => None,
        }
    }
}

/// Transaction-pool relevant subset of `ITIP403Registry::ITIP403RegistryEvents`.
enum Tip403PoolEvent {
    /// [`ITIP403Registry::BlacklistUpdated`] log.
    BlacklistUpdated(ITIP403Registry::BlacklistUpdated),
    /// [`ITIP403Registry::WhitelistUpdated`] log.
    WhitelistUpdated(ITIP403Registry::WhitelistUpdated),
}

impl Tip403PoolEvent {
    /// Decodes only TIP-403 registry events used by transaction-pool maintenance.
    fn decode(log: &Log) -> Option<Self> {
        match first_topic(log)? {
            ITIP403Registry::BlacklistUpdated::SIGNATURE_HASH => {
                decode_event(log).map(Self::BlacklistUpdated)
            }
            ITIP403Registry::WhitelistUpdated::SIGNATURE_HASH => {
                decode_event(log).map(Self::WhitelistUpdated)
            }
            _ => None,
        }
    }
}

/// Transaction-pool relevant subset of `ITIP20::ITIP20Events`.
enum Tip20PoolEvent {
    /// [`ITIP20::PauseStateUpdate`] log.
    PauseStateUpdate(ITIP20::PauseStateUpdate),
    /// [`ITIP20::TransferPolicyUpdate`] log.
    TransferPolicyUpdate,
    /// [`ITIP20::QuoteTokenUpdate`] log.
    QuoteTokenUpdate,
    /// [`ITIP20::Transfer`] log; only the debited `from` account is retained.
    Transfer { from: Address },
}

impl Tip20PoolEvent {
    /// Decodes only TIP-20 events used by transaction-pool maintenance.
    fn decode(log: &Log) -> Option<Self> {
        match first_topic(log)? {
            // `Transfer` is by far the most common TIP-20 log, so avoid a full event decode
            // and read the indexed `from` directly from `topics[1]`. We only need the debited
            // account for `fee_balance_changes`; `to` and `amount` are unused.
            ITIP20::Transfer::SIGNATURE_HASH => log.topics().get(1).map(|topic| Self::Transfer {
                from: Address::from_word(*topic),
            }),
            ITIP20::PauseStateUpdate::SIGNATURE_HASH => {
                decode_event(log).map(Self::PauseStateUpdate)
            }
            ITIP20::TransferPolicyUpdate::SIGNATURE_HASH => {
                decode_event::<ITIP20::TransferPolicyUpdate>(log)
                    .map(|_| Self::TransferPolicyUpdate)
            }
            ITIP20::QuoteTokenUpdate::SIGNATURE_HASH => {
                decode_event::<ITIP20::QuoteTokenUpdate>(log).map(|_| Self::QuoteTokenUpdate)
            }
            _ => None,
        }
    }
}

fn first_topic(log: &Log) -> Option<B256> {
    log.topics().first().copied()
}

/// Decodes after the caller has matched `topic0`, avoiding the allocating
/// invalid-signature error path for unrelated events.
fn decode_event<T: SolEvent>(log: &Log) -> Option<T> {
    T::decode_log(log).ok().map(|event| event.data)
}

/// Tracking state for pool maintenance operations.
///
/// Tracks AA transaction expiry (`valid_before` timestamps) for eviction.
///
/// Note: Stale entries (transactions no longer in the pool) are cleaned up lazily
/// when we check `pool.contains()` before eviction. This avoids the overhead of
/// subscribing to all transaction lifecycle events.
#[derive(Default)]
struct TempoPoolState {
    /// Maps timestamp to transactions that are going to be invalidated at that time (due to `valid_after` or keychain-related expiry).
    expiry_map: BTreeMap<u64, B256Set>,
    /// Reverse mapping: tx_hash -> valid_before timestamp (for cleanup during drain).
    tx_to_expiry: B256Map<u64>,
    /// Pool for transactions whose fee token is temporarily paused.
    paused_pool: PausedFeeTokenPool,
    /// Tracks pending transaction staleness for DoS mitigation.
    pending_staleness: PendingStalenessTracker,
}

impl TempoPoolState {
    /// Tracks an AA transaction with a `valid_before` timestamp.
    fn track(&mut self, tx: &TempoPooledTransaction) {
        let valid_before = tx
            .inner()
            .as_aa()
            .and_then(|tx| tx.tx().valid_before.map(|value| value.get()));
        let key_expiry = tx.key_expiry();

        let expiry = [valid_before, key_expiry].into_iter().flatten().min();

        if let Some(expiry) = expiry {
            self.expiry_map
                .entry(expiry)
                .or_default()
                .insert(*tx.hash());
            self.tx_to_expiry.insert(*tx.hash(), expiry);
        }
    }

    /// Removes expiry and key-expiry tracking for a single transaction.
    fn untrack(&mut self, hash: &TxHash) {
        if let Some(expiry) = self.tx_to_expiry.remove(hash)
            && let Entry::Occupied(mut entry) = self.expiry_map.entry(expiry)
        {
            entry.get_mut().remove(hash);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
    }

    /// Removes expiry and key-expiry tracking for a batch of transactions.
    ///
    /// Mined transactions often share the same expiry timestamp, so first group
    /// hashes by their recorded expiry and then touch each expiry bucket once.
    /// This avoids repeating the `expiry_map` lookup for every mined hash while
    /// preserving O(1)-ish removal from each `B256Set` bucket.
    fn untrack_many<'a>(&mut self, hashes: impl IntoIterator<Item = &'a TxHash>) {
        // Skip iterating the mined hashes if nothing is tracked for expiry.
        if self.tx_to_expiry.is_empty() {
            return;
        }

        let mut hashes_by_expiry: BTreeMap<u64, B256Set> = BTreeMap::new();

        for hash in hashes {
            if let Some(expiry) = self.tx_to_expiry.remove(hash) {
                hashes_by_expiry.entry(expiry).or_default().insert(*hash);
            }
        }

        for (expiry, hashes) in hashes_by_expiry {
            if let Entry::Occupied(mut entry) = self.expiry_map.entry(expiry) {
                let bucket = entry.get_mut();
                for hash in hashes {
                    bucket.remove(&hash);
                }
                if bucket.is_empty() {
                    entry.remove();
                }
            }
        }
    }

    /// Collects and removes all expired transactions up to the given timestamp.
    /// Returns the list of expired transaction hashes.
    fn drain_expired(&mut self, tip_timestamp: u64) -> Vec<TxHash> {
        let mut expired = Vec::new();
        while let Some(entry) = self.expiry_map.first_entry()
            && *entry.key() <= tip_timestamp
        {
            let expired_hashes = entry.remove();
            expired.reserve(expired_hashes.len());
            for tx_hash in expired_hashes {
                self.tx_to_expiry.remove(&tx_hash);
                expired.push(tx_hash);
            }
        }
        expired
    }
}

/// Default interval for pending transaction staleness checks (30 minutes).
/// Transactions that remain pending across two consecutive snapshots will be evicted.
const DEFAULT_PENDING_STALENESS_INTERVAL: u64 = 30 * 60;

/// Tracks pending transactions across snapshots to detect stale transactions.
///
/// Uses a simple snapshot comparison approach:
/// - Every interval, take a snapshot of current pending transactions
/// - Transactions present in both the previous and current snapshot are considered stale
/// - Stale transactions are evicted since they've been pending for at least one full interval
#[derive(Debug)]
struct PendingStalenessTracker {
    /// Previous snapshot of pending transaction hashes.
    previous_pending: B256Set,
    /// Timestamp of the last snapshot.
    last_snapshot_time: Option<u64>,
    /// Interval in seconds between staleness checks.
    interval_secs: u64,
}

impl PendingStalenessTracker {
    /// Creates a new tracker with the given check interval.
    fn new(interval_secs: u64) -> Self {
        Self {
            previous_pending: B256Set::default(),
            last_snapshot_time: None,
            interval_secs,
        }
    }

    /// Returns true if the staleness check interval has elapsed and a snapshot should be taken.
    fn should_check(&self, now: u64) -> bool {
        self.last_snapshot_time
            .is_none_or(|last| now.saturating_sub(last) >= self.interval_secs)
    }

    /// Checks for stale transactions and updates the snapshot.
    ///
    /// Returns transactions that have been pending across two consecutive snapshots
    /// (i.e., pending for at least one full interval).
    ///
    /// Call `should_check` first to avoid collecting the pending set on every block.
    fn check_and_update(&mut self, current_pending: B256Set, now: u64) -> Vec<TxHash> {
        let previous_pending = std::mem::take(&mut self.previous_pending);

        // Split the current snapshot into stale transactions to evict and fresh
        // transactions to track. A transaction is stale if it appears in both
        // the previous and current pending snapshots.
        let (stale, next_pending): (Vec<TxHash>, B256Set) =
            current_pending.into_iter().partition_map(|hash| {
                if previous_pending.contains(&hash) {
                    Either::Left(hash)
                } else {
                    Either::Right(hash)
                }
            });

        self.previous_pending = next_pending;
        self.last_snapshot_time = Some(now);

        stale
    }
}

impl Default for PendingStalenessTracker {
    fn default() -> Self {
        Self::new(DEFAULT_PENDING_STALENESS_INTERVAL)
    }
}

/// Unified maintenance task for the Tempo transaction pool.
///
/// Handles:
/// - Evicting expired AA transactions (`valid_before <= tip_timestamp`)
/// - Evicting transactions using expired keychain keys (`AuthorizedKey.expiry <= tip_timestamp`)
/// - Updating the AA 2D nonce pool from `NonceManager` changes
/// - Refreshing the AMM liquidity cache from `FeeManager` updates
/// - Removing transactions signed with revoked keychain keys
/// - Moving transactions to/from the paused pool when fee tokens are paused/unpaused
///
/// Consolidates these operations into a single event loop to avoid multiple tasks
/// competing for canonical state updates and to minimize contention on pool locks.
pub async fn maintain_tempo_pool<Client>(pool: TempoTransactionPool<Client>)
where
    Client: StateProviderFactory
        + HeaderProvider<Header = TempoHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let mut state = TempoPoolState::default();
    let metrics = TempoPoolMaintenanceMetrics::default();

    // Subscribe to new transactions and chain events
    let mut new_txs = pool.new_transactions_listener();
    let mut chain_events = pool.client().canonical_state_stream();

    // Populate expiry tracking with existing transactions to prevent race conditions at start-up
    let all_txs = pool.all_transactions();
    for tx in all_txs.iter() {
        state.track(&tx.transaction);
    }

    let amm_cache = pool.amm_liquidity_cache();
    let mut new_tx_events = Vec::with_capacity(NEW_TX_DRAIN_LIMIT);

    loop {
        tokio::select! {
            // Track new transactions for expiry (valid_before and key expiry)
            n = new_txs.recv_many(&mut new_tx_events, NEW_TX_DRAIN_LIMIT) => {
                if n == 0 {
                    break;
                }

                // Batch already-buffered events to amortize select/poll overhead while bounding
                // per-wakeup work so block processing can still make progress.
                for tx_event in new_tx_events.drain(..) {
                    state.track(&tx_event.transaction.transaction);
                }
            }

            // Process all maintenance operations on new block commit or reorg
            Some(event) = chain_events.next() => {
                let new = match event {
                    CanonStateNotification::Reorg { old: _, new } => {
                        // Repopulate AMM liquidity cache from the new canonical chain
                        // to invalidate stale entries from orphaned blocks.
                        if let Err(err) = amm_cache.repopulate(pool.client()) {
                            error!(target: "txpool", ?err, "AMM liquidity cache repopulate after reorg failed");
                        }

                        new
                    }
                    CanonStateNotification::Commit { new } => new,
                };

                let block_update_start = Instant::now();

                let tip = &new;
                let bundle_state = tip.execution_outcome().state().state();
                let tip_timestamp = tip.tip().header().timestamp();

                // Removed transactions are collected here and dropped at the end of the
                // iteration: deallocating them (input data, signatures, allocator work) is
                // expensive and there is a block time of slack after the updates are done.
                let mut removed_txs: Vec<Vec<_>> = Vec::with_capacity(1);

                // 1. Update 2D nonce pool before scan-based maintenance.
                // This removes mined 2D nonce transactions and promotes newly
                // unblocked transactions before later pool scans.
                let nonce_pool_start = Instant::now();
                removed_txs.push(pool.notify_aa_pool_on_state_updates(bundle_state));
                metrics.nonce_pool_update_duration_seconds.record(nonce_pool_start.elapsed());

                // 2. Update AMM liquidity cache before revalidation/invalidation scans.
                let amm_start = Instant::now();
                amm_cache.on_new_state(tip.execution_outcome());
                if let Err(err) = amm_cache
                    .on_new_blocks(tip.blocks_iter().map(|block| block.sealed_header()), pool.client())
                {
                    error!(target: "txpool", ?err, "AMM liquidity cache update failed");
                }
                metrics.amm_cache_update_duration_seconds.record(amm_start.elapsed());

                // 3. Collect all block-level invalidation events
                let updates = TempoPoolUpdates::from_chain(tip);

                // Remove expiry tracking for mined transactions.
                state.untrack_many(tip.transaction_hashes());

                // Evict transactions slightly before they expire to prevent
                // broadcasting near-expiry txs that peers would reject.
                let max_expiry = tip_timestamp.saturating_add(EVICTION_BUFFER_SECS);

                // Collect expired transactions from local tracking state. Mined transactions
                // were untracked above so they cannot be drained here, and hashes that have
                // since left the pool are no-ops for `remove_transactions`.
                let expired_txs = state.drain_expired(max_expiry);

                // 4. Evict expired AA transactions
                let expired_start = Instant::now();
                if !expired_txs.is_empty() {
                    let evicted = pool.remove_transactions(expired_txs);
                    debug!(
                        target: "txpool",
                        count = evicted.len(),
                        tip_timestamp,
                        "Evicting expired AA transactions (valid_before)"
                    );
                    metrics.expired_transactions_evicted.increment(evicted.len() as u64);
                    removed_txs.push(evicted);
                }
                metrics.expired_eviction_duration_seconds.record(expired_start.elapsed());

                let mut all_txs: Option<AllPoolTransactions<TempoPooledTransaction>> = None;
                let mut removed_this_iteration = B256Set::default();

                // 5. Handle fee token pause/unpause events
                let pause_start = Instant::now();

                // Collect pause tokens that need pool scanning.
                // For pause events, we need to scan the pool. For unpause events, we
                // only need to check the paused_pool (O(1) lookup by token).
                let pause_tokens: Vec<Address> = updates
                    .pause_events
                    .iter()
                    .filter_map(|(token, is_paused)| is_paused.then_some(*token))
                    .collect();

                // Process pause events: fetch pool transactions once for all pause tokens.
                // This avoids the O(pause_events * pool_size) cost of fetching per event.
                if !pause_tokens.is_empty() {
                    // Group transactions by effective fee token for efficient batch processing.
                    // This single pass over all transactions handles all pause events.
                    let mut by_token = {
                        let all_txs = all_txs.get_or_insert_with(|| pool.all_transactions());
                        all_txs.iter()
                            .filter(|tx| !removed_this_iteration.contains(tx.hash()))
                            .fold(
                                AddressMap::<Vec<TxHash>>::default(),
                                |mut by_token, tx| {
                                    by_token
                                        .entry(tx.transaction.effective_fee_token())
                                        .or_default()
                                        .push(*tx.hash());
                                    by_token
                                },
                            )
                    };

                    // Process each pause token
                    for token in pause_tokens {
                        let Some(hashes_to_pause) = by_token.remove(&token) else {
                            // No transactions use this fee token - skip
                            continue;
                        };

                        let removed_txs = pool.remove_transactions(hashes_to_pause);
                        let count = removed_txs.len();

                        if count > 0 {
                            // Clean up expiry tracking for paused txs
                            for tx in &removed_txs {
                                state.untrack(tx.hash());
                                removed_this_iteration.insert(*tx.hash());
                            }

                            let entries: Vec<_> = removed_txs
                                .into_iter()
                                .map(|tx| {
                                    let valid_before = tx
                                        .transaction
                                        .inner()
                                        .as_aa()
                                        .and_then(|aa| aa.tx().valid_before.map(|value| value.get()));
                                    PausedEntry { tx, valid_before }
                                })
                                .collect();

                            let cap_evicted = state.paused_pool.insert_batch(token, entries);
                            metrics.transactions_paused.increment(count as u64);
                            if cap_evicted > 0 {
                                metrics.paused_pool_cap_evicted.increment(cap_evicted as u64);
                                debug!(
                                    target: "txpool",
                                    cap_evicted,
                                    "Evicted oldest paused transactions due to global cap"
                                );
                            }
                            debug!(
                                target: "txpool",
                                %token,
                                count,
                                "Moved transactions to paused pool (fee token paused)"
                            );
                        }
                    }
                }

                // Process unpause events: O(1) lookup per token in paused_pool
                for (token, is_paused) in &updates.pause_events {
                    if *is_paused {
                        continue; // Already handled above
                    }

                    // Unpause: drain from paused pool and re-add to main pool
                    let paused_entries = state.paused_pool.drain_token(token);
                    if !paused_entries.is_empty() {
                        let count = paused_entries.len();
                        metrics.transactions_unpaused.increment(count as u64);
                        let pool_clone = pool.clone();
                        let token = *token;
                        tokio::spawn(async move {
                            let txs: Vec<_> = paused_entries
                                .into_iter()
                                .map(|e| e.tx.transaction.clone())
                                .collect();

                            let results = pool_clone
                                .add_external_transactions(txs)
                                .await;

                            let success = results.iter().filter(|r| r.is_ok()).count();
                            debug!(
                                target: "txpool",
                                %token,
                                total = count,
                                success,
                                "Restored transactions from paused pool (fee token unpaused)"
                            );
                        });
                    }
                }

                // 6. Evict expired transactions from the paused pool
                let paused_expired = state.paused_pool.evict_expired(tip_timestamp);
                let paused_timed_out = state.paused_pool.evict_timed_out();
                let total_paused_evicted = paused_expired + paused_timed_out;
                if total_paused_evicted > 0 {
                    debug!(
                        target: "txpool",
                        count = total_paused_evicted,
                        tip_timestamp,
                        "Evicted expired transactions from paused pool"
                    );
                }

                // 7. Evict hard keychain invalidations from paused pool
                // Ignore spending_limit_spends here: AccessKeySpend only proves partial limit consumption, and paused txs are fully revalidated on unpause.
                if !updates.revoked_keys.is_empty()
                    || !updates.key_authorization_target_changes.is_empty()
                    || !updates.spending_limit_changes.is_empty()
                    || !updates.key_authorization_witness_burns.is_empty()
                {
                    state.paused_pool.evict_invalidated(
                        &updates.revoked_keys,
                        &updates.key_authorization_target_changes,
                        &updates.spending_limit_changes,
                        &updates.key_authorization_witness_burns,
                    );
                }
                metrics.pause_events_duration_seconds.record(pause_start.elapsed());

                // 8. Handle potentially invalidating updates
                // When a cached value changes of a token (transfer policy, or quote token) changes,
                // pending transactions using that token may become invalid. We need to remove them
                // and re-add so they go through full validation against the updated state.
                for (updated, counter, reason) in [
                    (
                        &updates.transfer_policy_updates,
                        &metrics.transfer_policy_revalidated,
                        "transfer policy update",
                    ),
                    (
                        &updates.quote_token_updates,
                        &metrics.quote_token_revalidated,
                        "quote token update",
                    ),
                ] {
                    if updated.is_empty() {
                        continue;
                    }

                    let hashes: Vec<TxHash> = {
                        let all_txs = all_txs.get_or_insert_with(|| pool.all_transactions());
                        all_txs
                            .iter()
                            .filter(|tx| !removed_this_iteration.contains(tx.hash()))
                            .filter(|tx| {
                                tx.transaction
                                    .resolved_fee_token()
                                    .is_some_and(|t| updated.contains(&t))
                            })
                            .map(|tx| *tx.hash())
                            .collect()
                    };
                    if !hashes.is_empty() {
                        let removed_txs = pool.remove_transactions(hashes);
                        let count = removed_txs.len();

                        for tx in &removed_txs {
                            state.untrack(tx.hash());
                            removed_this_iteration.insert(*tx.hash());
                        }

                        counter.increment(count as u64);

                        let pool_clone = pool.clone();
                        tokio::spawn(async move {
                            let txs: Vec<_> = removed_txs
                                .into_iter()
                                .map(|tx| (tx.origin, tx.transaction.clone()))
                                .collect();

                            let results = pool_clone.add_transactions_with_origins(txs).await;
                            let success = results.iter().filter(|r| r.is_ok()).count();
                            debug!(
                                target: "txpool",
                                total = count,
                                success,
                                reason,
                                "Re-validated transactions"
                            );
                        });
                    }
                }

                // 9. Evict invalidated transactions in a single pool scan
                // This checks revoked keys, spending limit changes, validator token changes,
                // blacklist additions, and whitelist removals together to avoid scanning
                // all transactions multiple times per block.
                if updates.has_invalidation_events() {
                    let invalidation_start = Instant::now();
                    debug!(
                        target: "txpool",
                        revoked_keys = updates.revoked_keys.len(),
                        key_authorization_target_changes =
                            updates.key_authorization_target_changes.len(),
                        spending_limit_changes = updates.spending_limit_changes.len(),
                        spending_limit_spends = updates.spending_limit_spends.len(),
                        validator_token_changes = updates.validator_token_changes.len(),
                        user_token_changes = updates.user_token_changes.len(),
                        blacklist_additions = updates.blacklist_additions.len(),
                        whitelist_removals = updates.whitelist_removals.len(),
                        "Processing transaction invalidation events"
                    );
                    let evicted = {
                        let all_txs = all_txs.get_or_insert_with(|| pool.all_transactions());
                        pool.evict_invalidated_transactions_from(
                            &updates,
                            all_txs
                                .iter()
                                .filter(|tx| !removed_this_iteration.contains(tx.hash())),
                        )
                    };
                    for tx in &evicted {
                        state.untrack(tx.hash());
                    }
                    metrics.transactions_invalidated.increment(evicted.len() as u64);
                    removed_txs.push(evicted);
                    metrics
                        .invalidation_eviction_duration_seconds
                        .record(invalidation_start.elapsed());
                }

                // 10. Evict stale pending transactions (must happen after AA pool promotions in step 1)
                // Only runs once per interval (~30 min) to avoid overhead on every block.
                // Transactions pending across two consecutive snapshots are considered stale.
                if state.pending_staleness.should_check(tip_timestamp) {
                    let current_pending: B256Set =
                        pool.pending_transactions().iter().map(|tx| *tx.hash()).collect();
                    let stale_to_evict =
                        state.pending_staleness.check_and_update(current_pending, tip_timestamp);

                    if !stale_to_evict.is_empty() {
                        debug!(
                            target: "txpool",
                            count = stale_to_evict.len(),
                            tip_timestamp,
                            "Evicting stale pending transactions"
                        );
                        // Clean up expiry tracking for stale txs to prevent orphaned entries
                        for hash in &stale_to_evict {
                            state.untrack(hash);
                        }
                        removed_txs.push(pool.remove_transactions(stale_to_evict));
                    }
                }

                // Record total block update duration
                metrics.block_update_duration_seconds.record(block_update_start.elapsed());

                // Deallocating removed transactions is expensive, so do it after all updates are done.
                drop(removed_txs);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::{Address, B256, TxHash};
    use reth_primitives_traits::RecoveredBlock;
    use std::{collections::HashSet, sync::Arc};
    use tempo_primitives::{Block, BlockBody, TempoHeader, TempoTxEnvelope};

    mod pending_staleness_tracker_tests {
        use super::*;

        #[test]
        fn no_eviction_on_first_snapshot() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx1 = TxHash::random();

            // First snapshot should not evict anything (no previous snapshot to compare)
            let stale = tracker.check_and_update([tx1].into_iter().collect(), 100);
            assert!(stale.is_empty());
            assert!(tracker.previous_pending.contains(&tx1));
        }

        #[test]
        fn evicts_transactions_present_in_both_snapshots() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx_stale = TxHash::random();
            let tx_new = TxHash::random();

            // First snapshot at t=0
            tracker.check_and_update([tx_stale].into_iter().collect(), 0);

            // Second snapshot at t=100: tx_stale still pending, tx_new is new
            let stale = tracker.check_and_update([tx_stale, tx_new].into_iter().collect(), 100);

            // tx_stale was in both snapshots -> evicted
            assert_eq!(stale.len(), 1);
            assert!(stale.contains(&tx_stale));

            // tx_new should be tracked for the next snapshot
            assert!(tracker.previous_pending.contains(&tx_new));
            // tx_stale should NOT be in the snapshot (it was evicted)
            assert!(!tracker.previous_pending.contains(&tx_stale));
        }

        #[test]
        fn should_check_returns_false_before_interval_elapsed() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx = TxHash::random();

            // First snapshot at t=0
            assert!(tracker.should_check(0));
            tracker.check_and_update([tx].into_iter().collect(), 0);

            // At t=50 (before interval elapsed) - should_check returns false
            assert!(!tracker.should_check(50));
            assert_eq!(tracker.last_snapshot_time, Some(0));

            // At t=100 (interval elapsed) - should_check returns true
            assert!(tracker.should_check(100));
        }

        #[test]
        fn removes_transactions_no_longer_pending_from_snapshot() {
            let mut tracker = PendingStalenessTracker::new(100);
            let tx1 = TxHash::random();
            let tx2 = TxHash::random();

            // First snapshot with both txs at t=0
            tracker.check_and_update([tx1, tx2].into_iter().collect(), 0);
            assert_eq!(tracker.previous_pending.len(), 2);

            // Second snapshot at t=100: only tx1 still pending
            // tx1 was in both -> stale, tx2 not in current -> removed from tracking
            let stale = tracker.check_and_update([tx1].into_iter().collect(), 100);
            assert_eq!(stale.len(), 1);
            assert!(stale.contains(&tx1));

            // Neither should be in the snapshot now
            assert!(tracker.previous_pending.is_empty());
        }
    }

    #[test]
    fn track_groups_duplicate_expiries() {
        let mut state = TempoPoolState::default();
        let tx_a = TxBuilder::aa(Address::random())
            .nonce(1)
            .valid_before(1000)
            .build();
        let tx_b = TxBuilder::aa(Address::random())
            .nonce(2)
            .valid_before(1000)
            .build();

        state.track(&tx_a);
        state.track(&tx_b);
        state.track(&tx_a);

        let bucket = state.expiry_map.get(&1000).unwrap();
        assert_eq!(bucket.len(), 2);
        assert!(bucket.contains(tx_a.hash()));
        assert!(bucket.contains(tx_b.hash()));
        assert_eq!(state.tx_to_expiry.get(tx_a.hash()), Some(&1000));
        assert_eq!(state.tx_to_expiry.get(tx_b.hash()), Some(&1000));
    }

    #[test]
    fn untrack_removes_hash_and_empty_bucket() {
        let mut state = TempoPoolState::default();
        let hash_a = TxHash::random();
        let hash_b = TxHash::random();
        let hash_unknown = TxHash::random();

        // Track two txs at the same valid_before
        insert_tracked_hash(&mut state, hash_a, 1000);
        insert_tracked_hash(&mut state, hash_b, 1000);

        // Mine hash_a and an unknown hash
        state.untrack(&hash_a);
        state.untrack(&hash_unknown);

        // hash_a removed from both maps
        assert!(!state.tx_to_expiry.contains_key(&hash_a));
        let bucket = state.expiry_map.get(&1000).unwrap();
        assert_eq!(bucket.len(), 1);
        assert!(bucket.contains(&hash_b));

        // Mine hash_b should remove the expiry_map entry entirely
        state.untrack(&hash_b);
        assert!(!state.tx_to_expiry.contains_key(&hash_b));
        assert!(!state.expiry_map.contains_key(&1000));
    }

    #[test]
    fn untrack_many_removes_hashes_by_expiry_bucket() {
        let mut state = TempoPoolState::default();
        let hash_a = TxHash::random();
        let hash_b = TxHash::random();
        let hash_c = TxHash::random();
        let hash_d = TxHash::random();
        let hash_unknown = TxHash::random();

        insert_tracked_hash(&mut state, hash_a, 1000);
        insert_tracked_hash(&mut state, hash_b, 1000);
        insert_tracked_hash(&mut state, hash_c, 1000);
        insert_tracked_hash(&mut state, hash_d, 2000);

        state.untrack_many([&hash_a, &hash_b, &hash_unknown, &hash_d]);

        assert!(!state.tx_to_expiry.contains_key(&hash_a));
        assert!(!state.tx_to_expiry.contains_key(&hash_b));
        assert!(!state.tx_to_expiry.contains_key(&hash_d));
        assert_eq!(state.tx_to_expiry.get(&hash_c), Some(&1000));

        let bucket = state.expiry_map.get(&1000).unwrap();
        assert_eq!(bucket.len(), 1);
        assert!(bucket.contains(&hash_c));
        assert!(!state.expiry_map.contains_key(&2000));
    }

    #[test]
    fn drain_expired_removes_expired_buckets_and_returns_hashes() {
        let mut state = TempoPoolState::default();
        let hash_a = TxHash::random();
        let hash_b = TxHash::random();
        let hash_c = TxHash::random();
        let hash_d = TxHash::random();

        insert_tracked_hash(&mut state, hash_a, 1000);
        insert_tracked_hash(&mut state, hash_b, 1000);
        insert_tracked_hash(&mut state, hash_c, 2000);
        insert_tracked_hash(&mut state, hash_d, 3000);

        let expired = state.drain_expired(2000);

        assert_hashes_eq(expired, &[hash_a, hash_b, hash_c]);
        assert!(!state.expiry_map.contains_key(&1000));
        assert!(!state.expiry_map.contains_key(&2000));
        assert!(state.expiry_map[&3000].contains(&hash_d));
        assert!(!state.tx_to_expiry.contains_key(&hash_a));
        assert!(!state.tx_to_expiry.contains_key(&hash_b));
        assert!(!state.tx_to_expiry.contains_key(&hash_c));
        assert_eq!(state.tx_to_expiry.get(&hash_d), Some(&3000));
    }

    fn insert_tracked_hash(state: &mut TempoPoolState, hash: TxHash, expiry: u64) {
        state.expiry_map.entry(expiry).or_default().insert(hash);
        state.tx_to_expiry.insert(hash, expiry);
    }

    fn assert_hashes_eq(actual: Vec<TxHash>, expected: &[TxHash]) {
        assert_eq!(actual.len(), expected.len());
        let actual: HashSet<TxHash> = actual.into_iter().collect();
        let expected: HashSet<TxHash> = expected.iter().copied().collect();
        assert_eq!(actual, expected);
    }

    mod narrow_event_decoding {
        use super::*;
        use alloy_primitives::U256;

        macro_rules! assert_decodes_like_generated {
            ($enum_ty:ident, $variant:ident, $event_ty:ty, $log:expr) => {{
                let expected = generated_decode::<$event_ty>(&$log);
                match $enum_ty::decode(&$log) {
                    Some($enum_ty::$variant(event)) => assert_eq!(event, expected),
                    _ => panic!("unexpected decoded event"),
                }
            }};
        }

        macro_rules! assert_decodes_unit_like_generated {
            ($enum_ty:ident, $variant:ident, $event_ty:ty, $log:expr) => {{
                let _expected = generated_decode::<$event_ty>(&$log);
                assert!(
                    matches!($enum_ty::decode(&$log), Some($enum_ty::$variant)),
                    "unexpected decoded event"
                );
            }};
        }

        fn event_log<T>(address: Address, event: T) -> Log
        where
            T: SolEvent,
            for<'a> &'a T: Into<alloy_primitives::LogData>,
        {
            Log::new_from_event_unchecked(address, event).reserialize()
        }

        fn generated_decode<T: SolEvent>(log: &Log) -> T {
            T::decode_log(log)
                .expect("generated event decode should succeed")
                .data
        }

        #[test]
        fn account_keychain_decode_matches_generated_event_decoders() {
            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::KeyAuthorized {
                    account: Address::random(),
                    publicKey: Address::random(),
                    signatureType: 0,
                    expiry: u64::MAX,
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                KeyAuthorized,
                IAccountKeychain::KeyAuthorized,
                log
            );

            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::AdminKeyAuthorized {
                    account: Address::random(),
                    publicKey: Address::random(),
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                AdminKeyAuthorized,
                IAccountKeychain::AdminKeyAuthorized,
                log
            );

            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::KeyRevoked {
                    account: Address::random(),
                    publicKey: Address::random(),
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                KeyRevoked,
                IAccountKeychain::KeyRevoked,
                log
            );

            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::SpendingLimitUpdated {
                    account: Address::random(),
                    publicKey: Address::random(),
                    token: Address::random(),
                    newLimit: U256::from(12_345),
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                SpendingLimitUpdated,
                IAccountKeychain::SpendingLimitUpdated,
                log
            );

            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::AccessKeySpend {
                    account: Address::random(),
                    publicKey: Address::random(),
                    token: Address::random(),
                    amount: U256::from(25),
                    remainingLimit: U256::from(75),
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                AccessKeySpend,
                IAccountKeychain::AccessKeySpend,
                log
            );

            let log = event_log(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::KeyAuthorizationWitnessBurned {
                    account: Address::random(),
                    witness: B256::random(),
                },
            );
            assert_decodes_like_generated!(
                AccountKeychainPoolEvent,
                KeyAuthorizationWitnessBurned,
                IAccountKeychain::KeyAuthorizationWitnessBurned,
                log
            );
        }

        #[test]
        fn fee_manager_decode_matches_generated_event_decoders() {
            let log = event_log(
                TIP_FEE_MANAGER_ADDRESS,
                IFeeManager::ValidatorTokenSet {
                    validator: Address::random(),
                    token: Address::random(),
                },
            );
            assert_decodes_like_generated!(
                FeeManagerPoolEvent,
                ValidatorTokenSet,
                IFeeManager::ValidatorTokenSet,
                log
            );

            let log = event_log(
                TIP_FEE_MANAGER_ADDRESS,
                IFeeManager::UserTokenSet {
                    user: Address::random(),
                    token: Address::random(),
                },
            );
            assert_decodes_like_generated!(
                FeeManagerPoolEvent,
                UserTokenSet,
                IFeeManager::UserTokenSet,
                log
            );
        }

        #[test]
        fn tip403_decode_matches_generated_event_decoders() {
            let log = event_log(
                TIP403_REGISTRY_ADDRESS,
                ITIP403Registry::BlacklistUpdated {
                    policyId: 7,
                    updater: Address::random(),
                    account: Address::random(),
                    restricted: true,
                },
            );
            assert_decodes_like_generated!(
                Tip403PoolEvent,
                BlacklistUpdated,
                ITIP403Registry::BlacklistUpdated,
                log
            );

            let log = event_log(
                TIP403_REGISTRY_ADDRESS,
                ITIP403Registry::WhitelistUpdated {
                    policyId: 9,
                    updater: Address::random(),
                    account: Address::random(),
                    allowed: false,
                },
            );
            assert_decodes_like_generated!(
                Tip403PoolEvent,
                WhitelistUpdated,
                ITIP403Registry::WhitelistUpdated,
                log
            );
        }

        #[test]
        fn tip20_decode_matches_generated_event_decoders() {
            let token = tempo_precompiles::PATH_USD_ADDRESS;
            let log = event_log(
                token,
                ITIP20::PauseStateUpdate {
                    updater: Address::random(),
                    isPaused: true,
                },
            );
            assert_decodes_like_generated!(
                Tip20PoolEvent,
                PauseStateUpdate,
                ITIP20::PauseStateUpdate,
                log
            );

            let log = event_log(
                token,
                ITIP20::TransferPolicyUpdate {
                    updater: Address::random(),
                    newPolicyId: 11,
                },
            );
            assert_decodes_unit_like_generated!(
                Tip20PoolEvent,
                TransferPolicyUpdate,
                ITIP20::TransferPolicyUpdate,
                log
            );

            let log = event_log(
                token,
                ITIP20::QuoteTokenUpdate {
                    updater: Address::random(),
                    newQuoteToken: Address::random(),
                },
            );
            assert_decodes_unit_like_generated!(
                Tip20PoolEvent,
                QuoteTokenUpdate,
                ITIP20::QuoteTokenUpdate,
                log
            );

            let log = event_log(
                token,
                ITIP20::Transfer {
                    from: Address::random(),
                    to: Address::random(),
                    amount: U256::from(42),
                },
            );
            // `Transfer` decoding is specialized to read only the indexed `from` topic, so
            // compare that against the field a full event decode would produce.
            let expected = generated_decode::<ITIP20::Transfer>(&log);
            match Tip20PoolEvent::decode(&log) {
                Some(Tip20PoolEvent::Transfer { from }) => assert_eq!(from, expected.from),
                _ => panic!("unexpected decoded event"),
            }
        }
    }

    fn create_test_chain(
        blocks: Vec<reth_primitives_traits::RecoveredBlock<Block>>,
    ) -> Arc<Chain<TempoPrimitives>> {
        create_test_chain_with_receipts(blocks, Vec::new())
    }

    fn create_test_chain_with_receipts(
        blocks: Vec<reth_primitives_traits::RecoveredBlock<Block>>,
        receipts: Vec<Vec<tempo_primitives::TempoReceipt>>,
    ) -> Arc<Chain<TempoPrimitives>> {
        use reth_provider::{Chain, ExecutionOutcome};

        Arc::new(Chain::new(
            blocks,
            ExecutionOutcome {
                receipts,
                ..Default::default()
            },
            Default::default(),
        ))
    }

    /// Helper to create a recovered block containing the given transactions.
    fn create_block_with_txs(
        block_number: u64,
        transactions: Vec<TempoTxEnvelope>,
        senders: Vec<Address>,
    ) -> RecoveredBlock<Block> {
        let header = TempoHeader {
            inner: alloy_consensus::Header {
                number: block_number,
                ..Default::default()
            },
            ..Default::default()
        };
        let body = BlockBody {
            transactions,
            ..Default::default()
        };
        let block = Block::new(header, body);
        RecoveredBlock::new_unhashed(block, senders)
    }

    /// Helper to extract a TempoTxEnvelope from a TempoPooledTransaction.
    fn extract_envelope(tx: &crate::transaction::TempoPooledTransaction) -> TempoTxEnvelope {
        tx.inner().clone().into_inner()
    }

    mod from_chain_spending_limit_spends {
        use super::*;
        use alloy_primitives::{IntoLogData, Log, U256};
        use alloy_signer_local::PrivateKeySigner;
        use tempo_primitives::{TempoReceipt, TempoTxType};

        /// Verify from_chain uses AccessKeySpend logs so it can track the actually spent token
        /// even when it differs from the mined tx's fee token.
        #[test]
        fn extracts_access_key_spend_events() {
            let user_address = Address::random();
            let access_key_signer = PrivateKeySigner::random();
            let key_id = access_key_signer.address();
            let fee_token = Address::random();
            let spent_token = Address::random();

            let keychain_tx = TxBuilder::aa(user_address)
                .fee_token(fee_token)
                .build_keychain(user_address, &access_key_signer);
            let envelope = extract_envelope(&keychain_tx);

            let spend_log = alloy_primitives::Log::new_from_event_unchecked(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::AccessKeySpend {
                    account: user_address,
                    publicKey: key_id,
                    token: spent_token,
                    amount: U256::from(25),
                    remainingLimit: U256::from(75),
                },
            )
            .reserialize();
            let receipt = tempo_primitives::TempoReceipt {
                tx_type: tempo_primitives::TempoTxType::AA,
                success: true,
                cumulative_gas_used: 1,
                logs: vec![spend_log],
            };

            let block = create_block_with_txs(1, vec![envelope], vec![user_address]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);

            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates
                    .spending_limit_spends
                    .contains(user_address, key_id, spent_token),
                "Should contain the AccessKeySpend event's (account, key_id, token)"
            );
            assert!(
                !updates
                    .spending_limit_spends
                    .contains(user_address, key_id, fee_token),
                "Should not infer spends from the tx fee token"
            );
            assert_eq!(updates.spending_limit_spends.len(), 1);
        }

        #[test]
        fn extracts_key_authorization_witness_burned_events() {
            let account = Address::random();
            let witness = B256::random();

            let log = alloy_primitives::Log::new_from_event_unchecked(
                ACCOUNT_KEYCHAIN_ADDRESS,
                IAccountKeychain::KeyAuthorizationWitnessBurned { account, witness },
            )
            .reserialize();
            let receipt = tempo_primitives::TempoReceipt {
                tx_type: tempo_primitives::TempoTxType::AA,
                success: true,
                cumulative_gas_used: 1,
                logs: vec![log],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);

            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates
                    .key_authorization_witness_burns
                    .get(&account)
                    .is_some_and(|witnesses| witnesses.contains(&witness)),
                "Should contain the burned (account, witness)"
            );
            assert!(updates.has_invalidation_events());
        }

        /// The pool should only track actual AccessKeySpend events, not infer spends from the
        /// mined transaction body.
        #[test]
        fn ignores_keychain_transactions_without_access_key_spend_logs() {
            let user_address = Address::random();
            let access_key_signer = PrivateKeySigner::random();
            let fee_token = Address::random();

            let keychain_tx = TxBuilder::aa(user_address)
                .fee_token(fee_token)
                .build_keychain(user_address, &access_key_signer);
            let envelope = extract_envelope(&keychain_tx);

            let block = create_block_with_txs(1, vec![envelope], vec![user_address]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);
            assert!(updates.spending_limit_spends.is_empty());
        }

        /// Non-keychain AA txs should NOT produce spending limit spends.
        #[test]
        fn ignores_non_keychain_aa_transactions() {
            let sender = Address::random();
            let tx = TxBuilder::aa(sender).fee_token(Address::random()).build();
            let envelope = extract_envelope(&tx);

            let block = create_block_with_txs(1, vec![envelope], vec![sender]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);
            assert!(updates.spending_limit_spends.is_empty());
        }

        /// EIP-1559 txs should NOT produce spending limit spends.
        #[test]
        fn ignores_eip1559_transactions() {
            let sender = Address::random();
            let tx = TxBuilder::eip1559(Address::random()).build_eip1559();
            let envelope = extract_envelope(&tx);

            let block = create_block_with_txs(1, vec![envelope], vec![sender]);
            let chain = create_test_chain(vec![block]);

            let updates = TempoPoolUpdates::from_chain(&chain);
            assert!(updates.spending_limit_spends.is_empty());
        }

        /// has_invalidation_events returns true when spending_limit_spends is non-empty.
        #[test]
        fn has_invalidation_events_includes_spending_limit_spends() {
            let mut updates = TempoPoolUpdates::new();
            assert!(!updates.has_invalidation_events());

            updates.spending_limit_spends.insert(
                Address::random(),
                Address::random(),
                Some(Address::random()),
            );
            assert!(updates.has_invalidation_events());
        }

        #[test]
        fn extracts_fee_balance_changes_from_tip20_transfer_logs() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;
            let from = Address::random();
            let to = Address::random();
            let amount = U256::from(42_u64);
            let log_data = ITIP20::Transfer { from, to, amount }.into_log_data();
            let log =
                Log::new_unchecked(fee_token, log_data.topics().to_vec(), log_data.data.clone());
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates
                    .fee_balance_changes
                    .get(&fee_token)
                    .is_some_and(|accounts| accounts.len() == 1 && accounts.contains(&from)),
                "TIP20 transfer logs should only mark the debited sender as balance-changed"
            );
            assert!(updates.has_invalidation_events());
        }

        /// TransferPolicyUpdate events are parsed from TIP20 token logs.
        #[test]
        fn extracts_transfer_policy_updates() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;
            let updater = Address::random();
            let new_policy_id = 42u64;
            let log_data = ITIP20::TransferPolicyUpdate {
                updater,
                newPolicyId: new_policy_id,
            }
            .into_log_data();
            let log =
                Log::new_unchecked(fee_token, log_data.topics().to_vec(), log_data.data.clone());
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert!(
                updates.transfer_policy_updates.contains(&fee_token),
                "TransferPolicyUpdate should be tracked by token address"
            );
        }

        /// Duplicate TransferPolicyUpdate events for the same token are deduplicated.
        #[test]
        fn transfer_policy_updates_deduplicates_by_token() {
            let fee_token = tempo_precompiles::PATH_USD_ADDRESS;

            let log_data_1 = ITIP20::TransferPolicyUpdate {
                updater: Address::random(),
                newPolicyId: 1,
            }
            .into_log_data();
            let log_data_2 = ITIP20::TransferPolicyUpdate {
                updater: Address::random(),
                newPolicyId: 2,
            }
            .into_log_data();
            let log1 = Log::new_unchecked(
                fee_token,
                log_data_1.topics().to_vec(),
                log_data_1.data.clone(),
            );
            let log2 = Log::new_unchecked(
                fee_token,
                log_data_2.topics().to_vec(),
                log_data_2.data.clone(),
            );
            let receipt = TempoReceipt {
                tx_type: TempoTxType::Legacy,
                success: true,
                cumulative_gas_used: 21_000,
                logs: vec![log1, log2],
            };

            let block = create_block_with_txs(1, vec![], vec![]);
            let chain = create_test_chain_with_receipts(vec![block], vec![vec![receipt]]);
            let updates = TempoPoolUpdates::from_chain(&chain);

            assert_eq!(
                updates.transfer_policy_updates.len(),
                1,
                "duplicate policy updates for the same token should be deduplicated"
            );
        }

        /// Duplicate validator token changes must be deduplicated (last-write-wins).
        #[test]
        fn validator_token_changes_deduplicates_by_validator() {
            let validator = Address::random();
            let token_a = Address::random();
            let token_b = Address::random();

            let mut updates = TempoPoolUpdates::new();
            updates.validator_token_changes.insert(validator, token_a);
            updates.validator_token_changes.insert(validator, token_b);

            assert_eq!(
                updates.validator_token_changes.len(),
                1,
                "duplicate validator entries must be deduplicated"
            );
            assert_eq!(
                updates.validator_token_changes.get(&validator).copied(),
                Some(token_b),
                "last-write-wins: second token should overwrite the first"
            );
        }
    }
}
