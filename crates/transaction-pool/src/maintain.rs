//! Transaction pool maintenance tasks.

use crate::{
    RevokedKeys, SpendingLimitUpdates, TempoTransactionPool, metrics::TempoPoolMaintenanceMetrics,
    transaction::TempoPooledTransaction, validator::ConfigureTempoPoolEvm,
};
use alloy_consensus::transaction::TxHashRef;
use alloy_primitives::{
    Address, B256, Log, TxHash,
    map::{AddressMap, AddressSet, B256Set},
};
use alloy_sol_types::SolEvent;
use futures::StreamExt;
use itertools::{Either, Itertools};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{CanonStateNotification, CanonStateSubscriptions, Chain, HeaderProvider};
use reth_storage_api::StateProviderFactory;
use reth_transaction_pool::{AllPoolTransactions, PoolTransaction, TransactionPool};
use std::time::Instant;
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

/// Authentication-relevant leaf changes, independent of receipt events.
fn configurable_account_changes(state: &AddressMap<revm::database::BundleAccount>) -> AddressSet {
    state
        .iter()
        .filter_map(|(address, account)| {
            let auth = |info: &revm::state::AccountInfo| {
                (
                    tempo_primitives::account::decode_config_commitment(&info.extension, true),
                    info.code_hash,
                )
            };
            let old = account.original_info.as_ref().map(auth);
            let new = account.info.as_ref().map(auth);
            // Malformed extension payloads must also force stateful revalidation.
            (old != new || new.as_ref().is_some_and(|(hash, _)| hash.is_err())).then_some(*address)
        })
        .collect()
}

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
    /// Fee tokens paused by this block.
    pub paused_tokens: AddressSet,
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
            && self.paused_tokens.is_empty()
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
                        if event.isPaused {
                            updates.paused_tokens.insert(log.address);
                        } else {
                            updates.paused_tokens.remove(&log.address);
                        }
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
            || !self.paused_tokens.is_empty()
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
/// - Evicting transactions when their fee token is paused
///
/// Consolidates these operations into a single event loop to avoid multiple tasks
/// competing for canonical state updates and to minimize contention on pool locks.
pub async fn maintain_tempo_pool<Client, EvmConfig>(pool: TempoTransactionPool<Client, EvmConfig>)
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + HeaderProvider<Header = TempoHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + 'static,
{
    let chain_events = pool.client().canonical_state_stream();
    maintain_tempo_pool_with_events(pool, chain_events).await;
}

// Retry limits bound local maintenance memory and work, not transaction validity.
const MAINTENANCE_CONCURRENCY: usize = 4;
const RESURRECTION_CAPACITY: usize = 256;
const RESURRECTION_BYTES: usize = 16 * 1024 * 1024;
const RESURRECTION_ATTEMPTS: u8 = 8;
const RESURRECTION_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60);

enum MaintenanceItem {
    Revalidate(B256),
    Resurrect {
        transaction: Box<TempoPooledTransaction>,
        first_seen: Instant,
        attempts: u8,
    },
}

impl MaintenanceItem {
    fn hash(&self) -> B256 {
        match self {
            Self::Revalidate(hash) => *hash,
            Self::Resurrect { transaction, .. } => *transaction.hash(),
        }
    }

    fn expired(&self, now: Instant) -> bool {
        matches!(self, Self::Resurrect { first_seen, attempts, .. }
            if *attempts >= RESURRECTION_ATTEMPTS || now.duration_since(*first_seen) >= RESURRECTION_MAX_AGE)
    }
}

#[derive(Default)]
struct MaintenanceQueue {
    items: std::collections::VecDeque<MaintenanceItem>,
    hashes: B256Set,
    /// Failed work waits for the next timer tick or canonical event, not another job's completion.
    deferred: B256Set,
    in_flight: alloy_primitives::map::B256Map<std::sync::Arc<MaintenancePermit>>,
    resurrection_count: usize,
    resurrection_bytes: usize,
}

impl MaintenanceQueue {
    fn revalidate(&mut self, hash: B256) {
        self.deferred.remove(&hash);
        if self.hashes.insert(hash) {
            self.items.push_back(MaintenanceItem::Revalidate(hash));
        }
    }

    fn resurrect(&mut self, transaction: TempoPooledTransaction) {
        if transaction.encoded_length() > RESURRECTION_BYTES {
            return;
        }
        if let Some(index) = self
            .items
            .iter()
            .position(|item| item.hash() == *transaction.hash())
        {
            if matches!(self.items[index], MaintenanceItem::Resurrect { .. }) {
                return;
            }
            self.items.remove(index);
            self.hashes.remove(transaction.hash());
        }
        // These totals include in-flight work; evict only queued orphans, never restart a worker.
        while self.resurrection_count >= RESURRECTION_CAPACITY
            || self.resurrection_bytes + transaction.encoded_length() > RESURRECTION_BYTES
        {
            let Some(index) = self
                .items
                .iter()
                .position(|item| matches!(item, MaintenanceItem::Resurrect { .. }))
            else {
                return;
            };
            let removed = self.items.remove(index).unwrap();
            self.remove(&removed);
        }
        self.resurrection_count += 1;
        self.resurrection_bytes += transaction.encoded_length();
        self.hashes.insert(*transaction.hash());
        self.items.push_back(MaintenanceItem::Resurrect {
            transaction: Box::new(transaction),
            first_seen: Instant::now(),
            attempts: 0,
        });
    }

    fn retain(&mut self, mut keep: impl FnMut(&MaintenanceItem) -> bool) {
        self.items.retain(|item| {
            if keep(item) {
                true
            } else {
                self.hashes.remove(&item.hash());
                self.deferred.remove(&item.hash());
                if let MaintenanceItem::Resurrect { transaction, .. } = item {
                    self.resurrection_count -= 1;
                    self.resurrection_bytes -= transaction.encoded_length();
                }
                false
            }
        });
    }

    fn refresh(&mut self, contains: impl Fn(&B256) -> bool, now: Instant) {
        for item in &mut self.items {
            if let MaintenanceItem::Resurrect { transaction, .. } = item
                && contains(transaction.hash())
            {
                self.resurrection_count -= 1;
                self.resurrection_bytes -= transaction.encoded_length();
                *item = MaintenanceItem::Revalidate(*transaction.hash());
            }
        }
        self.retain(|item| {
            !item.expired(now)
                && match item {
                    MaintenanceItem::Revalidate(hash) => contains(hash),
                    MaintenanceItem::Resurrect { .. } => true,
                }
        });
    }

    fn remove(&mut self, item: &MaintenanceItem) {
        self.hashes.remove(&item.hash());
        self.deferred.remove(&item.hash());
        if let MaintenanceItem::Resurrect { transaction, .. } = item {
            self.resurrection_count -= 1;
            self.resurrection_bytes -= transaction.encoded_length();
        }
    }

    fn complete(&mut self, item: MaintenanceItem, retry: bool) {
        let permit = self
            .in_flight
            .remove(&item.hash())
            .expect("completed maintenance job");
        if retry
            && permit.is_valid()
            && !item.expired(Instant::now())
            && self.hashes.insert(item.hash())
        {
            self.deferred.insert(item.hash());
            self.items.push_back(item);
        } else {
            // A queued followup can carry an orphan payload while an earlier revalidation runs.
            if let MaintenanceItem::Resurrect { transaction, .. } = item {
                self.resurrection_count -= 1;
                self.resurrection_bytes -= transaction.encoded_length();
            }
        }
    }

    fn next(&mut self) -> Option<(MaintenanceItem, std::sync::Arc<MaintenancePermit>)> {
        let index = self.items.iter().position(|item| {
            !self.in_flight.contains_key(&item.hash()) && !self.deferred.contains(&item.hash())
        })?;
        let item = self.items.remove(index)?;
        self.hashes.remove(&item.hash());
        let permit = std::sync::Arc::new(MaintenancePermit::new(match &item {
            MaintenanceItem::Revalidate(_) => None,
            MaintenanceItem::Resurrect { first_seen, .. } => {
                Some(*first_seen + RESURRECTION_MAX_AGE)
            }
        }));
        self.in_flight.insert(item.hash(), permit.clone());
        Some((item, permit))
    }

    fn discard_mined(&mut self, hashes: &B256Set) {
        self.retain(|item| !hashes.contains(&item.hash()));
        for hash in hashes {
            if let Some(permit) = self.in_flight.get(hash) {
                permit.cancel();
            }
        }
    }
}

/// Checked after queued validation, immediately before applying its pool result.
pub(crate) struct MaintenancePermit {
    cancelled: std::sync::atomic::AtomicBool,
    expires_at: Option<Instant>,
}

impl MaintenancePermit {
    pub(crate) fn new(expires_at: Option<Instant>) -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
            expires_at,
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn is_valid(&self) -> bool {
        !self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
            && self
                .expires_at
                .is_none_or(|deadline| Instant::now() < deadline)
    }
}

async fn run_maintenance_item<Client, EvmConfig>(
    pool: TempoTransactionPool<Client, EvmConfig>,
    mut item: MaintenanceItem,
    permit: std::sync::Arc<MaintenancePermit>,
) -> (MaintenanceItem, bool)
where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
{
    let retry = match &mut item {
        MaintenanceItem::Revalidate(hash) => {
            let mut hashes = B256Set::from_iter([*hash]);
            pool.revalidate_pending_transactions(&mut hashes, Some(&permit))
                .await;
            hashes.contains(hash)
        }
        MaintenanceItem::Resurrect {
            transaction,
            attempts,
            ..
        } => {
            *attempts += 1;
            if pool.contains(transaction.hash()) {
                false
            } else {
                matches!(
                    pool.add_fresh_transaction_with_permit(reth_transaction_pool::TransactionOrigin::External, (**transaction).clone(), Some(&permit)).await,
                    Err(error) if matches!(error.kind, reth_transaction_pool::error::PoolErrorKind::Other(_))
                )
            }
        }
    };
    (item, retry)
}

pub(crate) async fn maintain_tempo_pool_with_events<Client, EvmConfig>(
    pool: TempoTransactionPool<Client, EvmConfig>,
    mut chain_events: impl futures::Stream<Item = CanonStateNotification<TempoPrimitives>> + Unpin,
) where
    EvmConfig: ConfigureTempoPoolEvm,
    Client: StateProviderFactory
        + HeaderProvider<Header = TempoHeader>
        + ChainSpecProvider<ChainSpec: EthChainSpec<Header = TempoHeader> + TempoHardforks>
        + 'static,
{
    let mut pending_staleness = PendingStalenessTracker::default();
    let mut pending = MaintenanceQueue::default();
    let mut jobs = futures::stream::FuturesUnordered::new();
    let mut wakeup = tokio::time::interval(std::time::Duration::from_millis(100));
    wakeup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rescan_all = false;
    let mut dispatch = false;
    let mut refresh_pending = false;
    let mut closed = false;
    let mut previous_tip = None;
    let mut mined_pending = B256Set::default();
    let metrics = TempoPoolMaintenanceMetrics::default();

    let amm_cache = pool.amm_liquidity_cache();

    // Process all maintenance operations on new block commit or reorg.
    loop {
        if dispatch {
            dispatch = false;
            if refresh_pending {
                refresh_pending = false;
                mined_pending.retain(|hash| pool.contains(hash));
                pending.refresh(|hash| pool.contains(hash), Instant::now());
            }
            if pool.processed_head_is_current().unwrap_or(false) {
                if rescan_all {
                    // A missed/early event can affect ordinary token-policy transactions too.
                    for tx in pool.all_transactions().iter() {
                        if !mined_pending.contains(tx.hash()) {
                            pending.revalidate(*tx.hash());
                        }
                    }
                    rescan_all = false;
                }
                while jobs.len() < MAINTENANCE_CONCURRENCY {
                    let Some((item, permit)) = pending.next() else {
                        break;
                    };
                    jobs.push(run_maintenance_item(pool.clone(), item, permit));
                }
            }
        }
        // Drain synchronized queued work once on stream closure; do not retry after shutdown.
        if closed
            && jobs.is_empty()
            && (pending.items.is_empty() || !pool.processed_head_is_current().unwrap_or(false))
        {
            break;
        }
        let event = tokio::select! {
            event = chain_events.next(), if !closed => match event {
                Some(event) => event,
                None => {
                    closed = true;
                    pending.deferred.clear();
                    refresh_pending = true;
                    dispatch = true;
                    continue;
                }
            },
            Some((item, retry)) = jobs.next(), if !jobs.is_empty() => {
                pending.complete(item, retry && !closed);
                dispatch = true;
                continue;
            },
            _ = wakeup.tick() => {
                pending.deferred.clear();
                refresh_pending = true;
                dispatch = true;
                continue;
            }
        };
        pending.deferred.clear();
        refresh_pending = true;
        let reorg = matches!(&event, CanonStateNotification::Reorg { .. });
        let new = match event {
            CanonStateNotification::Reorg { old, new } => {
                for hash in old.transaction_hashes() {
                    mined_pending.remove(hash);
                }
                let mined: B256Set = new.transaction_hashes().copied().collect();
                for transaction in old
                    .transactions_recovered_iter()
                    .filter(|tx| !mined.contains(tx.tx_hash()))
                    .map(|tx| TempoPooledTransaction::new(tx.cloned()))
                    .filter(|tx| tx.has_configurable_dependencies())
                {
                    pending.resurrect(transaction);
                }
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
        if previous_tip.is_some_and(|hash| {
            tip.blocks_iter()
                .next()
                .is_some_and(|block| block.header().parent_hash() != hash)
        }) {
            // Canonical streams may skip notifications on lag; recover dependencies from state.
            rescan_all = true;
            if !reorg && let Err(error) = amm_cache.repopulate(pool.client()) {
                error!(target: "txpool", %error, "AMM liquidity cache repopulate after notification gap failed");
            }
        }
        previous_tip = Some(tip.tip().hash());

        // Removed transactions are collected here and dropped at the end of the
        // iteration: deallocating them (input data, signatures, allocator work) is
        // expensive and there is a block time of slack after the updates are done.
        let mut removed_txs: Vec<Vec<_>> = Vec::with_capacity(1);

        // 1. Update 2D nonce pool before scan-based maintenance.
        // This removes mined 2D nonce transactions and promotes newly
        // unblocked transactions before later pool scans.
        let nonce_pool_start = Instant::now();
        removed_txs.push(pool.notify_aa_pool_on_state_updates(bundle_state));
        metrics
            .nonce_pool_update_duration_seconds
            .record(nonce_pool_start.elapsed());

        // 2. Update AMM liquidity cache before revalidation/invalidation scans.
        let amm_start = Instant::now();
        amm_cache.on_new_state(tip.execution_outcome());
        if let Err(err) = amm_cache.on_new_blocks(
            tip.blocks_iter().map(|block| block.sealed_header()),
            pool.client(),
        ) {
            error!(target: "txpool", ?err, "AMM liquidity cache update failed");
        }
        metrics
            .amm_cache_update_duration_seconds
            .record(amm_start.elapsed());

        // 3. Collect all block-level invalidation events
        let updates = TempoPoolUpdates::from_chain(tip);

        let mut all_txs: Option<AllPoolTransactions<TempoPooledTransaction>> = None;
        // Reth's canonical-update handling may not have pruned mined transactions yet.
        // Exclude them from every snapshot-based maintenance phase so they follow the
        // normal mined path rather than being discarded from the pool.
        let removed_this_iteration: B256Set = tip.transaction_hashes().copied().collect();
        mined_pending.extend(
            removed_this_iteration
                .iter()
                .filter(|hash| pool.contains(hash))
                .copied(),
        );
        pending.discard_mined(&removed_this_iteration);
        // Bookkeeping above must run even when the validation callback trails this event.
        // Never take a pool snapshot until H-validated insertions can no longer land.
        if !pool.processed_head_is_current().unwrap_or(false) {
            rescan_all = true;
            continue;
        }

        // Registration has no event. Inspect authenticated account deltas, including code changes.
        let changed = configurable_account_changes(bundle_state);
        let code_changed: AddressSet = bundle_state
            .iter()
            .filter_map(|(address, account)| {
                (account.original_info.as_ref().map(|info| info.code_hash)
                    != account.info.as_ref().map(|info| info.code_hash))
                .then_some(*address)
            })
            .collect();
        if reorg || !changed.is_empty() || !code_changed.is_empty() {
            for tx in all_txs
                .get_or_insert_with(|| pool.all_transactions())
                .iter()
            {
                if !removed_this_iteration.contains(tx.hash())
                    && ((reorg && tx.transaction.has_configurable_dependencies())
                        || tx
                            .transaction
                            .configurable_signers()
                            .any(|account| changed.contains(&account))
                        || tx
                            .transaction
                            .authorization_parent()
                            .is_some_and(|account| changed.contains(&account))
                        || tx
                            .transaction
                            .configurable_grant_recipient()
                            .is_some_and(|account| code_changed.contains(&account)))
                {
                    pending.revalidate(*tx.hash());
                }
            }
        }
        // 4. Handle potentially invalidating updates
        // When a cached value changes of a token (transfer policy, or quote token) changes,
        // pending transactions using that token may become invalid. Revalidate in place so
        // transient errors do not lose candidates or their listener registrations.
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
                counter.increment(hashes.len() as u64);
                debug!(target: "txpool", count = hashes.len(), reason, "Revalidating retained transactions");
                for hash in hashes {
                    pending.revalidate(hash);
                }
            }
        }

        dispatch = true;

        // 5. Evict expired and invalidated transactions in one pool traversal.
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
                Some(tip_timestamp.saturating_add(EVICTION_BUFFER_SECS)),
            )
        };
        metrics
            .transactions_invalidated
            .increment(evicted.len() as u64);
        removed_txs.push(evicted);
        metrics
            .invalidation_eviction_duration_seconds
            .record(invalidation_start.elapsed());

        metrics
            .expired_eviction_duration_seconds
            .record(invalidation_start.elapsed());

        // 6. Evict stale pending transactions (must happen after AA pool promotions in step 1)
        // Only runs once per interval (~30 min) to avoid overhead on every block.
        // Transactions pending across two consecutive snapshots are considered stale.
        if pending_staleness.should_check(tip_timestamp) {
            let current_pending: B256Set = pool
                .pending_transactions()
                .iter()
                .map(|tx| *tx.hash())
                .collect();
            let stale_to_evict = pending_staleness.check_and_update(current_pending, tip_timestamp);

            if !stale_to_evict.is_empty() {
                debug!(
                    target: "txpool",
                    count = stale_to_evict.len(),
                    tip_timestamp,
                    "Evicting stale pending transactions"
                );
                removed_txs.push(pool.remove_transactions(stale_to_evict));
            }
        }

        // Record total block update duration
        metrics
            .block_update_duration_seconds
            .record(block_update_start.elapsed());

        // Deallocating removed transactions is expensive, so do it after all updates are done.
        drop(removed_txs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::TxBuilder;
    use alloy_primitives::{Address, B256, TxHash};
    use reth_primitives_traits::RecoveredBlock;
    use std::sync::Arc;
    use tempo_primitives::{Block, BlockBody, TempoHeader, TempoTxEnvelope};

    #[test]
    fn configurable_leaf_changes_include_eventless_registration_and_code() {
        use revm::{
            database::{AccountStatus, BundleAccount},
            state::{AccountExtension, AccountInfo},
        };
        let address = Address::repeat_byte(0x22);
        let original = AccountInfo::default();
        let mut registered = original.clone();
        registered.extension = AccountExtension::copy_from_slice(
            &tempo_primitives::account::encode_config_commitment(B256::repeat_byte(0x42)),
        );
        for (old, new, changed) in [
            (original.clone(), registered.clone(), true),
            (registered.clone(), original, true),
            (registered.clone(), registered.clone(), false),
            (
                registered.clone(),
                AccountInfo {
                    code_hash: B256::repeat_byte(0x55),
                    ..registered
                },
                true,
            ),
        ] {
            let state = AddressMap::from_iter([(
                address,
                BundleAccount::new(
                    Some(old),
                    Some(new),
                    Default::default(),
                    AccountStatus::Changed,
                ),
            )]);
            assert_eq!(
                configurable_account_changes(&state).contains(&address),
                changed
            );
        }
    }

    #[test]
    fn maintenance_queue_preserves_orphan_followup_after_mining() {
        let tx = TxBuilder::aa(Address::repeat_byte(1)).build();
        let hash = *tx.hash();
        let mut queue = MaintenanceQueue::default();
        queue.revalidate(hash);
        let (running, permit) = queue.next().unwrap();
        queue.discard_mined(&B256Set::from_iter([hash]));
        assert!(!permit.is_valid());
        queue.resurrect(tx);
        assert!(
            queue.next().is_none(),
            "same hash must not run concurrently"
        );
        queue.complete(running, true);
        let (followup, _) = queue.next().unwrap();
        assert!(matches!(followup, MaintenanceItem::Resurrect { .. }));
        queue.complete(followup, false);
        assert_eq!(queue.resurrection_count, 0);
        assert_eq!(queue.resurrection_bytes, 0);
        assert!(queue.hashes.is_empty());
    }

    #[test]
    fn maintenance_queue_rotates_retries_and_preserves_new_requests() {
        let mut queue = MaintenanceQueue::default();
        let first = B256::repeat_byte(1);
        let second = B256::repeat_byte(2);
        queue.revalidate(first);
        queue.revalidate(second);
        let (running, _) = queue.next().unwrap();
        queue.revalidate(first);
        queue.complete(running, false);
        let (running, _) = queue.next().unwrap();
        assert_eq!(running.hash(), second);
        queue.complete(running, true);
        let (running, _) = queue.next().unwrap();
        assert_eq!(running.hash(), first);
        queue.complete(running, false);
        assert!(
            queue.next().is_none(),
            "completion must not wake failed work"
        );
        queue.deferred.clear();
        assert_eq!(queue.next().unwrap().0.hash(), second);
    }

    #[test]
    fn resurrection_retry_limits_include_inflight_and_idle_expiry() {
        let mut queue = MaintenanceQueue::default();
        for nonce in 0..=RESURRECTION_CAPACITY {
            queue.resurrect(
                TxBuilder::aa(Address::repeat_byte(1))
                    .nonce(nonce as u64)
                    .build(),
            );
        }
        assert_eq!(queue.resurrection_count, RESURRECTION_CAPACITY);
        let (mut running, _) = queue.next().unwrap();
        assert_eq!(queue.resurrection_count, RESURRECTION_CAPACITY);
        if let MaintenanceItem::Resurrect { attempts, .. } = &mut running {
            *attempts = RESURRECTION_ATTEMPTS;
        }
        queue.complete(running, true);
        assert_eq!(queue.resurrection_count, RESURRECTION_CAPACITY - 1);
        queue.refresh(|_| false, Instant::now() + RESURRECTION_MAX_AGE);
        assert!(queue.items.is_empty());
        assert!(queue.hashes.is_empty());
        assert_eq!(queue.resurrection_count, 0);
        assert_eq!(queue.resurrection_bytes, 0);
    }

    #[test]
    fn resurrection_payload_bytes_are_bounded() {
        use alloy_primitives::{Bytes, TxKind, U256};
        let mut queue = MaintenanceQueue::default();
        for nonce in 0..10 {
            let tx = TxBuilder::aa(Address::repeat_byte(1))
                .nonce(nonce)
                .calls(vec![tempo_primitives::transaction::Call {
                    to: TxKind::Call(Address::repeat_byte(2)),
                    input: Bytes::from(vec![0; 2 * 1024 * 1024]),
                    value: U256::ZERO,
                }])
                .build();
            queue.resurrect(tx);
            assert!(queue.resurrection_bytes <= RESURRECTION_BYTES);
        }
        assert!(queue.resurrection_count < 10);
    }

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
