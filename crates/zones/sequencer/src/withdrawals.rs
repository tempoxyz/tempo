//! Withdrawal collection store and L1 withdrawal processor for the zone sequencer.
//!
//! This module provides two main components:
//!
//! - [`WithdrawalStore`] — an in-memory store that holds [`abi::Withdrawal`] structs grouped by
//!   batch index. The L1 portal queue only stores hashes, so the sequencer must retain the actual
//!   withdrawal data to provide it when calling `processWithdrawals`.
//!
//! - [`WithdrawalProcessor`] — a background task that polls the ZonePortal withdrawal queue on
//!   **Tempo L1** and processes withdrawals by calling `processWithdrawals(withdrawals, remainingQueue)`.
//!
//! ## Data flow
//!
//! 1. Withdrawal requests originate on the **Zone L2** (`ZoneOutbox.requestWithdrawal`).
//! 2. The sequencer observes `WithdrawalRequested` events and stores the withdrawal data in the
//!    [`WithdrawalStore`].
//! 3. At batch finalization, the sequencer calls `finalizeWithdrawalBatch` on L2, which builds a
//!    hash chain. The proof then enqueues this hash chain into the portal's withdrawal queue on L1.
//! 4. The [`WithdrawalProcessor`] polls the portal queue on L1 and processes each withdrawal by
//!    providing the original data and the remaining queue hash.
//!
//! ## Batch-to-slot mapping
//!
//! The portal's withdrawal queue slots correspond to batch indices. The store's `batch_index`
//! should match the portal slot index. The caller (batch submitter) is responsible for tracking
//! which `batch_index` maps to which portal slot.

use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_eips::eip1559::Eip1559Estimation;
use alloy_network::ReceiptResponse;
use alloy_primitives::{Address, U256};
use alloy_provider::{DynProvider, Provider};
use futures::{StreamExt, stream::FuturesUnordered};
use parking_lot::Mutex;
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderExt};
use tempo_contracts::precompiles::{ITIP20, PATH_USD_ADDRESS};
use tokio::sync::Notify;
use tokio_util::sync;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    abi::{self, MAX_WITHDRAWAL_GAS_LIMIT, ZonePortal},
    metrics::{SequencerMetrics, WithdrawalProcessorMetrics},
    nonce_keys::PROCESS_WITHDRAWAL_NONCE_KEY,
    settlement::{WithdrawalPage, find_processed_offset},
};
use tempo_alloy::rpc::TempoCallBuilderExt;
use zone_primitives::constants::{MAX_UNPROCESSED_DEPOSITS, WITHDRAWAL_BOUNCEBACK_RESERVE};

const PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);

fn bound_l1_fees(fees: Eip1559Estimation) -> Eip1559Estimation {
    let max_fee_per_gas = fees.max_fee_per_gas.min(crate::TEMPO_L1_MAX_FEE_PER_GAS);
    Eip1559Estimation {
        max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas.min(max_fee_per_gas),
    }
}

// These planner allowances were calibrated against the current ZonePortal/ZoneMessenger bytecode.
// Pre-refund T1 dev-L1 traces used 553,703, 1,068,088, and 1,348,063 gas for one, two, and four
// successful simple items, and 1,347,339 gas around a callback. T3 Foundry traces used 1,026,857
// gas for a failed simple transfer with a bounceback and at most 1,030,017 for deposit bouncebacks.
// Re-run the traces when the contracts or Tempo gas accounting change.

/// Planner-only gas reserved once per `processWithdrawals` transaction for batch-level portal
/// work.
const PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS: u64 = 500_000;

/// Planner-only gas reserved for a simple withdrawal.
const PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS: u64 = 1_000_000;

/// Planner-only fixed allowance for a callback withdrawal, excluding its forwarded callback gas.
const PROCESS_CALLBACK_WITHDRAWAL_ITEM_OVERHEAD_GAS: u64 = 1_750_000;

/// Planner-only gas reserved for a failed-deposit bounceback withdrawal.
const PROCESS_DEPOSIT_BOUNCEBACK_ITEM_OVERHEAD_GAS: u64 = 1_250_000;

/// Default planned gas budget for one `processWithdrawals` transaction.
///
/// This is an operator-side batching limit, not the protocol callback cap. The planner charges the
/// allowances above against this budget. It currently has the same numeric value as
/// [`MAX_WITHDRAWAL_GAS_LIMIT`]; a single withdrawal may exceed the budget so it cannot block the
/// queue.
pub const DEFAULT_MAX_WITHDRAWAL_BATCH_GAS: u64 = 10_000_000;

/// Largest supported planned gas budget for one `processWithdrawals` transaction.
///
/// Tempo L1 currently caps transaction gas at 30,000,000. Packed batches cannot exceed this
/// 20,000,000 budget. Oversized singletons bypass the budget, but the protocol callback cap keeps
/// their maximum planned gas at 12,250,000. Both remain below the L1 limit, avoiding repeated
/// submission of a transaction that can never be mined.
pub const MAX_WITHDRAWAL_BATCH_GAS: u64 = 20_000_000;

/// Default maximum number of ordered withdrawal transactions kept in flight.
pub const DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES: usize = 8;

/// Generous safety bound for withdrawal payloads retained in memory.
///
/// Far-tail payloads beyond this limit remain reconstructible from canonical Zone history when
/// they approach the portal head.
const MAX_CACHED_WITHDRAWAL_SLOTS: usize = 10_000;

/// Shared handle to the withdrawal store.
#[derive(Clone)]
pub struct SharedWithdrawalStore(Arc<Mutex<WithdrawalStore>>);

impl SharedWithdrawalStore {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(WithdrawalStore::new())))
    }

    pub fn lock(&self) -> parking_lot::MutexGuard<'_, WithdrawalStore> {
        self.0.lock()
    }
}

impl Default for SharedWithdrawalStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for the withdrawal processor.
#[derive(Debug, Clone)]
pub struct WithdrawalProcessorConfig {
    /// ZonePortal contract address on Tempo L1.
    pub portal_address: Address,
    /// Fallback timeout for checking the withdrawal queue if no notification arrives.
    pub fallback_poll_interval: Duration,
    /// Address whose lane-2 nonces order withdrawal processing transactions.
    pub sequencer_address: Address,
    /// Gas and concurrency limits for withdrawal transactions.
    pub batch_limits: WithdrawalBatchLimits,
}

/// Limits applied while packing and submitting `processWithdrawals` transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithdrawalBatchLimits {
    /// Maximum planned gas for one transaction. A single oversized withdrawal is still emitted
    /// so that it cannot permanently block the queue.
    pub max_batch_gas: u64,
    /// Maximum number of transactions to keep concurrently in flight.
    pub max_in_flight_batches: usize,
}

impl WithdrawalBatchLimits {
    fn assert_valid(self) {
        assert!(self.max_batch_gas > 0, "max_batch_gas must be non-zero");
        assert!(
            self.max_batch_gas <= MAX_WITHDRAWAL_BATCH_GAS,
            "max_batch_gas must not exceed {MAX_WITHDRAWAL_BATCH_GAS}"
        );
        assert!(
            self.max_in_flight_batches > 0,
            "max_in_flight_batches must be non-zero"
        );
    }
}

impl Default for WithdrawalBatchLimits {
    fn default() -> Self {
        Self {
            max_batch_gas: DEFAULT_MAX_WITHDRAWAL_BATCH_GAS,
            max_in_flight_batches: DEFAULT_MAX_IN_FLIGHT_WITHDRAWAL_BATCHES,
        }
    }
}

/// In-memory store for withdrawal data grouped by batch index.
///
/// The L1 portal queue only stores hash chains. The sequencer must keep the actual
/// [`abi::Withdrawal`] structs so it can provide them when calling `processWithdrawals`.
///
/// Withdrawals are grouped by batch index, where each batch is a `Vec<Withdrawal>` in FIFO order
/// (oldest first). The batch index corresponds to the portal's withdrawal queue slot index.
pub struct WithdrawalStore {
    batches: BTreeMap<u64, Vec<abi::Withdrawal>>,
}

impl WithdrawalStore {
    pub fn new() -> Self {
        Self {
            batches: BTreeMap::new(),
        }
    }

    /// Add a withdrawal to the given batch.
    ///
    /// Withdrawals within a batch are stored in FIFO order (oldest first).
    pub fn add_withdrawal(&mut self, batch_index: u64, withdrawal: abi::Withdrawal) -> bool {
        if self.batches.len() >= MAX_CACHED_WITHDRAWAL_SLOTS
            && !self.batches.contains_key(&batch_index)
        {
            return false;
        }

        self.batches
            .entry(batch_index)
            .or_default()
            .push(withdrawal);
        true
    }

    /// Set all withdrawals for a batch at once, replacing any existing data.
    pub fn add_batch(&mut self, batch_index: u64, withdrawals: Vec<abi::Withdrawal>) -> bool {
        if self.batches.len() >= MAX_CACHED_WITHDRAWAL_SLOTS
            && !self.batches.contains_key(&batch_index)
        {
            return false;
        }

        self.batches.insert(batch_index, withdrawals);
        true
    }

    /// Reconcile a verified head page while preserving useful cached tail payloads.
    ///
    /// Entries outside the observed portal bounds are stale. If the merged cache exceeds its
    /// generous safety bound, farthest-tail entries are evicted first because head-adjacent data
    /// is immediately useful to the processor and omitted tails can be reconstructed later.
    pub(crate) fn replace_page(&mut self, page: WithdrawalPage) -> usize {
        self.remove_before(page.head);
        drop(self.batches.split_off(&page.tail));
        for (index, withdrawals) in page.batches {
            self.batches.insert(index, withdrawals);
        }

        let mut evicted = 0;
        while self.batches.len() > MAX_CACHED_WITHDRAWAL_SLOTS {
            self.batches.pop_last();
            evicted += 1;
        }
        evicted
    }

    /// Get all withdrawals for a batch.
    pub fn get_batch(&self, batch_index: u64) -> Option<&Vec<abi::Withdrawal>> {
        self.batches.get(&batch_index)
    }

    /// Remove a batch after all its withdrawals are processed.
    pub fn remove_batch(&mut self, batch_index: u64) {
        self.batches.remove(&batch_index);
    }

    /// Remove slots that the portal head has already passed.
    fn remove_before(&mut self, batch_index: u64) {
        self.batches = self.batches.split_off(&batch_index);
    }

    pub fn has_batch(&self, batch_index: u64) -> bool {
        self.batches.contains_key(&batch_index)
    }

    pub fn batch_count(&self) -> usize {
        self.batches.len()
    }

    /// Return the smallest and largest portal slot indices currently present.
    fn slot_range(&self) -> Option<(u64, u64)> {
        let first = *self.batches.keys().next()?;
        let last = *self.batches.keys().next_back()?;
        Some((first, last))
    }

    /// Return a compact summary of the store as `(batch_count, first_slot, last_slot)`.
    pub(crate) fn summary(&self) -> (usize, Option<u64>, Option<u64>) {
        let (first_slot, last_slot) = self
            .slot_range()
            .map_or((None, None), |(first, last)| (Some(first), Some(last)));
        (self.batch_count(), first_slot, last_slot)
    }

    /// Return the nearest populated slots before and after `slot`, if any exist.
    fn neighboring_slots(&self, slot: u64) -> (Option<u64>, Option<u64>) {
        let prev = self.batches.range(..slot).next_back().map(|(&idx, _)| idx);
        let next = self
            .batches
            .range(slot.saturating_add(1)..)
            .next()
            .map(|(&idx, _)| idx);
        (prev, next)
    }
}

impl Default for WithdrawalStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
//  Withdrawal processor
// ---------------------------------------------------------------------------

struct StoreSnapshot {
    batch_count: usize,
    first_slot: Option<u64>,
    last_slot: Option<u64>,
    prev_slot: Option<u64>,
    next_slot: Option<u64>,
    withdrawals: Option<Vec<abi::Withdrawal>>,
}

/// Background task that processes withdrawals from the ZonePortal queue on Tempo L1.
///
/// The processor waits for a [`Notify`] signal from the batch submitter (indicating a batch
/// has landed on L1) and then drains the portal's withdrawal queue, slot by slot.
/// A fallback timeout ensures the processor still checks periodically if a notification
/// is missed.
///
/// The processor is idempotent: before submitting a slot it reads the slot's
/// current on-chain hash and trims withdrawals the portal has already consumed,
/// so it can safely run at any time from any state (crash, timeout, restart).
///
/// Withdrawals are first split by the configured per-transaction gas limit, then submitted through
/// a bounded queue of consecutive-nonce transactions. On any failure, the next cycle reconciles
/// the portal queue and retries its unfinished suffix.
pub struct WithdrawalProcessor {
    config: WithdrawalProcessorConfig,
    provider: DynProvider<TempoNetwork>,
    portal: ZonePortal::ZonePortalInstance<DynProvider<TempoNetwork>, TempoNetwork>,
    store: SharedWithdrawalStore,
    notify: Arc<Notify>,
    repair_notify: Arc<Notify>,
    metrics: WithdrawalProcessorMetrics,
    sequencer_metrics: SequencerMetrics,
}

impl WithdrawalProcessor {
    /// Create a new withdrawal processor from a shared L1 provider.
    ///
    /// The provider must already include the sequencer wallet for signing.
    pub fn new(
        config: WithdrawalProcessorConfig,
        provider: DynProvider<TempoNetwork>,
        store: SharedWithdrawalStore,
        notify: Arc<Notify>,
        repair_notify: Arc<Notify>,
    ) -> Self {
        config.batch_limits.assert_valid();
        let portal = ZonePortal::new(config.portal_address, provider.clone());

        Self {
            config,
            provider,
            portal,
            store,
            notify,
            repair_notify,
            metrics: WithdrawalProcessorMetrics::default(),
            sequencer_metrics: SequencerMetrics::default(),
        }
    }

    /// Read the current store contents relevant to `slot` under a single lock.
    ///
    /// This keeps the diagnostic fields used in missing-slot logs consistent
    /// with each other and with the batch lookup result.
    fn capture_store_snapshot(&self, slot: u64) -> StoreSnapshot {
        let store = self.store.lock();
        let (batch_count, first_slot, last_slot) = store.summary();
        let (prev_slot, next_slot) = store.neighboring_slots(slot);

        StoreSnapshot {
            batch_count,
            first_slot,
            last_slot,
            prev_slot,
            next_slot,
            withdrawals: store.get_batch(slot).cloned(),
        }
    }

    /// Run the processor loop. This method never returns under normal operation.
    ///
    /// Waits for a notification from the batch submitter (or a fallback timeout) before
    /// checking the L1 withdrawal queue. Returns only when `shutdown` fires; the
    /// token is observed at the wait boundary so an in-flight processing cycle completes
    /// first.
    #[instrument(skip_all, fields(portal = %self.config.portal_address))]
    pub async fn run(&self, shutdown: &sync::CancellationToken) {
        info!("Withdrawal processor started");

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    debug!("Withdrawal processor observed shutdown at the poll boundary");
                    return;
                }
                _ = self.notify.notified() => {
                    debug!("Woken by batch submission notification");
                }
                _ = tokio::time::sleep(self.config.fallback_poll_interval) => {
                    debug!("Fallback poll interval elapsed");
                }
            }

            if let Err(e) = self.process_queue(shutdown).await {
                error!(error = %e, "Withdrawal processing cycle failed");
            }

            if shutdown.is_cancelled() {
                debug!("Withdrawal processor stopped after draining submitted transactions");
                return;
            }

            if let Err(error) = self.update_sequencer_metrics().await {
                warn!(
                    %error,
                    sequencer = %self.config.sequencer_address,
                    "Failed to refresh sequencer PathUSD balance metric"
                );
            }
        }
    }

    /// Update sequencer metrics from Tempo L1 state.
    async fn update_sequencer_metrics(&self) -> eyre::Result<()> {
        let balance = ITIP20::new(PATH_USD_ADDRESS, &self.provider)
            .balanceOf(self.config.sequencer_address)
            .call()
            .await?;
        self.sequencer_metrics
            .pathusd_balance
            .set(f64::from(balance));
        Ok(())
    }

    /// Drain the portal's withdrawal queue on Tempo L1, slot by slot, until the
    /// queue is empty or a withdrawal cannot be processed.
    ///
    /// For each head slot the processor reads the slot's current on-chain hash
    /// and trims withdrawals the portal has already consumed
    /// ([`find_processed_offset`]), so a crash, timeout, or restart mid-slot
    /// resumes exactly where the portal is.
    #[instrument(skip_all)]
    async fn process_queue(&self, shutdown: &sync::CancellationToken) -> eyre::Result<()> {
        if shutdown.is_cancelled() {
            return Ok(());
        }

        if self.portal.paused().call().await? {
            debug!("Portal is paused; withdrawal processor is idle");
            return Ok(());
        }
        // loop through all the slots
        loop {
            if shutdown.is_cancelled() {
                return Ok(());
            }

            let (head, tail): (U256, U256) = self
                .provider
                .multicall()
                .add(self.portal.withdrawalQueueHead())
                .add(self.portal.withdrawalQueueTail())
                .aggregate()
                .await?;

            let head_val: u64 = head.try_into().map_err(|_| eyre::eyre!("head overflow"))?;
            let tail_val: u64 = tail.try_into().map_err(|_| eyre::eyre!("tail overflow"))?;
            if head_val > tail_val {
                warn!(
                    head = head_val,
                    tail = tail_val,
                    "Inconsistent withdrawal queue bounds"
                );
                return Ok(());
            }
            self.store.lock().remove_before(head_val);
            let StoreSnapshot {
                batch_count: store_batch_count,
                first_slot: store_first_slot,
                last_slot: store_last_slot,
                prev_slot: prev_store_slot,
                next_slot: next_store_slot,
                withdrawals,
            } = self.capture_store_snapshot(head_val);
            self.record_queue_metrics(head_val, tail_val, store_batch_count);

            if head_val == tail_val {
                debug!("Withdrawal queue empty, nothing to process");
                return Ok(());
            }

            let pending_slots = tail_val - head_val;
            info!(
                head = head_val,
                tail = tail_val,
                pending_slots,
                "Withdrawal queue has pending slots"
            );

            let withdrawals = match withdrawals {
                Some(w) if !w.is_empty() => w,
                _ => {
                    self.repair_notify.notify_one();
                    warn!(
                        slot = head_val,
                        tail = tail_val,
                        pending_slots,
                        store_batches = store_batch_count,
                        store_first_slot,
                        store_last_slot,
                        prev_store_slot,
                        next_store_slot,
                        "No withdrawal data in store for current head slot"
                    );
                    return Ok(());
                }
            };

            // Read the committed nonce before the slot. If an older pending transaction lands
            // between these reads, reusing its now-stale nonce fails safely instead of pairing a
            // stale slot snapshot with a newer nonce.
            let first_nonce = self
                .provider
                .get_transaction_count_with_nonce_key(
                    self.config.sequencer_address,
                    PROCESS_WITHDRAWAL_NONCE_KEY,
                )
                .await?;

            // Read the head slot's current on-chain hash and skip withdrawals the portal has
            // already consumed.
            let slot_hash = self
                .portal
                .withdrawalQueueSlot(U256::from(head_val))
                .call()
                .await?;

            if slot_hash.is_zero() {
                // Exhausting a slot clears it before advancing the head. The head advanced between
                // our bounds read and this slot read, so re-check on the next cycle.
                debug!(
                    slot = head_val,
                    "Head slot already consumed; skipping cycle"
                );
                return Ok(());
            }

            let Some(offset) = find_processed_offset(&withdrawals, slot_hash) else {
                error!(
                    slot = head_val,
                    on_chain_slot_hash = %slot_hash,
                    store_queue_hash = %abi::Withdrawal::queue_hash(&withdrawals),
                    "Store data does not match the head slot's on-chain hash; requesting repair"
                );
                self.repair_notify.notify_one();
                return Ok(());
            };

            if offset > 0 {
                info!(
                    slot = head_val,
                    processed = offset,
                    remaining = withdrawals.len() - offset,
                    "Trimmed withdrawals already consumed by the portal"
                );
            }

            let remaining = &withdrawals[offset..];
            if remaining.is_empty() {
                // Defensive: queue_hash never produces B256::ZERO for a pending head
                // slot, but if it happens drop the stale batch and wait for the portal.
                warn!(
                    slot = head_val,
                    "Head slot fully processed but head not advanced"
                );
                self.store.lock().remove_batch(head_val);
                return Ok(());
            }

            let (deposit_count, last_processed_deposit_number): (u64, u64) = self
                .provider
                .multicall()
                .add(self.portal.depositCount())
                .add(self.portal.lastProcessedDepositNumber())
                .aggregate()
                .await?;
            let headroom =
                withdrawal_deposit_headroom(deposit_count, last_processed_deposit_number)?;
            if headroom == 0 {
                debug!(
                    deposit_count,
                    last_processed_deposit_number,
                    "Portal deposit backlog leaves no withdrawal bounce-back headroom"
                );
                return Ok(());
            }
            // Public deposits cannot consume the reserved suffix. Restricting each submission to
            // that reserve prevents a public deposit landing after this read from racing the
            // portal's withdrawal-capacity preflight.
            let admitted = remaining
                .len()
                .min(headroom)
                .min(WITHDRAWAL_BOUNCEBACK_RESERVE);
            let fully_admitted = admitted == remaining.len();
            let batches = build_withdrawal_batches(
                &remaining[..admitted],
                self.config.batch_limits.max_batch_gas,
            );
            let total_gas = batches
                .iter()
                .fold(0u64, |total, batch| total.saturating_add(batch.gas_limit));
            info!(
                slot = head_val,
                withdrawals = remaining.len(),
                admitted,
                deposit_headroom = headroom,
                transactions = batches.len(),
                total_gas,
                "Processing withdrawal batches"
            );
            let slot_started_at = Instant::now();
            if shutdown.is_cancelled() {
                return Ok(());
            }
            let outcome = self
                .submit_and_confirm_batches(
                    SubmitBatches {
                        slot: head_val,
                        offset,
                        first_nonce,
                        withdrawals: remaining,
                        batches,
                    },
                    shutdown,
                    || {},
                )
                .await?;
            self.record_slot_duration(slot_started_at.elapsed());

            match outcome {
                SubmitOutcome::Confirmed => {
                    if fully_admitted {
                        self.store.lock().remove_batch(head_val);
                        info!(
                            slot = head_val,
                            count = remaining.len(),
                            "Slot fully processed and removed from store"
                        );
                    } else {
                        info!(
                            slot = head_val,
                            processed = admitted,
                            remaining = remaining.len() - admitted,
                            "Processed portal-capacity-limited withdrawal prefix"
                        );
                    }
                }
                SubmitOutcome::Retry => {
                    // A lower nonce may have succeeded, changing every later batch's expected
                    // queue suffix. The next poll reconciles the slot before retrying.
                    return Ok(());
                }
                SubmitOutcome::Cancelled => return Ok(()),
            }
        }
    }

    /// Run all batches through a bounded queue of consecutive-nonce transactions.
    ///
    /// A failure stops new submissions. Already submitted transactions are still drained because
    /// dropping their receipt futures would not cancel them. The next cycle then reconciles the
    /// on-chain queue and retries only the unfinished suffix.
    async fn submit_and_confirm_batches(
        &self,
        submission: SubmitBatches<'_>,
        shutdown: &sync::CancellationToken,
        mut on_batch_drained: impl FnMut(),
    ) -> eyre::Result<SubmitOutcome> {
        let SubmitBatches {
            slot,
            offset,
            first_nonce,
            withdrawals,
            batches,
        } = submission;
        let nonce_count = u64::try_from(batches.len())
            .map_err(|_| eyre::eyre!("processWithdrawals batch count overflow"))?;
        first_nonce.checked_add(nonce_count).ok_or_else(|| {
            eyre::eyre!("processWithdrawals nonce range exhausted at {first_nonce}")
        })?;

        let limits = self.config.batch_limits;
        let batch_count = batches.len();
        let mut batches = batches.into_iter();
        let mut in_flight = FuturesUnordered::new();
        let mut submitted = 0usize;
        let mut retry = false;
        let fees = bound_l1_fees(self.provider.estimate_eip1559_fees().await?);

        loop {
            while !retry
                && !shutdown.is_cancelled()
                && in_flight.len() < limits.max_in_flight_batches
            {
                let Some(batch) = batches.next() else {
                    break;
                };

                let nonce = first_nonce + submitted as u64;
                let absolute_start = offset + batch.start;
                let batch_withdrawals = withdrawals[batch.start..batch.end].to_vec();
                let remaining_queue = abi::Withdrawal::queue_hash(&withdrawals[batch.end..]);

                for (item_index, withdrawal) in batch_withdrawals.iter().enumerate() {
                    if withdrawal.gasLimit > MAX_WITHDRAWAL_GAS_LIMIT {
                        warn!(
                            slot,
                            index = absolute_start + item_index,
                            requested_gas_limit = withdrawal.gasLimit,
                            max_gas_limit = MAX_WITHDRAWAL_GAS_LIMIT,
                            "withdrawal callback gas exceeds protocol cap; reserving bounded gas"
                        );
                    }
                }

                info!(
                    slot,
                    nonce,
                    start_index = absolute_start,
                    withdrawal_count = batch.len(),
                    total = withdrawals.len(),
                    gas_limit = batch.gas_limit,
                    expected_remaining_queue = %remaining_queue,
                    "📤 Broadcasting withdrawal batch to L1"
                );

                let call = self
                    .portal
                    .processWithdrawals(batch_withdrawals, remaining_queue)
                    .from(self.config.sequencer_address)
                    .nonce_key(PROCESS_WITHDRAWAL_NONCE_KEY)
                    .nonce(nonce)
                    .max_fee_per_gas(fees.max_fee_per_gas)
                    .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
                    .gas(batch.gas_limit);

                in_flight.push(async move {
                    let receipt =
                        tokio::time::timeout(PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT, call.send_sync())
                            .await
                            .map_err(|_| {
                                eyre::eyre!(
                                    "processWithdrawals sync submission timed out after {} seconds",
                                    PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT.as_secs()
                                )
                            })
                            .and_then(|result| result.map_err(Into::into));
                    (batch, nonce, remaining_queue, receipt)
                });
                submitted += 1;
            }

            let Some((batch, nonce, remaining_queue, receipt)) = in_flight.next().await else {
                break;
            };

            match receipt {
                Ok(receipt) => {
                    let tx_hash = receipt.transaction_hash();
                    self.metrics
                        .withdrawals_processed_total
                        .increment(batch.len() as u64);
                    self.metrics
                        .withdrawals_per_batch
                        .record(batch.len() as f64);
                    if receipt.status() {
                        self.metrics
                            .withdrawals_confirmed_total
                            .increment(batch.len() as u64);
                        self.metrics.batches_confirmed_total.increment(1);
                        info!(
                            slot,
                            nonce,
                            %tx_hash,
                            start_index = offset + batch.start,
                            withdrawal_count = batch.len(),
                            gas_used = receipt.gas_used,
                            "✅ Withdrawal batch confirmed on L1"
                        );
                    } else {
                        self.metrics
                            .withdrawals_failed_total
                            .increment(batch.len() as u64);
                        self.metrics
                            .withdrawals_reverted_total
                            .increment(batch.len() as u64);
                        error!(
                            slot,
                            nonce,
                            %tx_hash,
                            start_index = offset + batch.start,
                            withdrawal_count = batch.len(),
                            expected_remaining_queue = %remaining_queue,
                            "processWithdrawals tx reverted; queue will be reconciled and retried"
                        );
                        retry = true;
                    }
                }
                Err(e) => {
                    self.metrics
                        .withdrawals_failed_total
                        .increment(batch.len() as u64);
                    error!(
                        slot,
                        nonce,
                        start_index = offset + batch.start,
                        withdrawal_count = batch.len(),
                        expected_remaining_queue = %remaining_queue,
                        error = %e,
                        "processWithdrawals tx not confirmed; queue will be reconciled and retried"
                    );
                    retry = true;
                }
            }
            on_batch_drained();
        }

        if retry {
            warn!(
                slot,
                submitted,
                total_batches = batch_count,
                "Withdrawal processing incomplete; retrying from reconciled on-chain state"
            );
            Ok(SubmitOutcome::Retry)
        } else if submitted < batch_count {
            debug!(
                slot,
                submitted,
                total_batches = batch_count,
                "Withdrawal processing stopped admitting batches after cancellation"
            );
            Ok(SubmitOutcome::Cancelled)
        } else {
            debug_assert_eq!(submitted, batch_count);
            Ok(SubmitOutcome::Confirmed)
        }
    }

    fn record_queue_metrics(&self, head: u64, tail: u64, store_batch_count: usize) {
        self.metrics.portal_queue_head.set(head as f64);
        self.metrics.portal_queue_tail.set(tail as f64);
        self.metrics
            .portal_queue_pending_slots
            .set((tail.saturating_sub(head)) as f64);
        self.metrics.store_batch_count.set(store_batch_count as f64);
    }

    fn record_slot_duration(&self, duration: Duration) {
        self.metrics
            .slot_processing_duration_seconds
            .record(duration.as_secs_f64());
    }
}

/// Return the number of withdrawals that can each append one deposit without exceeding the
/// portal's unprocessed-deposit cap. This mirrors the `processWithdrawals` preflight using a live
/// portal snapshot; the portal revalidates the bound when the transaction executes.
fn withdrawal_deposit_headroom(
    deposit_count: u64,
    last_processed_deposit_number: u64,
) -> eyre::Result<usize> {
    let outstanding = deposit_count.checked_sub(last_processed_deposit_number).ok_or_else(|| {
        eyre::eyre!(
            "portal lastProcessedDepositNumber {last_processed_deposit_number} exceeds depositCount {deposit_count}"
        )
    })?;
    let maximum =
        u64::try_from(MAX_UNPROCESSED_DEPOSITS).expect("MAX_UNPROCESSED_DEPOSITS fits in u64");
    Ok(usize::try_from(maximum.saturating_sub(outstanding))
        .expect("withdrawal headroom fits in usize"))
}

struct SubmitBatches<'a> {
    slot: u64,
    offset: usize,
    first_nonce: u64,
    withdrawals: &'a [abi::Withdrawal],
    batches: Vec<WithdrawalBatch>,
}

/// Spawn the withdrawal processor as a background task.
///
/// The processor waits for notifications from the batch submitter (via `notify`) and then
/// processes withdrawals from the ZonePortal queue on Tempo L1.
///
/// The `provider` must already include the sequencer wallet for signing L1 transactions.
pub fn spawn_withdrawal_processor(
    config: WithdrawalProcessorConfig,
    provider: DynProvider<TempoNetwork>,
    store: SharedWithdrawalStore,
    notify: Arc<Notify>,
    repair_notify: Arc<Notify>,
    shutdown: sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let processor = WithdrawalProcessor::new(config, provider, store, notify, repair_notify);
        processor.run(&shutdown).await;
        info!("Withdrawal processor stopped");
    })
}

/// Return the gas reserved for one withdrawal inside a `processWithdrawals` transaction.
///
/// Deposit bouncebacks and simple withdrawals use separate fixed allowances. Callback withdrawals
/// add their requested callback gas directly. The callback portion is capped at
/// [`MAX_WITHDRAWAL_GAS_LIMIT`], keeping legacy over-cap withdrawals submit-able while bounding
/// the batcher's gas accounting.
const fn process_withdrawal_item_gas(callback_gas_limit: u64, fallback_nonce: u64) -> u64 {
    if fallback_nonce == 0 {
        return PROCESS_DEPOSIT_BOUNCEBACK_ITEM_OVERHEAD_GAS;
    }

    if callback_gas_limit == 0 {
        return PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS;
    }

    let bounded_callback_gas = if callback_gas_limit > MAX_WITHDRAWAL_GAS_LIMIT {
        MAX_WITHDRAWAL_GAS_LIMIT
    } else {
        callback_gas_limit
    };

    PROCESS_CALLBACK_WITHDRAWAL_ITEM_OVERHEAD_GAS + bounded_callback_gas
}

/// A contiguous, gas-bounded transaction within one withdrawal queue slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WithdrawalBatch {
    start: usize,
    end: usize,
    gas_limit: u64,
}

impl WithdrawalBatch {
    fn len(self) -> usize {
        self.end - self.start
    }
}

/// Split FIFO withdrawals by the configured per-transaction gas limit.
///
/// A withdrawal that exceeds the limit is kept as a singleton so it cannot block the queue.
fn build_withdrawal_batches(
    withdrawals: &[abi::Withdrawal],
    max_batch_gas: u64,
) -> Vec<WithdrawalBatch> {
    let mut batches = Vec::new();
    let mut start = 0;

    while start < withdrawals.len() {
        let mut end = start;
        let mut gas_limit = PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS;

        while end < withdrawals.len() {
            let withdrawal = &withdrawals[end];
            let next_gas = gas_limit.saturating_add(process_withdrawal_item_gas(
                withdrawal.gasLimit,
                withdrawal.fallbackNonce,
            ));
            if end > start && next_gas > max_batch_gas {
                break;
            }

            gas_limit = next_gas;
            end += 1;
        }

        batches.push(WithdrawalBatch {
            start,
            end,
            gas_limit,
        });
        start = end;
    }

    batches
}

/// Outcome of submitting and confirming a sequence of `processWithdrawals` transactions.
enum SubmitOutcome {
    /// Every transaction was included on L1 and succeeded.
    Confirmed,
    /// At least one transaction failed to send, reverted, or could not be confirmed. The next
    /// cycle reconciles the on-chain queue and retries the unfinished suffix.
    Retry,
    /// Cancellation stopped admission of new transactions. Transactions submitted before
    /// cancellation were still drained, and the unfinished suffix remains for reconciliation.
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, Bytes, U256, address, keccak256};
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_types_eth::FeeHistory;
    use alloy_sol_types::SolValue;
    use alloy_transport::mock::Asserter;
    use tempo_alloy::TempoNetwork;
    use tokio::time::timeout;

    fn mock_provider(asserter: Asserter) -> DynProvider<TempoNetwork> {
        ProviderBuilder::<_, _, TempoNetwork>::default()
            .connect_mocked_client(asserter)
            .erased()
    }

    fn abi_encode_u64(value: u64) -> Bytes {
        value.abi_encode().into()
    }

    fn abi_encode_multicall(values: Vec<Bytes>) -> Bytes {
        (U256::ZERO, values).abi_encode_params().into()
    }

    fn successful_receipt(tx_byte: u8) -> serde_json::Value {
        serde_json::json!({
            "transactionHash": B256::repeat_byte(tx_byte),
            "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0xbb),
            "blockNumber": "0x1",
            "from": Address::repeat_byte(0x77),
            "to": address!("0x7069DeC4E64Fd07334A0933eDe836C17259c9B23"),
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x0",
            "contractAddress": null,
            "logs": [],
            "logsBloom": format!("{:#x}", alloy_primitives::Bloom::ZERO),
            "status": "0x1",
            "type": "0x0",
            "feePayer": Address::repeat_byte(0x77),
        })
    }

    fn fee_history() -> FeeHistory {
        FeeHistory {
            base_fee_per_gas: vec![1, 1],
            gas_used_ratio: vec![0.5],
            reward: Some(vec![vec![1]]),
            ..Default::default()
        }
    }

    fn test_withdrawal(to: Address, amount: u128) -> abi::Withdrawal {
        abi::Withdrawal {
            token: address!("0x0000000000000000000000000000000000001000"),
            senderTag: B256::repeat_byte(0x11),
            to,
            amount,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: Default::default(),
            encryptedSender: Default::default(),
        }
    }

    #[test]
    fn empty_queue_hash_is_zero() {
        assert_eq!(abi::Withdrawal::queue_hash(&[]), B256::ZERO);
    }

    #[test]
    fn bounds_l1_fee_estimate() {
        let fees = bound_l1_fees(Eip1559Estimation {
            max_fee_per_gas: u128::MAX,
            max_priority_fee_per_gas: u128::MAX,
        });

        assert_eq!(fees.max_fee_per_gas, crate::TEMPO_L1_MAX_FEE_PER_GAS);
        assert_eq!(
            fees.max_priority_fee_per_gas,
            crate::TEMPO_L1_MAX_FEE_PER_GAS
        );
    }

    #[test]
    fn single_withdrawal_queue_hash() {
        let w = test_withdrawal(Address::with_last_byte(0x42), 1000);
        let hash = abi::Withdrawal::queue_hash(std::slice::from_ref(&w));

        let expected = keccak256((w, B256::ZERO).abi_encode_params());
        assert_eq!(hash, expected);
    }

    #[test]
    fn two_withdrawal_queue_hash() {
        let w0 = test_withdrawal(Address::with_last_byte(0x42), 100);
        let w1 = test_withdrawal(Address::with_last_byte(0x43), 200);

        let hash = abi::Withdrawal::queue_hash(&[w0.clone(), w1.clone()]);

        let inner = keccak256((w1, B256::ZERO).abi_encode_params());
        let expected = keccak256((w0, inner).abi_encode_params());
        assert_eq!(hash, expected);
    }

    #[test]
    fn withdrawal_hash_requires_param_encoding() {
        let w = abi::Withdrawal {
            token: address!("0x20c0000000000000000000000000000000000000"),
            senderTag: B256::repeat_byte(0x22),
            to: address!("0x70997970c51812dc3a010c7d01b50e0d17dc79c8"),
            amount: 500_000,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: Default::default(),
            encryptedSender: Default::default(),
        };

        let tuple_value_hash = keccak256((w.clone(), B256::ZERO).abi_encode());
        let param_hash = keccak256((w, B256::ZERO).abi_encode_params());

        assert_ne!(
            tuple_value_hash, param_hash,
            "tuple-value encoding must differ from Solidity abi.encode(args...) here"
        );
    }

    #[test]
    fn withdrawal_gas_limits_are_classified_and_bounded() {
        let at_cap = PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS
            + process_withdrawal_item_gas(MAX_WITHDRAWAL_GAS_LIMIT, 1);
        let over_cap = PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS
            + process_withdrawal_item_gas(MAX_WITHDRAWAL_GAS_LIMIT + 1, 1);

        assert_eq!(over_cap, at_cap);
        assert_eq!(
            process_withdrawal_item_gas(0, 1),
            PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS
        );
        assert_eq!(
            process_withdrawal_item_gas(0, 0),
            PROCESS_DEPOSIT_BOUNCEBACK_ITEM_OVERHEAD_GAS
        );
        assert_eq!(
            process_withdrawal_item_gas(3_000_000, 1),
            PROCESS_CALLBACK_WITHDRAWAL_ITEM_OVERHEAD_GAS + 3_000_000
        );
        assert_eq!(
            at_cap,
            PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS
                + PROCESS_CALLBACK_WITHDRAWAL_ITEM_OVERHEAD_GAS
                + MAX_WITHDRAWAL_GAS_LIMIT
        );
        assert!(at_cap <= MAX_WITHDRAWAL_BATCH_GAS);
    }

    fn simple_withdrawals(count: usize) -> Vec<abi::Withdrawal> {
        (0..count)
            .map(|i| test_withdrawal(Address::with_last_byte((i + 1) as u8), (i + 1) as u128))
            .collect()
    }

    #[test]
    fn batches_withdrawals_by_transaction_gas() {
        let withdrawals = simple_withdrawals(3);
        let one = PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS;
        let batches =
            build_withdrawal_batches(&withdrawals, PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS + 2 * one);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].start, 0);
        assert_eq!(batches[0].end, 2);
        assert_eq!(batches[1].start, 2);
        assert_eq!(batches[1].end, 3);
    }

    #[test]
    fn maximum_batch_fits_portal_bounceback_reserve() {
        let withdrawals = simple_withdrawals(WITHDRAWAL_BOUNCEBACK_RESERVE);
        let batches = build_withdrawal_batches(&withdrawals, MAX_WITHDRAWAL_BATCH_GAS);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 19);
        assert_eq!(batches[1].len(), 1);
        assert!(
            batches
                .iter()
                .all(|batch| batch.len() <= WITHDRAWAL_BOUNCEBACK_RESERVE)
        );
    }

    #[test]
    fn withdrawal_admission_respects_global_deposit_headroom() {
        assert_eq!(withdrawal_deposit_headroom(0, 0).unwrap(), 230);
        assert_eq!(withdrawal_deposit_headroom(229, 0).unwrap(), 1);
        assert_eq!(withdrawal_deposit_headroom(230, 0).unwrap(), 0);
        assert_eq!(withdrawal_deposit_headroom(300, 100).unwrap(), 30);
        assert!(withdrawal_deposit_headroom(9, 10).is_err());
    }

    #[test]
    fn oversized_withdrawal_is_a_singleton() {
        let mut withdrawals = simple_withdrawals(2);
        withdrawals[0].gasLimit = MAX_WITHDRAWAL_GAS_LIMIT;
        let batches = build_withdrawal_batches(&withdrawals, 1_000_000);

        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].start, 0);
        assert_eq!(batches[0].end, 1);
        assert!(batches[0].gas_limit > 1_000_000);
    }

    #[test]
    fn store_operations() {
        let mut store = WithdrawalStore::new();
        let w = test_withdrawal(Address::with_last_byte(0x42), 100);

        assert_eq!(store.batch_count(), 0);
        assert!(!store.has_batch(0));

        store.add_withdrawal(0, w.clone());
        assert!(store.has_batch(0));
        assert_eq!(store.batch_count(), 1);
        assert_eq!(store.get_batch(0).unwrap().len(), 1);

        store.add_withdrawal(0, w);
        assert_eq!(store.get_batch(0).unwrap().len(), 2);

        store.remove_batch(0);
        assert!(!store.has_batch(0));
        assert_eq!(store.batch_count(), 0);
    }

    #[test]
    fn store_slot_index_must_match_portal_tail() {
        // Demonstrates that withdrawals must be stored under the portal's actual
        // queue tail index. If the monitor starts with tail=0 but the portal is
        // at tail=5, withdrawals end up in slot 0 while the withdrawal processor
        // looks for them in slot 5.
        let mut store = WithdrawalStore::new();
        let w = test_withdrawal(Address::with_last_byte(0x42), 100);

        // Simulate storing under the wrong slot (tail=0 when portal is at 5).
        store.add_withdrawal(0, w.clone());
        assert!(store.has_batch(0));
        assert!(
            !store.has_batch(5),
            "withdrawal processor would look at slot 5 and find nothing"
        );

        // Correct: store under the portal's actual tail.
        let portal_tail = 5u64;
        store.add_withdrawal(portal_tail, w);
        assert!(store.has_batch(portal_tail));
    }

    #[test]
    fn store_add_batch() {
        let mut store = WithdrawalStore::new();
        let addr = Address::with_last_byte(0x42);
        let batch: Vec<_> = (0..3).map(|i| test_withdrawal(addr, i * 100)).collect();

        store.add_batch(0, batch);
        assert!(store.has_batch(0));
        assert_eq!(store.get_batch(0).unwrap().len(), 3);

        // Calling add_batch again replaces existing data (idempotent).
        let more: Vec<_> = (0..2).map(|i| test_withdrawal(addr, i * 200)).collect();
        store.add_batch(0, more);
        assert_eq!(store.get_batch(0).unwrap().len(), 2);

        store.add_batch(1, vec![test_withdrawal(addr, 999)]);
        assert_eq!(store.batch_count(), 2);
    }

    #[test]
    fn store_prunes_slots_before_portal_head() {
        let mut store = WithdrawalStore::new();
        let withdrawal = test_withdrawal(Address::repeat_byte(0x42), 100);
        store.add_batch(4, vec![withdrawal.clone()]);
        store.add_batch(5, vec![withdrawal.clone()]);
        store.add_batch(6, vec![withdrawal]);

        store.remove_before(5);

        assert!(!store.has_batch(4));
        assert!(store.has_batch(5));
        assert!(store.has_batch(6));
    }

    #[test]
    fn store_reconciles_head_page_and_preserves_tail() {
        let mut store = WithdrawalStore::new();
        let addr = Address::with_last_byte(0x42);

        store.add_batch(0, vec![test_withdrawal(addr, 100)]);
        store.add_batch(9, vec![test_withdrawal(addr, 900)]);
        store.add_batch(12, vec![test_withdrawal(addr, 1_200)]);

        let mut batches = BTreeMap::new();
        batches.insert(5, vec![test_withdrawal(addr, 500)]);
        batches.insert(6, vec![test_withdrawal(addr, 600)]);
        let evicted = store.replace_page(WithdrawalPage {
            head: 5,
            tail: 10,
            batches,
        });

        assert_eq!(evicted, 0);
        assert!(!store.has_batch(0));
        assert!(store.has_batch(5));
        assert!(store.has_batch(6));
        assert!(store.has_batch(9));
        assert!(!store.has_batch(12));
        assert_eq!(store.batch_count(), 3);
    }

    #[test]
    fn store_reconciles_recovery_page_without_discarding_backlog_beyond_100_slots() {
        let mut store = WithdrawalStore::new();
        let withdrawal = test_withdrawal(Address::repeat_byte(0x42), 100);
        for index in 100..201 {
            assert!(store.add_batch(index, vec![withdrawal.clone()]));
        }

        let batches = (0..100)
            .map(|index| (index, vec![withdrawal.clone()]))
            .collect();
        let evicted = store.replace_page(WithdrawalPage {
            head: 0,
            tail: 201,
            batches,
        });

        assert_eq!(evicted, 0);
        assert_eq!(store.batch_count(), 201);
        assert!((0..201).all(|index| store.has_batch(index)));
    }

    #[test]
    fn store_cache_limit_prioritizes_recovered_head_page() {
        let mut store = WithdrawalStore::new();
        let withdrawal = test_withdrawal(Address::repeat_byte(0x42), 100);
        for index in 1..=MAX_CACHED_WITHDRAWAL_SLOTS as u64 {
            store.batches.insert(index, vec![withdrawal.clone()]);
        }
        assert!(!store.add_batch(
            MAX_CACHED_WITHDRAWAL_SLOTS as u64 + 1,
            vec![withdrawal.clone()]
        ));

        let mut batches = BTreeMap::new();
        batches.insert(0, vec![withdrawal]);
        let evicted = store.replace_page(WithdrawalPage {
            head: 0,
            tail: MAX_CACHED_WITHDRAWAL_SLOTS as u64 + 1,
            batches,
        });

        assert_eq!(evicted, 1);
        assert_eq!(store.batch_count(), MAX_CACHED_WITHDRAWAL_SLOTS);
        assert!(store.has_batch(0));
        assert!(!store.has_batch(MAX_CACHED_WITHDRAWAL_SLOTS as u64));
    }

    fn abi_encode_b256(value: B256) -> Bytes {
        value.into()
    }

    fn test_processor(
        l1: Asserter,
        store: SharedWithdrawalStore,
        repair_notify: Arc<Notify>,
    ) -> WithdrawalProcessor {
        let config = WithdrawalProcessorConfig {
            portal_address: address!("0x7069DeC4E64Fd07334A0933eDe836C17259c9B23"),
            fallback_poll_interval: Duration::from_secs(1),
            sequencer_address: Address::repeat_byte(0x77),
            batch_limits: WithdrawalBatchLimits::default(),
        };
        WithdrawalProcessor::new(
            config,
            mock_provider(l1),
            store,
            Arc::new(Notify::new()),
            repair_notify,
        )
    }

    #[tokio::test]
    async fn process_queue_requests_head_page_refill_when_slot_missing() {
        let l1 = Asserter::new();
        l1.push_success(&abi_encode_u64(0));
        l1.push_success(&abi_encode_multicall(vec![
            abi_encode_u64(51),
            abi_encode_u64(71),
        ]));

        let repair_notify = Arc::new(Notify::new());
        let processor = test_processor(
            l1.clone(),
            SharedWithdrawalStore::new(),
            repair_notify.clone(),
        );

        processor
            .process_queue(&sync::CancellationToken::new())
            .await
            .unwrap();

        timeout(Duration::from_millis(50), repair_notify.notified())
            .await
            .expect("missing head slot should request a page refill");
        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn cancelled_processor_does_not_start_a_queue_slot() {
        let l1 = Asserter::new();
        let processor = test_processor(
            l1.clone(),
            SharedWithdrawalStore::new(),
            Arc::new(Notify::new()),
        );
        let shutdown = sync::CancellationToken::new();
        shutdown.cancel();

        processor.process_queue(&shutdown).await.unwrap();

        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn cancellation_stops_refill_but_drains_submitted_batches() {
        let l1 = Asserter::new();
        l1.push_success(&fee_history());

        let mut processor = test_processor(
            l1.clone(),
            SharedWithdrawalStore::new(),
            Arc::new(Notify::new()),
        );
        processor.config.batch_limits = WithdrawalBatchLimits {
            max_batch_gas: PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS
                + PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS,
            max_in_flight_batches: 2,
        };
        l1.push_success(&successful_receipt(1));
        l1.push_success(&successful_receipt(2));
        l1.push_success(&successful_receipt(3));

        let withdrawals = simple_withdrawals(3);
        let batches =
            build_withdrawal_batches(&withdrawals, processor.config.batch_limits.max_batch_gas);
        assert_eq!(batches.len(), 3);

        let shutdown = sync::CancellationToken::new();
        let mut drained = 0;
        let outcome = processor
            .submit_and_confirm_batches(
                SubmitBatches {
                    slot: 7,
                    offset: 0,
                    first_nonce: 10,
                    withdrawals: &withdrawals,
                    batches,
                },
                &shutdown,
                || {
                    drained += 1;
                    if drained == 1 {
                        shutdown.cancel();
                    }
                },
            )
            .await
            .unwrap();

        assert!(
            matches!(outcome, SubmitOutcome::Cancelled),
            "expected cancellation after draining {drained} batches with {} mock responses left",
            l1.read_q().len()
        );
        assert_eq!(
            drained, 2,
            "both transactions admitted before cancellation must drain"
        );
        assert_eq!(
            l1.read_q().len(),
            1,
            "the third response must remain unused because cancellation prevented a refill"
        );
    }

    #[tokio::test]
    async fn process_queue_requests_refill_when_store_data_mismatches_slot_hash() {
        let l1 = Asserter::new();
        l1.push_success(&abi_encode_u64(0));
        // head = 5, tail = 6, slot hash that matches no suffix of the stored batch.
        l1.push_success(&abi_encode_multicall(vec![
            abi_encode_u64(5),
            abi_encode_u64(6),
        ]));
        l1.push_success(&abi_encode_u64(0));
        l1.push_success(&abi_encode_b256(B256::repeat_byte(0xde)));

        let store = SharedWithdrawalStore::new();
        store
            .lock()
            .add_batch(5, vec![test_withdrawal(Address::with_last_byte(0x42), 100)]);

        let repair_notify = Arc::new(Notify::new());
        let processor = test_processor(l1.clone(), store, repair_notify.clone());

        processor
            .process_queue(&sync::CancellationToken::new())
            .await
            .unwrap();

        timeout(Duration::from_millis(50), repair_notify.notified())
            .await
            .expect("mismatched slot hash should request a page refill");
        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn process_queue_skips_cycle_when_head_slot_already_consumed() {
        let l1 = Asserter::new();
        l1.push_success(&abi_encode_u64(0));
        // head = 5, tail = 6, but slot 5 is already cleared because head advanced
        // between our bounds read and the slot read.
        l1.push_success(&abi_encode_multicall(vec![
            abi_encode_u64(5),
            abi_encode_u64(6),
        ]));
        l1.push_success(&abi_encode_u64(0));
        l1.push_success(&abi_encode_b256(B256::ZERO));

        let store = SharedWithdrawalStore::new();
        store
            .lock()
            .add_batch(5, vec![test_withdrawal(Address::with_last_byte(0x42), 100)]);

        let repair_notify = Arc::new(Notify::new());
        let processor = test_processor(l1.clone(), store.clone(), repair_notify.clone());

        processor
            .process_queue(&sync::CancellationToken::new())
            .await
            .unwrap();

        // No repair requested and the batch stays in the store.
        assert!(
            timeout(Duration::from_millis(50), repair_notify.notified())
                .await
                .is_err()
        );
        assert!(store.lock().has_batch(5));
        assert!(l1.read_q().is_empty());
    }

    #[tokio::test]
    async fn process_queue_is_idle_while_portal_is_paused() {
        let l1 = Asserter::new();
        l1.push_success(&abi_encode_u64(1));
        let repair_notify = Arc::new(Notify::new());
        let processor = test_processor(
            l1.clone(),
            SharedWithdrawalStore::new(),
            repair_notify.clone(),
        );

        processor
            .process_queue(&sync::CancellationToken::new())
            .await
            .unwrap();

        assert!(l1.read_q().is_empty());
        assert!(
            timeout(Duration::from_millis(50), repair_notify.notified())
                .await
                .is_err()
        );
    }
}
