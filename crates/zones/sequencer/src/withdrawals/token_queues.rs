//! Sequencer drain of TIP-1150 token queues through `processQueuedWithdrawals`.
//!
//! `processWithdrawals` appends a plain withdrawal or deposit bounce-back to its token's queue
//! when the token's withdrawal limit lacks capacity or the token already has unpaid records. The
//! portal stores each record's payout data, so anyone can pay a token queue by naming the token.
//! This drain calls `processQueuedWithdrawals` for each token whose head record capacity now
//! covers, without waiting for someone else to do so. Every decision is made from the portal's
//! current state, so a restart loses nothing.

use std::{future::Future, sync::Arc, time::Duration};

use alloy_network::ReceiptResponse as _;
use alloy_primitives::{Address, U256};
use alloy_provider::{DynProvider, Provider};
use alloy_sol_types::SolEvent as _;
use eyre::WrapErr as _;
use tempo_alloy::{TempoNetwork, provider::ext::TempoProviderExt, rpc::TempoCallBuilderExt};
use tokio_util::sync;
use tracing::{debug, info, instrument, warn};
use zone_chainspec::ZoneChainSpec;

use super::{
    PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT, PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS, bound_l1_fees,
};
use crate::{
    abi::ZonePortal, metrics::QueuedWithdrawalDrainMetrics,
    nonce_keys::PROCESS_QUEUED_WITHDRAWALS_NONCE_KEY, prover_config::active_l1_hardfork,
};

/// Planner-only gas reserved per record a drain may complete, on top of
/// [`PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS`].
///
/// Foundry traces of the T15 portal, with cold accounts and no TIP-1060 storage credits, used at
/// most 1,108,920 gas for a drain of one record (a plain withdrawal bounced back to the zone whose
/// deposit-queue append creates the first deposit checkpoint, four slots), 1,667,482 for two (that
/// bounce-back, then a deposit bounce-back whose fee creates the admin's token balance and whose
/// refund creates its recipient's), and at most 284,162 for each later record paid to a recipient
/// whose token balance was zero. `test_gas_drainsFitQueuedEntryReservation` in
/// `crates/zones/contracts` checks drains against this allowance. Records are created in TIP-1060
/// `Refund` mode, so storage the drain creates is charged upfront whatever credits the portal
/// holds.
const QUEUED_ENTRY_GAS: u64 = 400_000;

/// Deadline for a poll's reads: the hardfork check, the pause flag, the enabled tokens and every
/// queue's bounds, limit and head record.
const QUEUE_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Deadline for one token's whole drain: its nonce and fee reads, the send and the confirmation,
/// which alone may take [`PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT`].
const DRAIN_TIMEOUT: Duration =
    Duration::from_secs(PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT.as_secs() + 15);

/// A token queue with unpaid records, as read at the start of a poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TokenQueue {
    token: Address,
    head: u64,
    tail: u64,
    max_amount: u128,
    available: u128,
    /// What the head record still waits for.
    head_remaining: u128,
}

/// Drains TIP-1150 token queues with sequencer credentials.
pub(super) struct QueuedWithdrawalDrainer {
    provider: DynProvider<TempoNetwork>,
    portal: ZonePortal::ZonePortalInstance<DynProvider<TempoNetwork>, TempoNetwork>,
    sequencer_address: Address,
    max_batch_gas: u64,
    chain_spec: Arc<ZoneChainSpec>,
    metrics: QueuedWithdrawalDrainMetrics,
}

impl QueuedWithdrawalDrainer {
    /// Creates a drainer that signs as `sequencer_address` through `provider`.
    pub(super) fn new(
        provider: DynProvider<TempoNetwork>,
        portal_address: Address,
        sequencer_address: Address,
        max_batch_gas: u64,
        chain_spec: Arc<ZoneChainSpec>,
    ) -> Self {
        Self {
            portal: ZonePortal::new(portal_address, provider.clone()),
            provider,
            sequencer_address,
            max_batch_gas,
            chain_spec,
            metrics: QueuedWithdrawalDrainMetrics::default(),
        }
    }

    /// Drains token queues until `shutdown` fires.
    ///
    /// Sleeps `poll_interval` between polls, except after a poll in which some token's drain
    /// completed a full batch: that token may still have records capacity covers, so the next
    /// poll starts at once. Runs beside the `processWithdrawals` loop, so a slow or failing drain
    /// never delays it. A poll's reads and each token's drain have their own deadlines, so one
    /// stuck call delays neither the other tokens nor later polls. A poll in progress is abandoned
    /// at shutdown; a transaction it already broadcast may still land, and the next poll reads the
    /// portal again.
    #[instrument(skip_all)]
    pub(super) async fn run(&self, poll_interval: Duration, shutdown: &sync::CancellationToken) {
        let mut rescan = false;
        loop {
            if !rescan {
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => return,
                    () = tokio::time::sleep(poll_interval) => {}
                }
            }
            rescan = tokio::select! {
                biased;
                () = shutdown.cancelled() => return,
                result = self.poll() => result.unwrap_or_else(|error| {
                    warn!(%error, "Token queue drain failed; retrying next poll");
                    false
                }),
            };
        }
    }

    /// Reads every enabled token's queue within [`QUEUE_READ_TIMEOUT`] and, unless the portal is
    /// paused, sends one `processQueuedWithdrawals` for each token [`should_drain`] selects, each
    /// within [`DRAIN_TIMEOUT`]. A failed or timed-out token does not stop the others.
    ///
    /// Returns whether some token's drain completed a full batch.
    async fn poll(&self) -> eyre::Result<bool> {
        let queues = tokio::time::timeout(QUEUE_READ_TIMEOUT, self.read_round())
            .await
            .map_err(|_| {
                eyre::eyre!(
                    "token queue reads timed out after {} seconds",
                    QUEUE_READ_TIMEOUT.as_secs()
                )
            })??;
        let selected: Vec<_> = queues.into_iter().filter(should_drain).collect();
        Ok(drain_each(&selected, &self.metrics, |queue| self.drain(queue)).await)
    }

    /// Reads the queues with unpaid records, or none before T15 or while the portal is paused.
    async fn read_round(&self) -> eyre::Result<Vec<TokenQueue>> {
        // TODO: remove after T15
        // Portals before T15 do not have token queues.
        if !active_l1_hardfork(&self.provider, self.chain_spec.as_ref())
            .await?
            .is_t15()
        {
            return Ok(Vec::new());
        }
        let (paused, tokens) = tokio::try_join!(
            async { eyre::Ok(self.portal.paused().call().await?) },
            async {
                self.portal
                    .enabled_tokens()
                    .await
                    .wrap_err("failed to read enabled tokens")
            },
        )?;
        let backlogs = self.read_backlogs(tokens).await?;
        let pending = backlogs.iter().fold(0u64, |total, (_, head, tail)| {
            total.saturating_add(tail - head)
        });
        self.metrics.pending_entries.set(pending as f64);
        if paused {
            debug!(pending, "Portal is paused; token queues are not drained");
            return Ok(Vec::new());
        }
        self.read_queues(backlogs).await
    }

    /// Reads the bounds of each token's queue and returns `(token, head, tail)` for those with
    /// unpaid records.
    async fn read_backlogs(&self, tokens: Vec<Address>) -> eyre::Result<Vec<(Address, u64, u64)>> {
        if tokens.is_empty() {
            return Ok(Vec::new());
        }
        let mut bounds = self
            .provider
            .multicall()
            .dynamic::<ZonePortal::queuedWithdrawalsCall>();
        for token in &tokens {
            bounds = bounds.add_dynamic(self.portal.queuedWithdrawals(*token));
        }
        let bounds = bounds
            .aggregate()
            .await
            .wrap_err("failed to read token queue bounds")?;
        Ok(tokens
            .into_iter()
            .zip(bounds)
            .filter(|(_, bounds)| bounds.head < bounds.tail)
            .map(|(token, bounds)| (token, bounds.head, bounds.tail))
            .collect())
    }

    /// Reads the limit and head record of each queue with unpaid records.
    async fn read_queues(
        &self,
        backlogs: Vec<(Address, u64, u64)>,
    ) -> eyre::Result<Vec<TokenQueue>> {
        if backlogs.is_empty() {
            return Ok(Vec::new());
        }
        let mut limits = self
            .provider
            .multicall()
            .dynamic::<ZonePortal::withdrawalLimitCall>();
        let mut heads = self
            .provider
            .multicall()
            .dynamic::<ZonePortal::queuedWithdrawalAtCall>();
        for &(token, head, _) in &backlogs {
            limits = limits.add_dynamic(self.portal.withdrawalLimit(token));
            heads = heads.add_dynamic(self.portal.queuedWithdrawalAt(token, U256::from(head)));
        }
        let (limits, heads) = tokio::try_join!(limits.aggregate(), heads.aggregate())
            .wrap_err("failed to read token queue heads")?;
        Ok(backlogs
            .into_iter()
            .zip(limits.into_iter().zip(heads))
            .map(|((token, head, tail), (limit, record))| TokenQueue {
                token,
                head,
                tail,
                max_amount: limit.maxAmount,
                available: limit.available,
                head_remaining: record.remaining,
            })
            .collect())
    }

    /// Sends one `processQueuedWithdrawals` for `queue` and waits for its receipt.
    ///
    /// Returns whether the receipt shows the call completed `maxEntries` records, the most it
    /// could, so capacity may still cover the records after them.
    #[instrument(skip_all, fields(token = %queue.token, head = queue.head, tail = queue.tail))]
    async fn drain(&self, queue: &TokenQueue) -> eyre::Result<bool> {
        // Each send reads the lane's committed nonce, so a send that failed or timed out never
        // leaves later drains behind a skipped nonce.
        let nonce = self
            .provider
            .get_transaction_count_with_nonce_key(
                self.sequencer_address,
                PROCESS_QUEUED_WITHDRAWALS_NONCE_KEY,
            )
            .await?;
        let (max_entries, gas_limit) = plan_drain(queue.tail - queue.head, self.max_batch_gas);
        let fees = bound_l1_fees(self.provider.estimate_eip1559_fees().await?);
        info!(
            max_entries,
            nonce, gas_limit, "📤 Broadcasting processQueuedWithdrawals to L1"
        );

        let receipt = self
            .portal
            .processQueuedWithdrawals(queue.token, U256::from(max_entries))
            .from(self.sequencer_address)
            .nonce_key(PROCESS_QUEUED_WITHDRAWALS_NONCE_KEY)
            .nonce(nonce)
            .max_fee_per_gas(fees.max_fee_per_gas)
            .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
            .gas(gas_limit)
            .send_sync()
            .timeout(PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT)
            .await
            .map_err(|_| {
                eyre::eyre!(
                    "processQueuedWithdrawals sync submission timed out after {} seconds",
                    PROCESS_WITHDRAWAL_CONFIRM_TIMEOUT.as_secs()
                )
            })??;

        let tx_hash = receipt.transaction_hash;
        if !receipt.status() {
            eyre::bail!("processQueuedWithdrawals transaction {tx_hash} reverted");
        }
        self.metrics.drains_confirmed_total.increment(1);
        let completed = completed_records(receipt.logs(), *self.portal.address(), queue.token);
        info!(
            %tx_hash,
            gas_used = receipt.gas_used,
            completed,
            "✅ processQueuedWithdrawals confirmed on L1"
        );
        Ok(completed == max_entries)
    }
}

/// Runs `drain` for each of `queues` in order, each within [`DRAIN_TIMEOUT`]. A drain that fails
/// or times out is counted and logged, and the next queue still runs.
///
/// Returns whether some drain completed a full batch.
async fn drain_each<'a, F, Fut>(
    queues: &'a [TokenQueue],
    metrics: &QueuedWithdrawalDrainMetrics,
    mut drain: F,
) -> bool
where
    F: FnMut(&'a TokenQueue) -> Fut,
    Fut: Future<Output = eyre::Result<bool>>,
{
    let mut rescan = false;
    for queue in queues {
        let error = match tokio::time::timeout(DRAIN_TIMEOUT, drain(queue)).await {
            Ok(Ok(full)) => {
                rescan |= full;
                continue;
            }
            Ok(Err(error)) => error,
            Err(_) => eyre::eyre!("drain timed out after {} seconds", DRAIN_TIMEOUT.as_secs()),
        };
        metrics.drains_failed_total.increment(1);
        warn!(token = %queue.token, head = queue.head, tail = queue.tail, %error, "Failed to drain token queue");
    }
    rescan
}

/// Counts the records of `token` that a drain's receipt shows completed: `QueuedWithdrawalPaid`
/// logs `portal` emitted with nothing remaining. A record that was paid in full, bounced back to
/// the zone or parked as a refund each emits one.
fn completed_records(logs: &[alloy_rpc_types_eth::Log], portal: Address, token: Address) -> u64 {
    logs.iter()
        .filter(|log| {
            log.address() == portal
                && log.topics().first() == Some(&ZonePortal::QueuedWithdrawalPaid::SIGNATURE_HASH)
        })
        .filter_map(|log| ZonePortal::QueuedWithdrawalPaid::decode_log(&log.inner).ok())
        .filter(|event| event.token == token && event.remaining == 0)
        .count() as u64
}

/// Returns whether to send `processQueuedWithdrawals` for `queue`.
///
/// Matches the portal's payment rule: a token with no limit pays every record, and a limited
/// token pays its head record once capacity covers the record's remainder or `max_amount`,
/// whichever is smaller. A deposit bounce-back's fee is capped at that payment.
fn should_drain(queue: &TokenQueue) -> bool {
    queue.head < queue.tail
        && (queue.max_amount == 0 || queue.available >= queue.head_remaining.min(queue.max_amount))
}

/// Returns the `maxEntries` to pass for a queue of `unpaid` records, and the transaction's gas
/// limit. At least one record is always sent, so a small `max_batch_gas` still makes progress.
fn plan_drain(unpaid: u64, max_batch_gas: u64) -> (u64, u64) {
    let fit = max_batch_gas.saturating_sub(PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS) / QUEUED_ENTRY_GAS;
    let entries = unpaid.min(fit).max(1);
    (
        entries,
        PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS + entries * QUEUED_ENTRY_GAS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::withdrawals::{DEFAULT_MAX_WITHDRAWAL_BATCH_GAS, MAX_WITHDRAWAL_BATCH_GAS};
    use alloy_primitives::address;

    use alloy_sol_types::SolEvent;
    use std::cell::RefCell;

    const TOKEN: Address = address!("0x20c0000000000000000000000000000000000001");
    const OTHER_TOKEN: Address = address!("0x20c0000000000000000000000000000000000002");
    const PORTAL: Address = address!("0x5ad0000000000000000000000000000000000001");
    const OTHER_PORTAL: Address = address!("0x5ad0000000000000000000000000000000000002");

    fn paid_log(
        portal: Address,
        token: Address,
        queue_index: u64,
        remaining: u128,
    ) -> alloy_rpc_types_eth::Log {
        alloy_rpc_types_eth::Log {
            inner: alloy_primitives::Log {
                address: portal,
                data: ZonePortal::QueuedWithdrawalPaid {
                    token,
                    queueIndex: U256::from(queue_index),
                    paid: 100,
                    remaining,
                }
                .encode_log_data(),
            },
            ..Default::default()
        }
    }

    fn queue(max_amount: u128, available: u128, head_remaining: u128) -> TokenQueue {
        TokenQueue {
            token: TOKEN,
            head: 3,
            tail: 5,
            max_amount,
            available,
            head_remaining,
        }
    }

    #[test]
    fn empty_queues_never_drain() {
        let empty = TokenQueue {
            tail: 3,
            ..queue(0, 0, 0)
        };
        assert!(!should_drain(&empty));
        assert!(!should_drain(&TokenQueue {
            tail: 3,
            ..queue(1_000, 1_000, 0)
        }));
    }

    #[test]
    fn unlimited_tokens_always_drain() {
        assert!(should_drain(&queue(0, 0, 5_000)));
    }

    #[test]
    fn limited_tokens_wait_for_one_whole_payment() {
        // A record at or below max_amount waits until capacity covers all of it.
        assert!(!should_drain(&queue(1_000, 299, 300)));
        assert!(should_drain(&queue(1_000, 300, 300)));
        // A larger record is paid max_amount at a time, each once capacity is full.
        assert!(!should_drain(&queue(1_000, 999, 1_500)));
        assert!(should_drain(&queue(1_000, 1_000, 1_500)));
    }

    #[test]
    fn plans_entries_within_the_gas_budget() {
        let (entries, gas) = plan_drain(1_000, DEFAULT_MAX_WITHDRAWAL_BATCH_GAS);
        assert_eq!(entries, 21);
        assert_eq!(
            gas,
            PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS + 21 * QUEUED_ENTRY_GAS
        );
        assert!(gas <= DEFAULT_MAX_WITHDRAWAL_BATCH_GAS);

        let (entries, gas) = plan_drain(1_000, MAX_WITHDRAWAL_BATCH_GAS);
        assert_eq!(entries, 46);
        assert!(gas <= MAX_WITHDRAWAL_BATCH_GAS);
    }

    #[test]
    fn plans_no_more_entries_than_are_unpaid() {
        assert_eq!(
            plan_drain(2, DEFAULT_MAX_WITHDRAWAL_BATCH_GAS),
            (2, PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS + 2 * QUEUED_ENTRY_GAS)
        );
    }

    #[test]
    fn plans_one_entry_under_a_tiny_budget() {
        assert_eq!(
            plan_drain(10, 1),
            (1, PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS + QUEUED_ENTRY_GAS)
        );
    }

    /// Every drain fits the gas it is sent with, using the worst case measured on the T15 portal
    /// with no storage credits and recipients whose token balance is zero.
    #[test]
    fn drains_fit_worst_case_records() {
        const ONE_RECORD: u64 = 1_108_920;
        const TWO_RECORDS: u64 = 1_667_482;
        const NEXT_RECORD: u64 = 284_162;
        const INTRINSIC_AND_CALLDATA: u64 = 21_000 + 400;

        for max_batch_gas in [DEFAULT_MAX_WITHDRAWAL_BATCH_GAS, MAX_WITHDRAWAL_BATCH_GAS] {
            for unpaid in 1..=200 {
                let (entries, gas_limit) = plan_drain(unpaid, max_batch_gas);
                let worst = INTRINSIC_AND_CALLDATA
                    + match entries {
                        1 => ONE_RECORD,
                        _ => TWO_RECORDS + (entries - 2) * NEXT_RECORD,
                    };
                assert!(
                    worst <= gas_limit,
                    "{entries} records need {worst} gas, sent {gas_limit}"
                );
            }
        }
    }

    /// The drain rescans only when its receipt shows `maxEntries` records completed.
    #[test]
    fn rescans_after_completing_max_entries() {
        let max_entries = 2;
        let fewer = [paid_log(PORTAL, TOKEN, 3, 0)];
        assert!(completed_records(&fewer, PORTAL, TOKEN) < max_entries);

        // A partial payment of the next record does not complete it.
        let partial = [
            paid_log(PORTAL, TOKEN, 3, 0),
            paid_log(PORTAL, TOKEN, 4, 500),
        ];
        assert!(completed_records(&partial, PORTAL, TOKEN) < max_entries);

        let full = [paid_log(PORTAL, TOKEN, 3, 0), paid_log(PORTAL, TOKEN, 4, 0)];
        assert_eq!(completed_records(&full, PORTAL, TOKEN), max_entries);
    }

    #[test]
    fn completed_records_ignore_other_tokens_and_addresses() {
        let mut unrelated = paid_log(PORTAL, TOKEN, 4, 0);
        unrelated.inner.data = alloy_primitives::LogData::new_unchecked(
            vec![alloy_primitives::B256::repeat_byte(1)],
            unrelated.inner.data.data.clone(),
        );
        let logs = [
            paid_log(PORTAL, TOKEN, 3, 0),
            paid_log(PORTAL, OTHER_TOKEN, 3, 0),
            paid_log(OTHER_PORTAL, TOKEN, 4, 0),
            unrelated,
        ];
        assert_eq!(completed_records(&logs, PORTAL, TOKEN), 1);
        assert_eq!(completed_records(&logs, PORTAL, OTHER_TOKEN), 1);
        assert_eq!(completed_records(&[], PORTAL, TOKEN), 0);
    }

    /// A drain that never finishes is abandoned at [`DRAIN_TIMEOUT`], and the next token still
    /// drains.
    #[tokio::test(start_paused = true)]
    async fn timed_out_drain_lets_the_next_token_run() {
        let queues = [
            queue(0, 0, 1),
            TokenQueue {
                token: OTHER_TOKEN,
                ..queue(0, 0, 1)
            },
        ];
        let drained = RefCell::new(Vec::new());
        let start = tokio::time::Instant::now();

        let rescan = drain_each(&queues, &QueuedWithdrawalDrainMetrics::default(), |queue| {
            let drained = &drained;
            async move {
                if queue.token == TOKEN {
                    std::future::pending::<()>().await;
                }
                drained.borrow_mut().push(queue.token);
                Ok(true)
            }
        })
        .await;

        assert!(rescan);
        assert_eq!(drained.into_inner(), vec![OTHER_TOKEN]);
        assert_eq!(start.elapsed(), DRAIN_TIMEOUT);
    }

    #[tokio::test]
    async fn failed_drain_lets_the_next_token_run() {
        let queues = [
            queue(0, 0, 1),
            TokenQueue {
                token: OTHER_TOKEN,
                ..queue(0, 0, 1)
            },
        ];
        let drained = RefCell::new(Vec::new());

        let rescan = drain_each(&queues, &QueuedWithdrawalDrainMetrics::default(), |queue| {
            let drained = &drained;
            async move {
                drained.borrow_mut().push(queue.token);
                if queue.token == TOKEN {
                    eyre::bail!("send failed");
                }
                Ok(false)
            }
        })
        .await;

        assert!(!rescan);
        assert_eq!(drained.into_inner(), vec![TOKEN, OTHER_TOKEN]);
    }
}
