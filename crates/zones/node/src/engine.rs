//! Zone Engine — L1-event-driven block production for zone nodes.
//!
//! Advances the zone chain whenever new L1 blocks arrive in the deposit
//! queue, enabling full-speed sync during catch-up and instant reaction in
//! steady state.
//!
//! ## Block production flow
//!
//! ```text
//! L1Subscriber ──enqueue──► DepositQueue ──notify──► ZoneEngine
//!                                │                       │
//!                                │                   1. peek queue → L1 block
//!                                │                   2. build ZonePayloadAttributes
//!                                │                      (inner attrs + l1_block)
//!                                │                   3. FCU w/ payload attributes
//!                                │                       │
//!                                │                       ▼
//!                                │               reth payload service
//!                                │                       │
//!                                │               4. build payload
//!                                │                  (L1 data from attributes)
//!                                │                       │
//!                                │                       ▼
//!                                │                  ZoneEngine
//!                                │               5. resolve payload
//!                                │               6. newPayload
//!                                │               7. persist proofs (file + directory sync)
//!                                │               8. FCU (update head)
//!                                │                       │
//!                                ◄── confirm ◄───────────┘
//! ```
//!
//! The deposit queue uses a **peek / confirm** pattern: the engine peeks at
//! the next L1 block, wraps it into [`ZonePayloadAttributes`], and only
//! confirms (removes) the block after proof persistence and canonical forkchoice succeed.
//! A failed build, proof write, or forkchoice leaves the block in the queue for retry.
//!
//! The zone assumes **instant finality** — head, safe, and finalized all point
//! to the same block.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::{ForkchoiceState, PayloadAttributes as EthPayloadAttributes};
use eyre::{OptionExt, WrapErr as _};
use reth_chainspec::EthereumHardforks;
use reth_node_builder::ConsensusEngineHandle;
use reth_payload_builder::PayloadBuilderHandle;
use reth_payload_primitives::{BuiltPayload, PayloadKind};
use reth_primitives_traits::SealedHeader;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_primitives::TempoHeader;
use tracing::error;

use zone_chainspec::ZoneChainSpec;
use zone_consensus::import::{TempoImportDecision, tempo_import_decision, zone_timestamp_millis};
use zone_l1::{DepositQueue, EncryptionKeyRing, L1BlockDeposits, L1BlockTracker};
use zone_payload::{TempoImport, ZonePayloadAttributes, ZonePayloadTypes};
use zone_sequencer::ProofCollectorHandle;

/// A queue-backed block consumer that can drain all work currently available.
///
/// Kept separate from [`ZoneEngine`] so the pause boundary between two advances can be tested
/// deterministically without mocking the Engine API and payload builder.
trait AvailableBlockDrain {
    type Block;

    /// Returns the next available block without consuming it.
    fn next_available(&self) -> eyre::Result<Option<Self::Block>>;

    /// Returns whether a finalized Portal pause currently forbids producing another block.
    fn production_paused(&self) -> bool;

    /// Completes and consumes one block.
    async fn advance_one(&mut self, block: Self::Block) -> eyre::Result<()>;
}

/// Drain available blocks until the queue is empty or the Portal is paused.
///
/// The pause is checked only before starting a new advance. An advance already in flight is
/// always allowed to finish so its queue confirmation and canonical head remain consistent.
async fn drain_all_available<D>(drain: &mut D) -> eyre::Result<()>
where
    D: AvailableBlockDrain,
{
    loop {
        let Some(block) = drain.next_available()? else {
            return Ok(());
        };
        // The subscriber publishes a pause before enqueueing its block. Reading the gate after
        // selecting the candidate therefore stops before the pause block itself. The block stays
        // queued and is produced once the pause clears.
        if drain.production_paused() {
            return Ok(());
        }
        drain.advance_one(block).await?;
    }
}

/// Engine that drives L2 block production from L1 events.
///
/// Waits for L1 blocks in the [`DepositQueue`], then for each block:
/// 1. Peeks the L1 block from the queue
/// 2. Builds [`ZonePayloadAttributes`] wrapping inner Tempo attrs + L1 data
/// 3. Sends FCU with payload attributes to start a build
/// 4. Resolves the built payload
/// 5. Submits via `newPayload`
/// 6. Confirms the L1 block in the queue (removes it)
///
/// On failure the L1 block stays in the queue and is retried.
#[derive(Debug)]
pub struct ZoneEngine {
    /// Chain spec for hardfork checks when building attributes.
    chain_spec: Arc<ZoneChainSpec>,
    /// Engine API handle for FCU and newPayload.
    to_engine: ConsensusEngineHandle<ZonePayloadTypes>,
    /// Payload builder handle.
    payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
    /// Queue of L1 blocks with their deposits.
    deposit_queue: DepositQueue,
    /// Independently observed L1 blocks retained until their zone payload is accepted.
    l1_block_tracker: L1BlockTracker,
    /// Latest block header — used as parent for the next payload and as the
    /// head/safe/finalized hash in FCU (instant finality).
    last_header: SealedHeader<TempoHeader>,
    /// Address that receives block fees.
    fee_recipient: Address,
    /// Private keys bound to the Portal indexes used by deposits.
    encryption_keys: EncryptionKeyRing,
    /// ZonePortal address on L1 — used as context in HKDF key derivation.
    portal_address: Address,
    /// Proof WAL writer invoked after execution and before canonicalization.
    proof_collector: Option<ProofCollectorHandle>,
}

impl ZoneEngine {
    pub fn new(
        chain_spec: Arc<ZoneChainSpec>,
        to_engine: ConsensusEngineHandle<ZonePayloadTypes>,
        payload_builder: PayloadBuilderHandle<ZonePayloadTypes>,
        deposit_queue: DepositQueue,
        l1_block_tracker: L1BlockTracker,
        last_header: SealedHeader<TempoHeader>,
        fee_recipient: Address,
        encryption_keys: EncryptionKeyRing,
        portal_address: Address,
        proof_collector: Option<ProofCollectorHandle>,
    ) -> Self {
        Self {
            chain_spec,
            to_engine,
            payload_builder,
            deposit_queue,
            l1_block_tracker,
            last_header,
            fee_recipient,
            encryption_keys,
            portal_address,
            proof_collector,
        }
    }

    /// Runs the main Zone engine loop forever. It:
    /// 1. Waits for L1 blocks to arrive in the deposit queue
    /// 2. Advances the zone chain for each available L1 block (no delay between blocks)
    /// 3. Sends periodic FCU heartbeats
    pub async fn run(mut self) {
        let mut fcu_interval = tokio::time::interval(Duration::from_secs(1));
        fcu_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Send initial FCU to establish head
        if let Err(e) = self.update_forkchoice_state().await {
            error!(target: "zone::engine", "Error sending initial FCU: {:?}", e);
        }

        loop {
            tokio::select! {
                biased;
                // Wait for new L1 blocks in the deposit queue
                _ = self.deposit_queue.notified() => {
                    self.advance_all_available().await;
                }
                // Periodic FCU heartbeat — also drains any blocks we missed
                _ = fcu_interval.tick() => {
                    self.advance_all_available().await;
                    if let Err(e) = self.update_forkchoice_state().await {
                        error!(target: "zone::engine", "Error updating fork choice: {:?}", e);
                    }
                }
            }
        }
    }

    /// Returns the current forkchoice state.
    ///
    /// The zone has instant finality so head = safe = finalized.
    fn forkchoice_state(&self) -> ForkchoiceState {
        ForkchoiceState::same_hash(self.last_header.hash())
    }

    /// Send an FCU without payload attributes (heartbeat).
    async fn update_forkchoice_state(&self) -> eyre::Result<()> {
        let state = self.forkchoice_state();
        let res = self.to_engine.fork_choice_updated(state, None).await?;

        if !res.is_valid() {
            eyre::bail!("Invalid fork choice update {state:?}: {res:?}");
        }

        Ok(())
    }

    /// Advance the chain for all available L1 blocks in the queue.
    ///
    /// During catch-up this processes blocks as fast as the EVM can execute
    /// them, with no timer delays between blocks.
    async fn advance_all_available(&mut self) {
        if let Err(e) = drain_all_available(self).await {
            error!(target: "zone::engine", "Error advancing the chain: {:?}", e);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Advance the chain by one block.
    ///
    /// Wraps the given L1 block into [`ZonePayloadAttributes`], sends FCU
    /// with those attributes, waits for the payload to be built, then submits
    /// via `newPayload`. Only confirms (removes) the L1 block from the
    /// deposit queue after witness persistence and canonicalization succeed.
    async fn advance(&mut self, available: AvailableTempoImport) -> eyre::Result<()> {
        let AvailableTempoImport {
            l1_block,
            checkpoint_headers,
            wall_clock_timestamp_millis,
        } = available;
        let checkpoint_only = !checkpoint_headers.is_empty();
        let final_header = checkpoint_headers.last().unwrap_or(&l1_block.header);
        let l1_num_hash = final_header.num_hash();

        let timestamp_millis = zone_timestamp_millis(
            final_header.timestamp_millis(),
            self.last_header.timestamp_millis(),
            wall_clock_timestamp_millis,
        );
        let timestamp_secs = timestamp_millis / 1000;
        let timestamp_millis_part = timestamp_millis % 1000;

        let tempo_import = if checkpoint_only {
            TempoImport::CheckpointOnly(checkpoint_headers)
        } else {
            let portal_work = self
                .deposit_queue
                .operational_work(l1_block.header.num_hash())?;
            TempoImport::Full(Box::new(
                L1BlockDeposits::prepare_many(
                    portal_work,
                    &self.encryption_keys,
                    self.portal_address,
                )
                .await?,
            ))
        };

        let attributes = ZonePayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp: timestamp_secs,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: self.fee_recipient,
                withdrawals: self
                    .chain_spec
                    .is_shanghai_active_at_timestamp(timestamp_secs)
                    .then(Default::default),
                parent_beacon_block_root: self
                    .chain_spec
                    .is_cancun_active_at_timestamp(timestamp_secs)
                    .then_some(B256::ZERO),
                slot_number: None,
                target_gas_limit: None,
            },
            timestamp_millis_part,
            tempo_import,
        };

        // Send FCU with payload attributes through the engine API to trigger
        // payload building. The forkchoice state points at the current head;
        // the attributes carry the L1 block data for the new zone block.
        let res = self
            .to_engine
            .fork_choice_updated(self.forkchoice_state(), Some(attributes))
            .await?;

        if res.is_invalid() {
            eyre::bail!("Invalid payload status");
        }

        let payload_id = res.payload_id.ok_or_eyre("No payload id")?;

        let Some(Ok(payload)) = self
            .payload_builder
            .resolve_kind(payload_id, PayloadKind::WaitForPending)
            .await
        else {
            eyre::bail!("No payload");
        };

        let header = payload.block().sealed_header().clone();
        let block_number = header.number();
        let res = self.to_engine.new_payload(payload.into()).await?;

        if !res.is_valid() {
            eyre::bail!("Invalid payload for block {block_number}");
        }

        if let Some(collector) = &self.proof_collector {
            collector
                .collect_and_persist(block_number, header.hash())
                .await
                .wrap_err_with(|| {
                    format!("collect proofs before canonicalizing Zone block {block_number}")
                })?;
        }

        // Consume the L1 input only after witness persistence succeeds.
        if checkpoint_only {
            self.deposit_queue.defer_through(l1_num_hash)?;
        } else {
            self.deposit_queue.confirm_operational(l1_num_hash)?;
        }
        self.l1_block_tracker.prune_through(l1_num_hash.number);
        self.last_header = header;

        // Canonicalize the new head — FCU-with-attrs above only set the
        // *previous* head as canonical; this bare FCU makes the just-built
        // block the EL's canonical head.
        if let Err(e) = self.update_forkchoice_state().await {
            error!(target: "zone::engine", "Error sending post-newPayload FCU: {:?}", e);
        }

        Ok(())
    }
}

impl AvailableBlockDrain for ZoneEngine {
    type Block = AvailableTempoImport;

    fn next_available(&self) -> eyre::Result<Option<Self::Block>> {
        let Some(l1_block) = self.deposit_queue.peek() else {
            return Ok(None);
        };
        let mut queued_headers = self
            .deposit_queue
            .peek_headers(zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK + 1);
        let latest_l1_header = self
            .deposit_queue
            .latest_header()
            .ok_or_eyre("L1 deposit queue lost its latest header")?;
        let wall_clock_timestamp_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let decision = tempo_import_decision(
            &self.chain_spec,
            &queued_headers,
            &latest_l1_header,
            self.l1_block_tracker.finalized_l1_timestamp(),
            self.l1_block_tracker.finalized_target(),
            self.last_header.timestamp_millis(),
            wall_clock_timestamp_millis,
        );
        let checkpoint_headers = match decision {
            TempoImportDecision::WaitForHardforkMatch
            | TempoImportDecision::WaitForFinalizedTarget => return Ok(None),
            TempoImportDecision::ImportFull => Vec::new(),
            TempoImportDecision::ImportCheckpoints(count) => {
                queued_headers.truncate(count);
                queued_headers
            }
        };
        Ok(Some(AvailableTempoImport {
            l1_block,
            checkpoint_headers,
            wall_clock_timestamp_millis,
        }))
    }

    fn production_paused(&self) -> bool {
        self.l1_block_tracker.portal_paused()
    }

    async fn advance_one(&mut self, block: Self::Block) -> eyre::Result<()> {
        self.advance(block).await
    }
}

#[derive(Debug)]
struct AvailableTempoImport {
    l1_block: L1BlockDeposits,
    checkpoint_headers: Vec<SealedHeader<TempoHeader>>,
    wall_clock_timestamp_millis: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_chainspec::EthChainSpec as _;
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tokio::sync::oneshot;
    use zone_chainspec::test_utils::set_tempo_fork;
    use zone_l1::FinalizedTarget;

    #[test]
    fn zone_timestamp_uses_l1_timestamp_as_a_lower_bound() {
        assert_eq!(zone_timestamp_millis(2_000, 999, 1_500), 2_000);
    }

    #[test]
    fn zone_timestamp_uses_wall_clock_during_catch_up() {
        assert_eq!(zone_timestamp_millis(1_000, 999, 2_000), 2_000);
    }

    #[test]
    fn zone_timestamp_allows_parent_timestamp_when_catching_up_in_same_millisecond() {
        assert_eq!(zone_timestamp_millis(1_000, 2_000, 2_000), 2_000);
    }

    fn t13_spec(activation: u64) -> ZoneChainSpec {
        let mut genesis = tempo_chainspec::spec::DEV.genesis().clone();
        set_tempo_fork(&mut genesis, TempoHardfork::T13, activation);
        genesis.config.chain_id =
            zone_primitives::constants::zone_chain_id(tempo_chainspec::spec::DEV.chain_id(), 1)
                .unwrap();
        ZoneChainSpec::from_genesis(genesis).unwrap()
    }

    fn header(number: u64, timestamp: u64) -> SealedHeader<TempoHeader> {
        SealedHeader::seal_slow(TempoHeader {
            inner: alloy_consensus::Header {
                number,
                timestamp,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn finalized_target(number: u64, ready: bool) -> Option<FinalizedTarget> {
        Some(FinalizedTarget { number, ready })
    }

    #[test]
    fn t13_boundary_waits_for_l1_then_checkpoints_the_t12_prefix() {
        let spec = t13_spec(100);
        let t12 = header(1, 99);
        let t13 = header(2, 100);

        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&t12),
                &t12,
                None,
                finalized_target(1, true),
                98_000,
                100_000
            ),
            TempoImportDecision::WaitForHardforkMatch
        );
        // A full lookahead of T12 headers: finalized L1 observed outside the queue proves activation.
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&t12),
                &t12,
                Some(100),
                finalized_target(2, false),
                98_000,
                100_000
            ),
            TempoImportDecision::ImportCheckpoints(1)
        );
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&t12),
                &t13,
                None,
                None,
                98_000,
                100_000,
            ),
            TempoImportDecision::ImportCheckpoints(1)
        );
        assert_eq!(
            tempo_import_decision(
                &spec,
                &[t12, t13.clone()],
                &t13,
                None,
                finalized_target(2, false),
                98_000,
                100_000,
            ),
            TempoImportDecision::ImportCheckpoints(1)
        );
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&t13),
                &t13,
                None,
                finalized_target(2, true),
                99_000,
                100_000
            ),
            TempoImportDecision::ImportFull
        );
    }

    #[test]
    fn pre_t13_zone_block_imports_the_t12_front_normally() {
        let spec = t13_spec(100);
        let t12 = header(1, 99);
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&t12),
                &t12,
                None,
                finalized_target(1, true),
                98_000,
                99_000
            ),
            TempoImportDecision::ImportFull
        );
    }

    #[test]
    fn hardfork_gate_does_not_wait_when_l1_is_ahead_of_the_zone() {
        let spec = t13_spec(100);
        let t12 = header(1, 99);
        let t13 = header(2, 100);

        assert_eq!(
            tempo_import_decision(
                &spec,
                &[t12],
                &t13,
                None,
                finalized_target(2, true),
                98_000,
                99_000,
            ),
            TempoImportDecision::ImportFull
        );
    }

    #[test]
    fn checkpoint_batching_uses_announced_finalized_target() {
        let spec = t13_spec(100);

        // Backfill has announced 100 missing blocks, but only the first is verified and queued.
        // It must remain a checkpoint-only import instead of becoming a premature full block.
        let first = header(100, 100);
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&first),
                &first,
                None,
                finalized_target(199, false),
                99_000,
                100_000,
            ),
            TempoImportDecision::ImportCheckpoints(1)
        );

        // Once all 100 are queued, reserve the target header for the full operational import and
        // fold the preceding 99 headers into one checkpoint-only block.
        let headers = (100..=199)
            .map(|number| header(number, number))
            .collect::<Vec<_>>();
        assert_eq!(
            tempo_import_decision(
                &spec,
                &headers,
                headers.last().unwrap(),
                None,
                finalized_target(199, false),
                99_000,
                100_000,
            ),
            TempoImportDecision::ImportCheckpoints(99)
        );

        let target = header(199, 199);
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&target),
                &target,
                None,
                finalized_target(199, false),
                99_000,
                100_000,
            ),
            TempoImportDecision::WaitForFinalizedTarget
        );
        assert_eq!(
            tempo_import_decision(
                &spec,
                std::slice::from_ref(&target),
                &target,
                None,
                finalized_target(199, true),
                99_000,
                100_000,
            ),
            TempoImportDecision::ImportFull
        );
    }

    struct PausedDrain {
        pending: VecDeque<u64>,
        advanced: Vec<u64>,
        first_started: Option<oneshot::Sender<()>>,
        release_first: Option<oneshot::Receiver<()>>,
        portal_paused: Arc<AtomicBool>,
    }

    impl AvailableBlockDrain for PausedDrain {
        type Block = u64;

        fn next_available(&self) -> eyre::Result<Option<Self::Block>> {
            Ok(self.pending.front().copied())
        }

        fn production_paused(&self) -> bool {
            self.portal_paused.load(Ordering::Relaxed)
        }

        async fn advance_one(&mut self, block: Self::Block) -> eyre::Result<()> {
            if let Some(started) = self.first_started.take() {
                let _ = started.send(());
                self.release_first
                    .take()
                    .expect("first advance has a release signal")
                    .await
                    .expect("test releases the first advance");
            }

            assert_eq!(self.pending.pop_front(), Some(block));
            self.advanced.push(block);
            Ok(())
        }
    }

    #[tokio::test]
    async fn portal_pause_finishes_the_in_flight_block_then_retains_the_backlog() {
        let (first_started, started) = oneshot::channel();
        let (release, release_first) = oneshot::channel();
        let portal_paused = Arc::new(AtomicBool::new(false));
        let mut drain = PausedDrain {
            pending: VecDeque::from([1, 2, 3]),
            advanced: Vec::new(),
            first_started: Some(first_started),
            release_first: Some(release_first),
            portal_paused: portal_paused.clone(),
        };

        let task = tokio::spawn(async move {
            drain_all_available(&mut drain)
                .await
                .expect("drain succeeds");
            drain
        });

        started.await.expect("the first block starts");
        portal_paused.store(true, Ordering::Relaxed);
        release
            .send(())
            .expect("the first block is still in flight");

        // A pause does not stop the engine loop; the backlog stays queued.
        let mut drain = task.await.expect("drain task succeeds");
        assert_eq!(drain.advanced, [1]);
        assert_eq!(drain.pending, [2, 3]);

        // Resume or expiry clears the gate and the next drain catches up.
        portal_paused.store(false, Ordering::Relaxed);
        drain_all_available(&mut drain)
            .await
            .expect("drain succeeds");
        assert_eq!(drain.advanced, [1, 2, 3]);
        assert!(drain.pending.is_empty());
    }
}
