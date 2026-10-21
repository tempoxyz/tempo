//! Zone block proposal and verification for Simplex.
//!
//! A proposal imports the next finalized Tempo header (or a checkpoint range) after its parent's
//! checkpoint. Verification re-derives the same portal inputs from local finalized L1
//! observations and executes the block. Both read the deposit queue relative to the parent: the
//! queue only advances when a block finalizes, so a nullified proposal leaves it untouched.
//!
//! Verification returns `false` only for blocks no honest node could accept. Missing local
//! evidence (an anchor not observed yet, an execution layer without a verdict) keeps the future
//! pending until consensus moves on.

use std::{collections::HashMap, sync::Arc, time::Duration};

use alloy_consensus::BlockHeader as _;
use alloy_eips::NumHash;
use alloy_primitives::{Address, B256};
use alloy_rpc_types_engine::PayloadAttributes as EthPayloadAttributes;
use commonware_actor::Feedback;
use commonware_consensus::{
    Heightable as _, Reporter,
    marshal::{Update, ancestry::Ancestry},
    simplex::types::Context,
};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{Clock, Metrics, Spawner};
use commonware_utils::{Acknowledgement as _, SystemTimeExt as _};
use eyre::OptionExt as _;
use futures::StreamExt as _;
use rand_core::Rng;
use reth_chainspec::EthereumHardforks as _;
use tempo_consensus::consensus::{Block, Digest};
use tracing::{debug, info, instrument, warn};
use zone_chainspec::ZoneChainSpec;
use zone_l1::{DepositQueue, EncryptionKeyRing, L1BlockDeposits, L1BlockTracker, QueueSnapshot};
use zone_payload::{TempoImport, ZonePayloadAttributes};
use zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK;

use crate::{
    Scheme, executor,
    import::{
        DecodedTempoImport, SelectedImport, decode_advance_tempo, owed_portal_work, select_import,
        validate_l1_checkpoint_range, validate_portal_inputs, zone_timestamp_millis,
    },
    provider::ConsensusProvider,
};

/// Upper bound on unfinalized ancestors walked for one proposal or verification.
///
/// Consensus never builds far above the finalized tip; reaching this means the executor fell far
/// behind marshal, and the node abstains until it catches up.
const MAX_ANCESTRY_WALK: usize = 4_096;

/// Application settings.
pub(crate) struct Config<TProvider> {
    pub(crate) provider: TProvider,
    pub(crate) executor: executor::Mailbox,
    pub(crate) chain_spec: Arc<ZoneChainSpec>,
    pub(crate) deposit_queue: DepositQueue,
    pub(crate) l1_block_tracker: L1BlockTracker,
    pub(crate) encryption_keys: EncryptionKeyRing,
    pub(crate) portal_address: Address,
    pub(crate) fee_recipient: Address,
    pub(crate) beneficiaries: HashMap<PublicKey, Address>,
    pub(crate) proposal_anchor_wait: Duration,
    pub(crate) genesis_checkpoint: NumHash,
}

/// Zone block builder and verifier, see the module documentation.
#[derive(Clone)]
pub(crate) struct Application<TProvider> {
    inner: Arc<Config<TProvider>>,
}

impl<TProvider: ConsensusProvider> Application<TProvider> {
    pub(crate) fn new(config: Config<TProvider>) -> Self {
        Self {
            inner: Arc::new(config),
        }
    }

    /// Fee recipient `leader`'s proposals must use.
    fn expected_beneficiary(&self, leader: &PublicKey) -> Address {
        self.inner
            .beneficiaries
            .get(leader)
            .copied()
            .unwrap_or(self.inner.fee_recipient)
    }

    /// The Tempo checkpoint in `block`'s post-state, and whether `block` was checkpoint-only.
    fn checkpoint_of(&self, block: &Block) -> eyre::Result<(NumHash, bool)> {
        if block.height().is_zero() {
            return Ok((self.inner.genesis_checkpoint, false));
        }
        let import = decode_advance_tempo(block.block())?;
        let anchor = import
            .anchor()
            .ok_or_eyre("block imports no Tempo header")?;
        Ok((
            anchor,
            matches!(import, DecodedTempoImport::CheckpointOnly { .. }),
        ))
    }

    /// Walk `parent` and its ancestors down to the deposit queue's consumed checkpoint.
    ///
    /// Returns the ancestors reth may not have executed (oldest first) and the anchor of the
    /// newest full import the queue has not consumed yet.
    async fn walk_unfinalized(
        &self,
        parent: Arc<Block>,
        ancestry: &mut impl Ancestry<Block>,
        consumed_through: NumHash,
    ) -> eyre::Result<Unfinalized> {
        let mut unexecuted = Vec::new();
        let mut last_full_import = None;
        let mut next = Some(parent);
        for _ in 0..MAX_ANCESTRY_WALK {
            let block = next.ok_or_eyre("ancestry ended before the consumed checkpoint")?;
            // Genesis is executed and its checkpoint is never above the consumed one.
            let done = if block.height().is_zero() {
                true
            } else {
                let import = decode_advance_tempo(block.block())?;
                let anchor = import
                    .anchor()
                    .ok_or_eyre("ancestor imports no Tempo header")?;
                let unconsumed = anchor.number > consumed_through.number;
                if unconsumed
                    && last_full_import.is_none()
                    && matches!(import, DecodedTempoImport::Full { .. })
                {
                    last_full_import = Some(anchor.number);
                }
                // Canonical blocks were executed; re-submitting a known fork block is cheap.
                let executed = self.inner.provider.header(block.hash())?.is_some();
                if !executed {
                    unexecuted.push(block);
                }
                executed && !unconsumed
            };
            if done {
                unexecuted.reverse();
                return Ok(Unfinalized {
                    unexecuted,
                    last_full_import,
                });
            }
            next = ancestry.next().await;
        }
        eyre::bail!("unfinalized ancestry exceeds {MAX_ANCESTRY_WALK} blocks")
    }

    /// Snapshot the deposit queue through the headers a proposal on `checkpoint` may import.
    fn snapshot_after(&self, checkpoint: NumHash) -> eyre::Result<QueueSnapshot> {
        self.inner
            .deposit_queue
            .snapshot(checkpoint.number + MAX_TEMPO_HEADERS_PER_ZONE_BLOCK as u64 + 1)
            .ok_or_eyre("deposit queue has no consumed checkpoint yet")
    }

    #[instrument(
        skip_all,
        fields(round = %context.round, parent = %parent.digest(), height = %parent.height().next()),
        err(level = tracing::Level::WARN),
    )]
    async fn build<TContext: Clock>(
        &self,
        runtime: &TContext,
        context: Context<Digest, PublicKey>,
        parent: Arc<Block>,
        mut ancestry: impl Ancestry<Block>,
    ) -> eyre::Result<Option<Block>> {
        let inner = &self.inner;
        if inner.l1_block_tracker.portal_paused() {
            debug!(target: "zone::consensus", "Portal paused; skipping proposal");
            return Ok(None);
        }
        let (checkpoint, parent_checkpoint_only) = self.checkpoint_of(&parent)?;
        let parent_timestamp_millis = parent.header().timestamp_millis();

        // Wait for the next finalized anchor, bounded below the leader timeout. Nothing is
        // consumed here, so giving up leaves the queue for the next leader.
        let deadline = std::time::Instant::now() + inner.proposal_anchor_wait;
        let (snapshot, selected, wall_clock) = loop {
            let snapshot = self.snapshot_after(checkpoint)?;
            let wall_clock = runtime.current().epoch_millis();
            if let Some(selected) = select_import(
                &inner.chain_spec,
                &snapshot,
                checkpoint,
                parent_checkpoint_only,
                inner.l1_block_tracker.finalized_l1_timestamp(),
                inner.l1_block_tracker.finalized_target(),
                parent_timestamp_millis,
                wall_clock,
            )? {
                break (snapshot, selected, wall_clock);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero()
                || tokio::time::timeout(remaining, inner.deposit_queue.notified())
                    .await
                    .is_err()
            {
                debug!(target: "zone::consensus", ?checkpoint, "No finalized Tempo anchor to import; skipping proposal");
                return Ok(None);
            }
        };

        let unfinalized = self
            .walk_unfinalized(parent.clone(), &mut ancestry, snapshot.consumed_through)
            .await?;
        eyre::ensure!(
            inner.executor.execute(unfinalized.unexecuted).await?,
            "parent ancestry failed execution"
        );

        let (final_header_timestamp_millis, tempo_import) = match selected {
            SelectedImport::CheckpointOnly(headers) => (
                headers
                    .last()
                    .expect("checkpoint selections are nonempty")
                    .timestamp_millis(),
                TempoImport::CheckpointOnly(headers),
            ),
            SelectedImport::Full(anchor) => {
                let work = owed_portal_work(&snapshot, unfinalized.last_full_import, anchor)?;
                let timestamp = work
                    .last()
                    .expect("owed work ends at the anchor")
                    .header
                    .timestamp_millis();
                let prepared = L1BlockDeposits::prepare_many(
                    work,
                    &inner.encryption_keys,
                    inner.portal_address,
                )
                .await?;
                (timestamp, TempoImport::Full(Box::new(prepared)))
            }
        };

        let timestamp_millis = zone_timestamp_millis(
            final_header_timestamp_millis,
            parent_timestamp_millis,
            wall_clock,
        );
        let timestamp = timestamp_millis / 1000;
        let attributes = ZonePayloadAttributes {
            inner: EthPayloadAttributes {
                timestamp,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: self.expected_beneficiary(&context.leader),
                withdrawals: inner
                    .chain_spec
                    .is_shanghai_active_at_timestamp(timestamp)
                    .then(Default::default),
                parent_beacon_block_root: inner
                    .chain_spec
                    .is_cancun_active_at_timestamp(timestamp)
                    .then_some(B256::ZERO),
                slot_number: None,
                target_gas_limit: None,
            },
            timestamp_millis_part: timestamp_millis % 1000,
            tempo_import,
        };
        let block = inner.executor.build(parent.digest(), attributes).await?;
        Ok(Some(block))
    }

    async fn check<TContext: Clock>(
        &self,
        runtime: &TContext,
        context: &Context<Digest, PublicKey>,
        block: &Arc<Block>,
        parent: Arc<Block>,
        mut ancestry: impl Ancestry<Block>,
    ) -> Verdict {
        let header = block.header();
        if header.consensus_context.is_some() || !header.extra_data().is_empty() {
            return Verdict::Invalid(eyre::eyre!(
                "Zone headers carry neither a consensus context nor extra data"
            ));
        }
        let expected = self.expected_beneficiary(&context.leader);
        if header.beneficiary() != expected {
            return Verdict::Invalid(eyre::eyre!(
                "beneficiary {} is not the leader's fee recipient {expected}",
                header.beneficiary()
            ));
        }
        let import = match decode_advance_tempo(block.block()) {
            Ok(import) => import,
            Err(error) => return Verdict::Invalid(error),
        };
        let (checkpoint, _) = match self.checkpoint_of(&parent) {
            Ok(checkpoint) => checkpoint,
            Err(error) => return Verdict::Abstain(error.wrap_err("cannot read parent checkpoint")),
        };
        if let Err(error) = validate_l1_checkpoint_range(
            import.headers(),
            checkpoint.number,
            checkpoint.hash,
            block.number(),
        ) {
            return Verdict::Invalid(error);
        }
        let anchor = import.anchor().expect("validated nonempty range");

        // Every honest node eventually observes the same finalized anchor; until then, wait.
        // The subscriber enqueues each block before recording it, so the queue now holds the
        // whole imported range.
        if let Err(error) = self.inner.l1_block_tracker.wait_for(anchor).await {
            return Verdict::Abstain(error.wrap_err("cannot observe the imported Tempo anchor"));
        }
        let Some(snapshot) = self.inner.deposit_queue.snapshot(anchor.number) else {
            return Verdict::Abstain(eyre::eyre!("deposit queue has no consumed checkpoint yet"));
        };
        let unfinalized = match self
            .walk_unfinalized(parent, &mut ancestry, snapshot.consumed_through)
            .await
        {
            Ok(unfinalized) => unfinalized,
            Err(error) => {
                return Verdict::Abstain(error.wrap_err("cannot walk unfinalized ancestry"));
            }
        };
        if let DecodedTempoImport::Full {
            deposits,
            enabled_tokens,
            ..
        } = &import
        {
            let work = match owed_portal_work(&snapshot, unfinalized.last_full_import, anchor) {
                Ok(work) => work,
                Err(error) => return Verdict::Abstain(error.wrap_err("cannot derive owed work")),
            };
            if let Err(error) = validate_portal_inputs(&work, deposits, enabled_tokens) {
                return Verdict::Invalid(
                    error.wrap_err("block does not match observed portal events"),
                );
            }
        }

        // Only the local clock gates the vote; a future timestamp is not invalid.
        wait_until_timestamp(runtime, header.timestamp_millis()).await;

        let mut blocks = unfinalized.unexecuted;
        blocks.push(block.clone());
        match self.inner.executor.execute(blocks).await {
            Ok(true) => Verdict::Valid,
            Ok(false) => Verdict::Invalid(eyre::eyre!("execution layer rejected the block")),
            Err(error) => Verdict::Abstain(error),
        }
    }
}

impl<TContext, TProvider> commonware_consensus::Application<TContext> for Application<TProvider>
where
    TContext: Rng + Spawner + Metrics + Clock,
    TProvider: ConsensusProvider,
{
    type SigningScheme = Scheme;
    type Context = Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();

    async fn propose(
        &mut self,
        (runtime, context): (TContext, Self::Context),
        mut ancestry: impl Ancestry<Block>,
        (): (),
    ) -> Option<Block> {
        let parent = ancestry.next().await?;
        let block = self
            .build(&runtime, context, parent, ancestry)
            .await
            .ok()??;
        info!(
            target: "zone::consensus",
            digest = %block.digest(),
            height = block.number(),
            transactions = block.body().transactions.len(),
            "Proposed Zone block"
        );
        Some(block)
    }

    #[instrument(
        skip_all,
        fields(round = %context.round, leader = %context.leader, parent = %context.parent.1),
    )]
    async fn verify(
        &mut self,
        (runtime, context): (TContext, Self::Context),
        mut ancestry: impl Ancestry<Block>,
    ) -> bool {
        let (Some(block), Some(parent)) = (ancestry.next().await, ancestry.next().await) else {
            warn!(target: "zone::consensus", "ancestry ended before the block and its parent; abstaining");
            return std::future::pending().await;
        };
        match self
            .check(&runtime, &context, &block, parent, ancestry)
            .await
        {
            Verdict::Valid => true,
            Verdict::Invalid(reason) => {
                warn!(target: "zone::consensus", digest = %block.digest(), reason = ?reason, "Rejecting Zone proposal");
                false
            }
            Verdict::Abstain(reason) => {
                warn!(target: "zone::consensus", digest = %block.digest(), reason = ?reason, "Abstaining from Zone proposal");
                std::future::pending().await
            }
        }
    }
}

impl<TProvider: ConsensusProvider> Reporter for Application<TProvider> {
    type Activity = Update<Block>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        // The executor applies and acknowledges finalized blocks.
        if let Update::Block(_, ack) = update {
            ack.acknowledge();
        }
        Feedback::Ok
    }
}

/// Unfinalized ancestry of a proposal's parent.
struct Unfinalized {
    /// Ancestors reth may not have executed, oldest first.
    unexecuted: Vec<Arc<Block>>,
    /// Anchor of the newest full import the deposit queue has not consumed.
    last_full_import: Option<u64>,
}

/// Outcome of verifying one proposal.
enum Verdict {
    Valid,
    /// No honest node can accept the block.
    Invalid(eyre::Report),
    /// This node lacks the evidence for a verdict; it does not vote.
    Abstain(eyre::Report),
}

/// Waits for a validated block's timestamp without making a validity decision.
async fn wait_until_timestamp(runtime: &impl Clock, timestamp: u64) {
    while runtime.current().epoch_millis() < timestamp {
        runtime
            .sleep_until(std::time::UNIX_EPOCH + Duration::from_millis(timestamp))
            .await;
    }
}
