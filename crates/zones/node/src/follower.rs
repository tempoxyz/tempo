//! Follower block import, backfill, and settlement-signing.

use alloy_consensus::BlockHeader as _;
use alloy_eips::NumHash;
use alloy_primitives::B256;
use alloy_rlp::Decodable as _;
use alloy_rpc_types_engine::ForkchoiceState;
use alloy_sol_types::SolCall as _;
use eyre::{OptionExt as _, WrapErr as _};
use reth_node_api::{ConsensusEngineHandle, PayloadTypes as _};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use reth_provider::HeaderProvider;
use reth_storage_api::{BlockNumReader, BlockReader, ReceiptProvider, StateProviderFactory};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_precompiles::dispatch::abi_decoder_config_for_spec;
use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};
use tokio::sync::mpsc;
use tokio_util::sync;
use tracing::{debug, info};
#[cfg(test)]
use zone_l1::L1PortalEvents;
use zone_l1::{DepositQueue, L1BlockTracker, TempoStateExt as _};
use zone_p2p::{
    BackfillCommand, BackfillResponse, LeadershipSchedule, P2pCommand, P2pEvent, P2pPeerId, PeerTip,
};
use zone_payload::{
    ZonePayloadTypes,
    abi::{IZoneInbox, ZONE_INBOX_ADDRESS},
};
use zone_primitives::constants::MAX_TEMPO_HEADERS_PER_ZONE_BLOCK;
use zone_prover::VerifierMode;
use zone_sequencer::attestation::{SettlementAttestation, SignedSettlementAttestation};

use crate::{
    replication::{PeerBlock, decode_peer_block},
    settlement_attestation::{AttestationContext, build_settlement_attestation},
};

const BACKFILL_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const BLOCK_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_ANCHOR_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PENDING_BLOCKS: usize = 128;
/// Keep track of the backfill exactly. We'll buffer any live blocks received
/// during backfill.
struct BackfillProgress {
    target_tip: Option<u64>,
    received_completion: bool,
    needed: bool,
}

impl BackfillProgress {
    const fn new() -> Self {
        Self {
            target_tip: None,
            received_completion: false,
            needed: true,
        }
    }

    fn observe_block(&mut self, number: u64, best: u64) {
        self.target_tip = Some(self.target_tip.map_or(number, |tip| tip.max(number)));
        if number > best.saturating_add(1) {
            self.needed = true;
        }
    }

    fn refresh_after_import(&mut self, best: u64, first_pending: Option<u64>) {
        self.needed = !self.received_completion
            || self.target_tip.is_some_and(|tip| best < tip)
            || first_pending.is_some_and(|number| number > best.saturating_add(1));
    }

    fn complete(&mut self, tip: u64, best: u64, first_pending: Option<u64>) {
        self.received_completion = true;
        self.target_tip = Some(self.target_tip.map_or(tip, |target| target.max(tip)));
        self.needed = best < self.target_tip.unwrap_or(tip)
            || first_pending.is_some_and(|number| number > best.saturating_add(1));
    }

    fn request(&self, best: u64) -> Option<BackfillCommand> {
        self.needed.then(|| BackfillCommand::Request {
            start: best.saturating_add(1),
        })
    }

    fn probe_after_inactivity(&mut self, best: u64) -> BackfillCommand {
        self.needed = true;
        BackfillCommand::Request {
            start: best.saturating_add(1),
        }
    }
}

/// A peer block awaiting import, with its provenance.
///
/// `live_sender` is the broadcast sender for live blocks and `None` for
/// backfilled blocks.
#[derive(Debug)]
struct PendingPeerBlock {
    block: PeerBlock,
    live_sender: Option<P2pPeerId>,
}

/// Bounded, height-ordered peer blocks awaiting canonical import.
#[derive(Default)]
struct PendingBlocks {
    blocks: BTreeMap<u64, PendingPeerBlock>,
}

impl PendingBlocks {
    /// Adds a block unless its height is already present. When full, retains blocks closest to
    /// the local head and returns the height that was dropped.
    fn insert(&mut self, number: u64, block: PendingPeerBlock) -> Option<u64> {
        if self.blocks.contains_key(&number) {
            return None;
        }
        if self.blocks.len() < MAX_PENDING_BLOCKS {
            self.blocks.insert(number, block);
            return None;
        }

        let Some((&farthest, _)) = self.blocks.last_key_value() else {
            self.blocks.insert(number, block);
            return None;
        };
        if number < farthest {
            self.blocks.pop_last();
            self.blocks.insert(number, block);
            Some(farthest)
        } else {
            Some(number)
        }
    }

    fn first_number(&self) -> Option<u64> {
        self.blocks.first_key_value().map(|(&number, _)| number)
    }

    fn take_next_after(&mut self, head: u64) -> Option<PendingPeerBlock> {
        self.blocks.remove(&head.saturating_add(1))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.blocks.len()
    }

    #[cfg(test)]
    fn contains(&self, number: u64) -> bool {
        self.blocks.contains_key(&number)
    }
}

/// Latest tip evidence advertised by each peer, with observation time.
///
/// Fed by backfill completions on the follower sync loop and consumed by the status RPC.
#[derive(Debug, Clone, Default)]
pub(crate) struct PeerTipRegistry {
    inner: std::sync::Arc<std::sync::Mutex<HashMap<P2pPeerId, (PeerTip, std::time::Instant)>>>,
}

impl PeerTipRegistry {
    pub(crate) fn record(&self, peer: P2pPeerId, tip: PeerTip) {
        self.inner
            .lock()
            .expect("poisoned")
            .insert(peer, (tip, std::time::Instant::now()));
    }

    pub(crate) fn snapshot(&self) -> Vec<(P2pPeerId, PeerTip, std::time::Instant)> {
        self.inner
            .lock()
            .expect("poisoned")
            .iter()
            .map(|(peer, (tip, at))| (peer.clone(), *tip, *at))
            .collect()
    }
}
/// Shared state required to validate and import blocks in a follower generation.
pub(crate) struct FollowerBlockSyncContext<P> {
    pub(crate) provider: P,
    pub(crate) engine: ConsensusEngineHandle<ZonePayloadTypes>,
    pub(crate) l1_block_tracker: L1BlockTracker,
    pub(crate) deposit_queue: DepositQueue,
    pub(crate) attestation: AttestationContext,
    pub(crate) schedule: LeadershipSchedule,
    pub(crate) peer_tips: PeerTipRegistry,
    /// Required for unsettled imports on nodes that may later produce settlement proofs.
    pub(crate) proof_collector: Option<zone_sequencer::ProofCollectorHandle>,
}

/// Live P2P and backfill channels owned by one follower sync generation.
pub(crate) struct BlockSyncP2p {
    pub(crate) events: mpsc::Receiver<P2pEvent>,
    pub(crate) commands: mpsc::Sender<P2pCommand>,
    pub(crate) backfill_responses: mpsc::Receiver<BackfillResponse>,
    pub(crate) backfill_commands: mpsc::Sender<BackfillCommand>,
}

/// State and channels owned by one follower block-sync generation.
///
/// A role transition drops this value only after cancelling [`Self::stop`], so no dependency of
/// the import loop escapes the generation that owns it.
pub(crate) struct FollowerBlockSync<P> {
    context: FollowerBlockSyncContext<P>,
    p2p: BlockSyncP2p,
    stop: sync::CancellationToken,
    pending: PendingBlocks,
    backfill: BackfillProgress,
}

/// Import live/backfilled blocks in canonical order on a follower.
///
/// Live blocks are only imported from the leader when the sender equals
/// `schedule.leader_for(the block's embedded anchor)`. We do this because if there are accidentally
/// two leaders (split brain) for a block, we need to decide to import the correct one.
///
/// Backfilled blocks carry no producer claim and are judged by
/// parent/anchor/execution/conflict validation alone. The loop exits when `stop` fires.
impl<P> FollowerBlockSync<P>
where
    P: BlockNumReader
        + BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + StateProviderFactory
        + ReceiptProvider
        + Clone
        + Send
        + Sync
        + 'static,
{
    pub(crate) fn new(
        context: FollowerBlockSyncContext<P>,
        p2p: BlockSyncP2p,
        stop: sync::CancellationToken,
    ) -> Self {
        Self {
            context,
            p2p,
            stop,
            pending: PendingBlocks::default(),
            backfill: BackfillProgress::new(),
        }
    }

    pub(crate) async fn run(mut self) {
        // Always probe on startup to see if we're behind
        let mut retry = tokio::time::interval(BACKFILL_RETRY_INTERVAL);
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // If we don't get blocks after 30s, probe to get the next block
        let inactivity = tokio::time::sleep(BLOCK_INACTIVITY_TIMEOUT);
        tokio::pin!(inactivity);

        loop {
            tokio::select! {
            biased;
                () = self.stop.cancelled() => {
                    debug!(target: "zone::p2p", "Follower block sync stopped");
                    return;
                }
                response = self.p2p.backfill_responses.recv() => {
                    let Some(response) = response else {
                        debug!(target: "zone::p2p", "Backfill response channel closed");
                        return;
                    };
                    match response {
                        BackfillResponse::Block { block, .. } => {
                            let block = match decode_peer_block(&block) {
                                Ok(block) => block,
                                Err(err) => {
                                    tracing::error!(target: "zone::p2p", %err, "Rejected malformed peer block");
                                    continue;
                                }
                            };
                            inactivity
                                .as_mut()
                                .reset(tokio::time::Instant::now() + BLOCK_INACTIVITY_TIMEOUT);
                            if !self.process_follower_block(block, None).await
                            {
                                return;
                            }
                        }
                        BackfillResponse::Completed { peer, tip } => {
                            self.context.peer_tips.record(peer.clone(), tip);
                            let best = match self.context.provider.best_block_number() {
                                Ok(best) => best,
                                Err(err) => {
                                    tracing::error!(target: "zone::p2p", %err, "Failed reading local head after backfill response");
                                    continue;
                                }
                            };
                            self.backfill.complete(
                                tip.zone_height,
                                best,
                                self.pending.first_number(),
                            );
                            debug!(target: "zone::p2p", %peer, best, tip_height = tip.zone_height, tip_hash = ?tip.zone_hash, backfill_needed = self.backfill.needed, "Completed block backfill response page");
                        }
                    }
                }
                event = self.p2p.events.recv() => {
                    let Some(event) = event else {
                        debug!(target: "zone::p2p", "P2P event channel closed");
                        return;
                    };
                    match event {
                        P2pEvent::Started { .. } => {}
                        P2pEvent::SettlementProposalReceived { leader, proposal } => {
                            match self.handle_settlement_proposal(&leader, proposal).await {
                                Ok(height) => info!(target: "zone::p2p", %leader, height, "Signed settlement proposal"),
                                Err(err) => tracing::warn!(target: "zone::p2p", %leader, %err, "Rejected settlement proposal"),
                            }
                        }
                        P2pEvent::BlockReceived { leader_ed25519_public_key, block } => {
                            let block = match decode_peer_block(&block) {
                                Ok(block) => block,
                                Err(err) => {
                                    tracing::error!(target: "zone::p2p", %err, "Rejected malformed peer block");
                                    continue;
                                }
                            };
                            let live_sender = Some(leader_ed25519_public_key);
                            inactivity
                                .as_mut()
                                .reset(tokio::time::Instant::now() + BLOCK_INACTIVITY_TIMEOUT);
                            if !self.process_follower_block(block, live_sender).await
                            {
                                return;
                            }
                        }
                        P2pEvent::TransactionReceived { .. } => {
                            debug!(target: "zone::p2p", "Ignoring unexpected transaction event in follower block sync");
                        }
                        P2pEvent::SettlementSignatureReceived { .. } => {
                            debug!(target: "zone::p2p", "Ignoring leader-only attestation event on follower");
                        }
                    }
                }
                _ = retry.tick(), if self.backfill.needed => {
                    let best = match self.context.provider.best_block_number() {
                        Ok(best) => best,
                        Err(err) => {
                            tracing::error!(target: "zone::p2p", %err, "Failed reading local head for backfill request");
                            continue;
                        }
                    };

                    // retry the backfill
                    if let Some(command) = self.backfill.request(best)
                        && self.p2p.backfill_commands.send(command).await.is_err()
                    {
                        debug!(target: "zone::p2p", "P2P command channel closed");
                        return;
                    }
                }
                _ = &mut inactivity, if !self.backfill.needed => {
                    // Reset before reading the provider so a transient provider error cannot leave an
                    // elapsed sleep continuously ready and spin this loop.
                    inactivity
                        .as_mut()
                        .reset(tokio::time::Instant::now() + BLOCK_INACTIVITY_TIMEOUT);
                    let best = match self.context.provider.best_block_number() {
                        Ok(best) => best,
                        Err(err) => {
                            tracing::error!(target: "zone::p2p", %err, "Failed reading local head for inactivity backfill probe");
                            continue;
                        }
                    };
                    let command = self.backfill.probe_after_inactivity(best);
                    info!(target: "zone::p2p", best, "No peer block received recently; probing for backfill");
                    if self.p2p.backfill_commands.send(command).await.is_err() {
                        debug!(target: "zone::p2p", "P2P command channel closed");
                        return;
                    }
                }
            }
        }
    }

    async fn handle_settlement_proposal(
        &self,
        leader: &P2pPeerId,
        proposal: Vec<u8>,
    ) -> eyre::Result<u64> {
        let proposal = SettlementAttestation::decode(&proposal)?;
        let height: u64 = proposal
            .zoneHeight
            .try_into()
            .wrap_err("settlement height does not fit in u64")?;
        let persisted_head = self
            .context
            .provider
            .last_block_number()
            .wrap_err("failed reading persisted zone head")?;
        eyre::ensure!(
            height <= persisted_head,
            "settlement proposal at height {height} is not durable; persisted head is {persisted_head}"
        );
        let verifier_mode = VerifierMode::try_from(proposal.verifierConfigHash)?;
        let expected = build_settlement_attestation(
            &self.context.provider,
            height,
            &self.context.attestation,
            (proposal.anchorBlockNumber, proposal.anchorBlockHash),
            verifier_mode,
        )
        .await?
        .ok_or_eyre("proposed block is not a batch boundary")?;
        eyre::ensure!(
            proposal == expected,
            "settlement proposal does not match follower state"
        );

        // Unreachable on an rpc-only member: the P2P layer never routes a proposal to one.
        // Fails closed rather than panicking if it ever does.
        let signer = self.context.attestation.signer.as_ref().ok_or_eyre(
            "this node holds no individual secp256k1 key, so it cannot sign a settlement attestation",
        )?;
        let signed =
            SignedSettlementAttestation::sign(proposal, self.context.attestation.domain, signer)?;

        // During a scheduled handoff, return the attestation to the outgoing leader that
        // proposed it, rather than the most recently observed leader.
        self.p2p
            .commands
            .send(P2pCommand::SendSettlementSignature {
                leader: leader.clone(),
                signature: signed.encode(),
            })
            .await
            .wrap_err("P2P command channel closed")?;
        Ok(height)
    }

    async fn process_follower_block(
        &mut self,
        block: PeerBlock,
        live_sender: Option<P2pPeerId>,
    ) -> bool {
        let number = block.block.header.number();
        let best = match self.context.provider.best_block_number() {
            Ok(best) => best,
            Err(err) => {
                tracing::error!(target: "zone::p2p", %err, "Failed reading local head");
                return true;
            }
        };
        let peer_block = PendingPeerBlock { block, live_sender };
        if number <= best {
            match self.import_peer_block(peer_block).await {
                Ok(PeerBlockImportOutcome::Cancelled) => return false,
                Ok(PeerBlockImportOutcome::TimedOut { .. }) => {
                    tracing::warn!(target: "zone::p2p", "Dropping peer block whose L1 anchor was not observed before the import deadline");
                }
                Ok(PeerBlockImportOutcome::Imported) => {}
                Err(err) => {
                    tracing::error!(target: "zone::p2p", %err, "Rejected duplicate or conflicting peer block");
                }
            }
            return true;
        }
        self.backfill.observe_block(number, best);
        if let Some(dropped) = self.pending.insert(number, peer_block) {
            tracing::warn!(target: "zone::p2p", dropped, pending_limit = MAX_PENDING_BLOCKS, "Dropped far-future peer block because the pending block buffer is full");
        }
        if number > best.saturating_add(1) {
            info!(target: "zone::p2p", local_head = best, received = number, "Detected zone block gap; requesting backfill");
        }
        match self.import_pending_blocks().await {
            Ok(PeerBlockImportOutcome::Cancelled) => return false,
            Ok(PeerBlockImportOutcome::TimedOut {
                block_number,
                anchor,
            }) => {
                tracing::warn!(target: "zone::p2p", block_number, anchor_number = anchor.number, anchor_hash = ?anchor.hash, "Dropping peer block whose L1 anchor was not observed before the import deadline");
                self.backfill.needed = true;
            }
            Ok(PeerBlockImportOutcome::Imported) => {
                let best = match self.context.provider.best_block_number() {
                    Ok(best) => best,
                    Err(err) => {
                        tracing::error!(target: "zone::p2p", %err, "Failed reading local head after importing peer blocks");
                        return true;
                    }
                };
                self.backfill
                    .refresh_after_import(best, self.pending.first_number());
            }
            Err(err) => {
                tracing::error!(target: "zone::p2p", %err, "Rejected peer block while importing pending blocks");
                self.backfill.needed = true;
            }
        }
        true
    }

    async fn import_pending_blocks(&mut self) -> eyre::Result<PeerBlockImportOutcome> {
        loop {
            let head = self.context.provider.best_block_number()?;
            let Some(block) = self.pending.take_next_after(head) else {
                return Ok(PeerBlockImportOutcome::Imported);
            };
            self.import_peer_block(block).await?;
        }
    }

    async fn import_peer_block(
        &self,
        peer_block: PendingPeerBlock,
    ) -> eyre::Result<PeerBlockImportOutcome> {
        let block = SealedBlock::seal_slow(peer_block.block.block);
        let block_number = block.number();
        let hash = block.hash();
        let best_block = self.context.provider.best_block_number()?;
        let tempo_import = decode_advance_tempo(&block)?;

        // 1. Block number is correct
        if block_number <= best_block {
            let existing = self
                .context
                .provider
                .sealed_header(block_number)?
                .ok_or_else(|| {
                    eyre::eyre!("missing local canonical header at height {block_number}")
                })?;
            if existing.hash() == hash {
                // This path bypasses `new_payload`, so verify the peer-supplied body against the
                // canonical header before deriving queue mutations from it.
                block.ensure_transaction_root_valid()?;
                reconcile_canonical_import(&self.context.deposit_queue, &tempo_import)
                    .wrap_err_with(|| {
                        format!("cannot reconcile duplicate canonical peer block {block_number}")
                    })?;
                debug!(target: "zone::p2p", block_number, ?hash, "Ignoring duplicate peer block");
                return Ok(PeerBlockImportOutcome::Imported);
            }
            eyre::bail!(
                "peer block conflicts with canonical block at height {block_number}: local={}, received={hash}",
                existing.hash()
            );
        }

        let expected_number = best_block.saturating_add(1);
        if block_number != expected_number {
            eyre::bail!(
                "peer block gap: local head is {best_block}, received height {block_number}, expected {expected_number}"
            );
        }

        // 2. Block's parent hash is correct
        let parent = self
            .context
            .provider
            .sealed_header(best_block)?
            .ok_or_else(|| eyre::eyre!("missing local canonical head at height {best_block}"))?;
        if block.parent_hash() != parent.hash() {
            eyre::bail!(
                "peer block parent mismatch at height {block_number}: local={}, received={}",
                parent.hash(),
                block.parent_hash()
            );
        }

        // 3. Require the block to import a non-empty contiguous L1 header range
        // beginning immediately after the local Tempo checkpoint.
        let local = self
            .context
            .provider
            .state_by_block_hash(parent.hash())?
            .tempo_num_hash()?;
        let headers = tempo_import.headers();
        validate_l1_checkpoint_range(headers, local.number, local.hash, block_number)?;
        let anchor = headers.last().expect("validated nonempty range").num_hash();
        let leader_anchor = tempo_import.leader_anchor()?;

        // The subscriber enqueues each L1 block before publishing its observation, and observations
        // are contiguous. Seeing the final anchor therefore guarantees that the queue contains the
        // complete imported range.
        match wait_for_peer_anchor(
            &self.context.l1_block_tracker,
            anchor,
            block_number,
            &self.stop,
            PEER_ANCHOR_WAIT_TIMEOUT,
        )
        .await
        {
            Ok(()) => {}
            Err(PeerAnchorWaitError::Cancelled) => {
                return Ok(PeerBlockImportOutcome::Cancelled);
            }
            Err(PeerAnchorWaitError::TimedOut {
                block_number,
                anchor,
            }) => {
                return Ok(PeerBlockImportOutcome::TimedOut {
                    block_number,
                    anchor,
                });
            }
            Err(PeerAnchorWaitError::Other(error)) => return Err(error),
        }
        // Resolve live production authority after observing the imported range, which may publish
        // the leadership transition governing its first header. The schedule includes forced
        // recovery overrides. Backfilled blocks carry no producer claim.
        validate_live_block_sender(
            &self.context.schedule,
            peer_block.live_sender.as_ref(),
            leader_anchor,
            block_number,
        )?;

        if let DecodedTempoImport::Full {
            deposits,
            enabled_tokens,
            ..
        } = &tempo_import
        {
            validate_full_portal_inputs(
                &self.context.deposit_queue,
                anchor,
                deposits,
                enabled_tokens,
            )
            .wrap_err_with(|| {
                format!("peer block {block_number} does not match observed portal events")
            })?;
        }

        // Bind the received witness to this block. Its contents are trusted here; execution
        // still goes through the normal engine, without an additional stateless replay.
        if let Some(proof) = &peer_block.block.witness {
            eyre::ensure!(
                proof.witness.block_number == block_number
                    && proof.witness.block_hash == hash
                    && proof.witness.parent_hash == parent.hash(),
                "peer witness does not match block and canonical parent"
            );
        }

        // 4. All txns in the block execute properly
        validate_block_timestamp(block.header().timestamp_millis(), SystemTime::now())?;
        let payload = ZonePayloadTypes::block_to_payload(block, None);
        let status = self.context.engine.new_payload(payload).await?;
        if !status.is_valid() {
            eyre::bail!("execution engine rejected peer block {block_number} ({hash}): {status:?}");
        }

        // Peers without a stored witness still send plain blocks. Preserve local collection
        // for them; supplied witnesses are persisted directly. Both paths precede canonicalization.
        if let Some(collector) = &self.context.proof_collector {
            self.stop
                .run_until_cancelled(async {
                    match peer_block.block.witness {
                        Some(proof) => collector.persist_received(proof).await,
                        None => collector
                            .collect_and_persist(block_number, hash)
                            .await
                            .map(|_| ()),
                    }
                })
                .await
                .ok_or_else(|| eyre::eyre!("follower stopped while persisting peer witness"))?
                .wrap_err_with(|| {
                    format!("persist witness before importing Zone block {block_number}")
                })?;
        }

        // 5. Forkchoice
        let forkchoice = ForkchoiceState::same_hash(hash);
        let result = self
            .context
            .engine
            .fork_choice_updated(forkchoice, None)
            .await?;
        if !result.is_valid() {
            eyre::bail!(
                "execution engine rejected forkchoice for block {block_number} ({hash}): {result:?}"
            );
        }

        // Mirror the leader engine only after the block is canonical locally. The block cannot be
        // un-imported at this point, so the observation must be released unconditionally — leaving it
        // behind would stall the subscriber once the lookahead window fills. Advancing the queue is
        // likewise tolerant of drift; it fails only on a genuine hash conflict.
        self.context.l1_block_tracker.prune_through(anchor.number);
        match &tempo_import {
            DecodedTempoImport::CheckpointOnly { .. } => self
                .context
                .deposit_queue
                .defer_through(anchor)
                .wrap_err_with(|| {
                    format!("cannot defer checkpoint work from block {block_number}")
                })?,
            DecodedTempoImport::Full { .. } => self
                .context
                .deposit_queue
                .confirm_operational_through(anchor)
                .wrap_err_with(|| {
                    format!("cannot advance the deposit queue past block {block_number}")
                })?,
        }
        self.context.schedule.record_applied_anchor(anchor.number);

        info!(target: "zone::p2p", block_number, ?hash, "Imported canonical peer block");
        Ok(PeerBlockImportOutcome::Imported)
    }
}

fn validate_live_block_sender(
    schedule: &LeadershipSchedule,
    live_sender: Option<&P2pPeerId>,
    anchor_number: u64,
    block_number: u64,
) -> eyre::Result<()> {
    let Some(sender) = live_sender else {
        return Ok(());
    };
    match schedule.leader_for(anchor_number) {
        Some(record) if &record.leader == sender => Ok(()),
        Some(record) => {
            eyre::bail!(
                "live block {block_number} for anchor {anchor_number} was broadcast by {sender}, but \
                 the schedule assigns that anchor to {} (epoch {})",
                record.leader,
                record.epoch,
            );
        }
        None => {
            eyre::bail!(
                "live block {block_number} embeds anchor {anchor_number} which no retained leadership \
                 record governs",
            );
        }
    }
}

fn reconcile_canonical_import(
    deposit_queue: &DepositQueue,
    tempo_import: &DecodedTempoImport,
) -> eyre::Result<()> {
    let anchor = tempo_import
        .headers()
        .last()
        .expect("decoded Tempo imports are nonempty")
        .num_hash();
    match tempo_import {
        DecodedTempoImport::CheckpointOnly { .. } => deposit_queue.defer_through(anchor),
        DecodedTempoImport::Full { .. } => deposit_queue.confirm_operational_through(anchor),
    }
}

fn validate_full_portal_inputs(
    deposit_queue: &DepositQueue,
    anchor: NumHash,
    deposits: &[zone_payload::abi::QueuedDeposit],
    enabled_tokens: &[zone_payload::abi::EnabledToken],
) -> eyre::Result<()> {
    let work = deposit_queue.operational_work(anchor)?;
    let mut deposit_offset = 0usize;
    let mut token_offset = 0usize;
    for block in work {
        let next_deposit_offset = deposit_offset
            .checked_add(block.events.deposits.len())
            .ok_or_else(|| eyre::eyre!("advanceTempo deposit count overflow"))?;
        let next_token_offset = token_offset
            .checked_add(block.events.enabled_tokens.len())
            .ok_or_else(|| eyre::eyre!("advanceTempo token count overflow"))?;
        eyre::ensure!(
            next_deposit_offset <= deposits.len() && next_token_offset <= enabled_tokens.len(),
            "advanceTempo calldata is shorter than the deferred portal event range"
        );
        block.events.validate_advance_tempo_inputs(
            &deposits[deposit_offset..next_deposit_offset],
            &enabled_tokens[token_offset..next_token_offset],
        )?;
        deposit_offset = next_deposit_offset;
        token_offset = next_token_offset;
    }
    eyre::ensure!(
        deposit_offset == deposits.len(),
        "advanceTempo contains {} deposits, but observed portal events contain {deposit_offset}",
        deposits.len()
    );
    eyre::ensure!(
        token_offset == enabled_tokens.len(),
        "advanceTempo contains {} token enables, but observed portal events contain {token_offset}",
        enabled_tokens.len()
    );
    Ok(())
}

async fn wait_for_peer_anchor(
    l1_block_tracker: &L1BlockTracker,
    anchor: NumHash,
    block_number: u64,
    stop: &sync::CancellationToken,
    wait_timeout: Duration,
) -> Result<(), PeerAnchorWaitError> {
    tokio::select! {
        biased;
        () = stop.cancelled() => Err(PeerAnchorWaitError::Cancelled),
        observed = tokio::time::timeout(
            wait_timeout,
            l1_block_tracker.wait_for(anchor),
        ) => match observed {
            Ok(observed) => observed.map_err(PeerAnchorWaitError::Other),
            Err(_) => Err(PeerAnchorWaitError::TimedOut {
                block_number,
                anchor,
            }),
        },
    }
}

#[cfg(test)]
async fn wait_for_validated_peer_anchor(
    l1_block_tracker: &L1BlockTracker,
    schedule: &LeadershipSchedule,
    portal_inputs: &AdvanceTempoPortalInputs,
    live_sender: Option<&P2pPeerId>,
    anchor: NumHash,
    block_number: u64,
    stop: &sync::CancellationToken,
    wait_timeout: Duration,
) -> Result<L1PortalEvents, PeerAnchorWaitError> {
    wait_for_peer_anchor(l1_block_tracker, anchor, block_number, stop, wait_timeout).await?;
    let observed = l1_block_tracker
        .wait_for_portal_events(anchor)
        .await
        .map_err(PeerAnchorWaitError::Other)?;
    portal_inputs
        .validate(&observed)
        .map_err(PeerAnchorWaitError::Other)?;

    // The L1 subscriber publishes any transition finalized by this anchor before recording the
    // anchor in the tracker. Re-read the schedule now so the pre-wait decision cannot authorize a
    // sender that this anchor demoted.
    validate_live_block_sender(schedule, live_sender, anchor.number, block_number)
        .map_err(PeerAnchorWaitError::Other)?;
    Ok(observed)
}

#[derive(Debug)]
enum PeerBlockImportOutcome {
    Imported,
    Cancelled,
    TimedOut { block_number: u64, anchor: NumHash },
}

#[derive(Debug)]
enum PeerAnchorWaitError {
    Cancelled,
    TimedOut { block_number: u64, anchor: NumHash },
    Other(eyre::Report),
}

#[cfg(test)]
struct AdvanceTempoPortalInputs {
    deposits: Vec<zone_payload::abi::QueuedDeposit>,
    enabled_tokens: Vec<zone_payload::abi::EnabledToken>,
}

#[cfg(test)]
impl AdvanceTempoPortalInputs {
    fn validate(&self, observed: &L1PortalEvents) -> eyre::Result<()> {
        observed.validate_advance_tempo_inputs(&self.deposits, &self.enabled_tokens)
    }
}

fn validate_l1_checkpoint_range(
    headers: &[SealedHeader<TempoHeader>],
    local_number: u64,
    local_hash: B256,
    zone_block_number: u64,
) -> eyre::Result<()> {
    if headers.is_empty() {
        eyre::bail!("peer block imports no Tempo headers");
    }
    let mut previous_number = local_number;
    let mut previous_hash = local_hash;
    for l1_header in headers {
        if l1_header.number() != previous_number.saturating_add(1) {
            eyre::bail!(
                "peer block {zone_block_number} advances Tempo to L1 block {}, but local checkpoint is {}; expected {}",
                l1_header.number(),
                previous_number,
                previous_number.saturating_add(1)
            );
        }
        if l1_header.parent_hash() != previous_hash {
            eyre::bail!(
                "advanceTempo L1 header {} does not extend the local Tempo checkpoint: embedded parent {}, local hash {}",
                l1_header.number(),
                l1_header.parent_hash(),
                previous_hash
            );
        }
        previous_number = l1_header.number();
        previous_hash = l1_header.hash();
    }
    Ok(())
}

#[cfg(test)]
fn validate_l1_checkpoint_transition(
    header: &SealedHeader<TempoHeader>,
    local_number: u64,
    local_hash: B256,
    zone_block_number: u64,
) -> eyre::Result<()> {
    validate_l1_checkpoint_range(
        core::slice::from_ref(header),
        local_number,
        local_hash,
        zone_block_number,
    )
}

/// Decode the L1 header embedded in the first `IZoneInbox.advanceTempo` system transaction.
#[cfg(test)]
fn decode_advance_tempo_header(
    block: &SealedBlock<Block>,
) -> eyre::Result<SealedHeader<TempoHeader>> {
    decode_advance_tempo(block).map(|import| import.headers().last().unwrap().clone())
}

#[derive(Debug)]
enum DecodedTempoImport {
    Full {
        header: Box<SealedHeader<TempoHeader>>,
        deposits: Vec<zone_payload::abi::QueuedDeposit>,
        enabled_tokens: Vec<zone_payload::abi::EnabledToken>,
    },
    CheckpointOnly {
        headers: Vec<SealedHeader<TempoHeader>>,
    },
}

impl DecodedTempoImport {
    fn headers(&self) -> &[SealedHeader<TempoHeader>] {
        match self {
            Self::Full { header, .. } => core::slice::from_ref(header),
            Self::CheckpointOnly { headers } => headers,
        }
    }

    /// Tempo anchor whose leader must produce this Zone block.
    ///
    /// The first imported header selects the leader even if later headers cross a handoff.
    fn leader_anchor(&self) -> eyre::Result<u64> {
        self.headers()
            .first()
            .map(|header| header.number())
            .ok_or_eyre("empty Tempo import has no leader anchor")
    }
}

fn decode_advance_tempo(block: &SealedBlock<Block>) -> eyre::Result<DecodedTempoImport> {
    // Do some basic checks

    // 1. `advanceTempo` is the first tx
    let first_tx = block.body().transactions().next().ok_or_else(|| {
        eyre::eyre!("peer block has no transactions; expected an advanceTempo system tx")
    })?;
    let TempoTxEnvelope::Legacy(signed) = first_tx else {
        eyre::bail!("first transaction in peer block is not a legacy system transaction");
    };
    eyre::ensure!(
        first_tx.is_system_tx(),
        "first transaction in peer block is not a Tempo system transaction"
    );

    // 2. Address is correct
    eyre::ensure!(
        signed.tx().to == ZONE_INBOX_ADDRESS.into(),
        "first Tempo system transaction is not sent to IZoneInbox"
    );
    if signed
        .tx()
        .input
        .starts_with(&IZoneInbox::advanceTempoHeadersCall::SELECTOR)
    {
        eyre::ensure!(
            block.transaction_count() == 1,
            "advanceTempoHeaders must be the only transaction in its block"
        );
        let call = IZoneInbox::advanceTempoHeadersCall::abi_decode(signed.tx().input.as_ref())?;
        eyre::ensure!(
            call.headers.len() <= MAX_TEMPO_HEADERS_PER_ZONE_BLOCK,
            "advanceTempoHeaders has too many headers"
        );
        let mut headers = Vec::with_capacity(call.headers.len());
        for encoded in call.headers {
            let mut input = encoded.as_ref();
            let header = TempoHeader::decode(&mut input)?;
            if !input.is_empty() {
                eyre::bail!("advanceTempoHeaders header has trailing bytes");
            }
            headers.push(SealedHeader::seal_slow(header));
        }
        return Ok(DecodedTempoImport::CheckpointOnly { headers });
    }
    let call = IZoneInbox::advanceTempoCall::abi_decode_with_config(
        signed.tx().input.as_ref(),
        abi_decoder_config_for_spec(TempoHardfork::latest()),
    )
    .map_err(|err| eyre::eyre!("first transaction does not decode as advanceTempo: {err}"))?;

    // 3. the system tx is valid.
    let mut header_rlp = call.header.as_ref();
    let header = TempoHeader::decode(&mut header_rlp)
        .map_err(|err| eyre::eyre!("invalid RLP-encoded L1 header in advanceTempo: {err}"))?;
    eyre::ensure!(
        header_rlp.is_empty(),
        "advanceTempo L1 header has {} trailing bytes",
        header_rlp.len()
    );
    Ok(DecodedTempoImport::Full {
        header: Box::new(SealedHeader::seal_slow(header)),
        deposits: call.deposits,
        enabled_tokens: call.enabledTokens,
    })
}

/// Reject peer blocks too far ahead of the local clock before they reach `newPayload`.
fn validate_block_timestamp(timestamp_millis: u64, now: SystemTime) -> eyre::Result<()> {
    let now_millis = now.duration_since(UNIX_EPOCH)?.as_millis();
    eyre::ensure!(
        u128::from(timestamp_millis) <= now_millis + 100,
        "block timestamp {timestamp_millis} exceeds local clock {now_millis} by more than 100 ms"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_eips::NumHash;
    use alloy_primitives::{Address, B256};
    use tokio_util::sync;
    use zone_l1::{DepositQueue, EnabledToken, L1BlockDeposits, L1BlockTracker, L1PortalEvents};
    use zone_p2p::{BackfillCommand, LeadershipSchedule, LeadershipState};

    use super::*;

    #[test]
    fn decodes_advance_tempo_header_from_first_system_tx() {
        use alloy_consensus::BlockHeader as _;
        use reth_primitives_traits::{SealedBlock, SealedHeader};
        use tempo_primitives::{Block, TempoHeader};

        let l1_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 7,
                parent_hash: B256::repeat_byte(0x42),
                ..Default::default()
            },
            ..Default::default()
        };
        let prepared = zone_l1::PreparedL1Block {
            header: SealedHeader::seal_slow(l1_header),
            queued_deposits: vec![],
            decryptions: vec![],
            enabled_tokens: vec![],
            follows_checkpoint_blocks: false,
        };
        let tx = zone_payload::build_advance_tempo_tx(&prepared, 1337);
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: alloy_consensus::BlockBody {
                transactions: vec![tx.into_inner()],
                ommers: vec![],
                withdrawals: None,
            },
        });

        let decoded = decode_advance_tempo_header(&block).unwrap();
        assert_eq!(decoded.number(), 7);
        assert_eq!(decoded.parent_hash(), B256::repeat_byte(0x42));
        assert_eq!(decoded.hash(), prepared.header.hash());
    }

    #[test]
    fn rejects_advance_tempo_sent_to_wrong_contract() {
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_primitives::{Address, U256};
        use alloy_sol_types::SolCall as _;
        use reth_primitives_traits::SealedBlock;
        use tempo_primitives::{
            Block, TempoHeader, TempoTxEnvelope, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
        };

        let calldata = zone_payload::abi::IZoneInbox::advanceTempoCall {
            header: alloy_rlp::encode(TempoHeader::default()).into(),
            deposits: vec![],
            decryptions: vec![],
            enabledTokens: vec![],
        }
        .abi_encode();
        let tx = TxLegacy {
            chain_id: None,
            nonce: 0,
            gas_price: 0,
            gas_limit: 100_000,
            to: Address::repeat_byte(0x99).into(),
            value: U256::ZERO,
            input: calldata.into(),
        };
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: alloy_consensus::BlockBody {
                transactions: vec![TempoTxEnvelope::Legacy(Signed::new_unhashed(
                    tx,
                    TEMPO_SYSTEM_TX_SIGNATURE,
                ))],
                ommers: vec![],
                withdrawals: None,
            },
        });

        let error = decode_advance_tempo(&block).unwrap_err();
        assert!(error.to_string().contains("IZoneInbox"));
    }

    #[test]
    fn rejects_block_without_advance_tempo() {
        use reth_primitives_traits::SealedBlock;
        use tempo_primitives::{Block, TempoHeader};

        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: alloy_consensus::BlockBody {
                transactions: vec![],
                ommers: vec![],
                withdrawals: None,
            },
        });

        let error = decode_advance_tempo(&block).unwrap_err();
        assert!(error.to_string().contains("no transactions"));
    }

    #[test]
    fn rejects_non_system_advance_tempo_transaction() {
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_primitives::Signature;
        use reth_primitives_traits::{SealedBlock, SealedHeader};
        use tempo_primitives::{Block, TempoHeader, TempoTxEnvelope};

        let prepared = zone_l1::PreparedL1Block {
            header: SealedHeader::seal_slow(TempoHeader::default()),
            queued_deposits: vec![],
            decryptions: vec![],
            enabled_tokens: vec![],
            follows_checkpoint_blocks: false,
        };
        let TempoTxEnvelope::Legacy(system_tx) =
            zone_payload::build_advance_tempo_tx(&prepared, 1337).into_inner()
        else {
            unreachable!("advanceTempo builder must produce a legacy transaction")
        };
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: alloy_consensus::BlockBody {
                transactions: vec![TempoTxEnvelope::Legacy(Signed::<TxLegacy>::new_unhashed(
                    system_tx.tx().clone(),
                    Signature::test_signature(),
                ))],
                ommers: vec![],
                withdrawals: None,
            },
        });

        let error = decode_advance_tempo(&block).unwrap_err();
        assert!(error.to_string().contains("not a Tempo system transaction"));
    }

    #[test]
    fn rejects_malformed_advance_tempo_calldata() {
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_primitives::{Bytes, U256};
        use reth_primitives_traits::SealedBlock;
        use tempo_primitives::{
            Block, TempoHeader, TempoTxEnvelope, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
        };

        let tx = TxLegacy {
            to: zone_payload::abi::ZONE_INBOX_ADDRESS.into(),
            value: U256::ZERO,
            input: Bytes::from_static(b"not advanceTempo calldata"),
            ..Default::default()
        };
        let block = SealedBlock::seal_slow(Block {
            header: TempoHeader::default(),
            body: alloy_consensus::BlockBody {
                transactions: vec![TempoTxEnvelope::Legacy(Signed::new_unhashed(
                    tx,
                    TEMPO_SYSTEM_TX_SIGNATURE,
                ))],
                ommers: vec![],
                withdrawals: None,
            },
        });

        let error = decode_advance_tempo(&block).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not decode as advanceTempo")
        );
    }

    #[test]
    fn rejects_malformed_or_trailing_advance_tempo_header_rlp() {
        use alloy_consensus::{Signed, TxLegacy};
        use alloy_primitives::{Bytes, U256};
        use alloy_sol_types::SolCall as _;
        use reth_primitives_traits::SealedBlock;
        use tempo_primitives::{
            Block, TempoHeader, TempoTxEnvelope, transaction::envelope::TEMPO_SYSTEM_TX_SIGNATURE,
        };

        let make_block = |header: Vec<u8>| {
            let calldata = zone_payload::abi::IZoneInbox::advanceTempoCall {
                header: Bytes::from(header),
                deposits: vec![],
                decryptions: vec![],
                enabledTokens: vec![],
            }
            .abi_encode();
            let tx = TxLegacy {
                to: zone_payload::abi::ZONE_INBOX_ADDRESS.into(),
                value: U256::ZERO,
                input: calldata.into(),
                ..Default::default()
            };
            SealedBlock::seal_slow(Block {
                header: TempoHeader::default(),
                body: alloy_consensus::BlockBody {
                    transactions: vec![TempoTxEnvelope::Legacy(Signed::new_unhashed(
                        tx,
                        TEMPO_SYSTEM_TX_SIGNATURE,
                    ))],
                    ommers: vec![],
                    withdrawals: None,
                },
            })
        };

        let malformed = make_block(vec![0xff]);
        let error = decode_advance_tempo(&malformed).unwrap_err();
        assert!(error.to_string().contains("invalid RLP-encoded L1 header"));

        let mut trailing = alloy_rlp::encode(TempoHeader::default());
        trailing.push(0x00);
        let trailing = make_block(trailing);
        let error = decode_advance_tempo(&trailing).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn validates_embedded_l1_checkpoint_continuity() {
        use reth_primitives_traits::SealedHeader;
        use tempo_primitives::TempoHeader;

        let local_hash = B256::repeat_byte(0x42);
        let header = SealedHeader::seal_slow(TempoHeader {
            inner: alloy_consensus::Header {
                number: 11,
                parent_hash: local_hash,
                ..Default::default()
            },
            ..Default::default()
        });
        validate_l1_checkpoint_transition(&header, 10, local_hash, 7).unwrap();

        let skipped = validate_l1_checkpoint_transition(&header, 9, local_hash, 7).unwrap_err();
        assert!(skipped.to_string().contains("expected 10"));

        let wrong_parent =
            validate_l1_checkpoint_transition(&header, 10, B256::repeat_byte(0x99), 7).unwrap_err();
        assert!(wrong_parent.to_string().contains("does not extend"));
    }

    #[tokio::test]
    async fn revalidates_live_sender_after_anchor_observation() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

        const ANCHOR_NUMBER: u64 = 10;
        const ZONE_BLOCK_NUMBER: u64 = 7;

        let outgoing = PrivateKey::from_seed(1).public_key();
        let incoming = PrivateKey::from_seed(2).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, outgoing.clone(), 0));
        let tracker = L1BlockTracker::default();
        let anchor = NumHash::new(ANCHOR_NUMBER, B256::repeat_byte(0x10));

        // The sender is valid under the pre-observation schedule.
        validate_live_block_sender(&schedule, Some(&outgoing), ANCHOR_NUMBER, ZONE_BLOCK_NUMBER)
            .unwrap();

        let waiter = {
            let schedule = schedule.clone();
            let tracker = tracker.clone();
            let outgoing = outgoing.clone();
            tokio::spawn(async move {
                let portal_inputs = AdvanceTempoPortalInputs {
                    deposits: vec![],
                    enabled_tokens: vec![],
                };
                wait_for_validated_peer_anchor(
                    &tracker,
                    &schedule,
                    &portal_inputs,
                    Some(&outgoing),
                    anchor,
                    ZONE_BLOCK_NUMBER,
                    &sync::CancellationToken::new(),
                    PEER_ANCHOR_WAIT_TIMEOUT,
                )
                .await
            })
        };

        // Match subscriber ordering: publish the transition finalized by H before H becomes
        // observable to follower import.
        schedule
            .publish(LeadershipState::new(2, incoming.clone(), ANCHOR_NUMBER))
            .unwrap();
        tracker
            .record_with_portal_events(anchor, L1PortalEvents::default())
            .unwrap();

        let error = waiter
            .await
            .expect("anchor waiter must not panic")
            .expect_err("the post-observation sender check must reject the outgoing leader");
        let PeerAnchorWaitError::Other(error) = error else {
            panic!("sender validation must fail as an operational error");
        };
        let message = error.to_string();
        assert!(message.contains(&outgoing.to_string()));
        assert!(message.contains(&incoming.to_string()));
        assert!(message.contains("schedule assigns that anchor"));
    }

    #[tokio::test]
    async fn peer_anchor_wait_stops_promptly_on_generation_cancellation() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

        let leader = PrivateKey::from_seed(1).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, leader, 0));
        let tracker = L1BlockTracker::default();
        let stop = sync::CancellationToken::new();
        stop.cancel();

        let error = wait_for_validated_peer_anchor(
            &tracker,
            &schedule,
            &AdvanceTempoPortalInputs {
                deposits: vec![],
                enabled_tokens: vec![],
            },
            None,
            NumHash::new(10, B256::repeat_byte(0x10)),
            7,
            &stop,
            PEER_ANCHOR_WAIT_TIMEOUT,
        )
        .await
        .expect_err("cancelled generation must stop waiting for its peer anchor");

        assert!(matches!(error, PeerAnchorWaitError::Cancelled));
    }

    #[tokio::test]
    async fn peer_anchor_wait_has_one_finite_deadline() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

        let leader = PrivateKey::from_seed(1).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, leader, 0));
        let tracker = L1BlockTracker::default();

        let error = wait_for_validated_peer_anchor(
            &tracker,
            &schedule,
            &AdvanceTempoPortalInputs {
                deposits: vec![],
                enabled_tokens: vec![],
            },
            None,
            NumHash::new(10, B256::repeat_byte(0x10)),
            7,
            &sync::CancellationToken::new(),
            Duration::from_millis(1),
        )
        .await
        .expect_err("missing peer anchor must reach its import deadline");

        assert!(matches!(error, PeerAnchorWaitError::TimedOut { .. }));
    }

    #[test]
    fn forced_recovery_reassigns_live_sender_for_missing_anchors() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

        let outgoing = PrivateKey::from_seed(1).public_key();
        let incoming = PrivateKey::from_seed(2).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(7, outgoing.clone(), 0));
        schedule
            .install_forced_recovery(8, incoming.clone(), B256::repeat_byte(0x11), 51)
            .unwrap();
        schedule
            .publish(LeadershipState::new(8, incoming.clone(), 60))
            .unwrap();

        validate_live_block_sender(&schedule, Some(&incoming), 51, 11).unwrap();
        let error = validate_live_block_sender(&schedule, Some(&outgoing), 51, 11)
            .expect_err("the crashed leader must not remain authoritative in the recovery window");
        assert!(error.to_string().contains(&incoming.to_string()));
    }

    #[test]
    fn requests_backfill_again_when_live_block_reveals_gap_after_completion() {
        const LOCAL_HEAD: u64 = 10;

        let mut backfill = BackfillProgress::new();
        assert_eq!(
            backfill.request(LOCAL_HEAD),
            Some(BackfillCommand::Request {
                start: LOCAL_HEAD + 1,
            })
        );

        // The first response catches the follower up to the responder's snapshot tip.
        backfill.complete(LOCAL_HEAD, LOCAL_HEAD, None);
        assert_eq!(backfill.request(LOCAL_HEAD), None);

        // N+1's live broadcast is missed, then N+2 arrives and remains buffered behind the gap.
        let live_block = LOCAL_HEAD + 2;
        backfill.observe_block(live_block, LOCAL_HEAD);
        backfill.refresh_after_import(LOCAL_HEAD, Some(live_block));

        // The retry starts at the missing N+1 rather than skipping to the received N+2.
        assert_eq!(
            backfill.request(LOCAL_HEAD),
            Some(BackfillCommand::Request {
                start: LOCAL_HEAD + 1,
            })
        );
    }

    #[test]
    fn inactivity_probe_restarts_backfill_retries() {
        const LOCAL_HEAD: u64 = 10;

        let mut backfill = BackfillProgress::new();
        backfill.complete(LOCAL_HEAD, LOCAL_HEAD, None);
        assert_eq!(backfill.request(LOCAL_HEAD), None);

        assert_eq!(
            backfill.probe_after_inactivity(LOCAL_HEAD),
            BackfillCommand::Request {
                start: LOCAL_HEAD + 1,
            }
        );
        assert_eq!(
            backfill.request(LOCAL_HEAD),
            Some(BackfillCommand::Request {
                start: LOCAL_HEAD + 1,
            })
        );
    }

    #[test]
    fn peer_tip_registry_records_latest_tip() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
        use zone_p2p::PeerTip;

        let registry = PeerTipRegistry::default();

        let peer = PrivateKey::from_seed(1).public_key();
        let tip = PeerTip {
            zone_height: 7,
            zone_hash: B256::repeat_byte(0x07),
            tempo_block_number: 11,
            tempo_block_hash: B256::repeat_byte(0x11),
        };
        registry.record(peer.clone(), tip);

        // Re-advertising the same tip refreshes its observation timestamp.
        registry.record(peer.clone(), tip);
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, peer);
        assert_eq!(snapshot[0].1, tip);
    }

    fn pending_block(number: u64) -> PendingPeerBlock {
        PendingPeerBlock {
            block: crate::replication::PeerBlock {
                witness: None,
                block: Block {
                    header: TempoHeader {
                        inner: alloy_consensus::Header {
                            number,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                },
            },
            live_sender: None,
        }
    }

    #[test]
    fn pending_block_limit_keeps_blocks_closest_to_local_head() {
        let mut pending = PendingBlocks::default();
        for number in 100..100 + MAX_PENDING_BLOCKS as u64 {
            assert_eq!(pending.insert(number, pending_block(number)), None);
        }
        assert_eq!(pending.len(), MAX_PENDING_BLOCKS);
        assert_eq!(pending.first_number(), Some(100));

        let farthest = 100 + MAX_PENDING_BLOCKS as u64 - 1;
        assert_eq!(pending.insert(99, pending_block(99)), Some(farthest));
        assert_eq!(pending.len(), MAX_PENDING_BLOCKS);
        assert!(pending.contains(99));
        assert!(!pending.contains(farthest));

        let farther = farthest + 1;
        assert_eq!(
            pending.insert(farther, pending_block(farther)),
            Some(farther)
        );
        assert_eq!(pending.len(), MAX_PENDING_BLOCKS);
        assert!(!pending.contains(farther));

        let next = pending
            .take_next_after(98)
            .expect("the immediately next pending block must be available");
        assert_eq!(next.block.block.header.number(), 99);
        assert_eq!(pending.first_number(), Some(100));
    }
    #[test]
    fn full_import_validates_deferred_and_current_portal_events() {
        let queue = DepositQueue::new();
        let first = SealedHeader::seal_slow(TempoHeader {
            inner: alloy_consensus::Header {
                number: 1,
                ..Default::default()
            },
            ..Default::default()
        });
        let second = SealedHeader::seal_slow(TempoHeader {
            inner: alloy_consensus::Header {
                number: 2,
                parent_hash: first.hash(),
                ..Default::default()
            },
            ..Default::default()
        });
        let alpha = EnabledToken {
            token: Address::repeat_byte(0x11),
            name: "Alpha".into(),
            symbol: "A".into(),
            currency: "USD".into(),
        };
        let beta = EnabledToken {
            token: Address::repeat_byte(0x22),
            name: "Beta".into(),
            symbol: "B".into(),
            currency: "EUR".into(),
        };
        queue
            .try_enqueue_sealed(
                first.clone(),
                L1PortalEvents {
                    enabled_tokens: vec![alpha.clone()],
                    ..Default::default()
                },
            )
            .unwrap();
        queue.defer_through(first.num_hash()).unwrap();
        let current = L1BlockDeposits {
            header: second,
            events: L1PortalEvents {
                enabled_tokens: vec![beta.clone()],
                ..Default::default()
            },
        };
        queue
            .try_enqueue_sealed(current.header.clone(), current.events.clone())
            .unwrap();

        let expected = vec![alpha.to_abi(), beta.to_abi()];
        let anchor = current.header.num_hash();
        validate_full_portal_inputs(&queue, anchor, &[], &expected).unwrap();
        let err = validate_full_portal_inputs(&queue, anchor, &[], &expected[..1]).unwrap_err();
        assert!(err.to_string().contains("shorter"));
    }
    #[test]
    fn checkpoint_live_producer_uses_first_header_leader() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
        use reth_primitives_traits::SealedHeader;
        use tempo_primitives::TempoHeader;

        let outgoing = PrivateKey::from_seed(1).public_key();
        let incoming = PrivateKey::from_seed(2).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, outgoing.clone(), 0));
        schedule
            .publish(LeadershipState::new(2, incoming.clone(), 100))
            .unwrap();

        let headers = (90..=110)
            .map(|number| {
                SealedHeader::seal_slow(TempoHeader {
                    inner: alloy_consensus::Header {
                        number,
                        ..Default::default()
                    },
                    ..Default::default()
                })
            })
            .collect();
        let tempo_import = super::DecodedTempoImport::CheckpointOnly { headers };

        let leader_anchor = tempo_import.leader_anchor().unwrap();
        assert_eq!(leader_anchor, 90);
        validate_live_block_sender(&schedule, Some(&outgoing), leader_anchor, 7).unwrap();
        let error = validate_live_block_sender(&schedule, Some(&incoming), leader_anchor, 7)
            .expect_err("a crossed handoff must not change the catch-up producer");
        assert!(error.to_string().contains(&outgoing.to_string()));

        // Backfill authenticates the chain without attributing authorship to its relay peer.
        validate_live_block_sender(&schedule, None, leader_anchor, 7).unwrap();
        let error = validate_live_block_sender(
            &LeadershipSchedule::uninitialized(),
            Some(&outgoing),
            leader_anchor,
            7,
        )
        .expect_err("a live checkpoint block needs a known leader");
        assert!(error.to_string().contains("no retained leadership record"));

        let full_import = super::DecodedTempoImport::Full {
            header: Box::new(SealedHeader::seal_slow(TempoHeader {
                inner: alloy_consensus::Header {
                    number: 110,
                    ..Default::default()
                },
                ..Default::default()
            })),
            deposits: Vec::new(),
            enabled_tokens: Vec::new(),
        };
        let leader_anchor = full_import.leader_anchor().unwrap();
        assert_eq!(leader_anchor, 110);
        validate_live_block_sender(&schedule, Some(&incoming), leader_anchor, 8).unwrap();
        let error = validate_live_block_sender(&schedule, Some(&outgoing), leader_anchor, 8)
            .expect_err("the final full block must be produced by its effective leader");
        assert!(error.to_string().contains(&incoming.to_string()));
    }

    #[test]
    fn checkpoint_live_producer_respects_forced_recovery() {
        use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

        let historical = PrivateKey::from_seed(1).public_key();
        let recovery = PrivateKey::from_seed(2).public_key();
        let successor = PrivateKey::from_seed(3).public_key();
        let schedule = LeadershipSchedule::seeded(LeadershipState::new(1, historical.clone(), 0));
        schedule
            .install_forced_recovery(2, recovery.clone(), B256::repeat_byte(0x11), 90)
            .unwrap();
        schedule
            .publish(LeadershipState::new(2, successor.clone(), 100))
            .unwrap();

        for (first, expected, rejected) in [
            (90, &recovery, [&historical, &successor]),
            (111, &successor, [&historical, &recovery]),
        ] {
            let headers = (first..=first + 20)
                .map(|number| {
                    SealedHeader::seal_slow(TempoHeader {
                        inner: alloy_consensus::Header {
                            number,
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                })
                .collect();
            let import = DecodedTempoImport::CheckpointOnly { headers };
            let anchor = import.leader_anchor().unwrap();
            validate_live_block_sender(&schedule, Some(expected), anchor, 7).unwrap();
            for sender in rejected {
                let error = validate_live_block_sender(&schedule, Some(sender), anchor, 7)
                    .expect_err("only the effective first-header leader may broadcast");
                assert!(error.to_string().contains(&expected.to_string()));
            }
        }
    }
}
