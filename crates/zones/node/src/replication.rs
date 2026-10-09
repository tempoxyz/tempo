//! Node-side leader replication and role-neutral backfill serving.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::B256;
use alloy_rlp::Decodable as _;
use futures::{StreamExt as _, stream::BoxStream};
use reth_chain_state::PersistedBlockSubscriptions;
use reth_primitives_traits::SealedBlock;
use reth_provider::HeaderProvider;
use reth_storage_api::{BlockNumReader, BlockReader, StateProviderFactory};
use tempo_primitives::{Block, TempoHeader};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync;
use tracing::debug;
use zone_l1::TempoStateExt as _;
use zone_p2p::{BackfillCommand, BackfillRequest, EncodedBlock, P2pCommand, P2pEvent, PeerTip};
use zone_sequencer::{ProofCollectorHandle, SettlementManager, StoredBlockProof};

/// A decoded block and the optional witness supplied by its peer.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PeerBlock {
    pub block: Block,
    pub witness: Option<StoredBlockProof>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PersistedTip {
    number: u64,
    hash: B256,
}

pub(crate) struct EncodedPersistedBlock {
    number: u64,
    hash: B256,
    encoded: Vec<u8>,
}

/// The one shutdown decision the role controller makes for a leader's block broadcaster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BroadcasterShutdown {
    /// The engine has stopped, so wait for its frozen canonical tail to become durable.
    Drain,
    /// The engine stop was not proven; flush only the durable prefix and abandon the rest.
    Stop,
}

/// Interface used by the replication task to keep track of blocks that are persisted vs broadcast
pub(crate) trait PersistedBlockSource: Clone + Send + Sync + 'static {
    fn last_block_number(&self) -> eyre::Result<u64>;
    /// The canonical head, which may be ahead of the persisted head (reth persists lazily).
    ///
    /// This is a drain *target*, never a broadcast height: a canonical-only block lives in
    /// reth's volatile in-memory state and would vanish from this node on restart. Read it only
    /// after the engine has stopped, and publish the blocks it names through the persisted
    /// stream.
    fn canonical_block_number(&self) -> eyre::Result<u64>;
    fn persisted_block_stream(&self) -> BoxStream<'static, PersistedTip>;
    fn encoded_block_by_number(&self, number: u64) -> eyre::Result<EncodedPersistedBlock>;
}

impl<P> PersistedBlockSource for P
where
    P: PersistedBlockSubscriptions + BlockReader<Block = Block> + Clone + Send + Sync + 'static,
{
    fn last_block_number(&self) -> eyre::Result<u64> {
        Ok(BlockNumReader::last_block_number(self)?)
    }

    fn canonical_block_number(&self) -> eyre::Result<u64> {
        Ok(BlockNumReader::best_block_number(self)?)
    }

    fn persisted_block_stream(&self) -> BoxStream<'static, PersistedTip> {
        PersistedBlockSubscriptions::persisted_block_stream(self)
            .map(|tip| PersistedTip {
                number: tip.number,
                hash: tip.hash,
            })
            .boxed()
    }

    fn encoded_block_by_number(&self, number: u64) -> eyre::Result<EncodedPersistedBlock> {
        let block = self
            .block_by_number(number)?
            .ok_or_else(|| eyre::eyre!("persisted zone block {number} is missing"))?;
        let sealed = SealedBlock::seal_slow(block);
        Ok(EncodedPersistedBlock {
            number: sealed.number(),
            hash: sealed.hash(),
            encoded: alloy_rlp::encode(sealed.into_block()),
        })
    }
}

/// Broadcast every newly persisted leader block in canonical order until cancelled.
///
/// A single shutdown command decides how to handle the leader's final block:
///
/// * [`BroadcasterShutdown::Drain`] is the graceful path. The role controller sends it only
///   after the engine task has returned, which freezes the canonical head and lets this task wait
///   for the final block to persist before publishing it.
/// * [`BroadcasterShutdown::Stop`] is the abrupt path. It flushes what is already durable and
///   abandons the rest.
///
/// Neither path ever broadcasts a canonical-only block.
pub(crate) async fn broadcast_persisted_blocks<P>(
    provider: P,
    commands: mpsc::Sender<P2pCommand>,
    mut shutdown: oneshot::Receiver<BroadcasterShutdown>,
    proofs: Option<ProofCollectorHandle>,
) where
    P: PersistedBlockSource,
{
    // Handle race conditions carefully at startup. Read before subscribing, then reconcile after subscribing.
    // This closes both startup windows: a block persisted before the subscription is found by the
    // second read, while a block persisted after the subscription is retained by the stream.
    let mut last_broadcast = match provider.last_block_number() {
        Ok(number) => number,
        Err(err) => {
            tracing::error!(target: "zone::p2p", %err, "Failed reading persisted zone head");
            return;
        }
    };
    let mut persisted = provider.persisted_block_stream();
    let startup_tip = match provider.last_block_number() {
        Ok(number) => number,
        Err(err) => {
            tracing::error!(target: "zone::p2p", %err, "Failed reconciling persisted zone head");
            return;
        }
    };

    if let Err(err) = broadcast_persisted_range(
        &provider,
        &commands,
        &mut last_broadcast,
        startup_tip,
        None,
        proofs.as_ref(),
    )
    .await
    {
        tracing::error!(target: "zone::p2p", %err, "Failed broadcasting persisted zone blocks");
        return;
    }

    loop {
        let persisted_tip = tokio::select! {
            biased;
            command = &mut shutdown => {
                match command {
                    Ok(BroadcasterShutdown::Drain) => {
                        if let Err(err) = drain_persisted_blocks_after_engine_stop(
                            &provider,
                            &commands,
                            &mut last_broadcast,
                            &mut persisted,
                            proofs.as_ref(),
                        )
                        .await
                        {
                            tracing::error!(target: "zone::p2p", %err, "Failed draining persisted zone blocks after the leader engine stopped");
                        }
                    }
                    Ok(BroadcasterShutdown::Stop) => {
                        // Stopped without an engine-complete drain, so the canonical head is
                        // still moving and cannot be a flush target. Publish what is already
                        // durable and abandon the rest: a canonical-only block would disappear
                        // from this node on restart, leaving followers on a height no replica can
                        // serve.
                        match provider.last_block_number() {
                            Ok(persisted_head) => {
                                if let Err(err) = broadcast_persisted_range(
                                    &provider,
                                    &commands,
                                    &mut last_broadcast,
                                    persisted_head,
                                    None,
                                    proofs.as_ref(),
                                )
                                .await
                                {
                                    tracing::error!(target: "zone::p2p", %err, "Failed flushing persisted zone blocks on stop");
                                }
                            }
                            Err(err) => {
                                tracing::error!(target: "zone::p2p", %err, "Failed reading the persisted zone head for the stop flush");
                            }
                        }
                        debug!(target: "zone::p2p", "Persisted block broadcaster stopped");
                    }
                    Err(_) => {
                        debug!(target: "zone::p2p", "Persisted block broadcaster shutdown control dropped");
                    }
                }
                return;
            }
            tip = persisted.next() => match tip {
                Some(tip) => tip,
                None => break,
            },
        };
        if persisted_tip.number < last_broadcast {
            tracing::error!(
                target: "zone::p2p",
                persisted = persisted_tip.number,
                last_broadcast,
                "Persisted zone head moved backwards"
            );
            return;
        }

        if let Err(err) = broadcast_persisted_range(
            &provider,
            &commands,
            &mut last_broadcast,
            persisted_tip.number,
            Some(persisted_tip.hash),
            proofs.as_ref(),
        )
        .await
        {
            tracing::error!(target: "zone::p2p", %err, "Failed broadcasting persisted zone blocks");
            return;
        }
    }
    debug!(target: "zone::p2p", "Persisted block stream closed");
}

/// Publish the outgoing leader's final blocks once they are durable.
///
/// The caller must have observed the engine task return before signalling this, which is what
/// makes the loop terminate: cancelling the generation token is not a block boundary, because an
/// in-flight advance still completes before the engine yields. Only a stopped engine pins the
/// canonical head, and only a pinned target can be waited for.
///
/// Blocks still go out through [`broadcast_persisted_range`] with the hash the persisted stream
/// reported, so the durable-source invariant holds on this path too.
async fn drain_persisted_blocks_after_engine_stop<P>(
    provider: &P,
    commands: &mpsc::Sender<P2pCommand>,
    last_broadcast: &mut u64,
    persisted: &mut BoxStream<'static, PersistedTip>,
    proofs: Option<&ProofCollectorHandle>,
) -> eyre::Result<()>
where
    P: PersistedBlockSource,
{
    let canonical = provider.canonical_block_number()?;
    let persisted_head = provider.last_block_number()?;
    broadcast_persisted_range(
        provider,
        commands,
        last_broadcast,
        persisted_head,
        None,
        proofs,
    )
    .await?;

    while *last_broadcast < canonical {
        let persisted_tip = persisted.next().await.ok_or_else(|| {
            eyre::eyre!("persisted zone block stream closed before the canonical tail persisted")
        })?;
        if persisted_tip.number < *last_broadcast {
            eyre::bail!(
                "persisted zone head moved backwards while draining after the leader engine stopped: persisted={}, last_broadcast={}",
                persisted_tip.number,
                *last_broadcast,
            );
        }
        broadcast_persisted_range(
            provider,
            commands,
            last_broadcast,
            persisted_tip.number,
            Some(persisted_tip.hash),
            proofs,
        )
        .await?;
    }

    debug!(target: "zone::p2p", canonical, broadcast = *last_broadcast, "Drained the canonical tail after the leader engine stopped");
    Ok(())
}

async fn broadcast_persisted_range<P>(
    provider: &P,
    commands: &mpsc::Sender<P2pCommand>,
    last_broadcast: &mut u64,
    tip_number: u64,
    expected_tip_hash: Option<B256>,
    proofs: Option<&ProofCollectorHandle>,
) -> eyre::Result<()>
where
    P: PersistedBlockSource,
{
    for number in last_broadcast.saturating_add(1)..=tip_number {
        let block = provider.encoded_block_by_number(number)?;
        let number = block.number;
        let hash = block.hash;
        if number == tip_number
            && let Some(expected) = expected_tip_hash
            && hash != expected
        {
            eyre::bail!(
                "persisted zone block hash does not match notification at height {number}: expected={expected}, actual={hash}"
            );
        }
        let block = encode_block_with_witness(block.encoded, number, hash, proofs)?;
        commands
            .send(P2pCommand::BroadcastBlock(block))
            .await
            .map_err(|_| eyre::eyre!("P2P command channel closed"))?;
        debug!(target: "zone::p2p", number, ?hash, "Queued persisted block for followers");
        *last_broadcast = number;
    }
    Ok(())
}

fn encode_block_with_witness(
    block: Vec<u8>,
    number: u64,
    hash: B256,
    proofs: Option<&ProofCollectorHandle>,
) -> eyre::Result<EncodedBlock> {
    let witness = if let Some(proofs) = proofs {
        let witness = proofs.get(number, hash);
        eyre::ensure!(
            witness.is_some() || !proofs.requires_witness(number),
            "unsettled block {number} has no retained witness to replicate"
        );
        witness
    } else {
        None
    };
    let witness = witness.as_deref().map(minicbor_serde::to_vec).transpose()?;
    Ok(EncodedBlock { block, witness })
}

// Shared envelope for live blocks and backfill: magic/version, one RLP block, then witness CBOR.
// Settled history and nodes without proof persistence keep using bare RLP blocks.
pub(crate) fn decode_peer_block(encoded: &[u8]) -> eyre::Result<PeerBlock> {
    let witnessed = encoded.starts_with(EncodedBlock::WITNESS_PREFIX);
    let mut input = if witnessed {
        &encoded[EncodedBlock::WITNESS_PREFIX.len()..]
    } else {
        encoded
    };
    let block = Block::decode(&mut input)
        .map_err(|err| eyre::eyre!("invalid RLP-encoded zone block: {err}"))?;
    let witness = if witnessed {
        let mut deserializer = minicbor_serde::Deserializer::from(minicbor::Decoder::new(input));
        let proof = serde::Deserialize::deserialize(&mut deserializer)?;
        input = &input[deserializer.decoder().position()..];
        Some(proof)
    } else {
        None
    };
    eyre::ensure!(
        input.is_empty(),
        "encoded zone block has {} trailing bytes",
        input.len()
    );
    Ok(PeerBlock { block, witness })
}

const BACKFILL_PAGE_SIZE: u64 = 64;
/// Bounds queued requests at the process-lifetime backfill server. Requesters keep at most
/// one request outstanding per peer, so manifest size bounds the live queue depth; the
/// headroom absorbs requests arriving before the server task starts.
pub(crate) const BACKFILL_SERVE_QUEUE_CAPACITY: usize = 128;

fn serve_backfill_page<P>(
    provider: &P,
    commands: &mpsc::Sender<BackfillCommand>,
    peer: zone_p2p::P2pPeerId,
    request_id: u64,
    start: u64,
    proofs: Option<&ProofCollectorHandle>,
) -> eyre::Result<()>
where
    P: BlockNumReader
        + BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + StateProviderFactory,
{
    let tip = provider.last_block_number()?;
    let end = tip.min(start.saturating_add(BACKFILL_PAGE_SIZE.saturating_sub(1)));
    for number in start..=end {
        let block = provider.block_by_number(number)?.ok_or_else(|| {
            eyre::eyre!("persisted canonical block {number} is missing while serving backfill")
        })?;
        let block = encode_block_with_witness(
            alloy_rlp::encode(&block),
            number,
            block.header.hash_slow(),
            proofs,
        )?;
        commands
            .blocking_send(BackfillCommand::SendBlock {
                peer: peer.clone(),
                request_id,
                block,
            })
            .map_err(|_| eyre::eyre!("P2P command channel closed"))?;
    }
    // Advertise the persisted tip.
    let tip_header = provider.sealed_header(tip)?.ok_or_else(|| {
        eyre::eyre!("persisted canonical head {tip} is missing while serving backfill")
    })?;
    let tempo = provider
        .state_by_block_hash(tip_header.hash())?
        .tempo_num_hash()?;
    commands
        .blocking_send(BackfillCommand::Complete {
            peer,
            request_id,
            tip: PeerTip {
                zone_height: tip,
                zone_hash: tip_header.hash(),
                tempo_block_number: tempo.number,
                tempo_block_hash: tempo.hash,
            },
        })
        .map_err(|_| eyre::eyre!("P2P command channel closed"))?;
    Ok(())
}

/// Serve block backfill requests for the process lifetime.
///
/// Backfill serving is role-neutral: leaders, followers, and fenced nodes all serve the
/// same canonical provider. Running one server outside the role generations means a
/// generation switch can never drop or abandon an accepted request, which would suppress
/// the requesting peer until its response timeout and stall a leadership handoff.
/// Exits when the request channel closes.
pub(crate) async fn serve_backfill_requests<P>(
    provider: P,
    commands: mpsc::Sender<BackfillCommand>,
    mut requests: mpsc::Receiver<BackfillRequest>,
    proofs: Option<ProofCollectorHandle>,
) where
    P: BlockNumReader
        + BlockReader<Block = Block>
        + HeaderProvider<Header = TempoHeader>
        + StateProviderFactory
        + Clone
        + Send
        + Sync
        + 'static,
{
    // One worker deliberately serializes page construction and sending, bounding serving
    // concurrency independently of the block import loop.
    while let Some(BackfillRequest {
        peer,
        request_id,
        start,
    }) = requests.recv().await
    {
        let page_provider = provider.clone();
        let page_commands = commands.clone();
        let page_proofs = proofs.clone();
        let page = tokio::task::spawn_blocking(move || {
            serve_backfill_page(
                &page_provider,
                &page_commands,
                peer,
                request_id,
                start,
                page_proofs.as_ref(),
            )
        })
        .await;
        let result = match page {
            Ok(result) => result,
            Err(err) => Err(eyre::eyre!("backfill page worker failed: {err}")),
        };
        if let Err(err) = result {
            tracing::error!(target: "zone::p2p", %err, start, "Failed serving block backfill");
        }
    }
}

/// Collect and verify follower settlement signatures on the leader, without ever
/// requesting or importing peer blocks.
///
/// While this runs, [`ZoneEngine`](crate::ZoneEngine) is the sole chain-head
/// writer. Backfill requests are served by the process-lifetime
/// [`serve_backfill_requests`] task, never by role generations. The loop exits
/// when `stop` fires.
pub(crate) async fn collect_follower_settlement_signatures(
    mut events: mpsc::Receiver<P2pEvent>,
    settlements: SettlementManager,
    stop: sync::CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => {
                debug!(target: "zone::p2p", "Leader settlement signature collection stopped");
                return;
            }
            event = events.recv() => {
                let Some(event) = event else {
                    debug!(target: "zone::p2p", "P2P event channel closed");
                    return;
                };
                match event {
                    P2pEvent::Started { .. } => {}
                    P2pEvent::SettlementSignatureReceived { follower, signature } => {
                        if let Err(err) = settlements.add_signature(follower.clone(), &signature) {
                            tracing::warn!(target: "zone::p2p", %follower, %err, "Rejected follower settlement signature");
                        }
                    }
                    P2pEvent::BlockReceived { .. }
                    | P2pEvent::TransactionReceived { .. }
                    | P2pEvent::SettlementProposalReceived { .. } => {
                        // A leader never follows peer chain heads. Keeping this explicit ensures
                        // ZoneEngine remains the sole writer of the leader's canonical head.
                        debug!(target: "zone::p2p", "Ignoring peer block sync event on serve-only leader");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use futures::{StreamExt as _, stream};
    use tokio::sync::{oneshot, watch};

    use super::{
        Block, BroadcasterShutdown, EncodedPersistedBlock, PersistedBlockSource, PersistedTip,
        StoredBlockProof, broadcast_persisted_blocks, decode_peer_block, encode_block_with_witness,
    };
    use alloy_primitives::B256;
    use zone_p2p::{EncodedBlock, P2pCommand};

    #[derive(Clone)]
    struct StartupRaceSource {
        reads: Arc<AtomicUsize>,
        tip: PersistedTip,
    }

    impl PersistedBlockSource for StartupRaceSource {
        fn last_block_number(&self) -> eyre::Result<u64> {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(if read == 0 {
                self.tip.number - 1
            } else {
                self.tip.number
            })
        }

        fn canonical_block_number(&self) -> eyre::Result<u64> {
            Ok(self.tip.number)
        }

        fn persisted_block_stream(&self) -> futures::stream::BoxStream<'static, PersistedTip> {
            stream::iter([self.tip]).boxed()
        }

        fn encoded_block_by_number(&self, number: u64) -> eyre::Result<EncodedPersistedBlock> {
            assert_eq!(number, self.tip.number);
            Ok(EncodedPersistedBlock {
                number,
                hash: self.tip.hash,
                encoded: vec![number as u8],
            })
        }
    }

    /// A provider whose canonical head sits above its persisted head, which is the window the
    /// stop flush and the demotion drain both have to get right.
    #[derive(Clone)]
    struct DivergentHeadSource {
        canonical: u64,
        persisted: Arc<AtomicU64>,
        /// The persisted head observed while the broadcaster subscribes. Subsequent reads see
        /// `persisted`, allowing tests to model a block that becomes durable during shutdown.
        startup_persisted: u64,
        startup_reads: Arc<AtomicUsize>,
        updates: watch::Receiver<PersistedTip>,
    }

    impl PersistedBlockSource for DivergentHeadSource {
        fn last_block_number(&self) -> eyre::Result<u64> {
            let read = self.startup_reads.fetch_add(1, Ordering::SeqCst);
            Ok(if read < 2 {
                self.startup_persisted
            } else {
                self.persisted.load(Ordering::SeqCst)
            })
        }

        fn canonical_block_number(&self) -> eyre::Result<u64> {
            Ok(self.canonical)
        }

        fn persisted_block_stream(&self) -> futures::stream::BoxStream<'static, PersistedTip> {
            stream::unfold(self.updates.clone(), |mut updates| async move {
                updates.changed().await.ok()?;
                let tip = *updates.borrow_and_update();
                Some((tip, updates))
            })
            .boxed()
        }

        fn encoded_block_by_number(&self, number: u64) -> eyre::Result<EncodedPersistedBlock> {
            assert!(
                number <= self.persisted.load(Ordering::SeqCst),
                "encoded a block that is not durable yet: {number}"
            );
            Ok(EncodedPersistedBlock {
                number,
                hash: B256::repeat_byte(number as u8),
                encoded: vec![number as u8],
            })
        }
    }

    fn witness_envelope(block: Vec<u8>, proof: &StoredBlockProof) -> Vec<u8> {
        EncodedBlock {
            block,
            witness: Some(minicbor_serde::to_vec(proof).unwrap()),
        }
        .encode()
    }

    fn cbor_field<'a>(encoded: &'a [u8], field: &str) -> &'a [u8] {
        let mut decoder = minicbor::Decoder::new(encoded);
        let length = decoder.map().unwrap();
        let mut index = 0;
        while length.is_none_or(|length| index < length)
            && decoder.datatype().unwrap() != minicbor::data::Type::Break
        {
            let name = decoder.str().unwrap();
            let start = decoder.position();
            decoder.skip().unwrap();
            if name == field {
                return &encoded[start..decoder.position()];
            }
            index += 1;
        }
        panic!("missing CBOR field {field}");
    }

    #[test]
    fn witness_envelope_decodes_cbor_and_bare_blocks() {
        let block = Block::default();
        let bare = alloy_rlp::encode(&block);
        assert_eq!(
            encode_block_with_witness(bare.clone(), 0, B256::ZERO, None)
                .unwrap()
                .encode(),
            bare
        );
        assert_eq!(
            decode_peer_block(&bare).unwrap(),
            super::PeerBlock {
                block: block.clone(),
                witness: None
            }
        );
        let mut proof = StoredBlockProof {
            format_version: 2,
            witness: Default::default(),
        };
        proof.witness.block_number = 42;
        proof.witness.block_hash = B256::repeat_byte(0x11);
        proof.witness.parent_hash = B256::repeat_byte(0x22);
        proof.witness.initial_tempo_header.inner.number = 100;
        proof.witness.initial_tempo_header.inner.state_root = B256::repeat_byte(0x33);
        let nodes = vec![alloy_primitives::Bytes::from(vec![0, 0x80, 0xff])];
        proof.witness.execution_witness.state = nodes.clone();
        proof.witness.execution_witness.codes = nodes.clone();
        proof.witness.execution_witness.keys = nodes.clone();
        proof.witness.execution_witness.headers = nodes.clone();
        proof.witness.tempo_state = nodes;
        let encoded = witness_envelope(bare.clone(), &proof);
        assert_eq!(
            decode_peer_block(&encoded).unwrap(),
            super::PeerBlock {
                block,
                witness: Some(proof.clone())
            }
        );

        // Witness preimages and the RLP header must use CBOR byte strings, not hex strings.
        let encoded_proof = &encoded[EncodedBlock::WITNESS_PREFIX.len() + bare.len()..];
        let witness = cbor_field(encoded_proof, "witness");
        for name in ["state", "codes", "keys", "headers", "tempo_state"] {
            let mut decoder = minicbor::Decoder::new(cbor_field(witness, name));
            assert_eq!(decoder.array().unwrap(), Some(1));
            assert_eq!(decoder.bytes().unwrap(), &[0, 0x80, 0xff]);
        }
        let mut decoder = minicbor::Decoder::new(cbor_field(witness, "initial_tempo_header"));
        assert_eq!(
            decoder.bytes().unwrap(),
            alloy_rlp::encode(&proof.witness.initial_tempo_header)
        );

        // The shared header adapter must preserve the existing RPC and proof-store JSON shape.
        let json = serde_json::to_value(&proof).unwrap();
        assert_eq!(
            json["witness"]["initial_tempo_header"],
            serde_json::to_value(&proof.witness.initial_tempo_header).unwrap()
        );
        assert_eq!(json["witness"]["state"][0], "0x0080ff");
        assert_eq!(
            serde_json::from_value::<StoredBlockProof>(json).unwrap(),
            proof
        );
    }

    #[test]
    fn witness_envelope_rejects_truncation_trailing_data_and_unknown_formats() {
        let bare = alloy_rlp::encode(Block::default());
        let proof = StoredBlockProof {
            format_version: 2,
            witness: Default::default(),
        };
        let encoded = witness_envelope(bare.clone(), &proof);
        for len in EncodedBlock::WITNESS_PREFIX.len()..encoded.len() {
            assert!(
                decode_peer_block(&encoded[..len]).is_err(),
                "accepted prefix of length {len}"
            );
        }
        for mut trailing in [bare.clone(), encoded.clone()] {
            trailing.push(0);
            assert!(decode_peer_block(&trailing).is_err());
        }
        let mut unknown_version = encoded;
        unknown_version[4] = 2;
        assert!(decode_peer_block(&unknown_version).is_err());

        // The unreleased JSON draft is not accepted as a CBOR witness.
        let mut json = EncodedBlock::WITNESS_PREFIX.to_vec();
        json.extend_from_slice(&bare);
        serde_json::to_writer(&mut json, &proof).unwrap();
        assert!(decode_peer_block(&json).is_err());
    }

    #[tokio::test]
    async fn broadcasts_block_persisted_during_startup_reconciliation_once() {
        let source = StartupRaceSource {
            reads: Arc::new(AtomicUsize::new(0)),
            tip: PersistedTip {
                number: 1,
                hash: B256::repeat_byte(0x11),
            },
        };
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let (_shutdown, shutdown_rx) = oneshot::channel();

        broadcast_persisted_blocks(source, commands, shutdown_rx, None).await;

        assert_eq!(
            command_rx.recv().await,
            Some(P2pCommand::BroadcastBlock(zone_p2p::EncodedBlock {
                block: vec![1],
                witness: None
            }))
        );
        assert_eq!(command_rx.recv().await, None);
    }

    #[tokio::test]
    async fn stop_flush_never_broadcasts_a_canonical_only_block() {
        // Exactly the reported window: block N is canonical but only N-1 is durable.
        let source = DivergentHeadSource {
            canonical: 2,
            persisted: Arc::new(AtomicU64::new(1)),
            startup_persisted: 0,
            startup_reads: Arc::new(AtomicUsize::new(0)),
            updates: watch::channel(PersistedTip {
                number: 1,
                hash: B256::repeat_byte(1),
            })
            .1,
        };
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let (shutdown, shutdown_rx) = oneshot::channel();
        shutdown
            .send(BroadcasterShutdown::Stop)
            .expect("the broadcaster must retain the shutdown receiver");

        broadcast_persisted_blocks(source, commands, shutdown_rx, None).await;

        // Block 1 is durable and must be flushed; block 2 exists only in memory and would be
        // lost on restart, stranding any follower that imported it.
        assert_eq!(
            command_rx.recv().await,
            Some(P2pCommand::BroadcastBlock(zone_p2p::EncodedBlock {
                block: vec![1],
                witness: None
            }))
        );
        assert_eq!(
            command_rx.recv().await,
            None,
            "the stop flush broadcast a canonical-but-unpersisted block"
        );
    }

    #[tokio::test]
    async fn drain_after_engine_stop_waits_for_the_canonical_tail_to_persist() {
        let persisted = Arc::new(AtomicU64::new(1));
        let (updates, update_rx) = watch::channel(PersistedTip {
            number: 1,
            hash: B256::repeat_byte(1),
        });
        let source = DivergentHeadSource {
            canonical: 2,
            persisted: persisted.clone(),
            startup_persisted: 0,
            startup_reads: Arc::new(AtomicUsize::new(0)),
            updates: update_rx,
        };
        let (commands, mut command_rx) = tokio::sync::mpsc::channel(4);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(broadcast_persisted_blocks(
            source,
            commands,
            shutdown_rx,
            None,
        ));

        shutdown
            .send(BroadcasterShutdown::Drain)
            .expect("the broadcaster must retain the shutdown receiver");

        // The durable prefix goes out immediately.
        assert_eq!(
            command_rx.recv().await,
            Some(P2pCommand::BroadcastBlock(zone_p2p::EncodedBlock {
                block: vec![1],
                witness: None
            }))
        );
        // The canonical tail must not, until it persists.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), command_rx.recv())
                .await
                .is_err(),
            "the drain broadcast the canonical tail before it was durable"
        );

        persisted.store(2, Ordering::SeqCst);
        updates
            .send(PersistedTip {
                number: 2,
                hash: B256::repeat_byte(2),
            })
            .expect("the broadcaster must retain the persisted-block stream");

        assert_eq!(
            command_rx.recv().await,
            Some(P2pCommand::BroadcastBlock(zone_p2p::EncodedBlock {
                block: vec![2],
                witness: None
            }))
        );
        task.await.expect("the broadcaster task must not panic");
        assert_eq!(command_rx.recv().await, None);
    }
}
