use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use alloy_primitives::{B256, Bytes};
use commonware_consensus::types::{Epoch, Height};
use commonware_cryptography::{certificate::Provider as _, ed25519::PublicKey};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::IoBuf;
use futures::{
    StreamExt as _,
    channel::{mpsc, oneshot},
};
use prometheus_client::metrics::counter::Counter;
use reth_tasks::TaskExecutor;
use tempo_payload_types::{
    SsmrBuilderEvent, SsmrBuilderShard, SsmrBuilderSink, SsmrReplaySender, SsmrReplaySource,
    TempoBuiltPayload, TempoPayloadAttributes,
};
use tracing::{Level, debug, instrument, warn};

use crate::{consensus::Digest, epoch::SchemeProvider, utils::public_key_to_tempo_primitive};

use super::{
    SsmrCompleteStream, SsmrEnd, SsmrError, SsmrFlags, SsmrMessage, SsmrShardPayload, SsmrStart,
    SsmrStreamSnapshot, SsmrTranscript, SsmrTxShard, StreamKey,
};

/// Runtime configuration for the SSMR side-channel actor.
pub(crate) struct Config<TContext> {
    pub(crate) context: TContext,
    pub(crate) public_key: PublicKey,
    pub(crate) scheme_provider: SchemeProvider,
    pub(crate) task_executor: TaskExecutor,
    pub(crate) executor: crate::executor::Mailbox,
    pub(crate) shard_target_bytes: usize,
    pub(crate) max_buffered_bytes: usize,
}

/// Metadata known before payload building starts.
#[derive(Clone, Debug)]
pub(crate) struct ProposalStream {
    pub(crate) stream_key: StreamKey,
    pub(crate) parent_height: u64,
    pub(crate) extra_data: Bytes,
    pub(crate) gas_limit: u64,
    pub(crate) general_gas_limit: u64,
    pub(crate) shared_gas_limit: u64,
    pub(crate) shard_target_bytes: u64,
    pub(crate) bal_enabled: bool,
}

impl ProposalStream {
    fn message_for_event(&self, event: SsmrBuilderEvent) -> Option<SsmrMessage> {
        match event {
            SsmrBuilderEvent::Shard(shard) if shard.shard_index == 0 => {
                Some(SsmrMessage::Start(SsmrStart {
                    stream_key: self.stream_key,
                    parent_height: self.parent_height,
                    proposer: self.stream_key.proposer(),
                    extra_data: self.extra_data.clone(),
                    gas_limit: self.gas_limit,
                    general_gas_limit: self.general_gas_limit,
                    shared_gas_limit: self.shared_gas_limit,
                    shard_target_bytes: self.shard_target_bytes,
                    flags: SsmrFlags::tx_only(self.bal_enabled),
                    first_shard: shard.into_payload(),
                }))
            }
            SsmrBuilderEvent::Shard(shard) => Some(SsmrMessage::TxShard(SsmrTxShard {
                stream_key: self.stream_key,
                shard: shard.into_payload(),
            })),
            SsmrBuilderEvent::End {
                total_shards,
                total_transactions,
            } if total_shards > 0 => Some(SsmrMessage::End(SsmrEnd {
                stream_key: self.stream_key,
                total_shards,
                total_transactions,
            })),
            SsmrBuilderEvent::End { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SsmrMessageMetadata {
    kind: &'static str,
    shard_index: Option<u64>,
    first_tx_index: Option<u64>,
    tx_count: Option<usize>,
    total_shards: Option<u64>,
    total_transactions: Option<u64>,
}

impl SsmrMessageMetadata {
    fn from_message(message: &SsmrMessage) -> Self {
        match message {
            SsmrMessage::Start(start) => Self::from_payload("start", &start.first_shard),
            SsmrMessage::TxShard(shard) => Self::from_payload("tx_shard", &shard.shard),
            SsmrMessage::End(end) => Self {
                kind: "end",
                shard_index: None,
                first_tx_index: None,
                tx_count: None,
                total_shards: Some(end.total_shards),
                total_transactions: Some(end.total_transactions),
            },
        }
    }

    fn from_payload(kind: &'static str, payload: &SsmrShardPayload) -> Self {
        Self {
            kind,
            shard_index: Some(payload.shard_index),
            first_tx_index: Some(payload.first_tx_index),
            tx_count: Some(payload.tx_count()),
            total_shards: None,
            total_transactions: None,
        }
    }
}

trait IntoPayload {
    fn into_payload(self) -> SsmrShardPayload;
}

impl IntoPayload for SsmrBuilderShard {
    fn into_payload(self) -> SsmrShardPayload {
        SsmrShardPayload {
            shard_index: self.shard_index,
            first_tx_index: self.first_tx_index,
            transactions: self.transactions,
            block_access_list: self.block_access_list,
            cumulative_tx_bytes: self.cumulative_tx_bytes,
            cumulative_gas_estimate: self.cumulative_gas_estimate,
        }
    }
}

/// Side-channel actor for SSMR shard transport and transcript storage.
pub(crate) struct Actor {
    public_key: PublicKey,
    scheme_provider: SchemeProvider,
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    control_rx: mpsc::UnboundedReceiver<ControlMessage>,
    builder_tx: mpsc::UnboundedSender<BuilderMessage>,
    builder_rx: mpsc::UnboundedReceiver<BuilderMessage>,
    streams: HashMap<StreamKey, StreamBuffer>,
    retired_streams: HashSet<StreamKey>,
    task_executor: TaskExecutor,
    executor: crate::executor::Mailbox,
    buffered_bytes: usize,
    shard_target_bytes: usize,
    max_buffered_bytes: usize,
    metrics: Metrics,
}

impl Actor {
    pub(crate) fn new<TContext>(
        Config {
            context,
            public_key,
            scheme_provider,
            task_executor,
            executor,
            shard_target_bytes,
            max_buffered_bytes,
        }: Config<TContext>,
    ) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let (control_tx, control_rx) = mpsc::unbounded();
        let (builder_tx, builder_rx) = mpsc::unbounded();
        Self {
            public_key,
            scheme_provider,
            control_tx,
            control_rx,
            builder_tx,
            builder_rx,
            streams: HashMap::new(),
            retired_streams: HashSet::new(),
            task_executor,
            executor,
            buffered_bytes: 0,
            shard_target_bytes,
            max_buffered_bytes,
            metrics: Metrics::init(&context),
        }
    }

    pub(crate) fn mailbox(&self) -> Mailbox {
        Mailbox {
            control_tx: self.control_tx.clone(),
            builder_tx: self.builder_tx.clone(),
            shard_target_bytes: self.shard_target_bytes,
        }
    }

    pub(crate) async fn run(
        mut self,
        (mut network_tx, mut network_rx): (
            impl Sender<PublicKey = PublicKey> + Send + 'static,
            impl Receiver<PublicKey = PublicKey>,
        ),
    ) {
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded::<OutboundMessage>();
        let metrics = self.metrics.clone();
        self.task_executor
            .spawn_critical_task("ssmr-outbound", async move {
                while let Some(outbound) = outbound_rx.next().await {
                    let send_start = Instant::now();
                    if network_tx
                        .send(Recipients::All, outbound.bytes, true)
                        .await
                        .is_ok()
                    {
                        let send_elapsed = send_start.elapsed();
                        metrics.bytes_sent.inc_by(outbound.byte_len as u64);
                        if outbound.byte_len != 0 {
                            metrics.shards_sent.inc();
                        }
                        debug!(
                            stream.parent = %outbound.key.parent_hash,
                            stream.height = outbound.key.block_height,
                            message.kind = outbound.metadata.kind,
                            shard.index = ?outbound.metadata.shard_index,
                            shard.first_tx = ?outbound.metadata.first_tx_index,
                            shard.tx_count = ?outbound.metadata.tx_count,
                            stream.total_shards = ?outbound.metadata.total_shards,
                            stream.total_transactions = ?outbound.metadata.total_transactions,
                            bytes = outbound.byte_len,
                            ?send_elapsed,
                            "sent SSMR side-channel message"
                        );
                    } else {
                        warn!(
                            stream.parent = %outbound.key.parent_hash,
                            stream.height = outbound.key.block_height,
                            message.kind = outbound.metadata.kind,
                            shard.index = ?outbound.metadata.shard_index,
                            stream.total_shards = ?outbound.metadata.total_shards,
                            "failed sending SSMR side-channel message"
                        );
                    }
                }
            });

        loop {
            tokio::select! {
                biased;

                Some(message) = self.control_rx.next() => {
                    self.on_control_message(message);
                }
                Some(message) = self.builder_rx.next() => {
                    self.on_builder_message(message, &outbound_tx);
                }
                Ok((sender, message)) = network_rx.recv() => {
                    let _ = self.on_network_message(sender, message);
                }
            }
        }
    }

    fn on_builder_message(
        &mut self,
        message: BuilderMessage,
        outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    ) {
        match message {
            BuilderMessage::BuilderEvent { stream, event } => {
                self.broadcast_builder_event(stream, event, outbound_tx);
            }
        }
    }

    fn on_control_message(&mut self, message: ControlMessage) {
        match message {
            ControlMessage::GetStreamSnapshot { key, response } => {
                let stream = self.streams.get(&key).map(StreamBuffer::snapshot);
                let _ = response.send(stream);
            }
            ControlMessage::RetireStream { key } => {
                self.retire_stream(key);
            }
            ControlMessage::EvictStreamsThroughHeight { block_height } => {
                self.evict_streams_through_height(block_height);
            }
            ControlMessage::OptimisticPayloadReady { key, payload } => match payload {
                Ok(payload) => {
                    debug!(
                        stream.parent = %key.parent_hash,
                        stream.height = key.block_height,
                        "SSMR optimistic payload ready"
                    );
                    if let Some(stream) = self.streams.get_mut(&key) {
                        stream.optimistic_execution = None;
                        stream.optimistic_payload = Some(payload);
                    }
                }
                Err(error) => {
                    self.metrics.optimistic_payload_failures.inc();
                    if let Some(stream) = self.streams.get_mut(&key) {
                        stream.optimistic_execution = None;
                        stream.optimistic_failed = true;
                    }
                    warn!(
                        %error,
                        stream.parent = %key.parent_hash,
                        stream.height = key.block_height,
                        "failed executing complete SSMR stream optimistically"
                    );
                }
            },
        }
    }

    #[instrument(skip_all, fields(stream.parent = %stream.stream_key.parent_hash, stream.height = stream.stream_key.block_height))]
    fn broadcast_builder_event(
        &mut self,
        stream: ProposalStream,
        event: SsmrBuilderEvent,
        outbound_tx: &mpsc::UnboundedSender<OutboundMessage>,
    ) {
        if stream.stream_key.proposer() != public_key_to_tempo_primitive(&self.public_key) {
            return;
        }

        let Some(message) = stream.message_for_event(event) else {
            return;
        };
        let metadata = SsmrMessageMetadata::from_message(&message);
        let encoded = message.encode();
        let byte_len = encoded.len();
        debug!(
            stream.parent = %stream.stream_key.parent_hash,
            stream.height = stream.stream_key.block_height,
            message.kind = metadata.kind,
            shard.index = ?metadata.shard_index,
            shard.first_tx = ?metadata.first_tx_index,
            shard.tx_count = ?metadata.tx_count,
            stream.total_shards = ?metadata.total_shards,
            stream.total_transactions = ?metadata.total_transactions,
            bytes = byte_len,
            "queued SSMR side-channel message"
        );
        let _ = outbound_tx.unbounded_send(OutboundMessage {
            key: stream.stream_key,
            metadata,
            bytes: encoded.into(),
            byte_len,
        });
    }

    #[instrument(skip_all, err(level = Level::DEBUG), fields(sender = %sender, msg_bytes = message.len()))]
    fn on_network_message(&mut self, sender: PublicKey, message: IoBuf) -> eyre::Result<()> {
        let byte_len = message.len();
        self.metrics.bytes_received.inc_by(byte_len as u64);
        let message = SsmrMessage::decode(message.as_ref()).map_err(|error| eyre::eyre!(error))?;
        let key = message.stream_key();
        let metadata = SsmrMessageMetadata::from_message(&message);

        if key.proposer() != public_key_to_tempo_primitive(&sender) {
            warn!(%sender, "discarding SSMR message from non-proposer sender");
            return Ok(());
        }
        if !self.sender_in_epoch(key, &sender) {
            warn!(%sender, epoch = key.consensus_context.epoch, "discarding SSMR message from non-validator sender");
            return Ok(());
        }

        self.metrics.shards_received.inc();
        debug!(
            %sender,
            stream.parent = %key.parent_hash,
            stream.height = key.block_height,
            message.kind = metadata.kind,
            shard.index = ?metadata.shard_index,
            shard.first_tx = ?metadata.first_tx_index,
            shard.tx_count = ?metadata.tx_count,
            stream.total_shards = ?metadata.total_shards,
            stream.total_transactions = ?metadata.total_transactions,
            bytes = byte_len,
            "received SSMR side-channel message"
        );
        self.insert_stream_message(message);
        Ok(())
    }

    fn sender_in_epoch(&self, key: StreamKey, sender: &PublicKey) -> bool {
        self.scheme_provider
            .scoped(Epoch::new(key.consensus_context.epoch))
            .is_some_and(|scheme| {
                scheme
                    .participants()
                    .iter()
                    .any(|participant| participant == sender)
            })
    }

    fn insert_stream_message(&mut self, message: SsmrMessage) {
        let key = message.stream_key();
        let metadata = SsmrMessageMetadata::from_message(&message);
        if self.stream_retired(key) {
            debug!(
                stream.parent = %key.parent_hash,
                stream.height = key.block_height,
                message.kind = metadata.kind,
                shard.index = ?metadata.shard_index,
                "discarding retired SSMR stream message"
            );
            return;
        }

        let insert_result = {
            let stream = self.streams.entry(key).or_default();
            let was_complete = stream.complete_transcript().is_some();
            match stream.insert(message) {
                Ok(inserted_bytes) => Ok((
                    was_complete,
                    inserted_bytes,
                    stream.complete_transcript().is_some(),
                )),
                Err(error) => Err((error, stream.buffered_bytes)),
            }
        };
        let (was_complete, inserted_bytes, is_complete) = match insert_result {
            Ok(outcome) => outcome,
            Err((error, buffered_bytes)) => {
                self.metrics.streams_invalid.inc();
                warn!(
                    %error,
                    stream.parent = %key.parent_hash,
                    stream.height = key.block_height,
                    "discarding invalid SSMR stream"
                );
                self.buffered_bytes = self.buffered_bytes.saturating_sub(buffered_bytes);
                self.streams.remove(&key);
                return;
            }
        };

        self.buffered_bytes = self.buffered_bytes.saturating_add(inserted_bytes);
        if let Some(progress) = self.streams.get(&key).map(StreamBuffer::progress) {
            debug!(
                stream.parent = %key.parent_hash,
                stream.height = key.block_height,
                message.kind = metadata.kind,
                shard.index = ?metadata.shard_index,
                inserted_bytes,
                stream.buffered_bytes = progress.buffered_bytes,
                stream.received_shards = progress.received_shards,
                stream.expected_shards = ?progress.expected_shards,
                stream.received_transactions = progress.received_transactions,
                stream.expected_transactions = ?progress.expected_transactions,
                stream.end_received = progress.end_received,
                stream.next_missing_shard = ?progress.next_missing_shard,
                "inserted SSMR stream message"
            );
        }
        self.drive_optimistic_execution(key);

        if self.buffered_bytes > self.max_buffered_bytes {
            self.metrics.streams_invalid.inc();
            warn!(
                stream.parent = %key.parent_hash,
                stream.height = key.block_height,
                buffered_bytes = self.buffered_bytes,
                max_buffered_bytes = self.max_buffered_bytes,
                "discarding SSMR stream because buffered byte limit is reached"
            );
            if let Some(stream) = self.streams.remove(&key) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(stream.buffered_bytes);
            }
            return;
        }

        if !was_complete && is_complete {
            self.metrics.streams_completed.inc();
            let progress = self.streams.get(&key).map(StreamBuffer::progress);
            debug!(
                stream.parent = %key.parent_hash,
                stream.height = key.block_height,
                stream.received_shards = ?progress.map(|progress| progress.received_shards),
                stream.received_transactions = ?progress.map(|progress| progress.received_transactions),
                "completed SSMR transcript"
            );
        }
    }

    fn evict_stream(&mut self, key: StreamKey) {
        if let Some(stream) = self.streams.remove(&key) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(stream.buffered_bytes);
        }
    }

    fn evict_streams_through_height(&mut self, block_height: u64) {
        let mut evicted_bytes = 0usize;
        self.streams.retain(|key, stream| {
            if key.block_height <= block_height {
                evicted_bytes = evicted_bytes.saturating_add(stream.buffered_bytes);
                false
            } else {
                true
            }
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(evicted_bytes);
    }

    fn retire_stream(&mut self, key: StreamKey) {
        self.evict_stream(key);
        self.retired_streams.insert(key);
    }

    fn stream_retired(&self, key: StreamKey) -> bool {
        self.retired_streams.contains(&key)
    }

    fn drive_optimistic_execution(&mut self, key: StreamKey) {
        let maybe_start = self
            .streams
            .get(&key)
            .filter(|stream| {
                stream.transcript.is_some()
                    && stream.optimistic_execution.is_none()
                    && stream.optimistic_payload.is_none()
                    && !stream.optimistic_failed
            })
            .and_then(|stream| stream.transcript.as_ref())
            .map(|transcript| transcript.start().clone());

        if let Some(start) = maybe_start {
            let (replay_tx, replay_source) = SsmrReplaySource::channel();
            let attrs = ssmr_replay_attributes(&start, replay_source);
            match self.executor.canonicalize_and_build(
                Height::new(start.parent_height),
                Digest(start.stream_key.parent_hash),
                attrs,
            ) {
                Ok(payload_rx) => {
                    let mut should_spawn = false;
                    if let Some(stream) = self.streams.get_mut(&key)
                        && stream.optimistic_execution.is_none()
                    {
                        stream.optimistic_execution = Some(OptimisticExecutionState {
                            tx: replay_tx,
                            finalizing: false,
                        });
                        should_spawn = true;
                    }
                    if should_spawn {
                        debug!(
                            stream.parent = %key.parent_hash,
                            stream.height = key.block_height,
                            "started SSMR optimistic execution"
                        );
                        self.spawn_optimistic_execution(key, payload_rx);
                    }
                }
                Err(error) => {
                    self.metrics.optimistic_payload_failures.inc();
                    if let Some(stream) = self.streams.get_mut(&key) {
                        stream.optimistic_failed = true;
                    }
                    warn!(
                        %error,
                        stream.parent = %key.parent_hash,
                        stream.height = key.block_height,
                        "failed starting SSMR optimistic execution"
                    );
                }
            }
        }

        self.feed_optimistic_execution(key);
    }

    fn feed_optimistic_execution(&mut self, key: StreamKey) {
        let Some((tx, commands)) = self.streams.get_mut(&key).and_then(|stream| {
            let execution = stream.optimistic_execution.as_mut()?;
            let transcript = stream.transcript.as_ref()?;
            let mut commands = Vec::new();

            while let Some(shard) = transcript.shard(stream.next_execution_shard) {
                commands.push(ReplaySend::Shard {
                    shard_index: shard.shard_index,
                    transactions: shard.transactions.clone(),
                    block_access_list: shard.block_access_list.clone(),
                });
                stream.next_execution_shard += 1;
            }

            if transcript.is_complete()
                && !execution.finalizing
                && stream.next_execution_shard == transcript.shard_count()
            {
                execution.finalizing = true;
                commands.push(ReplaySend::Finish {
                    sent_shards: stream.next_execution_shard,
                });
            }

            (!commands.is_empty()).then(|| (execution.tx.clone(), commands))
        }) else {
            return;
        };

        for command in commands {
            let sent = match command {
                ReplaySend::Shard {
                    shard_index,
                    transactions,
                    block_access_list,
                } => {
                    let tx_count = transactions.len();
                    let bal_bytes = block_access_list
                        .as_ref()
                        .map(|bal| bal.len())
                        .unwrap_or_default();
                    debug!(
                        stream.parent = %key.parent_hash,
                        stream.height = key.block_height,
                        shard.index = shard_index,
                        shard.tx_count = tx_count,
                        shard.bal_bytes = bal_bytes,
                        "feeding SSMR shard to optimistic execution"
                    );
                    let sent = tx.send_shard(transactions, block_access_list);
                    if sent && bal_bytes > 0 {
                        let released = self
                            .streams
                            .get_mut(&key)
                            .and_then(|stream| stream.release_replayed_shard_bal(shard_index))
                            .unwrap_or_default();
                        if released > 0 {
                            self.buffered_bytes = self.buffered_bytes.saturating_sub(released);
                            debug!(
                                stream.parent = %key.parent_hash,
                                stream.height = key.block_height,
                                shard.index = shard_index,
                                shard.bal_bytes = released,
                                stream.buffered_bytes = self
                                    .streams
                                    .get(&key)
                                    .map(|stream| stream.buffered_bytes)
                                    .unwrap_or_default(),
                                "released SSMR shard BAL after feeding optimistic execution"
                            );
                        }
                    }
                    sent
                }
                ReplaySend::Finish { sent_shards } => {
                    debug!(
                        stream.parent = %key.parent_hash,
                        stream.height = key.block_height,
                        sent_shards,
                        "finishing SSMR optimistic execution stream"
                    );
                    tx.finish()
                }
            };
            if !sent {
                self.metrics.optimistic_payload_failures.inc();
                if let Some(stream) = self.streams.get_mut(&key) {
                    stream.optimistic_execution = None;
                    stream.optimistic_failed = true;
                }
                warn!(
                    stream.parent = %key.parent_hash,
                    stream.height = key.block_height,
                    "failed sending SSMR shard to optimistic execution worker"
                );
                break;
            }
        }
    }

    fn spawn_optimistic_execution(
        &self,
        key: StreamKey,
        payload_rx: oneshot::Receiver<TempoBuiltPayload>,
    ) {
        let tx = self.control_tx.clone();
        let metrics = self.metrics.clone();
        let build_start = std::time::Instant::now();
        self.task_executor
            .spawn_critical_task("ssmr-replay-payload", async move {
                let payload = payload_rx.await.map_err(|error| error.to_string());
                if payload.is_ok() {
                    metrics.optimistic_payloads_ready.inc();
                    metrics
                        .optimistic_execution_millis_total
                        .inc_by(build_start.elapsed().as_millis() as u64);
                }
                let _ = tx.unbounded_send(ControlMessage::OptimisticPayloadReady { key, payload });
            });
    }
}

fn ssmr_replay_attributes(
    start: &SsmrStart,
    replay_source: SsmrReplaySource,
) -> TempoPayloadAttributes {
    TempoPayloadAttributes::new(
        Some(B256::from(&start.proposer)),
        start.stream_key.timestamp,
        start.stream_key.timestamp_millis_part,
        start.extra_data.clone(),
        Some(start.stream_key.consensus_context),
        Vec::new,
    )
    .with_ssmr_replay_source(replay_source)
}

/// Handle to the SSMR actor.
#[derive(Clone)]
pub(crate) struct Mailbox {
    control_tx: mpsc::UnboundedSender<ControlMessage>,
    builder_tx: mpsc::UnboundedSender<BuilderMessage>,
    shard_target_bytes: usize,
}

impl Mailbox {
    pub(crate) fn shard_target_bytes(&self) -> usize {
        self.shard_target_bytes
    }

    pub(crate) fn builder_sink(&self, stream: ProposalStream) -> SsmrBuilderSink {
        let tx = self.builder_tx.clone();
        Arc::new(move |event| {
            let _ = tx.unbounded_send(BuilderMessage::BuilderEvent {
                stream: stream.clone(),
                event,
            });
        })
    }

    pub(crate) async fn get_stream_snapshot(&self, key: StreamKey) -> Option<SsmrStreamSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .unbounded_send(ControlMessage::GetStreamSnapshot { key, response: tx })
            .ok()?;
        rx.await.ok().flatten()
    }

    pub(crate) fn retire_stream(&self, key: StreamKey) {
        let _ = self
            .control_tx
            .unbounded_send(ControlMessage::RetireStream { key });
    }

    pub(crate) fn evict_streams_through_height(&self, block_height: u64) {
        let _ = self
            .control_tx
            .unbounded_send(ControlMessage::EvictStreamsThroughHeight { block_height });
    }
}

enum BuilderMessage {
    BuilderEvent {
        stream: ProposalStream,
        event: SsmrBuilderEvent,
    },
}

struct OutboundMessage {
    key: StreamKey,
    metadata: SsmrMessageMetadata,
    bytes: bytes::Bytes,
    byte_len: usize,
}

#[allow(clippy::large_enum_variant)]
enum ControlMessage {
    GetStreamSnapshot {
        key: StreamKey,
        response: oneshot::Sender<Option<SsmrStreamSnapshot>>,
    },
    RetireStream {
        key: StreamKey,
    },
    EvictStreamsThroughHeight {
        block_height: u64,
    },
    OptimisticPayloadReady {
        key: StreamKey,
        payload: Result<TempoBuiltPayload, String>,
    },
}

#[derive(Default)]
struct StreamBuffer {
    transcript: Option<SsmrTranscript>,
    pending_shards: BTreeMap<u64, SsmrTxShard>,
    pending_end: Option<SsmrEnd>,
    optimistic_execution: Option<OptimisticExecutionState>,
    optimistic_payload: Option<TempoBuiltPayload>,
    optimistic_failed: bool,
    next_execution_shard: u64,
    buffered_bytes: usize,
}

struct OptimisticExecutionState {
    tx: SsmrReplaySender,
    finalizing: bool,
}

enum ReplaySend {
    Shard {
        shard_index: u64,
        transactions: Vec<Bytes>,
        block_access_list: Option<Bytes>,
    },
    Finish {
        sent_shards: u64,
    },
}

#[derive(Clone, Copy, Debug)]
struct StreamProgress {
    started: bool,
    end_received: bool,
    received_shards: u64,
    expected_shards: Option<u64>,
    received_transactions: u64,
    expected_transactions: Option<u64>,
    buffered_bytes: usize,
    next_missing_shard: Option<u64>,
    next_execution_shard: u64,
    optimistic_execution_started: bool,
    optimistic_execution_finalizing: bool,
    optimistic_execution_failed: bool,
    optimistic_payload_ready: bool,
}

impl StreamBuffer {
    fn snapshot(&self) -> SsmrStreamSnapshot {
        let progress = self.progress();
        SsmrStreamSnapshot {
            started: progress.started,
            end_received: progress.end_received,
            received_shards: progress.received_shards,
            expected_shards: progress.expected_shards,
            received_transactions: progress.received_transactions,
            expected_transactions: progress.expected_transactions,
            buffered_bytes: progress.buffered_bytes,
            next_missing_shard: progress.next_missing_shard,
            next_execution_shard: progress.next_execution_shard,
            optimistic_execution_started: progress.optimistic_execution_started,
            optimistic_execution_finalizing: progress.optimistic_execution_finalizing,
            optimistic_execution_failed: progress.optimistic_execution_failed,
            optimistic_payload_ready: progress.optimistic_payload_ready,
            complete: self.complete_stream(),
        }
    }

    fn progress(&self) -> StreamProgress {
        let transcript = self.transcript.as_ref();
        let expected_shards = transcript
            .and_then(|transcript| transcript.end.as_ref())
            .map(|end| end.total_shards)
            .or_else(|| self.pending_end.as_ref().map(|end| end.total_shards));
        let expected_transactions = transcript
            .and_then(|transcript| transcript.end.as_ref())
            .map(|end| end.total_transactions)
            .or_else(|| self.pending_end.as_ref().map(|end| end.total_transactions));
        let transcript_shards = transcript.map_or(0, SsmrTranscript::shard_count);
        let pending_shards = self.pending_shards.len() as u64;
        let transcript_transactions = transcript.map_or(0, SsmrTranscript::total_transactions);
        let pending_transactions = self
            .pending_shards
            .values()
            .map(|shard| shard.shard.tx_count() as u64)
            .sum::<u64>();
        let optimistic_execution_finalizing = self
            .optimistic_execution
            .as_ref()
            .is_some_and(|execution| execution.finalizing);

        StreamProgress {
            started: transcript.is_some(),
            end_received: expected_shards.is_some(),
            received_shards: transcript_shards + pending_shards,
            expected_shards,
            received_transactions: transcript_transactions + pending_transactions,
            expected_transactions,
            buffered_bytes: self.buffered_bytes,
            next_missing_shard: self.next_missing_shard(expected_shards),
            next_execution_shard: self.next_execution_shard,
            optimistic_execution_started: self.optimistic_execution.is_some(),
            optimistic_execution_finalizing,
            optimistic_execution_failed: self.optimistic_failed,
            optimistic_payload_ready: self.optimistic_payload.is_some(),
        }
    }

    fn next_missing_shard(&self, expected_shards: Option<u64>) -> Option<u64> {
        let search_limit = if let Some(expected_shards) = expected_shards {
            expected_shards
        } else {
            let transcript_max = self
                .transcript
                .as_ref()
                .and_then(|transcript| transcript.shards.keys().next_back().copied());
            let pending_max = self.pending_shards.keys().next_back().copied();
            let max_seen = transcript_max.max(pending_max)?;
            max_seen.saturating_add(1)
        };

        (0..search_limit).find(|index| !self.has_shard(*index))
    }

    fn has_shard(&self, shard_index: u64) -> bool {
        self.transcript
            .as_ref()
            .is_some_and(|transcript| transcript.has_shard(shard_index))
            || self.pending_shards.contains_key(&shard_index)
    }

    fn complete_stream(&self) -> Option<SsmrCompleteStream> {
        self.complete_transcript()
            .cloned()
            .map(|transcript| SsmrCompleteStream {
                transcript,
                optimistic_payload: self.optimistic_payload.clone(),
                optimistic_execution_finalizing: self
                    .optimistic_execution
                    .as_ref()
                    .is_some_and(|execution| execution.finalizing),
                optimistic_execution_failed: self.optimistic_failed,
            })
    }

    fn complete_transcript(&self) -> Option<&SsmrTranscript> {
        self.transcript
            .as_ref()
            .filter(|transcript| transcript.is_complete())
    }

    fn release_replayed_shard_bal(&mut self, shard_index: u64) -> Option<usize> {
        let bal = self
            .transcript
            .as_mut()?
            .take_shard_block_access_list(shard_index)?;
        let released = bal.len();
        self.buffered_bytes = self.buffered_bytes.saturating_sub(released);
        Some(released)
    }

    fn insert(&mut self, message: SsmrMessage) -> Result<usize, SsmrError> {
        match message {
            SsmrMessage::Start(start) => self.insert_start(start),
            SsmrMessage::TxShard(shard) => self.insert_shard(shard),
            SsmrMessage::End(end) => self.insert_end(end),
        }
    }

    fn insert_start(&mut self, start: SsmrStart) -> Result<usize, SsmrError> {
        let inserted_bytes = start.first_shard.byte_len();
        if let Some(transcript) = &self.transcript {
            if transcript.start() == &start {
                return Ok(0);
            }
            return Err(SsmrError::ConflictingShard { shard_index: 0 });
        }

        let mut transcript = SsmrTranscript::new(start)?;
        for shard in std::mem::take(&mut self.pending_shards).into_values() {
            transcript.insert_shard(shard)?;
        }
        if let Some(end) = self.pending_end.take() {
            transcript.finish(end)?;
        }

        self.transcript = Some(transcript);
        self.buffered_bytes = self.buffered_bytes.saturating_add(inserted_bytes);
        Ok(inserted_bytes)
    }

    fn insert_shard(&mut self, shard: SsmrTxShard) -> Result<usize, SsmrError> {
        let shard_index = shard.shard.shard_index;
        let inserted_bytes = shard.shard.byte_len();
        if let Some(transcript) = &mut self.transcript {
            if transcript.has_shard(shard_index) {
                transcript.insert_shard(shard)?;
                return Ok(0);
            }
            transcript.insert_shard(shard)?;
            self.buffered_bytes = self.buffered_bytes.saturating_add(inserted_bytes);
            return Ok(inserted_bytes);
        }

        if let Some(existing) = self.pending_shards.get(&shard_index) {
            if existing == &shard {
                return Ok(0);
            }
            return Err(SsmrError::ConflictingShard { shard_index });
        }
        self.pending_shards.insert(shard_index, shard);
        self.buffered_bytes = self.buffered_bytes.saturating_add(inserted_bytes);
        Ok(inserted_bytes)
    }

    fn insert_end(&mut self, end: SsmrEnd) -> Result<usize, SsmrError> {
        if let Some(transcript) = &mut self.transcript {
            transcript.finish(end)?;
            return Ok(0);
        }
        if let Some(existing) = &self.pending_end
            && existing != &end
        {
            return Err(SsmrError::ConflictingEnd);
        }
        self.pending_end = Some(end);
        Ok(0)
    }
}

#[derive(Clone)]
struct Metrics {
    streams_completed: Counter,
    streams_invalid: Counter,
    shards_sent: Counter,
    shards_received: Counter,
    bytes_sent: Counter,
    bytes_received: Counter,
    optimistic_payloads_ready: Counter,
    optimistic_payload_failures: Counter,
    optimistic_execution_millis_total: Counter,
}

impl Metrics {
    fn init<TContext>(context: &TContext) -> Self
    where
        TContext: commonware_runtime::Metrics,
    {
        let streams_completed = Counter::default();
        context.register(
            "ssmr_streams_completed",
            "number of complete SSMR transcripts",
            streams_completed.clone(),
        );
        let streams_invalid = Counter::default();
        context.register(
            "ssmr_streams_invalid",
            "number of invalid SSMR transcripts discarded",
            streams_invalid.clone(),
        );
        let shards_sent = Counter::default();
        context.register(
            "ssmr_shards_sent",
            "number of SSMR side-channel messages sent",
            shards_sent.clone(),
        );
        let shards_received = Counter::default();
        context.register(
            "ssmr_shards_received",
            "number of SSMR side-channel messages received",
            shards_received.clone(),
        );
        let bytes_sent = Counter::default();
        context.register(
            "ssmr_bytes_sent",
            "number of SSMR side-channel bytes sent",
            bytes_sent.clone(),
        );
        let bytes_received = Counter::default();
        context.register(
            "ssmr_bytes_received",
            "number of SSMR side-channel bytes received",
            bytes_received.clone(),
        );
        let optimistic_payloads_ready = Counter::default();
        context.register(
            "ssmr_optimistic_payloads_ready",
            "number of complete SSMR streams that produced optimistic execution artifacts",
            optimistic_payloads_ready.clone(),
        );
        let optimistic_payload_failures = Counter::default();
        context.register(
            "ssmr_optimistic_payload_failures",
            "number of complete SSMR streams that failed optimistic execution",
            optimistic_payload_failures.clone(),
        );
        let optimistic_execution_millis_total = Counter::default();
        context.register(
            "ssmr_optimistic_execution_millis_total",
            "total milliseconds spent optimistically executing SSMR streams",
            optimistic_execution_millis_total.clone(),
        );

        Self {
            streams_completed,
            streams_invalid,
            shards_sent,
            shards_received,
            bytes_sent,
            bytes_received,
            optimistic_payloads_ready,
            optimistic_payload_failures,
            optimistic_execution_millis_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::B256;
    use tempo_primitives::{TempoConsensusContext, ed25519::PublicKey as TempoPublicKey};

    fn stream_key() -> StreamKey {
        StreamKey::new(
            B256::from([1u8; 32]),
            7,
            1_000,
            123,
            TempoConsensusContext {
                epoch: 3,
                view: 4,
                parent_view: 2,
                proposer: TempoPublicKey::from_seed([9u8; 32]),
            },
        )
    }

    fn builder_shard(
        shard_index: u64,
        first_tx_index: u64,
        transactions: &[&[u8]],
    ) -> SsmrBuilderShard {
        SsmrBuilderShard {
            shard_index,
            first_tx_index,
            transactions: transactions
                .iter()
                .map(|tx| Bytes::copy_from_slice(tx))
                .collect(),
            block_access_list: None,
            cumulative_tx_bytes: transactions.iter().map(|tx| tx.len() as u64).sum(),
            cumulative_gas_estimate: 21_000 * transactions.len() as u64,
        }
    }

    fn builder_shard_with_bal(
        shard_index: u64,
        first_tx_index: u64,
        transactions: &[&[u8]],
        block_access_list: &'static [u8],
    ) -> SsmrBuilderShard {
        SsmrBuilderShard {
            block_access_list: Some(Bytes::from_static(block_access_list)),
            ..builder_shard(shard_index, first_tx_index, transactions)
        }
    }

    fn stream() -> ProposalStream {
        ProposalStream {
            stream_key: stream_key(),
            parent_height: 6,
            extra_data: Bytes::default(),
            gas_limit: 30_000_000,
            general_gas_limit: 15_000_000,
            shared_gas_limit: 5_000_000,
            shard_target_bytes: 10 * 1024,
            bal_enabled: true,
        }
    }

    #[test]
    fn proposal_stream_bundles_first_shard_into_start() {
        let message = stream()
            .message_for_event(SsmrBuilderEvent::Shard(builder_shard(0, 0, &[b"tx0"])))
            .unwrap();

        let SsmrMessage::Start(start) = message else {
            panic!("expected start");
        };
        assert_eq!(start.stream_key, stream_key());
        assert_eq!(start.first_shard.shard_index, 0);
        assert_eq!(start.first_shard.first_tx_index, 0);
        assert_eq!(
            start.first_shard.transactions,
            vec![Bytes::copy_from_slice(b"tx0")]
        );
        assert!(start.flags.tx_only);
        assert!(start.flags.bal_enabled);
    }

    #[test]
    fn proposal_stream_preserves_first_shard_bal() {
        let message = stream()
            .message_for_event(SsmrBuilderEvent::Shard(builder_shard_with_bal(
                0,
                0,
                &[b"tx0"],
                b"bal",
            )))
            .unwrap();

        let SsmrMessage::Start(start) = message else {
            panic!("expected start");
        };
        assert_eq!(
            start.first_shard.block_access_list,
            Some(Bytes::from_static(b"bal"))
        );
        assert!(start.flags.shard_bal_enabled);
    }

    #[test]
    fn proposal_stream_bundles_empty_first_shard_into_start() {
        let message = stream()
            .message_for_event(SsmrBuilderEvent::Shard(builder_shard(0, 0, &[])))
            .unwrap();

        let SsmrMessage::Start(start) = message else {
            panic!("expected start");
        };
        assert_eq!(start.stream_key, stream_key());
        assert_eq!(start.first_shard.shard_index, 0);
        assert_eq!(start.first_shard.first_tx_index, 0);
        assert!(start.first_shard.transactions.is_empty());
        assert!(start.flags.tx_only);
        assert!(start.flags.bal_enabled);
    }

    #[test]
    fn stream_buffer_folds_out_of_order_messages_after_start() {
        let key = stream_key();
        let mut buffer = StreamBuffer::default();

        buffer
            .insert(SsmrMessage::TxShard(SsmrTxShard {
                stream_key: key,
                shard: builder_shard(1, 1, &[b"tx1"]).into_payload(),
            }))
            .unwrap();
        buffer
            .insert(SsmrMessage::End(SsmrEnd {
                stream_key: key,
                total_shards: 2,
                total_transactions: 2,
            }))
            .unwrap();
        assert!(buffer.complete_transcript().is_none());

        buffer
            .insert(
                stream()
                    .message_for_event(SsmrBuilderEvent::Shard(builder_shard(0, 0, &[b"tx0"])))
                    .unwrap(),
            )
            .unwrap();

        let transcript = buffer.complete_transcript().unwrap();
        let ordered = transcript.ordered_transactions().unwrap();
        assert_eq!(
            ordered,
            vec![
                Bytes::copy_from_slice(b"tx0"),
                Bytes::copy_from_slice(b"tx1")
            ]
        );
    }

    #[test]
    fn stream_buffer_rejects_conflicting_orphan_shard() {
        let key = stream_key();
        let mut buffer = StreamBuffer::default();
        buffer
            .insert(SsmrMessage::TxShard(SsmrTxShard {
                stream_key: key,
                shard: builder_shard(1, 1, &[b"tx1"]).into_payload(),
            }))
            .unwrap();

        let error = buffer
            .insert(SsmrMessage::TxShard(SsmrTxShard {
                stream_key: key,
                shard: builder_shard(1, 1, &[b"different"]).into_payload(),
            }))
            .unwrap_err();
        assert_eq!(error, SsmrError::ConflictingShard { shard_index: 1 });
    }
}
