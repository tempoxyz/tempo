//! Backpressured SPF validation, Nitro proof generation and verification for Zone batches.

mod verification;

use verification::{ProofVerification, verifier_call, verify_proof};

use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context as TaskContext, Poll},
    time::Instant,
};

use alloy_consensus::{BlockHeader as _, Sealable as _, Transaction as _};
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_primitives::{B256, Bytes, keccak256};
use alloy_provider::DynProvider;
use alloy_sol_types::{SolCall as _, SolInterface as _};
#[cfg(feature = "fuzz")]
use antithesis_sdk::assert_always;
use eyre::{Context as _, OptionExt as _, Result, bail, ensure};
use futures::{StreamExt as _, TryStreamExt as _, stream};
use reth_primitives_traits::RecoveredBlock;
#[cfg(feature = "fuzz")]
use serde_json::json;
use tempo_alloy::TempoNetwork;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::zones::{
    IZoneInbox as ZoneInbox, IZoneOutbox as ZoneOutbox, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
};
use tempo_primitives::{Block, TempoHeader};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot},
};
use tracing::{Instrument as _, Span, debug, info, info_span, warn};
use zone_chainspec::ZoneChainSpec;
use zone_l1::TempoStateExt as _;
use zone_prover::{
    DEFAULT_MAX_REQUEST_BYTES, NITRO_VERIFIER_CONFIG_V1, PROTOCOL_VERSION, ProofBundle,
    ProverConnection, VerifierMode, VerifyRequest, VerifyResponse,
    attested_transport::RemoteProverConfig,
};
use zone_spf::{
    BatchOutput, BatchWitness, PublicInputs, TempoImport, TempoStateWitness, ZoneBlock,
    ZoneStateWitness,
};

use crate::{
    BatchAnchor, BatchData, PreparedBatch, ProverAddresses, ZoneSequencerProvider,
    metrics::ProverMetrics, proofs::ProofCollectorHandle, prover_config::active_l1_hardfork,
    settlement::BatchSubmitError,
};

/// Number of candidates allowed to wait behind the active validation.
const SETTLEMENT_PROVER_QUEUE_CAPACITY: usize = 2;
const RPC_CONCURRENCY: usize = 8;

/// Node-owned inputs required to validate canonical Zone blocks with the SPF.
#[derive(Debug, Clone)]
pub struct SettlementProverConfig {
    /// Parent Tempo chain ID bound into SPF public inputs.
    pub parent_chain_id: u64,
    /// Zone identifier bound into SPF public inputs.
    pub zone_id: u32,
    /// Chain spec used to configure the SPF.
    pub chain_spec: Arc<ZoneChainSpec>,
    /// Authenticated remote Nitro prover endpoints, routed by the live L1 hardfork.
    pub prover_addresses: ProverAddresses,
}

/// Validation worker whose attested proofs gate L1 settlement.
#[derive(Debug, Clone)]
pub struct SettlementProver {
    sender: mpsc::Sender<ProverJob>,
}

/// Locally tracked routing policy for an attestation; not part of the proof wire format.
#[derive(Debug, Clone)]
pub struct SettlementProof {
    pub bundle: ProofBundle,
    pub hardfork: TempoHardfork,
}

#[derive(Debug)]
struct ProverJob {
    from: u64,
    to: u64,
    batch: BatchData,
    anchor: BatchAnchor,
    enqueued_at: Instant,
    /// Span of the requester, so validation joins the batch's trace.
    span: Span,
    response: oneshot::Sender<Result<SettlementProof>>,
}

#[derive(Debug)]
struct ValidationStats {
    witness_bytes: usize,
    blocks: usize,
    deposits: usize,
    withdrawals: usize,
    transactions: usize,
    zone_state_nodes: usize,
    tempo_state_nodes: usize,
}

struct ProverContext<P> {
    config: SettlementProverConfig,
    zone_provider: P,
    l1_provider: DynProvider<TempoNetwork>,
}

struct ZoneInputs {
    parent_header: TempoHeader,
    blocks: Vec<ZoneBlock>,
    initial_tempo_number: u64,
    initial_tempo_hash: B256,
}

/// I/O wrapper that records when the first response byte is read.
struct FirstReadTimed<T> {
    inner: T,
    first_read_at: Arc<OnceLock<Instant>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for FirstReadTimed<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > filled_before {
            let _ = this.first_read_at.set(Instant::now());
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FirstReadTimed<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Spawn the node's settlement prover, shared by every leader generation.
pub fn spawn_settlement_prover<P: ZoneSequencerProvider>(
    config: SettlementProverConfig,
    proofs: ProofCollectorHandle,
    zone_provider: P,
    l1_provider: DynProvider<TempoNetwork>,
) -> SettlementProver {
    info!(
        target: "zone::sequencer::prover",
        zone_id = config.zone_id,
        prover_addresses = ?config.prover_addresses,
        queue_capacity = SETTLEMENT_PROVER_QUEUE_CAPACITY,
        "Prover enabled"
    );
    let (sender, mut receiver) = mpsc::channel::<ProverJob>(SETTLEMENT_PROVER_QUEUE_CAPACITY);
    let context = ProverContext {
        config,
        zone_provider,
        l1_provider,
    };
    let metrics = ProverMetrics::default();

    tokio::spawn(async move {
        while let Some(job) = receiver.recv().await {
            metrics
                .queue_duration_seconds
                .record(job.enqueued_at.elapsed().as_secs_f64());
            let started = Instant::now();
            let span = info_span!(
                parent: &job.span,
                "zone.prover.validate",
                zone_from = job.from,
                zone_to = job.to,
                withdrawal_batch_index = job.batch.withdrawal_batch_index,
            );
            let result = validate_candidate(&context, &job, &proofs, &metrics)
                .instrument(span)
                .await;
            let validation_duration_seconds = if result.is_ok() {
                &metrics.validation_duration_seconds_success
            } else {
                &metrics.validation_duration_seconds_failure
            };
            validation_duration_seconds.record(started.elapsed().as_secs_f64());
            let response = match result {
                Ok((stats, proof)) => {
                    metrics.validation_success_total.increment(1);
                    metrics.witness_bytes.record(stats.witness_bytes as f64);
                    metrics.witness_bytes_last.set(stats.witness_bytes as f64);
                    metrics.batch_size_blocks.record(stats.blocks as f64);
                    metrics.batch_size_blocks_last.set(stats.blocks as f64);
                    metrics.deposits_per_batch.record(stats.deposits as f64);
                    metrics.deposits_per_batch_last.set(stats.deposits as f64);
                    metrics
                        .withdrawals_per_batch
                        .record(stats.withdrawals as f64);
                    metrics
                        .withdrawals_per_batch_last
                        .set(stats.withdrawals as f64);
                    metrics
                        .transactions_per_batch
                        .record(stats.transactions as f64);
                    metrics
                        .transactions_per_batch_last
                        .set(stats.transactions as f64);
                    metrics
                        .zone_state_nodes
                        .record(stats.zone_state_nodes as f64);
                    metrics
                        .zone_state_nodes_last
                        .set(stats.zone_state_nodes as f64);
                    metrics
                        .tempo_state_nodes
                        .record(stats.tempo_state_nodes as f64);
                    metrics
                        .tempo_state_nodes_last
                        .set(stats.tempo_state_nodes as f64);
                    info!(
                        target: "zone::sequencer::prover",
                        zone_from = job.from,
                        zone_to = job.to,
                        prev_block_hash = %job.batch.prev_block_hash,
                        next_block_hash = %job.batch.next_block_hash,
                        elapsed_ms = started.elapsed().as_millis(),
                        witness_bytes = stats.witness_bytes,
                        blocks = stats.blocks,
                        deposits = stats.deposits,
                        withdrawals = stats.withdrawals,
                        transactions = stats.transactions,
                        zone_state_nodes = stats.zone_state_nodes,
                        tempo_state_nodes = stats.tempo_state_nodes,
                        "Prover validated batch"
                    );
                    Ok(proof)
                }
                Err(err) => {
                    metrics.failure_total.increment(1);
                    warn!(
                        target: "zone::sequencer::prover",
                        zone_from = job.from,
                        zone_to = job.to,
                        prev_block_hash = %job.batch.prev_block_hash,
                        next_block_hash = %job.batch.next_block_hash,
                        elapsed_ms = started.elapsed().as_millis(),
                        error = ?err,
                        "Prover could not complete batch validation"
                    );
                    Err(err)
                }
            };
            let _ = job.response.send(response);
        }
    });

    SettlementProver { sender }
}

impl SettlementProver {
    /// Produce the proof required to settle one finalized batch.
    pub(crate) async fn prove(
        &self,
        from: u64,
        to: u64,
        prepared: PreparedBatch,
    ) -> Result<SettlementProof> {
        let unavailable = || eyre::eyre!("settlement prover is unavailable");
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(ProverJob {
                from,
                to,
                batch: prepared.batch,
                anchor: prepared.anchor,
                enqueued_at: Instant::now(),
                span: Span::current(),
                response,
            })
            .await
            .map_err(|_| unavailable())?;
        receiver.await.map_err(|_| unavailable())?
    }

    /// Answer the first proving request with `result`.
    #[cfg(test)]
    pub(crate) fn fixed(result: Result<SettlementProof>) -> Self {
        Self::fixed_after(std::future::ready(result))
    }

    #[cfg(test)]
    pub(crate) fn fixed_after(
        result: impl Future<Output = Result<SettlementProof>> + Send + 'static,
    ) -> Self {
        let (sender, mut receiver) = mpsc::channel::<ProverJob>(1);
        tokio::spawn(async move {
            if let Some(job) = receiver.recv().await {
                let _ = job.response.send(result.await);
            }
        });
        Self { sender }
    }
}

async fn validate_candidate<P: ZoneSequencerProvider>(
    context: &ProverContext<P>,
    job: &ProverJob,
    proofs: &ProofCollectorHandle,
    metrics: &ProverMetrics,
) -> Result<(ValidationStats, SettlementProof)> {
    let (witness, stats) = build_witness(context, job, proofs, metrics).await?;
    let public_inputs = witness.public_inputs.clone();
    let batch = &job.batch;

    let started = Instant::now();
    let (remote, hardfork) = context
        .config
        .prover_addresses
        .resolve(&context.l1_provider, context.config.chain_spec.as_ref())
        .await?;
    info!(
        address = remote.address(),
        ?hardfork,
        zone_from = job.from,
        zone_to = job.to,
        "Selected remote prover"
    );
    let (output, bundle) =
        verify_remotely(remote, context.config.zone_id, job, witness, metrics).await?;
    let proof = SettlementProof { bundle, hardfork };
    metrics
        .spf_execution_duration_seconds
        .record(started.elapsed().as_secs_f64());

    let started = Instant::now();
    let comparison = compare_output(&output, batch, batch.prev_block_hash);
    #[cfg(feature = "fuzz")]
    assert_always!(
        comparison.is_ok(),
        "Prover output matches the sequencer batch",
        &json!({
            "zone_from": job.from,
            "zone_to": job.to,
            "error": comparison.as_ref().err().map(|error| format!("{error:#}")),
        })
    );
    comparison?;
    metrics
        .output_validation_duration_seconds
        .record(started.elapsed().as_secs_f64());

    let started = Instant::now();
    let call = verifier_call(&public_inputs, &output, &proof.bundle);
    let result = verify_proof(
        &context.l1_provider,
        context.config.chain_spec.as_ref(),
        call,
    )
    .await;
    metrics
        .proof_verification_duration_seconds
        .record(started.elapsed().as_secs_f64());
    match result {
        Ok(ProofVerification::Verified) => {
            metrics.proof_verification_success_total.increment(1);
            info!(target: "zone::sequencer::prover", zone_from = job.from, zone_to = job.to,
                "Nitro proof verified");
        }
        Ok(ProofVerification::SkippedBeforeT13) => {
            metrics.proof_verification_skipped_total.increment(1);
            debug!(target: "zone::sequencer::prover", zone_from = job.from, zone_to = job.to,
                "On-chain proof verification skipped before T13");
        }
        Ok(ProofVerification::Rejected) => {
            // L1 may have activated a fork with new PCRs while proving.
            let current =
                active_l1_hardfork(&context.l1_provider, context.config.chain_spec.as_ref())
                    .await?;
            if current != proof.hardfork {
                return Err(BatchSubmitError::ProverHardforkChanged {
                    proved: proof.hardfork,
                    current,
                }
                .into());
            }
            metrics.proof_verification_failure_total.increment(1);
            bail!("verifier rejected the proof");
        }
        Err(error) => {
            metrics.proof_verification_error_total.increment(1);
            return Err(error);
        }
    }

    Ok((stats, proof))
}

/// Collect and assemble the SPF witness for a candidate batch.
async fn build_witness<P: ZoneSequencerProvider>(
    context: &ProverContext<P>,
    job: &ProverJob,
    proofs: &ProofCollectorHandle,
    metrics: &ProverMetrics,
) -> Result<(BatchWitness, ValidationStats)> {
    let batch = &job.batch;
    ensure!(
        batch.zone_height == job.to,
        "candidate zone height {} does not match range end {}",
        batch.zone_height,
        job.to
    );
    ensure!(
        job.from != 1 || batch.prev_block_hash.is_zero(),
        "first Zone batch must use the zero portal prev_block_hash sentinel, found {}",
        batch.prev_block_hash
    );

    let zone_provider = context.zone_provider.clone();
    let from = job.from;
    let to = job.to;
    let expected_prev_hash = batch.prev_block_hash;
    let expected_next_hash = batch.next_block_hash;

    let started = Instant::now();
    let zone_inputs = tokio::task::spawn_blocking(move || {
        build_zone_inputs(
            &zone_provider,
            from,
            to,
            expected_prev_hash,
            expected_next_hash,
        )
    })
    .await
    .context("Zone input worker panicked")??;
    metrics
        .zone_inputs_duration_seconds
        .record(started.elapsed().as_secs_f64());

    let started = Instant::now();
    let (zone_state_witness, tempo_state_witness) =
        zone_witnesses(proofs, &zone_inputs, expected_next_hash).await?;
    metrics
        .zone_witness_duration_seconds
        .record(started.elapsed().as_secs_f64());

    let started = Instant::now();
    let (final_tempo_header, anchor) = async {
        let initial_tempo_header =
            decode_tempo_header(&tempo_state_witness.initial_tempo_header_rlp)?;
        ensure!(
            initial_tempo_header.hash_slow() == zone_inputs.initial_tempo_hash,
            "parent Zone state commits Tempo block {} hash {}, but witness returned {}",
            zone_inputs.initial_tempo_number,
            zone_inputs.initial_tempo_hash,
            initial_tempo_header.hash_slow()
        );

        let final_tempo_header = zone_inputs
            .blocks
            .last()
            .map(final_tempo_header)
            .transpose()?
            .unwrap_or_else(|| initial_tempo_header.clone());
        ensure!(
            final_tempo_header.number() == batch.tempo_block_number,
            "candidate Tempo block is {}, but the final advanceTempo header is {}",
            batch.tempo_block_number,
            final_tempo_header.number()
        );

        validate_prepared_anchor(
            &job.anchor,
            final_tempo_header.number(),
            final_tempo_header.hash_slow(),
        )?;
        Ok::<_, eyre::Report>((final_tempo_header, job.anchor.clone()))
    }
    .await?;
    metrics
        .tempo_headers_duration_seconds
        .record(started.elapsed().as_secs_f64());

    let witness = BatchWitness {
        public_inputs: PublicInputs {
            parent_chain_id: context.config.parent_chain_id,
            zone_id: context.config.zone_id,
            tempo_block_number: final_tempo_header.number(),
            anchor_block_number: anchor.block_number(batch.tempo_block_number),
            anchor_block_hash: anchor.block_hash(),
            expected_withdrawal_batch_index: batch.withdrawal_batch_index,
        },
        parent_header: zone_inputs.parent_header,
        zone_blocks: zone_inputs.blocks,
        zone_state_witness,
        tempo_state_witness,
        tempo_ancestry_headers: anchor.ancestry_headers().to_vec(),
    };

    let stats = ValidationStats {
        witness_bytes: witness_size(&witness),
        blocks: witness.zone_blocks.len(),
        deposits: witness
            .zone_blocks
            .iter()
            .map(|block| block.tempo_import.deposits().len())
            .sum(),
        withdrawals: witness
            .zone_blocks
            .iter()
            .map(|block| block.finalize_withdrawal_batch_encrypted_senders.len())
            .sum(),
        transactions: witness
            .zone_blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum(),
        zone_state_nodes: witness.zone_state_witness.node_pool.len(),
        tempo_state_nodes: witness.tempo_state_witness.node_pool.len(),
    };

    Ok((witness, stats))
}

async fn verify_remotely(
    remote: &RemoteProverConfig,
    zone_id: u32,
    job: &ProverJob,
    witness: BatchWitness,
    metrics: &ProverMetrics,
) -> Result<(BatchOutput, ProofBundle)> {
    let address = remote.address();
    let request = VerifyRequest {
        version: PROTOCOL_VERSION,
        request_id: format!(
            "zone-{zone_id}-{}-{}-{}",
            job.from, job.to, job.batch.next_block_hash
        ),
        witness,
    };
    let started = Instant::now();
    let stream = remote.connect().await;
    let connect_duration_seconds = if stream.is_ok() {
        &metrics.spf_remote_connect_duration_seconds_success
    } else {
        &metrics.spf_remote_connect_duration_seconds_failure
    };
    connect_duration_seconds.record(started.elapsed().as_secs_f64());
    let stream = stream.wrap_err_with(|| format!("connect to remote prover at {address}"))?;

    let first_read_at = Arc::new(OnceLock::new());
    let stream = FirstReadTimed {
        inner: stream,
        first_read_at: Arc::clone(&first_read_at),
    };
    let mut connection = ProverConnection::new(stream, DEFAULT_MAX_REQUEST_BYTES);

    let started = Instant::now();
    let expected_id = request.request_id.clone();
    let send_result = connection.send(request).await;
    metrics
        .spf_remote_request_send_duration_seconds
        .record(started.elapsed().as_secs_f64());
    send_result.wrap_err_with(|| format!("send request to remote prover at {address}"))?;

    let response_started = Instant::now();
    let response_result = connection.receive();
    let response_result = response_result.await;
    let response_finished = Instant::now();
    if let Some(first_read_at) = first_read_at.get().copied() {
        metrics
            .spf_remote_response_wait_duration_seconds
            .record(first_read_at.duration_since(response_started).as_secs_f64());
        metrics.spf_remote_response_receive_duration_seconds.record(
            response_finished
                .duration_since(first_read_at)
                .as_secs_f64(),
        );
    } else {
        // EOF or an I/O failure before any response bytes still belongs to the wait phase.
        metrics.spf_remote_response_wait_duration_seconds.record(
            response_finished
                .duration_since(response_started)
                .as_secs_f64(),
        );
    }
    let response: VerifyResponse = response_result
        .wrap_err_with(|| format!("read response from remote prover at {address}"))
        .and_then(|response| {
            response.ok_or_eyre("remote prover closed the connection without a response")
        })?;

    match response {
        VerifyResponse::Ok {
            version,
            request_id,
            output,
            proof_bundle,
        } => {
            validate_response_header(version, Some(&request_id), &expected_id)?;
            validate_proof_bundle(&proof_bundle)?;
            Ok((*output, proof_bundle))
        }
        VerifyResponse::Error {
            version,
            request_id,
            code,
            message,
        } => {
            validate_response_header(version, request_id.as_deref(), &expected_id)?;
            Err(eyre::eyre!(
                "remote prover rejected request ({code:?}): {message}"
            ))
        }
    }
}

fn validate_response_header(
    version: u16,
    request_id: Option<&str>,
    expected_id: &str,
) -> Result<()> {
    ensure!(
        version == PROTOCOL_VERSION,
        "remote prover responded with protocol version {version}; expected {PROTOCOL_VERSION}"
    );
    if let Some(request_id) = request_id {
        ensure!(
            request_id == expected_id,
            "remote prover response request ID {request_id} does not match {expected_id}"
        );
    }
    Ok(())
}

fn validate_proof_bundle(proof_bundle: &ProofBundle) -> Result<()> {
    let mode = VerifierMode::try_from(proof_bundle.verifier_config.as_ref())?;
    ensure!(
        mode == VerifierMode::NitroV1,
        "remote prover returned unsupported verifier config {}; expected {}",
        alloy_primitives::hex::encode_prefixed(&proof_bundle.verifier_config),
        alloy_primitives::hex::encode_prefixed(NITRO_VERIFIER_CONFIG_V1),
    );
    mode.validate_proof_shape(&proof_bundle.proof)?;
    Ok(())
}

fn build_zone_inputs<P: ZoneSequencerProvider>(
    provider: &P,
    from: u64,
    to: u64,
    expected_prev_hash: B256,
    expected_next_hash: B256,
) -> Result<ZoneInputs> {
    ensure!(from > 0, "SPF batch cannot start at Zone genesis");
    ensure!(from <= to, "invalid Zone batch range {from}..={to}");

    let parent_header = provider
        .header_by_number(from - 1)?
        .ok_or_eyre(format!("canonical Zone parent {} not found", from - 1))?;
    let parent_hash = parent_header.hash_slow();
    // ZonePortal uses zero as its pre-genesis sentinel. SPF receives the real
    // canonical hash of block 0 as the parent of block 1 instead.
    if from == 1 {
        ensure!(
            expected_prev_hash.is_zero(),
            "first Zone batch must use the zero portal prev_block_hash sentinel, found {expected_prev_hash}"
        );
        ensure!(
            !parent_hash.is_zero(),
            "canonical Zone block 0 hash must be non-zero"
        );
    } else {
        ensure!(
            parent_hash == expected_prev_hash,
            "candidate parent hash changed: expected {expected_prev_hash}, found {parent_hash}"
        );
    }
    let parent_state = provider.state_by_block_hash(parent_hash)?;
    let initial_tempo = parent_state.tempo_num_hash()?;

    let recovered = provider.recovered_block_range(from..=to)?;
    ensure!(
        recovered.len() == (to - from + 1) as usize,
        "canonical Zone range {from}..={to} returned {} blocks",
        recovered.len()
    );

    let mut expected_parent = parent_hash;
    let mut extracted = Vec::with_capacity(recovered.len());
    for (offset, block) in recovered.iter().enumerate() {
        let number = from + offset as u64;
        ensure!(
            block.number() == number,
            "canonical Zone range returned block {} at expected height {number}",
            block.number()
        );
        ensure!(
            block.parent_hash() == expected_parent,
            "Zone block {number} parent changed: expected {expected_parent}, found {}",
            block.parent_hash()
        );
        let canonical_hash = provider
            .block_hash(number)?
            .ok_or_eyre(format!("canonical Zone block {number} has no hash"))?;
        ensure!(
            block.hash() == canonical_hash,
            "recovered Zone block {number} is not canonical"
        );

        let extracted_block = extract_zone_block(block)?;
        extracted.push(extracted_block);
        expected_parent = canonical_hash;
    }
    ensure!(
        expected_parent == expected_next_hash,
        "candidate tip hash changed: expected {expected_next_hash}, found {expected_parent}"
    );

    Ok(ZoneInputs {
        parent_header,
        blocks: extracted,
        initial_tempo_number: initial_tempo.number,
        initial_tempo_hash: initial_tempo.hash,
    })
}

fn extract_zone_block(block: &RecoveredBlock<Block>) -> Result<ZoneBlock> {
    let header = block.header();
    let mut tempo_import = None;
    let mut finalize_count = None;
    let mut finalize_encrypted_senders = Vec::new();
    let mut transactions = Vec::new();

    for transaction in &block.body().transactions {
        if !transaction.is_system_tx() {
            transactions.push(Bytes::from(transaction.encoded_2718()));
            continue;
        }

        match transaction.to() {
            Some(to) if to == ZONE_INBOX_ADDRESS => {
                ensure!(
                    tempo_import.is_none(),
                    "Zone block {} contains multiple advanceTempo calls",
                    header.number()
                );
                let call = ZoneInbox::IZoneInboxCalls::abi_decode(transaction.input())
                    .wrap_err_with(|| {
                        format!("decode ZoneInbox call in Zone block {}", header.number())
                    })?;
                match call {
                    ZoneInbox::IZoneInboxCalls::advanceTempo(call) => {
                        decode_tempo_header(&call.header)?;
                        tempo_import = Some(TempoImport::Full {
                            header_rlp: call.header,
                            deposits: call.deposits,
                            decryptions: call.decryptions,
                            enabled_tokens: call.enabledTokens,
                        });
                    }
                    ZoneInbox::IZoneInboxCalls::advanceTempoHeaders(call) => {
                        ensure!(
                            !call.headers.is_empty(),
                            "checkpoint-only Zone block has no headers"
                        );
                        for encoded in &call.headers {
                            decode_tempo_header(encoded)?;
                        }
                        tempo_import = Some(TempoImport::CheckpointOnly {
                            headers_rlp: call.headers,
                        });
                    }
                    _ => {
                        return Err(eyre::eyre!(
                            "unexpected ZoneInbox call in Zone block {}",
                            header.number()
                        ));
                    }
                }
            }
            Some(to) if to == ZONE_OUTBOX_ADDRESS => {
                ensure!(
                    finalize_count.is_none(),
                    "Zone block {} contains multiple finalizeWithdrawalBatch calls",
                    header.number()
                );
                let call = ZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(transaction.input())
                    .wrap_err_with(|| {
                        format!(
                            "decode finalizeWithdrawalBatch in Zone block {}",
                            header.number()
                        )
                    })?;
                ensure!(
                    call.blockNumber == header.number(),
                    "finalization in Zone block {} declares block {}",
                    header.number(),
                    call.blockNumber
                );
                finalize_count = Some(call.count);
                finalize_encrypted_senders = call.encryptedSenders;
            }
            target => {
                bail!(
                    "unsupported system transaction target {target:?} in Zone block {}",
                    header.number()
                );
            }
        }
    }

    let tempo_import = tempo_import.ok_or_eyre(format!(
        "no advanceTempo call in Zone block {}",
        header.number()
    ))?;

    Ok(ZoneBlock {
        number: header.number(),
        parent_hash: header.parent_hash(),
        timestamp: header.timestamp(),
        timestamp_millis_part: header.timestamp_millis_part,
        beneficiary: header.beneficiary(),
        tempo_import,
        finalize_withdrawal_batch_count: finalize_count,
        finalize_withdrawal_batch_encrypted_senders: finalize_encrypted_senders,
        transactions,
    })
}

fn final_tempo_header(block: &ZoneBlock) -> Result<TempoHeader> {
    let encoded = block
        .tempo_import
        .headers_rlp()
        .last()
        .ok_or_eyre("Zone block has no Tempo headers")?;
    decode_tempo_header(encoded)
}

fn decode_tempo_header(encoded: &[u8]) -> Result<TempoHeader> {
    alloy_rlp::decode_exact(encoded).context("decode Tempo header RLP")
}

async fn zone_witnesses(
    proofs: &ProofCollectorHandle,
    inputs: &ZoneInputs,
    tip_hash: B256,
) -> Result<(ZoneStateWitness, TempoStateWitness)> {
    let from = inputs
        .blocks
        .first()
        .ok_or_eyre("empty witness range")?
        .number;
    // The next block's parent (or the validated batch tip) identifies each block.
    let blocks = inputs
        .blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            let hash = inputs
                .blocks
                .get(index + 1)
                .map_or(tip_hash, |next| next.parent_hash);
            (block.number, hash)
        })
        .collect::<Vec<_>>();
    let results = stream::iter(blocks)
        .map(|(number, hash)| async move {
            let started = Instant::now();
            debug!(
                target: "zone::sequencer::prover",
                zone_block = number,
                "Requesting Zone execution witness"
            );
            // Settlement must never bypass durability, including on a cache miss after restart.
            let witness = proofs
                .collect_and_persist(number, hash)
                .await?
                .ok_or_eyre("settlement witness range has already finalized")?
                .witness
                .clone();
            ensure!(
                witness.block_number == number && witness.block_hash == hash,
                "execution witness does not match Zone block {number} ({hash})"
            );
            debug!(
                target: "zone::sequencer::prover",
                zone_block = number,
                state_nodes = witness.execution_witness.state.len(),
                bytecodes = witness.execution_witness.codes.len(),
                ancestor_headers = witness.execution_witness.headers.len(),
                tempo_state_nodes = witness.tempo_state.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "Received Zone execution witness"
            );
            Ok::<_, eyre::Report>((number, witness))
        })
        .buffer_unordered(RPC_CONCURRENCY)
        .try_collect::<Vec<_>>()
        .await?;

    let mut state = BTreeMap::new();
    let mut codes = BTreeMap::new();
    let mut tempo_nodes = BTreeMap::new();
    let mut initial_tempo_header_rlp = None;
    for (number, witness) in results {
        if number == from {
            initial_tempo_header_rlp = Some(Bytes::from(alloy_rlp::encode(
                &witness.initial_tempo_header,
            )));
        }
        for node in witness.execution_witness.state {
            state.entry(keccak256(&node)).or_insert(node);
        }
        for code in witness.execution_witness.codes {
            codes.entry(keccak256(&code)).or_insert(code);
        }
        for node in witness.tempo_state {
            tempo_nodes.entry(keccak256(&node)).or_insert(node);
        }
    }

    Ok((
        ZoneStateWitness {
            node_pool: state.into_values().collect(),
            bytecodes: codes.into_values().collect(),
        },
        TempoStateWitness {
            initial_tempo_header_rlp: initial_tempo_header_rlp.ok_or_eyre("empty witness range")?,
            node_pool: tempo_nodes.into_values().collect(),
        },
    ))
}

fn validate_prepared_anchor(
    anchor: &BatchAnchor,
    checkpoint_number: u64,
    checkpoint_hash: B256,
) -> Result<()> {
    let BatchAnchor::Ancestry {
        block_number,
        block_hash,
        ancestry_headers,
    } = anchor
    else {
        ensure!(
            anchor.block_hash() == checkpoint_hash,
            "direct Tempo anchor hash {} does not match checkpoint {checkpoint_hash}",
            anchor.block_hash()
        );
        return Ok(());
    };

    ensure!(
        *block_number > checkpoint_number,
        "Tempo ancestry anchor {block_number} does not follow checkpoint {checkpoint_number}"
    );
    ensure!(
        ancestry_headers.len() == (*block_number - checkpoint_number) as usize,
        "Tempo ancestry header count does not cover checkpoint {checkpoint_number} through anchor {block_number}"
    );
    let mut expected_parent = checkpoint_hash;
    for (offset, encoded) in ancestry_headers.iter().enumerate() {
        let number = checkpoint_number + 1 + offset as u64;
        let header = decode_tempo_header(encoded)?;
        ensure!(
            header.number() == number,
            "Tempo ancestry returned block {} at expected height {number}",
            header.number()
        );
        ensure!(
            header.parent_hash() == expected_parent,
            "Tempo ancestry broke at block {number}: expected parent {expected_parent}, found {}",
            header.parent_hash()
        );
        expected_parent = header.hash_slow();
    }
    ensure!(
        expected_parent == *block_hash,
        "Tempo ancestry ends at {expected_parent}, not prepared anchor hash {block_hash}"
    );
    Ok(())
}

fn compare_output(output: &BatchOutput, batch: &BatchData, expected_prev_hash: B256) -> Result<()> {
    ensure!(
        output.next_zone_height == batch.zone_height,
        "next Zone height mismatch: SPF {}, candidate {}",
        output.next_zone_height,
        batch.zone_height
    );
    ensure!(
        output.block_transition.prevBlockHash == expected_prev_hash,
        "previous Zone block commitment mismatch: SPF {}, canonical parent {}",
        output.block_transition.prevBlockHash,
        expected_prev_hash
    );
    ensure!(
        output.block_transition.nextBlockHash == batch.next_block_hash,
        "next Zone block commitment mismatch: SPF {}, candidate {}",
        output.block_transition.nextBlockHash,
        batch.next_block_hash
    );
    ensure!(
        output.deposit_queue_transition.prevProcessedHash == batch.prev_processed_deposit_hash,
        "previous deposit hash mismatch: SPF {}, candidate {}",
        output.deposit_queue_transition.prevProcessedHash,
        batch.prev_processed_deposit_hash
    );
    ensure!(
        output.deposit_queue_transition.nextProcessedHash == batch.next_processed_deposit_hash,
        "next deposit hash mismatch: SPF {}, candidate {}",
        output.deposit_queue_transition.nextProcessedHash,
        batch.next_processed_deposit_hash
    );
    ensure!(
        output.deposit_queue_transition.prevDepositNumber == batch.prev_deposit_number,
        "previous deposit number mismatch: SPF {}, candidate {}",
        output.deposit_queue_transition.prevDepositNumber,
        batch.prev_deposit_number
    );
    ensure!(
        output.deposit_queue_transition.nextDepositNumber == batch.next_deposit_number,
        "next deposit number mismatch: SPF {}, candidate {}",
        output.deposit_queue_transition.nextDepositNumber,
        batch.next_deposit_number
    );
    ensure!(
        output.token_enablement_transition.prevProcessedTokenCount
            == batch.prev_processed_token_count,
        "previous token count mismatch: SPF {}, candidate {}",
        output.token_enablement_transition.prevProcessedTokenCount,
        batch.prev_processed_token_count
    );
    ensure!(
        output.token_enablement_transition.nextProcessedTokenCount
            == batch.next_processed_token_count,
        "next token count mismatch: SPF {}, candidate {}",
        output.token_enablement_transition.nextProcessedTokenCount,
        batch.next_processed_token_count
    );
    ensure!(
        output.withdrawal_queue_hash == batch.withdrawal_queue_hash,
        "withdrawal queue hash mismatch: SPF {}, candidate {}",
        output.withdrawal_queue_hash,
        batch.withdrawal_queue_hash
    );
    ensure!(
        output.last_batch_commitment.withdrawal_batch_index == batch.withdrawal_batch_index,
        "withdrawal batch index mismatch: SPF {}, candidate {}",
        output.last_batch_commitment.withdrawal_batch_index,
        batch.withdrawal_batch_index
    );
    Ok(())
}

fn witness_size(witness: &BatchWitness) -> usize {
    witness
        .zone_state_witness
        .node_pool
        .iter()
        .chain(&witness.zone_state_witness.bytecodes)
        .chain(&witness.tempo_state_witness.node_pool)
        .chain(&witness.tempo_ancestry_headers)
        .map(|bytes| bytes.len())
        .sum::<usize>()
        + witness.tempo_state_witness.initial_tempo_header_rlp.len()
        + witness
            .zone_blocks
            .iter()
            .map(|block| {
                block
                    .tempo_import
                    .headers_rlp()
                    .iter()
                    .map(|bytes| bytes.len())
                    .sum::<usize>()
                    + block
                        .transactions
                        .iter()
                        .map(|bytes| bytes.len())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header as ConsensusHeader;
    use zone_rpc::types::ZoneExecutionWitness;
    use zone_spf::{
        BlockTransition, DepositQueueTransition, LastBatchCommitment, TokenEnablementTransition,
    };

    #[tokio::test]
    async fn zone_witnesses_accepts_multiple_ancestor_headers() {
        // Collection only transports these bytes; SPF authenticates their contents.
        let state_node = Bytes::from_static(&[0xc0]);
        let code = Bytes::from_static(&[0x00]);
        let tempo_node = Bytes::from_static(&[0xc1, 0x80]);
        let mut witness = ZoneExecutionWitness {
            block_number: 3,
            block_hash: B256::repeat_byte(3),
            ..Default::default()
        };
        let (first, first_hash) = ancestry_header(1, B256::ZERO);
        let (second, _) = ancestry_header(2, first_hash);
        witness.execution_witness.headers = vec![first, second];
        witness.execution_witness.state = vec![state_node.clone()];
        witness.execution_witness.codes = vec![code.clone()];
        witness.tempo_state = vec![tempo_node.clone()];
        let initial_tempo_header_rlp =
            Bytes::from(alloy_rlp::encode(&witness.initial_tempo_header));

        let inputs = ZoneInputs {
            parent_header: TempoHeader::default(),
            blocks: vec![zone_block(3)],
            initial_tempo_number: 0,
            initial_tempo_hash: B256::ZERO,
        };
        let (state, tempo_state) = zone_witnesses(
            &ProofCollectorHandle::answering(witness),
            &inputs,
            B256::repeat_byte(3),
        )
        .await
        .expect("ancestor headers must not prevent witness collection");

        assert_eq!(state.node_pool, vec![state_node]);
        assert_eq!(state.bytecodes, vec![code]);
        assert_eq!(tempo_state.node_pool, vec![tempo_node]);
        assert_eq!(
            tempo_state.initial_tempo_header_rlp,
            initial_tempo_header_rlp
        );
    }

    fn ancestry_header(number: u64, parent_hash: B256) -> (Bytes, B256) {
        let header = TempoHeader {
            inner: ConsensusHeader {
                number,
                parent_hash,
                ..Default::default()
            },
            ..Default::default()
        };
        let hash = header.hash_slow();
        (Bytes::from(alloy_rlp::encode(&header)), hash)
    }

    #[test]
    fn prover_uses_the_prepared_ancestry_without_sampling_a_head() {
        let checkpoint_number = 162_000;
        let checkpoint_hash = B256::repeat_byte(0x11);
        let (first, first_hash) = ancestry_header(checkpoint_number + 1, checkpoint_hash);
        let (second, anchor_hash) = ancestry_header(checkpoint_number + 2, first_hash);
        let anchor = BatchAnchor::Ancestry {
            block_number: checkpoint_number + 2,
            block_hash: anchor_hash,
            ancestry_headers: vec![first, second],
        };

        validate_prepared_anchor(&anchor, checkpoint_number, checkpoint_hash).unwrap();
    }

    #[test]
    fn prover_rejects_a_prepared_anchor_with_a_different_terminal_hash() {
        let checkpoint_number = 162_000;
        let checkpoint_hash = B256::repeat_byte(0x11);
        let (header, _) = ancestry_header(checkpoint_number + 1, checkpoint_hash);
        let anchor = BatchAnchor::Ancestry {
            block_number: checkpoint_number + 1,
            block_hash: B256::repeat_byte(0x22),
            ancestry_headers: vec![header],
        };

        let error = validate_prepared_anchor(&anchor, checkpoint_number, checkpoint_hash)
            .expect_err("terminal anchor mismatch must fail proving");
        assert!(error.to_string().contains("not prepared anchor hash"));
    }

    #[test]
    fn rejects_noncanonical_verifier_config() {
        let bundle = ProofBundle {
            verifier_config: Bytes::from_static(&[0x02]),
            proof: Bytes::from_static(&[0xaa]),
        };

        let error = validate_proof_bundle(&bundle).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported verifier config 0x02; expected 0x01")
        );
    }

    fn comparison_fixture() -> (BatchData, BatchOutput) {
        let batch = BatchData {
            zone_height: 1,
            tempo_block_number: 1,
            prev_block_hash: B256::repeat_byte(1),
            next_block_hash: B256::repeat_byte(2),
            prev_processed_deposit_hash: B256::repeat_byte(3),
            next_processed_deposit_hash: B256::repeat_byte(4),
            prev_deposit_number: 5,
            next_deposit_number: 6,
            prev_processed_token_count: 0,
            next_processed_token_count: 8,
            withdrawal_queue_hash: B256::repeat_byte(9),
            withdrawal_batch_index: 10,
        };
        let output = BatchOutput {
            next_zone_height: batch.zone_height,
            block_transition: BlockTransition {
                prevBlockHash: batch.prev_block_hash,
                nextBlockHash: batch.next_block_hash,
            },
            deposit_queue_transition: DepositQueueTransition {
                prevProcessedHash: batch.prev_processed_deposit_hash,
                nextProcessedHash: batch.next_processed_deposit_hash,
                prevDepositNumber: batch.prev_deposit_number,
                nextDepositNumber: batch.next_deposit_number,
            },
            token_enablement_transition: TokenEnablementTransition {
                prevProcessedTokenCount: batch.prev_processed_token_count,
                nextProcessedTokenCount: batch.next_processed_token_count,
            },
            withdrawal_queue_hash: batch.withdrawal_queue_hash,
            last_batch_commitment: LastBatchCommitment {
                withdrawal_batch_index: batch.withdrawal_batch_index,
            },
        };
        (batch, output)
    }

    #[test]
    fn proof_output_must_match_settlement_height() {
        let (batch, mut output) = comparison_fixture();
        compare_output(&output, &batch, batch.prev_block_hash).unwrap();
        output.next_zone_height += 1;
        assert!(
            compare_output(&output, &batch, batch.prev_block_hash)
                .unwrap_err()
                .to_string()
                .contains("next Zone height mismatch")
        );
    }

    #[test]
    fn output_comparison_preserves_raw_migration_cursor() {
        let (batch, mut output) = comparison_fixture();
        compare_output(&output, &batch, batch.prev_block_hash).unwrap();
        output.token_enablement_transition.prevProcessedTokenCount = 7;
        assert!(
            compare_output(&output, &batch, batch.prev_block_hash)
                .unwrap_err()
                .to_string()
                .contains("previous token count mismatch")
        );
    }
    fn zone_block(number: u64) -> ZoneBlock {
        ZoneBlock {
            number,
            parent_hash: B256::ZERO,
            timestamp: 0,
            timestamp_millis_part: 0,
            beneficiary: alloy_primitives::Address::ZERO,
            tempo_import: TempoImport::Full {
                header_rlp: Bytes::new(),
                deposits: Vec::new(),
                decryptions: Vec::new(),
                enabled_tokens: Vec::new(),
            },
            finalize_withdrawal_batch_count: None,
            finalize_withdrawal_batch_encrypted_senders: Vec::new(),
            transactions: Vec::new(),
        }
    }
}
