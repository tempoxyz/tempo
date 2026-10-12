use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_consensus::{BlockHeader as _, Sealable as _, Transaction as _};
use alloy_eips::{BlockHashOrNumber, eip2718::Encodable2718 as _, eip2935::HISTORY_SERVE_WINDOW};
use alloy_network::primitives::BlockTransactions;
use alloy_primitives::{Address, B256, Bytes, keccak256};
use alloy_provider::{DynProvider, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{Block, BlockNumberOrTag, Transaction};
use alloy_sol_types::{SolCall as _, SolInterface as _};
use clap::{Parser, Subcommand};
use eyre::{Context, OptionExt, Result, bail, eyre};
use futures::{StreamExt, TryStreamExt, stream};
use tempo_alloy::{TempoNetwork, rpc::TempoHeaderResponse};
use tempo_primitives::{TempoHeader, TempoTxEnvelope};
use tempo_contracts::zones::{
    IZoneInbox as ZoneInbox, IZoneOutbox as ZoneOutbox, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
    ZonePortal,
};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;
use zone_chainspec::{ZoneChainSpec, ZoneChainSpecParser};
use zone_precompiles::outbox;
use zone_primitives::constants::zone_chain_id;
use zone_prover::{
    DEFAULT_MAX_REQUEST_BYTES, PROTOCOL_VERSION, ProofBundle, ProverConnection, VerifyRequest,
    VerifyResponse, attested_transport::RemoteProverConfig,
};
use zone_rpc::types::ZoneExecutionWitness;
use zone_spf::{
    BatchOutput, BatchWitness, PublicInputs, SpfConfig, TempoImport, TempoStateWitness, ZoneBlock,
    ZoneStateWitness, prove_zone_batch,
};

mod verifier_request;
mod verify;

const EIP2935_SAFETY_MARGIN: u64 = 360;
const RPC_CONCURRENCY: usize = 8;
const ZONE_HEAD_POLL_INTERVAL: Duration = Duration::from_secs(1);
const LOG_QUERY_BLOCK_CHUNK: u64 = 1_000;

type RpcBlock = Block<Transaction<TempoTxEnvelope>, TempoHeaderResponse>;

#[derive(Debug, Parser)]
#[command(
    name = "tempo-zone-prover-utils",
    about = "Tempo Zone prover development utilities"
)]
struct Cli {
    /// Tracing filter. Can also be set with RUST_LOG.
    #[arg(
        long,
        global = true,
        env = "RUST_LOG",
        default_value = "tempo_zone_prover_utils=info"
    )]
    log_filter: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate and locally validate an SPF batch witness.
    GenerateInput(GenerateInputArgs),
    /// Send a saved witness to a prover and save its output and proof.
    Prove(ProveArgs),
    /// Verify a saved proof against the native L1 verifier using eth_call.
    Verify(verify::VerifyArgs),
}

#[derive(Debug, clap::Args)]
struct ProveArgs {
    /// Batch witness JSON produced by generate-input.
    #[arg(long, short, value_name = "PATH")]
    input: PathBuf,

    /// Prover TCP socket, including a TCP-to-vsock proxy for a Nitro enclave.
    #[arg(long, value_name = "HOST:PORT")]
    target: String,

    /// JSON allowlist used to authenticate the prover's Nitro attestation.
    #[arg(long, value_name = "PATH")]
    attestation_policy: PathBuf,

    /// Write the complete successful JSON response, including output and proofBundle.
    #[arg(long, short, value_name = "PATH")]
    output: PathBuf,
}

#[derive(Debug, clap::Args)]
struct GenerateInputArgs {
    /// Tempo L1 HTTP or WebSocket RPC URL.
    #[arg(long)]
    tempo_rpc_url: String,

    /// The Zone genesis JSON: a local path, inline JSON, or an HTTP(S) URL.
    #[arg(long, value_name = "CHAIN_OR_PATH_OR_URL")]
    chain: String,

    /// Unrestricted Zone RPC URL used for full blocks, state, and debug methods.
    #[arg(long)]
    zone_rpc_url: String,

    /// Override the first Zone block (inclusive) by number or hash.
    #[arg(long, value_name = "NUMBER_OR_HASH")]
    from_block: Option<BlockHashOrNumber>,

    /// Select the submitted batch containing this Zone block; fail if not yet submitted.
    #[arg(long, value_name = "NUMBER_OR_HASH", conflicts_with_all = ["from_block", "to_block", "zone_block_count", "wait_timeout"])]
    block: Option<BlockHashOrNumber>,

    /// Override the final Zone block (inclusive) by number or hash. Defaults to the Zone tip.
    #[arg(
        long,
        value_name = "NUMBER_OR_HASH",
        conflicts_with = "zone_block_count"
    )]
    to_block: Option<BlockHashOrNumber>,

    /// Execute exactly this many Zone blocks, waiting for the target block if necessary.
    #[arg(long, conflicts_with = "to_block")]
    zone_block_count: Option<u64>,

    /// Stop waiting for `--zone-block-count` after this many seconds.
    #[arg(long, value_name = "SECONDS", requires = "zone_block_count")]
    wait_timeout: Option<u64>,

    /// Write the complete JSON witness to this path.
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Send the generated witness to a Tempo Zone prover TCP socket.
    #[arg(long, value_name = "HOST:PORT", requires = "attestation_policy")]
    target: Option<String>,

    /// JSON allowlist used to authenticate the target prover's Nitro attestation.
    #[arg(long, value_name = "PATH", requires = "target")]
    attestation_policy: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct Timings(Vec<(&'static str, Duration)>);

impl Timings {
    fn record<T>(&mut self, name: &'static str, started: Instant, value: T) -> T {
        let elapsed = started.elapsed();
        info!(
            phase = name,
            elapsed_ms = elapsed.as_millis(),
            "phase complete"
        );
        self.0.push((name, elapsed));
        value
    }

    fn print(&self, total: Duration) {
        println!("\nTiming");
        for (name, elapsed) in &self.0 {
            println!("  {name:<22} {}", format_duration(*elapsed));
        }
        println!("  {:<22} {}", "total", format_duration(total));
    }
}

#[derive(Debug)]
struct Discovery {
    zone_id: u32,
    portal: Address,
    portal_withdrawal_batch_index: u64,
    portal_tempo_block_number: u64,
    tempo_chain_id: u64,
    portal_block_hash: B256,
}

#[derive(Debug)]
struct PortalSnapshot {
    withdrawal_batch_index: u64,
    tempo_block_number: u64,
    block_hash: B256,
}

#[derive(Debug)]
struct ExtractedBlock {
    input: ZoneBlock,
    block_hash: B256,
    checkpoint_number: u64,
    has_finalization: bool,
    user_transaction_count: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_filter)?;
    match cli.command {
        Command::GenerateInput(args) => generate_input(args).await,
        Command::Prove(args) => prove(args).await,
        Command::Verify(args) => verify::run(args).await,
    }
}

fn init_tracing(filter: &str) -> Result<()> {
    let filter = EnvFilter::try_new(filter).context("parse tracing filter")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|error| eyre!("initialize tracing: {error}"))
}

fn start_phase(name: &'static str) -> Instant {
    info!(phase = name, "starting phase");
    Instant::now()
}

async fn generate_input(args: GenerateInputArgs) -> Result<()> {
    let total_started = Instant::now();
    let mut timings = Timings::default();
    info!(
        block = ?args.block,
        from_block = ?args.from_block,
        to_block = ?args.to_block,
        zone_block_count = ?args.zone_block_count,
        wait_timeout_seconds = ?args.wait_timeout,
        writes_output = args.output.is_some(),
        target = ?args.target,
        "generating SPF input"
    );
    if args.zone_block_count == Some(0) {
        bail!("--zone-block-count must be greater than zero");
    }
    if args.block == Some(0.into()) {
        bail!("Zone genesis block 0 does not belong to a submitted batch");
    }
    let chain = load_chain(&args.chain).await?;

    let started = start_phase("discovery");
    let tempo_provider = connect(&args.tempo_rpc_url, "Tempo").await?;
    let zone_provider = connect(&args.zone_rpc_url, "unrestricted Zone").await?;
    let mut discovery = discover(&tempo_provider, &zone_provider).await?;
    let spf_config = SpfConfig::new(chain);
    info!(
        zone_id = discovery.zone_id,
        portal = %discovery.portal,
        committed_zone_hash = %discovery.portal_block_hash,
        portal_tempo_block = discovery.portal_tempo_block_number,
        withdrawal_batch_index = discovery.portal_withdrawal_batch_index,
        "discovered Zone"
    );
    timings.record("discovery", started, ());

    let started = start_phase("batch extraction");
    let (from_override, to_override, target_block) = tokio::try_join!(
        resolve_block_number(&zone_provider, args.from_block),
        resolve_block_number(&zone_provider, args.to_block),
        resolve_block_number(&zone_provider, args.block),
    )?;
    let (parent_header, parent_number, extracted) = if let Some(block) = target_block {
        let batch =
            find_submitted_batch(&tempo_provider, &zone_provider, &discovery, block).await?;
        let (parent, parent_number, extracted) =
            discover_batch(&zone_provider, &discovery, Some(batch.from), Some(batch.to)).await?;
        if parent.hash_slow() != batch.parent_hash
            || extracted.last().expect("non-empty batch").block_hash != batch.block_hash
        {
            bail!("selected Zone range does not match the submitted batch hashes");
        }
        let target = extracted
            .iter()
            .find(|extracted| extracted.input.number == block)
            .expect("selected batch contains the target block");
        validate_boundary_hash(args.block, block, target.block_hash)?;
        (parent, parent_number, extracted)
    } else if let Some(block_count) = args.zone_block_count {
        let (updated_discovery, parent_header, parent_number, extracted) = discover_counted_batch(
            &zone_provider,
            &tempo_provider,
            discovery,
            from_override,
            block_count,
            args.wait_timeout.map(Duration::from_secs),
        )
        .await?;
        discovery = updated_discovery;
        (parent_header, parent_number, extracted)
    } else {
        discover_batch(&zone_provider, &discovery, from_override, to_override).await?
    };
    let first_extracted = extracted
        .first()
        .expect("batch discovery returns a non-empty batch");
    let from_block = first_extracted.input.number;
    let last_extracted = extracted.last().expect("non-empty");
    let to_block = last_extracted.input.number;
    validate_boundary_hash(args.from_block, from_block, first_extracted.block_hash)?;
    validate_boundary_hash(args.to_block, to_block, last_extracted.block_hash)?;
    let next_block_hash = last_extracted.block_hash;
    let finalization_count = extracted
        .iter()
        .filter(|block| block.has_finalization)
        .count();
    let parent_withdrawal_batch_index = withdrawal_batch_index_at(&zone_provider, parent_number)
        .await
        .context("read withdrawal batch index from parent Zone state")?;
    if args.from_block.is_none()
        && args.block.is_none()
        && parent_withdrawal_batch_index != discovery.portal_withdrawal_batch_index
    {
        bail!(
            "parent Zone state has withdrawal batch index {parent_withdrawal_batch_index}, but the Tempo portal reports {}",
            discovery.portal_withdrawal_batch_index,
        );
    }
    let expected_withdrawal_batch_index = parent_withdrawal_batch_index
        .checked_add(u64::try_from(finalization_count).expect("block count fits u64"))
        .ok_or_else(|| eyre!("withdrawal batch index overflow"))?;
    let (zone_head, tempo_head) = tokio::try_join!(
        zone_provider.get_block_number(),
        tempo_provider.get_block_number()
    )?;
    info!(
        from_block,
        to_block,
        zone_head,
        tempo_head,
        portal_tempo_block = discovery.portal_tempo_block_number,
        block_count = extracted.len(),
        finalization_count,
        "selected Zone block range"
    );
    timings.record("batch extraction", started, ());

    let started = start_phase("Zone and Tempo state witnesses");
    let (zone_state_witness, tempo_state_witness) =
        zone_witnesses(&zone_provider, from_block, to_block).await?;
    let initial_tempo_header = decode_tempo_header(&tempo_state_witness.initial_tempo_header_rlp)?;
    timings.record("Zone and Tempo state witnesses", started, ());

    let final_tempo_header = extracted
        .iter()
        .last()
        .map(|encoded| {
            let block = &encoded.input;
            decode_tempo_header(
                block
                    .tempo_import
                    .headers_rlp()
                    .last()
                    .expect("extracted Tempo header"),
            )
        })
        .transpose()?
        .unwrap_or_else(|| initial_tempo_header.clone());

    let started = start_phase("Tempo ancestry");
    let (anchor_block_number, anchor_block_hash, tempo_ancestry_headers, anchor_mode) =
        tempo_anchor(&tempo_provider, &final_tempo_header).await?;
    timings.record("Tempo ancestry", started, ());

    let witness = BatchWitness {
        public_inputs: PublicInputs {
            parent_chain_id: discovery.tempo_chain_id,
            zone_id: discovery.zone_id,
            tempo_block_number: final_tempo_header.number(),
            anchor_block_number,
            anchor_block_hash,
            expected_withdrawal_batch_index,
        },
        parent_header,
        zone_blocks: extracted.iter().map(|block| block.input.clone()).collect(),
        zone_state_witness,
        tempo_state_witness,
        tempo_ancestry_headers,
    };

    let started = start_phase("SPF validation");
    let output = prove_zone_batch(&spf_config, witness.clone())
        .context("generated witness failed SPF validation")?;
    if output.block_transition.nextBlockHash != next_block_hash {
        bail!(
            "SPF replay produced {}, but Zone block {to_block} has hash {next_block_hash}",
            output.block_transition.nextBlockHash
        );
    }
    timings.record("SPF validation", started, ());

    let request_id = format!(
        "zone-{}-{from_block}-{to_block}-{}",
        discovery.zone_id, output.block_transition.nextBlockHash
    );
    let request = VerifyRequest {
        version: PROTOCOL_VERSION,
        request_id,
        witness,
    };

    let started = start_phase("output");
    let output_bytes = if let Some(path) = &args.output {
        let json =
            serde_json::to_vec_pretty(&request.witness).context("serialize batch witness")?;
        std::fs::write(path, &json)
            .wrap_err_with(|| format!("write SPF input to {}", path.display()))?;
        Some(json.len())
    } else {
        None
    };
    timings.record("output", started, ());

    print_summary(
        &discovery,
        &request.witness,
        &extracted,
        &output,
        anchor_mode,
        args.output.as_ref().zip(output_bytes),
    );

    // Clap requires the target and policy together.
    if let Some((target, policy)) = args.target.as_ref().zip(args.attestation_policy.as_deref()) {
        let remote = RemoteProverConfig::from_policy_file(target.clone(), policy)?;
        let started = start_phase("target prover");
        let bytes = send_to_prover(&remote, request, &output).await?;
        timings.record("target prover", started, ());
        println!("  Target prover:         {target} ({bytes} request bytes, verified)");
    } else {
        println!("  Target prover:         not sent (pass --target <HOST:PORT>)");
    }
    timings.print(total_started.elapsed());
    Ok(())
}

async fn prove(args: ProveArgs) -> Result<()> {
    let remote =
        RemoteProverConfig::from_policy_file(args.target.clone(), &args.attestation_policy)?;
    prove_with_connection(args, remote.connect()).await
}

async fn prove_with_connection<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    args: ProveArgs,
    connect: impl std::future::Future<Output = std::io::Result<IO>>,
) -> Result<()> {
    let total_started = Instant::now();
    let mut timings = Timings::default();
    info!(input = %args.input.display(), target = %args.target, output = %args.output.display(), "proving saved witness");
    let started = start_phase("read witness");
    let input = std::fs::read(&args.input)
        .wrap_err_with(|| format!("read batch witness from {}", args.input.display()))?;
    let witness: BatchWitness =
        serde_json::from_slice(&input).context("parse batch witness JSON")?;
    info!(bytes = input.len(), "loaded batch witness");
    timings.record("read witness", started, ());
    let request_id = format!("prove-{}", keccak256(&input));
    let request = VerifyRequest {
        version: PROTOCOL_VERSION,
        request_id: request_id.clone(),
        witness,
    };
    let started = start_phase("target prover");
    let stream = connect.await.wrap_err("authenticate target prover")?;
    let (_, response) = exchange_with_prover(&args.target, stream, request).await?;
    timings.record("target prover", started, ());
    let started = start_phase("validate response");
    validate_proof_response(&response, &request_id)?;
    timings.record("validate response", started, ());
    let started = start_phase("output");
    let json = serde_json::to_vec_pretty(&response).context("serialize prover response")?;
    std::fs::write(&args.output, &json)
        .wrap_err_with(|| format!("write prover response to {}", args.output.display()))?;
    println!("Saved prover output and proof to {}", args.output.display());
    info!(bytes = json.len(), "saved prover response");
    timings.record("output", started, ());
    timings.print(total_started.elapsed());
    Ok(())
}

fn validate_proof_response<'a>(
    response: &'a VerifyResponse,
    request_id: &str,
) -> Result<(&'a BatchOutput, &'a ProofBundle)> {
    match response {
        VerifyResponse::Ok {
            version,
            request_id: response_id,
            proof_bundle,
            output,
            ..
        } => {
            if *version != PROTOCOL_VERSION {
                bail!("target prover response version {version}; expected {PROTOCOL_VERSION}");
            }
            if response_id != request_id {
                bail!("target prover response ID {response_id} does not match {request_id}");
            }
            if proof_bundle.verifier_config.is_empty() {
                bail!("target prover returned empty proofBundle.verifierConfig");
            }
            if proof_bundle.proof.is_empty() {
                bail!("target prover returned empty proofBundle.proof");
            }
            Ok((output, proof_bundle))
        }
        VerifyResponse::Error {
            version,
            request_id: response_id,
            code,
            message,
        } => {
            if *version != PROTOCOL_VERSION {
                bail!("target prover response version {version}; expected {PROTOCOL_VERSION}");
            }
            if let Some(response_id) = response_id
                && response_id != request_id
            {
                bail!("target prover response ID {response_id} does not match {request_id}");
            }
            bail!("target prover rejected request ({code:?}): {message}");
        }
    }
}

async fn exchange_with_prover(
    target: &str,
    stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    request: VerifyRequest,
) -> Result<(usize, VerifyResponse)> {
    let mut connection = ProverConnection::new(stream, DEFAULT_MAX_REQUEST_BYTES);
    let started = Instant::now();
    info!("sending witness to prover");
    let request_bytes = connection
        .send(request)
        .await
        .wrap_err_with(|| format!("send request to target prover at {target}"))?;
    info!(
        bytes = request_bytes,
        elapsed_ms = started.elapsed().as_millis(),
        "sent witness; waiting for prover response"
    );
    let started = Instant::now();
    let response = connection
        .receive()
        .await
        .wrap_err_with(|| format!("read response from target prover at {target}"))?
        .ok_or_else(|| eyre!("target prover closed the connection without a response"))?;
    info!(
        elapsed_ms = started.elapsed().as_millis(),
        "received prover response"
    );
    Ok((request_bytes, response))
}

async fn send_to_prover(
    remote: &RemoteProverConfig,
    request: VerifyRequest,
    expected_output: &BatchOutput,
) -> Result<usize> {
    let target = remote.address();
    let started = Instant::now();
    info!(target, "connecting to prover");
    let stream = remote
        .connect()
        .await
        .wrap_err_with(|| format!("connect to target prover at {target}"))?;
    info!(
        elapsed_ms = started.elapsed().as_millis(),
        "connected to prover"
    );
    let expected_id = request.request_id.clone();
    let (request_bytes, response) = exchange_with_prover(target, stream, request).await?;
    validate_proof_response(&response, &expected_id)?;
    let VerifyResponse::Ok { output, .. } = response else {
        unreachable!("successful validation requires an ok response")
    };
    if *output != *expected_output {
        bail!("target prover output does not match local SPF output");
    }
    Ok(request_bytes)
}

async fn connect(url: &str, label: &str) -> Result<DynProvider<TempoNetwork>> {
    ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(url)
        .await
        .wrap_err_with(|| format!("connect to {label} RPC at {url}"))
        .map(Provider::erased)
}

async fn load_chain(source: &str) -> Result<Arc<ZoneChainSpec>> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let genesis = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?
            .get(source)
            .send()
            .await
            .context("download Zone genesis JSON")?
            .error_for_status()
            .context("download Zone genesis JSON")?
            .json()
            .await
            .context("decode Zone genesis JSON")?;
        Ok(Arc::new(ZoneChainSpec::from_genesis(genesis)?))
    } else {
        <ZoneChainSpecParser as reth_cli::chainspec::ChainSpecParser>::parse(source)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct SubmittedBatch {
    from: u64,
    to: u64,
    parent_hash: B256,
    block_hash: B256,
}

async fn find_submitted_batch(
    tempo: &DynProvider<TempoNetwork>,
    zone: &DynProvider<TempoNetwork>,
    discovery: &Discovery,
    target: u64,
) -> Result<SubmittedBatch> {
    if target == 0 {
        bail!("Zone genesis block 0 does not belong to a submitted batch");
    }
    let committed = portal_parent_number(zone, discovery).await?;
    if target > committed {
        bail!(
            "batch containing Zone block {target} has not been submitted yet (last submitted block: {committed})"
        );
    }

    let portal = ZonePortal::new(discovery.portal, tempo.clone());
    let mut hi = tempo.get_block_number().await?;
    let mut end = None;
    loop {
        let lo = hi.saturating_sub(LOG_QUERY_BLOCK_CHUNK - 1);
        let mut events = portal
            .BatchSubmitted_1_filter()
            .from_block(lo)
            .to_block(hi)
            .query()
            .await
            .wrap_err_with(|| format!("read submitted batches in Tempo blocks {lo}..={hi}"))?;
        events.sort_by_key(|(_, log)| (log.block_number, log.transaction_index, log.log_index));
        for (event, _) in events.into_iter().rev() {
            let hash = event.nextBlockHash;
            let block = zone.get_block_by_hash(hash).await?.ok_or_else(|| {
                eyre!("submitted Zone block {hash} not found on unrestricted RPC")
            })?;
            let number = block.header.number();
            if number < target {
                let (to, block_hash) =
                    end.ok_or_else(|| eyre!("no submitted batch contains Zone block {target}"))?;
                return Ok(SubmittedBatch {
                    from: number + 1,
                    to,
                    parent_hash: hash,
                    block_hash,
                });
            }
            end = Some((number, hash));
            // The portal starts at index zero and increments before emitting. Recognizing
            // its first submission avoids scanning all of Tempo history before deployment.
            if event.withdrawalBatchIndex == 1 {
                return Ok(SubmittedBatch {
                    from: 1,
                    to: number,
                    parent_hash: zone_header(zone, 0).await?.hash_slow(),
                    block_hash: hash,
                });
            }
        }
        if lo == 0 {
            bail!("could not find complete submitted batch boundaries for Zone block {target}");
        }
        hi = lo - 1;
    }
}

async fn discover(
    tempo: &DynProvider<TempoNetwork>,
    zone: &DynProvider<TempoNetwork>,
) -> Result<Discovery> {
    let inbox = ZoneInbox::new(ZONE_INBOX_ADDRESS, zone.clone());
    let portal_call = inbox.tempoPortal();
    let (tempo_chain_id, actual_zone_chain_id, portal_address) = tokio::try_join!(
        async { tempo.get_chain_id().await.context("read Tempo chain ID") },
        async {
            zone.get_chain_id()
                .await
                .context("read unrestricted Zone chain ID")
        },
        async {
            portal_call
                .call()
                .await
                .context("read Tempo portal from unrestricted Zone RPC")
        }
    )?;
    if portal_address.is_zero() {
        bail!("ZoneInbox reports a zero Tempo portal address");
    }
    let (zone_id, portal) = tokio::try_join!(
        async {
            ZonePortal::new(portal_address, tempo.clone())
                .zoneId()
                .call()
                .await
                .wrap_err_with(|| format!("read Zone ID from portal {portal_address}"))
        },
        read_portal_snapshot(tempo, portal_address),
    )?;
    let expected_chain_id = zone_chain_id(tempo_chain_id, zone_id)?;
    if actual_zone_chain_id != expected_chain_id {
        bail!(
            "Zone portal reports Zone ID {zone_id}, which requires chain ID {expected_chain_id}, but the unrestricted Zone RPC reports {actual_zone_chain_id}"
        );
    }

    Ok(Discovery {
        zone_id,
        portal: portal_address,
        portal_withdrawal_batch_index: portal.withdrawal_batch_index,
        portal_tempo_block_number: portal.tempo_block_number,
        tempo_chain_id,
        portal_block_hash: portal.block_hash,
    })
}

async fn read_portal_snapshot(
    tempo: &DynProvider<TempoNetwork>,
    portal_address: Address,
) -> Result<PortalSnapshot> {
    let portal = ZonePortal::new(portal_address, tempo.clone());
    let withdrawal_batch_index_call = portal.withdrawalBatchIndex();
    let block_hash_call = portal.blockHash();
    let tempo_block_number_call = portal.lastSyncedTempoBlockNumber();
    let (withdrawal_batch_index, block_hash, tempo_block_number) = tokio::try_join!(
        withdrawal_batch_index_call.call(),
        block_hash_call.call(),
        tempo_block_number_call.call(),
    )
    .wrap_err_with(|| format!("read Zone portal state from {portal_address}"))?;
    Ok(PortalSnapshot {
        withdrawal_batch_index,
        tempo_block_number,
        block_hash,
    })
}

fn apply_portal_snapshot(discovery: &mut Discovery, snapshot: PortalSnapshot) {
    discovery.portal_withdrawal_batch_index = snapshot.withdrawal_batch_index;
    discovery.portal_tempo_block_number = snapshot.tempo_block_number;
    discovery.portal_block_hash = snapshot.block_hash;
}

async fn discover_counted_batch(
    zone: &DynProvider<TempoNetwork>,
    tempo: &DynProvider<TempoNetwork>,
    mut discovery: Discovery,
    from_override: Option<u64>,
    block_count: u64,
    wait_timeout: Option<Duration>,
) -> Result<(Discovery, TempoHeader, u64, Vec<ExtractedBlock>)> {
    let wait_started = Instant::now();

    'selection: loop {
        let from = match from_override {
            Some(from) => from,
            None => portal_parent_number(zone, &discovery)
                .await?
                .checked_add(1)
                .ok_or_else(|| eyre!("Zone block number overflow after the portal commitment"))?,
        };
        let (_, to) = counted_range(from, block_count)?;
        info!(
            from_block = from,
            to_block = to,
            block_count,
            committed_zone_hash = %discovery.portal_block_hash,
            "waiting for counted Zone block range"
        );

        let mut last_logged_head = None;
        loop {
            let zone_head = if from_override.is_none() {
                let portal = ZonePortal::new(discovery.portal, tempo.clone());
                let block_hash_call = portal.blockHash();
                let (zone_head, portal_block_hash) =
                    tokio::join!(zone.get_block_number(), block_hash_call.call());
                let zone_head = zone_head.context("read Zone head while waiting")?;
                let portal_block_hash =
                    portal_block_hash.context("read portal block hash while waiting")?;
                if portal_block_hash != discovery.portal_block_hash {
                    info!(
                        old_committed_zone_hash = %discovery.portal_block_hash,
                        new_committed_zone_hash = %portal_block_hash,
                        "portal advanced while waiting; rebasing counted range"
                    );
                    let snapshot = read_portal_snapshot(tempo, discovery.portal).await?;
                    apply_portal_snapshot(&mut discovery, snapshot);
                    continue 'selection;
                }
                zone_head
            } else {
                zone.get_block_number().await?
            };

            if zone_head >= to {
                info!(
                    zone_head,
                    target_zone_block = to,
                    waited_ms = wait_started.elapsed().as_millis(),
                    "counted Zone block range is available"
                );
                break;
            }

            if last_logged_head != Some(zone_head) {
                info!(
                    zone_head,
                    target_zone_block = to,
                    remaining_blocks = to - zone_head,
                    waited_ms = wait_started.elapsed().as_millis(),
                    "waiting for Zone head"
                );
                last_logged_head = Some(zone_head);
            }

            let sleep_for = match wait_timeout {
                Some(timeout) => {
                    let elapsed = wait_started.elapsed();
                    if elapsed >= timeout {
                        bail!(
                            "timed out after {:.3}s waiting for Zone block {to}; current head is {zone_head}",
                            elapsed.as_secs_f64()
                        );
                    }
                    ZONE_HEAD_POLL_INTERVAL.min(timeout - elapsed)
                }
                None => ZONE_HEAD_POLL_INTERVAL,
            };
            tokio::time::sleep(sleep_for).await;
        }

        if from_override.is_none() {
            let snapshot = read_portal_snapshot(tempo, discovery.portal).await?;
            if snapshot.block_hash != discovery.portal_block_hash {
                info!(
                    old_committed_zone_hash = %discovery.portal_block_hash,
                    new_committed_zone_hash = %snapshot.block_hash,
                    "portal advanced after Zone target was reached; rebasing counted range"
                );
                apply_portal_snapshot(&mut discovery, snapshot);
                continue;
            }
            apply_portal_snapshot(&mut discovery, snapshot);
        }

        let (parent_header, parent_number, blocks) =
            discover_batch(zone, &discovery, from_override, Some(to)).await?;

        if from_override.is_none() {
            let snapshot = read_portal_snapshot(tempo, discovery.portal).await?;
            if snapshot.block_hash != discovery.portal_block_hash {
                info!(
                    old_committed_zone_hash = %discovery.portal_block_hash,
                    new_committed_zone_hash = %snapshot.block_hash,
                    "portal advanced during batch extraction; discarding range and rebasing"
                );
                apply_portal_snapshot(&mut discovery, snapshot);
                continue;
            }
            apply_portal_snapshot(&mut discovery, snapshot);
        }

        return Ok((discovery, parent_header, parent_number, blocks));
    }
}

fn counted_range(from: u64, block_count: u64) -> Result<(u64, u64)> {
    if from == 0 {
        bail!("a batch cannot start at Zone genesis block 0");
    }
    if block_count == 0 {
        bail!("--zone-block-count must be greater than zero");
    }
    let to = from
        .checked_add(block_count - 1)
        .ok_or_else(|| eyre!("Zone block range overflow"))?;
    Ok((from, to))
}

async fn portal_parent_number(
    zone: &DynProvider<TempoNetwork>,
    discovery: &Discovery,
) -> Result<u64> {
    if discovery.portal_block_hash.is_zero() {
        return Ok(0);
    }

    match zone.get_block_by_hash(discovery.portal_block_hash).await? {
        Some(block) => Ok(block.header.number()),
        None => {
            let tip = zone.get_block_number().await?;
            let genesis_hash = zone_header(zone, 0).await?.hash_slow();
            bail!(
                "Tempo portal {} commits Zone block hash {}, but the unrestricted Zone RPC does not contain it (Zone tip: {tip}, genesis hash: {genesis_hash}); the endpoint may belong to a reset or different Zone chain",
                discovery.portal,
                discovery.portal_block_hash
            );
        }
    }
}

/// Resolve hashes to heights; extraction below checks that the canonical range still matches them.
async fn resolve_block_number(
    zone: &DynProvider<TempoNetwork>,
    block: Option<BlockHashOrNumber>,
) -> Result<Option<u64>> {
    match block {
        None => Ok(None),
        Some(BlockHashOrNumber::Number(number)) => Ok(Some(number)),
        Some(BlockHashOrNumber::Hash(hash)) => {
            let block = zone
                .get_block_by_hash(hash)
                .await
                .wrap_err_with(|| format!("resolve Zone block hash {hash}"))?
                .ok_or_else(|| eyre!("Zone block {hash} not found"))?;
            Ok(Some(block.header.number()))
        }
    }
}

fn validate_boundary_hash(
    requested: Option<BlockHashOrNumber>,
    number: u64,
    actual_hash: B256,
) -> Result<()> {
    if let Some(BlockHashOrNumber::Hash(expected_hash)) = requested
        && expected_hash != actual_hash
    {
        bail!(
            "requested Zone block hash {expected_hash} does not match canonical block {number} ({actual_hash}); the block may have been reorged out"
        );
    }
    Ok(())
}

async fn discover_batch(
    zone: &DynProvider<TempoNetwork>,
    discovery: &Discovery,
    from_override: Option<u64>,
    to_override: Option<u64>,
) -> Result<(TempoHeader, u64, Vec<ExtractedBlock>)> {
    let from = match from_override {
        Some(from) => from,
        None => portal_parent_number(zone, discovery)
            .await?
            .checked_add(1)
            .ok_or_else(|| eyre!("Zone block number overflow"))?,
    };
    if from == 0 {
        bail!("a batch cannot start at Zone genesis block 0");
    }
    let parent_number = from - 1;
    let parent_header = zone_header(zone, parent_number).await?;
    if from_override.is_none()
        && !discovery.portal_block_hash.is_zero()
        && parent_header.hash_slow() != discovery.portal_block_hash
    {
        bail!("resolved parent header does not match the portal block hash");
    }

    let tip = zone.get_block_number().await?;
    let limit = to_override.unwrap_or(tip);
    if from > limit {
        bail!("no Zone blocks available in requested range {from}..={limit}");
    }

    let mut blocks = Vec::new();
    for number in from..=limit {
        let block = fetch_full_block(zone, number).await?;
        let extracted = extract_block(block)?;
        debug!(
            zone_block = number,
            parent_hash = %extracted.input.parent_hash,
            user_transactions = extracted.user_transaction_count,
            checkpoint = ?extracted.checkpoint_number,
            has_finalization = extracted.has_finalization,
            "extracted Zone block"
        );
        blocks.push(extracted);
    }
    Ok((parent_header, parent_number, blocks))
}

async fn fetch_full_block(zone: &DynProvider<TempoNetwork>, number: u64) -> Result<RpcBlock> {
    zone.get_block_by_number(BlockNumberOrTag::Number(number))
        .full()
        .await?
        .ok_or_else(|| eyre!("Zone block {number} not found"))
}

async fn zone_header(zone: &DynProvider<TempoNetwork>, number: u64) -> Result<TempoHeader> {
    let block = zone
        .get_block_by_number(BlockNumberOrTag::Number(number))
        .await?
        .ok_or_else(|| eyre!("Zone block {number} not found"))?;
    Ok(block.header.inner.into_consensus())
}

fn extract_block(block: RpcBlock) -> Result<ExtractedBlock> {
    let header = block.header.inner.into_consensus();
    let block_hash = header.hash_slow();
    let rpc_transactions = match block.transactions {
        BlockTransactions::Full(transactions) => transactions,
        _ => {
            bail!(
                "Zone block {} did not return full transactions",
                header.number()
            );
        }
    };

    let mut tempo_import = None;
    let mut finalize_count = None;
    let mut finalize_encrypted_senders = Vec::new();
    let mut transactions = Vec::new();
    let mut user_transaction_count = 0;
    let mut checkpoint_number = None;

    for transaction in rpc_transactions {
        let envelope = transaction.into_inner();
        if !envelope.is_system_tx() {
            transactions.push(Bytes::from(envelope.encoded_2718()));
            user_transaction_count += 1;
            continue;
        }

        match envelope.to() {
            Some(to) if to == ZONE_INBOX_ADDRESS => {
                if tempo_import.is_some() {
                    bail!(
                        "Zone block {} contains multiple advanceTempo calls",
                        header.number()
                    );
                }
                let call = ZoneInbox::IZoneInboxCalls::abi_decode(envelope.input()).wrap_err_with(
                    || format!("decode ZoneInbox call in Zone block {}", header.number()),
                )?;
                match call {
                    ZoneInbox::IZoneInboxCalls::advanceTempo(call) => {
                        checkpoint_number = Some(decode_tempo_header(&call.header)?.number());
                        tempo_import = Some(TempoImport::Full {
                            header_rlp: call.header,
                            deposits: call.deposits,
                            decryptions: call.decryptions,
                            enabled_tokens: call.enabledTokens,
                        });
                    }
                    ZoneInbox::IZoneInboxCalls::advanceTempoHeaders(call) => {
                        let final_header = call
                            .headers
                            .last()
                            .ok_or_eyre("checkpoint-only Zone block has no Tempo headers")?;
                        checkpoint_number = Some(decode_tempo_header(final_header)?.number());
                        for encoded in &call.headers {
                            decode_tempo_header(encoded)?;
                        }
                        tempo_import = Some(TempoImport::CheckpointOnly {
                            headers_rlp: call.headers,
                        });
                    }
                    _ => {
                        return Err(eyre!(
                            "unexpected ZoneInbox call in Zone block {}",
                            header.number()
                        ));
                    }
                }
            }
            Some(to) if to == ZONE_OUTBOX_ADDRESS => {
                if finalize_count.is_some() {
                    bail!(
                        "Zone block {} contains multiple finalizeWithdrawalBatch calls",
                        header.number()
                    );
                }
                let call = ZoneOutbox::finalizeWithdrawalBatchCall::abi_decode(envelope.input())
                    .wrap_err_with(|| {
                        format!(
                            "decode finalizeWithdrawalBatch in Zone block {}",
                            header.number()
                        )
                    })?;
                if call.blockNumber != header.number() {
                    bail!(
                        "finalization in Zone block {} declares block {}",
                        header.number(),
                        call.blockNumber
                    );
                }
                finalize_count = Some(call.count);
                finalize_encrypted_senders = call.encryptedSenders;
            }
            other => {
                bail!(
                    "unsupported system transaction target {other:?} in Zone block {}",
                    header.number()
                );
            }
        }
    }

    let (tempo_import, checkpoint_number) = tempo_import.zip(checkpoint_number).ok_or_eyre(
        format!("no advanceTempo call in Zone block {}", header.number()),
    )?;

    let has_finalization = finalize_count.is_some();
    Ok(ExtractedBlock {
        input: ZoneBlock {
            number: header.number(),
            parent_hash: header.parent_hash(),
            timestamp: header.timestamp(),
            timestamp_millis_part: header.timestamp_millis_part,
            beneficiary: header.beneficiary(),
            tempo_import,
            finalize_withdrawal_batch_count: finalize_count,
            finalize_withdrawal_batch_encrypted_senders: finalize_encrypted_senders,
            transactions,
        },
        block_hash,
        checkpoint_number,
        has_finalization,
        user_transaction_count,
    })
}

async fn withdrawal_batch_index_at(
    zone: &DynProvider<TempoNetwork>,
    block_number: u64,
) -> Result<u64> {
    let index = zone
        .get_storage_at(ZONE_OUTBOX_ADDRESS, outbox::slots::WITHDRAWAL_BATCH_INDEX)
        .number(block_number)
        .await?;
    Ok(index.as_limbs()[0])
}

async fn tempo_header(tempo: &DynProvider<TempoNetwork>, number: u64) -> Result<TempoHeader> {
    let block = tempo
        .get_block_by_number(BlockNumberOrTag::Number(number))
        .await?
        .ok_or_else(|| eyre!("Tempo block {number} not found"))?;
    Ok(block.header.inner.into_consensus())
}

fn decode_tempo_header(encoded: &[u8]) -> Result<TempoHeader> {
    alloy_rlp::decode_exact(encoded).context("decode Tempo header RLP")
}

async fn zone_witnesses(
    zone: &DynProvider<TempoNetwork>,
    from: u64,
    to: u64,
) -> Result<(ZoneStateWitness, TempoStateWitness)> {
    let results = stream::iter(from..=to)
        .map(|number| async move {
            let started = Instant::now();
            debug!(zone_block = number, "requesting Zone execution witness");
            let witness = zone
                .client()
                .request::<_, ZoneExecutionWitness>(
                    "debug_zoneExecutionWitness",
                    (BlockNumberOrTag::Number(number),),
                )
                .await
                .wrap_err_with(|| format!("debug_zoneExecutionWitness for Zone block {number}"))?;
            debug!(
                zone_block = number,
                state_nodes = witness.execution_witness.state.len(),
                bytecodes = witness.execution_witness.codes.len(),
                ancestor_headers = witness.execution_witness.headers.len(),
                tempo_state_nodes = witness.tempo_state.len(),
                elapsed_ms = started.elapsed().as_millis(),
                "received Zone execution witness"
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

async fn tempo_anchor(
    tempo: &DynProvider<TempoNetwork>,
    checkpoint: &TempoHeader,
) -> Result<(u64, B256, Vec<Bytes>, &'static str)> {
    let checkpoint_number = checkpoint.number();
    let tip = tempo.get_block_number().await?;
    if checkpoint_number > tip {
        bail!("Tempo checkpoint {checkpoint_number} is not yet confirmed behind tip {tip}");
    }
    let gap = tip - checkpoint_number;
    if gap < HISTORY_SERVE_WINDOW as u64 - EIP2935_SAFETY_MARGIN {
        return Ok((
            checkpoint_number,
            checkpoint.hash_slow(),
            Vec::new(),
            "direct",
        ));
    }

    let anchor = tip.saturating_sub(EIP2935_SAFETY_MARGIN);
    let mut headers =
        stream::iter(checkpoint_number + 1..=anchor)
            .map(|number| async move {
                Ok::<_, eyre::Report>((number, tempo_header(tempo, number).await?))
            })
            .buffer_unordered(RPC_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?;
    headers.sort_unstable_by_key(|(number, _)| *number);
    let anchor_hash = headers
        .last()
        .map(|(_, header)| header.hash_slow())
        .ok_or_else(|| eyre!("empty Tempo ancestry"))?;
    Ok((
        anchor,
        anchor_hash,
        headers
            .into_iter()
            .map(|(_, header)| Bytes::from(alloy_rlp::encode(header)))
            .collect(),
        "ancestry",
    ))
}

fn print_summary(
    discovery: &Discovery,
    witness: &BatchWitness,
    extracted: &[ExtractedBlock],
    output: &BatchOutput,
    anchor_mode: &str,
    written_output: Option<(&PathBuf, usize)>,
) {
    let first = witness.zone_blocks.first().expect("non-empty batch");
    let last = witness.zone_blocks.last().expect("non-empty batch");
    let user_transactions = extracted
        .iter()
        .map(|block| block.user_transaction_count)
        .sum::<usize>();
    let zone_node_bytes = witness
        .zone_state_witness
        .node_pool
        .iter()
        .map(|node| node.len())
        .sum::<usize>();
    let tempo_node_bytes = witness
        .tempo_state_witness
        .node_pool
        .iter()
        .map(|node| node.len())
        .sum::<usize>();

    println!("Generated and validated SPF input");
    println!("  Zone ID:               {}", discovery.zone_id);
    println!("  Portal:                {}", discovery.portal);
    println!(
        "  Zone blocks:           {}..={} ({})",
        first.number,
        last.number,
        witness.zone_blocks.len()
    );
    println!(
        "  Withdrawal finalizes:  {}",
        extracted
            .iter()
            .filter(|block| block.has_finalization)
            .count()
    );
    println!("  User transactions:     {user_transactions}");
    println!(
        "  Tempo checkpoint:      {}",
        witness.public_inputs.tempo_block_number
    );
    println!(
        "  Anchor:                {anchor_mode} at {}",
        witness.public_inputs.anchor_block_number
    );
    println!(
        "  Zone witness:          {} nodes / {} code blobs / {} bytes",
        witness.zone_state_witness.node_pool.len(),
        witness.zone_state_witness.bytecodes.len(),
        zone_node_bytes
    );
    println!(
        "  Tempo witness:         {} nodes / {} bytes",
        witness.tempo_state_witness.node_pool.len(),
        tempo_node_bytes
    );
    println!(
        "  Previous block hash:   {}",
        output.block_transition.prevBlockHash
    );
    println!(
        "  Next block hash:       {}",
        output.block_transition.nextBlockHash
    );
    match written_output {
        Some((path, bytes)) => println!(
            "  Output:                {} ({bytes} bytes)",
            path.display()
        ),
        _ => println!("  Output:                not written (pass --output <PATH>)"),
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        format!("{:.3}s", duration.as_secs_f64())
    } else {
        format!("{:.3}ms", duration.as_secs_f64() * 1_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zone_prover::{ErrorCode, ProofBundle};
    use zone_spf::{
        BlockTransition, DepositQueueTransition, LastBatchCommitment, TokenEnablementTransition,
    };

    fn successful_proof_response(request_id: &str) -> VerifyResponse {
        VerifyResponse::Ok {
            version: PROTOCOL_VERSION,
            request_id: request_id.into(),
            output: Box::new(BatchOutput {
                next_zone_height: 0,
                block_transition: BlockTransition {
                    prevBlockHash: B256::ZERO,
                    nextBlockHash: B256::ZERO,
                },
                deposit_queue_transition: DepositQueueTransition {
                    prevProcessedHash: B256::ZERO,
                    nextProcessedHash: B256::ZERO,
                    prevDepositNumber: 0,
                    nextDepositNumber: 0,
                },
                token_enablement_transition: TokenEnablementTransition {
                    prevProcessedTokenCount: 0,
                    nextProcessedTokenCount: 0,
                },
                withdrawal_queue_hash: B256::ZERO,
                last_batch_commitment: LastBatchCommitment {
                    withdrawal_batch_index: 0,
                },
            }),
            proof_bundle: ProofBundle {
                verifier_config: Bytes::from_static(&[1]),
                proof: Bytes::from_static(&[0x12, 0x34]),
            },
        }
    }

    fn empty_witness() -> BatchWitness {
        let tempo_header = TempoHeader {
            inner: alloy_consensus::Header {
                number: 2,
                state_root: B256::ZERO,
                ..Default::default()
            },
            ..Default::default()
        };
        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: 42_431,
                zone_id: 1,
                tempo_block_number: 2,
                anchor_block_number: 2,
                anchor_block_hash: B256::ZERO,
                expected_withdrawal_batch_index: 3,
            },
            parent_header: TempoHeader::default(),
            zone_blocks: Vec::new(),
            zone_state_witness: ZoneStateWitness {
                node_pool: Vec::new(),
                bytecodes: Vec::new(),
            },
            tempo_state_witness: TempoStateWitness {
                initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(tempo_header)),
                node_pool: Vec::new(),
            },
            tempo_ancestry_headers: Vec::new(),
        }
    }

    #[test]
    fn parses_prove_without_rpc_or_wallet_arguments() {
        let cli = Cli::try_parse_from([
            "tempo-zone-prover-utils",
            "prove",
            "--input",
            "witness.json",
            "--target",
            "localhost:5000",
            "--attestation-policy",
            "measurements.json",
            "--output",
            "proof.json",
        ])
        .unwrap();
        let Command::Prove(args) = cli.command else {
            panic!("expected prove")
        };
        assert_eq!(args.input, PathBuf::from("witness.json"));
        assert_eq!(args.target, "localhost:5000");
        assert_eq!(args.output, PathBuf::from("proof.json"));
        assert!(
            Cli::try_parse_from([
                "tempo-zone-prover-utils",
                "prove",
                "--input",
                "witness.json",
                "--target",
                "localhost:5000",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_invalid_proof_responses() {
        let valid = successful_proof_response("test");
        validate_proof_response(&valid, "test").unwrap();
        assert!(validate_proof_response(&valid, "different").is_err());

        let mut wrong_version = successful_proof_response("test");
        let VerifyResponse::Ok { version, .. } = &mut wrong_version else {
            unreachable!()
        };
        *version += 1;
        assert!(validate_proof_response(&wrong_version, "test").is_err());

        for clear_config in [false, true] {
            let mut empty = successful_proof_response("test");
            let VerifyResponse::Ok { proof_bundle, .. } = &mut empty else {
                unreachable!()
            };
            if clear_config {
                proof_bundle.verifier_config = Bytes::new();
            } else {
                proof_bundle.proof = Bytes::new();
            }
            assert!(validate_proof_response(&empty, "test").is_err());
        }

        let error = validate_proof_response(
            &VerifyResponse::Error {
                version: PROTOCOL_VERSION,
                request_id: Some("test".into()),
                code: ErrorCode::AttestationUnavailable,
                message: "NSM unavailable".into(),
            },
            "test",
        )
        .unwrap_err();
        assert!(error.to_string().contains("AttestationUnavailable"));
        assert!(error.to_string().contains("NSM unavailable"));
    }

    #[tokio::test]
    async fn prove_transcodes_json_witness_and_does_not_save_errors() {
        let directory =
            std::env::temp_dir().join(format!("prover-cli-prove-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let input = directory.join("witness.json");
        let output = directory.join("proof.json");
        let witness = empty_witness();
        std::fs::write(&input, serde_json::to_vec(&witness).unwrap()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let mut success = None;
            for attempt in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut connection = ProverConnection::new(stream, DEFAULT_MAX_REQUEST_BYTES);
                let request: VerifyRequest = connection.receive().await.unwrap().unwrap();
                assert_eq!(request.version, PROTOCOL_VERSION);
                assert_eq!(request.witness, witness);
                let response = if attempt == 0 {
                    let response = successful_proof_response(&request.request_id);
                    success = Some(serde_json::to_value(&response).unwrap());
                    response
                } else {
                    VerifyResponse::Error {
                        version: PROTOCOL_VERSION,
                        request_id: Some(request.request_id),
                        code: ErrorCode::VerificationFailed,
                        message: "bad witness".into(),
                    }
                };
                connection.send(response).await.unwrap();
            }
            success.unwrap()
        });
        prove_with_connection(
            ProveArgs {
                input: input.clone(),
                target: target.clone(),
                attestation_policy: PathBuf::new(),
                output: output.clone(),
            },
            tokio::net::TcpStream::connect(&target),
        )
        .await
        .unwrap();
        let saved = std::fs::read(&output).unwrap();
        let stream = tokio::net::TcpStream::connect(&target).await.unwrap();
        let error = prove_with_connection(
            ProveArgs {
                input,
                target,
                attestation_policy: PathBuf::new(),
                output: output.clone(),
            },
            std::future::ready(Ok(stream)),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("VerificationFailed"));
        assert_eq!(std::fs::read(&output).unwrap(), saved);
        let response: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        assert_eq!(response, server.await.unwrap());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn parse_range_args(range: &[&str]) -> Result<GenerateInputArgs, clap::Error> {
        let mut genesis = tempo_chainspec::spec::MODERATO.inner.genesis.clone();
        genesis.config.chain_id = zone_chain_id(42_431, 1).unwrap();
        let genesis = serde_json::to_string(&genesis).unwrap();
        let mut args = vec![
            "tempo-zone-prover-utils",
            "generate-input",
            "--tempo-rpc-url",
            "http://localhost:8545",
            "--zone-rpc-url",
            "http://localhost:8546",
            "--chain",
            &genesis,
        ];
        args.extend_from_slice(range);
        let Command::GenerateInput(args) = Cli::try_parse_from(args)?.command else {
            unreachable!("generate-input was requested");
        };
        Ok(args)
    }

    #[test]
    fn parses_number_and_hash_boundaries() {
        let hash = B256::repeat_byte(0xab);
        let hash_arg = hash.to_string();
        for (from, to, expected_from, expected_to) in [
            ("100", "120", 100.into(), 120.into()),
            ("100", hash_arg.as_str(), 100.into(), hash.into()),
            (hash_arg.as_str(), "120", hash.into(), 120.into()),
            (
                hash_arg.as_str(),
                hash_arg.as_str(),
                hash.into(),
                hash.into(),
            ),
        ] {
            let args = parse_range_args(&["--from-block", from, "--to-block", to]).unwrap();
            assert_eq!(args.from_block, Some(expected_from));
            assert_eq!(args.to_block, Some(expected_to));
        }
        let args =
            parse_range_args(&["--from-block", &hash_arg, "--zone-block-count", "20"]).unwrap();
        assert_eq!(args.from_block, Some(hash.into()));
        assert_eq!(args.zone_block_count, Some(20));
        assert!(parse_range_args(&["--from-block", "0xinvalid"]).is_err());
        assert!(parse_range_args(&["--to-block", "latest"]).is_err());
        assert!(parse_range_args(&["--to-block", &hash_arg, "--zone-block-count", "20"]).is_err());
    }

    #[tokio::test]
    async fn resolves_hashes_and_rejects_missing_blocks() {
        let asserter = alloy_transport::mock::Asserter::new();
        let zone = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_mocked_client(asserter.clone())
            .erased();
        assert_eq!(resolve_block_number(&zone, None).await.unwrap(), None);
        assert_eq!(
            resolve_block_number(&zone, Some(100.into())).await.unwrap(),
            Some(100)
        );

        let mut header = TempoHeader::default();
        header.inner.number = 120;
        let hash = header.hash_slow();
        let block = RpcBlock::new(
            TempoHeaderResponse {
                inner: alloy_rpc_types_eth::Header::new(header),
                timestamp_millis: 0,
            },
            BlockTransactions::Hashes(vec![]),
        );
        asserter.push_success(&Some(block));
        assert_eq!(
            resolve_block_number(&zone, Some(hash.into()))
                .await
                .unwrap(),
            Some(120)
        );
        asserter.push_success(&Option::<RpcBlock>::None);
        let error = resolve_block_number(&zone, Some(hash.into()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not found"));
    }

    #[test]
    fn rejects_a_hash_that_no_longer_matches_the_extracted_boundary() {
        let hash = B256::repeat_byte(0xab);
        assert!(validate_boundary_hash(None, 100, hash).is_ok());
        assert!(validate_boundary_hash(Some(100.into()), 100, hash).is_ok());
        assert!(validate_boundary_hash(Some(hash.into()), 100, hash).is_ok());
        let error = validate_boundary_hash(Some(hash.into()), 100, B256::ZERO).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match canonical block 100")
        );
    }

    #[test]
    fn derives_an_exact_counted_zone_range() {
        assert_eq!(counted_range(501, 20).unwrap(), (501, 520));
        assert!(counted_range(0, 20).is_err());
        assert!(counted_range(501, 0).is_err());
        assert!(counted_range(u64::MAX, 2).is_err());
    }

    #[test]
    fn parses_and_uses_a_zone_genesis_from_a_local_path() {
        let zone_chain_id = zone_chain_id(42_431, 1).unwrap();
        let mut genesis = tempo_chainspec::spec::MODERATO.inner.genesis.clone();
        genesis.config.chain_id = zone_chain_id;
        let path = std::env::temp_dir().join(format!(
            "tempo-zone-prover-utils-genesis-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, serde_json::to_vec(&genesis).unwrap()).unwrap();

        let chain_spec = <ZoneChainSpecParser as reth_cli::chainspec::ChainSpecParser>::parse(
            path.to_str().unwrap(),
        )
        .unwrap();
        let config = SpfConfig::new(chain_spec);

        std::fs::remove_file(path).unwrap();
        assert_eq!(
            config.chain_spec().inner.inner.genesis.config.chain_id,
            zone_chain_id
        );
    }
}
