//! Demo top-of-block operator.
//!
//! Connects to the validators as an authenticated secondary peer, computes
//! each round's leader from the consensus certificates the validators
//! broadcast, streams replaceable maker transactions straight to that leader,
//! verifies the resulting blocks over RPC, and serves a live dashboard.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use alloy::providers::{Provider as _, ProviderBuilder, RootProvider};
use alloy_consensus::{SignableTransaction as _, TxEip1559, transaction::TxHashRef as _};
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, address};
use alloy_rlp::Encodable as _;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use clap::Parser;
use commonware_codec::{Encode as _, ReadExt as _};
use commonware_consensus::{Epochable as _, Viewable as _};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_p2p::{Receiver as _, Recipients};
use commonware_runtime::Runner as _;
use eyre::WrapErr as _;
use parking_lot::Mutex;
use serde::Serialize;
use tempo_consensus::top_of_block::{
    self, OperatorChannels, OperatorNetwork,
    leader::{self, EpochLeaders},
    wire::{AckStatus, Message, Submit, SubmitTx},
};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_primitives::TempoTxEnvelope;

/// Makers send their quotes here; the address has no code.
const BOOK: Address = address!("0x000000000000000000000000000000000000b00c");
const ROUNDS_KEPT: usize = 40;

#[derive(Debug, Parser)]
#[command(name = "tempo-tob-operator", about = "Demo top-of-block operator")]
struct Args {
    /// Seed of the operator's ed25519 identity. For local devnets only:
    /// anyone can derive the key from the seed.
    #[arg(long, required_unless_present = "signing_key")]
    seed: Option<u64>,
    /// File with the operator's hex-encoded ed25519 private key, as written
    /// by `tempo consensus generate-private-key`.
    #[arg(long, conflicts_with = "seed")]
    signing_key: Option<std::path::PathBuf>,
    /// Print the operator's public key and exit.
    #[arg(long)]
    print_public_key: bool,
    /// Consensus p2p listen address. Validators never dial it.
    #[arg(long, default_value = "127.0.0.1:9900")]
    listen: SocketAddr,
    /// Validators as `<public key>@<consensus ip:port>`, in the order of `--rpc`.
    /// With only `<consensus ip:port>`, the key is read from the validator's
    /// RPC (`admin_validatorKey`).
    #[arg(long = "validator")]
    validators: Vec<String>,
    /// JSON-RPC endpoints of the validators, in the order of `--validator`.
    /// A single endpoint serves every validator. Chains without a built-in
    /// chainspec need `debug_chainConfig`.
    #[arg(long = "rpc")]
    rpcs: Vec<String>,
    /// Number of makers streaming quotes.
    #[arg(long, default_value_t = 20)]
    makers: u32,
    /// Maker transactions generated per second, across all makers.
    #[arg(long, default_value_t = 1000)]
    rate: u64,
    /// Public transactions per second sent to the mempool with a high tip.
    #[arg(long, default_value_t = 20)]
    public_rate: u64,
    /// Dashboard address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    http: SocketAddr,
    #[arg(
        long,
        default_value = "test test test test test test test test test test test junk"
    )]
    mnemonic: String,
    /// Mnemonic index of the first maker account.
    #[arg(long, default_value_t = 10)]
    maker_offset: u32,
    /// Mnemonic index of the first public-flow account.
    #[arg(long, default_value_t = 200)]
    public_offset: u32,
    /// Must be at least the validators' `--consensus.max-message-size-bytes`.
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    max_message_size: u32,
    /// Must equal the validators' `--consensus.wait-before-peers-reping`:
    /// 50s by default, 5s with `--consensus.use-local-defaults`. A mismatch
    /// stalls the connection behind rate-limited pings.
    #[arg(long, default_value = "50s")]
    ping_frequency: tempo_consensus::PositiveDuration,
}

fn main() -> eyre::Result<()> {
    let mut args = Args::parse();
    let signer = match (&args.signing_key, args.seed) {
        (Some(path), _) => tempo_consensus_config::SigningKey::read_from_file_unencrypted(path)
            .wrap_err_with(|| format!("failed reading signing key `{}`", path.display()))?
            .into_inner(),
        (None, Some(seed)) => PrivateKey::from_seed(seed),
        (None, None) => eyre::bail!("pass --seed or --signing-key"),
    };
    if args.print_public_key {
        println!("{}", signer.public_key());
        return Ok(());
    }

    if let [rpc] = args.rpcs.as_slice() {
        args.rpcs = vec![rpc.clone(); args.validators.len()];
    }
    eyre::ensure!(
        args.validators.len() == args.rpcs.len() && !args.rpcs.is_empty(),
        "pass one --rpc, or one per --validator"
    );
    let validators = args
        .validators
        .iter()
        .map(|value| match value.split_once('@') {
            Some(_) => top_of_block::parse_peer(value).map(|(key, address)| (Some(key), address)),
            None => Ok((None, value.parse()?)),
        })
        .collect::<eyre::Result<Vec<_>>>()?;

    let storage = tempfile::tempdir()?;
    let runner = commonware_runtime::tokio::Runner::new(
        commonware_runtime::tokio::Config::default()
            .with_tcp_nodelay(Some(true))
            .with_worker_threads(4)
            .with_storage_directory(storage.path()),
    );
    runner.start(async move |context| run(context, args, signer, validators).await)
}

#[derive(Clone, Debug, Serialize)]
struct ValidatorView {
    index: usize,
    public_key: String,
    rpc: String,
    rounds_led: u64,
    tob_txs_received: u64,
    last_ack_rtt_us: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct RoundView {
    epoch: u64,
    view: u64,
    /// Height of the proposed block; known once the leader broadcasts it.
    height: Option<u64>,
    leader: usize,
    /// Unix ms when the operator computed the leader from a certificate.
    leader_known_at_ms: u64,
    /// Transactions streamed to the leader for this round.
    sent: u64,
    accepted: u64,
    replaced: u64,
    rejected: u64,
    late: u64,
    /// Round trip of the first submission.
    first_ack_rtt_us: Option<u64>,
    /// Time between the leader opening its lane and receiving our first
    /// submission; zero if it arrived before the lane opened.
    first_since_open_us: Option<u64>,
    built: Option<BuiltView>,
    verification: Option<Verification>,
}

#[derive(Clone, Debug, Serialize)]
struct BuiltView {
    block_hash: B256,
    tx_count: u32,
    top_of_block: Vec<B256>,
}

#[derive(Clone, Debug, Serialize)]
struct Verification {
    /// Validator whose RPC served the block.
    checked_on: usize,
    canonical: bool,
    /// The first transactions of the canonical block are the lane transactions.
    prefix_ok: bool,
    /// Kind of every transaction in the block, in order: `t` top of block,
    /// `p` public high-tip transaction, `o` other.
    layout: String,
    public_positions: Vec<usize>,
}

#[derive(Default, Serialize)]
struct Dashboard {
    operator: String,
    makers: u32,
    rate: u64,
    public_rate: u64,
    maker_tip_wei: u128,
    public_tip_wei: u128,
    validators: Vec<ValidatorView>,
    current: Option<RoundView>,
    rounds: VecDeque<RoundView>,
    generated: u64,
    /// Transactions received through `tempo_sendTobTransaction`.
    rpc_received: u64,
    streamed: u64,
    public_sent: u64,
    public_failed: u64,
}

/// A maker's account. Its quotes are signed on its own thread; all quotes of
/// a maker share its nonce, so at most one of them lands.
struct Maker {
    signer: PrivateKeySigner,
    nonce: AtomicU64,
    /// Unix ms of the last local nonce bump.
    bumped_at_ms: AtomicU64,
}

/// A transaction to stream to leaders: a maker quote signed here, or one
/// submitted through `tempo_sendTobTransaction`.
struct Quote {
    /// The lane slot: signer and nonce key.
    slot: (Address, U256),
    /// Maker index and nonce of quotes signed here, to track their nonces.
    maker: Option<(usize, u64)>,
    hash: B256,
    raw: Bytes,
    /// Replacement sequence within the slot; `None` takes the next one.
    seq: Option<u64>,
    /// Unix ms at which the transaction expires; zero never expires.
    expires_at_ms: u64,
    reply: Option<tokio::sync::oneshot::Sender<Result<Accepted, String>>>,
}

/// The latest transaction of a slot.
struct Latest {
    hash: B256,
    raw: Bytes,
    seq: u64,
    expires_at_ms: u64,
}

impl Latest {
    fn submit_tx(&self) -> SubmitTx {
        SubmitTx {
            tx: self.raw.0.clone(),
            seq: self.seq,
            expires_at_ms: self.expires_at_ms,
        }
    }

    fn expired(&self, now_ms: u64) -> bool {
        self.expires_at_ms != 0 && now_ms >= self.expires_at_ms
    }
}

/// What `tempo_sendTobTransaction` returns.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Accepted {
    hash: B256,
    maker: Address,
    nonce_key: U256,
    seq: u64,
    expires_at: u64,
    /// The leader the transaction was streamed to, if its lane was not
    /// known to be closed.
    streamed_to: Option<usize>,
}

/// The next round and its leader.
struct Target {
    leader: usize,
    epoch: u64,
    view: u64,
    /// The leader's builder took the lane; later submissions would be late.
    closed: bool,
}

/// Chain parameters needed to elect leaders.
struct Election {
    epoch_length: u64,
    t12_time: Option<u64>,
}

impl Election {
    /// Reads the DKG outcome of `epoch` from its boundary block.
    async fn leaders(&self, provider: &RootProvider, epoch: u64) -> eyre::Result<EpochLeaders> {
        let boundary = (epoch * self.epoch_length).saturating_sub(1);
        let block: serde_json::Value = provider
            .raw_request(
                "eth_getBlockByNumber".into(),
                (format!("{boundary:#x}"), false),
            )
            .await?;
        let extra_data: Bytes = serde_json::from_value(block["extraData"].clone())?;
        let timestamp: alloy_primitives::U64 = serde_json::from_value(block["timestamp"].clone())?;
        let outcome = OnchainDkgOutcome::read(&mut extra_data.as_ref())?;
        eyre::ensure!(
            outcome.epoch().get() == epoch,
            "block {boundary} carries the outcome of epoch {}, not {epoch}",
            outcome.epoch()
        );
        let t12 = self
            .t12_time
            .is_some_and(|t12_time| timestamp.to::<u64>() >= t12_time);
        Ok(EpochLeaders::new(&outcome, t12))
    }
}

async fn run(
    context: commonware_runtime::tokio::Context,
    args: Args,
    signer: PrivateKey,
    validators: Vec<(
        Option<commonware_cryptography::ed25519::PublicKey>,
        SocketAddr,
    )>,
) -> eyre::Result<()> {
    // Serve the dashboard before anything else so it answers while the
    // validators are still starting.
    let dashboard = Arc::new(Mutex::new(Dashboard {
        operator: signer.public_key().to_string(),
        makers: args.makers,
        rate: args.rate,
        public_rate: args.public_rate,
        ..Default::default()
    }));
    let (quotes_tx, mut quotes_rx) = tokio::sync::mpsc::unbounded_channel::<Quote>();
    tokio::spawn(serve_dashboard(
        args.http,
        dashboard.clone(),
        quotes_tx.clone(),
    ));

    let providers: Vec<RootProvider> = args
        .rpcs
        .iter()
        .map(|url| Ok(ProviderBuilder::default().connect_http(url.parse()?)))
        .collect::<eyre::Result<_>>()?;
    let chain_id = retry(|| providers[0].get_chain_id()).await;
    // Known chains carry their epoch length and T12 activation in the built-in
    // chainspec; others (generated devnets) need `debug_chainConfig`.
    let election = Arc::new(
        match tempo_chainspec::spec::chainspec_from_chain_id(chain_id) {
            Some(spec) => {
                use tempo_chainspec::TempoHardforks as _;
                Election {
                    epoch_length: spec
                        .info
                        .epoch_length()
                        .ok_or_else(|| eyre::eyre!("chainspec has no epoch length"))?
                        .get(),
                    t12_time: spec
                        .tempo_fork_activation(tempo_chainspec::TempoHardfork::T12)
                        .as_timestamp(),
                }
            }
            None => {
                let config: serde_json::Value =
                    retry(|| providers[0].raw_request("debug_chainConfig".into(), ())).await;
                Election {
                    epoch_length: config["epochLength"]
                        .as_u64()
                        .ok_or_else(|| eyre::eyre!("debug_chainConfig has no epochLength"))?,
                    t12_time: config["t12Time"].as_u64(),
                }
            }
        },
    );
    let gas_price = retry(|| providers[0].get_gas_price()).await;
    let mut resolved = Vec::with_capacity(validators.len());
    for ((key, address), provider) in validators.into_iter().zip(&providers) {
        let key = match key {
            Some(key) => key,
            None => {
                let key: B256 =
                    retry(|| provider.raw_request::<_, B256>("admin_validatorKey".into(), ()))
                        .await;
                top_of_block::parse_peer(&format!("{key}@{address}"))?.0
            }
        };
        resolved.push((key, address));
    }
    let validators = resolved;
    // Makers pay no tip; the public flow outbids them by far. Pool ordering
    // alone would put the public flow first.
    let maker_tip = 0u128;
    let public_tip = gas_price.max(1) * 50;
    let max_fee = gas_price * 2 + public_tip;

    let mut makers = Vec::new();
    for i in 0..args.makers {
        let signer = MnemonicBuilder::from_phrase_nth(&args.mnemonic, args.maker_offset + i);
        let nonce = retry(|| providers[0].get_transaction_count(signer.address())).await;
        makers.push(Maker {
            signer,
            nonce: AtomicU64::new(nonce),
            bumped_at_ms: AtomicU64::new(0),
        });
    }
    let makers = Arc::new(makers);

    {
        let mut dashboard = dashboard.lock();
        dashboard.maker_tip_wei = maker_tip;
        dashboard.public_tip_wei = public_tip;
        dashboard.validators = validators
            .iter()
            .zip(&args.rpcs)
            .enumerate()
            .map(|(index, ((key, _), rpc))| ValidatorView {
                index,
                public_key: key.to_string(),
                rpc: rpc.clone(),
                rounds_led: 0,
                tob_txs_received: 0,
                last_ack_rtt_us: None,
            })
            .collect();
    }
    let public_hashes = Arc::new(Mutex::new(HashSet::<B256>::new()));

    let index_of: HashMap<_, _> = validators
        .iter()
        .enumerate()
        .map(|(index, (key, _))| (key.clone(), index))
        .collect();
    let keys: Vec<_> = validators.iter().map(|(key, _)| key.clone()).collect();

    let OperatorChannels {
        top_of_block: (mut sender, mut receiver),
        mut certificates,
        mut proposals,
    } = top_of_block::start_operator_network(
        &context,
        OperatorNetwork {
            signer,
            listen: args.listen,
            validators,
            max_message_size: args.max_message_size,
            ping_frequency: args.ping_frequency.into_duration(),
        },
    )?;

    tokio::spawn(public_flow(
        args.clone_public(),
        providers.clone(),
        chain_id,
        max_fee,
        public_tip,
        dashboard.clone(),
        public_hashes.clone(),
    ));
    tokio::spawn(resync_nonces(providers[0].clone(), makers.clone()));
    let (verify_tx, verify_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(verify_blocks(
        providers.clone(),
        verify_rx,
        dashboard.clone(),
        public_hashes,
    ));

    let per_maker = Duration::from_secs_f64(f64::from(args.makers) / args.rate.max(1) as f64);
    for index in 0..makers.len() {
        let (makers, quotes_tx) = (makers.clone(), quotes_tx.clone());
        let template = TxTemplate {
            chain_id,
            max_fee,
            maker_tip,
        };
        std::thread::spawn(move || {
            // Stagger makers so the stream is smooth.
            std::thread::sleep(per_maker.mul_f64(index as f64 / makers.len() as f64));
            let mut next = Instant::now();
            let mut seq = 0u64;
            loop {
                seq += 1;
                let maker = &makers[index];
                let nonce = maker.nonce.load(Ordering::Relaxed);
                let Ok((hash, raw)) = template.sign(maker, nonce, seq) else {
                    continue;
                };
                if quotes_tx
                    .send(Quote {
                        slot: (maker.signer.address(), U256::ZERO),
                        maker: Some((index, nonce)),
                        hash,
                        raw,
                        seq: None,
                        expires_at_ms: 0,
                        reply: None,
                    })
                    .is_err()
                {
                    return;
                }
                next += per_maker;
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
            }
        });
    }

    let mut target: Option<Target> = None;
    let mut leaders: HashMap<u64, EpochLeaders> = HashMap::new();
    let mut loading: HashSet<u64> = HashSet::new();
    let (leaders_tx, mut leaders_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut rng: rand::rngs::StdRng = rand::make_rng();
    let mut request_id = 0u64;
    let mut in_flight: HashMap<u64, Instant> = HashMap::new();
    let mut latest: HashMap<(Address, U256), Latest> = HashMap::new();
    // The highest sequence seen per slot, kept after the slot's transaction
    // lands so sequences only grow.
    let mut last_seq: HashMap<(Address, U256), u64> = HashMap::new();
    // Recently signed quotes, to map included hashes back to makers.
    let mut signed: HashMap<B256, (usize, u64)> = HashMap::new();
    let mut signed_order: VecDeque<B256> = VecDeque::new();
    // Recently streamed hashes, to find the lane prefix of proposed blocks.
    let mut streamed: HashSet<B256> = HashSet::new();
    let mut streamed_order: VecDeque<B256> = VecDeque::new();

    println!(
        "operator up: {} makers at {} tx/s, public flow {} tx/s, dashboard on http://{}",
        args.makers, args.rate, args.public_rate, args.http
    );

    loop {
        tokio::select! {
            message = certificates.recv() => {
                let (_, bytes) = message.map_err(|error| eyre::eyre!("{error}"))?;
                let Some(certificate) = leader::decode_certificate(bytes) else { continue };
                let (epoch, view) = (certificate.epoch().get(), certificate.view().get() + 1);
                // Every validator broadcasts several certificates per view;
                // only the first that names a later round matters.
                if target.as_ref().is_some_and(|target| (target.epoch, target.view) >= (epoch, view)) {
                    continue;
                }
                let Some(epoch_leaders) = leaders.get(&epoch) else {
                    if loading.insert(epoch) {
                        let (election, provider, leaders_tx) = (election.clone(), providers[0].clone(), leaders_tx.clone());
                        tokio::spawn(async move {
                            let _ = leaders_tx.send((epoch, election.leaders(&provider, epoch).await));
                        });
                    }
                    continue;
                };
                let Some((_, key)) = epoch_leaders.next_leader(&mut rng, &certificate) else { continue };
                let now = Instant::now();
                let Some(&leader) = index_of.get(&key) else {
                    // A leader the operator was not given cannot be reached.
                    target = None;
                    continue;
                };
                target = Some(Target { leader, epoch, view, closed: false });
                // Flush the latest transaction of every slot at once.
                let now_ms = unix_ms();
                latest.retain(|_, latest| !latest.expired(now_ms));
                let txs: Vec<_> = latest.values().map(Latest::submit_tx).collect();
                if !txs.is_empty() {
                    request_id += 1;
                    in_flight.insert(request_id, now);
                    submit(&mut sender, &keys[leader], epoch, view, request_id, txs.clone());
                }
                let mut dashboard = dashboard.lock();
                if let Some(previous) = dashboard.current.take() {
                    push_round(&mut dashboard.rounds, previous);
                }
                dashboard.validators[leader].rounds_led += 1;
                dashboard.streamed += txs.len() as u64;
                dashboard.current = Some(RoundView {
                    epoch,
                    view,
                    leader,
                    leader_known_at_ms: now_ms,
                    sent: txs.len() as u64,
                    ..Default::default()
                });
            }

            message = proposals.recv() => {
                let (peer, bytes) = message.map_err(|error| eyre::eyre!("{error}"))?;
                let Some(block) = top_of_block::decode_proposal(bytes) else { continue };
                let Some(context) = block.header().consensus_context else { continue };
                // Only the proposer's own broadcast; others may forward it later.
                if context.proposer.to_inner() != peer {
                    continue;
                }
                let Some(&leader) = index_of.get(&peer) else { continue };
                let (epoch, view) = (context.epoch, context.view);
                let txs = &block.body().transactions;
                // The lane executes first, so its transactions are the
                // block's leading transactions that the operator streamed.
                let top_of_block: Vec<B256> = txs
                    .iter()
                    .map(|tx| *tx.tx_hash())
                    .take_while(|hash| streamed.contains(hash))
                    .collect();
                let included: HashSet<_> = top_of_block.iter().copied().collect();
                latest.retain(|_, latest| !included.contains(&latest.hash));
                for hash in &top_of_block {
                    let Some(&(maker, nonce)) = signed.get(hash) else { continue };
                    let state = &makers[maker];
                    if state.nonce.fetch_max(nonce + 1, Ordering::Relaxed) <= nonce {
                        state.bumped_at_ms.store(unix_ms(), Ordering::Relaxed);
                    }
                }
                if let Some(target) = target.as_mut().filter(|target| (target.epoch, target.view) == (epoch, view)) {
                    target.closed = true;
                }
                let proposed = Proposed {
                    epoch,
                    view,
                    height: block.header().inner.number,
                    block_hash: block.hash(),
                    top_of_block,
                };
                let mut dashboard = dashboard.lock();
                let Some(round) = find_round(&mut dashboard, epoch, view) else { continue };
                if round.built.as_ref().is_some_and(|built| built.block_hash == proposed.block_hash) {
                    continue;
                }
                round.height = Some(proposed.height);
                round.built = Some(BuiltView {
                    block_hash: proposed.block_hash,
                    tx_count: txs.len() as u32,
                    top_of_block: proposed.top_of_block.clone(),
                });
                let _ = verify_tx.send((leader, proposed));
            }

            Some((epoch, loaded)) = leaders_rx.recv() => {
                loading.remove(&epoch);
                match loaded {
                    Ok(loaded) => {
                        leaders.insert(epoch, loaded);
                        leaders.retain(|known, _| known + 1 >= epoch);
                    }
                    Err(error) => eprintln!("failed loading the leaders of epoch {epoch}: {error:#}"),
                }
            }

            message = receiver.recv() => {
                let (peer, mut bytes) = message.map_err(|error| eyre::eyre!("{error}"))?;
                let Some(&leader) = index_of.get(&peer) else { continue };
                let Ok(message) = Message::read(&mut bytes) else { continue };
                match message {
                    Message::Ack(ack) => {
                        // The first `Closed` says the builder took the lane;
                        // stop streaming to it until the next leader.
                        if ack.status == AckStatus::Closed
                            && let Some(target) = target.as_mut().filter(|target| (target.epoch, target.view) == (ack.epoch, ack.view))
                        {
                            target.closed = true;
                        }
                        let rtt = in_flight.remove(&ack.id).map(|sent| sent.elapsed().as_micros() as u64);
                        let mut dashboard = dashboard.lock();
                        let dashboard = &mut *dashboard;
                        let validator = &mut dashboard.validators[leader];
                        validator.last_ack_rtt_us = rtt.or(validator.last_ack_rtt_us);
                        validator.tob_txs_received += u64::from(ack.accepted + ack.replaced);
                        if let Some(round) = find_round(dashboard, ack.epoch, ack.view) {
                            if ack.status == AckStatus::Ok {
                                round.accepted += u64::from(ack.accepted);
                                round.replaced += u64::from(ack.replaced);
                                round.rejected += u64::from(ack.rejected);
                                if round.first_ack_rtt_us.is_none() {
                                    round.first_ack_rtt_us = rtt;
                                    round.first_since_open_us = Some(ack.since_open_us);
                                }
                            } else {
                                round.late += 1;
                            }
                        }
                    }
                    Message::Submit(_) => {}
                }
            }

            Some(quote) = quotes_rx.recv() => {
                let mut fresh = vec![quote];
                while let Ok(quote) = quotes_rx.try_recv() {
                    fresh.push(quote);
                }
                let generated = fresh.iter().filter(|quote| quote.maker.is_some()).count() as u64;
                let received = fresh.len() as u64 - generated;
                let lane = target
                    .as_ref()
                    .filter(|target| !target.closed)
                    .map(|target| target.leader);
                let now_ms = unix_ms();
                let mut txs = Vec::with_capacity(fresh.len());
                for quote in fresh {
                    let Quote { slot, maker, hash, raw, seq, expires_at_ms, reply } = quote;
                    // Quotes signed before a nonce bump are already stale.
                    if let Some((maker, nonce)) = maker {
                        if nonce < makers[maker].nonce.load(Ordering::Relaxed) {
                            continue;
                        }
                        signed.insert(hash, (maker, nonce));
                        signed_order.push_back(hash);
                    }
                    let last = last_seq.get(&slot).copied().unwrap_or_default();
                    let seq = seq.unwrap_or(last + 1);
                    let outcome = if seq <= last {
                        Err(format!("sequence {seq} is not above the slot's sequence {last}"))
                    } else if expires_at_ms != 0 && now_ms >= expires_at_ms {
                        Err("transaction already expired".to_string())
                    } else {
                        last_seq.insert(slot, seq);
                        let entry = Latest { hash, raw, seq, expires_at_ms };
                        txs.push(entry.submit_tx());
                        if streamed.insert(hash) {
                            streamed_order.push_back(hash);
                        }
                        latest.insert(slot, entry);
                        Ok(Accepted {
                            hash,
                            maker: slot.0,
                            nonce_key: slot.1,
                            seq,
                            expires_at: expires_at_ms,
                            streamed_to: lane,
                        })
                    };
                    if let Some(reply) = reply {
                        let _ = reply.send(outcome);
                    }
                }
                while signed_order.len() > 50_000 {
                    if let Some(hash) = signed_order.pop_front() {
                        signed.remove(&hash);
                    }
                }
                while streamed_order.len() > 50_000 {
                    if let Some(hash) = streamed_order.pop_front() {
                        streamed.remove(&hash);
                    }
                }
                let mut streamed = 0;
                if let Some(target) = target.as_ref().filter(|_| lane.is_some())
                    && !txs.is_empty()
                {
                    // Stream fresh transactions to the leader immediately.
                    streamed = txs.len() as u64;
                    request_id += 1;
                    in_flight.insert(request_id, Instant::now());
                    in_flight.retain(|_, sent| sent.elapsed() < Duration::from_secs(5));
                    submit(&mut sender, &keys[target.leader], target.epoch, target.view, request_id, txs);
                }
                let mut dashboard = dashboard.lock();
                dashboard.generated += generated;
                dashboard.rpc_received += received;
                dashboard.streamed += streamed;
                if let Some(current) = dashboard.current.as_mut() {
                    current.sent += streamed;
                }
            }
        }
    }
}

/// Retries an RPC call until it succeeds; validators may still be starting.
async fn retry<T, E, F>(mut call: impl FnMut() -> F) -> T
where
    F: std::future::IntoFuture<Output = Result<T, E>>,
{
    loop {
        if let Ok(value) = call().await {
            return value;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn find_round(dashboard: &mut Dashboard, epoch: u64, view: u64) -> Option<&mut RoundView> {
    dashboard
        .current
        .iter_mut()
        .chain(dashboard.rounds.iter_mut())
        .find(|round| round.epoch == epoch && round.view == view)
}

/// Proposals that never finalize leave a maker's nonce ahead of the chain;
/// fall back to the chain after a grace period.
async fn resync_nonces(provider: RootProvider, makers: Arc<Vec<Maker>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for maker in makers.iter() {
            let Ok(chain) = provider
                .get_transaction_count(maker.signer.address())
                .latest()
                .await
            else {
                continue;
            };
            let local = maker.nonce.load(Ordering::Relaxed);
            let stale =
                unix_ms().saturating_sub(maker.bumped_at_ms.load(Ordering::Relaxed)) > 4_000;
            if chain > local || (chain < local && stale) {
                maker.nonce.store(chain, Ordering::Relaxed);
            }
        }
    }
}

fn submit(
    sender: &mut impl commonware_p2p::Sender<PublicKey = commonware_cryptography::ed25519::PublicKey>,
    leader: &commonware_cryptography::ed25519::PublicKey,
    epoch: u64,
    view: u64,
    id: u64,
    txs: Vec<SubmitTx>,
) {
    let message = Message::Submit(Submit {
        epoch,
        view,
        id,
        txs,
    });
    sender.send(Recipients::One(leader.clone()), message.encode(), true);
}

fn push_round(rounds: &mut VecDeque<RoundView>, round: RoundView) {
    rounds.push_front(round);
    rounds.truncate(ROUNDS_KEPT);
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy)]
struct TxTemplate {
    chain_id: u64,
    max_fee: u128,
    maker_tip: u128,
}

impl TxTemplate {
    fn sign(&self, maker: &Maker, nonce: u64, seq: u64) -> eyre::Result<(B256, Bytes)> {
        let tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit: 300_000,
            max_fee_per_gas: self.max_fee,
            max_priority_fee_per_gas: self.maker_tip,
            to: TxKind::Call(BOOK),
            value: U256::ZERO,
            input: U256::from(seq).to_be_bytes::<32>().to_vec().into(),
            access_list: Default::default(),
        };
        sign(&maker.signer, tx)
    }
}

fn sign(signer: &PrivateKeySigner, tx: TxEip1559) -> eyre::Result<(B256, Bytes)> {
    use alloy::signers::SignerSync as _;
    let signature = signer.sign_hash_sync(&tx.signature_hash())?;
    let envelope = TempoTxEnvelope::Eip1559(tx.into_signed(signature));
    let mut raw = Vec::with_capacity(envelope.length());
    envelope.encode_2718(&mut raw);
    Ok((*envelope.tx_hash(), raw.into()))
}

#[derive(Clone)]
struct PublicFlow {
    mnemonic: String,
    offset: u32,
    rate: u64,
}

impl Args {
    fn clone_public(&self) -> PublicFlow {
        PublicFlow {
            mnemonic: self.mnemonic.clone(),
            offset: self.public_offset,
            rate: self.public_rate,
        }
    }
}

/// Sends high-tip transactions to the public mempool of random validators.
async fn public_flow(
    flow: PublicFlow,
    providers: Vec<RootProvider>,
    chain_id: u64,
    max_fee: u128,
    tip: u128,
    dashboard: Arc<Mutex<Dashboard>>,
    hashes: Arc<Mutex<HashSet<B256>>>,
) {
    if flow.rate == 0 {
        return;
    }
    const ACCOUNTS: u32 = 8;
    let mut accounts = Vec::new();
    for i in 0..ACCOUNTS {
        let signer = MnemonicBuilder::from_phrase_nth(&flow.mnemonic, flow.offset + i);
        let nonce = providers[0]
            .get_transaction_count(signer.address())
            .await
            .unwrap_or_default();
        accounts.push((signer, nonce));
    }
    let mut ticker = tokio::time::interval(Duration::from_secs_f64(1.0 / flow.rate as f64));
    let mut resync = Instant::now();
    let mut i = 0u64;
    loop {
        i += 1;
        ticker.tick().await;
        if resync.elapsed() > Duration::from_secs(3) {
            resync = Instant::now();
            for (signer, nonce) in &mut accounts {
                if let Ok(chain) = providers[0].get_transaction_count(signer.address()).await
                    && chain > *nonce
                {
                    *nonce = chain;
                }
            }
        }
        let (signer, nonce) = &mut accounts[(i % u64::from(ACCOUNTS)) as usize];
        let tx = TxEip1559 {
            chain_id,
            nonce: *nonce,
            gas_limit: 300_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            to: TxKind::Call(BOOK),
            value: U256::ZERO,
            input: Bytes::from_static(b"public"),
            access_list: Default::default(),
        };
        let Ok((hash, raw)) = sign(signer, tx) else {
            continue;
        };
        let provider = &providers[(i as usize) % providers.len()];
        match provider.send_raw_transaction(&raw).await {
            Ok(_) => {
                *nonce += 1;
                hashes.lock().insert(hash);
                dashboard.lock().public_sent += 1;
            }
            Err(_) => {
                dashboard.lock().public_failed += 1;
                if let Ok(chain) = provider.get_transaction_count(signer.address()).await {
                    *nonce = chain;
                }
            }
        }
    }
}

/// A block proposed by a leader, read from the consensus broadcast.
struct Proposed {
    epoch: u64,
    view: u64,
    height: u64,
    block_hash: B256,
    top_of_block: Vec<B256>,
}

/// Checks each proposal against a different validator's view of the chain.
async fn verify_blocks(
    providers: Vec<RootProvider>,
    mut built_rx: tokio::sync::mpsc::UnboundedReceiver<(usize, Proposed)>,
    dashboard: Arc<Mutex<Dashboard>>,
    public_hashes: Arc<Mutex<HashSet<B256>>>,
) {
    while let Some((leader, built)) = built_rx.recv().await {
        let providers = providers.clone();
        let dashboard = dashboard.clone();
        let public_hashes = public_hashes.clone();
        tokio::spawn(async move {
            let checked_on = (leader + 1) % providers.len();
            let mut block = None;
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Ok(Some(found)) = providers[checked_on]
                    .raw_request::<_, Option<serde_json::Value>>(
                        "eth_getBlockByNumber".into(),
                        (format!("{:#x}", built.height), false),
                    )
                    .await
                {
                    block = Some(found);
                    break;
                }
            }
            let Some(block) = block else { return };
            let hash: Option<B256> = block["hash"].as_str().and_then(|hash| hash.parse().ok());
            let txs: Vec<B256> = block["transactions"]
                .as_array()
                .map(|txs| {
                    txs.iter()
                        .filter_map(|tx| tx.as_str()?.parse().ok())
                        .collect()
                })
                .unwrap_or_default();
            let canonical = hash == Some(built.block_hash);
            let public = public_hashes.lock();
            let top: HashSet<_> = built.top_of_block.iter().collect();
            let layout: String = txs
                .iter()
                .map(|tx| {
                    if top.contains(tx) {
                        't'
                    } else if public.contains(tx) {
                        'p'
                    } else {
                        'o'
                    }
                })
                .collect();
            let public_positions = layout
                .char_indices()
                .filter(|(_, kind)| *kind == 'p')
                .map(|(i, _)| i)
                .collect();
            drop(public);
            let prefix_ok = canonical
                && txs.len() >= built.top_of_block.len()
                && txs[..built.top_of_block.len()] == built.top_of_block[..];
            let mut dashboard = dashboard.lock();
            let dashboard = &mut *dashboard;
            if let Some(round) = dashboard
                .current
                .iter_mut()
                .chain(dashboard.rounds.iter_mut())
                .find(|round| round.epoch == built.epoch && round.view == built.view)
            {
                round.verification = Some(Verification {
                    checked_on,
                    canonical,
                    prefix_ok,
                    layout,
                    public_positions,
                });
            }
        });
    }
}

/// Serves the dashboard on `GET /` and JSON-RPC on `POST /`.
async fn serve_dashboard(
    address: SocketAddr,
    dashboard: Arc<Mutex<Dashboard>>,
    quotes: tokio::sync::mpsc::UnboundedSender<Quote>,
) -> eyre::Result<()> {
    use axum::{Json, Router, response::Html, routing::get};
    let app = Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("tob_operator.html")) }).post(
                move |Json(request): Json<serde_json::Value>| {
                    let quotes = quotes.clone();
                    async move { Json(rpc(request, &quotes).await) }
                },
            ),
        )
        .route(
            "/state",
            get(move || {
                let dashboard = dashboard.clone();
                async move {
                    let dashboard = dashboard.lock();
                    Json(serde_json::to_value(&*dashboard).unwrap_or_default())
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .wrap_err_with(|| format!("failed binding dashboard to {address}"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Handles one JSON-RPC 2.0 request.
///
/// `tempo_sendTobTransaction(rawTx, { seq?, expiresAt? })` queues a signed
/// transaction for the top of the next block. It replaces the transaction in
/// its slot (signer and nonce key) if `seq` is higher than the slot's; without
/// `seq`, it takes the slot's next sequence. `expiresAt` is unix time in
/// milliseconds; the leader drops the transaction unless the block is earlier.
async fn rpc(
    request: serde_json::Value,
    quotes: &tokio::sync::mpsc::UnboundedSender<Quote>,
) -> serde_json::Value {
    use alloy_consensus::transaction::SignerRecoverable as _;
    use alloy_eips::eip2718::Decodable2718 as _;

    let id = request.get("id").cloned().unwrap_or_default();
    let error = |code: i64, message: String| serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}});
    if request["method"] != "tempo_sendTobTransaction" {
        return error(-32601, "method not found".into());
    }
    let params = &request["params"];
    let Some(raw) = params[0]
        .as_str()
        .and_then(|raw| alloy_primitives::hex::decode(raw).ok())
    else {
        return error(-32602, "expected a hex-encoded signed transaction".into());
    };
    let options = &params[1];
    let number = |field: &str| -> Result<Option<u64>, String> {
        match &options[field] {
            serde_json::Value::Null => Ok(None),
            value => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| format!("`{field}` must be an unsigned integer")),
        }
    };
    let (seq, expires_at_ms) = match (number("seq"), number("expiresAt")) {
        (Ok(seq), Ok(expires_at)) => (seq, expires_at.unwrap_or_default()),
        (Err(message), _) | (_, Err(message)) => return error(-32602, message),
    };
    let tx = match TempoTxEnvelope::decode_2718_exact(&raw)
        .map_err(|error| error.to_string())
        .and_then(|tx| tx.try_into_recovered().map_err(|error| error.to_string()))
    {
        Ok(tx) => tx,
        Err(message) => return error(-32602, format!("invalid transaction: {message}")),
    };
    let (reply, accepted) = tokio::sync::oneshot::channel();
    let quote = Quote {
        slot: tempo_payload_types::top_of_block_slot(&tx),
        maker: None,
        hash: *tx.tx_hash(),
        raw: raw.into(),
        seq,
        expires_at_ms,
        reply: Some(reply),
    };
    if quotes.send(quote).is_err() {
        return error(-32603, "operator is shutting down".into());
    }
    match accepted.await {
        Ok(Ok(accepted)) => serde_json::json!({"jsonrpc": "2.0", "id": id, "result": accepted}),
        Ok(Err(message)) => error(-32000, message),
        Err(_) => error(-32603, "operator dropped the request".into()),
    }
}
