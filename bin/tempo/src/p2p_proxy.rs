use alloy::{
    consensus::BlockHeader,
    eips::{BlockHashOrNumber, BlockNumberOrTag},
    network::{Network, primitives::HeaderResponse},
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    rpc::client::BatchRequest,
};
use clap::Parser;
use eyre::{Context, Result};
use futures::StreamExt;
use reth_chainspec::Head;
use reth_cli_util::get_secret_key;
use reth_eth_wire_types::{
    HeadersDirection, PooledTransactions, primitives::BasicNetworkPrimitives,
};
use reth_ethereum::{
    network::{
        NetworkConfig, NetworkEventListenerProvider, NetworkInfo, NetworkManager, PeersConfig,
        PeersInfo, eth_requests::IncomingEthRequest, transactions::NetworkTransactionEvent,
    },
    tasks::Runtime,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::spec::{TempoChainSpec, chain_value_parser};
use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info};

/// Tempo-specific network primitives for the proxy node.
type TempoNetPrimitives = BasicNetworkPrimitives<TempoPrimitives, TempoTxEnvelope>;
type TempoRpcBlock = <TempoNetwork as Network>::BlockResponse;

/// 3 hrs of blocks at 500ms block time.
const CACHE_CAPACITY: u64 = 60 * 60 * 6; // 21600
const HEADER_BATCH_SIZE: usize = 512;

#[derive(Parser, Debug)]
#[command(
    about = "Run a proxy P2P node that serves cached block data fetched from an RPC endpoint"
)]
pub(crate) struct P2pProxyArgs {
    /// RPC endpoint to fetch blocks from (HTTP or WebSocket).
    #[arg(long, required = true)]
    rpc_url: String,

    /// Chain to connect to.
    #[arg(long, default_value = "mainnet")]
    chain: String,

    /// Port for the P2P listener.
    #[arg(long, default_value_t = 30303)]
    port: u16,

    /// Discovery port.
    #[arg(long)]
    discovery_port: Option<u16>,

    /// Maximum number of inbound peer connections.
    #[arg(long, default_value_t = 100)]
    max_inbound: usize,

    /// Maximum number of concurrent incoming connection attempts.
    #[arg(long, default_value_t = 30)]
    max_concurrent_inbound: usize,

    /// Number of blocks to cache.
    #[arg(long)]
    cache_blocks: Option<u64>,

    /// Path to the P2P secret key file. If the file doesn't exist, a new key is generated
    /// and saved. If omitted, an ephemeral key is generated on each start.
    #[arg(long)]
    p2p_secret_key: Option<PathBuf>,
}

impl P2pProxyArgs {
    pub(crate) async fn run(self) -> Result<()> {
        let chain_spec = chain_value_parser(&self.chain)?;

        // Fetch latest head from RPC for the network status handshake
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect(&self.rpc_url)
            .await
            .context("failed to connect to RPC")?;
        let latest_block = provider
            .get_block_by_number(Default::default())
            .await
            .context("failed to fetch latest block")?
            .ok_or_else(|| eyre::eyre!("latest block not found"))?;
        let head = Head {
            number: latest_block.header.number(),
            hash: latest_block.header.hash(),
            difficulty: latest_block.header.difficulty(),
            total_difficulty: latest_block.header.difficulty(),
            timestamp: latest_block.header.timestamp(),
        };
        info!(number = head.number, hash = %head.hash, "fetched latest head");

        // Channel for the single fetcher service
        let (fetch_tx, fetch_rx) = mpsc::channel::<FetchRequest>(256);

        // Spawn the block fetcher service
        let rpc_url = self.rpc_url.clone();
        let cache_blocks = self.cache_blocks.unwrap_or(CACHE_CAPACITY);
        tokio::spawn(async move {
            if let Err(err) = run_fetcher_service(rpc_url, fetch_rx, cache_blocks).await {
                error!(%err, "block fetcher service exited with error");
            }
        });

        // Resolve the P2P secret key: load from file (creating if needed), or ephemeral
        let secret_key = match &self.p2p_secret_key {
            Some(path) => get_secret_key(path).context("failed to load P2P secret key")?,
            None => reth_cli_util::load_secret_key::rng_secret_key(),
        };

        // Launch the P2P network
        let net_cfg = NetConfig {
            port: self.port,
            discovery_port: self.discovery_port,
            max_inbound: self.max_inbound,
            max_concurrent_inbound: self.max_concurrent_inbound,
            head,
        };
        run_p2p_network(chain_spec, net_cfg, fetch_tx, secret_key).await
    }
}

/// Resolved network configuration passed to `run_p2p_network`.
struct NetConfig {
    port: u16,
    discovery_port: Option<u16>,
    max_inbound: usize,
    max_concurrent_inbound: usize,
    head: Head,
}

/// Shared request counters for periodic stats logging.
struct RequestStats {
    headers: AtomicU64,
    bodies: AtomicU64,
}

/// Messages from the request handler to the single block-fetcher service.
enum FetchRequest {
    GetHeaders {
        request: reth_eth_wire_types::GetBlockHeaders,
        response: oneshot::Sender<Vec<TempoHeader>>,
    },
    GetBodies {
        hashes: Vec<B256>,
        response: oneshot::Sender<Vec<tempo_primitives::BlockBody>>,
    },
}

/// A cached block: header + body, indexed by number and hash.
struct BlockCache {
    /// Blocks ordered by number.
    by_number: BTreeMap<u64, CachedBlock>,
    /// Hash -> block number index.
    by_hash: HashMap<B256, u64>,
    capacity: u64,
}

impl BlockCache {
    fn new(capacity: u64) -> Self {
        Self {
            by_number: BTreeMap::new(),
            by_hash: HashMap::new(),
            capacity,
        }
    }

    fn insert_header(&mut self, number: u64, hash: B256, header: TempoHeader) {
        self.upsert(number, hash, header, None);
    }

    fn insert_block(
        &mut self,
        number: u64,
        hash: B256,
        header: TempoHeader,
        body: tempo_primitives::BlockBody,
    ) {
        self.upsert(number, hash, header, Some(body));
    }

    fn upsert(
        &mut self,
        number: u64,
        hash: B256,
        header: TempoHeader,
        body: Option<tempo_primitives::BlockBody>,
    ) {
        if let Some(old_hash) = self.by_number.get(&number).map(|block| block.hash)
            && old_hash != hash
        {
            self.by_hash.remove(&old_hash);
        }

        let body = match self.by_number.remove(&number) {
            Some(existing) => body.or(existing.body),
            None => body,
        };

        self.by_number
            .insert(number, CachedBlock { header, body, hash });
        self.by_hash.insert(hash, number);
        self.evict();
    }

    fn evict(&mut self) {
        while self.by_number.len() as u64 > self.capacity {
            if let Some((&oldest_num, _)) = self.by_number.iter().next()
                && let Some(block) = self.by_number.remove(&oldest_num)
            {
                self.by_hash.remove(&block.hash);
            }
        }
    }

    fn get_by_number(&self, number: u64) -> Option<&CachedBlock> {
        self.by_number.get(&number)
    }

    fn get_by_hash(&self, hash: &B256) -> Option<&CachedBlock> {
        self.by_hash
            .get(hash)
            .and_then(|num| self.by_number.get(num))
    }
}

#[derive(Clone)]
struct CachedBlock {
    header: TempoHeader,
    body: Option<tempo_primitives::BlockBody>,
    hash: B256,
}

/// Single block-fetcher service that owns the cache and handles all fetch requests.
async fn run_fetcher_service(
    rpc_url: String,
    mut fetch_rx: mpsc::Receiver<FetchRequest>,
    cache_blocks: u64,
) -> Result<()> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&rpc_url)
        .await
        .context("failed to connect to RPC")?;

    let mut cache = BlockCache::new(cache_blocks);

    // Process incoming requests
    while let Some(req) = fetch_rx.recv().await {
        match req {
            FetchRequest::GetHeaders { request, response } => {
                let headers = resolve_headers(&provider, &mut cache, &request).await;
                let _ = response.send(headers);
            }
            FetchRequest::GetBodies { hashes, response } => {
                let bodies = resolve_bodies(&provider, &mut cache, &hashes).await;
                let _ = response.send(bodies);
            }
        }
    }

    Ok(())
}

/// Launch the P2P network and handle incoming eth requests.
async fn run_p2p_network(
    chain_spec: Arc<TempoChainSpec>,
    cfg: NetConfig,
    fetch_tx: mpsc::Sender<FetchRequest>,
    secret_key: secp256k1::SecretKey,
) -> Result<()> {
    let peers_config = PeersConfig::default()
        .with_max_inbound(cfg.max_inbound)
        .with_max_outbound(0);

    let mut builder = NetworkConfig::<_, TempoNetPrimitives>::builder(secret_key, Runtime::test())
        .listener_port(cfg.port)
        .disable_dns_discovery()
        .disable_tx_gossip(true)
        .peer_config(peers_config)
        .set_head(cfg.head);

    if let Some(dp) = cfg.discovery_port {
        builder = builder.discovery_port(dp);
    }

    let mut config = builder.build_with_noop_provider(chain_spec);
    config.sessions_config.session_event_buffer = cfg.max_concurrent_inbound;

    let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(1024);
    let (transactions_tx, mut transactions_rx) = tokio::sync::mpsc::unbounded_channel();

    let network = NetworkManager::new(config)
        .await
        .context("failed to create network manager")?
        .with_eth_request_handler(requests_tx)
        .with_transactions(transactions_tx);

    let handle = network.handle().clone();
    info!(
        peer_id = %handle.peer_id(),
        local_addr = %handle.local_addr(),
        max_inbound = cfg.max_inbound,
        "P2P proxy node started"
    );

    // Print network events
    let events_handle = handle.clone();
    tokio::spawn(async move {
        let mut events = events_handle.event_listener();
        while let Some(event) = events.next().await {
            debug!(?event, "network event");
        }
    });

    // Drain transaction events — respond empty to all requests
    tokio::spawn(async move {
        while let Some(event) = transactions_rx.recv().await {
            if let NetworkTransactionEvent::GetPooledTransactions { response, .. } = event {
                let _ = response.send(Ok(PooledTransactions(vec![])));
            }
        }
    });

    // Spawn the network
    tokio::spawn(network);

    // Request stats for periodic logging
    let stats = Arc::new(RequestStats {
        headers: AtomicU64::new(0),
        bodies: AtomicU64::new(0),
    });

    // Periodic stats logging
    let stats_log = Arc::clone(&stats);
    let stats_handle = handle.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let h = stats_log.headers.load(Ordering::Relaxed);
            let b = stats_log.bodies.load(Ordering::Relaxed);
            let peers = stats_handle.num_connected_peers();
            info!(peers, headers_served = h, bodies_served = b, "proxy stats");
        }
    });

    // Handle incoming eth requests
    while let Some(eth_request) = requests_rx.recv().await {
        match eth_request {
            IncomingEthRequest::GetBlockHeaders {
                peer_id,
                request,
                response,
            } => {
                debug!(%peer_id, ?request, "received GetBlockHeaders");
                stats.headers.fetch_add(1, Ordering::Relaxed);
                let fetch_tx = fetch_tx.clone();
                tokio::spawn(async move {
                    let headers = async {
                        let (tx, rx) = oneshot::channel();
                        fetch_tx
                            .send(FetchRequest::GetHeaders {
                                request,
                                response: tx,
                            })
                            .await
                            .ok()?;
                        rx.await.ok()
                    }
                    .await
                    .unwrap_or_default();
                    let _ = response.send(Ok(headers.into()));
                });
            }
            IncomingEthRequest::GetBlockBodies {
                peer_id,
                request,
                response,
            } => {
                debug!(%peer_id, ?request, "received GetBlockBodies");
                stats.bodies.fetch_add(1, Ordering::Relaxed);
                let fetch_tx = fetch_tx.clone();
                tokio::spawn(async move {
                    let bodies = async {
                        let (tx, rx) = oneshot::channel();
                        fetch_tx
                            .send(FetchRequest::GetBodies {
                                hashes: request.0,
                                response: tx,
                            })
                            .await
                            .ok()?;
                        rx.await.ok()
                    }
                    .await
                    .unwrap_or_default();
                    let _ = response.send(Ok(bodies.into()));
                });
            }
            // All other requests get empty responses
            IncomingEthRequest::GetNodeData { response, .. } => {
                let _ = response.send(Ok(Default::default()));
            }
            IncomingEthRequest::GetReceipts { response, .. } => {
                let _ = response.send(Ok(reth_eth_wire_types::Receipts(vec![])));
            }
            IncomingEthRequest::GetReceipts69 { response, .. } => {
                let _ = response.send(Ok(reth_eth_wire_types::Receipts69(vec![])));
            }
            IncomingEthRequest::GetReceipts70 { response, .. } => {
                let _ = response.send(Ok(reth_eth_wire_types::Receipts70 {
                    last_block_incomplete: false,
                    receipts: vec![],
                }));
            }
            IncomingEthRequest::GetBlockAccessLists { response, .. } => {
                let _ = response.send(Ok(Default::default()));
            }
        }
    }

    Ok(())
}

/// Fetch a single block by number and insert it into the cache.
#[cfg(test)]
async fn fetch_and_cache_block(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    number: u64,
) -> Result<()> {
    let block = provider
        .get_block_by_number(number.into())
        .full()
        .await
        .context("rpc request failed")?
        .ok_or_else(|| eyre::eyre!("block {number} not found"))?;

    let hash = block.header.hash();
    let header: TempoHeader = block.header.inner.inner.clone();
    let body = tempo_primitives::BlockBody {
        transactions: block
            .transactions
            .into_transactions()
            .map(|tx| tx.into_inner())
            .collect(),
        ommers: vec![],
        withdrawals: block.withdrawals,
    };

    cache.insert_block(number, hash, header, body);
    Ok(())
}

async fn fetch_and_cache_header_by_hash(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    hash: B256,
) -> Result<u64> {
    let block = provider
        .get_block_by_hash(hash)
        .await
        .context("rpc request failed")?
        .ok_or_else(|| eyre::eyre!("block {hash} not found"))?;

    let number = block.header.number();
    let header: TempoHeader = block.header.inner.inner.clone();
    cache.insert_header(number, block.header.hash(), header);
    Ok(number)
}

async fn fetch_and_cache_header_by_number(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    number: u64,
) -> Result<()> {
    let block = provider
        .get_block_by_number(number.into())
        .await
        .context("rpc request failed")?
        .ok_or_else(|| eyre::eyre!("block {number} not found"))?;

    let header: TempoHeader = block.header.inner.inner.clone();
    cache.insert_header(block.header.number(), block.header.hash(), header);
    Ok(())
}

async fn fetch_and_cache_header_batch(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    numbers: &[u64],
) -> Result<()> {
    let mut batch = BatchRequest::new(provider.client());
    let mut waiters = Vec::with_capacity(numbers.len());

    for &number in numbers {
        let waiter = batch.add_call::<_, Option<TempoRpcBlock>>(
            "eth_getBlockByNumber",
            &(BlockNumberOrTag::Number(number), false),
        )?;
        waiters.push((number, waiter));
    }

    batch.send().await.context("failed to fetch header batch")?;

    for (number, waiter) in waiters {
        match waiter.await {
            Ok(Some(block)) => {
                let header: TempoHeader = block.header.inner.inner.clone();
                cache.insert_header(block.header.number(), block.header.hash(), header);
            }
            Ok(None) => {
                debug!(number, "header batch returned no block");
            }
            Err(err) => {
                debug!(number, %err, "header batch waiter failed; falling back to single request");
                let _ = fetch_and_cache_header_by_number(provider, cache, number).await;
            }
        }
    }

    Ok(())
}

async fn fetch_and_cache_headers(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    numbers: &[u64],
) {
    let missing_numbers: Vec<u64> = numbers
        .iter()
        .copied()
        .filter(|number| cache.get_by_number(*number).is_none())
        .collect();

    for chunk in missing_numbers.chunks(HEADER_BATCH_SIZE) {
        if fetch_and_cache_header_batch(provider, cache, chunk)
            .await
            .is_err()
        {
            for &number in chunk {
                let _ = fetch_and_cache_header_by_number(provider, cache, number).await;
            }
        }
    }
}

async fn resolve_start_block_number(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    start_block: BlockHashOrNumber,
) -> Option<u64> {
    match start_block {
        BlockHashOrNumber::Number(number) => Some(number),
        BlockHashOrNumber::Hash(hash) => {
            if let Some(block) = cache.get_by_hash(&hash) {
                return Some(block.header.number());
            }

            fetch_and_cache_header_by_hash(provider, cache, hash)
                .await
                .ok()
        }
    }
}

fn requested_header_numbers(
    mut current: u64,
    request: &reth_eth_wire_types::GetBlockHeaders,
) -> Vec<u64> {
    let mut numbers = Vec::with_capacity(request.limit.min(HEADER_BATCH_SIZE as u64) as usize);
    let step = u64::from(request.skip) + 1;

    for _ in 0..request.limit {
        numbers.push(current);

        match request.direction {
            HeadersDirection::Rising => match current.checked_add(step) {
                Some(next) => current = next,
                None => break,
            },
            HeadersDirection::Falling => match current.checked_sub(step) {
                Some(next) => current = next,
                None => break,
            },
        }
    }

    numbers
}

/// Resolve a GetBlockHeaders request from cache, fetching missing blocks from RPC as needed.
async fn resolve_headers(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    request: &reth_eth_wire_types::GetBlockHeaders,
) -> Vec<TempoHeader> {
    let Some(start_num) = resolve_start_block_number(provider, cache, request.start_block).await
    else {
        return Vec::new();
    };

    let requested_numbers = requested_header_numbers(start_num, request);
    fetch_and_cache_headers(provider, cache, &requested_numbers).await;

    let mut headers = Vec::with_capacity(requested_numbers.len());
    for number in requested_numbers {
        let Some(block) = cache.get_by_number(number) else {
            break;
        };
        headers.push(block.header.clone());
    }

    headers
}

async fn fetch_body_by_hash(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    hash: B256,
) -> Option<tempo_primitives::BlockBody> {
    let block = provider
        .get_block_by_hash(hash)
        .full()
        .await
        .ok()
        .flatten()?;
    let number = block.header.number();
    let header: TempoHeader = block.header.inner.inner.clone();
    let body = tempo_primitives::BlockBody {
        transactions: block
            .transactions
            .into_transactions()
            .map(|tx| tx.into_inner())
            .collect(),
        ommers: vec![],
        withdrawals: block.withdrawals,
    };

    cache.insert_block(number, hash, header, body.clone());
    Some(body)
}

/// Resolve a GetBlockBodies request from cache, fetching missing blocks from RPC as needed.
async fn resolve_bodies(
    provider: &impl Provider<TempoNetwork>,
    cache: &mut BlockCache,
    hashes: &[B256],
) -> Vec<tempo_primitives::BlockBody> {
    let mut bodies = Vec::new();

    for &hash in hashes {
        if let Some(body) = cache
            .get_by_hash(&hash)
            .and_then(|block| block.body.clone())
        {
            bodies.push(body);
            continue;
        }

        if let Some(body) = fetch_body_by_hash(provider, cache, hash).await {
            bodies.push(body);
        }
    }

    bodies
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{consensus::BlockHeader, primitives::Sealable};
    use reth_eth_wire_types::GetBlockHeaders;

    const MODERATO_RPC: &str = "https://rpc.moderato.tempo.xyz";

    fn moderato_provider() -> impl Provider<TempoNetwork> {
        ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http(MODERATO_RPC.parse().unwrap())
    }

    #[tokio::test]
    async fn fetch_headers_and_bodies() {
        let provider = moderato_provider();
        let mut cache = BlockCache::new(100);

        let latest = provider.get_block_number().await.unwrap();
        let start = latest.saturating_sub(4);

        // Fetch 5 rising headers
        let request = GetBlockHeaders {
            start_block: BlockHashOrNumber::Number(start),
            limit: 5,
            skip: 0,
            direction: HeadersDirection::Rising,
        };
        let headers = resolve_headers(&provider, &mut cache, &request).await;
        assert_eq!(headers.len(), 5);
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header.number(), start + i as u64);
        }
        // Parent hash chain should be consistent
        for pair in headers.windows(2) {
            assert_eq!(pair[1].parent_hash(), pair[0].hash_slow());
        }

        // Fetch bodies for the cached blocks
        let hashes: Vec<B256> = (start..=latest)
            .map(|n| cache.get_by_number(n).unwrap().hash)
            .collect();
        let bodies = resolve_bodies(&provider, &mut cache, &hashes).await;
        assert_eq!(bodies.len(), 5);
    }

    #[tokio::test]
    async fn fetch_body_by_hash_from_rpc() {
        let provider = moderato_provider();
        let mut cache = BlockCache::new(100);

        // Learn a hash, then clear cache to force RPC fetch
        let latest = provider.get_block_number().await.unwrap();
        fetch_and_cache_block(&provider, &mut cache, latest)
            .await
            .unwrap();
        let hash = cache.get_by_number(latest).unwrap().hash;
        cache = BlockCache::new(100);

        let bodies = resolve_bodies(&provider, &mut cache, &[hash]).await;
        assert_eq!(bodies.len(), 1);
        assert!(
            cache.get_by_hash(&hash).is_some(),
            "should be cached after fetch"
        );
    }

    #[tokio::test]
    async fn fetch_headers_by_hash_from_rpc_when_not_cached() {
        let provider = moderato_provider();
        let mut cache = BlockCache::new(100);

        let latest = provider.get_block_number().await.unwrap();
        let start = latest.saturating_sub(2);
        let start_block = provider
            .get_block_by_number(start.into())
            .await
            .unwrap()
            .unwrap();
        let start_hash = start_block.header.hash();

        let request = GetBlockHeaders {
            start_block: BlockHashOrNumber::Hash(start_hash),
            limit: 3,
            skip: 0,
            direction: HeadersDirection::Rising,
        };
        let headers = resolve_headers(&provider, &mut cache, &request).await;

        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].number(), start);
        assert_eq!(headers[0].hash_slow(), start_hash);
        assert!(cache.get_by_hash(&start_hash).is_some());
    }
}
