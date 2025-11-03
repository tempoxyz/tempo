use alloy::consensus::BlockHeader;
use alloy_primitives::Sealable;
use alloy_rpc_types_eth::{Filter, Log};
use futures::{StreamExt, stream::FuturesOrdered};
use itertools::Itertools;
use jsonrpsee::{core::RpcResult, tracing::trace};
use reth_errors::RethError;
use reth_primitives_traits::{NodePrimitives, SealedHeader};
use reth_provider::{
    BlockIdReader, BlockNumReader, BlockReader, HeaderProvider, ProviderBlock, ProviderReceipt,
    ReceiptProvider,
};
use reth_rpc_eth_api::{
    EthApiTypes, QueryLimits, RpcNodeCore, RpcNodeCoreExt, helpers::SpawnBlocking,
};
use reth_rpc_eth_types::{
    EthApiError,
    error::FromEthApiError,
    logs_utils::{ProviderOrBlock, append_matching_block_logs},
};
use reth_tracing::tracing::debug;
use reth_transaction_pool::TransactionPool;
use std::{
    collections::VecDeque,
    iter::{Peekable, StepBy},
    ops::RangeInclusive,
    pin::Pin,
    sync::Arc,
};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::TempoHeader;

pub(crate) async fn filter_logs<EthApi>(eth_api: EthApi, filter: Filter) -> RpcResult<Vec<Log>>
where
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>
        + SpawnBlocking
        + RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool>
        + EthApiTypes
        + 'static,
{
    let limits = QueryLimits::no_limits();
    let to_block = eth_api
        .provider()
        .last_block_number()
        .map_err(EthApiError::from)
        .map_err(EthApi::Error::from_eth_err)
        .map_err(Into::into)?;

    trace!(
        target: "rpc::policy::addresses",
        ?filter,
        "finding policy addresses in logs"
    );

    eth_api
        .spawn_blocking_io_fut(move |this| {
            Box::pin(async move {
                get_logs_in_block_range_inner(this, &filter, 0, to_block, limits)
                    .await
                    .map_err(EthApi::Error::from_eth_err)
            })
        })
        .await
        .map_err(Into::into)
}

async fn get_logs_in_block_range_inner<EthApi>(
    eth_api: EthApi,
    filter: &Filter,
    from_block: u64,
    to_block: u64,
    limits: QueryLimits,
) -> Result<Vec<Log>, EthApiError>
where
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>
        + SpawnBlocking
        + RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool>
        + EthApiTypes
        + 'static,
{
    let mut all_logs = Vec::new();
    let mut matching_headers = Vec::new();

    // get current chain tip to determine processing mode
    let chain_tip = eth_api.provider().best_block_number()?;

    // first collect all headers that match the bloom filter for cached mode decision
    for (from, to) in BlockRangeInclusiveIter::new(from_block..=to_block, MAX_HEADERS_RANGE) {
        let headers = eth_api.provider().headers_range(from..=to)?;

        let mut headers_iter = headers.into_iter().peekable();

        while let Some(header) = headers_iter.next() {
            if !filter.matches_bloom(header.logs_bloom()) {
                continue;
            }

            let current_number = header.number();

            let block_hash = match headers_iter.peek() {
                Some(next_header) if next_header.number() == current_number + 1 => {
                    // Headers are consecutive, use the more efficient parent_hash
                    next_header.parent_hash()
                }
                _ => {
                    // Headers not consecutive or last header, calculate hash
                    header.hash_slow()
                }
            };

            matching_headers.push(SealedHeader::new(header, block_hash));
        }
    }

    // initialize the appropriate range mode based on collected headers
    let mut range_mode = RangeMode::new(
        eth_api.clone(),
        matching_headers,
        from_block,
        to_block,
        MAX_HEADERS_RANGE,
        chain_tip,
    );

    // iterate through the range mode to get receipts and blocks
    while let Some(ReceiptBlockResult {
        receipts,
        recovered_block,
        header,
    }) = range_mode.next().await?
    {
        let num_hash = header.num_hash();
        append_matching_block_logs(
            &mut all_logs,
            recovered_block
                .map(ProviderOrBlock::Block)
                .unwrap_or_else(|| ProviderOrBlock::Provider(eth_api.provider())),
            filter,
            num_hash,
            &receipts,
            false,
            header.timestamp(),
        )?;

        // size check but only if range is multiple blocks, so we always return all
        // logs of a single block
        let is_multi_block_range = from_block != to_block;
        if let Some(max_logs_per_response) = limits.max_logs_per_response
            && is_multi_block_range
            && all_logs.len() > max_logs_per_response
        {
            debug!(
                target: "rpc::policy::addresses",
                logs_found = all_logs.len(),
                max_logs_per_response,
                from_block,
                to_block = num_hash.number.saturating_sub(1),
                "Query exceeded max logs per response limit"
            );
        }
    }

    Ok(all_logs)
}

/// Represents different modes for processing block ranges when filtering logs
enum RangeMode<
    Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static,
> {
    /// Use cache-based processing for recent blocks
    Cached(CachedMode<Eth>),
    /// Use range-based processing for older blocks
    Range(RangeBlockMode<Eth>),
}

impl<Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static>
    RangeMode<Eth>
{
    /// Creates a new `RangeMode`.
    fn new(
        filter_inner: Eth,
        sealed_headers: Vec<SealedHeader<<Eth::Provider as HeaderProvider>::Header>>,
        from_block: u64,
        to_block: u64,
        max_headers_range: u64,
        chain_tip: u64,
    ) -> Self {
        let block_count = to_block - from_block + 1;
        let distance_from_tip = chain_tip.saturating_sub(to_block);

        // Determine if we should use cached mode based on range characteristics
        let use_cached_mode =
            Self::should_use_cached_mode(&sealed_headers, block_count, distance_from_tip);

        if use_cached_mode && !sealed_headers.is_empty() {
            Self::Cached(CachedMode {
                filter_inner,
                headers_iter: sealed_headers.into_iter(),
            })
        } else {
            Self::Range(RangeBlockMode {
                filter_inner,
                iter: sealed_headers.into_iter().peekable(),
                next: VecDeque::new(),
                max_range: max_headers_range as usize,
                pending_tasks: FuturesOrdered::new(),
            })
        }
    }

    /// Determines whether to use cached mode based on bloom filter matches and range size
    const fn should_use_cached_mode(
        headers: &[SealedHeader<<Eth::Provider as HeaderProvider>::Header>],
        block_count: u64,
        distance_from_tip: u64,
    ) -> bool {
        // Headers are already filtered by bloom, so count equals length
        let bloom_matches = headers.len();

        // Calculate adjusted threshold based on bloom matches
        let adjusted_threshold = Self::calculate_adjusted_threshold(block_count, bloom_matches);

        block_count <= adjusted_threshold && distance_from_tip <= adjusted_threshold
    }

    /// Calculates the adjusted cache threshold based on bloom filter matches
    const fn calculate_adjusted_threshold(block_count: u64, bloom_matches: usize) -> u64 {
        // Only apply adjustments for larger ranges
        if block_count <= BLOOM_ADJUSTMENT_MIN_BLOCKS {
            return CACHED_MODE_BLOCK_THRESHOLD;
        }

        match bloom_matches {
            n if n > HIGH_BLOOM_MATCH_THRESHOLD => CACHED_MODE_BLOCK_THRESHOLD / 2,
            n if n > MODERATE_BLOOM_MATCH_THRESHOLD => (CACHED_MODE_BLOCK_THRESHOLD * 3) / 4,
            _ => CACHED_MODE_BLOCK_THRESHOLD,
        }
    }

    /// Gets the next (receipts, `maybe_block`, header, `block_hash`) tuple.
    async fn next(&mut self) -> Result<Option<ReceiptBlockResult<Eth::Provider>>, EthApiError> {
        match self {
            Self::Cached(cached) => cached.next().await,
            Self::Range(range) => range.next().await,
        }
    }
}

/// An iterator that yields _inclusive_ block ranges of a given step size
#[derive(Debug)]
struct BlockRangeInclusiveIter {
    iter: StepBy<RangeInclusive<u64>>,
    step: u64,
    end: u64,
}

impl BlockRangeInclusiveIter {
    fn new(range: RangeInclusive<u64>, step: u64) -> Self {
        Self {
            end: *range.end(),
            iter: range.step_by(step as usize + 1),
            step,
        }
    }
}

impl Iterator for BlockRangeInclusiveIter {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.iter.next()?;
        let end = (start + self.step).min(self.end);
        if start > end {
            return None;
        }
        Some((start, end))
    }
}

/// Mode for processing blocks using cache optimization for recent blocks
struct CachedMode<
    Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static,
> {
    filter_inner: Eth,
    headers_iter: std::vec::IntoIter<SealedHeader<<Eth::Provider as HeaderProvider>::Header>>,
}

impl<Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static>
    CachedMode<Eth>
{
    async fn next(&mut self) -> Result<Option<ReceiptBlockResult<Eth::Provider>>, EthApiError> {
        for header in self.headers_iter.by_ref() {
            // Use get_receipts_and_maybe_block which has automatic fallback to provider
            if let Some((receipts, maybe_block)) = self
                .filter_inner
                .cache()
                .get_receipts_and_maybe_block(header.hash())
                .await?
            {
                return Ok(Some(ReceiptBlockResult {
                    receipts,
                    recovered_block: maybe_block,
                    header,
                }));
            }
        }

        Ok(None) // No more headers
    }
}

/// Helper type for the common pattern of returning receipts, block and the original header that is
/// a match for the filter.
struct ReceiptBlockResult<P>
where
    P: ReceiptProvider + BlockReader,
{
    /// We always need the entire receipts for the matching block.
    receipts: Arc<Vec<ProviderReceipt<P>>>,
    /// Block can be optional and we can fetch it lazily when needed.
    recovered_block: Option<Arc<reth_primitives_traits::RecoveredBlock<ProviderBlock<P>>>>,
    /// The header of the block.
    header: SealedHeader<<P as HeaderProvider>::Header>,
}

/// Type alias for parallel receipt fetching task futures used in `RangeBlockMode`
type ReceiptFetchFuture<P> =
    Pin<Box<dyn Future<Output = Result<Vec<ReceiptBlockResult<P>>, EthApiError>> + Send>>;

/// Mode for processing blocks using range queries for older blocks
struct RangeBlockMode<
    Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static,
> {
    filter_inner: Eth,
    iter: Peekable<std::vec::IntoIter<SealedHeader<<Eth::Provider as HeaderProvider>::Header>>>,
    next: VecDeque<ReceiptBlockResult<Eth::Provider>>,
    max_range: usize,
    // Stream of ongoing receipt fetching tasks
    pending_tasks: FuturesOrdered<ReceiptFetchFuture<Eth::Provider>>,
}

impl<Eth: RpcNodeCoreExt<Provider: BlockIdReader, Pool: TransactionPool> + EthApiTypes + 'static>
    RangeBlockMode<Eth>
{
    async fn next(&mut self) -> Result<Option<ReceiptBlockResult<Eth::Provider>>, EthApiError> {
        loop {
            // First, try to return any already processed result from buffer
            if let Some(result) = self.next.pop_front() {
                return Ok(Some(result));
            }

            // Try to get a completed task result if there are pending tasks
            if let Some(task_result) = self.pending_tasks.next().await {
                self.next.extend(task_result?);
                continue;
            }

            // No pending tasks - try to generate more work
            let Some(next_header) = self.iter.next() else {
                // No more headers to process
                return Ok(None);
            };

            let mut range_headers = Vec::with_capacity(self.max_range);
            range_headers.push(next_header);

            // Collect consecutive blocks up to max_range size
            while range_headers.len() < self.max_range {
                let Some(peeked) = self.iter.peek() else {
                    break;
                };
                let Some(last_header) = range_headers.last() else {
                    break;
                };

                let expected_next = last_header.number() + 1;
                if peeked.number() != expected_next {
                    debug!(
                        target: "rpc::policy::addresses",
                        last_block = last_header.number(),
                        next_block = peeked.number(),
                        expected = expected_next,
                        range_size = range_headers.len(),
                        "Non-consecutive block detected, stopping range collection"
                    );
                    break; // Non-consecutive block, stop here
                }

                let Some(next_header) = self.iter.next() else {
                    break;
                };
                range_headers.push(next_header);
            }

            // Check if we should use parallel processing for large ranges
            let remaining_headers = self.iter.len() + range_headers.len();
            if remaining_headers >= PARALLEL_PROCESSING_THRESHOLD {
                self.spawn_parallel_tasks(range_headers);
                // Continue loop to await the spawned tasks
            } else {
                // Process small range sequentially and add results to buffer
                if let Some(result) = self.process_small_range(range_headers).await? {
                    return Ok(Some(result));
                }
                // Continue loop to check for more work
            }
        }
    }

    /// Process a small range of headers sequentially
    ///
    /// This is used when the remaining headers count is below [`PARALLEL_PROCESSING_THRESHOLD`].
    async fn process_small_range(
        &mut self,
        range_headers: Vec<SealedHeader<<Eth::Provider as HeaderProvider>::Header>>,
    ) -> Result<Option<ReceiptBlockResult<Eth::Provider>>, EthApiError> {
        // Process each header individually to avoid queuing for all receipts
        for header in range_headers {
            // First check if already cached to avoid unnecessary provider calls
            let (maybe_block, maybe_receipts) = self
                .filter_inner
                .cache()
                .maybe_cached_block_and_receipts(header.hash())
                .await?;

            let receipts = match maybe_receipts {
                Some(receipts) => receipts,
                None => {
                    // Not cached - fetch directly from provider
                    match self
                        .filter_inner
                        .provider()
                        .receipts_by_block(header.hash().into())?
                    {
                        Some(receipts) => Arc::new(receipts),
                        None => continue, // No receipts found
                    }
                }
            };

            if !receipts.is_empty() {
                self.next.push_back(ReceiptBlockResult {
                    receipts,
                    recovered_block: maybe_block,
                    header,
                });
            }
        }

        Ok(self.next.pop_front())
    }

    /// Spawn parallel tasks for processing a large range of headers
    ///
    /// This is used when the remaining headers count is at or above
    /// [`PARALLEL_PROCESSING_THRESHOLD`].
    fn spawn_parallel_tasks(
        &mut self,
        range_headers: Vec<SealedHeader<<Eth::Provider as HeaderProvider>::Header>>,
    ) {
        // Split headers into chunks
        let chunk_size = std::cmp::max(range_headers.len() / DEFAULT_PARALLEL_CONCURRENCY, 1);
        let header_chunks = range_headers
            .into_iter()
            .chunks(chunk_size)
            .into_iter()
            .map(|chunk| chunk.collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // Spawn each chunk as a separate task directly into the FuturesOrdered stream
        for chunk_headers in header_chunks {
            let filter_inner = self.filter_inner.clone();
            let chunk_task = Box::pin(async move {
                let chunk_task = tokio::task::spawn_blocking(move || {
                    let mut chunk_results = Vec::new();

                    for header in chunk_headers {
                        // Fetch directly from provider - RangeMode is used for older blocks
                        // unlikely to be cached
                        let receipts = match filter_inner
                            .provider()
                            .receipts_by_block(header.hash().into())?
                        {
                            Some(receipts) => Arc::new(receipts),
                            None => continue, // No receipts found
                        };

                        if !receipts.is_empty() {
                            chunk_results.push(ReceiptBlockResult {
                                receipts,
                                recovered_block: None,
                                header,
                            });
                        }
                    }

                    Ok(chunk_results)
                });

                // Await the blocking task and handle the result
                match chunk_task.await {
                    Ok(Ok(chunk_results)) => Ok(chunk_results),
                    Ok(Err(e)) => Err(e),
                    Err(join_err) => {
                        trace!(target: "rpc::policy::addresses", error = ?join_err, "Task join error");
                        Err(EthApiError::Internal(RethError::Other(Box::new(join_err))))
                    }
                }
            });

            self.pending_tasks.push_back(chunk_task);
        }
    }
}

/// Threshold for deciding between cached and range mode processing
const CACHED_MODE_BLOCK_THRESHOLD: u64 = 250;

/// Threshold for bloom filter matches that triggers reduced caching
const HIGH_BLOOM_MATCH_THRESHOLD: usize = 20;

/// Threshold for bloom filter matches that triggers moderately reduced caching
const MODERATE_BLOOM_MATCH_THRESHOLD: usize = 10;

/// Minimum block count to apply bloom filter match adjustments
const BLOOM_ADJUSTMENT_MIN_BLOCKS: u64 = 100;

/// The maximum number of headers we read at once when handling a range filter.
const MAX_HEADERS_RANGE: u64 = 1_000; // with ~530bytes per header this is ~500kb

/// Threshold for enabling parallel processing in range mode
const PARALLEL_PROCESSING_THRESHOLD: usize = 1000;

/// Default concurrency for parallel processing
const DEFAULT_PARALLEL_CONCURRENCY: usize = 4;
