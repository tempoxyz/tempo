use super::cache::TokenEventCache;
use alloy::consensus::transaction::TxHashRef;
use futures::StreamExt;
use reth_primitives_traits::{AlloyBlockHeader, Block, BlockBody};
use reth_provider::{
    BlockNumReader, BlockReader, CanonStateNotification, CanonStateSubscriptions, HeaderProvider,
    ReceiptProvider,
};
use reth_tracing::tracing::{error, info};
use tempo_primitives::TempoPrimitives;

/// Runs the token event indexer as a background task.
///
/// Wraps the inner indexer in a panic-catching layer so that a panic doesn't
/// silently kill the background task. On failure the hybrid RPC approach
/// gracefully degrades to full chain scanning.
pub async fn run_token_indexer<P>(cache: TokenEventCache, provider: P)
where
    P: BlockReader
        + HeaderProvider
        + ReceiptProvider
        + BlockNumReader
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + Clone
        + 'static,
{
    if let Err(e) = run_token_indexer_inner(cache, provider).await {
        error!(target: "token_indexer", %e, "Token indexer terminated with error");
    }
}

/// Inner implementation that returns `Result` for structured error handling.
///
/// 1. Subscribes to `canonical_state_stream()` **first** so events are buffered
///    in the broadcast channel during the historical scan.
/// 2. Performs an async historical scan with periodic yielding so the tokio
///    runtime stays responsive.
/// 3. Consumes buffered + new stream events (no gap between scan and stream).
async fn run_token_indexer_inner<P>(cache: TokenEventCache, provider: P) -> Result<(), String>
where
    P: BlockReader
        + HeaderProvider
        + ReceiptProvider
        + BlockNumReader
        + CanonStateSubscriptions<Primitives = TempoPrimitives>
        + Clone
        + 'static,
{
    // Phase 1: Subscribe FIRST so events buffer during the historical scan
    let mut stream = provider.canonical_state_stream();

    // Phase 2: Historical scan (async, yields every 1000 blocks)
    scan_historical_blocks(&cache, &provider).await?;

    // Phase 3: Consume buffered + new canonical state events
    while let Some(event) = stream.next().await {
        match event {
            CanonStateNotification::Commit { new } => {
                process_chain_segment(&cache, &new);
            }
            CanonStateNotification::Reorg { old, new } => {
                let fork_block = old.first().number().saturating_sub(1);
                cache.rollback_after(fork_block + 1);
                process_chain_segment(&cache, &new);
            }
        }
    }

    Err("Canonical state stream ended unexpectedly".into())
}

/// Scans blocks `[start, latest]` using the provider and populates the cache.
///
/// This is an async function that yields to the tokio runtime every 1000 blocks
/// to avoid blocking a worker thread for extended periods on large chains.
async fn scan_historical_blocks<P>(cache: &TokenEventCache, provider: &P) -> Result<(), String>
where
    P: BlockReader + HeaderProvider + ReceiptProvider + BlockNumReader,
{
    let latest = provider
        .best_block_number()
        .map_err(|e| format!("best_block_number: {e}"))?;

    let (_, last_cached) = cache.snapshot_tokens();
    let start = last_cached.map(|b| b + 1).unwrap_or(0);

    if start > latest {
        info!(target: "token_indexer", "Cache already up to date (block {latest})");
        return Ok(());
    }

    info!(target: "token_indexer", start, latest, "Starting historical scan");

    for block_num in start..=latest {
        if block_num % 100_000 == 0 && block_num > 0 {
            info!(target: "token_indexer", block_num, latest, "Scanning progress");
        }

        let receipts = provider
            .receipts_by_block(block_num.into())
            .map_err(|e| format!("receipts_by_block({block_num}): {e}"))?;

        let Some(receipts) = receipts else {
            cache.mark_indexed(block_num);
            continue;
        };

        let header = provider
            .header_by_number(block_num)
            .map_err(|e| format!("header_by_number({block_num}): {e}"))?;
        let timestamp = header.map(|h| h.timestamp()).unwrap_or(0);

        let block = provider
            .block_by_number(block_num)
            .map_err(|e| format!("block_by_number({block_num}): {e}"))?;

        let tx_hashes: Vec<_> = block
            .as_ref()
            .map(|b| {
                b.body()
                    .transactions()
                    .iter()
                    .map(|tx| *tx.tx_hash())
                    .collect()
            })
            .unwrap_or_default();

        cache.index_block(block_num, timestamp, &receipts, &tx_hashes);

        // Yield to the tokio runtime periodically to keep the event loop responsive
        if block_num % 1000 == 0 {
            tokio::task::yield_now().await;
        }
    }

    info!(target: "token_indexer", latest, "Historical scan complete");
    Ok(())
}

/// Processes a committed chain segment from a `CanonStateNotification`.
///
/// Uses block data directly from the chain segment (no provider I/O).
fn process_chain_segment(cache: &TokenEventCache, chain: &reth_provider::Chain<TempoPrimitives>) {
    let receipts = chain.execution_outcome().receipts();

    for (block_idx, block) in chain.blocks_iter().enumerate() {
        let block_number = block.header().number();
        let timestamp = block.header().timestamp();

        let tx_hashes: Vec<_> = block
            .body()
            .transactions()
            .map(|tx| *tx.tx_hash())
            .collect();

        if let Some(block_receipts) = receipts.get(block_idx) {
            cache.index_block(block_number, timestamp, block_receipts, &tx_hashes);
        } else {
            cache.mark_indexed(block_number);
        }
    }
}
