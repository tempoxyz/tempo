use crate::rpc::eth_ext::transactions::{Transaction, TransactionsResponse};
use alloy::consensus::Typed2718;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_primitives_traits::{AlloyBlockHeader, NodePrimitives, Recovered};
use reth_provider::{BlockNumReader, BlockReader, HeaderProvider, TransactionVariant};
use reth_rpc_eth_api::RpcNodeCore;
use tempo_alloy::rpc::pagination::{PaginationParams, SortOrder};
use tempo_primitives::TempoTxEnvelope;

pub mod transactions;
pub use transactions::TransactionsFilter;

/// Maximum number of blocks to scan per RPC call.
/// Prevents unbounded chain traversal when filters match no transactions.
/// Clients can continue scanning via the returned cursor.
const MAX_SCAN_BLOCKS: u64 = 10_000;

#[rpc(server, namespace = "eth")]
pub trait TempoEthExtApi {
    /// Gets paginated transactions on Tempo with flexible filtering and sorting.
    ///
    /// Uses cursor-based pagination for stable iteration through transactions.
    #[method(name = "getTransactions")]
    async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse>;
}

/// The JSON-RPC handlers for the `dex_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoEthExt<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoEthExt<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

/// Parses a cursor string of the form "block_number:tx_index".
fn parse_tx_cursor(cursor: &str) -> Result<(u64, usize), jsonrpsee::types::ErrorObject<'static>> {
    let parts: Vec<&str> = cursor.split(':').collect();
    if parts.len() != 2 {
        return Err(internal_rpc_err(
            "invalid cursor format, expected 'block_number:tx_index'",
        ));
    }
    let block_number = parts[0]
        .parse::<u64>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad block_number"))?;
    let tx_index = parts[1]
        .parse::<usize>()
        .map_err(|_| internal_rpc_err("invalid cursor: bad tx_index"))?;
    Ok((block_number, tx_index))
}

/// Resolves pagination limit, default 10, max 100.
fn resolve_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(10).min(100)
}

#[async_trait::async_trait]
impl<EthApi> TempoEthExtApiServer for TempoEthExt<EthApi>
where
    EthApi: RpcNodeCore + Send + Sync + 'static,
    EthApi::Provider: BlockReader + HeaderProvider + BlockNumReader,
    EthApi::Primitives: NodePrimitives<SignedTx = TempoTxEnvelope>,
{
    async fn transactions(
        &self,
        params: PaginationParams<TransactionsFilter>,
    ) -> RpcResult<TransactionsResponse> {
        use alloy::consensus::Transaction as TxTrait;

        let provider = self.provider();
        let limit = resolve_limit(params.limit);
        let filters = params.filters.unwrap_or_default();

        let latest = provider
            .best_block_number()
            .map_err(|e| internal_rpc_err(e.to_string()))?;

        let desc = params
            .sort
            .as_ref()
            .map(|s| matches!(s.order, SortOrder::Desc))
            .unwrap_or(true);

        let (cursor_block, cursor_tx_idx) = match params.cursor {
            Some(ref c) => {
                let (b, t) = parse_tx_cursor(c)?;
                (Some(b), Some(t))
            }
            None => (None, None),
        };

        let mut results: Vec<Transaction> = Vec::new();
        let mut next_cursor: Option<String> = None;

        // Macro-like closure to process a single block
        let mut process_block = |block_num: u64,
                                 start_tx: usize,
                                 end_tx_exclusive: usize,
                                 ascending: bool|
         -> Result<bool, jsonrpsee::types::ErrorObject<'static>> {
            let block = provider
                .recovered_block(block_num.into(), TransactionVariant::WithHash)
                .map_err(|e| internal_rpc_err(e.to_string()))?;

            let Some(block) = block else {
                return Ok(false);
            };

            let block_hash = block.sealed_block().hash();
            let base_fee = block.header().base_fee_per_gas().unwrap_or(0);

            let txs_with_senders: Vec<_> =
                block.clone_transactions_recovered().enumerate().collect();
            let tx_count = txs_with_senders.len();
            let end = end_tx_exclusive.min(tx_count);

            let indices: Vec<usize> = if ascending {
                (start_tx..end).collect()
            } else {
                (start_tx..end).rev().collect()
            };

            for tx_idx in indices {
                let (_, recovered_tx) = &txs_with_senders[tx_idx];

                // Apply filters
                if let Some(from_filter) = filters.from
                    && recovered_tx.signer() != from_filter
                {
                    continue;
                }
                if let Some(to_filter) = filters.to
                    && recovered_tx.to() != Some(to_filter)
                {
                    continue;
                }
                if let Some(type_filter) = filters.type_ {
                    let filter_type: u8 = type_filter.into();
                    if recovered_tx.ty() != filter_type {
                        continue;
                    }
                }

                if results.len() >= limit {
                    next_cursor = Some(format!("{block_num}:{tx_idx}"));
                    return Ok(true);
                }

                let rpc_tx = Transaction {
                    inner: Recovered::new_unchecked(
                        recovered_tx.inner().clone(),
                        recovered_tx.signer(),
                    ),
                    block_hash: Some(block_hash),
                    block_number: Some(block_num),
                    transaction_index: Some(tx_idx as u64),
                    effective_gas_price: Some(base_fee as u128),
                };

                results.push(rpc_tx);
            }

            Ok(false)
        };

        if desc {
            let start_block = cursor_block.unwrap_or(latest);
            let scan_floor = start_block.saturating_sub(MAX_SCAN_BLOCKS - 1);

            for block_num in (scan_floor..=start_block).rev() {
                let tx_count_hint = 1000; // Upper bound, actual count is checked inside
                let end_tx = if cursor_block == Some(block_num) {
                    cursor_tx_idx.map(|i| i + 1).unwrap_or(tx_count_hint)
                } else {
                    tx_count_hint
                };

                if process_block(block_num, 0, end_tx, false)? {
                    break;
                }
            }

            // Scan window exhausted but limit not reached — set continuation cursor
            if next_cursor.is_none() && scan_floor > 0 {
                next_cursor = Some(format!("{}:{}", scan_floor - 1, usize::MAX));
            }
        } else {
            let start_block = cursor_block.unwrap_or(0);
            let scan_ceiling = start_block.saturating_add(MAX_SCAN_BLOCKS - 1).min(latest);

            for block_num in start_block..=scan_ceiling {
                let start_tx = if cursor_block == Some(block_num) {
                    cursor_tx_idx.unwrap_or(0)
                } else {
                    0
                };

                if process_block(block_num, start_tx, usize::MAX, true)? {
                    break;
                }
            }

            // Scan window exhausted but limit not reached — set continuation cursor
            if next_cursor.is_none() && scan_ceiling < latest {
                next_cursor = Some(format!("{}:0", scan_ceiling + 1));
            }
        }

        Ok(TransactionsResponse {
            next_cursor,
            transactions: results,
        })
    }
}

impl<EthApi: RpcNodeCore> TempoEthExt<EthApi> {
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }
}
