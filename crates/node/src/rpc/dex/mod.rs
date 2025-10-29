use alloy_eips::{BlockId, BlockNumberOrTag};
pub use books::{Orderbook, OrderbooksFilter, OrderbooksParam, OrderbooksResponse};
use reth_ethereum::evm::revm::database::StateProviderDatabase;
use reth_evm::{EvmInternals, revm::database::CacheDB};
use reth_provider::{BlockReaderIdExt, StateProviderFactory};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::TempoHeader;
pub use types::{
    FilterRange, Order, OrdersFilters, OrdersResponse, OrdersSort, OrdersSortOrder,
    PaginationParams, Tick,
};

use alloy_primitives::{Address, Sealable};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_api::{ConfigureEvm, NodePrimitives};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

use tempo_precompiles::{
    stablecoin_exchange::{
        Orderbook as PrecompileOrderbook, StablecoinExchange, orderbook::compute_book_key,
    },
    storage::evm::EvmPrecompileStorageProvider,
};

mod books;
pub mod types;

#[rpc(server, namespace = "dex")]
pub trait TempoDexApi {
    #[method(name = "getOrders")]
    async fn orders(&self, params: PaginationParams<OrdersFilters>) -> RpcResult<OrdersResponse>;

    #[method(name = "getOrderbooks")]
    async fn orderbooks(
        &self,
        params: PaginationParams<OrderbooksFilter>,
    ) -> RpcResult<OrderbooksResponse>;
}

/// The JSON-RPC handlers for the `dex_` namespace.
#[derive(Debug, Clone, Default)]
pub struct TempoDex<EthApi> {
    eth_api: EthApi,
}

impl<EthApi> TempoDex<EthApi> {
    pub fn new(eth_api: EthApi) -> Self {
        Self { eth_api }
    }
}

#[async_trait::async_trait]
impl<
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>,
> TempoDexApiServer for TempoDex<EthApi>
{
    async fn orders(&self, _params: PaginationParams<OrdersFilters>) -> RpcResult<OrdersResponse> {
        Err(internal_rpc_err("unimplemented"))
    }

    async fn orderbooks(
        &self,
        _params: PaginationParams<OrderbooksFilter>,
    ) -> RpcResult<OrderbooksResponse> {
        Err(internal_rpc_err("unimplemented"))
    }
}

impl<
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>,
> TempoDex<EthApi>
{
    /// Access the underlying provider.
    pub fn provider(&self) -> &EthApi::Provider {
        self.eth_api.provider()
    }

    /// Creates an `EvmPrecompileStorageProvider` at the given block.
    /// This handles the boilerplate of creating the EVM context and state provider.
    fn with_storage_at_block<F, R>(&self, at: BlockId, f: F) -> Result<R, String>
    where
        F: FnOnce(&mut EvmPrecompileStorageProvider<'_>) -> Result<R, String>,
    {
        // Get the header for the specified block
        let provider = self.eth_api.provider();
        let header = provider
            .header_by_id(at)
            .map_err(|e| format!("Failed to get header: {e}"))?
            .ok_or_else(|| "Header not found".to_string())?;

        let block_hash = header.hash_slow();
        let state_provider = provider
            .state_by_block_hash(block_hash)
            .map_err(|e| format!("Failed to get state provider: {e}"))?;

        // Create EVM using state provider db
        let db = CacheDB::new(StateProviderDatabase::new(state_provider));
        let mut evm = self
            .eth_api
            .evm_config()
            .evm_for_block(db, &header)
            .map_err(|e| format!("Failed to create EVM: {e}"))?;

        let ctx = evm.ctx_mut();
        let internals = EvmInternals::new(&mut ctx.journaled_state, &ctx.block);
        let mut storage = EvmPrecompileStorageProvider::new(internals, ctx.cfg.chain_id);

        f(&mut storage)
    }

    /// Creates a `StablecoinExchange` instance at the given block.
    /// This builds on `with_storage_at_block` to provide the exchange.
    fn with_exchange_at_block<F, R>(&self, at: BlockId, f: F) -> Result<R, String>
    where
        F: FnOnce(
            &mut StablecoinExchange<'_, EvmPrecompileStorageProvider<'_>>,
        ) -> Result<R, String>,
    {
        self.with_storage_at_block(at, |storage| {
            let mut exchange = StablecoinExchange::new(storage);
            f(&mut exchange)
        })
    }

    /// Converts a precompile orderbook to RPC orderbook format
    fn to_rpc_orderbook(&self, book: &PrecompileOrderbook) -> Orderbook {
        let book_key = compute_book_key(book.base, book.quote);
        let spread = if book.best_ask_tick != i16::MAX && book.best_bid_tick != i16::MIN {
            book.best_ask_tick - book.best_bid_tick
        } else {
            0
        };

        Orderbook {
            base_token: book.base,
            quote_token: book.quote,
            book_key,
            best_ask_tick: book.best_ask_tick,
            best_bid_tick: book.best_bid_tick,
            spread,
        }
    }

    /// Returns the orderbooks that should be filtered based on the filter params.
    pub fn pick_orderbooks(&self, filter: OrderbooksFilter) -> Vec<PrecompileOrderbook> {
        // If both base and quote are specified, get just that specific orderbook
        if let (Some(base), Some(quote)) = (filter.base_token, filter.quote_token) {
            return vec![self.get_orderbook(base, quote)];
        }

        // Get all orderbooks and filter them
        let all_books = self.get_all_books();

        all_books
            .into_iter()
            .filter(|book| {
                // Filter by base token if specified
                if let Some(base) = filter.base_token {
                    if book.base != base {
                        return false;
                    }
                }

                // Filter by quote token if specified
                if let Some(quote) = filter.quote_token {
                    if book.quote != quote {
                        return false;
                    }
                }

                // Filter by best ask tick range
                if let Some(ref ask_range) = filter.best_ask_tick {
                    // Only filter if the book has a valid ask (not i16::MAX)
                    if book.best_ask_tick != i16::MAX && !ask_range.in_range(book.best_ask_tick) {
                        return false;
                    }
                }

                // Filter by best bid tick range
                if let Some(ref bid_range) = filter.best_bid_tick {
                    // Only filter if the book has a valid bid (not i16::MIN)
                    if book.best_bid_tick != i16::MIN && !bid_range.in_range(book.best_bid_tick) {
                        return false;
                    }
                }

                // Filter by spread range
                if let Some(ref spread_range) = filter.spread {
                    // Calculate spread only if both ticks are valid
                    if book.best_ask_tick != i16::MAX && book.best_bid_tick != i16::MIN {
                        let spread = book.best_ask_tick - book.best_bid_tick;
                        if !spread_range.in_range(spread) {
                            return false;
                        }
                    }
                }

                true
            })
            .collect()
    }

    /// Returns all orderbooks.
    pub fn get_all_books(&self) -> Vec<PrecompileOrderbook> {
        self.with_exchange_at_block(BlockNumberOrTag::Latest.into(), |exchange| {
            let mut books = Vec::new();
            for book_key in exchange
                .get_book_keys()
                .map_err(|e| format!("Failed to get book keys: {e}"))?
            {
                let book = exchange
                    .books(book_key)
                    .map_err(|e| format!("Failed to get book: {e}"))?;
                books.push(book);
            }
            Ok(books)
        })
        .expect("TODO: remove")
    }

    /// Returns an orderbook based on the base and quote tokens.
    pub fn get_orderbook(&self, base: Address, quote: Address) -> PrecompileOrderbook {
        self.with_exchange_at_block(BlockNumberOrTag::Latest.into(), |exchange| {
            let book_key = compute_book_key(base, quote);
            exchange
                .books(book_key)
                .map_err(|e| format!("Failed to get orderbook: {e}"))
        })
        .expect("TODO: remove")
    }
}
