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

use alloy_primitives::{Address, B256, Sealable};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_node_api::{ConfigureEvm, NodePrimitives};
use reth_node_core::rpc::result::internal_rpc_err;
use reth_rpc_eth_api::RpcNodeCore;

use tempo_precompiles::{
    stablecoin_exchange::{
        Order as PrecompileOrder, Orderbook as PrecompileOrderbook, PriceLevel, StablecoinExchange,
        TickBitmap, orderbook::compute_book_key,
    },
    storage::evm::EvmPrecompileStorageProvider,
};

mod books;
pub mod types;

/// Default limit for pagination
const DEFAULT_LIMIT: usize = 10;

/// Maximum limit for pagination
const MAX_LIMIT: usize = 100;

/// Result of paginated query containing items and optional cursor for next page
// TODO: remove this, useless
pub struct PaginatedResult<T> {
    /// The items for this page
    pub items: Vec<T>,
    /// Cursor for the next page, if there are more items
    pub next_cursor: Option<String>,
}

/// Trait for items that can provide a cursor value for pagination
// TODO: remove this, useless
trait CursorProvider {
    /// Returns the cursor value for this item
    fn cursor_value(&self) -> String;
}

impl CursorProvider for PrecompileOrderbook {
    fn cursor_value(&self) -> String {
        // Use book key as cursor for orderbooks
        format!("0x{}", compute_book_key(self.base, self.quote))
    }
}

/// An iterator over orders for a specific orderbook
pub struct BookIterator<'a, 'b> {
    // TODO: add filter
    /// Whether or not to iterate over bids or asks.
    bids: bool,
    /// Book key
    book_key: B256,
    /// Address of the exchange
    exchange_address: Address,
    /// Starting order ID
    starting_order: Option<u128>,
    /// Current order ID
    order: Option<u128>,
    /// Orderbook information
    orderbook: PrecompileOrderbook,
    /// Inner precompile storage
    storage: &'b mut EvmPrecompileStorageProvider<'a>,
}

impl<'a, 'b> BookIterator<'a, 'b> {
    /// Create a new book iterator, optionally with the given order ID as the starting order.
    fn new(
        storage: &'b mut EvmPrecompileStorageProvider<'a>,
        orderbook: PrecompileOrderbook,
        exchange_address: Address,
        bids: bool,
        starting_order: Option<u128>,
    ) -> Self {
        let book_key = compute_book_key(orderbook.base, orderbook.quote);
        Self {
            book_key,
            exchange_address,
            order: None,
            starting_order,
            orderbook,
            storage,
            bids,
        }
    }

    /// Get a PrecompileOrder from an order ID
    pub fn get_order(&mut self, order_id: u128) -> PrecompileOrder {
        PrecompileOrder::from_storage(order_id, self.storage, self.exchange_address)
            .expect("TODO: errors")
    }

    /// Get a PriceLevel from a tick
    pub fn get_price_level(&mut self, tick: i16) -> PriceLevel {
        PriceLevel::from_storage(
            self.storage,
            self.exchange_address,
            self.book_key,
            tick,
            self.bids,
        )
        .expect("TODO: errors")
    }

    /// Get the next initialized tick after the given tick
    /// Returns None if there are no more ticks
    pub fn get_next_tick(&mut self, tick: i16) -> Option<i16> {
        let mut bitmap = TickBitmap::new(self.storage, self.exchange_address, self.book_key);

        let (next_tick, more_ticks) = if self.bids {
            bitmap.next_initialized_bid_tick(tick)
        } else {
            bitmap.next_initialized_ask_tick(tick)
        };

        if more_ticks { Some(next_tick) } else { None }
    }
}

impl<'a, 'b> Iterator for BookIterator<'a, 'b> {
    type Item = PrecompileOrder;

    fn next(&mut self) -> Option<Self::Item> {
        // If we have a starting order, use that to initialize
        if let Some(starting_order) = self.starting_order.take() {
            let current_order = self.get_order(starting_order);
            return Some(current_order);
        };

        // If there is no current order we get the first one based on the best bid or ask tick
        let current_id = match &self.order {
            Some(order) => *order,
            None => {
                let tick = if self.bids {
                    self.orderbook.best_bid_tick
                } else {
                    self.orderbook.best_ask_tick
                };

                let price_level = self.get_price_level(tick);

                // if the best bid level is empty then there are no more bids and we should stop the
                // iteration
                // TODO: double check this
                if price_level.is_empty() {
                    return None;
                }

                price_level.head
            }
        };

        let current_order = self.get_order(current_id);

        // Now get the order after this one.
        let next_order = if current_order.next() != 0 {
            current_order.next()
        } else {
            let tick = current_order.tick();

            // find the next tick
            let next_tick = self.get_next_tick(tick)?;

            // get the price level for this tick so we can get the head of the price level
            let price_level = self.get_price_level(next_tick);
            if price_level.is_empty() {
                return None;
            }

            // return the head of the price level as the next order
            price_level.head
        };

        // set the current order
        self.order = Some(next_order);

        // return the order
        Some(self.get_order(next_order))
    }
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

#[async_trait::async_trait]
impl<
    EthApi: RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>,
> TempoDexApiServer for TempoDex<EthApi>
{
    /// Returns orders based on pagination parameters.
    ///
    /// ## Cursor
    /// The cursor for this method is the **Order ID** (u128).
    /// - When provided in the request, returns orders starting after the given order ID
    /// - Returns `next_cursor` in the response containing the last order ID for the next page
    async fn orders(&self, params: PaginationParams<OrdersFilters>) -> RpcResult<OrdersResponse> {
        let response = self
            .with_storage_at_block(BlockNumberOrTag::Latest.into(), |storage| {
                let mut exchange = StablecoinExchange::new(storage);
                // TODO: filtering books by order filter
                let orderbook_id = exchange.get_book_keys().expect("TODO: errors")[0];
                let exchange_address = exchange.address();

                let orderbook =
                    PrecompileOrderbook::from_storage(orderbook_id, storage, exchange_address)
                        .expect("TODO: errors");

                let book_iterator =
                    BookIterator::new(storage, orderbook, exchange_address, true, None);
                // TODO: fix starting point bug in iterator so this works properly.
                // Right now it will return gaps because if we init the iterator with an order ID as
                // cursor then it will not return that as the first element.
                //
                // ideally we have a non-option current field, and an option init field in the
                // BookIterator
                let limit = 10;
                let orders = book_iterator.into_iter().take(limit).collect::<Vec<_>>();

                // since we ask for limit + 1, if we get limit elements then the iterator has ended and
                // we have nothing to set as the next cursor
                let next_cursor = if orders.len() == limit {
                    // NOTE: the len is greater than one
                    let last = orders.last().unwrap();
                    let next_id = last.next();
                    if next_id == 0 {
                        None
                    } else {
                        Some(format!("0x{next_id:x}"))
                    }
                } else {
                    None
                };

                let response = OrdersResponse {
                    next_cursor,
                    orders: vec![],
                };
                Ok(response)
            })
            .expect("TODO: proper errors");
        Ok(response)
    }

    /// Returns orderbooks based on pagination parameters.
    ///
    /// ## Cursor
    /// The cursor for this method is the **Book Key** (B256).
    /// - When provided in the request, returns orderbooks starting after the given book key
    /// - Returns `next_cursor` in the response containing the last book key for the next page
    async fn orderbooks(
        &self,
        params: PaginationParams<OrderbooksFilter>,
    ) -> RpcResult<OrderbooksResponse> {
        // Get paginated orderbooks
        let paginated_result = self
            .apply_pagination_to_orderbooks(params)
            .map_err(|e| internal_rpc_err(format!("Failed to get orderbooks: {e}")))?;

        // Convert PrecompileOrderbooks to RPC Orderbooks
        let orderbooks = paginated_result
            .items
            .into_iter()
            .map(|book| self.to_rpc_orderbook(&book))
            .collect();

        // Create response with next cursor
        Ok(OrderbooksResponse {
            next_cursor: paginated_result.next_cursor,
            orderbooks,
        })
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

    /// Parses a cursor string into a B256 for orderbooks
    fn parse_orderbook_cursor(cursor: &str) -> Result<B256, String> {
        cursor
            .parse::<B256>()
            .map_err(|e| format!("Invalid cursor format: {e}"))
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

    /// Applies pagination parameters (filtering, limiting) to orderbooks.
    ///
    /// Returns a paginated result with items and optional next cursor.
    pub fn apply_pagination_to_orderbooks(
        &self,
        params: PaginationParams<OrderbooksFilter>,
    ) -> Result<PaginatedResult<PrecompileOrderbook>, String> {
        self.with_exchange_at_block(BlockNumberOrTag::Latest.into(), |exchange| {
            let keys = if let Some(ref filter) = params.filters {
                // If specific base and quote are provided, we have just one key
                if let (Some(base), Some(quote)) = (filter.base_token, filter.quote_token) {
                    vec![compute_book_key(base, quote)]
                } else {
                    // Get all keys
                    exchange
                        .get_book_keys()
                        .map_err(|e| format!("Failed to get book keys: {e}"))?
                }
            } else {
                // Get all book keys
                exchange
                    .get_book_keys()
                    .map_err(|e| format!("Failed to get book keys: {e}"))?
            };

            // Find starting position based on cursor
            let start_idx = if let Some(ref cursor_str) = params.cursor {
                let cursor_key = Self::parse_orderbook_cursor(cursor_str)?;

                keys.iter()
                    .position(|k| *k == cursor_key)
                    .expect("TODO: error for when the user inputs a cursor that doesnt exist")
            } else {
                0
            };

            // Convert keys to orderbooks, starting from cursor position
            let mut orderbooks = Vec::new();
            let limit = params
                .limit
                .map(|l| l.min(MAX_LIMIT))
                .unwrap_or(DEFAULT_LIMIT);

            // Take limit + 1 to check if there's a next page
            for key in keys.into_iter().skip(start_idx).take(limit + 1) {
                let book = exchange
                    .books(key)
                    .map_err(|e| format!("Failed to get book: {e}"))?;

                // Apply filters if present
                if let Some(ref filter) = params.filters
                    && !orderbook_matches_filter(&book, filter)
                {
                    continue;
                }

                orderbooks.push(book);

                // Stop if we have enough items
                if orderbooks.len() > limit {
                    break;
                }
            }

            // Get the next page / cursor
            let has_next_page = orderbooks.len() > limit;
            let next_cursor = if has_next_page {
                // Use the last item's cursor as the next cursor
                orderbooks.get(limit).map(|book| book.cursor_value())
            } else {
                None
            };

            // Return only up to limit items
            let items = orderbooks.into_iter().take(limit).collect();

            Ok(PaginatedResult { items, next_cursor })
        })
    }

    /// Converts a precompile orderbook to RPC orderbook format.
    ///
    /// ## Cursor Field
    /// The `book_key` field in the returned Orderbook serves as the cursor
    /// for pagination when requesting subsequent pages.
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
            .filter(|book| orderbook_matches_filter(book, &filter))
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
    ///
    /// ## Note
    /// Single orderbook fetches don't require cursor pagination.
    /// This is used when filters specify both base and quote tokens.
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

/// Checks if an orderbook matches the given filters
fn orderbook_matches_filter(book: &PrecompileOrderbook, filter: &OrderbooksFilter) -> bool {
    // Check base token filter
    if filter.base_token.is_some_and(|base| base != book.base) {
        return false;
    }

    // Check quote token filter
    if filter.quote_token.is_some_and(|quote| quote != book.base) {
        return false;
    }

    // Check best ask tick range
    if let Some(ref ask_range) = filter.best_ask_tick {
        // Only filter if the book has a valid ask (not i16::MAX)
        if book.best_ask_tick != i16::MAX && !ask_range.in_range(book.best_ask_tick) {
            return false;
        }
    }

    // Check best bid tick range
    if let Some(ref bid_range) = filter.best_bid_tick {
        // Only filter if the book has a valid bid (not i16::MIN)
        if book.best_bid_tick != i16::MIN && !bid_range.in_range(book.best_bid_tick) {
            return false;
        }
    }

    // Check spread range
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
}
