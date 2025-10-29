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

/// Represents an order along with its orderbook context.
/// Used when iterating through multiple orderbooks to maintain
/// the relationship between orders and their parent book.
struct OrderWithBook {
    /// The order from the orderbook
    order: PrecompileOrder,
    /// Base token address of the orderbook containing this order
    base: Address,
    /// Quote token address of the orderbook containing this order
    quote: Address,
}

/// Determines which book keys to query based on base and quote token filters.
///
/// Returns:
/// - A single book key if both base and quote tokens are specified
/// - All book keys from the exchange if filters are partial or absent
fn get_filtered_book_keys(
    exchange: &mut StablecoinExchange<'_, EvmPrecompileStorageProvider<'_>>,
    base_token: Option<Address>,
    quote_token: Option<Address>,
) -> Result<Vec<B256>, String> {
    match (base_token, quote_token) {
        (Some(base), Some(quote)) => Ok(vec![compute_book_key(base, quote)]),
        _ => exchange
            .get_book_keys()
            .map_err(|e| format!("Failed to get book keys: {e}")),
    }
}

/// An iterator over orders for a specific orderbook
pub struct BookIterator<'a, 'b> {
    /// Optional filter to apply to orders
    filter: Option<OrdersFilters>,
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
    orderbook: &'b PrecompileOrderbook,
    /// Inner precompile storage
    storage: &'b mut EvmPrecompileStorageProvider<'a>,
}

impl<'a, 'b> BookIterator<'a, 'b> {
    /// Create a new book iterator, optionally with the given order ID as the starting order.
    fn new(
        storage: &'b mut EvmPrecompileStorageProvider<'a>,
        orderbook: &'b PrecompileOrderbook,
        exchange_address: Address,
        bids: bool,
        starting_order: Option<u128>,
        filter: Option<OrdersFilters>,
    ) -> Self {
        let book_key = compute_book_key(orderbook.base, orderbook.quote);
        Self {
            filter,
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

    /// Find the next order in the orderbook, starting from current position.
    /// Returns the order ID of the next order, or None if no more orders.
    fn find_next_order(&mut self) -> Option<u128> {
        // If we have a starting order, use that to initialize
        if let Some(starting_order) = self.starting_order.take() {
            return Some(starting_order);
        }

        // If there is no current order we get the first one based on the best bid or ask tick
        let Some(current_id) = self.order else {
            let tick = if self.bids {
                self.orderbook.best_bid_tick
            } else {
                self.orderbook.best_ask_tick
            };

            let price_level = self.get_price_level(tick);

            // if the best bid level is empty then there are no more bids and we should stop the
            // iteration
            if price_level.is_empty() {
                return None;
            }

            return Some(price_level.head);
        };

        let current_order = self.get_order(current_id);

        // Now get the order after this one.
        if current_order.next() != 0 {
            Some(current_order.next())
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
            Some(price_level.head)
        }
    }
}

impl<'a, 'b> Iterator for BookIterator<'a, 'b> {
    type Item = PrecompileOrder;

    fn next(&mut self) -> Option<Self::Item> {
        // keep searching until we find an order that matches the filter
        while let Some(order_id) = self.find_next_order() {
            let order = self.get_order(order_id);

            // update current position
            self.order = Some(order_id);

            // check if order passes filter
            if let Some(ref filter) = self.filter {
                if order_matches_filter(&order, filter) {
                    return Some(order);
                }
            } else {
                // no filter, return the order
                return Some(order);
            }
        }

        None
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
                let exchange_address = exchange.address();

                // Determine which books to iterate based on filter
                let base_token = params.filters.as_ref().and_then(|f| f.base_token);
                let quote_token = params.filters.as_ref().and_then(|f| f.quote_token);
                let book_keys = get_filtered_book_keys(&mut exchange, base_token, quote_token)?;

                let is_bid = params
                    .filters
                    .as_ref()
                    .is_none_or(|f| f.is_bid.unwrap_or(false));

                let cursor = params
                    .cursor
                    .map(|cursor| parse_order_cursor(&cursor))
                    .transpose()
                    .expect("TODO: errors");

                let limit = params
                    .limit
                    .map(|l| l.min(MAX_LIMIT))
                    .unwrap_or(DEFAULT_LIMIT);

                let mut all_orders: Vec<OrderWithBook> = Vec::new();
                let mut next_cursor = None;

                // Iterate through books collecting orders until we reach the limit
                for book_key in book_keys {
                    let orderbook =
                        PrecompileOrderbook::from_storage(book_key, storage, exchange_address)
                            .expect("TODO: errors");

                    // Check if this book matches the base/quote filter
                    if let Some(ref filter) = params.filters {
                        if filter.base_token.is_some_and(|base| base != orderbook.base) {
                            continue;
                        }
                        if filter
                            .quote_token
                            .is_some_and(|quote| quote != orderbook.quote)
                        {
                            continue;
                        }
                    }

                    let starting_order = if all_orders.is_empty() {
                        cursor // Use cursor only for the first book
                    } else {
                        None
                    };

                    let book_iterator = BookIterator::new(
                        storage,
                        &orderbook,
                        exchange_address,
                        is_bid,
                        starting_order,
                        params.filters.clone(),
                    );

                    let base = orderbook.base;
                    let quote = orderbook.quote;

                    // Collect orders from this book
                    for order in book_iterator {
                        all_orders.push(OrderWithBook { order, base, quote });

                        // Check if we've reached the limit + 1
                        if all_orders.len() > limit {
                            // Use the last order for cursor
                            let last = &all_orders[limit];
                            next_cursor = Some(format!("0x{:x}", last.order.order_id()));
                            break;
                        }
                    }

                    // If we have enough orders, stop iterating through books
                    if all_orders.len() > limit {
                        break;
                    }
                }

                // Truncate to limit
                all_orders.truncate(limit);

                // Convert orders to RPC format - create temp orderbook for conversion
                let orders = all_orders
                    .into_iter()
                    .map(|item| {
                        // Create a minimal orderbook for conversion
                        let book = PrecompileOrderbook {
                            base: item.base,
                            quote: item.quote,
                            best_bid_tick: 0, // Not used in to_rpc_order
                            best_ask_tick: 0, // Not used in to_rpc_order
                        };
                        self.to_rpc_order(item.order, &book)
                    })
                    .collect();

                let response = OrdersResponse {
                    next_cursor,
                    orders,
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
        let (items, next_cursor) = self
            .apply_pagination_to_orderbooks(params)
            .map_err(|e| internal_rpc_err(format!("Failed to get orderbooks: {e}")))?;

        // Convert PrecompileOrderbooks to RPC Orderbooks
        let orderbooks = items
            .into_iter()
            .map(|book| self.to_rpc_orderbook(&book))
            .collect();

        // Create response with next cursor
        Ok(OrderbooksResponse {
            next_cursor,
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
    /// Returns orderbooks and optional next cursor.
    pub fn apply_pagination_to_orderbooks(
        &self,
        params: PaginationParams<OrderbooksFilter>,
    ) -> Result<(Vec<PrecompileOrderbook>, Option<String>), String> {
        self.with_exchange_at_block(BlockNumberOrTag::Latest.into(), |exchange| {
            let base_token = params.filters.as_ref().and_then(|f| f.base_token);
            let quote_token = params.filters.as_ref().and_then(|f| f.quote_token);
            let keys = get_filtered_book_keys(exchange, base_token, quote_token)?;

            // Find starting position based on cursor
            let start_idx = if let Some(ref cursor_str) = params.cursor {
                let cursor_key = parse_orderbook_cursor(cursor_str)?;

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
                orderbooks
                    .get(limit)
                    .map(|book| format!("0x{}", compute_book_key(book.base, book.quote)))
            } else {
                None
            };

            // Return only up to limit items
            let items = orderbooks.into_iter().take(limit).collect();

            Ok((items, next_cursor))
        })
    }

    /// Converts a precompile order to a rpc order.
    ///
    /// Uses the orderbook to determine base and quote token.
    fn to_rpc_order(&self, order: PrecompileOrder, book: &PrecompileOrderbook) -> Order {
        let PrecompileOrder {
            order_id,
            maker,
            book_key: _,
            is_bid,
            tick,
            amount,
            remaining,
            prev,
            next,
            is_flip,
            flip_tick,
        } = order;

        Order {
            amount,
            base_token: book.base,
            flip_tick,
            is_bid,
            is_flip,
            maker,
            next,
            order_id,
            quote_token: book.quote,
            prev,
            remaining,
            tick,
        }
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

/// Checks if an order matches the given filters
fn order_matches_filter(order: &PrecompileOrder, filter: &OrdersFilters) -> bool {
    // Note: base_token and quote_token filtering is handled at the book level,
    // not at the individual order level

    // Check bid/ask side filter
    if filter.is_bid.is_some_and(|is_bid| is_bid != order.is_bid) {
        return false;
    }

    // Check flip filter
    if filter
        .is_flip
        .is_some_and(|is_flip| is_flip != order.is_flip)
    {
        return false;
    }

    // Check maker filter
    if filter.maker.is_some_and(|maker| maker != order.maker) {
        return false;
    }

    // Check remaining amount range
    if filter
        .remaining
        .as_ref()
        .is_some_and(|remaining_range| !remaining_range.in_range(order.remaining))
    {
        return false;
    }

    // Check tick range
    if filter
        .tick
        .as_ref()
        .is_some_and(|tick_range| !tick_range.in_range(order.tick))
    {
        return false;
    }

    true
}

/// Parses a cursor string into a u128 for orders
fn parse_order_cursor(cursor: &str) -> Result<u128, String> {
    // TODO: just make this better, there must be a util for this that we have already in alloy or
    // ruint or something
    if let Some(hex_val) = cursor.strip_prefix("0x") {
        u128::from_str_radix(hex_val, 16).map_err(|e| format!("Invalid cursor format: {e}"))
    } else {
        Err("Must be a hex string".to_string())
    }
}

/// Parses a cursor string into a B256 for orderbooks
fn parse_orderbook_cursor(cursor: &str) -> Result<B256, String> {
    cursor
        .parse::<B256>()
        .map_err(|e| format!("Invalid cursor format: {e}"))
}
