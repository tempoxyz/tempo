use crate::rpc::dex::{FilterRange, types::Tick};
use alloy_primitives::{Address, B256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderbooksParam {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderbooksResponse {
    /// Cursor for next page, null if no more results
    next_cursor: Option<String>,
    /// Orderbooks that match the query
    orderbooks: Vec<Orderbook>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Orderbook {
    /// Base token address
    base_token: Address,
    /// Orderbook key (keccak256 of base and quote tokens)
    book_key: B256,
    /// Best ask tick (lowest ask price)
    best_ask_tick: Tick,
    /// Best bid tick (highest bid price)
    best_bid_tick: Tick,
    /// Quote token address
    quote_token: Address,
    /// Spread in ticks (best_ask_tick - best_bid_tick)
    spread: Tick,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderbooksFilter {
    /// Filter by base token address
    base_token: Option<Address>,
    /// Best ask tick in range
    best_ask_tick: Option<FilterRange<Tick>>,
    /// Best bid tick in range
    best_bid_tick: Option<FilterRange<Tick>>,
    /// Filter by quote token address
    quote_token: Option<Address>,
    /// Spread in range (in ticks)
    spread: Option<FilterRange<Tick>>,
}
