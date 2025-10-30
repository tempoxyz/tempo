use crate::rpc::dex::{
    FilterRange,
    types::{FieldName, Tick},
};
use alloy_primitives::{Address, B256};
use jsonrpsee::core::Serialize;
use serde::Deserialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Orderbook {
    /// Base token address
    pub base_token: Address,
    /// Orderbook key (keccak256 of base and quote tokens)
    pub book_key: B256,
    /// Best ask tick (lowest ask price)
    pub best_ask_tick: Tick,
    /// Best bid tick (highest bid price)
    pub best_bid_tick: Tick,
    /// Quote token address
    pub quote_token: Address,
    /// Spread in ticks (best_ask_tick - best_bid_tick)
    pub spread: Tick,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderbooksFilter {
    /// Filter by base token address
    pub base_token: Option<Address>,
    /// Best ask tick in range
    pub best_ask_tick: Option<FilterRange<Tick>>,
    /// Best bid tick in range
    pub best_bid_tick: Option<FilterRange<Tick>>,
    /// Filter by quote token address
    pub quote_token: Option<Address>,
    /// Spread in range (in ticks)
    pub spread: Option<FilterRange<Tick>>,
}

impl FieldName for Orderbook {
    fn field_plural_camel_case() -> &'static str {
        "orderbooks"
    }
}
