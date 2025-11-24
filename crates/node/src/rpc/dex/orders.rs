use alloy::primitives::Address;
use serde::{Deserialize, Serialize};
use tempo_alloy::rpc::pagination::{FilterRange, PaginationParams};

pub type OrdersParams = PaginationParams<OrdersFilters>;
pub type Tick = i16;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrdersFilters {
    /// Filter by specific base token
    pub base_token: Option<Address>,
    /// Filter by order side (true=buy, false=sell)
    pub is_bid: Option<bool>,
    /// Filter flip orders
    pub is_flip: Option<bool>,
    /// Filter by maker address
    pub maker: Option<Address>,
    /// Filter by quote token
    pub quote_token: Option<Address>,
    /// Remaining amount in range
    pub remaining: Option<RemainingFilterRange>,
    /// Tick in range (from -2000 to 2000)
    pub tick: Option<FilterRange<Tick>>,
}

/// FilterRange type for u128, so that we can serialize the u128s as QUANTITY.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemainingFilterRange {
    #[serde(with = "alloy_serde::quantity::opt")]
    pub min: Option<u128>,
    #[serde(with = "alloy_serde::quantity::opt")]
    pub max: Option<u128>,
}

impl RemainingFilterRange {
    /// Checks if a value is within this range (inclusive)
    pub fn in_range(&self, value: u128) -> bool {
        if self.min.as_ref().is_some_and(|min| &value < min) {
            return false;
        }

        if self.max.as_ref().is_some_and(|max| &value > max) {
            return false;
        }

        true
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrdersResponse {
    pub next_cursor: Option<String>,
    pub orders: Vec<Order>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// Original order amount
    #[serde(with = "alloy_serde::quantity")]
    pub amount: u128,
    /// Target tick to flip to when order is filled
    pub flip_tick: i16,
    /// Order side: true for buy (bid), false for sell (ask)
    pub is_bid: bool,
    /// Whether this is a flip order that auto-flips when filled
    pub is_flip: bool,
    /// Address of order maker
    pub maker: Address,
    /// Next order ID in FIFO queue
    #[serde(with = "alloy_serde::quantity")]
    pub next: u128,
    /// Unique order ID
    #[serde(with = "alloy_serde::quantity")]
    pub order_id: u128,
    /// Previous order ID in FIFO queue
    #[serde(with = "alloy_serde::quantity")]
    pub prev: u128,
    /// Remaining amount to fill
    #[serde(with = "alloy_serde::quantity")]
    pub remaining: u128,
    /// Price tick
    pub tick: i16,
    /// Address of the base token
    pub base_token: Address,
    /// Address of the quote token
    pub quote_token: Address,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case::test_case(
        OrdersParams::default();
        "None filled"
    )]
    fn test_serialize_and_deserialize_is_identical(expected_params: OrdersParams) {
        let json = serde_json::to_string(&expected_params).unwrap();
        let actual_params: OrdersParams = serde_json::from_str(&json).unwrap();

        assert_eq!(actual_params, expected_params);
    }

    #[test_case::test_case(
        "{}";
        "None filled"
    )]
    fn test_deserialize_and_serialize_is_identical(expected_json: &str) {
        let params: OrdersParams = serde_json::from_str(expected_json).unwrap();
        let actual_json = serde_json::to_string(&params).unwrap();

        assert_eq!(actual_json, expected_json);
    }
}
