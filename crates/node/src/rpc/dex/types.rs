use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrdersParams {
    /// Cursor for pagination. Based on orderId.
    ///
    /// Defaults to first entry based on the sort and filter configuration.
    /// Use the `nextCursor` in response to get the next set of orders.
    pub cursor: Option<String>,

    /// Determines which items should be yielded in the response.
    pub filters: Option<OrdersFilters>,

    /// Maximum number of orders to return.
    ///
    /// Defaults to 10.
    /// Maximum is 100.
    pub limit: Option<usize>,

    /// Determines the order of the items yielded in the response.
    pub sort: Option<OrdersSort>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrdersSort {
    /// A field the items are compared with.
    pub on: String,

    /// An ordering direction.
    pub order: OrdersSortOrder,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrdersSortOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrdersFilters {
    /// Filter by specific base token
    pub base_token: Option<Address>,
    /// Created timestamp (seconds) in range
    pub created_at: Option<FilterRange<u64>>,
    /// Filter by order side (true=buy, false=sell)
    pub is_bid: Option<bool>,
    /// Filter flip orders
    pub is_flip: Option<bool>,
    /// Last filled timestamp (seconds) in range
    pub last_filled_at: Option<FilterRange<u64>>,
    /// Filter by maker address
    pub maker: Option<Address>,
    /// Filter by quote token
    pub quote_token: Option<Address>,
    /// Remaining amount in range
    pub remaining: Option<FilterRange<u128>>,
    /// Tick in range (from -2000 to 2000)
    pub tick: Option<FilterRange<i16>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterRange<T> {
    pub min: Option<T>,
    pub max: Option<T>,
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
    pub amount: B256,
    /// Address of the base token
    pub base_token: Address,
    /// Timestamp when order was created
    pub created_at: u64,
    /// Target tick to flip to when order is filled
    pub flip_tick: u64,
    /// Order side: true for buy (bid), false for sell (ask)
    pub is_bid: bool,
    /// Whether this is a flip order that auto-flips when filled
    pub is_flip: bool,
    /// Timestamp of most recent fill (null if never filled)
    pub last_filled_at: Option<u64>,
    /// Address of order maker
    pub maker: Address,
    /// Next order ID in FIFO queue
    pub next: B256,
    /// Unique order ID
    pub order_id: B256,
    /// Address of the quote token
    pub quote_token: Address,
    /// Previous order ID in FIFO queue
    pub prev: B256,
    /// Remaining amount to fill
    pub remaining: B256,
    /// Price tick
    pub tick: u64,
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
}
