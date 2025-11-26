use serde::{Deserialize, Serialize};

/// Field sorting parameters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    /// A field the items are compared with.
    pub on: String,

    /// An ordering direction.
    pub order: SortOrder,
}

/// A sort order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SortOrder {
    Asc,
    #[default]
    Desc,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams<Filters> {
    /// Cursor for pagination.
    ///
    /// The cursor format depends on the endpoint:
    /// - `dex_getOrders`: Order ID (u128 encoded as string)
    /// - `dex_getOrderbooks`: Book Key (B256 encoded as hex string)
    ///
    /// Defaults to first entry based on the sort and filter configuration.
    /// Use the `nextCursor` in response to get the next set of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Determines which items should be yielded in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<Filters>,

    /// Maximum number of orders to return.
    ///
    /// Defaults to 10.
    /// Maximum is 100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Determines the order of the items yielded in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<Sort>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilterRange<T> {
    pub min: Option<T>,
    pub max: Option<T>,
}

impl<T: PartialOrd> FilterRange<T> {
    /// Checks if a value is within this range (inclusive)
    pub fn in_range(&self, value: T) -> bool {
        if self.min.as_ref().is_some_and(|min| &value < min) {
            return false;
        }

        if self.max.as_ref().is_some_and(|max| &value > max) {
            return false;
        }

        true
    }
}
