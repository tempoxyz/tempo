use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationParams<Filters, Sort = crate::rpc::dex::OrdersSort> {
    /// Cursor for pagination.
    ///
    /// The cursor format depends on the endpoint:
    /// - `dex_getOrders`: Order ID (u128 encoded as string)
    /// - `dex_getOrderbooks`: Book Key (B256 encoded as hex string)
    /// - `policy_getAddresses`: Address (hex string)
    ///
    /// Defaults to first entry based on the sort and filter configuration.
    /// Use the `nextCursor` in response to get the next set of results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,

    /// Determines which items should be yielded in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filters: Option<Filters>,

    /// Maximum number of items to return.
    ///
    /// Defaults to 10.
    /// Maximum is 100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,

    /// Determines the order of the items yielded in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort: Option<Sort>,
}

/// Generic sort configuration
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Sort {
    /// Field to sort by
    pub on: String,
    /// Sort direction
    pub order: SortOrder,
}

/// Sort order direction
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SortOrder {
    /// Ascending order
    Asc,
    /// Descending order
    #[default]
    Desc,
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

/// Result of pagination operation
pub struct PaginatedResult<T> {
    /// The page of items
    pub items: Vec<T>,
    /// Cursor for next page, None if no more results
    pub next_cursor: Option<String>,
}

/// Apply cursor-based pagination to a collection of items
pub fn paginate<T, C>(
    mut items: Vec<T>,
    cursor: Option<&String>,
    limit: Option<usize>,
    get_cursor_value: impl Fn(&T) -> C,
) -> Result<PaginatedResult<T>, String>
where
    C: std::str::FromStr + PartialOrd + std::fmt::Display,
    <C as std::str::FromStr>::Err: std::fmt::Display,
{
    // Find start index based on cursor
    let start_index = if let Some(cursor_str) = cursor {
        let cursor_value = cursor_str
            .parse::<C>()
            .map_err(|e| format!("Invalid cursor format: {e}"))?;

        // Find position after cursor
        items
            .iter()
            .position(|item| get_cursor_value(item) > cursor_value)
            .unwrap_or(items.len())
    } else {
        0
    };

    // Apply limit
    let limit = limit.unwrap_or(10).min(100);
    let end_index = (start_index + limit).min(items.len());

    // Slice to current page
    let page = items.drain(start_index..end_index).collect::<Vec<_>>();

    // Generate next cursor
    let next_cursor = if end_index < items.len() + end_index - start_index {
        page.last().map(|item| get_cursor_value(item).to_string())
    } else {
        None
    };

    Ok(PaginatedResult {
        items: page,
        next_cursor,
    })
}
