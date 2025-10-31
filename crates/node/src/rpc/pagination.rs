use crate::rpc::dex::OrdersSort;
use jsonrpsee::core::Serialize;
use serde::{Deserialize, Serializer, ser::SerializeStruct};

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PaginationResponse<Item> {
    /// Cursor for next page, null if no more results
    pub next_cursor: Option<String>,
    /// Array of items matching the input query
    pub items: Vec<Item>,
}

/// A trait whose implementation determines a field name for [`PaginationResponse`] implementation
/// of [`Serialize`]r.
pub trait FieldName {
    /// Returns the camel case plural name for this field.
    ///
    /// For example a struct called `RoleChange` would likely return `"roleChanges"`.
    fn field_plural_camel_case() -> &'static str;
}

impl<Item: Serialize + FieldName> Serialize for PaginationResponse<Item> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut ser = serializer.serialize_struct("PaginationResponse", 2)?;
        ser.serialize_field("nextCursor", &self.next_cursor)?;
        ser.serialize_field(Item::field_plural_camel_case(), &self.items)?;
        ser.end()
    }
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
    pub sort: Option<OrdersSort>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct FakeItem {
        some_field: String,
    }

    impl FieldName for FakeItem {
        fn field_plural_camel_case() -> &'static str {
            "fakeItems"
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DifferentFakeItem {
        some_other_field: String,
    }

    impl FieldName for DifferentFakeItem {
        fn field_plural_camel_case() -> &'static str {
            "differentFakeItems"
        }
    }

    #[test_case::test_case(
        PaginationResponse {
            next_cursor: Some("foo".to_owned()),
            items: vec![FakeItem {
                some_field: "bar".to_owned(),
            }],
        },
        r#"{"nextCursor":"foo","fakeItems":[{"someField":"bar"}]}"#;
        "With next cursor and fake item"
    )]
    #[test_case::test_case(
        PaginationResponse {
            next_cursor: None,
            items: vec![FakeItem {
                some_field: "something".to_owned(),
            }],
        },
        r#"{"nextCursor":null,"fakeItems":[{"someField":"something"}]}"#;
        "Without next cursor and fake item"
    )]
    #[test_case::test_case(
        PaginationResponse {
            next_cursor: None,
            items: vec![DifferentFakeItem {
                some_other_field: "hey".to_owned(),
            }],
        },
        r#"{"nextCursor":null,"differentFakeItems":[{"someOtherField":"hey"}]}"#;
        "Without next cursor and different fake item"
    )]
    fn test_pagination_response_serializes_successfully(
        response: PaginationResponse<impl Serialize + FieldName>,
        expected_json: &str,
    ) {
        let actual_json = serde_json::to_string(&response).unwrap();

        assert_eq!(actual_json, expected_json);
    }
}
