use alloc::borrow::Cow;

use super::FixedBytes;
use ::schemars::*;

impl<const N: usize> JsonSchema for FixedBytes<N> {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("FixedBytes")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "hexadecimal string",
            "anyOf": [
                {
                    "type": "string",
                    "minLength": N * 2,
                    "maxLength": N * 2,
                    "pattern": "^[0-9a-fA-F]*$"
                },
                {
                    "type": "string",
                    "minLength": 2 + N * 2,
                    "maxLength": 2 + N * 2,
                    "pattern": "^0x[0-9a-fA-F]*$"
                },
            ]
        })
    }

    fn schema_id() -> Cow<'static, str> {
        Cow::Borrowed(concat!(module_path!(), "::FixedBytes"))
    }
}
