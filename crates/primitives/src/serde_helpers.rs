//! Serde helpers for hand-written `Deserialize` impls.

use core::fmt;
use serde::{
    Deserializer,
    de::{MapAccess, Visitor},
    forward_to_deserialize_any,
};

/// A [`Deserializer`] that decodes a struct from a map only.
///
/// Derived struct impls also accept an array of the fields in order, which derived impls with a
/// `#[serde(flatten)]` field reject. Types that replace such a derive with a decode-only struct
/// decode it through this wrapper to keep rejecting arrays. Asking for a map also leaves the
/// entries in place when the type is flattened into another one: asking for a struct would remove
/// them from the entries that type's other flattened fields see.
#[derive(Debug)]
pub struct MapOnly<D>(pub D);

impl<'de, D: Deserializer<'de>> Deserializer<'de> for MapOnly<D> {
    type Error = D::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.0.deserialize_any(visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.0.deserialize_map(MapOnlyVisitor(visitor))
    }

    fn is_human_readable(&self) -> bool {
        self.0.is_human_readable()
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

/// A [`Visitor`] that passes only maps to the visitor it wraps.
///
/// Some formats ignore the map hint and visit a sequence, which a derived visitor accepts.
struct MapOnlyVisitor<V>(V);

impl<'de, V: Visitor<'de>> Visitor<'de> for MapOnlyVisitor<V> {
    type Value = V::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.expecting(formatter)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.0.visit_map(map)
    }
}

/// Helpers for testing hand-written impls against the derives they replace.
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use alloc::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    /// Values that are invalid for most fields, or valid only for some.
    const VALUES: &[&str] = &[
        "null",
        "0",
        "1",
        "-1",
        "1.5",
        "18446744073709551616",
        "true",
        "\"\"",
        "\"0x\"",
        "\"0x0\"",
        "\"0x01\"",
        "\"0xzz\"",
        "[]",
        "[0]",
        "[[]]",
        "{}",
        "{\"a\":1}",
    ];

    /// Keys no type here decodes.
    const UNKNOWN_KEYS: &[&str] = &["", "x", "Input", "DATA", "chainid"];

    /// Returns the JSON text of `object` after applying `edits`, each of which replaces, removes
    /// or duplicates one of its entries, or adds an entry under one of `keys` or an unknown key.
    pub fn mutate_object(
        object: &serde_json::Value,
        keys: &[&str],
        edits: &[(u8, u8, u8)],
    ) -> String {
        let mut entries: Vec<(String, String)> = object
            .as_object()
            .expect("mutated value must be an object")
            .iter()
            .map(|(key, value)| (key.clone(), value.to_string()))
            .collect();
        for &(op, a, b) in edits {
            let (a, b) = (usize::from(a), usize::from(b));
            let value = VALUES[b % VALUES.len()].to_string();
            match (op % 4, entries.len()) {
                (0, len) if len > 0 => entries[a % len].1 = value,
                (1, len) if len > 0 => {
                    entries.remove(a % len);
                }
                (2, len) if len > 0 => entries.push(entries[a % len].clone()),
                _ => {
                    let key = keys
                        .iter()
                        .chain(UNKNOWN_KEYS)
                        .nth(a % (keys.len() + UNKNOWN_KEYS.len()))
                        .expect("index is in range");
                    entries.push((key.to_string(), value));
                }
            }
        }
        let fields: Vec<String> = entries
            .iter()
            .map(|(key, value)| format!("{}:{value}", serde_json::Value::from(key.as_str())))
            .collect();
        format!("{{{}}}", fields.join(","))
    }

    /// Returns the message of `err` without its position. A derive with `#[serde(flatten)]`
    /// reports errors in buffered fields at the end of the object, so positions differ from
    /// impls that decode fields in place.
    pub fn without_position(err: &serde_json::Error) -> String {
        let message = err.to_string();
        message
            .split(" at line ")
            .next()
            .expect("split yields at least one part")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{
        Deserialize,
        de::value::{self, SeqDeserializer},
    };

    /// Has a derived visitor, which also accepts a sequence.
    #[derive(Debug, Deserialize)]
    struct Fields {}

    /// Formats that ignore the map hint, such as MessagePack, visit a sequence.
    #[test]
    fn map_only_rejects_sequence_without_map_hint() {
        let sequence = SeqDeserializer::<_, value::Error>::new(core::iter::empty::<()>());
        let err = Fields::deserialize(MapOnly(sequence)).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid type: sequence, expected struct Fields"
        );
    }
}
