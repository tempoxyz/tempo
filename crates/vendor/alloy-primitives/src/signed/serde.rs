use super::Signed;
use alloc::string::String;
use core::{fmt, str};
use ruint::Uint;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};

impl<const BITS: usize, const LIMBS: usize> Serialize for Signed<BITS, LIMBS> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            self.into_raw().serialize(serializer)
        }
    }
}

impl<'de, const BITS: usize, const LIMBS: usize> Deserialize<'de> for Signed<BITS, LIMBS> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserialize(deserializer)
    }
}

fn deserialize<'de, const BITS: usize, const LIMBS: usize, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Signed<BITS, LIMBS>, D::Error> {
    struct SignedVisitor<const BITS: usize, const LIMBS: usize>;

    impl<const BITS: usize, const LIMBS: usize> Visitor<'_> for SignedVisitor<BITS, LIMBS> {
        type Value = Signed<BITS, LIMBS>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "a {BITS} bit signed integer")
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Signed::try_from(v).map_err(de::Error::custom)
        }

        fn visit_u128<E: de::Error>(self, v: u128) -> Result<Self::Value, E> {
            Signed::try_from(v).map_err(de::Error::custom)
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Signed::try_from(v).map_err(de::Error::custom)
        }

        fn visit_i128<E: de::Error>(self, v: i128) -> Result<Self::Value, E> {
            Signed::try_from(v).map_err(de::Error::custom)
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse().map_err(serde::de::Error::custom)
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }
    }

    if deserializer.is_human_readable() {
        deserializer.deserialize_any(SignedVisitor)
    } else {
        Uint::<BITS, LIMBS>::deserialize(deserializer).map(Signed::from_raw)
    }
}

#[cfg(test)]
mod tests {
    use crate::I256;
    use core::str::FromStr;

    const TEST_VALS: [&str; 5] = [
        "12345681238128738123",
        "-1239373781294184527124318238",
        "99999999999999999999999999999999999999999999999999999999999",
        "57896044618658097711785492504343953926634992332820282019728792003956564819967",
        "-57896044618658097711785492504343953926634992332820282019728792003956564819968",
    ];

    #[test]
    fn serde_json_roundtrip() {
        for val in TEST_VALS {
            let signed = I256::from_str(val).unwrap();
            let ser = serde_json::to_string(&signed).unwrap();
            assert_eq!(serde_json::from_str::<I256>(&ser).unwrap(), signed);
            assert_eq!(serde_json::from_str::<I256>(&format!("\"{val}\"")).unwrap(), signed);
        }
    }

    #[test]
    fn serde_bincode_roundtrip() {
        for val in TEST_VALS {
            let signed = I256::from_str(val).unwrap();
            let ser = bincode::serialize(&signed).unwrap();
            assert!(ser.len() <= 64);
            assert_eq!(bincode::deserialize::<I256>(&ser).unwrap(), signed);
        }
    }
}
