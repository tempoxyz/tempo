//! Signed policy references and inline policy definitions.

use super::FundingSource;
use alloc::vec::Vec;
use alloy_primitives::Address;
use alloy_rlp::{Decodable, Encodable};
use core::num::NonZeroU64;
use tempo_contracts::precompiles::IFundingPolicy;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum FundingPolicyAuthorization {
    Id(#[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))] NonZeroU64),
    Inline(FundingPolicy),
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for FundingPolicyAuthorization {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            Ok(Self::Inline(u.arbitrary()?))
        } else {
            Ok(Self::Id(
                NonZeroU64::new(u.arbitrary::<u64>()?.max(1)).unwrap(),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct FundingPolicy {
    /// Accounts permitted to update the shared policy.
    pub admins: Vec<Address>,
    pub rules: FundingPolicyRules,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(rename_all = "camelCase", deny_unknown_fields)
)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct FundingPolicyRules {
    /// Maximum aggregate tolerance in basis points.
    pub max_slippage_bps: u16,
    /// Output routes in ascending token order; source order is significant.
    #[cfg_attr(feature = "serde", serde(rename = "sources", with = "routes_by_token"))]
    pub routes: Vec<FundingPolicyRoute>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct FundingPolicyRoute {
    pub token: Address,
    pub sources: Vec<FundingSource>,
}

impl FundingPolicyAuthorization {
    pub fn heap_size(&self) -> usize {
        match self {
            Self::Id(_) => 0,
            Self::Inline(policy) => {
                policy.admins.capacity() * size_of::<Address>()
                    + policy.rules.routes.capacity() * size_of::<FundingPolicyRoute>()
                    + policy
                        .rules
                        .routes
                        .iter()
                        .map(|route| {
                            route.sources.capacity() * size_of::<FundingSource>()
                                + route
                                    .sources
                                    .iter()
                                    .map(|source| source.data.len())
                                    .sum::<usize>()
                        })
                        .sum::<usize>()
            }
        }
    }
}

impl From<FundingPolicyRules> for IFundingPolicy::Rules {
    fn from(policy: FundingPolicyRules) -> Self {
        Self {
            maxSlippageBps: policy.max_slippage_bps,
            routes: policy
                .routes
                .into_iter()
                .map(|route| IFundingPolicy::Route {
                    token: route.token,
                    sources: route
                        .sources
                        .into_iter()
                        .map(|source| IFundingPolicy::Source {
                            target: source.target,
                            data: source.data,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

impl Encodable for FundingPolicyAuthorization {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        match self {
            Self::Id(id) => id.encode(out),
            Self::Inline(policy) => policy.encode(out),
        }
    }

    fn length(&self) -> usize {
        match self {
            Self::Id(id) => id.length(),
            Self::Inline(policy) => policy.length(),
        }
    }
}

impl Decodable for FundingPolicyAuthorization {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        match buf.first() {
            Some(prefix) if *prefix >= 0xc0 => FundingPolicy::decode(buf).map(Self::Inline),
            _ => NonZeroU64::decode(buf).map(Self::Id),
        }
    }
}

#[cfg(feature = "serde")]
mod routes_by_token {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::fmt;
    use serde::{
        Deserializer, Serializer,
        de::{Error, MapAccess, Visitor},
        ser::SerializeMap,
    };

    pub(super) fn serialize<S: Serializer>(
        routes: &[FundingPolicyRoute],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(routes.len()))?;
        for route in routes {
            map.serialize_entry(&route.token, &route.sources)?;
        }
        map.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<FundingPolicyRoute>, D::Error> {
        struct Routes;
        impl<'de> Visitor<'de> for Routes {
            type Value = Vec<FundingPolicyRoute>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map of unique output tokens to ordered funding sources")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut routes = BTreeMap::<Address, Vec<FundingSource>>::new();
                while let Some((token, sources)) = map.next_entry()? {
                    if routes.insert(token, sources).is_some() {
                        return Err(M::Error::custom("duplicate funding policy token"));
                    }
                }
                Ok(routes
                    .into_iter()
                    .map(|(token, sources)| FundingPolicyRoute { token, sources })
                    .collect())
            }
        }
        deserializer.deserialize_map(Routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SignatureType, transaction::KeyAuthorization};
    use alloy_primitives::{Bytes, U256};

    fn inline() -> FundingPolicy {
        FundingPolicy {
            admins: vec![Address::repeat_byte(1)],
            rules: FundingPolicyRules {
                max_slippage_bps: 100,
                routes: vec![FundingPolicyRoute {
                    token: Address::repeat_byte(2),
                    sources: vec![FundingSource {
                        target: Address::repeat_byte(3),
                        data: Bytes::from_static(&[4]),
                    }],
                }],
            },
        }
    }

    #[test]
    fn policy_reference_has_canonical_trailing_encoding() {
        let legacy =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x11));
        let mut expected = vec![0xd7, 1, 0x80, 0x94];
        expected.extend([0x11; 20]);
        assert_eq!(alloy_rlp::encode(&legacy), expected);
        let auth =
            legacy.with_funding_policy(FundingPolicyAuthorization::Id(NonZeroU64::new(7).unwrap()));
        expected[0] = 0xde;
        expected.extend([0x80; 6]);
        expected.push(7);
        assert_eq!(alloy_rlp::encode(&auth), expected);
        assert_eq!(
            KeyAuthorization::decode(&mut expected.as_slice()).unwrap(),
            auth
        );
        assert!(!auth.is_legacy_compatible());
        assert!(FundingPolicyAuthorization::decode(&mut [0x80].as_slice()).is_err());
        assert!(FundingPolicyAuthorization::decode(&mut [0].as_slice()).is_err());
        assert!(
            FundingPolicyAuthorization::decode(
                &mut alloy_rlp::encode(U256::from(u64::MAX) + U256::ONE).as_slice()
            )
            .is_err()
        );
    }

    #[test]
    fn inline_encoding_and_all_signed_fields_are_bound() {
        let policy = inline();
        let auth =
            KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x11))
                .with_funding_policy(FundingPolicyAuthorization::Inline(policy.clone()));
        let encoded = alloy_rlp::encode(&auth);
        assert_eq!(
            KeyAuthorization::decode(&mut encoded.as_slice()).unwrap(),
            auth
        );
        let mutations: &[fn(&mut FundingPolicy)] = &[
            |p| p.admins.push(Address::repeat_byte(5)),
            |p| p.rules.max_slippage_bps = 0,
            |p| p.rules.routes[0].token = Address::repeat_byte(6),
            |p| p.rules.routes[0].sources[0].target = Address::repeat_byte(7),
            |p| p.rules.routes[0].sources[0].data = Bytes::from_static(&[8]),
            |p| p.rules.routes[0].sources.clear(),
            |p| p.rules.routes.clear(),
        ];
        for mutate in mutations {
            let mut changed = policy.clone();
            mutate(&mut changed);
            let changed = auth
                .clone()
                .with_funding_policy(FundingPolicyAuthorization::Inline(changed));
            assert_ne!(changed.signature_hash(), auth.signature_hash());
        }
        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(KeyAuthorization::decode(&mut truncated.as_slice()).is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn policy_json_uses_token_map_and_hex_ids() {
        let existing = FundingPolicyAuthorization::Id(NonZeroU64::new(u64::MAX).unwrap());
        assert_eq!(
            serde_json::to_string(&existing).unwrap(),
            "\"0xffffffffffffffff\""
        );
        assert_eq!(
            serde_json::from_str::<FundingPolicyAuthorization>("\"0xffffffffffffffff\"").unwrap(),
            existing
        );
        assert!(serde_json::from_str::<FundingPolicyAuthorization>("\"0x0\"").is_err());
        let policy = inline();
        let value =
            serde_json::to_value(FundingPolicyAuthorization::Inline(policy.clone())).unwrap();
        assert!(value["rules"].get("sources").unwrap().is_object());
        assert!(value["rules"].get("routes").is_none());
        assert_eq!(
            serde_json::from_value::<FundingPolicyAuthorization>(value).unwrap(),
            FundingPolicyAuthorization::Inline(policy)
        );
        let duplicate = r#"{"admins":[],"rules":{"maxSlippageBps":0,"sources":{"0x000000000000000000000000000000000000000a":[],"0x000000000000000000000000000000000000000A":[]}}}"#;
        assert!(serde_json::from_str::<FundingPolicyAuthorization>(duplicate).is_err());
        let ordered = r#"{"admins":[],"rules":{"maxSlippageBps":0,"sources":{"0x000000000000000000000000000000000000000b":[],"0x000000000000000000000000000000000000000a":[]}}}"#;
        let policy: FundingPolicy = serde_json::from_str(ordered).unwrap();
        assert!(policy.rules.routes[0].token < policy.rules.routes[1].token);
        let unknown = r#"{"admins":[],"rules":{"maxSlippageBps":0,"sources":{}},"id":7}"#;
        assert!(serde_json::from_str::<FundingPolicyAuthorization>(unknown).is_err());
    }
}
