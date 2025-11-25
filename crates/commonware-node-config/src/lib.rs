//! Definitions to read and write a tempo consensus configuration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{fmt::Display, net::SocketAddr, path::Path};

use commonware_codec::{DecodeExt as _, Encode as _, FixedSize, Read};
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        poly::Public,
        variant::{MinSig, Variant},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::set::OrderedAssociated;
use indexmap::IndexMap;
use serde::{
    Deserialize,
    Deserializer,
    Serialize,
    ser::{SerializeMap as _, Serializer}, // codespell:ignore ser
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peers {
    inner: OrderedAssociated<PublicKey, SocketAddr>,
}

impl Peers {
    pub fn empty() -> Self {
        Self {
            inner: OrderedAssociated::from(vec![]),
        }
    }

    pub fn into_inner(self) -> OrderedAssociated<PublicKey, SocketAddr> {
        self.inner
    }
}

impl From<OrderedAssociated<PublicKey, SocketAddr>> for Peers {
    fn from(inner: OrderedAssociated<PublicKey, SocketAddr>) -> Self {
        Self { inner }
    }
}

impl Serialize for Peers {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        /// Serialization target for public keys.
        struct Helper<'a>(&'a PublicKey);
        impl<'a> Serialize for Helper<'a> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use commonware_codec::Encode as _;

                let bytes = self.0.encode();
                const_hex::serde::serialize(&bytes, serializer)
            }
        }
        let mut map = serializer.serialize_map(Some(self.inner.len()))?;
        for (key, addr) in &self.inner {
            map.serialize_entry(&Helper(key), addr)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Peers {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialization target for public keys.
        struct Helper(PublicKey);
        impl<'de> Deserialize<'de> for Helper {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
                let key = PublicKey::decode(&bytes[..]).map_err(|err| {
                    serde::de::Error::custom(format!(
                        "failed decoding hex-formatted bytes as public key: {err:?}"
                    ))
                })?;
                Ok(Self(key))
            }
        }
        struct PeersVisitor;

        impl<'de> serde::de::Visitor<'de> for PeersVisitor {
            type Value = IndexMap<crate::PublicKey, SocketAddr>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter
                    .write_str("a map of hex-formatted ed25519 public keys to <ip>:<port> entries")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut peers = IndexMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, addr)) = map.next_entry::<Helper, _>()? {
                    let key = key.0;
                    if peers.insert(key.clone(), addr).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "peers must not have duplicate entries; duplicate key: `{key}`",
                        )))?;
                    }
                }
                Ok(peers)
            }
        }

        let peers = deserializer.deserialize_map(PeersVisitor)?;
        Ok(Self {
            inner: peers.into_iter().collect(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicPolynomial {
    inner: Public<MinSig>,
}

impl PublicPolynomial {
    pub fn into_inner(self) -> Public<MinSig> {
        self.inner
    }
}

impl From<Public<MinSig>> for PublicPolynomial {
    fn from(inner: Public<MinSig>) -> Self {
        Self { inner }
    }
}

impl Serialize for PublicPolynomial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.inner.encode();
        const_hex::serde::serialize(&bytes, serializer)
    }
}

impl<'de> Deserialize<'de> for PublicPolynomial {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
        let degree_of_public_polynomial = degree_of_public_polynomial_from_bytes(&bytes);
        let inner = Public::<MinSig>::read_cfg(&mut &bytes[..], &degree_of_public_polynomial)
            .map_err(serde::de::Error::custom)?;
        Ok(Self { inner })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    inner: PrivateKey,
}

impl SigningKey {
    pub fn into_inner(self) -> PrivateKey {
        self.inner
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, SigningKeyError> {
        let hex = std::fs::read_to_string(path).map_err(SigningKeyErrorKind::Read)?;
        Self::try_from_hex(&hex)
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningKeyError> {
        let bytes = const_hex::decode(hex).map_err(SigningKeyErrorKind::Hex)?;
        let inner = PrivateKey::decode(&bytes[..]).map_err(SigningKeyErrorKind::Parse)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SigningKeyError> {
        std::fs::write(path, self.to_string()).map_err(SigningKeyErrorKind::Write)?;
        Ok(())
    }
}

impl Display for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.inner.encode().as_ref()))
    }
}

impl From<PrivateKey> for SigningKey {
    fn from(inner: PrivateKey) -> Self {
        Self { inner }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SigningKeyError {
    #[from]
    inner: SigningKeyErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum SigningKeyErrorKind {
    #[error("failed decoding file contents as hex-encoded bytes")]
    Hex(#[source] const_hex::FromHexError),
    #[error("failed parsing hex-decoded bytes as ed25519 private key")]
    Parse(#[source] commonware_codec::Error),
    #[error("failed reading file")]
    Read(#[source] std::io::Error),
    #[error("failed writing to file")]
    Write(#[source] std::io::Error),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningShare {
    inner: Share,
}

impl SigningShare {
    pub fn into_inner(self) -> Share {
        self.inner
    }

    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, SigningShareError> {
        let hex = std::fs::read_to_string(path).map_err(SigningShareErrorKind::Read)?;
        Self::try_from_hex(&hex)
    }

    pub fn try_from_hex(hex: &str) -> Result<Self, SigningShareError> {
        let bytes = const_hex::decode(hex).map_err(SigningShareErrorKind::Hex)?;
        let inner = Share::decode(&bytes[..]).map_err(SigningShareErrorKind::Parse)?;
        Ok(Self { inner })
    }

    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SigningShareError> {
        std::fs::write(path, self.to_string()).map_err(SigningShareErrorKind::Write)?;
        Ok(())
    }
}

impl Display for SigningShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&const_hex::encode_prefixed(self.inner.encode().as_ref()))
    }
}

impl From<Share> for SigningShare {
    fn from(inner: Share) -> Self {
        Self { inner }
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct SigningShareError {
    #[from]
    inner: SigningShareErrorKind,
}

#[derive(Debug, thiserror::Error)]
enum SigningShareErrorKind {
    #[error("failed decoding file contents as hex-encoded bytes")]
    Hex(#[source] const_hex::FromHexError),
    #[error("failed parsing hex-decoded bytes as bls12381 private share")]
    Parse(#[source] commonware_codec::Error),
    #[error("failed reading file")]
    Read(#[source] std::io::Error),
    #[error("failed writing to file")]
    Write(#[source] std::io::Error),
}

// Reverses the operation C::SIZE * self.0.len() from
// <Public<Minsig> as EncodeSize>::encode_size.
fn degree_of_public_polynomial_from_bytes(bytes: &[u8]) -> usize {
    bytes.len() / <<MinSig as Variant>::Public as FixedSize>::SIZE
}
