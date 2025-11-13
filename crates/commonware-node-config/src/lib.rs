//! Definitions to read and write a tempo consensus configuration.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

use std::{net::SocketAddr, path::Path};

use commonware_codec::Decode;
use commonware_cryptography::{
    bls12381::primitives::{
        group::Share,
        poly::Poly,
        variant::{MinSig, Variant},
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::quorum;
use indexmap::IndexMap;

pub mod p2p;
pub mod timeouts;

#[cfg(test)]
mod tests;

/// Configuration for the commonware consensus engine.
///
// TODO: There are plenty of other settings that could be added here. alto's `engine::Config`
// lists a number of hardcoded values, while also hardcoding a lot of other settings.
//
// + partition_prefix
// + blocks_freezer_table_initial_size
// + finalized_freezer_table_initial_size
// + backfill_quota
// + leader_timeout
// + notarization_timeout
// + nullify_retry
// + activity_timeout
// + skip_timeout
// + fetch_timeout
// + max_fetch_count
// + fetch_concurrent
// + fetch_rate_per_peer
// + pending_limit
// + recovered_limit
// + resolver_limit
// + broadcaster_limit
// + backfill_quota
// + namespace
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "DeserConfig")]
pub struct Config {
    #[serde(serialize_with = "crate::_serde::private_key::serialize")]
    pub signer: PrivateKey,
    #[serde(serialize_with = "crate::_serde::share::serialize")]
    pub share: Share,
    #[serde(serialize_with = "crate::_serde::polynomial::serialize")]
    pub polynomial: Poly<<MinSig as Variant>::Public>,

    /// Address on which the node listens. Supply `0.0.0.0:<port>` to listen
    /// on all addresses.
    pub listen_addr: SocketAddr,

    pub metrics_port: Option<u16>,

    pub p2p: p2p::Config,

    pub storage_directory: camino::Utf8PathBuf,
    pub worker_threads: usize,

    /// The number of heights H that make up an epoch E.
    /// The heights starting from (E-1) * H + 1 up to and including E * H make
    /// up the epoch E.
    pub epoch_length: u64,

    // XXX: alto has a config `allowed_peers`, which it does not make any use of, instead relying
    // on a "peers" file.
    //
    // The intention behind peers is apparently to run a local validator set. A "hosts" file
    // on the other hand would be used to run with a set of remote hosts.
    //
    // For now, we will not use a peers file and instead just chugg all the peers in here.
    //
    // TODO: enforce the invariant that `signer.public_key` is part of `peers`.
    #[serde(with = "crate::_serde::peers")]
    pub peers: IndexMap<PublicKey, String>,

    pub message_backlog: usize,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub fee_recipient: alloy_primitives::Address,

    /// Various timeouts employed by the consensus engine, both continuous
    /// and discrete time.
    #[serde(default)]
    pub timeouts: timeouts::Config,
}

impl Config {
    /// Parses [`Config`] from a toml formatted file at `path`.
    // TODO: also support json down the line because eth/reth chainspecs
    // are json? Maybe even replace toml? Toml is nicer for humans.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file_contents = std::fs::read_to_string(path)?;
        let this = toml::from_str(&file_contents)?;
        Ok(this)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to open file for reading")]
    OpenFile(#[from] std::io::Error),
    #[error("failed parsing file contents")]
    Parse(#[from] toml::de::Error),
    #[error("failed decoding provided hex encoded bytes as a public polynomial")]
    Polynomial(#[source] commonware_codec::Error),
}

/// The deserialization target that will be turned into a [`Config`].
///
/// The reason this exists is that there are fields in [`Config`] that
/// require an extrastrep during deserialization that depends on the
/// value of other fields.
#[derive(Debug, serde::Deserialize)]
struct DeserConfig {
    #[serde(deserialize_with = "crate::_serde::private_key::deserialize")]
    signer: PrivateKey,
    #[serde(deserialize_with = "crate::_serde::share::deserialize")]
    share: Share,
    #[serde(deserialize_with = "const_hex::serde::deserialize")]
    polynomial: Vec<u8>,

    listen_addr: SocketAddr,

    metrics_port: Option<u16>,

    p2p: p2p::Config,

    storage_directory: camino::Utf8PathBuf,
    worker_threads: usize,

    epoch_length: u64,

    // XXX: alto has a config `allowed_peers`, which it does not make any use of, instead relying
    // on a "peers" file.
    //
    // The intention behind peers is apparently to run a local validator set. A "hosts" file
    // on the other hand would be used to run with a set of remote hosts.
    //
    // For now, we will not use a peers file and instead just chugg all the peers in here.
    //
    // TODO: enforce the invariant that `signer.public_key` is part of `peers`.
    #[serde(deserialize_with = "crate::_serde::peers::deserialize")]
    peers: IndexMap<PublicKey, String>,

    message_backlog: usize,
    mailbox_size: usize,
    deque_size: usize,

    fee_recipient: alloy_primitives::Address,

    timeouts: timeouts::Config,
}

impl TryFrom<DeserConfig> for Config {
    type Error = Error;

    fn try_from(value: DeserConfig) -> Result<Self, Self::Error> {
        let DeserConfig {
            signer,
            share,
            polynomial,
            listen_addr,
            metrics_port,
            p2p,
            storage_directory,
            worker_threads,
            peers,
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
            timeouts,
            epoch_length,
        } = value;

        let threshold = quorum(peers.len() as u32);

        Ok(Self {
            signer,
            share,
            polynomial: Poly::decode_cfg(&polynomial[..], &(threshold as usize))
                .map_err(Error::Polynomial)?,
            listen_addr,
            metrics_port,
            p2p,
            storage_directory,
            worker_threads,
            peers,
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
            timeouts,
            epoch_length,
        })
    }
}

mod _serde {
    use commonware_codec::DecodeExt as _;
    use serde::{Deserialize, Serialize};

    /// Serialization target for public keys.
    struct PublicKeySer<'a>(&'a super::PublicKey);
    impl<'a> Serialize for PublicKeySer<'a> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use commonware_codec::Encode as _;

            let bytes = self.0.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }
    }
    // Deserialization target for public keys.
    struct PublicKeyDe(super::PublicKey);
    impl<'de> Deserialize<'de> for PublicKeyDe {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let key = super::PublicKey::decode(&bytes[..]).map_err(|err| {
                serde::de::Error::custom(format!(
                    "failed decoding hex-formatted bytes as public key: {err:?}"
                ))
            })?;
            Ok(Self(key))
        }
    }

    pub(crate) mod share {
        use commonware_codec::{DecodeExt as _, Encode as _};
        use serde::{Deserializer, Serializer};

        pub(crate) fn serialize<S>(share: &crate::Share, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = share.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<crate::Share, D::Error>
        where
            D: Deserializer<'de>,
        {
            // XXX: we don't use commonware's built-in hex tooling because it doesn't provide good
            // errors. If it fails, `None` is all you get.
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let share = crate::Share::decode(&bytes[..]).map_err(|err| {
                serde::de::Error::custom(format!(
                    "failed decoding hex-formatted bytes as group share: {err:?}"
                ))
            })?;
            Ok(share)
        }
    }

    pub(crate) mod polynomial {
        use commonware_codec::Encode as _;
        use serde::Serializer;

        pub(crate) fn serialize<S>(
            polynomial: &crate::Poly<<crate::MinSig as crate::Variant>::Public>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = polynomial.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }
    }

    pub(crate) mod peers {
        use indexmap::IndexMap;
        use serde::{Deserializer, Serializer, de::Visitor, ser::SerializeMap}; // # codespell:ignore ser

        use super::PublicKeyDe;

        struct PeersVisitor;

        impl<'de> Visitor<'de> for PeersVisitor {
            type Value = IndexMap<crate::PublicKey, String>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a map of hex-formatted ed25519 public keys to DNS name")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut peers = IndexMap::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((key, addr)) = map.next_entry::<PublicKeyDe, _>()? {
                    // TODO: reject dupes
                    peers.insert(key.0, addr);
                }
                Ok(peers)
            }
        }

        pub(crate) fn serialize<S>(
            peers: &IndexMap<crate::PublicKey, String>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut map = serializer.serialize_map(Some(peers.len()))?;
            for (key, addr) in peers {
                map.serialize_entry(&super::PublicKeySer(key), addr)?;
            }
            map.end()
        }

        pub(crate) fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<IndexMap<crate::PublicKey, String>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(PeersVisitor)
        }
    }

    pub(crate) mod private_key {
        use commonware_codec::{DecodeExt as _, Encode as _};
        use serde::{Deserializer, Serializer};

        pub(crate) fn serialize<S>(
            private_key: &crate::PrivateKey,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = private_key.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<crate::PrivateKey, D::Error>
        where
            D: Deserializer<'de>,
        {
            // XXX: we don't use commonware's built-in hex tooling because it doesn't provide good
            // errors. If it fails, `None` is all you get.
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let signer = crate::PrivateKey::decode(&bytes[..]).map_err(|err| {
                serde::de::Error::custom(format!(
                    "failed decoding hex-formatted bytes as private key: {err:?}"
                ))
            })?;
            Ok(signer)
        }
    }
}
