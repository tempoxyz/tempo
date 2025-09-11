//! Definitions to read and write a tempo consensus configuration.

use std::{net::SocketAddr, path::Path};

use commonware_codec::Decode;
use commonware_utils::quorum;
use indexmap::IndexMap;
use tempo_commonware_node_cryptography::{GroupShare, PrivateKey, PublicKey, PublicPolynomial};

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
// + max_fetch_size
// + fetch_concurrent
// + fetch_rate_per_peer
// + pending_limit
// + recovered_limit
// + resolver_limit
// + broadcaster_limit
// + backfill_quota
// + max_message_size
// + namespace
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(try_from = "DeserConfig")]
pub struct Config {
    #[serde(serialize_with = "crate::_serde::private_key::serialize")]
    pub signer: PrivateKey,
    #[serde(serialize_with = "crate::_serde::group_share::serialize")]
    pub share: GroupShare,
    #[serde(serialize_with = "crate::_serde::polynomial::serialize")]
    pub polynomial: PublicPolynomial,

    pub listen_port: u16,
    pub metrics_port: u16,

    pub storage_directory: camino::Utf8PathBuf,
    pub worker_threads: usize,

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
    pub peers: IndexMap<PublicKey, SocketAddr>,

    // TODO: enforce the invariant that all `bootstrappers` are part of `peers`.
    pub bootstrappers: Bootstrappers,

    pub message_backlog: usize,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub fee_recipient: alloy_primitives::Address,
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

    /// Returns a iterator over the bootstrappers and their socket address.
    ///
    /// # Panics
    ///
    /// This iterator will panic if one of the bootstrappers is not a member
    /// of `peers`. This invariant is enforced when deserialing and can only
    /// be violated by setting the field manually.
    pub fn bootstrappers(&self) -> impl Iterator<Item = (PublicKey, SocketAddr)> {
        self.bootstrappers.iter().map(|key| {
            let addr = self.peers.get(key).expect(
                "all bootstrappers must be contained in the peers map; \
                    this invariant is enforced when deserializing and can only \
                    be violated by mutating manually",
            );
            (key.clone(), *addr)
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to open file for reading")]
    OpenFile(#[from] std::io::Error),
    #[error("failed parsing file contents")]
    Parse(#[from] toml::de::Error),
    #[error("bootstrapper `{key}` does not have an entry in the config's peers list")]
    BootstrapperWithoutPeer { key: Box<PublicKey> },
    #[error("failed decoding provided hex encoded bytes as a public polynomial")]
    Polynomial(#[source] commonware_codec::Error),
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct Bootstrappers {
    #[serde(with = "crate::_serde::bootstrappers")]
    inner: Vec<PublicKey>,
}

impl Bootstrappers {
    pub fn iter(&self) -> impl Iterator<Item = &PublicKey> {
        self.inner.iter()
    }
}

impl From<Vec<PublicKey>> for Bootstrappers {
    fn from(inner: Vec<PublicKey>) -> Self {
        Self { inner }
    }
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
    #[serde(deserialize_with = "crate::_serde::group_share::deserialize")]
    share: GroupShare,
    #[serde(deserialize_with = "const_hex::serde::deserialize")]
    polynomial: Vec<u8>,

    listen_port: u16,
    metrics_port: u16,

    storage_directory: camino::Utf8PathBuf,
    worker_threads: usize,

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
    peers: IndexMap<PublicKey, SocketAddr>,

    bootstrappers: Bootstrappers,

    message_backlog: usize,
    mailbox_size: usize,
    deque_size: usize,

    fee_recipient: alloy_primitives::Address,
}

impl TryFrom<DeserConfig> for Config {
    type Error = Error;

    fn try_from(value: DeserConfig) -> Result<Self, Self::Error> {
        let DeserConfig {
            signer,
            share,
            polynomial,
            listen_port,
            metrics_port,
            storage_directory,
            worker_threads,
            peers,
            bootstrappers,
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
        } = value;

        let threshold = quorum(peers.len() as u32);
        for key in &bootstrappers.inner {
            if !peers.contains_key(key) {
                return Err(Error::BootstrapperWithoutPeer {
                    key: Box::new(key.clone()),
                });
            }
        }
        Ok(Self {
            signer,
            share,
            polynomial: PublicPolynomial::decode_cfg(&polynomial[..], &(threshold as usize))
                .map_err(Error::Polynomial)?,
            listen_port,
            metrics_port,
            storage_directory,
            worker_threads,
            peers,
            bootstrappers,
            message_backlog,
            mailbox_size,
            deque_size,
            fee_recipient,
        })
    }
}

mod _serde {
    use commonware_codec::DecodeExt as _;
    use serde::{Deserialize, Serialize};

    /// Serialization target for public keys.
    struct PublicKeySer<'a>(&'a tempo_commonware_node_cryptography::PublicKey);
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
    struct PublicKeyDe(tempo_commonware_node_cryptography::PublicKey);
    impl<'de> Deserialize<'de> for PublicKeyDe {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let key = tempo_commonware_node_cryptography::PublicKey::decode(&bytes[..]).map_err(
                |err| {
                    serde::de::Error::custom(format!(
                        "failed decoding hex-formatted bytes as public key: {err:?}"
                    ))
                },
            )?;
            Ok(Self(key))
        }
    }

    pub(crate) mod bootstrappers {

        use serde::{Deserializer, Serializer, de::Visitor, ser::SerializeSeq}; // # codespell:ignore ser

        use tempo_commonware_node_cryptography::PublicKey;

        use super::PublicKeyDe;

        struct BootstrappersVisitor;

        impl<'de> Visitor<'de> for BootstrappersVisitor {
            type Value = Vec<PublicKey>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a list of hex-formarred ed25519 public keys")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut keys = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some(public_key) = seq.next_element::<PublicKeyDe>()? {
                    keys.push(public_key.0);
                }
                Ok(keys)
            }
        }

        pub(crate) fn serialize<S>(
            bootstrappers: &Vec<PublicKey>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(bootstrappers.len()))?;
            for key in bootstrappers {
                seq.serialize_element(&super::PublicKeySer(key))?;
            }
            seq.end()
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<PublicKey>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(BootstrappersVisitor)
        }
    }

    pub(crate) mod group_share {
        use commonware_codec::{DecodeExt as _, Encode as _};
        use serde::{Deserializer, Serializer};

        use tempo_commonware_node_cryptography::GroupShare;

        pub(crate) fn serialize<S>(
            group_share: &GroupShare,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = group_share.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<GroupShare, D::Error>
        where
            D: Deserializer<'de>,
        {
            // XXX: we don't use commonware's built-in hex tooling because it doesn't provide good
            // errors. If it fails, `None` is all you get.
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let share = GroupShare::decode(&bytes[..]).map_err(|err| {
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

        use tempo_commonware_node_cryptography::PublicPolynomial;

        pub(crate) fn serialize<S>(
            polynomial: &PublicPolynomial,
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
        use std::net::SocketAddr;

        use indexmap::IndexMap;
        use serde::{Deserializer, Serializer, de::Visitor, ser::SerializeMap}; // # codespell:ignore ser

        use tempo_commonware_node_cryptography::PublicKey;

        use super::PublicKeyDe;

        struct PeersVisitor;

        impl<'de> Visitor<'de> for PeersVisitor {
            type Value = IndexMap<PublicKey, SocketAddr>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a map of hex-formatted ed25519 public keys to ip addresses")
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
            peers: &IndexMap<PublicKey, SocketAddr>,
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
        ) -> Result<IndexMap<PublicKey, SocketAddr>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_seq(PeersVisitor)
        }
    }

    pub(crate) mod private_key {
        use commonware_codec::{DecodeExt as _, Encode as _};
        use serde::{Deserializer, Serializer};

        use tempo_commonware_node_cryptography::PrivateKey;

        pub(crate) fn serialize<S>(
            private_key: &PrivateKey,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = private_key.encode();
            const_hex::serde::serialize(&bytes, serializer)
        }

        pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<PrivateKey, D::Error>
        where
            D: Deserializer<'de>,
        {
            // XXX: we don't use commonware's built-in hex tooling because it doesn't provide good
            // errors. If it fails, `None` is all you get.
            let bytes: Vec<u8> = const_hex::serde::deserialize(deserializer)?;
            let signer = PrivateKey::decode(&bytes[..]).map_err(|err| {
                serde::de::Error::custom(format!(
                    "failed decoding hex-formatted bytes as private key: {err:?}"
                ))
            })?;
            Ok(signer)
        }
    }
}
