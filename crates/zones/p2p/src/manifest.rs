use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use alloy_primitives::{Address as EthereumAddress, B256};
use commonware_codec::DecodeExt as _;
use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::{Address, Ingress};
use commonware_utils::Hostname;
use serde::Deserialize;

/// Minimum number of Simplex voters. Commonware's `N3f1` fault model needs four voters to keep
/// finalizing while one of them is unavailable.
const MIN_QUORUM_NODES: usize = 4;

/// Simplex consensus parameters from the manifest's `[consensus]` table.
///
/// Omitted values take the zone defaults documented in `simplex.md` §7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusParams {
    /// How long a view waits for the leader's proposal before nullifying it.
    pub leader_timeout: Duration,
    /// How long a view waits for a notarization before nullifying it. Exceeds `leader_timeout`.
    pub certification_timeout: Duration,
    /// How often a nullify vote is rebroadcast while a view is stuck.
    pub timeout_retry: Duration,
    /// Leader inactivity after which its views are skipped early. Exceeds both
    /// `certification_timeout` and `timeout_retry`.
    pub skip_timeout: Duration,
    /// How long a peer has to answer a fetch request.
    pub fetch_timeout: Duration,
    /// How long a proposer waits for the next finalized Tempo anchor before skipping its view.
    /// Below `leader_timeout`.
    pub proposal_anchor_wait: Duration,
    /// How long a non-owner waits after a batch boundary finalizes locally before it submits the
    /// batch itself.
    pub settlement_failover: Duration,
}

impl Default for ConsensusParams {
    fn default() -> Self {
        Self {
            leader_timeout: Duration::from_millis(2_500),
            certification_timeout: Duration::from_secs(4),
            timeout_retry: Duration::from_secs(10),
            skip_timeout: Duration::from_secs(12),
            fetch_timeout: Duration::from_secs(2),
            proposal_anchor_wait: Duration::from_millis(1_500),
            settlement_failover: Duration::from_secs(30),
        }
    }
}

impl ConsensusParams {
    fn from_raw(raw: RawConsensus) -> Result<Self, ManifestError> {
        let defaults = Self::default();
        let millis =
            |value: Option<u64>, default: Duration| value.map_or(default, Duration::from_millis);
        let params = Self {
            leader_timeout: millis(raw.leader_timeout_ms, defaults.leader_timeout),
            certification_timeout: millis(
                raw.certification_timeout_ms,
                defaults.certification_timeout,
            ),
            timeout_retry: millis(raw.timeout_retry_ms, defaults.timeout_retry),
            skip_timeout: millis(raw.skip_timeout_ms, defaults.skip_timeout),
            fetch_timeout: millis(raw.fetch_timeout_ms, defaults.fetch_timeout),
            proposal_anchor_wait: millis(
                raw.proposal_anchor_wait_ms,
                defaults.proposal_anchor_wait,
            ),
            settlement_failover: millis(raw.settlement_failover_ms, defaults.settlement_failover),
        };
        // Commonware asserts these orderings when the engine starts; reject them while parsing.
        let ordered = [
            (
                params.proposal_anchor_wait < params.leader_timeout,
                "proposal_anchor_wait_ms must be below leader_timeout_ms",
            ),
            (
                params.leader_timeout < params.certification_timeout,
                "leader_timeout_ms must be below certification_timeout_ms",
            ),
            (
                params.certification_timeout < params.skip_timeout
                    && params.timeout_retry < params.skip_timeout,
                "skip_timeout_ms must exceed certification_timeout_ms and timeout_retry_ms",
            ),
            (
                !params.fetch_timeout.is_zero() && !params.timeout_retry.is_zero(),
                "fetch_timeout_ms and timeout_retry_ms must be non-zero",
            ),
        ];
        if let Some((_, reason)) = ordered.iter().find(|(valid, _)| !valid) {
            return Err(ManifestError::InvalidConsensusTiming(reason));
        }
        Ok(params)
    }
}

/// A validated P2P address from the manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManifestAddress {
    /// A literal IP address and port.
    Socket(SocketAddr),
    /// A DNS hostname and port.
    Dns { host: Hostname, port: u16 },
}

impl ManifestAddress {
    pub(crate) fn to_commonware(&self) -> Address {
        match self {
            Self::Socket(address) => Address::Symmetric(*address),
            Self::Dns { host, port } => Address::Asymmetric {
                ingress: Ingress::Dns {
                    host: host.clone(),
                    port: *port,
                },
                // DNS-only manifests cannot know a pod's egress IP ahead of time.
                // The network enables authenticated-key-only ingress filtering when
                // DNS addresses are present, so this placeholder is never consulted.
                egress: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            },
        }
    }

    pub(crate) const fn is_dns(&self) -> bool {
        matches!(self, Self::Dns { .. })
    }
}

impl fmt::Display for ManifestAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(address) => address.fmt(f),
            Self::Dns { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl std::str::FromStr for ManifestAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            if address.port() == 0 {
                return Err("port must be non-zero".to_owned());
            }
            return Ok(Self::Socket(address));
        }

        let (host, port) = value
            .rsplit_once(':')
            .ok_or_else(|| "expected `host:port`".to_owned())?;
        if host.is_empty() || host.contains(':') {
            return Err("expected a DNS hostname or bracketed IP followed by a port".to_owned());
        }
        let host = Hostname::new(host).map_err(|err| format!("invalid DNS hostname: {err}"))?;
        let port = port
            .parse::<u16>()
            .map_err(|err| format!("invalid port: {err}"))?;
        if port == 0 {
            return Err("port must be non-zero".to_owned());
        }
        Ok(Self::Dns { host, port })
    }
}

/// One Simplex participant in a zone's static topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestNode {
    name: String,
    ed25519_public_key: PublicKey,
    secp256k1_address: EthereumAddress,
    address: ManifestAddress,
    beneficiary: Option<EthereumAddress>,
}

impl ManifestNode {
    /// Human-readable node name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Node's Ed25519 public key: its Commonware network identity and its Simplex vote key.
    pub const fn ed25519_public_key(&self) -> &PublicKey {
        &self.ed25519_public_key
    }

    /// Address derived from this node's individual secp256k1 key, registered with `ZonePortal`
    /// and used to sign and submit settlements.
    pub const fn secp256k1_address(&self) -> EthereumAddress {
        self.secp256k1_address
    }

    /// Node's advertised P2P address.
    pub const fn address(&self) -> &ManifestAddress {
        &self.address
    }

    /// Fee recipient this node's proposals must use.
    ///
    /// `None` means the shared sequencer address every quorum node holds.
    pub const fn beneficiary(&self) -> Option<EthereumAddress> {
        self.beneficiary
    }
}

/// A parsed and intrinsically validated zone manifest.
#[derive(Debug, Clone)]
pub struct ZoneManifest {
    consensus: ConsensusParams,
    nodes: Vec<ManifestNode>,
}

impl ZoneManifest {
    /// Parses and validates a TOML manifest.
    pub fn parse(input: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(input).map_err(ManifestError::Toml)?;
        let consensus = raw
            .consensus
            .map_or_else(|| Ok(ConsensusParams::default()), ConsensusParams::from_raw)?;

        let mut names = BTreeSet::new();
        let mut ed25519_public_keys = BTreeSet::new();
        let mut secp256k1_addresses = BTreeSet::new();
        let mut nodes = Vec::with_capacity(raw.nodes.len());

        for raw_node in raw.nodes {
            if raw_node.name.trim().is_empty() {
                return Err(ManifestError::EmptyNodeName);
            }
            if !names.insert(raw_node.name.clone()) {
                return Err(ManifestError::DuplicateNodeName(raw_node.name));
            }

            let ed25519_public_key = parse_ed25519_public_key(
                &format!("nodes.{}.ed25519_public_key", raw_node.name),
                &raw_node.ed25519_public_key,
            )?;
            if !ed25519_public_keys.insert(ed25519_public_key.clone()) {
                return Err(ManifestError::DuplicateEd25519PublicKey(
                    ed25519_public_key.to_string(),
                ));
            }

            let secp256k1_address = raw_node
                .secp256k1_address
                .parse::<EthereumAddress>()
                .map_err(|source| ManifestError::InvalidSecp256k1Address {
                    node: raw_node.name.clone(),
                    address: raw_node.secp256k1_address,
                    reason: source.to_string(),
                })?;
            if !secp256k1_addresses.insert(secp256k1_address) {
                return Err(ManifestError::DuplicateSecp256k1Address(secp256k1_address));
            }

            let address =
                raw_node
                    .address
                    .parse()
                    .map_err(|reason| ManifestError::InvalidAddress {
                        node: raw_node.name.clone(),
                        address: raw_node.address.clone(),
                        reason,
                    })?;
            let beneficiary = raw_node
                .beneficiary
                .map(|beneficiary| {
                    beneficiary.parse::<EthereumAddress>().map_err(|source| {
                        ManifestError::InvalidBeneficiary {
                            node: raw_node.name.clone(),
                            address: beneficiary,
                            reason: source.to_string(),
                        }
                    })
                })
                .transpose()?;
            nodes.push(ManifestNode {
                name: raw_node.name,
                ed25519_public_key,
                secp256k1_address,
                address,
                beneficiary,
            });
        }

        if nodes.len() < MIN_QUORUM_NODES {
            return Err(ManifestError::TooFewQuorumNodes(nodes.len()));
        }
        Ok(Self { consensus, nodes })
    }

    /// Reads, parses, and validates a TOML manifest from disk.
    pub fn read_from_file(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let input = std::fs::read_to_string(path).map_err(|source| ManifestError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&input)
    }

    /// Checks that both local private keys belong to the same manifest member.
    pub fn validate_node(
        &self,
        local_ed25519_public_key: &PublicKey,
        local_secp256k1_address: EthereumAddress,
    ) -> Result<&ManifestNode, ManifestError> {
        let local_node = self
            .node_by_ed25519_public_key(local_ed25519_public_key)
            .ok_or_else(|| {
                ManifestError::LocalNodeNotFound(local_ed25519_public_key.to_string())
            })?;
        if local_node.secp256k1_address != local_secp256k1_address {
            return Err(ManifestError::LocalSecp256k1AddressMismatch {
                manifest: local_node.secp256k1_address,
                local: local_secp256k1_address,
            });
        }
        Ok(local_node)
    }

    /// Simplex timing and settlement-failover parameters.
    pub const fn consensus(&self) -> &ConsensusParams {
        &self.consensus
    }

    /// All participants, in manifest order.
    pub fn nodes(&self) -> &[ManifestNode] {
        &self.nodes
    }

    /// Ed25519 identities of every participant, in manifest order.
    pub fn participants(&self) -> impl Iterator<Item = &PublicKey> {
        self.nodes.iter().map(ManifestNode::ed25519_public_key)
    }

    /// Digest of the settlement-relevant membership, logged at startup.
    ///
    /// Covers each member's Ed25519 identity and the address its settlements come from, which
    /// is everything two nodes must agree on to derive the same participant set and settlement
    /// duty rotation. Compare it across nodes to diagnose a manifest mismatch. Addresses are
    /// excluded so relocating a node does not change it. Sorted, so file order does not matter.
    pub fn membership_digest(&self) -> B256 {
        let mut members = self
            .nodes
            .iter()
            .map(|node| {
                (
                    node.ed25519_public_key.as_ref().to_vec(),
                    node.secp256k1_address,
                )
            })
            .collect::<Vec<_>>();
        members.sort();

        let mut preimage = Vec::with_capacity(members.len() * 52);
        for (ed25519_public_key, secp256k1_address) in members {
            preimage.extend_from_slice(&ed25519_public_key);
            preimage.extend_from_slice(secp256k1_address.as_slice());
        }
        alloy_primitives::keccak256(&preimage)
    }

    /// Returns the manifest node registered with an Ed25519 public key.
    pub fn node_by_ed25519_public_key(
        &self,
        ed25519_public_key: &PublicKey,
    ) -> Option<&ManifestNode> {
        self.nodes
            .iter()
            .find(|node| node.ed25519_public_key() == ed25519_public_key)
    }

    pub(crate) fn has_dns_addresses(&self) -> bool {
        self.nodes.iter().any(|node| node.address.is_dns())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    /// Deprecated compatibility field. Zone identity comes from the genesis chain ID.
    #[serde(default, rename = "zone_id")]
    _legacy_zone_id: Option<u32>,
    /// Deprecated compatibility field. The signer-set version comes from `ZonePortal`.
    #[serde(default, rename = "sequencer_set_version")]
    _legacy_sequencer_set_version: Option<u64>,
    /// Timing overrides; every key is optional.
    #[serde(default)]
    consensus: Option<RawConsensus>,
    nodes: Vec<RawManifestNode>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConsensus {
    #[serde(default)]
    leader_timeout_ms: Option<u64>,
    #[serde(default)]
    certification_timeout_ms: Option<u64>,
    #[serde(default)]
    timeout_retry_ms: Option<u64>,
    #[serde(default)]
    skip_timeout_ms: Option<u64>,
    #[serde(default)]
    fetch_timeout_ms: Option<u64>,
    #[serde(default)]
    proposal_anchor_wait_ms: Option<u64>,
    #[serde(default)]
    settlement_failover_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestNode {
    name: String,
    ed25519_public_key: String,
    secp256k1_address: String,
    address: String,
    /// Fee recipient this node's proposals use instead of the shared sequencer.
    #[serde(default)]
    beneficiary: Option<String>,
}

fn parse_ed25519_public_key(field: &str, encoded: &str) -> Result<PublicKey, ManifestError> {
    let bytes =
        const_hex::decode(encoded).map_err(|source| ManifestError::InvalidEd25519PublicKey {
            field: field.to_owned(),
            reason: source.to_string(),
        })?;
    PublicKey::decode(&bytes[..]).map_err(|source| ManifestError::InvalidEd25519PublicKey {
        field: field.to_owned(),
        reason: source.to_string(),
    })
}

/// Manifest parsing and validation errors.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("failed reading sequencer manifest `{path}`")]
    Read {
        path: std::path::PathBuf,

        #[source]
        source: std::io::Error,
    },

    #[error("invalid sequencer manifest TOML")]
    Toml(#[source] toml::de::Error),

    #[error(
        "sequencer manifest needs at least {MIN_QUORUM_NODES} nodes to tolerate one unavailable node, found {0}"
    )]
    TooFewQuorumNodes(usize),

    #[error("invalid beneficiary `{address}` for node `{node}`: {reason}")]
    InvalidBeneficiary {
        node: String,
        address: String,
        reason: String,
    },

    #[error("invalid `[consensus]` timing: {0}")]
    InvalidConsensusTiming(&'static str),

    #[error("sequencer manifest node names must not be empty")]
    EmptyNodeName,

    #[error("duplicate sequencer manifest node name `{0}`")]
    DuplicateNodeName(String),

    #[error("duplicate sequencer manifest Ed25519 public key `{0}`")]
    DuplicateEd25519PublicKey(String),

    #[error("duplicate sequencer manifest secp256k1 address `{0}`")]
    DuplicateSecp256k1Address(EthereumAddress),

    #[error("invalid Ed25519 public key in `{field}`: {reason}")]
    InvalidEd25519PublicKey { field: String, reason: String },

    #[error("invalid secp256k1 address `{address}` for node `{node}`: {reason}")]
    InvalidSecp256k1Address {
        node: String,
        address: String,
        reason: String,
    },

    #[error("invalid address `{address}` for node `{node}`: {reason}")]
    InvalidAddress {
        node: String,
        address: String,
        reason: String,
    },

    #[error("this node's Ed25519 public key `{0}` is not present in the sequencer manifest")]
    LocalNodeNotFound(String),

    #[error(
        "this node's secp256k1 address `{local}` does not match its manifest address `{manifest}`"
    )]
    LocalSecp256k1AddressMismatch {
        manifest: EthereumAddress,
        local: EthereumAddress,
    },
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use alloy_primitives::Address;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{ConsensusParams, MIN_QUORUM_NODES, ManifestError, ZoneManifest};

    fn public_key(seed: u64) -> commonware_cryptography::ed25519::PublicKey {
        PrivateKey::from_seed(seed).public_key()
    }

    fn ed25519_public_key(seed: u64) -> String {
        const_hex::encode_prefixed(public_key(seed).as_ref())
    }

    fn secp256k1_address(seed: u64) -> String {
        format!("0x{seed:040x}")
    }

    /// Builds a manifest whose nodes are `(ed25519 seed, name, address)`; the secp256k1 address
    /// is derived from the seed.
    fn manifest(consensus: &str, nodes: &[(u64, &str, &str)]) -> String {
        let mut value = consensus.to_owned();
        for (key, name, address) in nodes {
            value.push_str(&format!(
                "\n[[nodes]]\nname = \"{name}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"{}\"\naddress = \"{address}\"\n",
                ed25519_public_key(*key),
                secp256k1_address(*key),
            ));
        }
        value
    }

    const FOUR_NODES: [(u64, &str, &str); 4] = [
        (1, "seq-0", "127.0.0.1:9200"),
        (2, "seq-1", "seq-1.zone.local:9200"),
        (3, "seq-2", "127.0.0.1:9202"),
        (4, "seq-3", "127.0.0.1:9203"),
    ];

    #[test]
    fn parses_with_default_consensus_parameters() {
        let parsed = ZoneManifest::parse(&manifest("", &FOUR_NODES)).unwrap();
        assert_eq!(parsed.consensus(), &ConsensusParams::default());
        assert_eq!(parsed.nodes().len(), 4);
        assert_eq!(
            parsed.participants().cloned().collect::<Vec<_>>(),
            (1..=4).map(public_key).collect::<Vec<_>>()
        );
        let node = parsed.node_by_ed25519_public_key(&public_key(2)).unwrap();
        assert_eq!(node.name(), "seq-1");
        assert_eq!(
            node.secp256k1_address(),
            secp256k1_address(2).parse::<Address>().unwrap()
        );
        assert_eq!(node.beneficiary(), None);
        assert!(parsed.has_dns_addresses());
        assert_eq!(
            parsed
                .validate_node(&public_key(2), node.secp256k1_address())
                .unwrap()
                .name(),
            "seq-1"
        );
    }

    #[test]
    fn consensus_table_overrides_defaults_and_rejects_bad_orderings() {
        let overridden = ZoneManifest::parse(&manifest(
            "[consensus]\nleader_timeout_ms = 1000\ncertification_timeout_ms = 1500\n\
             timeout_retry_ms = 1000\nskip_timeout_ms = 3000\nfetch_timeout_ms = 1000\n\
             proposal_anchor_wait_ms = 500\nsettlement_failover_ms = 5000\n",
            &FOUR_NODES,
        ))
        .unwrap();
        assert_eq!(
            overridden.consensus(),
            &ConsensusParams {
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_millis(1_500),
                timeout_retry: Duration::from_secs(1),
                skip_timeout: Duration::from_secs(3),
                fetch_timeout: Duration::from_secs(1),
                proposal_anchor_wait: Duration::from_millis(500),
                settlement_failover: Duration::from_secs(5),
            }
        );

        for (table, reason) in [
            (
                "[consensus]\nproposal_anchor_wait_ms = 3000\n",
                "proposal_anchor_wait_ms must be below leader_timeout_ms",
            ),
            (
                "[consensus]\ncertification_timeout_ms = 2500\n",
                "leader_timeout_ms must be below certification_timeout_ms",
            ),
            (
                "[consensus]\nskip_timeout_ms = 4000\n",
                "skip_timeout_ms must exceed certification_timeout_ms and timeout_retry_ms",
            ),
            (
                "[consensus]\nfetch_timeout_ms = 0\n",
                "fetch_timeout_ms and timeout_retry_ms must be non-zero",
            ),
        ] {
            assert!(matches!(
                ZoneManifest::parse(&manifest(table, &FOUR_NODES)),
                Err(ManifestError::InvalidConsensusTiming(actual)) if actual == reason
            ));
        }
    }

    #[test]
    fn beneficiary_is_optional_per_node() {
        let mut input = manifest("", &FOUR_NODES);
        input.push_str(&format!("beneficiary = \"{}\"\n", secp256k1_address(0x44)));
        let parsed = ZoneManifest::parse(&input).unwrap();
        assert_eq!(
            parsed.nodes()[3].beneficiary(),
            Some(secp256k1_address(0x44).parse().unwrap())
        );

        let mut invalid = manifest("", &FOUR_NODES);
        invalid.push_str("beneficiary = \"0x1234\"\n");
        assert!(matches!(
            ZoneManifest::parse(&invalid),
            Err(ManifestError::InvalidBeneficiary { node, .. }) if node == "seq-3"
        ));
    }

    #[test]
    fn readme_manifest_example_has_expected_shape() {
        let (_, after_fence) = include_str!("../README.md")
            .split_once("```toml\n")
            .expect("README contains a TOML manifest example");
        let (example, _) = after_fence
            .split_once("\n```")
            .expect("README closes the TOML manifest example");

        // The example uses placeholder keys, so only its shape can be checked.
        let manifest: super::RawManifest = toml::from_str(example).unwrap();
        assert_eq!(manifest.nodes.len(), MIN_QUORUM_NODES);
        assert!(manifest.consensus.is_some());
    }

    #[test]
    fn membership_digest_tracks_identities_not_addresses_or_order() {
        let baseline = ZoneManifest::parse(&manifest("", &FOUR_NODES))
            .unwrap()
            .membership_digest();

        // File order is not part of the identity.
        let mut reordered = FOUR_NODES;
        reordered.swap(0, 3);
        assert_eq!(
            ZoneManifest::parse(&manifest("", &reordered))
                .unwrap()
                .membership_digest(),
            baseline
        );

        // Addresses are excluded.
        let mut moved = FOUR_NODES;
        moved[1].2 = "127.0.0.1:9300";
        assert_eq!(
            ZoneManifest::parse(&manifest("", &moved))
                .unwrap()
                .membership_digest(),
            baseline
        );

        // The address a member settles from changes it.
        let rekeyed = manifest("", &FOUR_NODES).replace(
            &format!("secp256k1_address = \"{}\"", secp256k1_address(3)),
            &format!("secp256k1_address = \"{}\"", secp256k1_address(9)),
        );
        assert_ne!(
            ZoneManifest::parse(&rekeyed).unwrap().membership_digest(),
            baseline
        );
    }

    #[test]
    fn rejects_invalid_topologies_and_local_identities() {
        assert!(matches!(
            ZoneManifest::parse(&manifest("", &FOUR_NODES[..3])),
            Err(ManifestError::TooFewQuorumNodes(3))
        ));

        let mut duplicate_key = FOUR_NODES;
        duplicate_key[3].0 = 2;
        assert!(matches!(
            ZoneManifest::parse(&manifest("", &duplicate_key)),
            Err(ManifestError::DuplicateEd25519PublicKey(_))
        ));

        let duplicate_address = manifest("", &FOUR_NODES).replace(
            &format!("secp256k1_address = \"{}\"", secp256k1_address(3)),
            &format!("secp256k1_address = \"{}\"", secp256k1_address(2)),
        );
        assert!(matches!(
            ZoneManifest::parse(&duplicate_address),
            Err(ManifestError::DuplicateSecp256k1Address(_))
        ));

        let missing_address = manifest("", &FOUR_NODES).replace(
            &format!("secp256k1_address = \"{}\"\n", secp256k1_address(3)),
            "",
        );
        assert!(matches!(
            ZoneManifest::parse(&missing_address),
            Err(ManifestError::Toml(_))
        ));

        // Portal-leader fields are gone for good; unknown keys are rejected rather than ignored.
        let legacy = format!(
            "leader_ed25519_public_key = \"{}\"\n{}",
            ed25519_public_key(1),
            manifest("", &FOUR_NODES)
        );
        assert!(matches!(
            ZoneManifest::parse(&legacy),
            Err(ManifestError::Toml(_))
        ));

        let valid = ZoneManifest::parse(&manifest("", &FOUR_NODES)).unwrap();
        assert!(matches!(
            valid.validate_node(&public_key(99), secp256k1_address(99).parse().unwrap()),
            Err(ManifestError::LocalNodeNotFound(_))
        ));
        assert!(matches!(
            valid.validate_node(&public_key(2), secp256k1_address(3).parse().unwrap()),
            Err(ManifestError::LocalSecp256k1AddressMismatch { .. })
        ));
    }
}
