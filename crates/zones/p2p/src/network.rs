use std::{net::SocketAddr, num::NonZeroUsize, time::Duration};

use alloy_primitives::Address as EthereumAddress;
use commonware_cryptography::{
    Signer as _,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::{AddressableTrackedPeers, authenticated::lookup};
use commonware_runtime::{Quota, Supervisor as _};
use commonware_utils::{NZU32, NZUsize, ordered::Map};
use eyre::WrapErr as _;

use crate::ZoneManifest;

/// Leader-to-follower sealed block replication channel.
pub(crate) const BLOCK_CHANNEL: u64 = 0;
/// Catch-up range requests sent by a lagging node to eligible peers.
pub(crate) const BACKFILL_REQUEST_CHANNEL: u64 = 1;
/// Ordered block and completion frames returned for a catch-up request.
pub(crate) const BACKFILL_RESPONSE_CHANNEL: u64 = 2;
/// Raw transaction propagation channel into the sequencer quorum.
pub(crate) const TRANSACTION_CHANNEL: u64 = 3;
/// Leader-to-follower proposed settlement statement channel.
pub(crate) const SETTLEMENT_PROPOSAL_CHANNEL: u64 = 4;
/// Follower-to-leader settlement signature channel.
pub(crate) const SETTLEMENT_SIGNATURE_CHANNEL: u64 = 5;
/// Commonware derives receive capacity from this burst size and the retained peer count.
/// Forwarded transactions are retried from the sender's pool, so a small per-peer burst bounds
/// memory before the transaction-specific wire limit can run without sacrificing eventual relay.
pub(crate) const TRANSACTION_BURST: u32 = 4;

/// Maximum raw EIP-2718 transaction frame accepted from another sequencer.
///
/// This is eight times Reth's default 128 KiB transaction input limit, leaving room for operators
/// to raise the pool limit without allowing block-sized frames into transaction event queues.
pub const MAX_TRANSACTION_MESSAGE_SIZE: usize = 1024 * 1024;

// At 30M gas, calldata is bounded below 7.5 MiB; leave headroom for block overhead.
pub(crate) const MAX_MESSAGE_SIZE: u32 = 20 * 1024 * 1024;

/// Version of the Tempo Zone P2P wire protocol.
pub(crate) const WIRE_PROTOCOL_VERSION: u8 = 0;
const NETWORK_NAMESPACE_PREFIX: &[u8] = b"TEMPO_ZONE_P2P";

/// Immutable L1 identity used to keep P2P networks for different deployments separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2pNetworkId {
    l1_chain_id: u64,
    portal_address: EthereumAddress,
}

impl P2pNetworkId {
    /// Creates the P2P identity for one ZonePortal deployment.
    pub const fn new(l1_chain_id: u64, portal_address: EthereumAddress) -> Self {
        Self {
            l1_chain_id,
            portal_address,
        }
    }
}

pub(crate) type Network = lookup::Network<commonware_runtime::tokio::Context, PrivateKey>;
pub(crate) type Oracle = lookup::Oracle<PublicKey>;

/// Builds the synchronized Commonware configuration for the Zone's small, trusted peer set.
///
/// Start from Commonware's production defaults and override only the settings required by the
/// Zone's controlled 3-5 sequencer topology.
fn setup_commonware_config(
    ed25519_private_key: PrivateKey,
    namespace: &[u8],
    listen: SocketAddr,
    max_peers: NonZeroUsize,
    bypass_ip_check: bool,
) -> lookup::Config<PrivateKey> {
    let mut config = lookup::Config::recommended(
        ed25519_private_key,
        namespace,
        listen,
        max_peers,
        MAX_MESSAGE_SIZE,
    );

    // Zone membership is fixed by the manifest and registered at a single peer-set index.
    config.tracked_peer_sets = NZUsize!(1);

    // Sequencers communicate over private pod or VPC addresses in a multi-AZ deployment.
    config.allow_private_ips = true;
    // Stable DNS names allow sequencer addresses to survive pod and node replacement.
    config.allow_dns = true;
    // DNS peers lack fixed egress IPs; network policy must restrict access to the P2P port.
    config.bypass_ip_check = bypass_ip_check;
    // Five seconds is ample cross-AZ while bounding unauthenticated resource use.
    config.handshake_timeout = Duration::from_secs(5);
    // Trusted peers retry quickly instead of waiting Commonware's 60-second public default.
    config.peer_connection_cooldown = Duration::from_secs(1);
    // At most four legitimate remote peers are expected, so 32 leaves generous rollout headroom.
    config.max_concurrent_handshakes = NZU32!(32);
    // Eight attempts per second permits fast restarts while limiting a single source IP.
    config.allowed_handshake_rate_per_ip = Quota::per_second(NZU32!(8));
    // Thirty-two attempts per second handles the whole small peer set restarting together.
    config.allowed_handshake_rate_per_subnet = Quota::per_second(NZU32!(32));
    // Ten-second pings detect idle broken connections with negligible overhead.
    config.ping_frequency = Duration::from_secs(10);
    // One dial per 250 ms reconnects a small primary-peer set in about one second per node.
    config.dial_frequency = Duration::from_millis(250);

    config
}

pub(crate) fn instantiate(
    context: &commonware_runtime::tokio::Context,
    manifest: &ZoneManifest,
    zone_id: u32,
    ed25519_private_key: PrivateKey,
    listen: SocketAddr,
    bypass_ip_check: bool,
    network_id: P2pNetworkId,
) -> eyre::Result<(Network, Oracle, AddressableTrackedPeers<PublicKey>)> {
    let namespace = namespace(zone_id, network_id);
    // Logged, not bound into the namespace: a mismatch between nodes stalls settlement loudly at
    // the next batch boundary, and making it a handshake failure would turn every membership edit
    // into a coordinated fleet restart. Compare this across nodes to diagnose one.
    tracing::info!(target: "zone::p2p", membership_digest = %manifest.membership_digest(), "Zone P2P membership");
    let local_ed25519_public_key = ed25519_private_key.public_key();
    let max_peers = NonZeroUsize::new(manifest.nodes().len())
        .ok_or_else(|| eyre::eyre!("P2P manifest must contain at least one node"))?;
    let config = setup_commonware_config(
        ed25519_private_key,
        &namespace,
        listen,
        max_peers,
        bypass_ip_check,
    );
    let peers = peer_sets(manifest, &local_ed25519_public_key)?;
    let (network, oracle) = lookup::Network::new(context.child("network"), config);
    Ok((network, oracle, peers))
}

fn peer_sets(
    manifest: &ZoneManifest,
    local_ed25519_public_key: &PublicKey,
) -> eyre::Result<AddressableTrackedPeers<PublicKey>> {
    let (primary, secondary): (Vec<_>, Vec<_>) = manifest
        .nodes()
        .iter()
        .map(|node| {
            (
                node.is_rpc_only(),
                node.ed25519_public_key().clone(),
                node.address().to_commonware(),
            )
        })
        // RPC-only nodes initiate their own replication connections. Quorum members retain the
        // RPC-only members as secondary peers so their inbound connection is authenticated, but
        // they never create reverse P2P dials into the public RPC environment.
        .partition(|(rpc_only, public_key, _)| !rpc_only || public_key == local_ed25519_public_key);
    let primary = Map::try_from(
        primary
            .into_iter()
            .map(|(_, public_key, address)| (public_key, address))
            .collect::<Vec<_>>(),
    )
    .wrap_err("manifest contains duplicate primary P2P identities")?;
    let secondary = Map::try_from(
        secondary
            .into_iter()
            .map(|(_, public_key, address)| (public_key, address))
            .collect::<Vec<_>>(),
    )
    .wrap_err("manifest contains duplicate secondary P2P identities")?;
    Ok(AddressableTrackedPeers::new(primary, secondary))
}

fn namespace(zone_id: u32, network_id: P2pNetworkId) -> Vec<u8> {
    // The protocol version and immutable L1 deployment identity keep keys or endpoints
    // accidentally reused across local, test, and production environments from authenticating
    // into one another's network.
    let mut namespace = Vec::with_capacity(
        NETWORK_NAMESPACE_PREFIX.len() + 1 + 8 + EthereumAddress::len_bytes() + 4,
    );
    namespace.extend_from_slice(NETWORK_NAMESPACE_PREFIX);
    namespace.push(WIRE_PROTOCOL_VERSION);
    namespace.extend_from_slice(&network_id.l1_chain_id.to_be_bytes());
    namespace.extend_from_slice(network_id.portal_address.as_slice());
    namespace.extend_from_slice(&zone_id.to_be_bytes());
    namespace
}

pub(crate) fn block_quota() -> Quota {
    Quota::per_second(NZU32!(128))
}

pub(crate) fn backfill_request_quota() -> Quota {
    Quota::per_second(NZU32!(1))
}

pub(crate) fn backfill_response_quota() -> Quota {
    Quota::per_second(NZU32!(128))
}

pub(crate) fn transaction_quota() -> Quota {
    Quota::per_second(NZU32!(1024)).allow_burst(NZU32!(TRANSACTION_BURST))
}

/// ACKs are small fixed-shape EIP-712 statements plus one secp256k1 signature.
pub(crate) fn settlement_quota() -> Quota {
    Quota::per_second(NZU32!(8))
}

#[cfg(test)]
mod tests {

    use alloy_primitives::Address;
    use commonware_cryptography::{Signer as _, ed25519::PrivateKey};

    use super::{
        MAX_MESSAGE_SIZE, MAX_TRANSACTION_MESSAGE_SIZE, NETWORK_NAMESPACE_PREFIX, P2pNetworkId,
        TRANSACTION_BURST, WIRE_PROTOCOL_VERSION, namespace, peer_sets, transaction_quota,
    };
    use crate::ZoneManifest;

    fn ed25519_public_key(seed: u64) -> String {
        let key = PrivateKey::from_seed(seed).public_key();
        const_hex::encode_prefixed(key.as_ref())
    }

    fn manifest_with_rpc_follower() -> ZoneManifest {
        let mut manifest = format!(
            "leader_ed25519_public_key = \"{}\"\n",
            ed25519_public_key(1)
        );
        for seed in 1..=3 {
            manifest.push_str(&format!(
                "\n[[nodes]]\nname = \"seq-{seed}\"\ned25519_public_key = \"{}\"\nsecp256k1_address = \"0x{seed:040x}\"\naddress = \"127.0.0.1:{}\"\n",
                ed25519_public_key(seed),
                9200 + seed,
            ));
        }
        manifest.push_str(&format!(
            "\n[[nodes]]\nname = \"rpc\"\ned25519_public_key = \"{}\"\naddress = \"rpc.example:19200\"\nrpc_only = true\n",
            ed25519_public_key(4),
        ));
        ZoneManifest::parse(&manifest).unwrap()
    }

    #[test]
    fn transaction_channel_bounds_pre_validation_memory() {
        assert!(MAX_TRANSACTION_MESSAGE_SIZE < MAX_MESSAGE_SIZE as usize);
        assert_eq!(
            transaction_quota().burst_size().get() as usize * MAX_MESSAGE_SIZE as usize,
            80 * 1024 * 1024,
        );
        assert_eq!(transaction_quota().burst_size().get(), TRANSACTION_BURST);
    }

    #[test]
    fn namespace_separates_l1_environments_and_portals() {
        let portal_a = Address::repeat_byte(0x11);
        let portal_b = Address::repeat_byte(0x22);

        assert_ne!(
            namespace(7, P2pNetworkId::new(1, portal_a)),
            namespace(7, P2pNetworkId::new(2, portal_a)),
        );
        assert_ne!(
            namespace(7, P2pNetworkId::new(1, portal_a)),
            namespace(7, P2pNetworkId::new(1, portal_b)),
        );
        assert_ne!(
            namespace(7, P2pNetworkId::new(1, portal_a)),
            namespace(8, P2pNetworkId::new(1, portal_a)),
        );

        let namespace = namespace(7, P2pNetworkId::new(1, portal_a));
        assert_eq!(
            namespace[NETWORK_NAMESPACE_PREFIX.len()],
            WIRE_PROTOCOL_VERSION
        );
    }

    #[test]
    fn rpc_follower_dials_quorum_but_quorum_does_not_dial_rpc_follower() {
        let manifest = manifest_with_rpc_follower();
        let quorum_member = PrivateKey::from_seed(1).public_key();
        let rpc_follower = PrivateKey::from_seed(4).public_key();

        let quorum_peers = peer_sets(&manifest, &quorum_member).unwrap();
        assert!(quorum_peers.primary.position(&quorum_member).is_some());
        assert!(quorum_peers.primary.position(&rpc_follower).is_none());
        assert!(quorum_peers.secondary.position(&rpc_follower).is_some());

        let rpc_peers = peer_sets(&manifest, &rpc_follower).unwrap();
        assert!(rpc_peers.primary.position(&quorum_member).is_some());
        assert!(rpc_peers.primary.position(&rpc_follower).is_some());
        assert!(rpc_peers.secondary.is_empty());
    }
}
