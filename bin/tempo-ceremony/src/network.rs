//! P2P network setup using commonware-p2p lookup.

use crate::{
    config::CeremonyConfig,
    constants::{GENESIS_EPOCH, network::CHANNEL_ID},
};
use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{Manager, authenticated::lookup};
use commonware_runtime::tokio::Context;
use commonware_utils::set::OrderedAssociated;
use governor::Quota;
use std::{net::SocketAddr, path::PathBuf};

/// Arguments for the connectivity test command.
pub struct ConnectivityArgs {
    pub config: PathBuf,
    pub signing_key: PathBuf,
    pub log_level: String,
}

/// Network wrapper for the ceremony.
pub struct CeremonyNetwork {
    /// The underlying P2P lookup network.
    network: lookup::Network<Context, PrivateKey>,
    /// Oracle for managing peer set membership.
    oracle: lookup::Oracle<PublicKey>,
}

impl CeremonyNetwork {
    /// Create a new ceremony network.
    pub fn new(context: Context, signing_key: PrivateKey, config: &CeremonyConfig) -> Self {
        let p2p_namespace = commonware_utils::union_unique(config.namespace.as_bytes(), b"_P2P");

        let p2p_config = lookup::Config {
            mailbox_size: config.network.mailbox_size,
            tracked_peer_sets: 1,
            attempt_unregistered_handshakes: false,
            ..lookup::Config::local(
                signing_key,
                &p2p_namespace,
                config.network.listen_address,
                config.network.max_message_size,
            )
        };

        let (network, oracle) = lookup::Network::new(context, p2p_config);

        Self { network, oracle }
    }

    /// Register all ceremony participants as peers.
    pub async fn register_peers(&mut self, peers: OrderedAssociated<PublicKey, SocketAddr>) {
        self.oracle.update(GENESIS_EPOCH, peers).await;
    }

    /// Register the ceremony channel and return sender/receiver.
    pub fn register_channel(
        &mut self,
        message_backlog: usize,
    ) -> (lookup::Sender<PublicKey>, lookup::Receiver<PublicKey>) {
        // Use a non-limiting quota for the ceremony
        let quota = Quota::per_second(std::num::NonZeroU32::MAX);
        self.network.register(CHANNEL_ID, quota, message_backlog)
    }

    /// Start the network (returns future that runs until shutdown).
    pub async fn start(self) -> Result<(), commonware_runtime::Error> {
        self.network.start().await
    }
}
