//! Test P2P network implementation.
//!
//! Wraps the simulated network oracle to provide the same interface as production.

use commonware_cryptography::ed25519::PublicKey;
use commonware_p2p::simulated::{Control, Oracle, Receiver, Sender, SocketManager};
use commonware_runtime::Clock;
use tempo_commonware_node::{
    Channels, P2pNetwork, BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT,
    CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT, DKG_CHANNEL_IDENT, DKG_LIMIT,
    MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT,
    SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

/// Test P2P network for e2e tests.
///
/// Implements [`P2pNetwork`] using simulated networking.
pub struct TestNetwork<TClock: Clock> {
    oracle: Oracle<PublicKey, TClock>,
    public_key: PublicKey,
}

impl<TClock: Clock> TestNetwork<TClock> {
    /// Create a new test network for a specific peer.
    pub fn new(oracle: Oracle<PublicKey, TClock>, public_key: PublicKey) -> Self {
        Self { oracle, public_key }
    }
}

impl<TClock: Clock + Clone + Send + Sync + 'static> P2pNetwork for TestNetwork<TClock> {
    type Blocker = Control<PublicKey, TClock>;
    type PeerManager = SocketManager<PublicKey, TClock>;
    type Sender = Sender<PublicKey, TClock>;
    type Receiver = Receiver<PublicKey>;

    fn blocker(&self) -> Self::Blocker {
        self.oracle.control(self.public_key.clone())
    }

    fn peer_manager(&self) -> Self::PeerManager {
        self.oracle.socket_manager()
    }

    async fn register_channels(
        &mut self,
    ) -> eyre::Result<Channels<Self::Sender, Self::Receiver>> {
        let ctrl = self.oracle.control(self.public_key.clone());

        let votes = ctrl
            .register(VOTES_CHANNEL_IDENT, VOTES_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register votes channel: {e:?}"))?;
        let certificates = ctrl
            .register(CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register certificates channel: {e:?}"))?;
        let resolver = ctrl
            .register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register resolver channel: {e:?}"))?;
        let broadcaster = ctrl
            .register(BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register broadcaster channel: {e:?}"))?;
        let marshal = ctrl
            .register(MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register marshal channel: {e:?}"))?;
        let dkg = ctrl
            .register(DKG_CHANNEL_IDENT, DKG_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register dkg channel: {e:?}"))?;
        let subblocks = ctrl
            .register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT)
            .await
            .map_err(|e| eyre::eyre!("failed to register subblocks channel: {e:?}"))?;

        Ok(Channels {
            votes,
            certificates,
            resolver,
            broadcaster,
            marshal,
            dkg,
            subblocks,
        })
    }
}
