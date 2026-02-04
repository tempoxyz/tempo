//! Production P2P network implementation.

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::authenticated::lookup::{self, Receiver, Sender};
use commonware_runtime::{Handle, tokio::Context};

use super::{Channels, P2pNetwork};
use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, RESOLVER_CHANNEL_IDENT,
    RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

/// Tempo P2P network.
///
/// Implements [`P2pNetwork`] to provide channel registration and peer management
/// for the consensus engine.
///
/// 1. Build with [`TempoNetworkBuilder::build`](super::TempoNetworkBuilder::build).
/// 2. Call [`register_channels`](P2pNetwork::register_channels) to obtain channel pairs.
/// 3. Use [`blocker`](P2pNetwork::blocker) and [`peer_manager`](P2pNetwork::peer_manager)
///    for the consensus engine.
/// 4. Call [`start`](TempoNetwork::start) and run it in `tokio::select!` with the engine.
pub struct TempoNetwork {
    pub(super) network: lookup::Network<Context, PrivateKey>,
    pub(super) oracle: lookup::Oracle<PublicKey>,
    pub(super) message_backlog: usize,
}

impl TempoNetwork {
    /// Starts the network task and returns its handle.
    ///
    /// Consumes `self`. Run the returned handle in `tokio::select!` with the
    /// consensus engine.
    pub fn start(self) -> Handle<()> {
        self.network.start()
    }
}

impl P2pNetwork for TempoNetwork {
    type Blocker = lookup::Oracle<PublicKey>;
    type PeerManager = lookup::Oracle<PublicKey>;
    type Sender = Sender<PublicKey, Context>;
    type Receiver = Receiver<PublicKey>;

    fn blocker(&self) -> Self::Blocker {
        self.oracle.clone()
    }

    fn peer_manager(&self) -> Self::PeerManager {
        self.oracle.clone()
    }

    async fn register_channels(&mut self) -> eyre::Result<Channels<Self::Sender, Self::Receiver>> {
        let b = self.message_backlog;
        let n = &mut self.network;
        Ok(Channels {
            votes: n.register(VOTES_CHANNEL_IDENT, VOTES_LIMIT, b),
            certificates: n.register(CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT, b),
            resolver: n.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, b),
            broadcaster: n.register(BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, b),
            marshal: n.register(MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, b),
            dkg: n.register(DKG_CHANNEL_IDENT, DKG_LIMIT, b),
            subblocks: n.register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, b),
        })
    }
}
