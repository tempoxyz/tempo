//! Tempo commonware P2P network: builder, network, and channel registration.
//!
//! Encapsulates the lifecycle: build from config → register consensus channels →
//! start the network task. Keeps the same execution model as before (network and
//! consensus in the same async context).

use std::net::SocketAddr;

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::authenticated::lookup::{self, Receiver, Sender};
use commonware_runtime::{Handle, Metrics, tokio::Context};
use eyre::ContextCompat;

use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, PEERSETS_TO_TRACK,
    RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT,
    VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

/// Builder for configuring and constructing a [`TempoNetwork`].
///
///
/// Set all required fields via `with_*` setters, then call [`build`](TempoNetworkBuilder::build).
#[derive(Default)]
pub(crate) struct TempoNetworkBuilder {
    signing_key: Option<PrivateKey>,
    listen_address: Option<SocketAddr>,
    mailbox_size: Option<usize>,
    max_message_size: Option<u32>,
    bypass_ip_check: Option<bool>,
    use_local_defaults: Option<bool>,
    message_backlog: Option<usize>,
}

impl TempoNetworkBuilder {
    #[must_use]
    pub(crate) fn with_signing_key(mut self, signing_key: PrivateKey) -> Self {
        self.signing_key = Some(signing_key);
        self
    }

    #[must_use]
    pub(crate) const fn with_listen_address(mut self, listen_address: SocketAddr) -> Self {
        self.listen_address = Some(listen_address);
        self
    }

    #[must_use]
    pub(crate) const fn with_mailbox_size(mut self, mailbox_size: usize) -> Self {
        self.mailbox_size = Some(mailbox_size);
        self
    }

    #[must_use]
    pub(crate) const fn with_max_message_size(mut self, max_message_size: u32) -> Self {
        self.max_message_size = Some(max_message_size);
        self
    }

    #[must_use]
    pub(crate) const fn with_bypass_ip_check(mut self, bypass_ip_check: bool) -> Self {
        self.bypass_ip_check = Some(bypass_ip_check);
        self
    }

    #[must_use]
    pub(crate) const fn with_use_local_defaults(mut self, use_local_defaults: bool) -> Self {
        self.use_local_defaults = Some(use_local_defaults);
        self
    }

    #[must_use]
    pub(crate) const fn with_message_backlog(mut self, message_backlog: usize) -> Self {
        self.message_backlog = Some(message_backlog);
        self
    }

    /// Build the network from this builder.
    ///
    /// Validates all required fields and returns a configured [`TempoNetwork`].
    /// Call [`register_channels`](TempoNetwork::register_channels) on the result
    /// before [`start`](TempoNetwork::start).
    ///
    /// # Errors
    /// Returns an error if any required field is missing.
    pub(crate) fn build(self, context: &Context) -> eyre::Result<TempoNetwork> {
        let signing_key = self
            .signing_key
            .context("signing key is required - call with_signing_key()")?;
        let listen_address = self
            .listen_address
            .context("listen address is required - call with_listen_address()")?;
        let mailbox_size = self
            .mailbox_size
            .context("mailbox size is required - call with_mailbox_size()")?;
        let max_message_size = self
            .max_message_size
            .context("max message size is required - call with_max_message_size()")?;
        let bypass_ip_check = self
            .bypass_ip_check
            .context("bypass_ip_check is required - call with_bypass_ip_check()")?;
        let use_local_defaults = self
            .use_local_defaults
            .context("use_local_defaults is required - call with_use_local_defaults()")?;
        let message_backlog = self
            .message_backlog
            .context("message backlog is required - call with_message_backlog()")?;

        let p2p_namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
        let default_config = if use_local_defaults {
            lookup::Config::local(
                signing_key,
                &p2p_namespace,
                listen_address,
                max_message_size,
            )
        } else {
            lookup::Config::recommended(
                signing_key,
                &p2p_namespace,
                listen_address,
                max_message_size,
            )
        };
        let p2p_cfg = lookup::Config {
            mailbox_size,
            tracked_peer_sets: PEERSETS_TO_TRACK,
            bypass_ip_check,
            ..default_config
        };

        let (network, oracle) = lookup::Network::new(context.with_label("network"), p2p_cfg);

        Ok(TempoNetwork {
            network,
            oracle,
            message_backlog,
        })
    }
}

/// Tempo commonware P2P network before start.
///
/// 1. Build with [`TempoNetworkBuilder::build`].
/// 2. Call [`register_channels`](TempoNetwork::register_channels) to obtain channel pairs.
/// 3. Pass [`oracle`](TempoNetwork::oracle) to the consensus engine and channels to
///    `Engine::start`.
/// 4. Call [`start`](TempoNetwork::start) and run it in `tokio::select!` with the engine.
pub(crate) struct TempoNetwork {
    network: lookup::Network<Context, PrivateKey>,
    oracle: lookup::Oracle<PublicKey>,
    message_backlog: usize,
}

type TempoChannel = (Sender<PublicKey, Context>, Receiver<PublicKey>);

impl TempoNetwork {
    /// Registers all consensus P2P channels and returns them.
    ///
    /// Must be called exactly once before [`start`](TempoNetwork::start).
    pub(crate) fn register_channels(&mut self) -> TempoNetworkChannels {
        let b = self.message_backlog;
        let n = &mut self.network;
        TempoNetworkChannels {
            votes: n.register(VOTES_CHANNEL_IDENT, VOTES_LIMIT, b),
            certificates: n.register(CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT, b),
            resolver: n.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, b),
            broadcaster: n.register(BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, b),
            marshal: n.register(MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, b),
            dkg: n.register(DKG_CHANNEL_IDENT, DKG_LIMIT, b),
            subblocks: n.register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, b),
        }
    }

    /// Returns a reference to the oracle (blocker / peer manager).
    pub(crate) fn oracle(&self) -> &lookup::Oracle<PublicKey> {
        &self.oracle
    }

    /// Starts the network task and returns its handle.
    ///
    /// Consumes `self`. Run the returned handle in `tokio::select!` with the
    /// consensus engine.
    pub(crate) fn start(self) -> Handle<()> {
        self.network.start()
    }
}

/// All consensus P2P channel pairs.
///
/// Obtained from [`TempoNetwork::register_channels`] and passed into
/// [`Engine::start`](crate::consensus::engine::Engine::start).
pub(crate) struct TempoNetworkChannels {
    pub(crate) votes: TempoChannel,
    pub(crate) certificates: TempoChannel,
    pub(crate) resolver: TempoChannel,
    pub(crate) broadcaster: TempoChannel,
    pub(crate) marshal: TempoChannel,
    pub(crate) dkg: TempoChannel,
    pub(crate) subblocks: TempoChannel,
}
