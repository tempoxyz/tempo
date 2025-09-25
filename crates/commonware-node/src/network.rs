use commonware_cryptography::Signer;
use commonware_p2p::authenticated::discovery::{
    self, Receiver as CommonwareP2PRx, Sender as CommonwareP2PTx,
};
use commonware_runtime::Metrics as _;
use eyre::{WrapErr as _, bail, eyre};
use futures_util::stream::{FuturesOrdered, TryStreamExt as _};
use indexmap::IndexMap;
use std::net::{Ipv4Addr, SocketAddr};
use tracing::info;

use crate::config::{
    BACKFILL_BY_DIGEST_CHANNE_IDENTL, BACKFILL_QUOTA, BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT,
    PENDING_CHANNEL_IDENT, PENDING_LIMIT, RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT,
    RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT,
};
use tempo_commonware_node_cryptography::{PrivateKey, PublicKey};

pub struct CommonwareNetworkHandle {
    pub network: discovery::Network<commonware_runtime::tokio::Context, PrivateKey>,
    pub pending: (CommonwareP2PTx<PublicKey>, CommonwareP2PRx<PublicKey>),
    pub recovered: (CommonwareP2PTx<PublicKey>, CommonwareP2PRx<PublicKey>),
    pub resolver: (CommonwareP2PTx<PublicKey>, CommonwareP2PRx<PublicKey>),
    pub broadcaster: (CommonwareP2PTx<PublicKey>, CommonwareP2PRx<PublicKey>),
    pub backfill: (CommonwareP2PTx<PublicKey>, CommonwareP2PRx<PublicKey>),
}

impl CommonwareNetworkHandle {
    pub async fn new(
        context: &commonware_runtime::tokio::Context,
        config: &tempo_commonware_node_config::Config,
    ) -> eyre::Result<(
        Self,
        discovery::Oracle<commonware_runtime::tokio::Context, PublicKey>,
    )> {
        let (mut network, mut oracle) = init_network(context, config)
            .await
            .wrap_err("failed to start network")?;

        oracle
            .register(0, config.peers.keys().cloned().collect())
            .await;

        let message_backlog = config.message_backlog;
        let pending = network.register(PENDING_CHANNEL_IDENT, PENDING_LIMIT, message_backlog);
        let recovered = network.register(RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT, message_backlog);
        let resolver = network.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, message_backlog);
        let broadcaster = network.register(
            BROADCASTER_CHANNEL_IDENT,
            BROADCASTER_LIMIT,
            message_backlog,
        );
        let backfill = network.register(
            BACKFILL_BY_DIGEST_CHANNE_IDENTL,
            BACKFILL_QUOTA,
            message_backlog,
        );

        Ok((
            Self {
                network,
                pending,
                recovered,
                resolver,
                broadcaster,
                backfill,
            },
            oracle,
        ))
    }

    pub async fn run(self) -> eyre::Result<()> {
        self.network
            .start()
            .await
            .map_err(eyre::Report::from)
            .and_then(|()| Err(eyre!("exited unexpectedly")))
            .wrap_err("network task failed")
    }
}

pub async fn init_network(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
) -> eyre::Result<(
    discovery::Network<commonware_runtime::tokio::Context, PrivateKey>,
    discovery::Oracle<commonware_runtime::tokio::Context, PublicKey>,
)> {
    let my_public_key = config.signer.public_key();
    let all_resolved_peers = resolve_all_peers(&config.peers)
        .await
        .wrap_err("failed resolving peers")?;

    let Some((_, my_addr)) = all_resolved_peers.get(&config.signer.public_key()) else {
        bail!(
            "peers entry does not contain an entry for this node's public key (generated from the signer key): `{my_public_key}`"
        )
    };

    // TODO: rework this entire peer and bootstrapper resolution so that it
    // becomes clear that bootstrappers fall out of the peers && get their
    // addresses that way.
    let bootstrappers = config
    .bootstrappers()
    .map(|(key, _dns_name)| {
        let addr = all_resolved_peers
        .get(&key)
        .expect("all bootstrappers must have a resolved IP; if that's not the case an invariant of the function was violated")
        .1;
        (key, addr)
    }).collect();

    // TODO: Find out why `union_unique` should be used at all. This is the only place
    // where `NAMESPACE` is used at all. We follow alto's example for now.
    let p2p_namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    let p2p_cfg = discovery::Config {
        mailbox_size: config.mailbox_size,
        ..discovery::Config::aggressive(
            config.signer.clone(),
            &p2p_namespace,
            // TODO: should the listen addr be restricted to ipv4?
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), config.listen_port),
            SocketAddr::new(my_addr.ip(), config.listen_port),
            bootstrappers,
            crate::config::MAX_MESSAGE_SIZE_BYTES,
        )
    };

    Ok(discovery::Network::new(
        context.with_label("network"),
        p2p_cfg,
    ))
}

async fn resolve_all_peers(
    peers: impl IntoIterator<Item = (&PublicKey, &String)>,
) -> eyre::Result<IndexMap<PublicKey, (String, SocketAddr)>> {
    let resolve_all = peers
        .into_iter()
        .map(|(peer, name)| async move {
            // XXX: collecting every single result isn't exactly efficient, but
            // we only do it once at startup, so w/e.
            let addrs = tokio::net::lookup_host(name)
                .await
                .wrap_err_with(|| {
                    format!("failed looking up IP of peer `{peer}` for DNS name `{name}`")
                })?
                .collect::<Vec<_>>();
            info!(
                %peer,
                name,
                potential_addresses = ?addrs,
                "resolved DNS name to IPs; taking the first one"
            );
            let addr = addrs.first().ok_or_else(|| {
                eyre!("peer `{peer}` with DNS name `{name}` resolved to zero addresses")
            })?;
            Ok::<_, eyre::Report>((peer.clone(), (name.clone(), *addr)))
        })
        .collect::<FuturesOrdered<_>>();
    resolve_all
        .try_collect::<IndexMap<_, _>>()
        .await
        .wrap_err("failed resolving at least one peer")
}
