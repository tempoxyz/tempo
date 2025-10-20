//! A Tempo node using commonware's threshold simplex as consensus.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub(crate) mod config;
pub mod consensus;
pub mod metrics;

use std::net::SocketAddr;

use commonware_cryptography::Signer;
use commonware_p2p::authenticated::discovery;
use commonware_runtime::Metrics as _;
use eyre::{WrapErr as _, bail, eyre};
use indexmap::IndexMap;
use tempo_node::TempoFullNode;
use tracing::info;

use crate::config::{
    BACKFILL_BY_DIGEST_CHANNEL_IDENTL, BACKFILL_QUOTA, BROADCASTER_CHANNEL_IDENT,
    BROADCASTER_LIMIT, PENDING_CHANNEL_IDENT, PENDING_LIMIT, RECOVERED_CHANNEL_IDENT,
    RECOVERED_LIMIT, RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT,
};
use tempo_commonware_node_cryptography::{PrivateKey, PublicKey};

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
    execution_node: TempoFullNode,
) -> eyre::Result<()> {
    let (mut network, mut oracle) = instantiate_network(context, config)
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
        BACKFILL_BY_DIGEST_CHANNEL_IDENTL,
        BACKFILL_QUOTA,
        message_backlog,
    );

    let consensus_engine = crate::consensus::engine::Builder {
        context: context.with_label("engine"),

        fee_recipient: config.fee_recipient,

        execution_node,
        blocker: oracle,
        // TODO: Set this through config?
        partition_prefix: "engine".into(),
        signer: config.signer.clone(),
        polynomial: config.polynomial.clone(),
        share: config.share.clone(),
        participants: config.peers.keys().cloned().collect::<Vec<_>>(),
        mailbox_size: config.mailbox_size,
        deque_size: config.deque_size,

        leader_timeout: config.timeouts.time_to_propose,
        notarization_timeout: config.timeouts.time_to_collect_notarizations,
        nullify_retry: config.timeouts.time_to_retry_nullify_broadcast,
        fetch_timeout: config.timeouts.time_for_peer_response,
        activity_timeout: config.timeouts.views_to_track,
        skip_timeout: config.timeouts.views_until_leader_skip,
        new_payload_wait_time: config.timeouts.new_payload_wait_time,
        // indexer: Option<TIndexer>,
    }
    .try_init()
    .await
    .wrap_err("failed initializing consensus engine")?;

    let (network, consensus_engine) = (
        network.start(),
        consensus_engine.start(pending, recovered, resolver, broadcaster, backfill),
    );

    tokio::select! {
        ret = network => {
            ret.map_err(eyre::Report::from)
                .and_then(|()| Err(eyre!("exited unexpectedly")))
                .wrap_err("network task failed")
        }

        ret = consensus_engine => {
            ret.map_err(eyre::Report::from)
                .and_then(|ret| ret.and_then(|()| Err(eyre!("exited unexpectedly"))))
                .wrap_err("consensus engine task failed")
        }
    }
}

async fn instantiate_network(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
) -> eyre::Result<(
    discovery::Network<commonware_runtime::tokio::Context, PrivateKey>,
    discovery::Oracle<PublicKey>,
)> {
    use commonware_p2p::authenticated::discovery;
    use std::net::Ipv4Addr;

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
        ..discovery::Config::local(
            config.signer.clone(),
            &p2p_namespace,
            // TODO: should the listen addr be restricted to ipv4?
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), config.listen_port),
            SocketAddr::new(my_addr.ip(), config.listen_port),
            bootstrappers,
            config.p2p.max_message_size_bytes,
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
    use futures::stream::{FuturesOrdered, TryStreamExt as _};
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
