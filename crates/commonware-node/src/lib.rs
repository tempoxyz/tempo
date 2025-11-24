//! A Tempo node using commonware's threshold simplex as consensus.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod alias;
pub(crate) mod config;
pub mod consensus;
pub mod db;
pub mod dkg;
pub(crate) mod epoch;
pub mod metrics;

pub(crate) mod subblocks;

use std::net::SocketAddr;

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::{Manager as _, authenticated::lookup};
use commonware_runtime::Metrics as _;
use commonware_utils::set::OrderedAssociated;
use eyre::{WrapErr as _, eyre};
use tempo_node::TempoFullNode;
use tracing::info;

use crate::config::{
    BOUNDARY_CERT_CHANNEL_IDENT, BOUNDARY_CERT_LIMIT, BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, PENDING_CHANNEL_IDENT,
    PENDING_LIMIT, RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT, RESOLVER_CHANNEL_IDENT,
    RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT,
};

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
    execution_node: TempoFullNode,
) -> eyre::Result<()> {
    let (mut network, mut oracle) = instantiate_network(context, config)
        .await
        .wrap_err("failed to start network")?;

    let all_resolved_peers = resolve_all_peers(&config.peers)
        .await
        .wrap_err("failed resolving peers")?;

    oracle.update(0, all_resolved_peers).await;

    let message_backlog = config.message_backlog;
    let pending = network.register(PENDING_CHANNEL_IDENT, PENDING_LIMIT, message_backlog);
    let recovered = network.register(RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT, message_backlog);
    let resolver = network.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, message_backlog);
    let broadcaster = network.register(
        BROADCASTER_CHANNEL_IDENT,
        BROADCASTER_LIMIT,
        message_backlog,
    );
    let marshal = network.register(MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, message_backlog);
    let dkg = network.register(DKG_CHANNEL_IDENT, DKG_LIMIT, message_backlog);
    let boundary_certificates = network.register(
        BOUNDARY_CERT_CHANNEL_IDENT,
        BOUNDARY_CERT_LIMIT,
        message_backlog,
    );
    let subblocks = network.register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, message_backlog);

    let consensus_engine = crate::consensus::engine::Builder {
        context: context.with_label("engine"),

        fee_recipient: config.fee_recipient,

        execution_node,
        blocker: oracle.clone(),
        peer_manager: oracle.clone(),
        // TODO: Set this through config?
        partition_prefix: "engine".into(),
        signer: config.signer.clone(),
        polynomial: config.polynomial.clone(),
        share: config.share.clone(),
        participants: config.peers.keys().cloned().collect::<Vec<_>>().into(),
        mailbox_size: config.mailbox_size,
        deque_size: config.deque_size,

        epoch_length: config.epoch_length,

        time_to_propose: config.timeouts.time_to_propose,
        time_to_collect_notarizations: config.timeouts.time_to_collect_notarizations,
        time_to_retry_nullify_broadcast: config.timeouts.time_to_retry_nullify_broadcast,
        time_for_peer_response: config.timeouts.time_for_peer_response,
        views_to_track: config.timeouts.views_to_track,
        views_until_leader_skip: config.timeouts.views_until_leader_skip,
        new_payload_wait_time: config.timeouts.new_payload_wait_time,
        time_to_build_subblock: config.timeouts.time_to_build_subblock,
    }
    .try_init()
    .await
    .wrap_err("failed initializing consensus engine")?;

    let (network, consensus_engine) = (
        network.start(),
        consensus_engine.start(
            pending,
            recovered,
            resolver,
            broadcaster,
            marshal,
            dkg,
            boundary_certificates,
            subblocks,
        ),
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
    lookup::Network<commonware_runtime::tokio::Context, PrivateKey>,
    lookup::Oracle<PublicKey>,
)> {
    // TODO: Find out why `union_unique` should be used at all. This is the only place
    // where `NAMESPACE` is used at all. We follow alto's example for now.
    let p2p_namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    let p2p_cfg = lookup::Config {
        mailbox_size: config.mailbox_size,
        ..lookup::Config::local(
            config.signer.clone(),
            &p2p_namespace,
            config.listen_addr,
            config.p2p.max_message_size_bytes,
        )
    };

    Ok(lookup::Network::new(context.with_label("network"), p2p_cfg))
}

async fn resolve_all_peers(
    peers: impl IntoIterator<Item = (&PublicKey, &String)>,
) -> eyre::Result<OrderedAssociated<PublicKey, SocketAddr>> {
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
            Ok::<_, eyre::Report>((peer.clone(), *addr))
        })
        .collect::<FuturesOrdered<_>>();
    let resolved = resolve_all
        .try_collect::<Vec<(_, _)>>()
        .await
        .wrap_err("failed resolving at least one peer")?;
    Ok(resolved.into())
}
