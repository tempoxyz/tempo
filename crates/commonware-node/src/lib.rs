//! A Tempo node using commonware's threshold simplex as consensus.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod alias;
mod args;
pub(crate) mod config;
pub mod consensus;
pub(crate) mod dkg;
pub(crate) mod epoch;
pub(crate) mod executor;
pub mod feed;
pub mod metrics;
pub(crate) mod peer_manager;
pub(crate) mod utils;
pub(crate) mod validators;

pub(crate) mod subblocks;

use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
use commonware_p2p::authenticated::lookup;
use commonware_runtime::Metrics as _;
use eyre::{OptionExt, WrapErr as _, eyre};
use tempo_commonware_node_config::SigningShare;
use tempo_node::TempoFullNode;

pub use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, NAMESPACE,
    RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT,
    VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

pub use args::{Args, PositiveDuration};

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: Args,
    execution_node: TempoFullNode,
    feed_state: feed::FeedStateHandle,
) -> eyre::Result<()> {
    let share = config
        .signing_share
        .as_ref()
        .map(|share| {
            SigningShare::read_from_file(share).wrap_err_with(|| {
                format!(
                    "failed reading private bls12-381 key share from file `{}`",
                    share.display()
                )
            })
        })
        .transpose()?
        .map(|signing_share| signing_share.into_inner());

    let signing_key = config
        .signing_key()?
        .ok_or_eyre("required option `consensus.signing-key` not set")?;

    let backfill_quota = commonware_runtime::Quota::per_second(config.backfill_frequency);

    let (mut network, oracle) =
        instantiate_network(context, &config, signing_key.clone().into_inner())
            .await
            .wrap_err("failed to start network")?;

    let message_backlog = config.message_backlog;
    let votes = network.register(VOTES_CHANNEL_IDENT, VOTES_LIMIT, message_backlog);
    let certificates = network.register(
        CERTIFICATES_CHANNEL_IDENT,
        CERTIFICATES_LIMIT,
        message_backlog,
    );
    let resolver = network.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, message_backlog);
    let broadcaster = network.register(
        BROADCASTER_CHANNEL_IDENT,
        BROADCASTER_LIMIT,
        message_backlog,
    );
    let marshal = network.register(MARSHAL_CHANNEL_IDENT, backfill_quota, message_backlog);
    let dkg = network.register(DKG_CHANNEL_IDENT, DKG_LIMIT, message_backlog);
    let subblocks = network.register(SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, message_backlog);

    let fee_recipient = config
        .fee_recipient
        .ok_or_eyre("required option `consensus.fee-recipient` not set")?;

    let consensus_engine = crate::consensus::engine::Builder {
        fee_recipient,

        execution_node: Some(execution_node),
        blocker: oracle.clone(),
        peer_manager: oracle.clone(),

        // TODO: Set this through config?
        partition_prefix: "engine".into(),
        signer: signing_key.into_inner(),
        share,

        mailbox_size: config.mailbox_size,
        deque_size: config.deque_size,

        time_to_propose: config.wait_for_proposal.into_duration(),
        time_to_collect_notarizations: config.wait_for_notarizations.into_duration(),
        time_to_retry_nullify_broadcast: config.wait_to_rebroadcast_nullify.into_duration(),
        time_for_peer_response: config.wait_for_peer_response.into_duration(),
        views_to_track: config.views_to_track,
        views_until_leader_skip: config.inactive_views_until_leader_skip,
        new_payload_wait_time: config.time_to_build_proposal.into_duration(),
        time_to_build_subblock: config.time_to_build_subblock.into_duration(),
        subblock_broadcast_interval: config.subblock_broadcast_interval.into_duration(),
        fcu_heartbeat_interval: config.fcu_heartbeat_interval.into_duration(),

        feed_state,
    }
    .try_init(context.with_label("engine"))
    .await
    .wrap_err("failed initializing consensus engine")?;

    let (network, consensus_engine) = (
        network.start(),
        consensus_engine.start(
            votes,
            certificates,
            resolver,
            broadcaster,
            marshal,
            dkg,
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
    config: &Args,
    signing_key: PrivateKey,
) -> eyre::Result<(
    lookup::Network<commonware_runtime::tokio::Context, PrivateKey>,
    lookup::Oracle<PublicKey>,
)> {
    // TODO: Find out why `union_unique` should be used. This is the only place
    // where `NAMESPACE` is used at all. We follow alto's example for now.
    let namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    let cfg = lookup::Config {
        namespace,
        crypto: signing_key,
        listen: config.listen_address,
        max_message_size: config.max_message_size_bytes,
        mailbox_size: config.mailbox_size,
        bypass_ip_check: config.bypass_ip_check,
        allow_private_ips: config.allow_private_ips,
        allow_dns: config.allow_dns,
        tracked_peer_sets: crate::config::PEERSETS_TO_TRACK,
        synchrony_bound: config.synchrony_bound.into_duration(),
        max_handshake_age: config.handshake_stale_after.into_duration(),
        handshake_timeout: config.handshake_timeout.into_duration(),
        max_concurrent_handshakes: config.max_concurrent_handshakes,
        block_duration: config.time_to_unblock_byzantine_peer.into_duration(),
        dial_frequency: config.wait_before_peers_redial.into_duration(),
        query_frequency: config.wait_before_peers_discovery.into_duration(),
        ping_frequency: config.wait_before_peers_reping.into_duration(),
        allowed_connection_rate_per_peer: commonware_runtime::Quota::with_period(
            config.connection_per_peer_min_period.into_duration(),
        )
        .ok_or_eyre("connection min period must be non-zero")?,
        allowed_handshake_rate_per_ip: commonware_runtime::Quota::with_period(
            config.handshake_per_ip_min_period.into_duration(),
        )
        .ok_or_eyre("handshake per ip min period must be non-zero")?,
        allowed_handshake_rate_per_subnet: commonware_runtime::Quota::with_period(
            config.handshake_per_subnet_min_period.into_duration(),
        )
        .ok_or_eyre("handshake per subnet min period must be non-zero")?,
    };

    Ok(lookup::Network::new(context.with_label("network"), cfg))
}
