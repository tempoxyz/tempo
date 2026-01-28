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
pub(crate) mod network;
pub mod node;
pub(crate) mod utils;

pub(crate) mod subblocks;

use commonware_runtime::Metrics as _;
use eyre::{OptionExt, WrapErr as _, eyre};
use tempo_node::TempoFullNode;

pub use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, RESOLVER_CHANNEL_IDENT,
    RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

pub use args::Args;
pub use node::{ConsensusNode, ConsensusNodeBuilder, ConsensusNodeHandle};

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: Args,
    execution_node: TempoFullNode,
    feed_state: feed::FeedStateHandle,
) -> eyre::Result<()> {
    let share = config.signing_share()?;

    let signing_key = config
        .signing_key()?
        .ok_or_eyre("required option `consensus.signing-key` not set")?;

    let mut net = network::TempoNetworkBuilder::default()
        .with_signing_key(signing_key.clone().into_inner())
        .with_listen_address(config.listen_address)
        .with_mailbox_size(config.mailbox_size)
        .with_max_message_size(config.max_message_size_bytes)
        .with_bypass_ip_check(config.bypass_ip_check)
        .with_use_local_defaults(config.use_local_defaults)
        .with_message_backlog(config.message_backlog)
        .build(context)
        .wrap_err("failed to build network")?;

    let channels = net.register_channels();
    let oracle = net.oracle().clone();

    let consensus_engine = crate::consensus::EngineBuilder::default()
        .with_fee_recipient(
            config
                .fee_recipient
                .ok_or_eyre("required option `consensus.fee-recipient` not set")?,
        )
        .with_execution_node(execution_node)
        .with_oracle(oracle)
        .with_signer(signing_key)
        .with_share(share)
        .with_mailbox_size(config.mailbox_size)
        .with_deque_size(config.deque_size)
        .with_time_to_propose(config.wait_for_proposal)?
        .with_time_to_collect_notarizations(config.wait_for_notarizations)?
        .with_time_to_retry_nullify_broadcast(config.wait_to_rebroadcast_nullify)?
        .with_time_for_peer_response(config.wait_for_peer_response)?
        .with_views_to_track(config.views_to_track)
        .with_views_until_leader_skip(config.inactive_views_until_leader_skip)
        .with_new_payload_wait_time(config.time_to_build_proposal)?
        .with_time_to_build_subblock(config.time_to_build_subblock)?
        .with_subblock_broadcast_interval(config.subblock_broadcast_interval)?
        .with_fcu_heartbeat_interval(config.fcu_heartbeat_interval)?
        .with_feed_state(feed_state)
        .try_init(context.with_label("engine"))
        .await
        .wrap_err("failed initializing consensus engine")?;

    let (network_handle, consensus_engine) = (
        net.start(),
        consensus_engine.start(
            channels.votes,
            channels.certificates,
            channels.resolver,
            channels.broadcaster,
            channels.marshal,
            channels.dkg,
            channels.subblocks,
        ),
    );

    tokio::select! {
        ret = network_handle => {
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
