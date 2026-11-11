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
pub mod finalization_verifier;
pub mod finalized_header_stream;
pub mod follow;
pub mod gossip;
pub mod metrics;
mod network;
pub(crate) mod network_identity;
pub(crate) mod peer_manager;
pub(crate) mod startup;
pub mod storage;
#[cfg(test)]
pub(crate) mod test_utils;
pub(crate) mod utils;
pub(crate) mod validators;

use std::sync::Arc;

use commonware_consensus::types::FixedEpocher;
use commonware_runtime::Supervisor as _;
use eyre::{OptionExt, WrapErr as _, eyre};
use tempo_consensus_config::SigningShare;
use tempo_node::TempoFullNode;
use tracing::{info, warn};

pub use crate::config::{
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, NAMESPACE,
    RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, VOTES_CHANNEL_IDENT, VOTES_LIMIT,
};

pub use args::{Args, PositiveDuration, VerificationMode};

// Shared by both the consensus and follow engines such that
// snapshots for overlapping archives can be reused.
pub const PARTITION_PREFIX: &str = "engine";

const MAINNET_TESTNET_EPOCH_LENGTH_BLOCKS: u64 = 21_600;

/// Tempo's peer sync window: nodes up to three mainnet/testnet epochs behind
/// the finalized tip should be able to sync from peers.
pub const MINIMAL_PEER_SYNC_FINALIZED_BLOCKS: u64 = 3 * MAINNET_TESTNET_EPOCH_LENGTH_BLOCKS;

/// Starts consensus using `estimator` as the authority for proposal pacing.
///
/// The estimator must be shared with the payload builder. Timing fields in
/// `config` seed that estimator at the launch boundary; this function does not
/// apply them again, so an explicit estimator override takes precedence.
pub async fn run_consensus_stack(
    context: commonware_runtime::tokio::Context,
    config: Args,
    execution_node: Arc<TempoFullNode>,
    executed_state: tempo_node::ExecutedState,
    feed_state: feed::FeedStateHandle,
    gossip_transport: Option<tempo_node::gossip::TransportHandle>,
    estimator: tempo_payload_types::Estimator,
) -> eyre::Result<()> {
    config.validate_simplex_timing()?;

    let network_identity = config
        .network_identity()
        .or_else(|| execution_node.chain_spec().network_identity.clone())
        .ok_or_eyre("chainspec has no network identity and none was configured")?;

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
        .signing_key()
        .await?
        .ok_or_eyre("required option `consensus.signing-key` not set")?;

    if let Some(ignored) = config.max_message_size_bytes {
        warn!(
            ignored,
            "--consensus.max-message-size-bytes is deprecated and ignored; the p2p message size \
             limit is derived from the largest consensus payload"
        );
    }

    let backfill_quota = commonware_runtime::Quota::per_second(config.backfill_frequency);
    let max_message_size = network::max_message_size(config.max_peers_per_set);

    let (mut network, oracle) = network::instantiate(
        &context,
        &config,
        signing_key.clone().into_inner(),
        max_message_size,
    )
    .await
    .wrap_err("failed to start network")?;

    let votes = network.register(VOTES_CHANNEL_IDENT, VOTES_LIMIT);
    let certificates = network.register(CERTIFICATES_CHANNEL_IDENT, CERTIFICATES_LIMIT);
    let resolver = network.register(RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT);
    let broadcaster = network.register(BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT);
    let marshal = network.register(MARSHAL_CHANNEL_IDENT, backfill_quota);
    let dkg = network.register(DKG_CHANNEL_IDENT, DKG_LIMIT);
    let consensus_engine = crate::consensus::engine::Builder {
        network_identity,
        execution_node: Some(execution_node),
        executed_state,
        gossip: gossip_transport.map(|transport| gossip::Config {
            transport,
            verify_rate: config.gossip_verify_rate,
        }),
        blocker: oracle.clone(),
        peer_manager: oracle.clone(),

        // TODO: Set this through config?
        partition_prefix: PARTITION_PREFIX.into(),
        signer: signing_key.into_inner(),
        share,

        mailbox_size: config.mailbox_size,
        max_peers: config.max_peers_per_set,
        deque_size: config.deque_size,
        verification_mode: config.verification_mode,

        time_to_propose: config.wait_for_proposal.into_duration(),
        time_to_collect_notarizations: config.wait_for_notarizations.into_duration(),
        time_to_retry_nullify_broadcast: config.wait_to_rebroadcast_nullify.into_duration(),
        time_for_peer_response: config.wait_for_peer_response.into_duration(),
        views_to_track: config.views_to_track,
        inactive_time_before_leader_skip: config.inactive_time_before_leader_skip.into_duration(),
        estimator,
        fcu_heartbeat_interval: config.fcu_heartbeat_interval.into_duration(),

        feed_state,

        finalized_blocks_retention: config.finalized_blocks_retention,
    }
    .try_init(context.child("engine"))
    .await
    .wrap_err("failed initializing consensus engine")?;

    let (network, consensus_engine) = (
        network.start(),
        consensus_engine.start(votes, certificates, resolver, broadcaster, marshal, dkg),
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

/// Run the follower stack. This uses RPC to sync consensus state and drive
/// the execution layer from the upstream node.
pub async fn run_follow_stack(
    context: commonware_runtime::tokio::Context,
    config: Args,
    upstream_url: String,
    upstream_request_timeout: std::time::Duration,
    execution_node: Arc<TempoFullNode>,
    feed_state: feed::FeedStateHandle,
    gossip_transport: Option<tempo_node::gossip::TransportHandle>,
) -> eyre::Result<()> {
    let chain_spec = execution_node.chain_spec();

    let epoch_length = chain_spec
        .info
        .epoch_length()
        .ok_or_eyre("chainspec did not contain epochLength")?;

    let chain_spec_network_identity = chain_spec
        .network_identity
        .clone()
        .ok_or_eyre("chainspec has no dkg outcome in genesis header")?;

    let network_identity = config
        .network_identity()
        .unwrap_or(chain_spec_network_identity);

    info!(%network_identity.from_epoch, %network_identity.identity, "registered network identity");

    let (upstream, upstream_mailbox) = crate::follow::upstream::init(
        context.child("upstream"),
        crate::follow::upstream::Config { upstream_url },
    )
    .wrap_err("failed to initialize client to upstream node")?;

    let follow_engine = follow::Config {
        execution_node,
        gossip: gossip_transport.map(|transport| gossip::Config {
            transport,
            verify_rate: config.gossip_verify_rate,
        }),
        feed_state,
        upstream,
        upstream_mailbox,
        network_identity,
        partition_prefix: PARTITION_PREFIX.into(),
        epoch_strategy: FixedEpocher::new(epoch_length),
        mailbox_size: config.mailbox_size,
        upstream_request_timeout,
        fcu_heartbeat_interval: config.fcu_heartbeat_interval.into_duration(),
        finalized_blocks_retention: config.finalized_blocks_retention,
    };

    let ret = follow_engine
        .try_init(context.child("engine"))
        .await
        .wrap_err("failed initializing follow engine")?
        .start()
        .await;

    ret.map_err(eyre::Report::from)
        .and_then(|ret| ret.and_then(|()| Err(eyre!("exited unexpectedly"))))
        .wrap_err("follow engine task failed")
}
