//! A Tempo node using commonware's threshold simplex as consensus.

pub mod config;
pub mod consensus;

use std::net::SocketAddr;

use commonware_cryptography::Signer;
use commonware_p2p::authenticated::discovery;
use commonware_runtime::{Handle, Metrics as _};
use eyre::{WrapErr as _, eyre};
use tempo_node::TempoFullNode;

use crate::config::{
    BACKFILL_BY_DIGEST_CHANNE_IDENTL, BACKFILL_QUOTA, BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
    BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT, FETCH_TIMEOUT,
    FINALIZED_FREEZER_TABLE_INITIAL_SIZE_BYTES, LEADER_TIMEOUT, MAX_FETCH_SIZE_BYTES,
    NOTARIZATION_TIMEOUT, NUMBER_CONCURRENT_FETCHES, NUMBER_MAX_FETCHES, NUMBER_OF_VIEWS_TO_TRACK,
    NUMBER_OF_VIEWS_UNTIL_LEADER_SKIP, PENDING_CHANNEL_IDENT, PENDING_LIMIT,
    RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT, RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT,
    TIME_TO_NULLIFY_RETRY,
};
use tempo_commonware_node_cryptography::{PrivateKey, PublicKey};

pub struct ConsensusStack {
    pub network: Handle<()>,
    pub consensus_engine: Handle<eyre::Result<()>>,
}

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
    execution_node: TempoFullNode,
) -> eyre::Result<()> {
    let (mut network, mut oracle) =
        instantiate_network(context, config).wrap_err("failed to start network")?;

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

    let consensus_engine = crate::consensus::engine::Builder {
        context: context.with_label("engine"),

        fee_recipient: config.fee_recipient,

        execution_node,
        blocker: oracle,
        // TODO: Set this through config?
        partition_prefix: "engine".into(),
        blocks_freezer_table_initial_size: BLOCKS_FREEZER_TABLE_INITIAL_SIZE_BYTES,
        finalized_freezer_table_initial_size: FINALIZED_FREEZER_TABLE_INITIAL_SIZE_BYTES,
        signer: config.signer.clone(),
        polynomial: config.polynomial.clone(),
        share: config.share.clone(),
        participants: config.peers.keys().cloned().collect::<Vec<_>>(),
        mailbox_size: config.mailbox_size,
        backfill_quota: BACKFILL_QUOTA,
        deque_size: config.deque_size,

        leader_timeout: LEADER_TIMEOUT,
        notarization_timeout: NOTARIZATION_TIMEOUT,
        nullify_retry: TIME_TO_NULLIFY_RETRY,
        fetch_timeout: FETCH_TIMEOUT,
        activity_timeout: NUMBER_OF_VIEWS_TO_TRACK,
        skip_timeout: NUMBER_OF_VIEWS_UNTIL_LEADER_SKIP,
        max_fetch_count: NUMBER_MAX_FETCHES,
        max_fetch_size: MAX_FETCH_SIZE_BYTES,
        fetch_concurrent: NUMBER_CONCURRENT_FETCHES,
        fetch_rate_per_peer: RESOLVER_LIMIT,
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

fn instantiate_network(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_commonware_node_config::Config,
) -> eyre::Result<(
    discovery::Network<commonware_runtime::tokio::Context, PrivateKey>,
    discovery::Oracle<commonware_runtime::tokio::Context, PublicKey>,
)> {
    use commonware_p2p::authenticated::discovery;
    use std::net::Ipv4Addr;

    let my_public_key = config.signer.public_key();
    let my_ip = config.peers.get(&config.signer.public_key()).ok_or_else(||
        eyre!("peers entry does not contain an entry for this node's public key (generated from the signer key): `{my_public_key}`")
    )?.ip();

    let bootstrappers = config.bootstrappers().collect();

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
            SocketAddr::new(my_ip, config.listen_port),
            bootstrappers,
            crate::config::MAX_MESSAGE_SIZE_BYTES,
        )
    };

    Ok(discovery::Network::new(
        context.with_label("network"),
        p2p_cfg,
    ))
}
