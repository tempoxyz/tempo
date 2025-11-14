//! A Tempo node using commonware's threshold simplex as consensus.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub(crate) mod alias;
pub(crate) mod config;
pub mod consensus;
pub(crate) mod dkg;
pub(crate) mod epoch;
pub mod metrics;

pub(crate) mod subblocks;

use std::{net::SocketAddr, path::Path};

use commonware_codec::{DecodeExt, IsUnit};
use commonware_cryptography::{
    bls12381::primitives::group::Share,
    ed25519::{PrivateKey, PublicKey},
};
use commonware_p2p::authenticated::lookup;
use commonware_runtime::Metrics as _;
use eyre::{WrapErr as _, eyre};
use reth_chainspec::EthChainSpec;
use tempo_node::TempoFullNode;
use tracing::info;

use crate::config::{
    BOUNDARY_CERT_CHANNEL_IDENT, BOUNDARY_CERT_LIMIT, BROADCASTER_CHANNEL_IDENT, BROADCASTER_LIMIT,
    DKG_CHANNEL_IDENT, DKG_LIMIT, MARSHAL_CHANNEL_IDENT, MARSHAL_LIMIT, PEERSETS_TO_TRACK,
    PENDING_CHANNEL_IDENT, PENDING_LIMIT, RECOVERED_CHANNEL_IDENT, RECOVERED_LIMIT,
    RESOLVER_CHANNEL_IDENT, RESOLVER_LIMIT, SUBBLOCKS_CHANNEL_IDENT, SUBBLOCKS_LIMIT,
};

pub async fn run_consensus_stack(
    context: &commonware_runtime::tokio::Context,
    config: &tempo_consensus_args::ConsensusArgs,
    execution_node: TempoFullNode,
) -> eyre::Result<()> {
    let share = config
        .share
        .as_ref()
        .map(|share| {
            read_from_file::<Share, _, _>(share).wrap_err_with(|| {
                format!(
                    "failed reading private bls12-381 key share from file `{}`",
                    share.display()
                )
            })
        })
        .transpose()?;

    let signing_key =
        read_from_file::<PrivateKey, _, _>(&config.signing_key).wrap_err_with(|| {
            format!(
                "failed reading private ed25519 signing key share from file `{}`",
                config.signing_key.display()
            )
        })?;

    let (mut network, oracle) = instantiate_network(
        context,
        signing_key.clone(),
        config.listen_address,
        config.mailbox_size,
        config.max_message_size_bytes,
    )
    .await
    .wrap_err("failed to start network")?;

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

    let fee_recipient = config.fee_recipient.unwrap_or_else(|| {
        // FIXME: outside of root span; put in root span.
        info!("argument fee-recipient not set; using coinbase set in genesis");
        execution_node.chain_spec().genesis().coinbase
    });

    let consensus_engine = crate::consensus::engine::Builder {
        context: context.with_label("engine"),

        fee_recipient,

        execution_node,
        blocker: oracle.clone(),
        peer_manager: oracle.clone(),
        // TODO: Set this through config?
        partition_prefix: "engine".into(),
        signer: signing_key,
        share: share,
        mailbox_size: config.mailbox_size,
        deque_size: config.deque_size,

        time_to_propose: config.wait_for_proposal.try_into().wrap_err(
            "failed converting argument wait-for-proposal to regular duration; \
            was it negative or chosen too large?",
        )?,
        time_to_collect_notarizations: config.wait_for_notarizations.try_into().wrap_err(
            "failed converting argument wait-for-notarizations to regular \
            duration; was it negative or chosen too large",
        )?,
        time_to_retry_nullify_broadcast: config.wait_to_rebroadcast_nullify.try_into().wrap_err(
            "failed converting argument wait-to-rebroadcast-nullify to regular \
            duration; was it negative or chosen too large",
        )?,
        time_for_peer_response: config.wait_for_peer_response.try_into().wrap_err(
            "failed converting argument wait-for-peer-response to regular \
            duration; was it negative or chosen too large",
        )?,
        views_to_track: config.views_to_track,
        views_until_leader_skip: config.inactive_views_until_leader_skip,
        new_payload_wait_time: config.time_to_build_proposal.try_into().wrap_err(
            "failed converting argument time-to-build-proposal to regular \
            duration; was it negative or chosen too large",
        )?,
        time_to_build_subblock: config.time_to_build_subblock.try_into().wrap_err(
            "failed converting argument time-to-build-subblock to regular \
            duration; was it negative or chosen too large",
        )?,
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
    signing_key: PrivateKey,
    listen_addr: SocketAddr,
    mailbox_size: usize,
    max_message_size: usize,
) -> eyre::Result<(
    lookup::Network<commonware_runtime::tokio::Context, PrivateKey>,
    lookup::Oracle<PublicKey>,
)> {
    // TODO: Find out why `union_unique` should be used at all. This is the only place
    // where `NAMESPACE` is used at all. We follow alto's example for now.
    let p2p_namespace = commonware_utils::union_unique(crate::config::NAMESPACE, b"_P2P");
    let p2p_cfg = lookup::Config {
        mailbox_size,
        tracked_peer_sets: PEERSETS_TO_TRACK,
        ..lookup::Config::local(signing_key, &p2p_namespace, listen_addr, max_message_size)
    };

    Ok(lookup::Network::new(context.with_label("network"), p2p_cfg))
}

fn read_from_file<T: DecodeExt<X>, X: IsUnit, P: AsRef<Path>>(path: P) -> eyre::Result<T> {
    let raw_bytes = std::fs::read(path).wrap_err("failed reading file")?;
    let decoded = const_hex::decode(&raw_bytes).wrap_err("failed decoding file contents as hex")?;
    let obj = T::decode(&decoded[..]).wrap_err("failed parsing hex-decoded file contents")?;
    Ok(obj)
}
