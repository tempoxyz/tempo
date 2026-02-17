//! Follow mode engine that syncs from upstream via RPC.
//!
//! This module provides a minimal consensus-layer stack for follow mode:
//! - Marshal for storage and verification
//! - Executor for driving Reth
//! - FeedState for RPC serving
//! - FollowResolver for marshal's gap-repair
//! - Tip tracker for push-based finalization events
//!
//! The archive format is shared with the consensus engine (see [`crate::storage`])
//! so nodes can switch between validator and follower modes without data migration.

use std::{sync::Arc, time::Duration};

use commonware_broadcast::buffered;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    marshal,
    simplex::scheme::bls12381_threshold::vrf::Scheme,
    types::{Epocher as _, FixedEpocher, Height},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_parallel::Sequential;
use commonware_runtime::{Clock, Metrics, Pacer, Spawner, Storage};
use commonware_utils::channel::mpsc;
use eyre::{OptionExt as _, WrapErr as _};
use rand_08::{CryptoRng, Rng};
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoFullNode, rpc::consensus::Query};
use tracing::{info, info_span};

use super::{driver, resolver::FollowResolver, stubs, upstream::UpstreamNode};
use crate::{
    config::NAMESPACE,
    consensus::block::Block,
    epoch::SchemeProvider,
    executor, feed,
    feed::FeedStateHandle,
    storage::{self, REPLAY_BUFFER, WRITE_BUFFER},
};

/// Builder for the follow engine.
#[derive(Clone)]
pub struct Builder<U: UpstreamNode> {
    /// The execution node to drive.
    pub execution_node: TempoFullNode,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    /// Upstream node to sync from.
    pub upstream: Arc<U>,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Mailbox size for async channels.
    pub mailbox_size: usize,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,
}

impl<U: UpstreamNode> Builder<U> {
    /// Initialize all components and return an [`Engine`] ready to start.
    pub async fn try_init<TContext>(self, context: TContext) -> eyre::Result<Engine<TContext, U>>
    where
        TContext:
            Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
    {
        let scheme_provider = SchemeProvider::new();
        let page_cache_ref = storage::create_page_cache();

        let finalizations_by_height = storage::init_finalizations_archive(
            context.with_label("finalizations_by_height"),
            &self.partition_prefix,
            page_cache_ref.clone(),
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let finalized_blocks = storage::init_finalized_blocks_archive(
            context.with_label("finalized_blocks"),
            &self.partition_prefix,
            page_cache_ref.clone(),
        )
        .await
        .wrap_err("failed to initialize finalized blocks archive")?;

        let epoch_strategy = self.epoch_strategy.clone();

        let (marshal_actor, marshal_mailbox, last_finalized_height): (
            crate::alias::marshal::Actor<TContext>,
            crate::alias::marshal::Mailbox,
            _,
        ) = marshal::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: scheme_provider.clone(),
                epocher: epoch_strategy.clone(),
                partition_prefix: self.partition_prefix.clone(),
                mailbox_size: self.mailbox_size,
                view_retention_timeout: commonware_consensus::types::ViewDelta::new(1),
                prunable_items_per_section: storage::PRUNABLE_ITEMS_PER_SECTION,
                page_cache: page_cache_ref,
                replay_buffer: REPLAY_BUFFER,
                key_write_buffer: WRITE_BUFFER,
                value_write_buffer: WRITE_BUFFER,
                max_repair: storage::MAX_REPAIR,
                block_codec_config: (),
                strategy: Sequential,
            },
        )
        .await;

        info_span!("follow_engine").in_scope(|| {
            info!(
                last_finalized_height = last_finalized_height.get(),
                "initialized marshal"
            )
        });

        let (resolver_tx, resolver_rx) = mpsc::channel(self.mailbox_size);
        let resolver = FollowResolver::new(
            context.with_label("resolver"),
            self.upstream.clone(),
            resolver_tx,
            self.execution_node.clone(),
        );

        let (executor_actor, executor_mailbox) = executor::init(
            context.with_label("executor"),
            executor::Config {
                execution_node: self.execution_node,
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                fcu_heartbeat_interval: self.fcu_heartbeat_interval,
            },
        )
        .wrap_err("failed to initialize executor")?;

        let (feed_actor, feed_mailbox) = feed::init(
            context.with_label("feed"),
            marshal_mailbox.clone(),
            epoch_strategy.clone(),
            self.feed_state,
        );

        // No broadcast is needed in follow mode.
        let broadcast = stubs::null_broadcast(context.with_label("broadcast"), self.mailbox_size);

        Ok(Engine {
            context,
            upstream: self.upstream,
            resolver,
            resolver_rx,
            scheme_provider,
            epoch_strategy,
            marshal_actor,
            marshal_mailbox,
            executor_actor,
            executor_mailbox,
            feed_actor,
            feed_mailbox,
            broadcast,
            last_finalized_height,
        })
    }
}

pub struct Engine<TContext, U: UpstreamNode>
where
    TContext:
        Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
{
    context: TContext,
    upstream: Arc<U>,
    resolver: FollowResolver<TContext, U>,
    resolver_rx: mpsc::Receiver<commonware_consensus::marshal::ingress::handler::Message<Block>>,
    scheme_provider: SchemeProvider,
    epoch_strategy: FixedEpocher,
    marshal_actor: crate::alias::marshal::Actor<TContext>,
    marshal_mailbox: crate::alias::marshal::Mailbox,
    executor_actor: executor::Actor<TContext>,
    executor_mailbox: executor::Mailbox,
    feed_actor: feed::Actor<TContext>,
    feed_mailbox: feed::Mailbox,
    broadcast: buffered::Mailbox<PublicKey, Block>,
    last_finalized_height: Height,
}

impl<TContext, U: UpstreamNode> Engine<TContext, U>
where
    TContext:
        Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
{
    pub async fn start(mut self) -> eyre::Result<()> {
        let _executor_handle = self.executor_actor.start();
        let _feed_handle = self.feed_actor.start();
        let _marshal_handle = self.marshal_actor.start(
            self.executor_mailbox.clone(),
            self.broadcast,
            (self.resolver_rx, self.resolver),
        );

        let bootstrap = self.last_finalized_height == Height::zero();
        let last_finalized_height = if bootstrap {
            let tip = self
                .upstream
                .get_finalization(Query::Latest)
                .await
                .map_err(|e| eyre::eyre!("{e}"))?
                .and_then(|c| c.height)
                .unwrap_or(0);

            Height::new(tip)
        } else {
            self.last_finalized_height
        };

        let epoch_info = self
            .epoch_strategy
            .containing(last_finalized_height)
            .ok_or_eyre("failed to determine epoch for start height")?;

        let scheme_block_height = match epoch_info.epoch().previous() {
            None => Height::zero(),
            Some(prev_epoch) => self
                .epoch_strategy
                .last(prev_epoch)
                .ok_or_eyre("failed to determine previous epoch boundary")?,
        };

        if bootstrap {
            self.marshal_mailbox.set_floor(scheme_block_height).await;
            info_span!("follow_engine").in_scope(|| {
                info!(
                    boundary = scheme_block_height.get(),
                    epoch = epoch_info.epoch().get(),
                    "set marshal floor"
                )
            });
        }

        let block = if bootstrap {
            self.upstream
                .get_block_by_number(scheme_block_height.get())
                .await
                .map_err(|e| eyre::eyre!("{e}"))?
                .ok_or_eyre(format!(
                    "block at height {} not found on upstream",
                    scheme_block_height.get()
                ))?
        } else {
            self.marshal_mailbox
                .get_block(scheme_block_height)
                .await
                .ok_or_eyre(format!(
                    "block at height {} not found in local archive",
                    scheme_block_height.get()
                ))?
        };

        let extra_data = block.header().inner.extra_data.as_ref();
        let onchain_outcome = OnchainDkgOutcome::read(&mut &extra_data[..])
            .wrap_err("block did not contain a DKG outcome")?;

        let scheme: Scheme<PublicKey, MinSig> = Scheme::verifier(
            NAMESPACE,
            onchain_outcome.players().clone(),
            onchain_outcome.sharing().clone(),
        );

        self.scheme_provider.register(onchain_outcome.epoch, scheme);
        info_span!("follow_engine").in_scope(|| {
            info!(
                height = scheme_block_height.get(),
                epoch = onchain_outcome.epoch.get(),
                source = if bootstrap { "upstream" } else { "archive" },
                "bootstrapped identity scheme"
            )
        });

        let driver = driver::FollowDriver::new(
            self.context,
            self.upstream,
            self.scheme_provider,
            self.marshal_mailbox,
            self.feed_mailbox,
            self.epoch_strategy,
            last_finalized_height,
        );

        driver.run().await
    }
}
