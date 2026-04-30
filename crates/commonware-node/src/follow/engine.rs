//! Follow mode engine that syncs from upstream via RPC.
//!
//! This module provides a minimal consensus-layer stack for follow mode:
//! - Marshal for storage and verification
//! - Executor for driving Reth
//! - FeedState for RPC serving
//! - Resolver for marshal's gap-repair
//! - Tip tracker for push-based finalization events
//!
//! The archive format is shared with the consensus engine running in validator mode
//! so nodes can switch between validator and follower modes without data migration.

use std::{sync::Arc, time::Duration};

use commonware_broadcast::buffered;
use commonware_consensus::{Reporters, marshal, types::FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Pacer, Spawner, Storage,
    buffer::paged::CacheRef, spawn_cell,
};
use commonware_utils::{NZUsize, channel::mpsc};
use eyre::{WrapErr as _, eyre};
use futures::{StreamExt as _, stream::FuturesUnordered};
use rand_08::{CryptoRng, Rng};
use tempo_node::TempoFullNode;
use tracing::{info, info_span};

use super::{driver, resolver, resolver::Resolver, stubs};
use crate::{
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    executor,
    feed::{self, FeedStateHandle},
    follow::upstream,
    storage,
};

/// Builder for the follow engine.
#[derive(Clone)]
pub struct Config {
    /// The execution node to drive.
    pub execution_node: TempoFullNode,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    pub upstream_url: String,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Mailbox size for async channels.
    pub mailbox_size: usize,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,
}

impl Config {
    /// Initialize all components and return an [`Engine`] ready to start.
    pub async fn try_init<TContext>(self, context: TContext) -> eyre::Result<Engine<TContext>>
    where
        TContext: Clock
            + Rng
            + CryptoRng
            + Metrics
            + Pacer
            + Spawner
            + Storage
            + BufferPooler
            + Clone
            + Send
            + 'static,
    {
        let scheme_provider = SchemeProvider::new();

        let page_cache_ref = CacheRef::from_pooler(
            &context,
            storage::BUFFER_POOL_PAGE_SIZE,
            storage::BUFFER_POOL_CAPACITY,
        );

        let finalizations_by_height = storage::init_finalizations_archive(
            &context,
            &self.partition_prefix,
            page_cache_ref.clone(),
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let finalized_blocks = storage::init_finalized_blocks_archive(
            &context,
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
        ) = marshal::core::Actor::init(
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
                replay_buffer: storage::REPLAY_BUFFER,
                key_write_buffer: storage::WRITE_BUFFER,
                value_write_buffer: storage::WRITE_BUFFER,
                max_repair: storage::MAX_REPAIR,
                max_pending_acks: NZUsize!(1),
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

        let execution_node = Arc::new(self.execution_node.clone());

        let (upstream_actor, upstream_mailbox) = upstream::init(
            context.with_label("upstream"),
            upstream::Config {
                upstream_url: self.upstream_url,
            },
        );

        let (resolver, resolver_mailbox, resolver_rx) = resolver::try_init(
            context.with_label("resolver"),
            resolver::Config {
                execution_node: execution_node.clone(),
                upstream: upstream_mailbox.clone(),
                mailbox_size: self.mailbox_size,
            },
        );

        let (feed_actor, feed_mailbox) = feed::init(
            context.with_label("feed"),
            marshal_mailbox.clone(),
            epoch_strategy.clone(),
            self.execution_node.clone(),
            self.feed_state,
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

        // No broadcast is needed in follow mode.
        let broadcast = stubs::null_broadcast(context.with_label("broadcast"), self.mailbox_size);

        let (driver, driver_mailbox) = driver::try_init(
            context.with_label("driver"),
            driver::Config {
                execution_node: execution_node.clone(),
                scheme_provider: scheme_provider.clone(),
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                feed: feed_mailbox.clone(),
                epoch_strategy: epoch_strategy.clone(),
            },
        )
        .wrap_err("failed initializing driver actor")?;

        Ok(Engine {
            context: ContextCell::new(context),
            upstream_actor,
            driver,
            driver_mailbox,
            resolver,
            resolver_mailbox,
            resolver_rx,
            marshal: marshal_actor,
            executor: executor_actor,
            executor_mailbox,
            feed: feed_actor,
            broadcast,
        })
    }
}

pub struct Engine<TContext>
where
    TContext: Clock
        + Rng
        + CryptoRng
        + Metrics
        + Pacer
        + Spawner
        + Storage
        + BufferPooler
        + Clone
        + Send
        + 'static,
{
    context: ContextCell<TContext>,
    upstream_actor: upstream::Actor<TContext>,
    driver: driver::Driver<TContext>,
    driver_mailbox: driver::Mailbox,
    resolver: Resolver<TContext>,
    resolver_mailbox: resolver::Mailbox,
    resolver_rx: mpsc::Receiver<commonware_consensus::marshal::resolver::handler::Message<Digest>>,
    marshal: crate::alias::marshal::Actor<TContext>,
    executor: executor::Actor<TContext>,
    executor_mailbox: executor::Mailbox,
    feed: feed::Actor<TContext>,
    broadcast: buffered::Mailbox<PublicKey, Block>,
}

impl<TContext> Engine<TContext>
where
    TContext: Clock
        + Rng
        + CryptoRng
        + Metrics
        + Pacer
        + Spawner
        + Storage
        + BufferPooler
        + Clone
        + Send
        + 'static,
{
    pub fn start(mut self) -> Handle<eyre::Result<()>> {
        spawn_cell!(self.context, self.run().await)
    }

    async fn run(self) -> eyre::Result<()> {
        let Self {
            upstream_actor,
            driver,
            driver_mailbox,
            resolver,
            resolver_mailbox,
            resolver_rx,
            marshal,
            executor,
            executor_mailbox,
            feed,
            broadcast,
            ..
        } = self;

        let actors = vec![
            driver.start(),
            executor.start(),
            feed.start(),
            marshal.start(
                Reporters::from((
                    executor_mailbox.clone(),
                    driver_mailbox.to_marshal_reporter(),
                )),
                broadcast,
                (resolver_rx, resolver_mailbox),
            ),
            resolver.start(),
            upstream_actor.start(driver_mailbox.to_event_reporter()),
        ];

        // TODO: report which actor failed and why.
        if let Some(_) = FuturesUnordered::from_iter(actors).next().await {
            return Err(eyre!("one critical subsystem exited unexpectedly"));
        }

        Ok(())
    }
}
