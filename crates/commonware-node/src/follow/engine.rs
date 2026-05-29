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
use commonware_consensus::{Reporters, types::FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Pacer, Spawner, Storage,
    buffer::paged::CacheRef, spawn_cell,
};
use commonware_utils::{NZUsize, channel::mpsc};
use eyre::{WrapErr as _, eyre};
use futures::{StreamExt as _, stream::FuturesUnordered};
use rand_08::{CryptoRng, Rng};
use tempo_chainspec::NetworkIdentity;
use tempo_node::TempoFullNode;
use tracing::{info, info_span};

use super::{driver, resolver, resolver::Resolver, stubs};
use crate::{
    alias,
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    executor,
    feed::{self, FeedStateHandle},
    follow::upstream,
    storage,
};

/// Builder for the follow engine.
#[derive(Clone)]
pub struct Config<TUpstream> {
    /// The execution node to drive.
    pub execution_node: Arc<TempoFullNode>,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Latest network Identity of the chain.
    pub network_identity: NetworkIdentity,

    /// Mailbox size for async channels.
    pub mailbox_size: usize,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,

    /// An actor that can be started with reporters listening to consensus events.
    pub upstream: TUpstream,

    /// Mailbox to an upstream actor running outside of the follower engine.
    pub upstream_mailbox: upstream::Mailbox,

    /// Number of recently finalized blocks retained in the prunable archive
    /// passed to the marshal actor. Older blocks are served from reth.
    pub finalized_blocks_retention: u64,

    /// Whether to dual-write each newly finalized block to the legacy
    /// immutable archive in addition to the prunable archive. Enabled in
    /// production for rollback safety; disabled in tests that exercise
    /// the prunable-archive-only restart path.
    pub with_legacy: bool,
}

impl<TUpstream> Config<TUpstream> {
    /// Initialize all components and return an [`Engine`] ready to start.
    pub async fn try_init<TContext>(
        self,
        context: TContext,
    ) -> eyre::Result<Engine<TContext, TUpstream>>
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

        let epoch_strategy = self.epoch_strategy.clone();

        let alias::marshal::Initialized {
            actor: marshal_actor,
            mailbox: marshal_mailbox,
            last_finalized_height,
        } = alias::marshal::init(
            context.clone(),
            page_cache_ref,
            self.execution_node.clone(),
            alias::marshal::Config {
                partition_prefix: self.partition_prefix.clone(),
                mailbox_size: self.mailbox_size,
                view_retention_timeout: commonware_consensus::types::ViewDelta::new(1),
                max_pending_acks: NZUsize!(1),
                finalized_blocks_retention: self.finalized_blocks_retention,
                with_legacy: self.with_legacy,
                epoch_strategy: epoch_strategy.clone(),
                scheme_provider: scheme_provider.clone(),
            },
        )
        .await
        .wrap_err("failed to initialize marshal")?;

        info_span!("follow_engine").in_scope(|| {
            info!(
                last_finalized_height = last_finalized_height.get(),
                "initialized marshal"
            )
        });

        let (resolver, resolver_mailbox, resolver_rx) = resolver::try_init(
            context.with_label("resolver"),
            resolver::Config {
                execution_node: self.execution_node.clone(),
                upstream: self.upstream_mailbox.clone(),
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
                execution_node: self.execution_node.clone(),
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                fcu_heartbeat_interval: self.fcu_heartbeat_interval,
                public_key: None,
            },
        )
        .wrap_err("failed to initialize executor")?;

        // No broadcast is needed in follow mode.
        let broadcast = stubs::null_broadcast(context.with_label("broadcast"), self.mailbox_size);

        let (driver, driver_mailbox) = driver::try_init(
            context.with_label("driver"),
            driver::Config {
                execution_node: self.execution_node.clone(),
                scheme_provider: scheme_provider.clone(),
                network_identity: self.network_identity,
                last_finalized_height,
                marshal: marshal_mailbox,
                feed: feed_mailbox,
                epoch_strategy: epoch_strategy.clone(),
            },
        )
        .wrap_err("failed initializing driver actor")?;

        Ok(Engine {
            context: ContextCell::new(context),
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
            upstream: self.upstream,
        })
    }
}

pub struct Engine<TContext, TUpstreamActor>
where
    TContext: Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + BufferPooler,
    TUpstreamActor:,
{
    context: ContextCell<TContext>,
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
    upstream: TUpstreamActor,
}

impl<TContext, TUpstreamActor> Engine<TContext, TUpstreamActor>
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
    TUpstreamActor: upstream::UpstreamActor,
{
    pub fn start(mut self) -> Handle<eyre::Result<()>> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) -> eyre::Result<()> {
        let Self {
            upstream,
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
            upstream.start(driver_mailbox.to_event_reporter()),
        ];

        // TODO: report which actor failed and why.
        if FuturesUnordered::from_iter(actors).next().await.is_some() {
            return Err(eyre!("one critical subsystem exited unexpectedly"));
        }

        Ok(())
    }
}
