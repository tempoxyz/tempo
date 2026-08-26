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

use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use commonware_broadcast::buffered;
use commonware_consensus::{Reporters, types::FixedEpocher};
use commonware_cryptography::ed25519::PublicKey;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics, Pacer, Spawner, Storage,
    buffer::paged::CacheRef, spawn_cell,
};
use commonware_utils::NZUsize;
use eyre::{WrapErr as _, eyre};
use futures::{StreamExt as _, stream::FuturesUnordered};
use rand_core::{CryptoRng, Rng};
use reth_engine_primitives::ConsensusEngineHandle;
use reth_node_builder::NodeTypesWithDBAdapter;
use reth_provider::providers::BlockchainProvider;
use tempo_chainspec::NetworkIdentity;
use tempo_node::{TempoFullNode, TempoPayloadTypes, node::TempoNode};
use tracing::{info, info_span};

use super::{driver, executor, resolver, stubs};
use crate::{
    alias,
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    feed::{self, FeedStateHandle},
    follow::upstream,
    storage,
};

/// Builder for the follow engine.
pub struct Config<TUpstream> {
    /// The execution node to drive.
    pub execution_node: Arc<TempoFullNode>,

    /// Optional `tempo/1` transport. Its receivers make this configuration single-use.
    pub gossip: Option<crate::gossip::Config>,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Latest network Identity of the chain.
    pub network_identity: NetworkIdentity,

    /// Mailbox size for async channels.
    pub mailbox_size: NonZeroUsize,

    /// Deadline for individual requests to the upstream node.
    pub upstream_request_timeout: Duration,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,

    /// An actor that can be started with reporters listening to consensus events.
    pub upstream: TUpstream,

    /// Mailbox to an upstream actor running outside of the follower engine.
    pub upstream_mailbox: upstream::Mailbox,

    /// Number of recently finalized blocks retained in the prunable archive
    /// passed to the marshal actor. Older blocks are served from reth.
    pub finalized_blocks_retention: u64,
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
            finalized_floor: last_finalized_height,
            ..
        } = alias::marshal::init(
            context.child("marshal"),
            page_cache_ref,
            self.execution_node.clone(),
            alias::marshal::Config {
                partition_prefix: self.partition_prefix.clone(),
                mailbox_size: self.mailbox_size,
                view_retention_timeout: commonware_consensus::types::ViewDelta::new(1),
                max_pending_acks: NZUsize!(1),
                finalized_blocks_retention: self.finalized_blocks_retention,
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

        let (resolver, resolver_rx) = resolver::try_init(
            context.child("resolver"),
            resolver::Config {
                execution_provider: self.execution_node.provider.clone(),
                upstream: self.upstream_mailbox.clone(),
                mailbox_size: self.mailbox_size,
                upstream_request_timeout: self.upstream_request_timeout,
            },
        );

        let (feed_actor, feed_mailbox) = feed::init(
            context.child("feed"),
            marshal_mailbox.clone(),
            self.feed_state,
        );

        let (executor_actor, executor_mailbox) = executor::init(
            context.child("executor"),
            executor::Config {
                execution_provider: self.execution_node.provider.clone(),
                execution_engine: self
                    .execution_node
                    .add_ons_handle
                    .beacon_engine_handle
                    .clone(),
                marshal: marshal_mailbox.clone(),
                epoch_strategy: epoch_strategy.clone(),
                floor: last_finalized_height,
                fcu_heartbeat_interval: self.fcu_heartbeat_interval,
            },
        );

        // No broadcast is needed in follow mode.
        let broadcast = stubs::null_broadcast(context.child("broadcast"), self.mailbox_size);

        let (driver, driver_mailbox) = driver::try_init(
            context.child("driver"),
            driver::Config {
                execution_provider: self.execution_node.provider.clone(),
                scheme_provider: scheme_provider.clone(),
                network_identity: self.network_identity,
                last_finalized_height,
                marshal: marshal_mailbox.clone(),
                executor: executor_mailbox.clone(),
                epoch_strategy: epoch_strategy.clone(),
            },
        )
        .wrap_err("failed initializing driver actor")?;

        let (gossip_actor, gossip_mailbox) = self
            .gossip
            .map(|gossip_config| {
                crate::gossip::init(
                    context.child("gossip"),
                    crate::gossip::actor::Config {
                        verify_rate: gossip_config.verify_rate,
                        transport: gossip_config.transport,
                        epoch_strategy: epoch_strategy.clone(),
                        finalized_floor: last_finalized_height,
                        peer_control: self.execution_node.network.clone(),
                        driver: driver_mailbox.clone(),
                        marshal: marshal_mailbox,
                    },
                )
            })
            .unzip();

        Ok(Engine {
            context: ContextCell::new(context),
            // Keep every execution-node service alive for the lifetime of the follower engine.
            _execution_node: self.execution_node,
            driver,
            driver_mailbox,
            resolver,
            resolver_rx,
            marshal: marshal_actor,
            executor: executor_actor,
            executor_mailbox,
            feed: feed_actor,
            feed_mailbox,
            broadcast,
            gossip_mailbox,
            gossip_actor,
            upstream: self.upstream,
        })
    }
}

type FollowExecutionProvider =
    BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, reth_ethereum::provider::db::DatabaseEnv>>;

pub struct Engine<TContext, TUpstreamActor>
where
    TContext: Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + BufferPooler,
    TUpstreamActor:,
{
    context: ContextCell<TContext>,
    _execution_node: Arc<TempoFullNode>,
    driver: driver::Driver<
        TContext,
        FollowExecutionProvider,
        crate::alias::marshal::Mailbox,
        executor::Mailbox,
    >,
    driver_mailbox: driver::Mailbox,
    resolver: resolver::Mailbox,
    resolver_rx: commonware_consensus::marshal::resolver::handler::Receiver<Digest>,
    marshal: crate::alias::marshal::Actor<TContext>,
    executor: executor::Actor<
        TContext,
        FollowExecutionProvider,
        ConsensusEngineHandle<TempoPayloadTypes>,
    >,
    executor_mailbox: executor::Mailbox,
    feed: feed::Actor<TContext>,
    feed_mailbox: feed::Mailbox,
    broadcast: buffered::Mailbox<PublicKey, Block>,
    gossip_mailbox: Option<crate::gossip::Mailbox>,
    gossip_actor:
        Option<crate::gossip::Actor<TContext, driver::Mailbox, crate::gossip::NetworkPeerControl>>,
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
        + Send
        + 'static,
    TUpstreamActor: upstream::UpstreamActor,
{
    pub fn start(mut self) -> Handle<eyre::Result<()>> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) -> eyre::Result<()> {
        let Self {
            _execution_node,
            upstream,
            driver,
            driver_mailbox,
            resolver,
            resolver_rx,
            marshal,
            executor,
            executor_mailbox,
            feed,
            feed_mailbox,
            broadcast,
            gossip_mailbox,
            gossip_actor,
            ..
        } = self;

        let mut actors = vec![
            driver.start(),
            executor.start(),
            feed.start(),
            marshal.start(
                Reporters::from((
                    executor_mailbox.clone(),
                    Reporters::from((
                        // Keep the driver ahead of gossip. When gossip observes a
                        // boundary block, any certificate retry it submits must be
                        // queued after the driver update that installs its scheme.
                        driver_mailbox.to_marshal_reporter(),
                        Reporters::<_, feed::Mailbox, crate::gossip::Mailbox>::from((
                            feed_mailbox,
                            gossip_mailbox,
                        )),
                    )),
                )),
                broadcast,
                (resolver_rx, resolver),
            ),
            upstream.start(driver_mailbox.to_event_reporter()),
        ];

        if let Some(gossip_actor) = gossip_actor {
            actors.push(gossip_actor.start());
        }

        // TODO: report which actor failed and why.
        if FuturesUnordered::from_iter(actors).next().await.is_some() {
            return Err(eyre!("one critical subsystem exited unexpectedly"));
        }

        Ok(())
    }
}
