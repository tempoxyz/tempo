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

use alloy_consensus::BlockHeader as _;
use commonware_broadcast::buffered;
use commonware_codec::ReadExt as _;
use commonware_consensus::{
    Reporter as _, marshal,
    simplex::{
        scheme::bls12381_threshold::vrf::Scheme,
        types::{Activity, Finalization},
    },
    types::{Epoch, Epocher as _, FixedEpocher, Height, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
use commonware_macros::select;
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Clock, Metrics, Pacer, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_utils::{NZUsize, channel::mpsc};
use eyre::{OptionExt as _, WrapErr as _, bail, eyre};
use futures::future::join_all;
use rand_08::{CryptoRng, Rng};
use reth_node_core::primitives::SealedBlock;
use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
use tempo_node::{TempoFullNode, rpc::consensus::Query};
use tracing::{info, info_span};

use super::{driver, resolver, resolver::Resolver, stubs, upstream::UpstreamNode};
use crate::{
    config::NAMESPACE,
    consensus::{Digest, block::Block},
    epoch::SchemeProvider,
    executor,
    feed::{self, FeedStateHandle},
    storage,
};

/// Builder for the follow engine.
#[derive(Clone)]
pub struct Config<U: UpstreamNode> {
    /// The execution node to drive.
    pub execution_node: TempoFullNode,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    /// Upstream node to sync from.
    pub upstream: U,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Mailbox size for async channels.
    pub mailbox_size: usize,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,
}

impl<U: UpstreamNode> Config<U> {
    /// Initialize all components and return an [`Engine`] ready to start.
    pub async fn try_init<TContext>(self, context: TContext) -> eyre::Result<Engine<TContext, U>>
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

        let (resolver, resolver_mailbox, resolver_rx) = resolver::try_init(
            context.with_label("resolver"),
            resolver::Config {
                execution_node: Arc::new(self.execution_node.clone()),
                upstream: self.upstream.clone(),
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

        Ok(Engine {
            context,
            upstream: self.upstream,
            resolver,
            resolver_mailbox,
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
    context: TContext,
    upstream: U,
    resolver: Resolver<TContext, U>,
    resolver_mailbox: resolver::Mailbox,
    resolver_rx: mpsc::Receiver<commonware_consensus::marshal::resolver::handler::Message<Digest>>,
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
    pub async fn start(mut self) -> eyre::Result<()> {
        let mut actors = join_all([
            self.executor_actor.start(),
            self.feed_actor.start(),
            self.marshal_actor.start(
                self.executor_mailbox.clone(),
                self.broadcast,
                (self.resolver_rx, self.resolver_mailbox),
            ),
            self.resolver.start(),
        ]);

        let bootstrap = self.last_finalized_height == Height::zero();
        let boundary_block = if bootstrap {
            // If we're bootstrapping, find the latest boundary block and
            // use it as the trusted floor for the identity scheme.
            let latest_finalization = self
                .upstream
                .get_finalization(Query::Latest)
                .await?
                .ok_or_eyre("failed to get latest finalization")?;

            let latest_finalization_height = Height::new(latest_finalization.block.number());

            let epoch_info = self
                .epoch_strategy
                .containing(latest_finalization_height)
                .ok_or_eyre("failed to determine epoch for latest finalization height")?;

            let boundary_height = if latest_finalization_height == epoch_info.last() {
                latest_finalization_height
            } else {
                match epoch_info.epoch().previous() {
                    None => Height::zero(),
                    Some(prev_epoch) => self.epoch_strategy.last(prev_epoch).unwrap(),
                }
            };

            let block = self
                .upstream
                .get_block_by_number(boundary_height.get())
                .await?
                .ok_or_eyre(format!(
                    "block at height {} not found on upstream",
                    boundary_height.get()
                ))?;

            // Process the boundary with the marshal so that the starting scheme has it's corresponding
            // block available. The genesis block is an exception as there is no finalization certificate.
            if boundary_height > Height::zero() {
                let boundary_block = self
                    .upstream
                    .get_finalization(Query::Height(boundary_height.get()))
                    .await?
                    .ok_or_else(|| {
                        eyre!(
                            "finalization at height {} not found on upstream",
                            boundary_height.get()
                        )
                    })?;

                let sealed = SealedBlock::seal_slow(block.clone());
                let consensus_block = Block::from_execution_block(sealed);
                eyre::ensure!(boundary_block.digest == consensus_block.block_hash());

                let cert_bytes = alloy_primitives::hex::decode(&boundary_block.certificate)?;
                let finalization: Finalization<Scheme<PublicKey, MinSig>, Digest> =
                    Finalization::read(&mut &cert_bytes[..])?;

                // Process the boundary block & finalization
                let epoch = Epoch::new(boundary_block.epoch);
                let round = Round::new(epoch, View::new(boundary_block.view));
                let activity = Activity::Finalization(finalization);
                self.marshal_mailbox.verified(round, consensus_block).await;
                self.marshal_mailbox.report(activity.clone()).await;
                self.feed_mailbox.report(activity).await;

                self.last_finalized_height = boundary_height;
                self.marshal_mailbox.set_floor(boundary_height).await;
                info_span!("follow_engine")
                    .in_scope(|| info!(?boundary_height, ?epoch, "bootstrapped marshal floor"));
            }

            block
        } else {
            // Get the last boundary block processed.
            let epoch_info = self
                .epoch_strategy
                .containing(self.last_finalized_height)
                .ok_or_eyre("failed to determine epoch for last finalized height")?;

            let boundary_height = if self.last_finalized_height == epoch_info.last() {
                self.last_finalized_height
            } else {
                match epoch_info.epoch().previous() {
                    None => Height::zero(),
                    Some(prev_epoch) => self.epoch_strategy.last(prev_epoch).unwrap(),
                }
            };

            self.marshal_mailbox
                .get_block(boundary_height)
                .await
                .ok_or_else(|| {
                    eyre!(
                        "block at height {} not found in local archive",
                        boundary_height.get()
                    )
                })?
                .into_inner()
                .into_block()
        };

        let extra_data = boundary_block.extra_data();
        let outcome = OnchainDkgOutcome::read(&mut &extra_data[..])
            .wrap_err("could not read DKG outcome from block")?;

        let outcome_scheme: Scheme<PublicKey, MinSig> = Scheme::verifier(
            NAMESPACE,
            outcome.players().clone(),
            outcome.sharing().clone(),
        );

        // Register the boundary scheme so that driver can correctly process finalizations
        self.scheme_provider.register(outcome.epoch, outcome_scheme);
        info_span!("follow_engine").in_scope(|| {
            info!(
                height = boundary_block.header.number(),
                epoch = ?outcome.epoch,
                source = if bootstrap { "upstream" } else { "archive" },
                "registered starting identity scheme"
            )
        });

        let driver = driver::FollowDriver::new(
            self.context,
            self.upstream,
            self.scheme_provider,
            self.marshal_mailbox,
            self.feed_mailbox,
            self.epoch_strategy,
            self.last_finalized_height,
        );

        select! {
            result = driver.run() => result,
            _ = &mut actors => bail!("actors exited unexpectedly"),
        }
    }
}
