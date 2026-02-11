//! Follow mode engine that syncs from upstream via RPC.
//!
//! This module provides a minimal consensus-layer stack for follow mode:
//! - Marshal for storage and verification
//! - Executor for driving Reth
//! - FeedState for RPC serving
//! - RpcResolver for fetching blocks/finalizations from upstream on demand
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
use tempo_node::TempoFullNode;
use tracing::{info, info_span};

use super::{driver, resolver::RpcResolver, stubs};
use crate::{
    alias::marshal as marshal_alias,
    config::NAMESPACE,
    consensus::block::Block,
    epoch::SchemeProvider,
    executor, feed,
    feed::FeedStateHandle,
    storage::{self, REPLAY_BUFFER, WRITE_BUFFER},
};

/// Builder for the follow engine.
#[derive(Clone)]
pub(crate) struct Builder {
    /// The execution node to drive.
    pub execution_node: TempoFullNode,

    /// Feed state handle for RPC serving.
    pub feed_state: FeedStateHandle,

    /// Partition prefix for storage.
    pub partition_prefix: String,

    /// URL of the upstream node to sync from. Passed explicitly
    /// as this is a Tempo argument.
    pub upstream_url: String,

    /// Epoch strategy.
    pub epoch_strategy: FixedEpocher,

    /// Mailbox size for async channels.
    pub mailbox_size: usize,

    /// FCU heartbeat interval.
    pub fcu_heartbeat_interval: Duration,
}

impl Builder {
    /// Initialize all components and return an [`Engine`] ready to start.
    pub(crate) async fn try_init<TContext>(
        self,
        context: TContext,
    ) -> eyre::Result<Engine<TContext>>
    where
        TContext:
            Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
    {
        let scheme_provider = SchemeProvider::new();
        let page_cache_ref = storage::create_page_cache();

        // Initialize archives using shared format (compatible with consensus engine)
        let finalizations_by_height = storage::init_finalizations_archive(
            context.with_label("finalizations_by_height"),
            &self.partition_prefix,
            page_cache_ref.clone(),
        )
        .await?;

        let finalized_blocks = storage::init_finalized_blocks_archive(
            context.with_label("finalized_blocks"),
            &self.partition_prefix,
            page_cache_ref.clone(),
        )
        .await?;

        let epoch_strategy = self.epoch_strategy.clone();

        // Initialize marshal (use type alias to satisfy type inference)
        let (marshal_actor, marshal_mailbox, last_finalized_height): (
            marshal_alias::Actor<TContext>,
            marshal_alias::Mailbox,
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

        info_span!("follow").in_scope(|| {
            info!(
                last_finalized_height = last_finalized_height.get(),
                "initialized marshal"
            )
        });

        // Create resolver — used for DKG bootstrap and then by the driver + marshal
        let (resolver_tx, resolver_rx) = mpsc::channel(self.mailbox_size);
        let rpc_resolver = RpcResolver::new(self.upstream_url, resolver_tx);
        let resolver = Arc::new(rpc_resolver);

        // Initialize executor (handles forwarding blocks to EL and FCU heartbeats)
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

        // Initialize feed actor
        let (feed_actor, feed_mailbox) = feed::init(
            context.with_label("feed"),
            marshal_mailbox.clone(),
            epoch_strategy.clone(),
            self.feed_state,
        );

        // Create null broadcast (follower never broadcasts blocks)
        let null_broadcast =
            stubs::null_broadcast(context.with_label("broadcast"), self.mailbox_size);

        Ok(Engine {
            context,
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
            null_broadcast,
            last_finalized_height,
        })
    }
}

pub(crate) struct Engine<TContext>
where
    TContext:
        Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
{
    context: TContext,
    resolver: Arc<RpcResolver>,
    resolver_rx: mpsc::Receiver<commonware_consensus::marshal::ingress::handler::Message<Block>>,
    scheme_provider: SchemeProvider,
    epoch_strategy: FixedEpocher,
    marshal_actor: marshal_alias::Actor<TContext>,
    marshal_mailbox: marshal_alias::Mailbox,
    executor_actor: executor::Actor<TContext>,
    executor_mailbox: executor::Mailbox,
    feed_actor: feed::Actor<TContext>,
    feed_mailbox: feed::Mailbox,
    null_broadcast: buffered::Mailbox<PublicKey, Block>,
    last_finalized_height: Height,
}

impl<TContext> Engine<TContext>
where
    TContext:
        Clock + Rng + CryptoRng + Metrics + Pacer + Spawner + Storage + Clone + Send + 'static,
{
    pub(crate) async fn start(mut self) -> eyre::Result<()> {
        // Start actors
        let _executor_handle = self.executor_actor.start();
        let _feed_handle = self.feed_actor.start();
        let _marshal_handle = self.marshal_actor.start(
            self.executor_mailbox,
            self.null_broadcast,
            (self.resolver_rx, (*self.resolver).clone()),
        );

        // Bootstrap the DKG scheme and determine the sync starting point.
        //
        // For epoch 0 the genesis block carries the initial DKG outcome.
        // For epoch N>0 the boundary block of epoch N-1 carries the DKG outcome.
        //
        // Fresh followers (empty archive) query the upstream tip, set the marshal
        // floor to skip historical gap-repair, and bootstrap the DKG from upstream.
        // Non-fresh followers read the boundary block from the local marshal archive.
        let bootstrap = self.last_finalized_height == Height::zero();
        let last_finalized_height = if bootstrap {
            let tip = self
                .resolver
                .fetch_latest_finalization()
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

        // If bootstrapping, set the floor to this boundary block to prevent historical
        // gap-repair all the way to genesis. Setting the boundary block as the floor
        // and not the upstream tip ensures the boundary block for the current epoch is retained.
        if bootstrap {
            self.marshal_mailbox.set_floor(scheme_block_height).await;
            info_span!("follow").in_scope(|| {
                info!(
                    boundary = scheme_block_height.get(),
                    epoch = epoch_info.epoch().get(),
                    "set marshal floor to previous epoch boundary"
                )
            });
        }

        let block = if bootstrap {
            // Bootstrap DKG from upstream (trusted)
            self.resolver
                .fetch_block(scheme_block_height.get())
                .await
                .map_err(|e| eyre::eyre!("{e}"))?
                .ok_or_eyre(format!(
                    "block at height {} not found on upstream",
                    scheme_block_height.get()
                ))?
        } else {
            // Bootstrap from local archive (trustless)
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
        info_span!("follow").in_scope(|| {
            info!(
                height = scheme_block_height.get(),
                epoch = onchain_outcome.epoch.get(),
                source = if bootstrap { "upstream" } else { "archive" },
                "bootstrapped identity scheme"
            )
        });

        let driver = driver::FollowDriver::new(
            self.context,
            self.resolver,
            self.scheme_provider,
            self.marshal_mailbox,
            self.feed_mailbox,
            self.epoch_strategy,
            last_finalized_height.get(),
        );

        driver.run().await
    }
}
