//! A collection of aliases and shared initialization for frequently used
//! (primarily commonware) types.

pub(crate) mod marshal {
    use std::{num::NonZeroUsize, sync::Arc};

    use alloy_consensus::{BlockHeader as _, Sealable as _};
    use commonware_consensus::{
        Epochable as _,
        marshal::{self, core, standard::Standard},
        simplex::scheme::bls12381_threshold::vrf::Scheme,
        types::{Epoch, Epocher as _, FixedEpocher, Height, Round, ViewDelta},
    };
    use commonware_cryptography::{bls12381::primitives::variant::MinSig, ed25519::PublicKey};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Clock, Metrics, Spawner, Storage, buffer::paged::CacheRef,
    };
    use commonware_storage::archive::{Archive as _, Identifier, immutable};
    use commonware_utils::acknowledgement::Exact;
    use eyre::{OptionExt as _, WrapErr as _, bail, ensure, eyre};
    use rand_core::{CryptoRng, Rng};
    use reth_ethereum::{chainspec::EthChainSpec, provider::db::DatabaseEnv};
    use reth_node_builder::NodeTypesWithDBAdapter;
    use reth_provider::{BlockReader as _, providers::BlockchainProvider};
    use tempo_chainspec::TempoHardforks as _;
    use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
    use tempo_node::{TempoFullNode, node::TempoNode};
    use tempo_primitives::TempoHeader;
    use tracing::{info, instrument};

    use crate::{
        consensus::{Digest, block::Block},
        epoch::SchemeProvider,
        gossip::Certificate,
        storage::{self, Hybrid},
    };

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        Standard<Block>,
        SchemeProvider,
        immutable::Archive<TContext, Digest, Certificate>,
        Hybrid<TContext, BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>>,
        FixedEpocher,
        Sequential,
        Exact,
    >;

    pub(crate) type Mailbox = core::Mailbox<Scheme<PublicKey, MinSig>, Standard<Block>>;

    /// Settings shared by both engines when initializing the marshal actor
    /// and its backing finalized-blocks store.
    pub(crate) struct Config {
        /// Partition prefix shared with the engine's other on-disk archives.
        pub partition_prefix: String,

        /// Marshal mailbox capacity.
        pub mailbox_size: NonZeroUsize,

        /// Minimum number of views to retain temporary marshal data after a
        /// block is processed. The two engines pick very different values for
        /// this — consensus keeps state around long enough to serve peers,
        /// follow mode does not — so the caller computes it.
        pub view_retention_timeout: ViewDelta,

        /// Maximum number of marshal-dispatched blocks the application may
        /// buffer before acknowledging.
        pub max_pending_acks: NonZeroUsize,

        /// Number of recently finalized blocks retained in the prunable
        /// archive. Older blocks are served from reth via [`Hybrid`].
        pub finalized_blocks_retention: u64,

        /// Epoch length / boundary configuration.
        pub epoch_strategy: FixedEpocher,

        /// Provider for epoch-specific signing schemes used by marshal to
        /// verify finalizations. The same instance is shared with the rest of
        /// the engine, so the caller passes it in.
        pub scheme_provider: SchemeProvider,
    }

    /// Marshal actor + mailbox + the height marshal will resume from,
    /// returned by [`init`].
    pub(crate) struct Initialized<TContext>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng,
    {
        /// The marshal actor, ready to be started.
        pub actor: Actor<TContext>,

        /// Mailbox for sending messages to [`Self::actor`].
        pub mailbox: Mailbox,

        /// Startup backfill target, selected from marshal's stored finalized
        /// height and the startup floor height.
        pub finalized_floor: Height,

        /// Archive tip metadata used to initialize the executor and peer manager.
        pub finalized_tip: (Round, Height, Digest),

        /// The archive certificate to authenticate during initialization.
        /// `None` only at genesis.
        pub finalized_tip_certificate: Option<Certificate>,
    }

    /// Initialize the marshal actor and its backing finalized-blocks store
    /// (the finalizations-by-height archive plus the [`Hybrid`] finalized
    /// blocks store), select the startup finalized floor, and advance
    /// marshal's sync floor when needed.
    ///
    /// Both the consensus and follow engines must initialize marshal in
    /// exactly the same way so that nodes can switch modes without data
    /// migration. Use this function to maintain that invariant; differences
    /// between the two engines belong in [`Config`].
    #[instrument(
        skip_all,
        fields(partition_prefix = %config.partition_prefix),
        err(Display)
    )]
    pub(crate) async fn init<TContext>(
        mut context: TContext,
        page_cache: CacheRef,
        execution_node: Arc<TempoFullNode>,
        config: Config,
    ) -> eyre::Result<Initialized<TContext>>
    where
        TContext:
            Clock + Metrics + Spawner + Storage + BufferPooler + Rng + CryptoRng + Send + 'static,
    {
        let finalizations_by_height = storage::init_finalizations_archive(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            &config.epoch_strategy,
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let finalized_blocks = storage::init_finalized_blocks(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
        )
        .await
        .wrap_err("failed to initialize hybrid finalized blocks store")?;

        let FinalizationRange {
            floor: finalized_floor,
            tip: finalized_tip,
        } = establish_finalization_range(
            &finalizations_by_height,
            &finalized_blocks,
            &execution_node,
        )
        .await?;
        let (tip_round, tip_height, tip_digest) = match &finalized_tip {
            Some((height, certificate)) => (
                certificate.proposal.round,
                *height,
                certificate.proposal.payload,
            ),
            None => (Round::zero(), finalized_floor.0, finalized_floor.1),
        };
        info!(
            floor_height = %finalized_floor.0,
            floor_digest = %finalized_floor.1,
            tip_round = %tip_round,
            tip_height = %tip_height,
            tip_digest = %tip_digest,
            "selected finalized startup range"
        );

        let start =
            start_from_finalized_floor(&finalizations_by_height, &execution_node, finalized_floor)
                .await?;

        if let marshal::Start::Floor(finalization) = &start {
            register_scheme(
                &mut context,
                &config.epoch_strategy,
                &config.scheme_provider,
                &execution_node.chain_spec(),
                &finalized_blocks,
                finalization,
            )
            .await?;
        }

        let (actor, mailbox, marshal_floor) = core::Actor::init(
            context,
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: config.scheme_provider,
                epocher: config.epoch_strategy,
                start,
                partition_prefix: config.partition_prefix,
                mailbox_size: config.mailbox_size,
                view_retention: config.view_retention_timeout,
                prunable_items_per_section: storage::PRUNABLE_ITEMS_PER_SECTION,
                page_cache,
                replay_buffer: storage::REPLAY_BUFFER,
                key_write_buffer: storage::WRITE_BUFFER,
                value_write_buffer: storage::WRITE_BUFFER,
                max_repair: storage::MAX_REPAIR,
                max_pending_acks: config.max_pending_acks,
                block_codec_config: (),
                strategy: Sequential,
            },
        )
        .await;

        if let Some(marshal_stored_height) = marshal_floor.height() {
            ensure!(
                tip_height >= marshal_stored_height,
                "finalizations archive is inconsistent with the node's consensus metadata: \
                archive tip height `{}` is below stored marshal height `{marshal_stored_height}`; \
                have you overwritten consensus storage from a stale snapshot? delete consensus \
                storage and try again",
                tip_height,
            );
        }

        let startup_floor_height = finalized_floor.0;
        let last_finalized_height = marshal_floor
            .height()
            .map_or(startup_floor_height, |height| {
                height.max(startup_floor_height)
            });

        info!(
            marshal_stored = ?marshal_floor,
            selected_floor = %startup_floor_height,
            "setting marshal sync floor"
        );

        Ok(Initialized {
            actor,
            mailbox,
            finalized_floor: last_finalized_height,
            finalized_tip: (tip_round, tip_height, tip_digest),
            finalized_tip_certificate: finalized_tip.map(|(_, certificate)| certificate),
        })
    }

    struct FinalizationRange {
        floor: (Height, Digest),
        tip: Option<(Height, Certificate)>,
    }

    async fn establish_finalization_range<TContext>(
        certificates: &immutable::Archive<TContext, Digest, Certificate>,
        blocks: &Hybrid<
            TContext,
            BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
        >,
        execution_node: &TempoFullNode,
    ) -> eyre::Result<FinalizationRange>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + Sync + 'static,
    {
        let (first, last) = match (certificates.first_index(), certificates.last_index()) {
            (None, None) => {
                let floor = execution_finalized_point(execution_node);
                ensure!(
                    floor.0.is_zero(),
                    "consensus startup requires a finalized certificate archive unless the \
                     execution layer is empty, but no finalized certificate was found and execution \
                     finalized block is `{}` at height `{}`",
                    floor.1,
                    floor.0,
                );
                return Ok(FinalizationRange { floor, tip: None });
            }
            (Some(first), Some(last)) => (first, last),
            (first, last) => {
                bail!(
                    "finalized certificate archive reported inconsistent index range: \
                    first={first:?}, last={last:?}"
                );
            }
        };
        ensure!(
            first != 0,
            "genesis must not have a finalization certificate"
        );

        let floor_certificate = certificates
            .get(Identifier::Index(first))
            .await
            .wrap_err("failed reading finalized floor certificate")?
            .ok_or_eyre("archive did not contain finalized floor certificate")?;
        let floor = (Height::new(first), floor_certificate.proposal.payload);
        let certificate = if first == last {
            floor_certificate
        } else {
            certificates
                .get(Identifier::Index(last))
                .await
                .wrap_err("failed reading finalized tip certificate")?
                .ok_or_eyre("archive did not contain finalized tip certificate")?
        };
        let height = Height::new(last);
        let header = blocks
            .get_header(Identifier::Key(&certificate.proposal.payload))
            .await
            .wrap_err("failed reading finalized tip header")?;
        if let Some(header) = &header {
            verify_tip_header(height, certificate.proposal.payload, header)?;
        }

        Ok(FinalizationRange {
            floor,
            tip: Some((height, certificate)),
        })
    }

    fn verify_tip_header(height: Height, digest: Digest, header: &TempoHeader) -> eyre::Result<()> {
        ensure!(
            header.number() == height.get(),
            "finalized tip header number `{}` does not match archive height `{height}`",
            header.number(),
        );
        ensure!(
            Digest(header.hash_slow()) == digest,
            "finalized tip header hash does not match certificate payload at height `{height}`",
        );
        Ok(())
    }

    async fn start_from_finalized_floor<TContext>(
        archive: &immutable::Archive<TContext, Digest, Certificate>,
        execution_node: &TempoFullNode,
        finalized_floor: (Height, Digest),
    ) -> eyre::Result<marshal::Start<Scheme<PublicKey, MinSig>, Digest, Block>>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        if !finalized_floor.0.is_zero() {
            match archive
                .get(Identifier::Index(finalized_floor.0.get()))
                .await
                .wrap_err("failed reading finalization")?
            {
                Some(finalization) => return Ok(marshal::Start::Floor(finalization)),
                None => {
                    bail!("finalized range floor missing from archive");
                }
            }
        }

        let genesis_hash = execution_node.chain_spec().genesis_hash();
        let genesis = execution_node
            .provider
            .find_sealed_or_recovered_block(genesis_hash, reth_provider::BlockSource::Any)
            .wrap_err("failed querying execution layer for genesis block")?
            .ok_or_eyre("execution layer did not contain the genesis block")?;
        Ok(marshal::Start::Genesis(
            Block::from_execution_block_unchecked(genesis, None),
        ))
    }

    #[instrument(skip_all, fields(epoch = %finalization.epoch()), err)]
    async fn register_scheme<TContext>(
        context: &mut TContext,
        epoch_strategy: &FixedEpocher,
        scheme_provider: &SchemeProvider,
        chain_spec: &tempo_chainspec::TempoChainSpec,
        finalized_blocks: &Hybrid<
            TContext,
            BlockchainProvider<NodeTypesWithDBAdapter<TempoNode, DatabaseEnv>>,
        >,
        finalization: &Certificate,
    ) -> eyre::Result<()>
    where
        TContext: Clock + Metrics + Storage + BufferPooler + CryptoRng + Send + Sync + 'static,
    {
        let epoch = finalization.epoch();
        let boundary = boundary_for_epoch(epoch_strategy, epoch)?;
        let header = finalized_blocks
            .get_header(Identifier::Index(boundary.get()))
            .await
            .wrap_err_with(|| format!("failed reading boundary header at height `{boundary}`"))?
            .ok_or_else(|| {
                eyre!("missing boundary header at height `{boundary}` in hybrid store")
            })?;

        let onchain_outcome = OnchainDkgOutcome::decode_boundary(
            header.extra_data().as_ref(),
            &chain_spec.tempo_hardfork_at(header.timestamp()),
        )
        .wrap_err("failed to read DKG outcome from boundary header")?;
        ensure!(
            onchain_outcome.epoch() == epoch,
            "boundary outcome is for epoch `{}`, expected finalization epoch `{epoch}`",
            onchain_outcome.epoch,
        );

        let scheme = Scheme::verifier(
            crate::config::NAMESPACE,
            onchain_outcome.players().clone(),
            onchain_outcome.sharing().clone(),
        );

        ensure!(
            finalization.verify(context, &scheme, &Sequential),
            "finalized floor failed verification"
        );

        scheme_provider.register(epoch, scheme);
        Ok(())
    }

    fn boundary_for_epoch(epoch_strategy: &FixedEpocher, epoch: Epoch) -> eyre::Result<Height> {
        let Some(previous) = epoch.previous() else {
            return Ok(Height::zero());
        };
        epoch_strategy.last(previous).ok_or_else(|| {
            eyre!("epoch strategy did not provide a boundary for epoch `{previous}`")
        })
    }

    fn execution_finalized_point(execution_node: &TempoFullNode) -> (Height, Digest) {
        execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| (Height::new(nh.number), Digest(nh.hash)))
            .unwrap_or_else(|| {
                (
                    Height::zero(),
                    Digest(execution_node.chain_spec().genesis_hash()),
                )
            })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn startup_tip_header_must_match_archive_height_and_certificate_digest() {
            let height = Height::new(12);
            let mut header = TempoHeader::default();
            header.inner.number = height.get();
            let digest = Digest(header.hash_slow());
            verify_tip_header(height, digest, &header).unwrap();

            let error = verify_tip_header(height.next(), digest, &header).unwrap_err();
            assert!(error.to_string().contains("does not match archive height"));

            header.inner.extra_data = vec![1].into();
            let error = verify_tip_header(height, digest, &header).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("header hash does not match certificate payload")
            );
        }
    }
}
