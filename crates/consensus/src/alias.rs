//! A collection of aliases and shared initialization for frequently used
//! (primarily commonware) types.

pub(crate) mod marshal {
    use std::{num::NonZeroUsize, sync::Arc};

    use alloy_consensus::BlockHeader as _;
    use commonware_codec::ReadExt as _;
    use commonware_consensus::{
        Epochable as _,
        marshal::{self, core, standard::Standard},
        simplex::{scheme::bls12381_threshold::vrf::Scheme, types::Finalization},
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
    use reth_provider::{
        BlockHashReader as _, BlockReader as _, HeaderProvider as _, providers::BlockchainProvider,
    };
    use tempo_dkg_onchain_artifacts::OnchainDkgOutcome;
    use tempo_node::{TempoFullNode, node::TempoNode};
    use tracing::{info, instrument};

    use crate::{
        consensus::{Digest, block::Block},
        epoch::SchemeProvider,
        storage::{self, Hybrid},
    };

    pub(crate) type Actor<TContext> = core::Actor<
        TContext,
        Standard<Block>,
        SchemeProvider,
        immutable::Archive<TContext, Digest, Finalization<Scheme<PublicKey, MinSig>, Digest>>,
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

        /// Finalized tip selected at startup from the archive or genesis.
        pub startup_tip: StartupTip,
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
        )
        .await
        .wrap_err("failed to initialize finalizations by height archive")?;

        let FinalizationRange {
            floor: finalized_floor,
            tip: startup_tip,
        } = establish_finalization_range(&finalizations_by_height, &execution_node).await?;
        info!(
            floor_height = %finalized_floor.height,
            floor_digest = %finalized_floor.digest,
            tip_height = %startup_tip.height,
            tip_digest = %startup_tip.digest,
            "selected finalized startup range"
        );
        let start = start_from_finalized_floor(
            &finalizations_by_height,
            &execution_node,
            finalized_floor.point(),
        )
        .await?;

        if let marshal::Start::Floor(finalization) = &start {
            register_scheme(
                &mut context,
                &config.epoch_strategy,
                &config.scheme_provider,
                &execution_node,
                (finalized_floor.height, finalization),
            )?;
        }

        let finalized_blocks = storage::init_finalized_blocks(
            &context,
            &config.partition_prefix,
            page_cache.clone(),
            execution_node.provider.clone(),
            config.finalized_blocks_retention,
        )
        .await
        .wrap_err("failed to initialize hybrid finalized blocks store")?;

        let (actor, mailbox, marshal_stored_height) = core::Actor::init(
            context,
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: config.scheme_provider,
                epocher: config.epoch_strategy,
                start,
                partition_prefix: config.partition_prefix,
                mailbox_size: config.mailbox_size,
                view_retention_timeout: config.view_retention_timeout,
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

        let startup_floor_height = finalized_floor.height;
        let last_finalized_height = marshal_stored_height.map_or(startup_floor_height, |height| {
            height.max(startup_floor_height)
        });

        info!(
            marshal_stored = ?marshal_stored_height,
            selected_floor = %startup_floor_height,
            "setting marshal sync floor"
        );

        Ok(Initialized {
            actor,
            mailbox,
            finalized_floor: last_finalized_height,
            startup_tip,
        })
    }

    struct FinalizationRange {
        floor: StartupTip,
        tip: StartupTip,
    }

    /// A finalized block selected at startup.
    ///
    /// Genesis has no certificate, so its round is `None`. Other startup tips
    /// come from certificates and have a round. The round lets callers compare
    /// the tip with a gossiped certificate before they know its block height.
    /// Feed tips always have a round, so they use a separate type.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct StartupTip {
        pub(crate) round: Option<Round>,
        pub(crate) height: Height,
        pub(crate) digest: Digest,
    }

    impl StartupTip {
        pub(crate) const fn point(&self) -> (Height, Digest) {
            (self.height, self.digest)
        }
    }

    async fn establish_finalization_range<TContext>(
        finalizations_by_height: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
        execution_node: &TempoFullNode,
    ) -> eyre::Result<FinalizationRange>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let archive_range = finalized_archive_range(finalizations_by_height)
            .await
            .wrap_err("failed to establish finalized archive bounds")?;
        let execution_tip = execution_finalized_tip(execution_node);

        match archive_range {
            Some((floor, tip)) => Ok(FinalizationRange { floor, tip }),
            None if execution_tip.height.is_zero() => Ok(FinalizationRange {
                floor: execution_tip,
                tip: execution_tip,
            }),
            None => Err(eyre!(
                "consensus startup requires a finalized certificate archive unless the \
                    execution layer is empty, but no finalized certificate was found and execution \
                    finalized block is `{}` at height `{}`",
                execution_tip.digest,
                execution_tip.height,
            )),
        }
    }

    async fn finalized_archive_range<TContext>(
        archive: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
    ) -> eyre::Result<Option<(StartupTip, StartupTip)>>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let (first, last) = match (archive.first_index(), archive.last_index()) {
            (None, None) => return Ok(None),
            (Some(first), Some(last)) => (first, last),
            (first, last) => {
                bail!(
                    "finalized certificate archive reported inconsistent index range: \
                    first={first:?}, last={last:?}"
                );
            }
        };

        let floor = finalized_archive_tip(archive, first)
            .await
            .wrap_err_with(|| {
                format!("failed to read finalized floor from archive at height `{first}`")
            })?;
        let tip = if first == last {
            floor
        } else {
            finalized_archive_tip(archive, last)
                .await
                .wrap_err_with(|| {
                    format!("failed to read finalized tip from archive at height `{last}`")
                })?
        };

        Ok(Some((floor, tip)))
    }

    async fn start_from_finalized_floor<TContext>(
        archive: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
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

    fn register_scheme<R: CryptoRng>(
        rng: &mut R,
        epoch_strategy: &FixedEpocher,
        scheme_provider: &SchemeProvider,
        execution_node: &TempoFullNode,
        (height, finalization): (Height, &Finalization<Scheme<PublicKey, MinSig>, Digest>),
    ) -> eyre::Result<()> {
        let digest = execution_node
            .provider
            .block_hash(height.get())
            .map_err(eyre::Report::new)
            .wrap_err("failed reading finalized floor block hash")?
            .ok_or_eyre("missing finalized floor block hash")?;

        ensure!(
            digest == finalization.proposal.payload.0,
            "finalization digest does not match execution state"
        );

        let epoch = finalization.epoch();
        let boundary = boundary_for_epoch(epoch_strategy, epoch)?;
        let header = execution_node
            .provider
            .header_by_number(boundary.get())
            .map_err(eyre::Report::new)
            .wrap_err("failed reading block header")?
            .ok_or_eyre("missing boundary header")?;
        let onchain_outcome = OnchainDkgOutcome::read(&mut header.extra_data().as_ref())
            .wrap_err("failed to read DKG outcome from boundary header")?;
        let scheme = Scheme::verifier(
            crate::config::NAMESPACE,
            onchain_outcome.players().clone(),
            onchain_outcome.sharing().clone(),
        );

        ensure!(
            finalization.verify(rng, &scheme, &Sequential),
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

    async fn finalized_archive_tip<TContext>(
        archive: &immutable::Archive<
            TContext,
            Digest,
            Finalization<Scheme<PublicKey, MinSig>, Digest>,
        >,
        height: u64,
    ) -> eyre::Result<StartupTip>
    where
        TContext: Clock + Metrics + Spawner + Storage + BufferPooler + Send + 'static,
    {
        let finalization = archive
            .get(Identifier::Index(height))
            .await
            .wrap_err("failed reading certificate from archive")?
            .ok_or_eyre("archive did not contain certificate")?;
        Ok(StartupTip {
            round: Some(finalization.proposal.round),
            height: Height::new(height),
            digest: finalization.proposal.payload,
        })
    }

    fn execution_finalized_tip(execution_node: &TempoFullNode) -> StartupTip {
        let (height, digest) = execution_node
            .provider
            .canonical_in_memory_state()
            .get_finalized_num_hash()
            .map(|nh| (Height::new(nh.number), Digest(nh.hash)))
            .unwrap_or_else(|| {
                (
                    Height::zero(),
                    Digest(execution_node.chain_spec().genesis_hash()),
                )
            });
        StartupTip {
            round: None,
            height,
            digest,
        }
    }

    #[cfg(test)]
    mod tests {
        use alloy_primitives::B256;
        use commonware_codec::{FixedSize, types::lazy::Lazy};
        use commonware_consensus::{
            simplex::{
                scheme::bls12381_threshold::vrf::{
                    Certificate as VrfCertificate, Signature as VrfSignature,
                },
                types::Proposal,
            },
            types::{Epoch, View},
        };
        use commonware_macros::test_traced;
        use commonware_runtime::{Runner as _, deterministic};

        use super::*;

        /// Uses a dummy signature because this test reads only the proposal.
        fn make_finalization(
            height: u64,
            digest: Digest,
        ) -> Finalization<Scheme<PublicKey, MinSig>, Digest> {
            let signature_bytes = [0u8; <VrfSignature<MinSig> as FixedSize>::SIZE];
            Finalization {
                proposal: Proposal::new(
                    Round::new(Epoch::zero(), View::new(height)),
                    View::zero(),
                    digest,
                ),
                certificate: VrfCertificate {
                    signature: Lazy::deferred(&mut &signature_bytes[..], ()),
                },
            }
        }

        #[test_traced]
        fn single_certificate_archive_preserves_tip_round() {
            deterministic::Runner::default().start(|context| async move {
                let height = 7u64;
                let digest = Digest(B256::with_last_byte(height as u8));
                let certificate = make_finalization(height, digest);
                let expected = StartupTip {
                    round: Some(certificate.proposal.round),
                    height: Height::new(height),
                    digest,
                };
                let page_cache = CacheRef::from_pooler(
                    &context,
                    storage::BUFFER_POOL_PAGE_SIZE,
                    storage::BUFFER_POOL_CAPACITY,
                );
                let mut archive =
                    storage::init_finalizations_archive(&context, "test-alias", page_cache)
                        .await
                        .expect("initialize finalizations archive");
                archive
                    .put(height, digest, certificate)
                    .await
                    .expect("store finalization");

                let range = finalized_archive_range(&archive)
                    .await
                    .expect("read archive range");

                assert_eq!(range, Some((expected, expected)));
            });
        }
    }
}
