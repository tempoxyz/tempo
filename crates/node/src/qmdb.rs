use crate::node::{QmdbArgs, StateRootBackend};
use alloy_eips::BlockNumHash;
use reth_chainspec::{ChainInfo, ChainSpecProvider, EthChainSpec};
use reth_engine_tree::{
    persistence::{RemoveBlocksHook, SaveBlocksHook},
    tree::{BasicEngineValidator, TreeConfig, payload_validator::CustomStateRootInput},
};
use reth_node_api::{
    BlockTy, ConfigureEngineEvm, FullNodeComponents, NodeTypes, PayloadTypes, PayloadValidator,
};
use reth_node_builder::{
    AddOnsContext, NodeConfig,
    invalid_block_hook::InvalidBlockHookExt,
    rpc::{EngineValidatorBuilder, PayloadValidatorBuilder},
};
use reth_primitives_traits::AlloyBlockHeader;
use reth_provider::{ProviderError, ProviderResult};
use reth_qmdb::{
    QmdbBlock, QmdbConfig, QmdbStage, QmdbState, QmdbStateProviderFactory, genesis_hashed_state,
};
use reth_stages::{StageId, StageSetBuilder};
use reth_storage_api::{
    AccountReader, BlockHashReader, BlockIdReader, BlockNumReader, ChangeSetReader, HeaderProvider,
    StateProviderBox, StateProviderFactory, StateReader, StorageChangeSetReader, StorageReader,
};
use reth_trie_common::{HashedPostState, updates::TrieUpdates};
use reth_trie_db::ChangesetCache;
use std::{
    fmt,
    sync::{Arc, OnceLock},
};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_primitives::TempoPrimitives;

/// Lazy QMDB state opener shared across node services.
#[derive(Clone)]
pub struct QmdbStateLoader {
    args: QmdbArgs,
    state: Arc<OnceLock<QmdbState>>,
}

impl Default for QmdbStateLoader {
    fn default() -> Self {
        Self::new(QmdbArgs::default())
    }
}

impl fmt::Debug for QmdbStateLoader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QmdbStateLoader")
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

impl QmdbStateLoader {
    /// Creates a QMDB state loader.
    pub fn new(args: QmdbArgs) -> Self {
        Self {
            args,
            state: Arc::new(OnceLock::new()),
        }
    }

    /// Returns the QMDB config for a node config.
    pub fn config_for_node<ChainSpec>(&self, config: &NodeConfig<ChainSpec>) -> QmdbConfig
    where
        ChainSpec: EthChainSpec,
    {
        QmdbConfig::new(config.datadir().data_dir().join("qmdb"))
            .with_partition_prefix(self.args.partition_prefix.clone())
            .with_worker_threads(self.args.worker_threads)
    }

    /// Opens the QMDB state store.
    pub fn open<ChainSpec>(&self, config: &NodeConfig<ChainSpec>) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
    {
        if let Some(state) = self.state.get() {
            return Ok(state.clone());
        }

        let state = QmdbState::open(self.config_for_node(config))?;
        let _ = self.state.set(state);
        Ok(self
            .state
            .get()
            .expect("QMDB state was just initialized")
            .clone())
    }

    /// Opens QMDB and commits genesis if needed.
    pub fn open_initialized<ChainSpec>(
        &self,
        config: &NodeConfig<ChainSpec>,
    ) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
    {
        let state = self.open(config)?;
        if state.head()?.is_none() {
            let genesis = config.chain.genesis_header();
            state.commit_block(
                QmdbBlock {
                    number: genesis.number(),
                    hash: config.chain.genesis_hash(),
                    parent_hash: genesis.parent_hash(),
                },
                genesis_hashed_state(config.chain.genesis()),
            )?;
        }
        Ok(state)
    }

    /// Opens initialized QMDB and reconciles it against the canonical DB.
    pub fn open_for_provider<ChainSpec, Provider>(
        &self,
        config: &NodeConfig<ChainSpec>,
        provider: &Provider,
    ) -> eyre::Result<QmdbState>
    where
        ChainSpec: EthChainSpec,
        Provider: BlockNumReader + HeaderProvider,
    {
        let state = self.open_initialized(config)?;
        state.reconcile_canonical(provider)?;
        Ok(state)
    }

    pub(crate) fn batch_blocks(&self) -> u64 {
        self.args.batch_blocks
    }
}

/// State provider factory used by Tempo payload building.
#[derive(Clone, Debug)]
pub enum TempoStateRootProviderFactory<P> {
    Mpt(P),
    Qmdb(QmdbStateProviderFactory<P>),
}

impl<P> TempoStateRootProviderFactory<P> {
    /// Creates an MPT-backed provider factory.
    pub const fn mpt(provider: P) -> Self {
        Self::Mpt(provider)
    }

    /// Creates a QMDB-backed provider factory.
    pub const fn qmdb(provider: P, qmdb: QmdbState) -> Self {
        Self::Qmdb(QmdbStateProviderFactory::new(provider, qmdb))
    }
}

impl<P: BlockHashReader> BlockHashReader for TempoStateRootProviderFactory<P> {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<alloy_primitives::B256>> {
        match self {
            Self::Mpt(provider) => provider.block_hash(number),
            Self::Qmdb(provider) => provider.block_hash(number),
        }
    }

    fn canonical_hashes_range(
        &self,
        start: u64,
        end: u64,
    ) -> ProviderResult<Vec<alloy_primitives::B256>> {
        match self {
            Self::Mpt(provider) => provider.canonical_hashes_range(start, end),
            Self::Qmdb(provider) => provider.canonical_hashes_range(start, end),
        }
    }
}

impl<P: BlockNumReader> BlockNumReader for TempoStateRootProviderFactory<P> {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        match self {
            Self::Mpt(provider) => provider.chain_info(),
            Self::Qmdb(provider) => provider.chain_info(),
        }
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.best_block_number(),
            Self::Qmdb(provider) => provider.best_block_number(),
        }
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.last_block_number(),
            Self::Qmdb(provider) => provider.last_block_number(),
        }
    }

    fn earliest_block_number(&self) -> ProviderResult<u64> {
        match self {
            Self::Mpt(provider) => provider.earliest_block_number(),
            Self::Qmdb(provider) => provider.earliest_block_number(),
        }
    }

    fn block_number(&self, hash: alloy_primitives::B256) -> ProviderResult<Option<u64>> {
        match self {
            Self::Mpt(provider) => provider.block_number(hash),
            Self::Qmdb(provider) => provider.block_number(hash),
        }
    }
}

impl<P: BlockIdReader> BlockIdReader for TempoStateRootProviderFactory<P> {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.pending_block_num_hash(),
            Self::Qmdb(provider) => provider.pending_block_num_hash(),
        }
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.safe_block_num_hash(),
            Self::Qmdb(provider) => provider.safe_block_num_hash(),
        }
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        match self {
            Self::Mpt(provider) => provider.finalized_block_num_hash(),
            Self::Qmdb(provider) => provider.finalized_block_num_hash(),
        }
    }
}

impl<P: ChainSpecProvider> ChainSpecProvider for TempoStateRootProviderFactory<P> {
    type ChainSpec = P::ChainSpec;

    fn chain_spec(&self) -> Arc<Self::ChainSpec> {
        match self {
            Self::Mpt(provider) => provider.chain_spec(),
            Self::Qmdb(provider) => provider.chain_spec(),
        }
    }
}

impl<P: StateProviderFactory> StateProviderFactory for TempoStateRootProviderFactory<P> {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.latest(),
            Self::Qmdb(provider) => provider.latest(),
        }
    }

    fn state_by_block_number_or_tag(
        &self,
        number_or_tag: alloy_eips::BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.state_by_block_number_or_tag(number_or_tag),
            Self::Qmdb(provider) => provider.state_by_block_number_or_tag(number_or_tag),
        }
    }

    fn history_by_block_number(&self, block: u64) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.history_by_block_number(block),
            Self::Qmdb(provider) => provider.history_by_block_number(block),
        }
    }

    fn history_by_block_hash(
        &self,
        block: alloy_primitives::B256,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.history_by_block_hash(block),
            Self::Qmdb(provider) => provider.history_by_block_hash(block),
        }
    }

    fn state_by_block_hash(
        &self,
        block: alloy_primitives::B256,
    ) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.state_by_block_hash(block),
            Self::Qmdb(provider) => provider.state_by_block_hash(block),
        }
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        match self {
            Self::Mpt(provider) => provider.pending(),
            Self::Qmdb(provider) => provider.pending(),
        }
    }

    fn pending_state_by_hash(
        &self,
        block_hash: alloy_primitives::B256,
    ) -> ProviderResult<Option<StateProviderBox>> {
        match self {
            Self::Mpt(provider) => provider.pending_state_by_hash(block_hash),
            Self::Qmdb(provider) => provider.pending_state_by_hash(block_hash),
        }
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        match self {
            Self::Mpt(provider) => provider.maybe_pending(),
            Self::Qmdb(provider) => provider.maybe_pending(),
        }
    }
}

/// Engine validator builder that switches to QMDB roots for QMDB chain specs.
#[derive(Debug, Clone)]
pub struct QmdbEngineValidatorBuilder<EV> {
    payload_validator_builder: EV,
    qmdb: QmdbStateLoader,
    state_root_backend: Option<StateRootBackend>,
}

impl<EV> QmdbEngineValidatorBuilder<EV> {
    /// Creates a QMDB-aware engine validator builder.
    pub const fn new(
        payload_validator_builder: EV,
        qmdb: QmdbStateLoader,
        state_root_backend: Option<StateRootBackend>,
    ) -> Self {
        Self {
            payload_validator_builder,
            qmdb,
            state_root_backend,
        }
    }

    fn backend(&self, chain_spec: &TempoChainSpec) -> StateRootBackend {
        StateRootBackend::resolve(self.state_root_backend, chain_spec)
    }
}

impl<Node, EV> EngineValidatorBuilder<Node> for QmdbEngineValidatorBuilder<EV>
where
    Node: FullNodeComponents<
            Evm: ConfigureEngineEvm<
                <<Node::Types as NodeTypes>::Payload as PayloadTypes>::ExecutionData,
            >,
            Types: NodeTypes<ChainSpec = TempoChainSpec, Primitives = TempoPrimitives>,
        >,
    EV: PayloadValidatorBuilder<Node>,
    EV::Validator:
        PayloadValidator<<Node::Types as NodeTypes>::Payload, Block = BlockTy<Node::Types>> + Clone,
{
    type EngineValidator = BasicEngineValidator<Node::Provider, Node::Evm, EV::Validator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        changeset_cache: ChangesetCache,
    ) -> eyre::Result<Self::EngineValidator> {
        let backend = self.backend(ctx.config.chain.as_ref());
        let validator = self.payload_validator_builder.build(ctx).await?;
        let data_dir = ctx
            .config
            .datadir
            .clone()
            .resolve_datadir(ctx.config.chain.chain());
        let invalid_block_hook = ctx.create_invalid_block_hook(&data_dir).await?;

        let validator = BasicEngineValidator::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            ctx.node.evm_config().clone(),
            validator,
            tree_config,
            invalid_block_hook,
            changeset_cache,
            ctx.node.task_executor().clone(),
        );

        if !matches!(backend, StateRootBackend::Qmdb) {
            return Ok(validator);
        }

        let qmdb = self
            .qmdb
            .open_for_provider(ctx.config, ctx.node.provider())?;
        let save_qmdb = qmdb.clone();
        let save_blocks_hook: SaveBlocksHook<TempoPrimitives> = Arc::new(move |blocks| {
            let mut qmdb_blocks = Vec::with_capacity(blocks.len());
            for block in blocks {
                let recovered = block.recovered_block();
                let header = recovered.header();
                qmdb_blocks.push((
                    QmdbBlock {
                        number: header.number(),
                        hash: recovered.hash(),
                        parent_hash: header.parent_hash(),
                    },
                    HashedPostState::from((*block.hashed_state()).clone()),
                ));
            }
            if let Some((first, _)) = qmdb_blocks.first()
                && let Some(head) = save_qmdb.head().map_err(ProviderError::other)?
                && (head.number >= first.number || head.hash != first.parent_hash)
            {
                save_qmdb
                    .rewind_to_block(first.number.saturating_sub(1))
                    .map_err(ProviderError::other)?;
            }
            save_qmdb
                .commit_blocks(qmdb_blocks)
                .map(|_| ())
                .map_err(ProviderError::other)
        });

        let remove_qmdb = qmdb.clone();
        let remove_blocks_hook: RemoveBlocksHook = Arc::new(move |new_tip| {
            remove_qmdb
                .rewind_to_block(new_tip)
                .map(|_| ())
                .map_err(ProviderError::other)
        });

        let root_qmdb = qmdb;
        let custom_state_root =
            Arc::new(move |input: CustomStateRootInput<'_, TempoPrimitives>| {
                root_qmdb
                    .overlay_root(input.hashed_state.get().as_ref().clone())
                    .map(|commit| (commit.root, TrieUpdates::default()))
                    .map_err(ProviderError::other)
            });

        Ok(validator
            .with_custom_state_root(custom_state_root)
            .with_persistence_hooks(Some(save_blocks_hook), Some(remove_blocks_hook)))
    }

    fn customize_pipeline_stages<Provider>(
        &self,
        config: &NodeConfig<<Node::Types as NodeTypes>::ChainSpec>,
        stages: StageSetBuilder<Provider>,
    ) -> eyre::Result<StageSetBuilder<Provider>>
    where
        Provider: HeaderProvider<
                Header = <<Node::Types as NodeTypes>::Primitives as reth_primitives_traits::NodePrimitives>::BlockHeader,
            > + AccountReader
            + ChangeSetReader
            + StorageChangeSetReader
            + StorageReader
            + StateReader
            + BlockNumReader
            + Send
            + 'static,
    {
        if !matches!(self.backend(config.chain.as_ref()), StateRootBackend::Qmdb) {
            return Ok(stages);
        }

        let qmdb = self.qmdb.open_initialized(config)?;
        Ok(stages
            .disable_all(&[
                StageId::MerkleUnwind,
                StageId::AccountHashing,
                StageId::StorageHashing,
                StageId::MerkleExecute,
            ])
            .add_after(
                QmdbStage::new(qmdb).with_batch_blocks(self.qmdb.batch_blocks()),
                StageId::Execution,
            ))
    }
}
