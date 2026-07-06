use crate::{
    TempoExecutionData,
    engine::TempoEngineValidator,
    node::{TempoEngineValidatorBuilder, TempoNode},
};
use reth_chain_state::StateTrieOverlayManager;
use reth_chainspec::ChainSpecProvider;
use reth_engine_tree::tree::{
    BasicEngineValidator, StateProviderBuilder, TreeConfig,
    payload_processor::multiproof::{PayloadStateRootHandle, StateRootStreams},
    state_root_strategy::{
        DefaultStateRootStrategy, PayloadStateRootJobContext, PreparedStateRootJob, StateRootJob,
        StateRootJobContext, StateRootJobOutcome, StateRootStrategy,
    },
};
use reth_errors::ProviderResult;
use reth_evm::{ConfigureEngineEvm, ConfigureEvm, revm::context::Block as _};
use reth_node_api::FullNodeComponents;
use reth_node_builder::{
    AddOnsContext,
    rpc::{BasicEngineValidatorBuilder, ChangesetCache, EngineValidatorBuilder},
};
use reth_primitives_traits::{AlloyBlockHeader as _, NodePrimitives, RecoveredBlock};
use reth_provider::{
    BlockExecutionOutput, BlockReader, ProviderError, StateProviderFactory, StateReader,
};
use reth_storage_api::StateRootProvider;
use std::{
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};
use tempo_chainspec::{PageAccountPredicate, spec::TempoChainSpec};
use tempo_page_state::{MdbxPageStore, PageStateManager};
use tempo_primitives::TempoPrimitives;

#[derive(Clone, Default)]
pub(crate) struct SharedPageStateManager {
    inner: Arc<Mutex<Option<PageStateManager>>>,
}

impl fmt::Debug for SharedPageStateManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedPageStateManager")
            .field(
                "initialized",
                &self
                    .inner
                    .lock()
                    .map(|manager| manager.is_some())
                    .unwrap_or_default(),
            )
            .finish()
    }
}

impl SharedPageStateManager {
    pub(crate) fn get_or_open(
        &self,
        data_dir: &Path,
        chain_spec: Arc<TempoChainSpec>,
    ) -> eyre::Result<PageStateManager> {
        let mut manager = self
            .inner
            .lock()
            .map_err(|_| eyre::eyre!("page-state manager lock poisoned"))?;
        if let Some(manager) = manager.as_ref() {
            return Ok(manager.clone());
        }

        let store = MdbxPageStore::open(&data_dir.join("page-state"))?;
        let new_manager = PageStateManager::new(store, PageAccountPredicate::new(chain_spec));
        *manager = Some(new_manager.clone());
        Ok(new_manager)
    }
}

#[derive(Clone, Default)]
pub struct TempoPageStateValidatorBuilder {
    inner: BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>,
    page_state_manager: SharedPageStateManager,
}

impl TempoPageStateValidatorBuilder {
    pub(crate) fn new(page_state_manager: SharedPageStateManager) -> Self {
        Self {
            inner: BasicEngineValidatorBuilder::default(),
            page_state_manager,
        }
    }
}

impl fmt::Debug for TempoPageStateValidatorBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoPageStateValidatorBuilder")
            .field("inner", &self.inner)
            .field("page_state_manager", &self.page_state_manager)
            .finish_non_exhaustive()
    }
}

impl<Node> EngineValidatorBuilder<Node> for TempoPageStateValidatorBuilder
where
    Node: FullNodeComponents<Types = TempoNode, Evm: ConfigureEngineEvm<TempoExecutionData>>,
{
    type EngineValidator = BasicEngineValidator<Node::Provider, Node::Evm, TempoEngineValidator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        changeset_cache: ChangesetCache,
        state_trie_overlays: StateTrieOverlayManager<TempoPrimitives>,
    ) -> eyre::Result<Self::EngineValidator> {
        let validator = self
            .inner
            .build_tree_validator(ctx, tree_config, changeset_cache, state_trie_overlays)
            .await?;
        let page_state_manager = self.page_state_manager.get_or_open(
            ctx.config.datadir().data_dir(),
            ctx.node.provider().chain_spec(),
        )?;
        let state_root_strategy: Arc<
            dyn StateRootStrategy<TempoPrimitives, Node::Provider, Node::Evm>,
        > = Arc::new(TempoPageStateRootStrategy {
            manager: page_state_manager,
            default: DefaultStateRootStrategy,
        });
        Ok(validator.with_state_root_strategy(state_root_strategy))
    }
}

#[derive(Debug)]
struct TempoPageStateRootStrategy {
    manager: PageStateManager,
    default: DefaultStateRootStrategy,
}

impl<P, Evm> StateRootStrategy<TempoPrimitives, P, Evm> for TempoPageStateRootStrategy
where
    P: BlockReader + StateProviderFactory + StateReader + Clone + Send + Sync + 'static,
    Evm: ConfigureEvm<Primitives = TempoPrimitives> + 'static,
    DefaultStateRootStrategy: StateRootStrategy<TempoPrimitives, P, Evm>,
{
    fn prepare(
        &self,
        ctx: StateRootJobContext<'_, TempoPrimitives, P, Evm>,
    ) -> ProviderResult<PreparedStateRootJob<TempoPrimitives>> {
        let timestamp = ctx.env().evm_env.block_env.timestamp().saturating_to();
        if !self.manager.is_active(timestamp) {
            return self.default.prepare(ctx);
        }

        Ok(PreparedStateRootJob::new(
            Box::new(TempoPageStateRootJob {
                manager: self.manager.clone(),
                provider_builder: ctx.provider_builder(),
                timestamp,
            }),
            StateRootStreams::empty(),
            None,
        ))
    }

    fn prepare_payload_builder(
        &self,
        ctx: PayloadStateRootJobContext<'_, TempoPrimitives, P, Evm>,
    ) -> ProviderResult<Option<PayloadStateRootHandle>> {
        if !self.manager.is_active(ctx.timestamp()) {
            return self.default.prepare_payload_builder(ctx);
        }

        Ok(None)
    }
}

#[derive(Debug)]
struct TempoPageStateRootJob<P> {
    manager: PageStateManager,
    provider_builder: StateProviderBuilder<TempoPrimitives, P>,
    timestamp: u64,
}

impl<P> StateRootJob<TempoPrimitives> for TempoPageStateRootJob<P>
where
    P: BlockReader + StateProviderFactory + StateReader + Clone + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        "tempo-page-state"
    }

    fn finish(
        &mut self,
        block: &RecoveredBlock<<TempoPrimitives as NodePrimitives>::Block>,
        output: Arc<BlockExecutionOutput<<TempoPrimitives as NodePrimitives>::Receipt>>,
        hashed_state: &reth_engine_tree::tree::payload_validator::LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let mut bundle = output.state.clone();
        let mut hashed_state = hashed_state.get().as_ref().clone();
        let updates = self
            .manager
            .process_block(
                self.timestamp,
                block.parent_hash(),
                &mut bundle,
                &mut hashed_state,
            )
            .map_err(ProviderError::other)?;

        let provider = self.provider_builder.clone().build()?;
        let (state_root, trie_updates) = provider.state_root_with_updates(hashed_state.clone())?;
        if state_root == block.state_root() {
            self.manager
                .insert_block(block.hash(), block.number(), block.parent_hash(), updates)
                .map_err(ProviderError::other)?;
        }

        Ok(StateRootJobOutcome::new(state_root, Arc::new(trie_updates))
            .with_hashed_state(Some(Arc::new(hashed_state))))
    }
}
