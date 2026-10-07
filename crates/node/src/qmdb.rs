//! Experimental QMDB state commitments for isolated development nodes.

use alloy_primitives::B256;
use reth_chainspec::EthChainSpec;
use reth_engine_tree::{
    persistence::{RemoveBlocksHook, SaveBlocksHook},
    tree::state_root_strategy::{
        LazyHashedPostState, PayloadStateRootHandle, PayloadStateRootJobContext,
        PreparedStateRootJob, StateRootJob, StateRootJobContext, StateRootJobOutcome,
        StateRootStrategy, StateRootUpdateStream,
    },
};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::{AlloyBlockHeader, RecoveredBlock};
use reth_provider::{
    BlockExecutionOutput, BlockNumReader, HeaderProvider, ProviderError, ProviderResult,
};
use reth_qmdb::{QmdbBlock, QmdbConfig, QmdbState, genesis_hashed_state};
use reth_revm::state::EvmState;
use reth_trie_common::{HashedPostState, updates::TrieUpdates};
use reth_trie_parallel::state_root_task::{
    StateRootComputeOutcome, StateRootSink, evm_state_to_hashed_post_state,
};
use std::sync::{Arc, OnceLock, mpsc};
use tempo_chainspec::TempoChainSpec;
use tempo_primitives::TempoPrimitives;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum StateRootBackend {
    #[default]
    Mpt,
    Qmdb,
}

#[derive(Clone, Debug, Default)]
pub struct QmdbStateLoader {
    state: Arc<OnceLock<QmdbState>>,
}

impl QmdbStateLoader {
    pub fn open<P: BlockNumReader + HeaderProvider>(
        &self,
        config: &reth_node_builder::NodeConfig<TempoChainSpec>,
        provider: &P,
    ) -> eyre::Result<QmdbState> {
        if !config.dev.dev {
            eyre::bail!("QMDB is experimental and requires an isolated --dev node");
        }
        if let Some(state) = self.state.get() {
            return Ok(state.clone());
        }
        let state = QmdbState::open(QmdbConfig::new(config.datadir().data_dir().join("qmdb")))?;
        if state.head()?.is_none() {
            state.commit_block(
                QmdbBlock {
                    number: 0,
                    hash: config.chain.genesis_hash(),
                    parent_hash: B256::ZERO,
                },
                genesis_hashed_state(config.chain.genesis()),
            )?;
        }
        state.reconcile_canonical(provider)?;
        self.state
            .set(state.clone())
            .map_err(|_| eyre::eyre!("QMDB was initialized concurrently"))?;
        Ok(state)
    }
}

#[derive(Clone, Debug)]
pub struct QmdbStrategy {
    state: QmdbState,
}

impl QmdbStrategy {
    pub fn new(state: QmdbState) -> Self {
        Self { state }
    }

    pub fn persistence_hooks(&self) -> (SaveBlocksHook<TempoPrimitives>, RemoveBlocksHook) {
        let save_state = self.state.clone();
        let save = Arc::new(
            move |blocks: &[reth_chain_state::ExecutedBlock<TempoPrimitives>]| {
                let mutations = blocks
                    .iter()
                    .map(|block| {
                        let recovered = block.recovered_block();
                        (
                            QmdbBlock {
                                number: recovered.number(),
                                hash: recovered.hash(),
                                parent_hash: recovered.parent_hash(),
                            },
                            HashedPostState::from(block.hashed_state().as_ref().clone()),
                        )
                    })
                    .collect::<Vec<_>>();
                if let Some((first, _)) = mutations.first()
                    && let Some(head) = save_state.head().map_err(ProviderError::other)?
                    && head.hash != first.parent_hash
                {
                    save_state
                        .rewind_to_block(first.number.saturating_sub(1))
                        .map_err(ProviderError::other)?;
                }
                let head = save_state
                    .commit_blocks(mutations)
                    .map_err(ProviderError::other)?;
                if let Some(block) = blocks.last()
                    && let Some(head) = head
                    && head.root != block.recovered_block().state_root()
                {
                    return Err(ProviderError::other(std::io::Error::other(
                        "QMDB persistence root differs from the executed block",
                    )));
                }
                Ok(())
            },
        );
        let remove_state = self.state.clone();
        let remove = Arc::new(move |number| {
            remove_state
                .rewind_to_block(number)
                .map(|_| ())
                .map_err(ProviderError::other)
        });
        (save, remove)
    }
}

impl<P, Evm: ConfigureEvm<Primitives = TempoPrimitives>> StateRootStrategy<TempoPrimitives, P, Evm>
    for QmdbStrategy
{
    fn prepare(
        &self,
        _ctx: StateRootJobContext<'_, TempoPrimitives, P, Evm>,
    ) -> ProviderResult<PreparedStateRootJob<TempoPrimitives>> {
        Ok(PreparedStateRootJob::new(
            Box::new(QmdbJob(self.state.clone())),
            None,
        ))
    }

    fn prepare_payload_builder(
        &self,
        ctx: PayloadStateRootJobContext<'_, TempoPrimitives, P>,
    ) -> ProviderResult<Option<PayloadStateRootHandle>> {
        let parent_hash = ctx.parent_hash();
        let number = ctx.parent_header().number() + 1;
        let state = self.state.clone();
        let remembered_state = state.clone();
        let (updates_tx, updates_rx) = mpsc::channel();
        let (root_tx, root_rx) = mpsc::channel();
        let (hashed_tx, hashed_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("qmdb-payload-root".into())
            .spawn(move || {
                let mut hashed_state = HashedPostState::default();
                while let Ok(update) = updates_rx.recv() {
                    match update {
                        RootUpdate::State(update) => hashed_state.extend(update),
                        RootUpdate::Finished => {
                            let hashed_state = Arc::new(hashed_state);
                            let result = state
                                .preview(parent_hash, hashed_state.as_ref().clone())
                                .map(|commit| StateRootComputeOutcome {
                                    state_root: commit.root,
                                    trie_updates: Arc::new(TrieUpdates::default()),
                                    hashed_state: hashed_state.clone(),
                                })
                                .map_err(|error| ProviderError::other(error).into());
                            let _ = hashed_tx.send(hashed_state);
                            let _ = root_tx.send(result);
                            break;
                        }
                    }
                }
            })
            .map_err(ProviderError::other)?;
        let hook = StateRootUpdateStream::new(Arc::new(QmdbSink(updates_tx))).into_state_hook();
        Ok(Some(
            PayloadStateRootHandle::new("qmdb", Some(hook), root_rx, Some(hashed_rx))
                .with_on_payload_built(move |hash, root| {
                    if let Err(error) = remembered_state.remember(
                        QmdbBlock {
                            number,
                            hash,
                            parent_hash,
                        },
                        root,
                    ) {
                        tracing::error!(%error, "failed to retain QMDB payload state");
                    }
                }),
        ))
    }
}

struct QmdbJob(QmdbState);

impl StateRootJob<TempoPrimitives> for QmdbJob {
    fn name(&self) -> &'static str {
        "qmdb"
    }

    fn finish(
        &mut self,
        block: &RecoveredBlock<tempo_primitives::Block>,
        _output: Arc<BlockExecutionOutput<tempo_primitives::TempoReceipt>>,
        hashed_state: &LazyHashedPostState,
    ) -> ProviderResult<StateRootJobOutcome> {
        let commit = self
            .0
            .preview(block.parent_hash(), hashed_state.get().as_ref().clone())
            .map_err(ProviderError::other)?;
        if commit.root == block.state_root() {
            self.0
                .remember(
                    QmdbBlock {
                        number: block.number(),
                        hash: block.hash(),
                        parent_hash: block.parent_hash(),
                    },
                    commit.root,
                )
                .map_err(ProviderError::other)?;
        }
        Ok(StateRootJobOutcome::new(
            commit.root,
            Arc::new(TrieUpdates::default()),
        ))
    }
}

enum RootUpdate {
    State(HashedPostState),
    Finished,
}

struct QmdbSink(mpsc::Sender<RootUpdate>);

impl StateRootSink for QmdbSink {
    fn on_state_update(&self, state: EvmState) {
        self.on_hashed_state_update(evm_state_to_hashed_post_state(state));
    }

    fn on_hashed_state_update(&self, state: HashedPostState) {
        let _ = self.0.send(RootUpdate::State(state));
    }

    fn on_updates_finished(&self) {
        let _ = self.0.send(RootUpdate::Finished);
    }
}
