//! Read access to the post-state of blocks that the engine has executed.

use std::sync::{Arc, RwLock};

use alloy_primitives::{Address, B256};
use eyre::{OptionExt as _, WrapErr as _};
use reth_chainspec::EthChainSpec as _;
use reth_engine_tree::tree::{
    TxPoolPrewarmSource, TxPoolPrewarmTransaction, TxPoolPrewarmTransactions,
};
use reth_node_api::{AddOnsContext, FullNodeComponents, PrimitivesTy, TreeConfig};
use reth_node_builder::{
    invalid_block_hook::InvalidBlockHookExt as _,
    rpc::{BasicEngineValidator, EngineValidatorBuilder, PayloadValidatorBuilder as _},
};
use reth_storage_api::{
    AccountReader as _, DatabaseProviderROFactory, StateProvider, StateProviderBox,
};
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use reth_transaction_pool::{
    BestTransactions as _, BestTransactionsAttributes, PoolTransaction, TransactionPool,
};
use tempo_primitives::{TempoPrimitives, TempoTxEnvelope};

use crate::{TempoNode, engine::TempoEngineValidator, node::TempoEngineValidatorBuilder};

/// Reads the post-state of blocks that the engine has executed, including
/// blocks on forks.
///
/// The provider serves state only for the canonical chain and for the
/// engine's single pending block. The engine keeps each block that it has
/// executed in memory until the block is persisted or its fork is pruned, and
/// this does not depend on which block is the head. This handle reads through
/// that in-memory overlay. The engine uses the same overlay when it executes a
/// payload on top of its parent. Blocks that are persisted are read from the
/// database.
///
/// reth creates the overlay when it launches the engine, and gives it only to
/// the engine validator builder. [`TempoEngineTreeValidatorBuilder`] puts it
/// into this handle. Until then, the handle is empty and all reads fail.
#[derive(Clone, Debug, Default)]
pub struct ExecutedState {
    overlay_manager: Arc<RwLock<Option<OverlayManager<TempoPrimitives>>>>,
}

impl ExecutedState {
    /// Returns whether reth has given the engine's overlay to this handle,
    /// which happens when the node launches.
    pub fn is_launched(&self) -> bool {
        self.overlay_manager
            .read()
            .expect("the lock is never held across a panic")
            .is_some()
    }

    /// Returns the post-state of the block `block_hash`.
    ///
    /// Fails if the engine has not executed the block, or if the block was on
    /// a fork that the engine has pruned.
    pub fn state_by_block_hash<P>(
        &self,
        provider: P,
        block_hash: B256,
    ) -> eyre::Result<StateProviderBox>
    where
        OverlayStateProviderFactory<P, TempoPrimitives>:
            DatabaseProviderROFactory<Provider: StateProvider + Send + 'static>,
    {
        let overlay_manager = self
            .overlay_manager
            .read()
            .expect("the lock is never held across a panic")
            .clone()
            .ok_or_eyre("the engine is not launched yet")?;
        let state =
            OverlayStateProviderFactory::new(provider, overlay_manager.overlay_builder(block_hash))
                .database_provider_ro()
                .wrap_err("failed opening a read-only database provider")?;

        // The overlay looks up `block_hash` on the first read. Read once here
        // so that an unknown block fails now, and callers never run on a
        // state that cannot be resolved.
        state.basic_account(&Address::ZERO).wrap_err_with(|| {
            format!("failed reading the engine's state for block `{block_hash}`")
        })?;
        Ok(Box::new(state))
    }

    fn set(&self, overlay_manager: OverlayManager<TempoPrimitives>) {
        *self
            .overlay_manager
            .write()
            .expect("the lock is never held across a panic") = Some(overlay_manager);
    }
}

/// Builds the engine validator and gives the engine's in-memory overlay to an
/// [`ExecutedState`].
#[derive(Clone, Debug)]
pub struct TempoEngineTreeValidatorBuilder {
    payload_validator_builder: TempoEngineValidatorBuilder,
    executed_state: ExecutedState,
}

impl TempoEngineTreeValidatorBuilder {
    /// Creates a builder that fills `executed_state` when reth launches the
    /// engine.
    pub fn new(executed_state: ExecutedState) -> Self {
        Self {
            payload_validator_builder: TempoEngineValidatorBuilder,
            executed_state,
        }
    }
}

impl<Node> EngineValidatorBuilder<Node> for TempoEngineTreeValidatorBuilder
where
    Node: FullNodeComponents<Types = TempoNode, Evm = tempo_evm::TempoEvmConfig>,
{
    type EngineValidator =
        BasicEngineValidator<Node::Provider, tempo_evm::TempoEvmConfig, TempoEngineValidator>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        overlay_manager: OverlayManager<PrimitivesTy<Node::Types>>,
    ) -> eyre::Result<Self::EngineValidator> {
        self.executed_state.set(overlay_manager.clone());
        // Reth installs cached precompiles through `Evm::precompiles_mut`, which
        // correctly disables speculation for potentially custom precompiles.
        // Use the standard precompiles when workers are enabled so Engine API
        // validation runs the same scheduler as block building. Their outputs
        // and gas are unchanged; only the engine's optional result cache is off.
        let tree_config = if ctx.node.evm_config().speculative_executor.is_some() {
            tree_config.without_precompile_cache(true)
        } else {
            tree_config
        };
        let payload_validator = self.payload_validator_builder.build(ctx).await?;
        let data_dir = ctx
            .config
            .datadir
            .clone()
            .resolve_datadir(ctx.config.chain.chain());
        let invalid_block_hook = ctx.create_invalid_block_hook(&data_dir).await?;
        let txpool_prewarming = tree_config.txpool_prewarming();
        let transaction_prewarm_policy = (!tree_config.disable_prewarming())
            .then(|| ctx.node.evm_config().speculative_executor.as_ref())
            .flatten()
            .and_then(|executor| {
                let window = executor.capture_window().transactions();
                reth_engine_tree::tree::payload_processor::prewarm::TransactionPrewarmPolicy::new(
                    window,
                    window,
                    std::time::Duration::from_micros(100),
                )
            });

        // Give only the Engine a marked clone. RPC, builder, and invalid-block
        // hooks retain the original configuration from AddOnsContext.
        let evm_config = ctx.node.evm_config().clone();
        let evm_config = if tree_config.disable_prewarming() {
            evm_config
        } else {
            evm_config.with_engine_prewarming()
        };
        let mut validator = BasicEngineValidator::new(
            ctx.node.provider().clone(),
            Arc::new(ctx.node.consensus().clone()),
            evm_config,
            payload_validator,
            tree_config,
            invalid_block_hook,
            overlay_manager,
            ctx.node.task_executor().clone(),
        )
        .with_transaction_prewarm_policy(transaction_prewarm_policy);
        if txpool_prewarming {
            validator =
                validator.with_txpool_prewarming(TempoTxPoolPrewarmSource(ctx.node.pool().clone()));
        }
        Ok(validator)
    }
}

/// Mirrors Reth's private pool adapter, preserving its parent and fee filters.
#[derive(Debug)]
struct TempoTxPoolPrewarmSource<P>(P);

impl<P> TxPoolPrewarmSource<TempoPrimitives> for TempoTxPoolPrewarmSource<P>
where
    P: TransactionPool<Transaction: PoolTransaction<Consensus = TempoTxEnvelope>> + 'static,
{
    fn best_transactions(
        &self,
        parent_hash: B256,
    ) -> Option<TxPoolPrewarmTransactions<TempoPrimitives>> {
        let block_info = self.0.block_info();
        if block_info.last_seen_block_hash != parent_hash {
            return None;
        }
        let mut best = self
            .0
            .best_transactions_with_attributes(BestTransactionsAttributes::new(
                block_info.pending_basefee,
                block_info
                    .pending_blob_fee
                    .map(|fee| u64::try_from(fee).unwrap_or(u64::MAX)),
            ));
        best.allow_updates_out_of_order();
        best.skip_blobs();
        Some(Box::new(best.map(|transaction| TxPoolPrewarmTransaction {
            hash: *transaction.hash(),
            sender: transaction.sender(),
            transaction: transaction.transaction.clone_into_consensus(),
        })))
    }
}
