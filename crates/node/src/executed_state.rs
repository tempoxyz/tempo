//! Read access to the post-state of blocks that the engine has executed.

use std::sync::{Arc, RwLock};

use alloy_primitives::{Address, B256};
use eyre::{OptionExt as _, WrapErr as _};
use reth_node_api::{AddOnsContext, FullNodeComponents, PrimitivesTy, TreeConfig};
use reth_node_builder::rpc::{BasicEngineValidatorBuilder, EngineValidatorBuilder};
use reth_storage_api::{
    AccountReader as _, DatabaseProviderROFactory, StateProvider, StateProviderBox,
};
use reth_storage_overlay::{OverlayManager, OverlayStateProviderFactory};
use tempo_primitives::TempoPrimitives;

use crate::{TempoNode, node::TempoEngineValidatorBuilder};

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
    inner: BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>,
    executed_state: ExecutedState,
}

impl TempoEngineTreeValidatorBuilder {
    /// Creates a builder that fills `executed_state` when reth launches the
    /// engine.
    pub fn new(executed_state: ExecutedState) -> Self {
        Self {
            inner: BasicEngineValidatorBuilder::default(),
            executed_state,
        }
    }
}

impl<Node> EngineValidatorBuilder<Node> for TempoEngineTreeValidatorBuilder
where
    Node: FullNodeComponents<Types = TempoNode>,
    BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>: EngineValidatorBuilder<Node>,
{
    type EngineValidator =
        <BasicEngineValidatorBuilder<TempoEngineValidatorBuilder> as EngineValidatorBuilder<
            Node,
        >>::EngineValidator;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        overlay_manager: OverlayManager<PrimitivesTy<Node::Types>>,
    ) -> eyre::Result<Self::EngineValidator> {
        self.executed_state.set(overlay_manager.clone());
        self.inner
            .build_tree_validator(ctx, tree_config, overlay_manager)
            .await
    }
}
