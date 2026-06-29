use crate::{TempoExecutionData, TempoPayloadTypes};
use reth_chain_state::ExecutedBlock;
use reth_engine_tree::tree::{
    CacheWaitDurations, EngineApiTreeState, EngineValidator, SavedCache, TreeConfig,
    ValidationOutcome, ValidationOutput, WaitForCaches,
    error::{InsertBlockError, InsertBlockErrorKind},
    payload_processor::multiproof::StateRootHandle,
    payload_validator::TreeCtx,
};
use reth_errors::ProviderResult;
use reth_node_api::{
    FullNodeComponents, InvalidPayloadAttributesError, NewPayloadError, PayloadValidator,
};
use reth_node_builder::{
    AddOnsContext,
    rpc::{BasicEngineValidatorBuilder, EngineValidatorBuilder},
};
use reth_payload_primitives::BuiltPayloadExecutedBlock;
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock};
use reth_trie_db::ChangesetCache;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block, TempoHeader, TempoPrimitives};

use crate::node::{TempoEngineValidatorBuilder, TempoNode};

/// Type encapsulating Tempo engine validation logic.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoEngineValidator;

impl TempoEngineValidator {
    /// Creates a new [`TempoEngineValidator`] with the given chain spec.
    pub fn new() -> Self {
        Self {}
    }
}

impl PayloadValidator<TempoPayloadTypes> for TempoEngineValidator {
    type Block = Block;

    fn convert_payload_to_block(
        &self,
        payload: TempoExecutionData,
    ) -> Result<SealedBlock<Self::Block>, NewPayloadError> {
        let TempoExecutionData {
            block,
            block_access_list: _,
            validator_set: _,
            executed_block: _,
        } = payload;
        Ok(block.into_sealed_block())
    }

    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        // Ensure that payload attributes timestamp is not in the past
        if attr.timestamp < header.timestamp() {
            return Err(InvalidPayloadAttributesError::InvalidTimestamp);
        }
        Ok(())
    }
}

/// Builds the Tempo engine validator with an SSMR-aware fast path.
#[derive(Debug, Default, Clone)]
pub struct SsmrEngineValidatorBuilder {
    inner: BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>,
}

impl SsmrEngineValidatorBuilder {
    /// Creates a new SSMR-aware validator builder.
    pub const fn new() -> Self {
        Self {
            inner: BasicEngineValidatorBuilder::new(TempoEngineValidatorBuilder),
        }
    }
}

impl<Node> EngineValidatorBuilder<Node> for SsmrEngineValidatorBuilder
where
    Node: FullNodeComponents<Types = TempoNode>,
    BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>: EngineValidatorBuilder<Node>,
    <BasicEngineValidatorBuilder<TempoEngineValidatorBuilder> as EngineValidatorBuilder<
        Node,
    >>::EngineValidator: EngineValidator<TempoPayloadTypes, TempoPrimitives> + WaitForCaches,
{
    type EngineValidator = SsmrEngineValidator<
        <BasicEngineValidatorBuilder<TempoEngineValidatorBuilder> as EngineValidatorBuilder<
            Node,
        >>::EngineValidator,
    >;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: TreeConfig,
        changeset_cache: ChangesetCache,
    ) -> eyre::Result<Self::EngineValidator> {
        let inner = self
            .inner
            .build_tree_validator(ctx, tree_config, changeset_cache)
            .await?;
        Ok(SsmrEngineValidator { inner })
    }
}

/// Tempo wrapper around Reth's tree validator that can consume an already
/// executed payload artifact carried through `TempoExecutionData`.
#[derive(Debug)]
pub struct SsmrEngineValidator<V> {
    inner: V,
}

impl<V> EngineValidator<TempoPayloadTypes, TempoPrimitives> for SsmrEngineValidator<V>
where
    V: EngineValidator<TempoPayloadTypes, TempoPrimitives>,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &TempoPayloadAttributes,
        header: &TempoHeader,
    ) -> Result<(), InvalidPayloadAttributesError> {
        self.inner
            .validate_payload_attributes_against_header(attr, header)
    }

    fn convert_payload_to_block(
        &self,
        payload: TempoExecutionData,
    ) -> Result<SealedBlock<Block>, NewPayloadError> {
        self.inner.convert_payload_to_block(payload)
    }

    fn validate_payload(
        &mut self,
        mut payload: TempoExecutionData,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        if let Some(executed_block) = payload.executed_block.take()
            && executed_block.recovered_block.sealed_block() == payload.block.sealed_block()
        {
            let error_block = payload.block.clone().into_sealed_block();
            return self
                .inner
                .on_inserted_executed_block(executed_block)
                .map(|executed_block| ValidationOutput::new(executed_block, None))
                .map_err(|error| {
                    InsertBlockError::new(error_block, InsertBlockErrorKind::Provider(error)).into()
                });
        }

        self.inner.validate_payload(payload, ctx)
    }

    fn validate_block(
        &mut self,
        block: SealedBlock<Block>,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        self.inner.validate_block(block, ctx)
    }

    fn on_inserted_executed_block(
        &self,
        block: BuiltPayloadExecutedBlock<TempoPrimitives>,
    ) -> ProviderResult<ExecutedBlock<TempoPrimitives>> {
        self.inner.on_inserted_executed_block(block)
    }

    fn cache_for(&self, block_hash: alloy_primitives::B256) -> Option<SavedCache> {
        self.inner.cache_for(block_hash)
    }

    fn sparse_trie_handle_for(
        &self,
        parent_hash: alloy_primitives::B256,
        parent_state_root: alloy_primitives::B256,
        state: &EngineApiTreeState<TempoPrimitives>,
    ) -> Option<StateRootHandle> {
        self.inner
            .sparse_trie_handle_for(parent_hash, parent_state_root, state)
    }
}

impl<V> WaitForCaches for SsmrEngineValidator<V>
where
    V: WaitForCaches,
{
    fn wait_for_caches(&self) -> CacheWaitDurations {
        self.inner.wait_for_caches()
    }
}
