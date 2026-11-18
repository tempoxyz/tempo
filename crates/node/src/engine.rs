use crate::{TempoExecutionData, TempoPayloadTypes};
use alloy_primitives::B256;
use reth_chain_state::ExecutedBlock;
use reth_engine_tree::tree::{
    CacheWaitDurations, EngineApiTreeState, ValidationOutcome, WaitForCaches,
    error::{InsertBlockError, InsertBlockErrorKind},
    payload_validator::TreeCtx,
};
use reth_errors::ProviderResult;
use reth_ethereum::consensus::HeaderValidator;
use reth_network_p2p::full_block::SealedBlockWithAccessList;
use reth_node_api::{
    AddOnsContext, BuiltPayload, BuiltPayloadExecutedBlock, FullNodeComponents,
    InvalidPayloadAttributesError, NewPayloadError, NodeTypes, PayloadTypes, PayloadValidator,
    PrimitivesTy, TreeConfig,
};
use reth_node_builder::rpc::{EngineValidator, EngineValidatorBuilder};
use reth_payload_builder::PayloadBuilderResources;
use reth_primitives_traits::{AlloyBlockHeader as _, SealedBlock, SealedHeader};
use reth_storage_api::HeaderProvider;
use reth_storage_overlay::OverlayManager;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{Block, TempoHeader, TempoPrimitives};

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
        let TempoExecutionData { block } = payload;
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

/// Engine validator that validates the header of a block before the inner validator executes
/// the block.
///
/// The hardfork and the gas limits of an execution come from the header. reth validates the
/// header on a background thread while it executes the block.
#[derive(Debug)]
pub struct EagerHeaderValidator<V, P, C> {
    /// Executes the blocks whose header is valid.
    inner: V,
    /// Reads the parent headers that the engine does not keep in memory.
    provider: P,
    /// The consensus rules that a header must satisfy.
    consensus: C,
}

impl<V, P, C> EagerHeaderValidator<V, P, C>
where
    P: HeaderProvider<Header = TempoHeader>,
    C: HeaderValidator<TempoHeader>,
{
    /// Validates `header` on its own and against its parent.
    ///
    /// Skips the validation against the parent if the parent is unknown: the inner validator
    /// reports that without executing the block.
    fn validate_header(
        &self,
        header: &SealedHeader<TempoHeader>,
        state: &EngineApiTreeState<TempoPrimitives>,
    ) -> Result<(), InsertBlockErrorKind> {
        self.consensus.validate_header(header)?;

        let parent_hash = header.parent_hash();
        let parent = match state.tree_state().sealed_header_by_hash(&parent_hash) {
            Some(parent) => parent,
            None => match self.provider.sealed_header_by_hash(parent_hash)? {
                Some(parent) => parent,
                None => return Ok(()),
            },
        };

        self.consensus
            .validate_header_against_parent(header, &parent)?;
        Ok(())
    }
}

impl<T, V, P, C> EngineValidator<T> for EagerHeaderValidator<V, P, C>
where
    T: PayloadTypes<
            ExecutionData = TempoExecutionData,
            BuiltPayload: BuiltPayload<Primitives = TempoPrimitives>,
        >,
    V: EngineValidator<T>,
    P: HeaderProvider<Header = TempoHeader> + Send + Sync + 'static,
    C: HeaderValidator<TempoHeader> + Send + Sync + 'static,
{
    fn validate_payload_attributes_against_header(
        &self,
        attr: &T::PayloadAttributes,
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
        payload: TempoExecutionData,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        let header = payload.block.sealed_block().sealed_header();
        if let Err(kind) = self.validate_header(header, ctx.state()) {
            let block = self.inner.convert_payload_to_block(payload)?;
            return Err(InsertBlockError::new(block, kind).into());
        }
        self.inner.validate_payload(payload, ctx)
    }

    fn validate_block(
        &mut self,
        block: SealedBlockWithAccessList<Block>,
        ctx: TreeCtx<'_, TempoPrimitives>,
    ) -> ValidationOutcome<TempoPrimitives> {
        if let Err(kind) = self.validate_header(block.block().sealed_header(), ctx.state()) {
            return Err(InsertBlockError::new(block.split().0, kind).into());
        }
        self.inner.validate_block(block, ctx)
    }

    fn on_inserted_executed_block(
        &self,
        block: BuiltPayloadExecutedBlock<TempoPrimitives>,
    ) -> ProviderResult<ExecutedBlock<TempoPrimitives>> {
        self.inner.on_inserted_executed_block(block)
    }

    fn on_canonical_head_changed(&self, hash: B256, state: &EngineApiTreeState<TempoPrimitives>) {
        self.inner.on_canonical_head_changed(hash, state)
    }

    fn payload_builder_resources(
        &self,
        parent_hash: B256,
        parent_header: &TempoHeader,
        timestamp: u64,
        state: &mut EngineApiTreeState<TempoPrimitives>,
    ) -> PayloadBuilderResources {
        self.inner
            .payload_builder_resources(parent_hash, parent_header, timestamp, state)
    }
}

impl<V, P, C> WaitForCaches for EagerHeaderValidator<V, P, C>
where
    V: WaitForCaches,
{
    fn wait_for_caches(&self) -> CacheWaitDurations {
        self.inner.wait_for_caches()
    }
}

/// Builds the engine validator of the inner builder inside an [`EagerHeaderValidator`].
#[derive(Clone, Debug, Default)]
pub struct EagerHeaderValidatorBuilder<B> {
    /// Builds the validator that executes blocks.
    inner: B,
}

impl<N, B> EngineValidatorBuilder<N> for EagerHeaderValidatorBuilder<B>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            Primitives = TempoPrimitives,
            Payload: PayloadTypes<ExecutionData = TempoExecutionData>,
        >,
    >,
    B: EngineValidatorBuilder<N>,
{
    type EngineValidator = EagerHeaderValidator<B::EngineValidator, N::Provider, N::Consensus>;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, N>,
        tree_config: TreeConfig,
        overlay_manager: OverlayManager<PrimitivesTy<N::Types>>,
    ) -> eyre::Result<Self::EngineValidator> {
        Ok(EagerHeaderValidator {
            inner: self
                .inner
                .build_tree_validator(ctx, tree_config, overlay_manager)
                .await?,
            provider: ctx.node.provider().clone(),
            consensus: ctx.node.consensus().clone(),
        })
    }
}
