use crate::args::TempoArgs;
use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use alloy_rpc_types_engine::{ExecutionData, PayloadAttributes};
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_ethereum_primitives::EthPrimitives;
use reth_evm::{
    ConfigureEvm, EvmFactory, EvmFactoryFor, NextBlockEnvAttributes,
    eth::spec::EthExecutorSpec,
    revm::{context::TxEnv, primitives::Address},
};
use reth_malachite::MalachiteConsensusBuilder;
use reth_node_api::{
    AddOnsContext, EngineTypes, FullNodeComponents, FullNodeTypes, NodeAddOns, NodeTypes,
    PayloadAttributesBuilder, PayloadTypes, TxTy,
};
use reth_node_builder::{
    BuilderContext, DebugNode, Node, NodeAdapter, PayloadBuilderConfig,
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ExecutorBuilder, PoolBuilder, TxPoolBuilder,
    },
    rpc::{
        BasicEngineApiBuilder, BasicEngineValidatorBuilder, EngineApiBuilder, EngineValidatorAddOn,
        EngineValidatorBuilder, EthApiBuilder, PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns,
    },
};
use reth_node_ethereum::{
    EthEngineTypes, EthEvmConfig, EthereumEngineValidator, EthereumEngineValidatorBuilder,
    EthereumEthApiBuilder, EthereumNetworkBuilder, EthereumPayloadBuilder,
};
use reth_provider::{EthStorage, providers::ProviderFactoryBuilder};
use reth_rpc_builder::Identity;
use reth_rpc_eth_api::FromEvmError;
use reth_rpc_eth_types::EthApiError;
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{
    EthPoolTransaction, EthTransactionPool, PoolTransaction, TransactionValidationTaskExecutor,
    blobstore::DiskFileBlobStore,
};
use std::{default::Default, sync::Arc, time::SystemTime};
use tempo_chainspec::spec::TempoChainSpec;
use tempo_evm::evm::TempoEvmFactory;
use tempo_transaction_pool::transaction::TempoPooledTransaction;

pub const TEMPO_BASE_FEE: u64 = 0;

/// Type configuration for a regular Ethereum node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoNode {
    pub args: TempoArgs,
}

impl TempoNode {
    /// Create new instance of a Tempo node
    pub fn new(args: TempoArgs) -> Self {
        Self { args }
    }

    /// Returns a [`ComponentsBuilder`] configured for a regular Tempo node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        TempoPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        TempoExecutorBuilder,
        MalachiteConsensusBuilder,
    >
    where
        Node: FullNodeTypes<
            Types: NodeTypes<
                ChainSpec: Hardforks + EthereumHardforks + EthExecutorSpec,
                Primitives = EthPrimitives,
            >,
        >,
        <Node::Types as NodeTypes>::Payload: PayloadTypes<
                BuiltPayload = EthBuiltPayload,
                PayloadAttributes = PayloadAttributes,
                PayloadBuilderAttributes = EthPayloadBuilderAttributes,
            >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(TempoPoolBuilder::default())
            .executor(TempoExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(MalachiteConsensusBuilder)
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }
}

impl NodeTypes for TempoNode {
    type Primitives = EthPrimitives;
    type ChainSpec = TempoChainSpec;
    type Storage = EthStorage;
    type Payload = EthEngineTypes;
}

#[derive(Debug)]
pub struct TempoAddOns<
    N: FullNodeComponents,
    EthB: EthApiBuilder<N>,
    PVB,
    EB = BasicEngineApiBuilder<PVB>,
    EVB = BasicEngineValidatorBuilder<PVB>,
    RpcMiddleware = Identity,
> {
    inner: RpcAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>,
}

impl<N, EthB, PVB, EB, EVB, RpcMiddleware> TempoAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>
where
    N: FullNodeComponents,
    EthB: EthApiBuilder<N>,
{
    /// Creates a new instance from the inner `RpcAddOns`.
    pub const fn new(inner: RpcAddOns<N, EthB, PVB, EB, EVB, RpcMiddleware>) -> Self {
        Self { inner }
    }
}

impl<N> Default for TempoAddOns<N, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>
where
    N: FullNodeComponents<
        Types: NodeTypes<
            ChainSpec: EthereumHardforks + Clone + 'static,
            Payload: EngineTypes<ExecutionData = ExecutionData>
                         + PayloadTypes<PayloadAttributes = PayloadAttributes>,
            Primitives = EthPrimitives,
        >,
    >,
    EthereumEthApiBuilder: EthApiBuilder<N>,
{
    fn default() -> Self {
        Self::new(RpcAddOns::new(
            EthereumEthApiBuilder::default(),
            EthereumEngineValidatorBuilder::default(),
            BasicEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
        ))
    }
}

impl<N, EthB, PVB, EB, EVB> NodeAddOns<N> for TempoAddOns<N, EthB, PVB, EB, EVB>
where
    N: FullNodeComponents<
            Types: NodeTypes<
                ChainSpec: EthChainSpec + EthereumHardforks,
                Primitives = EthPrimitives,
                Payload: EngineTypes<ExecutionData = ExecutionData>,
            >,
            Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
        >,
    EthB: EthApiBuilder<N>,
    PVB: Send + PayloadValidatorBuilder<N>,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type Handle = <RpcAddOns<N, EthB, PVB, EB, EVB> as NodeAddOns<N>>::Handle;

    async fn launch_add_ons(
        self,
        ctx: reth_node_api::AddOnsContext<'_, N>,
    ) -> eyre::Result<Self::Handle> {
        self.inner.launch_add_ons(ctx).await
    }
}

impl<N, EthB, PVB, EB, EVB> RethRpcAddOns<N> for TempoAddOns<N, EthB, PVB, EB, EVB>
where
    N: FullNodeComponents<
            Types: NodeTypes<
                ChainSpec: EthChainSpec + EthereumHardforks,
                Primitives = EthPrimitives,
                Payload: EngineTypes<ExecutionData = ExecutionData>,
            >,
            Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
        >,
    EthB: EthApiBuilder<N>,
    PVB: PayloadValidatorBuilder<N>,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type EthApi = EthB::EthApi;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N, EthB, PVB, EB, EVB> EngineValidatorAddOn<N> for TempoAddOns<N, EthB, PVB, EB, EVB>
where
    N: FullNodeComponents<
            Types: NodeTypes<
                ChainSpec: EthChainSpec + EthereumHardforks,
                Primitives = EthPrimitives,
                Payload: EngineTypes<ExecutionData = ExecutionData>,
            >,
            Evm: ConfigureEvm<NextBlockEnvCtx = NextBlockEnvAttributes>,
        >,
    EthB: EthApiBuilder<N>,
    PVB: Send,
    EB: EngineApiBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    EthApiError: FromEvmError<N::Evm>,
    EvmFactoryFor<N::Evm>: EvmFactory<Tx = TxEnv>,
{
    type ValidatorBuilder = EVB;

    fn engine_validator_builder(&self) -> Self::ValidatorBuilder {
        self.inner.engine_validator_builder()
    }
}

impl<N> Node<N> for TempoNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        TempoPoolBuilder,
        BasicPayloadServiceBuilder<EthereumPayloadBuilder>,
        EthereumNetworkBuilder,
        TempoExecutorBuilder,
        MalachiteConsensusBuilder,
    >;

    type AddOns =
        TempoAddOns<NodeAdapter<N>, EthereumEthApiBuilder, EthereumEngineValidatorBuilder>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }

    fn add_ons(&self) -> Self::AddOns {
        TempoAddOns::default()
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for TempoNode {
    type RpcBlock = alloy_rpc_types_eth::Block;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> reth_ethereum_primitives::Block {
        rpc_block.into_consensus().convert_transactions()
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes> {
        TempoPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// The attributes builder with a restricted set of validators
#[derive(Debug)]
#[non_exhaustive]
pub struct TempoPayloadAttributesBuilder<ChainSpec> {
    /// The vanilla eth payload attributes builder
    inner: LocalPayloadAttributesBuilder<ChainSpec>,
}

impl<ChainSpec> TempoPayloadAttributesBuilder<ChainSpec> {
    /// Creates a new instance of the builder.
    pub const fn new(chain_spec: Arc<ChainSpec>) -> Self {
        Self {
            inner: LocalPayloadAttributesBuilder::new(chain_spec),
        }
    }
}

impl<ChainSpec> PayloadAttributesBuilder<EthPayloadAttributes>
    for TempoPayloadAttributesBuilder<ChainSpec>
where
    ChainSpec: Send + Sync + EthereumHardforks + 'static,
{
    fn build(&self, timestamp: u64) -> EthPayloadAttributes {
        let mut attributes = self.inner.build(timestamp);
        attributes.suggested_fee_recipient = Address::ZERO;
        attributes
    }
}

/// A regular ethereum evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoExecutorBuilder;

impl<Types, Node> ExecutorBuilder<Node> for TempoExecutorBuilder
where
    Types: NodeTypes<
            ChainSpec: Hardforks + EthExecutorSpec + EthereumHardforks,
            Primitives = EthPrimitives,
        >,
    Node: FullNodeTypes<Types = Types>,
{
    type EVM = EthEvmConfig<Types::ChainSpec, TempoEvmFactory>;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let evm_config =
            EthEvmConfig::new_with_evm_factory(ctx.chain_spec(), TempoEvmFactory::default())
                .with_extra_data(ctx.payload_builder_config().extra_data_bytes());
        Ok(evm_config)
    }
}

/// Builder for [`EthereumEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoEngineValidatorBuilder;

impl<Node, Types> PayloadValidatorBuilder<Node> for TempoEngineValidatorBuilder
where
    Types: NodeTypes<
            ChainSpec: Hardforks + EthereumHardforks + Clone + 'static,
            Payload: EngineTypes<ExecutionData = ExecutionData>
                         + PayloadTypes<PayloadAttributes = PayloadAttributes>,
            Primitives = EthPrimitives,
        >,
    Node: FullNodeComponents<Types = Types>,
{
    type Validator = EthereumEngineValidator<Types::ChainSpec>;

    async fn build(self, ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(EthereumEngineValidator::new(ctx.config.chain.clone()))
    }
}

/// A basic optimism transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Clone)]
pub struct TempoPoolBuilder<T = TempoPooledTransaction> {
    /// Marker for the pooled transaction type.
    _pd: core::marker::PhantomData<T>,
}

impl<T> Default for TempoPoolBuilder<T> {
    fn default() -> Self {
        Self {
            _pd: Default::default(),
        }
    }
}

impl<Node, T> PoolBuilder<Node> for TempoPoolBuilder<T>
where
    Node: FullNodeTypes<Types: NodeTypes<ChainSpec: EthereumHardforks>>,
    T: EthPoolTransaction<Consensus = TxTy<Node::Types>> + PoolTransaction,
{
    type Pool = EthTransactionPool<Node::Provider, DiskFileBlobStore, T>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let mut pool_config = ctx.pool_config().clone();
        pool_config.minimal_protocol_basefee = TEMPO_BASE_FEE;

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            Some(blob_cache_size)
        } else {
            // get the current blob params for the current timestamp, fallback to default Cancun
            // params
            let current_timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            // Derive the blob cache size from the target blob count, to auto scale it by
            // multiplying it with the slot count for 2 epochs: 384 for pectra
            Some((blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32)
        };

        let blob_store =
            reth_node_builder::components::create_blob_store_with_cache(ctx, blob_cache_size)?;

        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(ctx.head().timestamp)
            .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
            .kzg_settings(ctx.kzg_settings()?)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
            .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        if validator.validator().eip4844() {
            // initializing the KZG settings can be expensive, this should be done upfront so that
            // it doesn't impact the first block or the first gossiped blob transaction, so we
            // initialize this in the background
            let kzg_settings = validator.validator().kzg_settings().clone();
            ctx.task_executor().spawn_blocking(async move {
                let _ = kzg_settings.get();
                debug!(target: "reth::cli", "Initialized KZG settings");
            });
        }

        // TODO: custom tempo tx validation
        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}
