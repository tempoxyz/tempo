use crate::{
    TempoPayloadTypes,
    engine::TempoEngineValidator,
    rpc::{
        TempoAdminApi, TempoAdminApiServer, TempoAmm, TempoAmmApiServer, TempoDex,
        TempoDexApiServer, TempoEthApiBuilder, TempoEthExt, TempoEthExtApiServer, TempoPolicy,
        TempoPolicyApiServer, TempoToken, TempoTokenApiServer,
    },
};
use alloy_primitives::B256;
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_evm::revm::primitives::Address;
use reth_node_api::{
    AddOnsContext, FullNodeComponents, FullNodeTypes, NodeAddOns, NodePrimitives, NodeTypes,
    PayloadAttributesBuilder, PayloadTypes,
};
use reth_node_builder::{
    BuilderContext, DebugNode, Node, NodeAdapter,
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        PayloadBuilderBuilder, PoolBuilder, TxPoolBuilder, spawn_maintenance_tasks,
    },
    rpc::{
        BasicEngineValidatorBuilder, EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder,
        NoopEngineApiBuilder, PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns,
    },
};
use reth_node_ethereum::EthereumNetworkBuilder;
use reth_primitives_traits::SealedHeader;
use reth_provider::{EthStorage, providers::ProviderFactoryBuilder};
use reth_rpc_builder::{Identity, RethRpcModule};
use reth_rpc_eth_api::{
    RpcNodeCore,
    helpers::config::{EthConfigApiServer, EthConfigHandler},
};
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::{TransactionValidationTaskExecutor, blobstore::InMemoryBlobStore};
use std::{default::Default, sync::Arc};
use tempo_chainspec::spec::{TEMPO_BASE_FEE, TempoChainSpec};
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, evm::TempoEvmFactory};
use tempo_payload_builder::TempoPayloadBuilder;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType};
use tempo_transaction_pool::{
    AA2dPool, AA2dPoolConfig, TempoTransactionPool, amm::AmmLiquidityCache,
    validator::TempoTransactionValidator,
};

/// Default maximum allowed `valid_after` offset for AA txs (1 hour).
pub const DEFAULT_AA_VALID_AFTER_MAX_SECS: u64 = 3600;

/// Tempo node CLI arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::Args)]
pub struct TempoNodeArgs {
    /// Maximum allowed `valid_after` offset for AA txs.
    #[arg(long = "txpool.aa-valid-after-max-secs", default_value_t = DEFAULT_AA_VALID_AFTER_MAX_SECS)]
    pub aa_valid_after_max_secs: u64,

    /// Enable state provider metrics for the payload builder.
    #[arg(long = "builder.state-provider-metrics", default_value_t = false)]
    pub builder_state_provider_metrics: bool,

    /// Disable state cache for the payload builder.
    #[arg(long = "builder.disable-state-cache", default_value_t = false)]
    pub builder_disable_state_cache: bool,
}

impl TempoNodeArgs {
    /// Returns a [`TempoPoolBuilder`] configured from these args.
    pub fn pool_builder(&self) -> TempoPoolBuilder {
        TempoPoolBuilder {
            aa_valid_after_max_secs: self.aa_valid_after_max_secs,
        }
    }

    /// Returns a [`TempoPayloadBuilderBuilder`] configured from these args.
    pub fn payload_builder_builder(&self) -> TempoPayloadBuilderBuilder {
        TempoPayloadBuilderBuilder {
            state_provider_metrics: self.builder_state_provider_metrics,
            disable_state_cache: self.builder_disable_state_cache,
        }
    }
}

/// Type configuration for a regular Ethereum node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoNode {
    /// Transaction pool builder.
    pool_builder: TempoPoolBuilder,
    /// Payload builder builder.
    payload_builder_builder: TempoPayloadBuilderBuilder,
    /// Validator public key for `admin_validatorKey` RPC method.
    validator_key: Option<B256>,
}

impl TempoNode {
    /// Create new instance of a Tempo node
    pub fn new(args: &TempoNodeArgs, validator_key: Option<B256>) -> Self {
        Self {
            pool_builder: args.pool_builder(),
            payload_builder_builder: args.payload_builder_builder(),
            validator_key,
        }
    }

    /// Returns a [`ComponentsBuilder`] configured for a regular Tempo node.
    pub fn components<Node>(
        pool_builder: TempoPoolBuilder,
        payload_builder_builder: TempoPayloadBuilderBuilder,
    ) -> ComponentsBuilder<
        Node,
        TempoPoolBuilder,
        BasicPayloadServiceBuilder<TempoPayloadBuilderBuilder>,
        EthereumNetworkBuilder,
        TempoExecutorBuilder,
        TempoConsensusBuilder,
    >
    where
        Node: FullNodeTypes<Types = Self>,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(pool_builder)
            .executor(TempoExecutorBuilder::default())
            .payload(BasicPayloadServiceBuilder::new(payload_builder_builder))
            .network(EthereumNetworkBuilder::default())
            .consensus(TempoConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }

    /// Sets the validator key for filtering subblock transactions.
    pub fn with_validator_key(mut self, validator_key: Option<B256>) -> Self {
        self.validator_key = validator_key;
        self
    }
}

impl NodeTypes for TempoNode {
    type Primitives = TempoPrimitives;
    type ChainSpec = TempoChainSpec;
    type Storage = EthStorage<TempoTxEnvelope, TempoHeader>;
    type Payload = TempoPayloadTypes;
}

#[derive(Debug)]
pub struct TempoAddOns<
    N: FullNodeComponents,
    EthB: EthApiBuilder<N> = TempoEthApiBuilder,
    PVB = TempoEngineValidatorBuilder,
    EVB = BasicEngineValidatorBuilder<PVB>,
    RpcMiddleware = Identity,
> {
    inner: RpcAddOns<N, EthB, PVB, NoopEngineApiBuilder, EVB, RpcMiddleware>,
    validator_key: Option<B256>,
}

impl<N> TempoAddOns<NodeAdapter<N>, TempoEthApiBuilder>
where
    N: FullNodeTypes<Types = TempoNode>,
{
    /// Creates a new instance from the inner `RpcAddOns`.
    pub fn new(validator_key: Option<B256>) -> Self {
        Self {
            inner: RpcAddOns::new(
                TempoEthApiBuilder::new(validator_key),
                TempoEngineValidatorBuilder,
                NoopEngineApiBuilder::default(),
                BasicEngineValidatorBuilder::default(),
                Identity::default(),
            ),
            validator_key,
        }
    }
}

impl<N, EthB, PVB, EVB> NodeAddOns<N> for TempoAddOns<N, EthB, PVB, EVB>
where
    N: FullNodeComponents<Types = TempoNode, Evm = TempoEvmConfig>,
    EthB: EthApiBuilder<N>,
    PVB: Send + PayloadValidatorBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    EthB::EthApi:
        RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>,
{
    type Handle = <RpcAddOns<N, EthB, PVB, NoopEngineApiBuilder, EVB> as NodeAddOns<N>>::Handle;

    async fn launch_add_ons(self, ctx: AddOnsContext<'_, N>) -> eyre::Result<Self::Handle> {
        let eth_config =
            EthConfigHandler::new(ctx.node.provider().clone(), ctx.node.evm_config().clone());

        self.inner
            .launch_add_ons_with(ctx, move |container| {
                let reth_node_builder::rpc::RpcModuleContainer {
                    modules, registry, ..
                } = container;

                let eth_api = registry.eth_api().clone();
                let dex = TempoDex::new(eth_api.clone());
                let amm = TempoAmm::new(eth_api.clone());
                let token = TempoToken::new(eth_api.clone());
                let policy = TempoPolicy::new(eth_api.clone());
                let eth_ext = TempoEthExt::new(eth_api);
                let admin = TempoAdminApi::new(self.validator_key);

                modules.merge_configured(dex.into_rpc())?;
                modules.merge_configured(amm.into_rpc())?;
                modules.merge_configured(token.into_rpc())?;
                modules.merge_configured(policy.into_rpc())?;
                modules.merge_configured(eth_ext.into_rpc())?;
                modules.merge_if_module_configured(RethRpcModule::Admin, admin.into_rpc())?;
                modules.merge_if_module_configured(RethRpcModule::Eth, eth_config.into_rpc())?;

                Ok(())
            })
            .await
    }
}

impl<N, EthB, PVB, EVB> RethRpcAddOns<N> for TempoAddOns<N, EthB, PVB, EVB>
where
    N: FullNodeComponents<Types = TempoNode, Evm = TempoEvmConfig>,
    EthB: EthApiBuilder<N>,
    PVB: PayloadValidatorBuilder<N>,
    EVB: EngineValidatorBuilder<N>,
    EthB::EthApi:
        RpcNodeCore<Evm = TempoEvmConfig, Primitives: NodePrimitives<BlockHeader = TempoHeader>>,
{
    type EthApi = EthB::EthApi;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N, EthB, PVB, EVB> EngineValidatorAddOn<N> for TempoAddOns<N, EthB, PVB, EVB>
where
    N: FullNodeComponents<Types = TempoNode, Evm = TempoEvmConfig>,
    EthB: EthApiBuilder<N>,
    PVB: Send,
    EVB: EngineValidatorBuilder<N>,
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
        BasicPayloadServiceBuilder<TempoPayloadBuilderBuilder>,
        EthereumNetworkBuilder,
        TempoExecutorBuilder,
        TempoConsensusBuilder,
    >;

    type AddOns = TempoAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self.pool_builder, self.payload_builder_builder)
    }

    fn add_ons(&self) -> Self::AddOns {
        TempoAddOns::new(self.validator_key)
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for TempoNode {
    type RpcBlock =
        alloy_rpc_types_eth::Block<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeader>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> tempo_primitives::Block {
        rpc_block
            .into_consensus_block()
            .map_transactions(|tx| tx.into_inner())
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes, TempoHeader>
    {
        TempoPayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// The attributes builder with a restricted set of validators
#[derive(Debug)]
#[non_exhaustive]
pub struct TempoPayloadAttributesBuilder {
    /// The vanilla eth payload attributes builder
    inner: LocalPayloadAttributesBuilder<TempoChainSpec>,
}

impl TempoPayloadAttributesBuilder {
    /// Creates a new instance of the builder.
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            inner: LocalPayloadAttributesBuilder::new(chain_spec).without_increasing_timestamp(),
        }
    }
}

impl PayloadAttributesBuilder<TempoPayloadAttributes, TempoHeader>
    for TempoPayloadAttributesBuilder
{
    fn build(&self, parent: &SealedHeader<TempoHeader>) -> TempoPayloadAttributes {
        let mut inner = self.inner.build(parent);
        inner.suggested_fee_recipient = Address::ZERO;

        let timestamp_millis_part = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            % 1000;

        TempoPayloadAttributes {
            inner,
            timestamp_millis_part,
        }
    }
}

/// A regular ethereum evm and executor builder.
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoExecutorBuilder;

impl<Node> ExecutorBuilder<Node> for TempoExecutorBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type EVM = TempoEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let evm_config = TempoEvmConfig::new(ctx.chain_spec(), TempoEvmFactory::default());
        Ok(evm_config)
    }
}

/// Builder for [`TempoConsensus`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoConsensusBuilder;

impl<Node> ConsensusBuilder<Node> for TempoConsensusBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type Consensus = TempoConsensus;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(TempoConsensus::new(ctx.chain_spec()))
    }
}

/// Builder for [`TempoEngineValidator`].
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoEngineValidatorBuilder;

impl<Node> PayloadValidatorBuilder<Node> for TempoEngineValidatorBuilder
where
    Node: FullNodeComponents<Types = TempoNode>,
{
    type Validator = TempoEngineValidator;

    async fn build(self, _ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(TempoEngineValidator::new())
    }
}

/// A basic Tempo transaction pool.
///
/// This contains various settings that can be configured and take precedence over the node's
/// config.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TempoPoolBuilder {
    /// Maximum allowed `valid_after` offset for AA txs.
    pub aa_valid_after_max_secs: u64,
}

impl TempoPoolBuilder {
    /// Sets the maximum allowed `valid_after` offset for AA txs.
    pub const fn with_aa_tx_valid_after_max_secs(mut self, secs: u64) -> Self {
        self.aa_valid_after_max_secs = secs;
        self
    }
}

impl Default for TempoPoolBuilder {
    fn default() -> Self {
        Self {
            aa_valid_after_max_secs: DEFAULT_AA_VALID_AFTER_MAX_SECS,
        }
    }
}

impl<Node> PoolBuilder<Node> for TempoPoolBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type Pool = TempoTransactionPool<Node::Provider>;

    async fn build_pool(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Pool> {
        let mut pool_config = ctx.pool_config();
        pool_config.minimal_protocol_basefee = TEMPO_BASE_FEE;
        pool_config.max_inflight_delegated_slot_limit = pool_config.max_account_slots;

        // this store is effectively a noop
        let blob_store = InMemoryBlobStore::default();
        let validator = TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone())
            .with_head_timestamp(ctx.head().timestamp)
            .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
            .with_local_transactions_config(pool_config.local_transactions_config.clone())
            .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
            .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
            .disable_balance_check()
            .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .with_custom_tx_type(TempoTxType::AA as u8)
            .no_eip4844()
            .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let aa_2d_config = AA2dPoolConfig {
            price_bump_config: pool_config.price_bumps,
            // TODO: configure dedicated limit
            aa_2d_limit: pool_config.pending_limit,
        };
        let aa_2d_pool = AA2dPool::new(aa_2d_config);
        let amm_liquidity_cache = AmmLiquidityCache::new(ctx.provider())?;

        let validator = validator.map(|v| {
            TempoTransactionValidator::new(
                v,
                self.aa_valid_after_max_secs,
                amm_liquidity_cache.clone(),
            )
        });
        let protocol_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build(blob_store, pool_config.clone());

        // Wrap the protocol pool in our hybrid TempoTransactionPool
        let transaction_pool = TempoTransactionPool::new(protocol_pool, aa_2d_pool);

        spawn_maintenance_tasks(ctx, transaction_pool.clone(), &pool_config)?;

        // Spawn (protocol) mempool maintenance tasks
        let task_pool = transaction_pool.clone();
        let task_provider = ctx.provider().clone();
        ctx.task_executor().spawn_critical(
            "txpool maintenance (protocol) - evict expired AA txs",
            tempo_transaction_pool::maintain::evict_expired_aa_txs(task_pool, task_provider),
        );

        // Spawn (AA 2d nonce) mempool maintenance tasks
        ctx.task_executor().spawn_critical(
            "txpool maintenance - 2d nonce AA txs",
            tempo_transaction_pool::maintain::maintain_2d_nonce_pool(transaction_pool.clone()),
        );

        // Spawn AMM liquidity cache maintenance task
        ctx.task_executor().spawn_critical(
            "txpool maintenance - amm liquidity cache",
            tempo_transaction_pool::maintain::maintain_amm_cache(transaction_pool.clone()),
        );

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}

#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct TempoPayloadBuilderBuilder {
    /// Enable state provider metrics for the payload builder.
    pub state_provider_metrics: bool,
    /// Disable state cache for the payload builder.
    pub disable_state_cache: bool,
}

impl<Node> PayloadBuilderBuilder<Node, TempoTransactionPool<Node::Provider>, TempoEvmConfig>
    for TempoPayloadBuilderBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type PayloadBuilder = TempoPayloadBuilder<Node::Provider>;

    async fn build_payload_builder(
        self,
        ctx: &BuilderContext<Node>,
        pool: TempoTransactionPool<Node::Provider>,
        evm_config: TempoEvmConfig,
    ) -> eyre::Result<Self::PayloadBuilder> {
        Ok(TempoPayloadBuilder::new(
            pool,
            ctx.provider().clone(),
            evm_config,
            self.state_provider_metrics,
            self.disable_state_cache,
        ))
    }
}
