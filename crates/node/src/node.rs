use crate::{
    TempoPayloadTypes,
    engine::TempoEngineValidator,
    rpc::{
        TempoAmm, TempoAmmApiServer, TempoDex, TempoDexApiServer, TempoEthApiBuilder, TempoEthExt,
        TempoEthExtApiServer, TempoPolicy, TempoPolicyApiServer, TempoToken, TempoTokenApiServer,
    },
};
use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use reth_chainspec::EthChainSpec;
use reth_engine_local::LocalPayloadAttributesBuilder;
use reth_ethereum::provider::CanonStateSubscriptions;
use reth_evm::revm::primitives::Address;
use reth_node_api::{
    AddOnsContext, FullNodeComponents, FullNodeTypes, NodeAddOns, NodePrimitives, NodeTypes,
    PayloadAttributesBuilder, PayloadTypes,
};
use reth_node_builder::{
    BuilderContext, DebugNode, Node, NodeAdapter,
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        PayloadBuilderBuilder, PoolBuilder, TxPoolBuilder,
    },
    rpc::{
        BasicEngineValidatorBuilder, EngineValidatorAddOn, EngineValidatorBuilder, EthApiBuilder,
        NoopEngineApiBuilder, PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns,
    },
};
use reth_node_ethereum::EthereumNetworkBuilder;
use reth_primitives_traits::SealedHeader;
use reth_provider::{EthStorage, providers::ProviderFactoryBuilder};
use reth_rpc_builder::Identity;
use reth_rpc_eth_api::RpcNodeCore;
use reth_tracing::tracing::{debug, info};
use reth_transaction_pool::TransactionValidationTaskExecutor;
use std::{default::Default, sync::Arc, time::SystemTime};
use tempo_chainspec::spec::{TEMPO_BASE_FEE, TempoChainSpec};
use tempo_consensus::TempoConsensus;
use tempo_evm::{TempoEvmConfig, evm::TempoEvmFactory};
use tempo_payload_builder::TempoPayloadBuilder;
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType};
use tempo_transaction_pool::{
    AA2dNonceKeys, AA2dPool, AA2dPoolConfig, TempoTransactionPool, amm::AmmLiquidityCache,
    validator::TempoTransactionValidator,
};

/// Default maximum allowed `valid_after` offset for AA txs (1 hour).
pub const DEFAULT_AA_VALID_AFTER_MAX_SECS: u64 = 3600;

/// Tempo node CLI arguments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::Args)]
#[command(next_help_heading = "TxPool")]
pub struct TempoNodeArgs {
    /// Maximum allowed `valid_after` offset for AA txs.
    #[arg(long = "txpool.aa-valid-after-max-secs", default_value_t = DEFAULT_AA_VALID_AFTER_MAX_SECS)]
    pub aa_valid_after_max_secs: u64,
}

impl TempoNodeArgs {
    /// Returns a [`TempoPoolBuilder`] configured from these args.
    pub fn pool_builder(&self) -> TempoPoolBuilder {
        TempoPoolBuilder {
            aa_valid_after_max_secs: self.aa_valid_after_max_secs,
        }
    }
}

/// Type configuration for a regular Ethereum node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoNode {
    /// Transaction pool builder.
    pool_builder: TempoPoolBuilder,
}

impl TempoNode {
    /// Create new instance of a Tempo node
    pub fn new(args: &TempoNodeArgs) -> Self {
        Self {
            pool_builder: args.pool_builder(),
        }
    }

    /// Returns a [`ComponentsBuilder`] configured for a regular Tempo node.
    pub fn components<Node>(
        pool_builder: TempoPoolBuilder,
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
            .payload(BasicPayloadServiceBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .consensus(TempoConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
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
}

impl<N, EthB, PVB, EVB, RpcMiddleware> TempoAddOns<N, EthB, PVB, EVB, RpcMiddleware>
where
    N: FullNodeComponents,
    EthB: EthApiBuilder<N>,
{
    /// Creates a new instance from the inner `RpcAddOns`.
    pub const fn new(
        inner: RpcAddOns<N, EthB, PVB, NoopEngineApiBuilder, EVB, RpcMiddleware>,
    ) -> Self {
        Self { inner }
    }
}

impl<N> Default for TempoAddOns<NodeAdapter<N>, TempoEthApiBuilder, TempoEngineValidatorBuilder>
where
    N: FullNodeTypes<Types = TempoNode>,
{
    fn default() -> Self {
        Self::new(RpcAddOns::new(
            TempoEthApiBuilder::default(),
            TempoEngineValidatorBuilder::default(),
            NoopEngineApiBuilder::default(),
            BasicEngineValidatorBuilder::default(),
            Default::default(),
        ))
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

                modules.merge_configured(dex.into_rpc())?;
                modules.merge_configured(amm.into_rpc())?;
                modules.merge_configured(token.into_rpc())?;
                modules.merge_configured(policy.into_rpc())?;
                modules.merge_configured(eth_ext.into_rpc())?;

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
        Self::components(self.pool_builder)
    }

    fn add_ons(&self) -> Self::AddOns {
        TempoAddOns::default()
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
            .disable_balance_check()
            .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
            .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
            .with_custom_tx_type(TempoTxType::AA as u8)
            .with_custom_tx_type(TempoTxType::FeeToken as u8)
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

        let aa_2d_config = AA2dPoolConfig {
            price_bump_config: pool_config.price_bumps,
            // TODO: configure dedicated limit
            aa_2d_limit: pool_config.pending_limit,
        };
        let nonce_keys = AA2dNonceKeys::default();
        let aa_2d_pool = AA2dPool::new(aa_2d_config, nonce_keys.clone());
        let amm_liquidity_cache = AmmLiquidityCache::new();

        let validator = validator.map(|v| {
            TempoTransactionValidator::new(
                v,
                nonce_keys.clone(),
                self.aa_valid_after_max_secs,
                amm_liquidity_cache.clone(),
            )
        });
        let protocol_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_and_spawn_maintenance_task(blob_store, pool_config)?;

        // Spawn (protocol) mempool maintenance tasks
        let task_pool = protocol_pool.clone();
        let task_provider = ctx.provider().clone();
        ctx.task_executor().spawn_critical(
            "txpool maintenance (protocol) - evict expired AA txs",
            tempo_transaction_pool::maintain::evict_expired_aa_txs(task_pool, task_provider),
        );

        // Wrap the protocol pool in our hybrid TempoTransactionPool
        let transaction_pool = TempoTransactionPool::new(protocol_pool, aa_2d_pool);

        // Spawn (AA 2d nonce) mempool maintenance tasks
        ctx.task_executor().spawn_critical(
            "txpool maintenance - 2d nonce AA txs",
            tempo_transaction_pool::maintain::maintain_2d_nonce_pool(
                transaction_pool.clone(),
                ctx.provider().canonical_state_stream(),
            ),
        );

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}

#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TempoPayloadBuilderBuilder;

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
        ))
    }
}
