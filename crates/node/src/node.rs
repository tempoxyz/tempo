use crate::{
    TempoPayloadTypes,
    engine::TempoEngineValidator,
    rpc::{
        TempoAdminApi, TempoAdminApiServer, TempoEthApi, TempoEthApiBuilder, TempoEthExt,
        TempoEthExtApiServer, TempoForkScheduleApiServer, TempoForkScheduleRpc,
        TempoOperatorApiServer, TempoOperatorRpc, TempoSimulate, TempoSimulateApiServer,
        TempoToken, TempoTokenApiServer,
    },
};
use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use reth_chainspec::{ChainKind, EthChainSpec, NamedChain};
use reth_db_api::{cursor::DbCursorRO, tables, transaction::DbTx};
use reth_node_api::{
    AddOnsContext, FullNodeComponents, FullNodeTypes, NodeAddOns, NodeTypes,
    PayloadAttributesBuilder, PayloadTypes,
};
use reth_node_builder::{
    BuilderContext, DebugNode, Node, NodeAdapter, PayloadBuilderConfig,
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        PayloadBuilderBuilder, PoolBuilder, spawn_maintenance_tasks,
    },
    rpc::{
        BasicEngineValidatorBuilder, EngineValidatorAddOn, NoopEngineApiBuilder,
        PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns, RpcHandle, RpcHooks,
    },
};
use reth_node_ethereum::EthereumNetworkBuilder;
use reth_primitives_traits::SealedHeader;
use reth_provider::providers::ProviderFactoryBuilder;
use reth_rpc_builder::{Identity, RethRpcModule};
use reth_rpc_eth_api::{
    RpcNodeCore,
    helpers::config::{EthConfigApiServer, EthConfigHandler},
};
use reth_storage_api::{AccountInfoReader, DBProvider, DatabaseProviderFactory, EmptyBodyStorage};
use reth_tracing::tracing::{debug, info, warn};
use reth_transaction_pool::{
    Pool, StatefulValidationFn, StatelessValidationFn, TransactionOrigin,
    TransactionValidationTaskExecutor, blobstore::InMemoryBlobStore,
    error::InvalidPoolTransactionError,
};
use std::sync::Arc;
use tempo_chainspec::spec::TempoChainSpec;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_payload_builder::{
    DEFAULT_BUILD_TIME_MULTIPLIER, TempoPayloadBuilder, TempoPayloadBuilderConfig,
};
use tempo_payload_types::TempoPayloadAttributes;
use tempo_primitives::{TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType};
use tempo_transaction_pool::{
    AA2dPool, AA2dPoolConfig, TempoTransactionPool,
    amm::AmmLiquidityCache,
    ordering::TempoTipOrdering,
    transaction::TempoPooledTransaction,
    validator::{
        DEFAULT_AA_VALID_AFTER_MAX_SECS, DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
        TempoTransactionValidator,
    },
};

/// 500M gas limit
pub const BLOCK_GAS_LIMIT_500M: u64 = 500_000_000;

fn load_flat_checkpoint<Tx: DbTx>(
    tx: &Tx,
    flat: &mut tempo_flatmpt::FlatMpt,
) -> anyhow::Result<(u64, u64)> {
    const BATCH_ACCOUNTS: usize = 4096;
    let mut accounts_cursor = tx.cursor_read::<tables::HashedAccounts>()?;
    let mut storage_cursor = tx.cursor_read::<tables::HashedStorages>()?;
    let mut accounts = accounts_cursor.walk(None)?;
    let mut storages = storage_cursor.walk(None)?;
    let mut next_storage = storages.next().transpose()?;
    let mut batch = Vec::with_capacity(BATCH_ACCOUNTS);
    let mut account_count = 0u64;
    let mut slot_count = 0u64;

    while let Some((account_key, account)) = accounts.next().transpose()? {
        let mut slots = Vec::new();
        while let Some((storage_account, entry)) = next_storage {
            if storage_account < account_key {
                anyhow::bail!("orphan hashed storage for account {storage_account}");
            }
            if storage_account != account_key {
                next_storage = Some((storage_account, entry));
                break;
            }
            if !entry.value.is_zero() {
                slots.push((entry.key.0, tempo_flatmpt::storage_value_rlp(entry.value)));
                slot_count += 1;
            }
            next_storage = storages.next().transpose()?;
        }
        batch.push((
            account_key.0,
            tempo_flatmpt::AccountSeed {
                nonce: account.nonce,
                balance: account.balance,
                code_hash: account.get_bytecode_hash().0,
                slots,
            },
        ));
        account_count += 1;
        if batch.len() == BATCH_ACCOUNTS {
            flat.insert_batch_accounts(std::mem::take(&mut batch))
                .map_err(|e| anyhow::anyhow!("flat checkpoint batch: {e:#}"))?;
            batch = Vec::with_capacity(BATCH_ACCOUNTS);
        }
    }
    anyhow::ensure!(
        next_storage.is_none(),
        "hashed storage exists without an account"
    );
    if !batch.is_empty() {
        flat.insert_batch_accounts(batch)
            .map_err(|e| anyhow::anyhow!("flat checkpoint batch: {e:#}"))?;
    }
    Ok((account_count, slot_count))
}

/// Tempo node CLI arguments.
#[derive(Debug, Clone, Copy, PartialEq, clap::Args)]
pub struct TempoNodeArgs {
    /// Maximum allowed `valid_after` offset for AA txs.
    #[arg(long = "txpool.aa-valid-after-max-secs", default_value_t = DEFAULT_AA_VALID_AFTER_MAX_SECS)]
    pub aa_valid_after_max_secs: u64,

    /// Maximum number of authorizations allowed in an AA transaction.
    #[arg(long = "txpool.max-tempo-authorizations", default_value_t = DEFAULT_MAX_TEMPO_AUTHORIZATIONS)]
    pub max_tempo_authorizations: usize,

    /// Enable state provider metrics for the payload builder.
    #[arg(long = "builder.state-provider-metrics", default_value_t = false)]
    pub builder_state_provider_metrics: bool,

    /// Disable prewarming for the payload builder.
    #[arg(long = "builder.disable-prewarming", default_value_t = false)]
    pub builder_disable_prewarming: bool,

    /// No-op legacy flag for payload builder prewarming.
    #[arg(long = "builder.enable-prewarming", default_value_t = true)]
    pub builder_enable_prewarming: bool,

    /// Enable speculative parallel payload builder.
    #[arg(long = "builder.parallel", default_value_t = false, hide = true)]
    pub builder_parallel: bool,

    /// Disable sharing the execution cache with the payload builder.
    #[arg(
        long = "engine.disable-execution-cache-sharing-with-builder",
        default_value_t = false
    )]
    pub engine_disable_execution_cache_sharing_with_builder: bool,

    /// Initial estimate of total replayable payload build work divided by work
    /// at transaction cutoff.
    ///
    /// The builder updates this at runtime. Higher values stop pool transaction
    /// execution earlier to leave more room for `builder_finish`.
    #[arg(
        long = "builder.build-time-multiplier",
        default_value_t = DEFAULT_BUILD_TIME_MULTIPLIER
    )]
    pub builder_build_time_multiplier: f64,
}

impl Default for TempoNodeArgs {
    fn default() -> Self {
        Self {
            aa_valid_after_max_secs: DEFAULT_AA_VALID_AFTER_MAX_SECS,
            max_tempo_authorizations: DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            builder_state_provider_metrics: false,
            builder_disable_prewarming: false,
            builder_enable_prewarming: true,
            builder_parallel: false,
            engine_disable_execution_cache_sharing_with_builder: false,
            builder_build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
        }
    }
}

impl TempoNodeArgs {
    /// Returns a [`TempoPoolBuilder`] configured from these args.
    pub fn pool_builder(&self) -> TempoPoolBuilder {
        TempoPoolBuilder {
            aa_valid_after_max_secs: self.aa_valid_after_max_secs,
            max_tempo_authorizations: self.max_tempo_authorizations,
            ..Default::default()
        }
    }

    /// Returns a [`TempoPayloadBuilderBuilder`] configured from these args.
    pub fn payload_builder_builder(&self) -> TempoPayloadBuilderBuilder {
        if self.builder_parallel {
            warn!("Parallel block builder is still in development and should not be used");
        }

        TempoPayloadBuilderBuilder {
            state_provider_metrics: self.builder_state_provider_metrics,
            enable_prewarming: !self.builder_disable_prewarming,
            enable_parallel: self.builder_parallel,
            build_time_multiplier: self.builder_build_time_multiplier,
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
            .payload(
                BasicPayloadServiceBuilder::new(payload_builder_builder)
                    // we can disable basic parent state caching because tempo builder always uses execution cache
                    .with_pre_cache_state(false),
            )
            .network(EthereumNetworkBuilder::default())
            .consensus(TempoConsensusBuilder::default())
    }

    pub fn provider_factory_builder() -> ProviderFactoryBuilder<Self> {
        ProviderFactoryBuilder::default()
    }

    /// Sets the transaction pool builder.
    pub fn with_pool_builder(mut self, pool_builder: TempoPoolBuilder) -> Self {
        self.pool_builder = pool_builder;
        self
    }

    /// Maps the transaction pool builder.
    pub fn map_pool_builder<F>(mut self, f: F) -> Self
    where
        F: FnOnce(TempoPoolBuilder) -> TempoPoolBuilder,
    {
        self.pool_builder = f(self.pool_builder);
        self
    }

    /// Sets the payload builder builder.
    pub fn with_payload_builder_builder(
        mut self,
        payload_builder_builder: TempoPayloadBuilderBuilder,
    ) -> Self {
        self.payload_builder_builder = payload_builder_builder;
        self
    }

    /// Maps the payload builder builder.
    pub fn map_payload_builder_builder<F>(mut self, f: F) -> Self
    where
        F: FnOnce(TempoPayloadBuilderBuilder) -> TempoPayloadBuilderBuilder,
    {
        self.payload_builder_builder = f(self.payload_builder_builder);
        self
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
    type Storage = EmptyBodyStorage<TempoTxEnvelope, TempoHeader>;
    type Payload = TempoPayloadTypes;
}

#[derive(Debug)]
pub struct TempoAddOns<N: FullNodeTypes<Types = TempoNode>> {
    #[allow(clippy::type_complexity)]
    inner: RpcAddOns<
        NodeAdapter<N>,
        TempoEthApiBuilder<NodeAdapter<N>>,
        TempoEngineValidatorBuilder,
        NoopEngineApiBuilder,
        BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>,
        Identity,
    >,
    validator_key: Option<B256>,
}

impl<N> TempoAddOns<N>
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
                Default::default(),
            ),
            validator_key,
        }
    }
}

impl<N> NodeAddOns<NodeAdapter<N>> for TempoAddOns<N>
where
    N: FullNodeTypes<Types = TempoNode>,
{
    type Handle = RpcHandle<NodeAdapter<N>, TempoEthApi<NodeAdapter<N>>>;

    async fn launch_add_ons(
        self,
        ctx: AddOnsContext<'_, NodeAdapter<N>>,
    ) -> eyre::Result<Self::Handle> {
        let eth_config = EthConfigHandler::new(
            ctx.node.provider.clone(),
            ctx.node.components.evm_config.clone(),
        );

        self.inner
            .launch_add_ons_with(ctx, move |container| {
                let reth_node_builder::rpc::RpcModuleContainer {
                    modules, registry, ..
                } = container;

                let eth_api = registry.eth_api().clone();
                let token = TempoToken::new(eth_api.clone());
                let eth_ext = TempoEthExt::new(eth_api.clone());
                let simulate = TempoSimulate::new(eth_api);
                let admin = TempoAdminApi::new(self.validator_key);
                let operator = TempoOperatorRpc::new(registry.admin_api());
                let fork_schedule =
                    TempoForkScheduleRpc::new(registry.eth_api().provider().clone());

                modules.merge_configured(token.into_rpc())?;
                modules.merge_configured(eth_ext.into_rpc())?;
                modules.merge_if_module_configured(RethRpcModule::Eth, simulate.into_rpc())?;
                modules.merge_configured(fork_schedule.into_rpc())?;
                modules.merge_if_module_configured(
                    RethRpcModule::Other("operator".to_string()),
                    operator.into_rpc(),
                )?;
                modules.merge_if_module_configured(RethRpcModule::Admin, admin.into_rpc())?;
                modules.merge_if_module_configured(RethRpcModule::Eth, eth_config.into_rpc())?;

                Ok(())
            })
            .await
    }
}

impl<N> RethRpcAddOns<NodeAdapter<N>> for TempoAddOns<N>
where
    N: FullNodeTypes<Types = TempoNode>,
{
    type EthApi = TempoEthApi<NodeAdapter<N>>;

    fn hooks_mut(&mut self) -> &mut RpcHooks<NodeAdapter<N>, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<NodeAdapter<N>> for TempoAddOns<N>
where
    N: FullNodeTypes<Types = TempoNode>,
{
    type ValidatorBuilder = FlatMptEngineValidatorBuilder;

    fn engine_validator_builder(&self) -> Self::ValidatorBuilder {
        FlatMptEngineValidatorBuilder(self.inner.engine_validator_builder())
    }
}

/// [`BasicEngineValidatorBuilder`] wrapper that, in flat-MPT `Root` mode, installs
/// the flat engine as the tree validator's custom state-root computation — every
/// inserted block's header root is then checked against the flat MPT.
#[derive(Debug, Clone, Default)]
pub struct FlatMptEngineValidatorBuilder(BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>);

impl<Node> reth_node_builder::rpc::EngineValidatorBuilder<Node> for FlatMptEngineValidatorBuilder
where
    Node: FullNodeComponents<
            Types = TempoNode,
            Evm: reth_node_api::ConfigureEngineEvm<
                <<TempoNode as NodeTypes>::Payload as PayloadTypes>::ExecutionData,
            >,
        >,
    BasicEngineValidatorBuilder<TempoEngineValidatorBuilder>:
        reth_node_builder::rpc::EngineValidatorBuilder<
                Node,
                EngineValidator = reth_engine_tree::tree::BasicEngineValidator<
                    Node::Provider,
                    Node::Evm,
                    TempoEngineValidator,
                >,
            >,
    Node::Provider: DatabaseProviderFactory,
{
    type EngineValidator = reth_engine_tree::tree::BasicEngineValidator<
        Node::Provider,
        Node::Evm,
        TempoEngineValidator,
    >;

    async fn build_tree_validator(
        self,
        ctx: &AddOnsContext<'_, Node>,
        tree_config: reth_node_api::TreeConfig,
        state_trie_overlays: reth_node_builder::rpc::OverlayManager<TempoPrimitives>,
    ) -> eyre::Result<Self::EngineValidator> {
        let validator = self
            .0
            .build_tree_validator(ctx, tree_config, state_trie_overlays)
            .await?;
        if tempo_flatmpt::mode() != tempo_flatmpt::FlatMode::Root {
            return Ok(validator);
        }
        let chain_spec = ctx.config.chain.clone();
        info!(target: "flatmpt", "installing flat MPT as the engine's state-root computation");
        // Initialize the shadow now, at node startup — a large bloat-mode load
        // (minutes at 100M+ slots) must not run inside the first payload build.
        {
            use reth_provider::BlockReaderIdExt as _;
            let canonical_tip = ctx.node.provider().latest_header()?;
            if let Some(tip) = canonical_tip {
                let db_provider = ctx
                    .node
                    .provider()
                    .database_provider_ro()?
                    .disable_long_read_transaction_safety();
                let checkpoint_number = tip.number();
                let checkpoint_root = if checkpoint_number == 0 {
                    use reth_trie_db::{
                        DatabaseHashedCursorFactory, DatabaseStateRoot as _,
                        DatabaseTrieCursorFactory, PackedKeyAdapter,
                    };
                    type DbStateRoot<'a, Tx> = reth_trie::StateRoot<
                        DatabaseTrieCursorFactory<&'a Tx, PackedKeyAdapter>,
                        DatabaseHashedCursorFactory<&'a Tx>,
                    >;
                    DbStateRoot::<_>::from_tx(db_provider.tx_ref()).root()?
                } else {
                    tip.state_root()
                };
                tempo_flatmpt::shadow_from_checkpoint(
                    checkpoint_number,
                    checkpoint_root,
                    tip.state_root(),
                    move |flat| load_flat_checkpoint(db_provider.tx_ref(), flat),
                );
            } else {
                let chain_spec = chain_spec.clone();
                tempo_flatmpt::shadow(move || {
                    (
                        tempo_flatmpt::genesis_to_ops(chain_spec.inner.genesis()),
                        chain_spec.inner.genesis_header().state_root(),
                    )
                });
            }
        }
        // TEMPO_NO_STATE_KV: the duplicate state KV is not persisted, so
        // latest-state point reads (engine validation misses, txpool, RPC)
        // must come from the flat store. Install the canonical-tip read hook
        // that reth's latest-state provider consults. Correctness: these
        // reads sit underneath the engine's in-memory overlay of unpersisted
        // blocks, which shadows every key written after the last persisted
        // block — so serving the canonical tip state is exact. The tip
        // anchor (not "newest flat state") keeps not-yet-canonical candidate
        // blocks out of the served state.
        if std::env::var("TEMPO_NO_STATE_KV").is_ok_and(|v| v == "1" || v == "all") {
            let provider = ctx.node.provider().clone();
            let chain_spec = chain_spec.clone();
            // Resolution is cached per tip: pool validation calls this for
            // every incoming transaction's fee-balance read, so the walk must
            // not repeat per read.
            type TipState = (
                B256,
                tempo_flatmpt::FlatSnapshot,
                Vec<Arc<tempo_flatmpt::PendingBlock>>,
            );
            let cached: Arc<std::sync::Mutex<Option<Arc<TipState>>>> =
                Arc::new(std::sync::Mutex::new(None));
            let resolve = move || -> Result<Arc<TipState>, reth_errors::ProviderError> {
                use reth_provider::BlockReaderIdExt as _;
                let err = |m: &str| {
                    reth_errors::ProviderError::other(std::io::Error::other(m.to_string()))
                };
                let tip_root = provider
                    .latest_header()?
                    .ok_or_else(|| err("no canonical head for flat tip read"))?
                    .state_root();
                if let Ok(guard) = cached.lock()
                    && let Some(state) = guard.as_ref()
                    && state.0 == tip_root
                {
                    return Ok(state.clone());
                }
                let shadow = tempo_flatmpt::shadow(|| {
                    (
                        tempo_flatmpt::genesis_to_ops(chain_spec.inner.genesis()),
                        chain_spec.inner.genesis_header().state_root(),
                    )
                })
                .expect("flat root mode is on");
                // Transient gaps (publish/retire races around an apply) heal
                // within an apply cycle; a persistent failure is loud.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                loop {
                    if let Some((k, snap)) = tempo_flatmpt::published_snapshot()
                        && let Some(chain) = tempo_flatmpt::pending_chain(k, tip_root)
                    {
                        let state = Arc::new((tip_root, snap, chain));
                        if let Ok(mut g) = cached.lock() {
                            *g = Some(state.clone());
                        }
                        return Ok(state);
                    }
                    if let Some(g) = shadow.try_read_for(std::time::Duration::from_millis(2))
                        && g.at_parent(tip_root)
                    {
                        let snap = g.snapshot();
                        drop(g);
                        let state = Arc::new((tip_root, snap, Vec::new()));
                        if let Ok(mut g) = cached.lock() {
                            *g = Some(state.clone());
                        }
                        return Ok(state);
                    }
                    if std::time::Instant::now() > deadline {
                        return Err(err("flat store cannot serve the canonical tip state"));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            };
            let resolve_acct = Arc::new(resolve);
            let resolve_slot = resolve_acct.clone();
            let _ = reth_provider::providers::FLAT_STATE_READS.set(
                reth_provider::providers::FlatStateReads {
                    account: Box::new(move |address| {
                        let state = resolve_acct()?;
                        let (_, snap, chain) = &*state;
                        let key = alloy_primitives::keccak256(address);
                        let read =
                            tempo_flatmpt::overlay_account(chain, snap, &key.0).map_err(|e| {
                                reth_errors::ProviderError::other(std::io::Error::other(format!(
                                    "{e:#}"
                                )))
                            })?;
                        Ok(read.map(|(nonce, balance, code_hash)| {
                            reth_primitives_traits::Account {
                                nonce,
                                balance,
                                bytecode_hash: (code_hash != alloy_primitives::keccak256([]).0)
                                    .then(|| B256::from(code_hash)),
                            }
                        }))
                    }),
                    storage: Box::new(move |address, slot| {
                        let state = resolve_slot()?;
                        let (_, snap, chain) = &*state;
                        let acct_key = alloy_primitives::keccak256(address);
                        let slot_key = alloy_primitives::keccak256(slot.0);
                        tempo_flatmpt::overlay_storage(chain, snap, &acct_key.0, &slot_key.0)
                            .map_err(|e| {
                                reth_errors::ProviderError::other(std::io::Error::other(format!(
                                    "{e:#}"
                                )))
                            })
                    }),
                },
            );
            info!(target: "flatmpt", "flat tip-state read hook installed (no state KV)");
        }
        let chain_spec = ctx.config.chain.clone();
        Ok(validator.with_custom_state_root(Arc::new(move |input| {
            let shadow = tempo_flatmpt::shadow(|| {
                (
                    tempo_flatmpt::genesis_to_ops(chain_spec.inner.genesis()),
                    chain_spec.inner.genesis_header().state_root(),
                )
            })
            .expect("flat root mode is on");
            let mut ops = tempo_flatmpt::bundle_to_ops(&input.output.state);
            // A block whose sparse commitment this process already produced
            // (and whose flat apply is queued on the follower) validates
            // without waiting behind the apply's write lock; the follower's
            // root cross-check is the loud gate for those.
            if let Some(root) =
                tempo_flatmpt::follower::pending_root(input.parent_block.state_root(), &mut ops)
            {
                return Ok((root, reth_trie_common::updates::TrieUpdates::default()));
            }
            let root = shadow
                .write()
                .root_for(
                    input.parent_block.number(),
                    input.parent_block.state_root(),
                    ops,
                )
                .map_err(|e| {
                    reth_errors::ProviderError::other(std::io::Error::other(format!("{e:#}")))
                })?;
            Ok((root, reth_trie_common::updates::TrieUpdates::default()))
        })))
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

    type AddOns = TempoAddOns<N>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components(self.pool_builder.clone(), self.payload_builder_builder)
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
        _chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes, TempoHeader>
    {
        TempoPayloadAttributesBuilder::new()
    }
}

/// The attributes builder with a restricted set of validators
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct TempoPayloadAttributesBuilder;

impl TempoPayloadAttributesBuilder {
    /// Creates a new instance of the builder.
    pub const fn new() -> Self {
        Self
    }
}

impl PayloadAttributesBuilder<TempoPayloadAttributes, TempoHeader>
    for TempoPayloadAttributesBuilder
{
    fn build(&self, _parent: &SealedHeader<TempoHeader>) -> TempoPayloadAttributes {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let (timestamp, timestamp_millis_part) = (millis / 1000, millis % 1000);
        TempoPayloadAttributes::new(
            None,
            timestamp,
            timestamp_millis_part,
            Default::default(),
            None,
            Vec::new,
        )
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
        let mut evm_config = TempoEvmConfig::new(ctx.chain_spec());
        if let Some(cache) = ctx.sender_recovery_cache() {
            evm_config = evm_config.with_sender_recovery_cache(cache.clone());
        }
        Ok(evm_config)
    }
}

/// Builder for [`TempoConsensus`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TempoConsensusBuilder {
    /// Whether to allow BAL hashes before Amsterdam activation.
    pub allow_bal_hashes: bool,
}

#[allow(clippy::derivable_impls)]
impl Default for TempoConsensusBuilder {
    fn default() -> Self {
        Self {
            allow_bal_hashes: cfg!(feature = "bal"),
        }
    }
}

impl<Node> ConsensusBuilder<Node> for TempoConsensusBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type Consensus = TempoConsensus;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(TempoConsensus::new_with_bal_hashes(
            ctx.chain_spec(),
            self.allow_bal_hashes,
        ))
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
#[derive(Clone)]
#[non_exhaustive]
pub struct TempoPoolBuilder {
    /// Maximum allowed `valid_after` offset for AA txs.
    pub aa_valid_after_max_secs: u64,
    /// Maximum number of authorizations allowed in an AA transaction.
    pub max_tempo_authorizations: usize,
    /// Whether to skip the FeeAMM liquidity check during pool admission.
    pub disable_fee_amm_check: bool,
    /// Optional additional stateless validation check forwarded to the inner ETH validator.
    pub additional_stateless_validation: Option<StatelessValidationFn<TempoPooledTransaction>>,
    /// Optional additional stateful validation check forwarded to the inner ETH validator.
    pub additional_stateful_validation: Option<StatefulValidationFn<TempoPooledTransaction>>,
}

impl TempoPoolBuilder {
    /// Sets the maximum allowed `valid_after` offset for AA txs.
    pub const fn with_aa_tx_valid_after_max_secs(mut self, secs: u64) -> Self {
        self.aa_valid_after_max_secs = secs;
        self
    }

    /// Sets the maximum number of authorizations allowed in an AA transaction.
    pub const fn with_max_tempo_authorizations(mut self, max: usize) -> Self {
        self.max_tempo_authorizations = max;
        self
    }

    /// Configures whether to disable the FeeAMM liquidity check during pool admission.
    pub const fn with_disable_fee_amm_check(mut self, disable: bool) -> Self {
        self.disable_fee_amm_check = disable;
        self
    }

    /// Sets an additional stateless validation check applied at the end of the inner ETH
    /// validator's stateless validation.
    ///
    /// This is the programmatic equivalent of installing a custom check with
    /// [`EthTransactionValidator::set_additional_stateless_validation`](reth_transaction_pool::EthTransactionValidator::set_additional_stateless_validation).
    /// It is intended to be used from a [`TempoNode`] mapper, for example via
    /// `tempo::TempoOverrides::map_tempo_node`, when the validation policy should not be exposed
    /// as a CLI argument.
    ///
    /// The closure receives the transaction origin and pooled transaction. Return `Ok(())` to
    /// accept the transaction or [`InvalidPoolTransactionError`] to reject it.
    pub fn with_additional_stateless_validation<F>(mut self, f: F) -> Self
    where
        F: Fn(
                TransactionOrigin,
                &TempoPooledTransaction,
            ) -> Result<(), InvalidPoolTransactionError>
            + Send
            + Sync
            + 'static,
    {
        self.additional_stateless_validation = Some(Arc::new(f));
        self
    }

    /// Sets or clears an additional shared stateless validation check applied at the end of the
    /// inner ETH validator's stateless validation.
    ///
    /// See [`EthTransactionValidator::set_additional_stateless_validation_fn_opt`](reth_transaction_pool::EthTransactionValidator::set_additional_stateless_validation_fn_opt).
    pub fn with_additional_stateless_validation_fn_opt(
        mut self,
        f: Option<StatelessValidationFn<TempoPooledTransaction>>,
    ) -> Self {
        self.additional_stateless_validation = f;
        self
    }

    /// Sets an additional stateful validation check applied at the end of the inner ETH
    /// validator's stateful validation.
    ///
    /// See [`EthTransactionValidator::set_additional_stateful_validation`](reth_transaction_pool::EthTransactionValidator::set_additional_stateful_validation).
    pub fn with_additional_stateful_validation<F>(mut self, f: F) -> Self
    where
        F: Fn(
                TransactionOrigin,
                &TempoPooledTransaction,
                &dyn AccountInfoReader,
            ) -> Result<(), InvalidPoolTransactionError>
            + Send
            + Sync
            + 'static,
    {
        self.additional_stateful_validation = Some(Arc::new(f));
        self
    }

    /// Sets or clears an additional shared stateful validation check applied at the end of the
    /// inner ETH validator's stateful validation.
    ///
    /// See [`EthTransactionValidator::set_additional_stateful_validation_fn_opt`](reth_transaction_pool::EthTransactionValidator::set_additional_stateful_validation_fn_opt).
    pub fn with_additional_stateful_validation_fn_opt(
        mut self,
        f: Option<StatefulValidationFn<TempoPooledTransaction>>,
    ) -> Self {
        self.additional_stateful_validation = f;
        self
    }
}

impl core::fmt::Debug for TempoPoolBuilder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TempoPoolBuilder")
            .field("aa_valid_after_max_secs", &self.aa_valid_after_max_secs)
            .field("max_tempo_authorizations", &self.max_tempo_authorizations)
            .field("disable_fee_amm_check", &self.disable_fee_amm_check)
            .field(
                "additional_stateless_validation",
                &self.additional_stateless_validation.as_ref().map(|_| "..."),
            )
            .field(
                "additional_stateful_validation",
                &self.additional_stateful_validation.as_ref().map(|_| "..."),
            )
            .finish()
    }
}

impl Default for TempoPoolBuilder {
    fn default() -> Self {
        Self {
            aa_valid_after_max_secs: DEFAULT_AA_VALID_AFTER_MAX_SECS,
            max_tempo_authorizations: DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
            disable_fee_amm_check: false,
            additional_stateless_validation: None,
            additional_stateful_validation: None,
        }
    }
}

impl<Node> PoolBuilder<Node, TempoEvmConfig> for TempoPoolBuilder
where
    Node: FullNodeTypes<Types = TempoNode>,
{
    type Pool = TempoTransactionPool<Node::Provider>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: TempoEvmConfig,
    ) -> eyre::Result<Self::Pool> {
        let mut pool_config = ctx.pool_config();
        pool_config.max_inflight_delegated_slot_limit = pool_config.max_account_slots;

        // this store is effectively a noop
        let blob_store = InMemoryBlobStore::default();
        let validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .set_block_gas_limit(ctx.chain_spec().inner.genesis().gas_limit)
                .disable_balance_check()
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
                .with_custom_tx_type(TempoTxType::AA as u8)
                .no_eip4844()
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let aa_2d_config = AA2dPoolConfig {
            price_bump_config: pool_config.price_bumps,
            pending_limit: pool_config.pending_limit,
            queued_limit: pool_config.queued_limit,
            max_txs_per_sender: pool_config.max_account_slots,
        };
        let aa_2d_pool = AA2dPool::new(aa_2d_config);
        let amm_liquidity_cache = AmmLiquidityCache::new(ctx.provider())?;

        let Self {
            aa_valid_after_max_secs,
            max_tempo_authorizations,
            disable_fee_amm_check,
            additional_stateless_validation,
            additional_stateful_validation,
        } = self;
        let validator = validator.map(move |mut v| {
            v.set_additional_stateless_validation_fn_opt(additional_stateless_validation.clone());
            v.set_additional_stateful_validation_fn_opt(additional_stateful_validation.clone());
            TempoTransactionValidator::new(
                v,
                aa_valid_after_max_secs,
                max_tempo_authorizations,
                amm_liquidity_cache.clone(),
            )
            .with_disable_fee_amm_check(disable_fee_amm_check)
        });
        let protocol_pool = Pool::new(
            validator,
            TempoTipOrdering::default(),
            blob_store,
            pool_config.clone(),
        );

        // Wrap the protocol pool in our hybrid TempoTransactionPool
        let transaction_pool = TempoTransactionPool::new(protocol_pool, aa_2d_pool);

        spawn_maintenance_tasks(ctx, transaction_pool.clone(), &pool_config)?;

        // Spawn unified Tempo pool maintenance task
        // This consolidates: expired AA txs, 2D nonce updates, AMM cache, and keychain revocations
        ctx.task_executor().spawn_critical_os_thread(
            "tempo-txpool-maintenance",
            "txpool maintenance - tempo pool",
            tempo_transaction_pool::maintain::maintain_tempo_pool(transaction_pool.clone()),
        );

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TempoPayloadBuilderBuilder {
    /// Enable state provider metrics for the payload builder.
    pub state_provider_metrics: bool,
    /// Enable prewarming for the payload builder.
    pub enable_prewarming: bool,
    /// Enable speculative parallel payload-builder planning.
    pub enable_parallel: bool,
    /// Initial estimate of total replayable payload build work divided by work
    /// at transaction cutoff.
    pub build_time_multiplier: f64,
}

impl Default for TempoPayloadBuilderBuilder {
    fn default() -> Self {
        Self {
            state_provider_metrics: false,
            enable_prewarming: true,
            enable_parallel: false,
            build_time_multiplier: DEFAULT_BUILD_TIME_MULTIPLIER,
        }
    }
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
        let conf = ctx.payload_builder_config();
        let chain = ctx.chain_spec().chain();
        let desired_gas_limit = conf.gas_limit().or_else(|| match chain.kind() {
            ChainKind::Named(NamedChain::Tempo | NamedChain::TempoModerato) => {
                Some(BLOCK_GAS_LIMIT_500M)
            }
            _ => None,
        });

        Ok(TempoPayloadBuilder::new(
            pool,
            ctx.provider().clone(),
            ctx.task_executor().clone(),
            evm_config,
            TempoPayloadBuilderConfig {
                desired_gas_limit,
                is_dev: ctx.is_dev(),
                state_provider_metrics: self.state_provider_metrics,
                enable_prewarming: self.enable_prewarming,
                skip_state_root: ctx.config().tree_config().skip_state_root(),
                enable_parallel: self.enable_parallel,
                build_time_multiplier: self.build_time_multiplier,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{TempoNode, TempoNodeArgs, TempoPayloadBuilderBuilder, TempoPoolBuilder};

    #[test]
    fn tempo_node_maps_pool_builder() {
        let node = TempoNode::new(
            &TempoNodeArgs {
                aa_valid_after_max_secs: 12,
                ..Default::default()
            },
            None,
        )
        .map_pool_builder(|pool| pool.with_max_tempo_authorizations(7));

        assert_eq!(node.pool_builder.aa_valid_after_max_secs, 12);
        assert_eq!(node.pool_builder.max_tempo_authorizations, 7);
    }

    #[test]
    fn tempo_node_disables_fee_amm_pool_check() {
        let node =
            TempoNode::default().map_pool_builder(|pool| pool.with_disable_fee_amm_check(true));

        assert!(node.pool_builder.disable_fee_amm_check);
    }

    #[test]
    fn tempo_node_sets_pool_builder() {
        let node = TempoNode::default().with_pool_builder(TempoPoolBuilder {
            aa_valid_after_max_secs: 42,
            ..Default::default()
        });

        assert_eq!(node.pool_builder.aa_valid_after_max_secs, 42);
    }

    #[test]
    fn tempo_node_maps_payload_builder_builder() {
        let node = TempoNode::new(&TempoNodeArgs::default(), None).map_payload_builder_builder(
            |mut payload| {
                payload.state_provider_metrics = true;
                payload
            },
        );

        assert!(node.payload_builder_builder.state_provider_metrics);
        assert_eq!(
            node.payload_builder_builder.build_time_multiplier,
            TempoNodeArgs::default().builder_build_time_multiplier
        );
    }

    #[test]
    fn tempo_node_sets_payload_builder_builder() {
        let node = TempoNode::default().with_payload_builder_builder(TempoPayloadBuilderBuilder {
            state_provider_metrics: true,
            ..Default::default()
        });

        assert!(node.payload_builder_builder.state_provider_metrics);
    }
}
