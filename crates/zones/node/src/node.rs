//! Tempo Zone Node configuration.
//!
//! This is a lightweight L2 node built on reth's node builder infrastructure.
//! It reuses Tempo's EVM, primitives, and pool, but with noop consensus/network/payload.

use crate::{
    ZoneEngine,
    rpc::{
        NodeZoneDebugApi, OperatorWeb3Api, OperatorZoneApi, ZoneApiServer as _, ZoneRpc,
        ZoneRpcApi, operator_zone_rpc_module, rpc_connection_config, start_redacted_rpc,
    },
};
use alloy_consensus::TxReceipt as _;
use alloy_eips::BlockHashOrNumber;
use alloy_primitives::{Address, U256};
use alloy_provider::Provider as _;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolEvent as _;
use k256::SecretKey;
use reth_chainspec::EthChainSpec;
use reth_eth_wire_types::primitives::BasicNetworkPrimitives;
use reth_node_api::{
    AddOnsContext, FullNodeComponents, FullNodeTypes, NodeAddOns, NodeTypes,
    PayloadAttributesBuilder, PayloadTypes,
};
use reth_node_builder::{
    BuilderContext, DebugNode, Node, NodeAdapter,
    components::{
        BasicPayloadServiceBuilder, ComponentsBuilder, ConsensusBuilder, ExecutorBuilder,
        NoopNetworkBuilder, PoolBuilder, spawn_maintenance_tasks,
    },
    rpc::{
        BasicEngineValidatorBuilder, EngineValidatorAddOn, EthApiBuilder, NoopEngineApiBuilder,
        PayloadValidatorBuilder, RethRpcAddOns, RpcAddOns,
    },
};
use reth_primitives_traits::SealedHeader;
use reth_provider::ChainSpecProvider;
use reth_rpc_api::Web3ApiServer as _;
use reth_rpc_builder::Identity;
use reth_storage_api::{
    BlockNumReader, EmptyBodyStorage, HeaderProvider, ReceiptProvider, StateProvider,
    StateProviderFactory,
};
use reth_transaction_pool::{
    Pool, PoolTransaction, TransactionValidationTaskExecutor, blobstore::InMemoryBlobStore,
    error::InvalidPoolTransactionError,
};
use std::{num::NonZeroU32, sync::Arc, time::Duration};
use tempo_alloy::TempoNetwork;
use tempo_contracts::zones::{
    LegacyTempoAdvanced, TempoAdvanced, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS,
    ZonePortal::{self},
};
use tempo_evm::{TempoInvalidTransaction, consensus::TempoConsensus};
use tempo_node::{
    DEFAULT_AA_VALID_AFTER_MAX_SECS, engine::TempoEngineValidator, rpc::TempoEthApiBuilder,
};
use tempo_precompiles::tip20::TIP20Token;
use tempo_primitives::{
    self as primitives, TempoHeader, TempoPrimitives, TempoTxEnvelope, TempoTxType,
};
use tempo_transaction_pool::{
    AA2dPool, AA2dPoolConfig, TempoTransactionPool, TempoTransactionPoolExt,
    amm::AmmLiquidityCache,
    ordering::TempoTipOrdering,
    transaction::{TempoPoolTransactionError, TempoPooledTransaction},
    validator::{DEFAULT_MAX_TEMPO_AUTHORIZATIONS, TempoTransactionValidator},
};
use tracing::{debug, info, warn};
use zone_chainspec::ZoneChainSpec;
use zone_evm::ZoneEvmConfig;
use zone_l1::{
    DepositQueue, EncryptionKeyRing, EncryptionKeyRotation, L1BlockTracker, L1Subscriber,
    L1SubscriberConfig, TempoStateExt, encryption_key_address, initialize_portal_pause,
    state::{EnabledTokenRegistry, L1StateCache, L1StateProvider, L1StateProviderConfig},
    watch_portal_pause,
};
use zone_p2p::P2pConfig;
use zone_payload::{
    DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS, WithdrawalRevealEncryptor, ZonePayloadAttributes,
    ZonePayloadFactory, ZonePayloadTypes,
};
use zone_primitives::constants::{decode_l1_chain_id, zone_chain_id};
use zone_rpc::ZoneDebugApiRpcServer;
use zone_sequencer::{
    BatchAnchorConfig, ProofCollectorConfig, ProverAddresses, SettlementProver,
    SettlementProverConfig, WithdrawalBatchLimits, ZoneSequencerConfig, create_proof_collector,
    spawn_settlement_prover, spawn_zone_sequencer,
};

fn validate_zone_chain_id(parent_chain_id: u64, zone_id: u32, chain_id: u64) -> eyre::Result<()> {
    let expected = zone_chain_id(parent_chain_id, zone_id)?;
    eyre::ensure!(
        chain_id == expected,
        "chain ID mismatch: portal zone ID {zone_id} on parent chain {parent_chain_id} requires chain_id={expected}, but genesis has {chain_id}"
    );
    Ok(())
}

fn validate_configured_zone_id(
    source: &str,
    configured_zone_id: u32,
    portal_zone_id: u32,
) -> eyre::Result<()> {
    eyre::ensure!(
        configured_zone_id == portal_zone_id,
        "zone ID mismatch: {source} has {configured_zone_id}, but portal has {portal_zone_id}"
    );
    Ok(())
}

/// Network primitives for Zone Nodes
type ZoneNetworkPrimitives = BasicNetworkPrimitives<TempoPrimitives, TempoTxEnvelope>;

/// Sequencer-side sender reveal encryptor used while building
/// `finalizeWithdrawalBatch` system transactions.
///
/// The encrypted sender payload is hashed into withdrawal data, so ECIES must
/// not use fresh randomness here. This implementation derives reproducible
/// encryption material from the sequencer encryption key, zone id, reveal key,
/// sender, withdrawal transaction hash, and fallback nonce, which keeps identical
/// withdrawal batches byte-for-byte stable across sequencers.
struct SequencerWithdrawalRevealEncryptor {
    encryption_key: Arc<SecretKey>,
    zone_id: u32,
}

impl SequencerWithdrawalRevealEncryptor {
    fn new(encryption_key: SecretKey, zone_id: u32) -> Self {
        Self {
            encryption_key: Arc::new(encryption_key),
            zone_id,
        }
    }
}

impl std::fmt::Debug for SequencerWithdrawalRevealEncryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SequencerWithdrawalRevealEncryptor")
            .field("zone_id", &self.zone_id)
            .finish_non_exhaustive()
    }
}

impl WithdrawalRevealEncryptor for SequencerWithdrawalRevealEncryptor {
    fn encrypt_sender(
        &self,
        reveal_to: &[u8],
        sender: Address,
        tx_hash: alloy_primitives::B256,
        fallback_nonce: u64,
    ) -> Option<Vec<u8>> {
        zone_precompiles::ecies::encrypt_authenticated_withdrawal_deterministic(
            &self.encryption_key,
            self.zone_id,
            reveal_to,
            sender,
            tx_hash,
            fallback_nonce,
        )
    }
}

/// Configuration for the sequencer background tasks
#[derive(Debug, Clone)]
pub struct ZoneSequencerAddOnsConfig {
    /// Shared sequencer signer used for block production and encryption. Without a manifest it
    /// also signs L1 settlement transactions.
    pub sequencer_signer: PrivateKeySigner,
    /// Zone ID used by sequencer encryption.
    pub zone_id: u32,
    /// Fallback interval for reconciling the canonical Zone head.
    pub zone_poll_interval: Duration,
    /// EIP-2935 history and safety-margin limits used by the batch submitter.
    pub batch_anchor_config: BatchAnchorConfig,
    /// How often the withdrawal processor polls the L1 queue.
    pub withdrawal_poll_interval: Duration,
    /// Gas and concurrency limits for withdrawal processing transactions.
    pub withdrawal_batch_limits: WithdrawalBatchLimits,
}

/// Configuration for the Zone redacted RPC server extension.
#[derive(Debug, Clone, Default)]
pub struct ZoneRedactedRpcConfig {
    /// Port for RPC traffic.
    pub redacted_rpc_port: u16,
    /// Zone ID used by redacted RPC authentication.
    pub zone_id: u32,
    /// Max duration for redacted RPC auth.
    pub max_auth_token_validity: Duration,
}

/// Tempo Zone node type configuration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ZoneNode {
    /// Queue of L1 deposit messages to be included in the next zone block.
    deposit_queue: DepositQueue,
    /// Configuration for the L1 event subscriber (RPC endpoint, retries, etc.).
    l1_config: L1SubscriberConfig,
    /// Configuration for the L1 state provider (contract addresses, query parameters).
    l1_state_provider_config: L1StateProviderConfig,
    /// Shared L1 state cache (enabled tokens, zone metadata, etc.).
    l1_state_cache: L1StateCache,
    /// Shared registry of tokens enabled for this zone.
    enabled_tokens: EnabledTokenRegistry,
    /// L1 anchors independently observed and applied by the subscriber.
    l1_block_tracker: L1BlockTracker,
    /// Private encryption keys bound by finalized Portal rotation events.
    encryption_keys: Option<EncryptionKeyRing>,
    /// Address of the L1 deposit portal contract.
    portal_address: Address,
    /// Number of zone blocks between withdrawal batch boundaries.
    withdrawal_batch_interval_blocks: u64,
    /// Encrypts authenticated-withdrawal sender reveal data during payload construction.
    withdrawal_reveal_encryptor: Option<Arc<dyn WithdrawalRevealEncryptor>>,
    /// Redacted RPC config.
    redacted_rpc_config: ZoneRedactedRpcConfig,
    /// Optional sequencer config. When set, sequencer tasks are spawned.
    sequencer_config: Option<ZoneSequencerAddOnsConfig>,
    /// Optional SPF validation config.
    prover_config: Option<ProverAddresses>,
    /// Optional static Zone P2P networking config.
    p2p_config: Option<P2pConfig>,
    /// Whether a consumer outside this builder drains the deposit queue.
    external_deposit_consumer: bool,
}

impl ZoneNode {
    // Creates a new ZoneNode
    pub fn new(
        l1_rpc_url: String,
        portal_address: Address,
        l1_fetch_concurrency: usize,
        retry_connection_interval: Duration,
    ) -> Self {
        let deposit_queue = DepositQueue::default();

        let l1_state_cache = L1StateCache::new();
        let enabled_tokens = EnabledTokenRegistry::default();
        let l1_block_tracker = L1BlockTracker::default();
        let l1_config = L1SubscriberConfig {
            l1_rpc_url: l1_rpc_url.clone(),
            portal_address,
            l1_fetch_concurrency,
            retry_connection_interval,
            retain_portal_evidence: false,
            deferred_work_start: None,
            checkpoint_zone_block: None,
        };

        let l1_state_provider_config = L1StateProviderConfig {
            l1_rpc_url,
            portal_address,
            retry_connection_interval,
            ..Default::default()
        };

        Self {
            deposit_queue,
            l1_config,
            l1_state_provider_config,
            l1_state_cache,
            enabled_tokens,
            l1_block_tracker,
            encryption_keys: None,
            portal_address,
            withdrawal_batch_interval_blocks: DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS,
            withdrawal_reveal_encryptor: None,
            redacted_rpc_config: ZoneRedactedRpcConfig::default(),
            sequencer_config: None,
            prover_config: None,
            p2p_config: None,
            external_deposit_consumer: false,
        }
    }

    /// Set the redacted RPC configuration.
    pub fn with_redacted_rpc(mut self, config: ZoneRedactedRpcConfig) -> Self {
        self.redacted_rpc_config = config;
        self
    }

    /// Retain authenticated Portal logs for an external observer.
    pub fn with_portal_evidence_retention(mut self) -> Self {
        self.l1_config.retain_portal_evidence = true;
        self
    }

    /// Set the sequencer configuration. When set, batch submission and
    /// withdrawal processing tasks are spawned during node launch.
    pub fn with_sequencer(mut self, config: ZoneSequencerAddOnsConfig) -> Self {
        let encryption_key = SecretKey::from(config.sequencer_signer.credential());
        self.withdrawal_reveal_encryptor = Some(Arc::new(SequencerWithdrawalRevealEncryptor::new(
            encryption_key.clone(),
            config.zone_id,
        )));
        self = self.with_deposit_decryption_keys([encryption_key]);
        self.sequencer_config = Some(config);
        self
    }

    /// Require SPF validation and a Nitro NSM attestation from the prover assigned to the live
    /// L1 hardfork before settlement. Implies proof persistence.
    pub fn with_prover(mut self, prover_addresses: ProverAddresses) -> Self {
        self.prover_config = Some(prover_addresses);
        self
    }

    /// Add private keys that may be referenced by finalized encrypted deposits.
    pub fn with_deposit_decryption_keys(
        mut self,
        keys: impl IntoIterator<Item = SecretKey>,
    ) -> Self {
        let ring = self
            .encryption_keys
            .get_or_insert_with(EncryptionKeyRing::default);
        for key in keys {
            ring.add_candidate(key);
        }
        self
    }

    /// Declare that a consumer outside this builder drains [`Self::deposit_queue`].
    ///
    /// Callers that drive their own [`crate::ZoneEngine`] against the shared queue — such as test
    /// harnesses — must opt in so node startup knows the Zone chain can advance.
    pub fn with_external_deposit_consumer(mut self) -> Self {
        self.external_deposit_consumer = true;
        self
    }

    /// Enable static Zone P2P networking for this node.
    pub fn with_p2p(mut self, config: P2pConfig) -> Self {
        self.p2p_config = Some(config);
        self
    }

    /// Set the encryptor used for authenticated-withdrawal sender reveal data.
    pub fn with_withdrawal_reveal_encryptor(
        mut self,
        encryptor: Arc<dyn WithdrawalRevealEncryptor>,
    ) -> Self {
        self.withdrawal_reveal_encryptor = Some(encryptor);
        self
    }

    /// Set the parent L1 chain ID, avoiding a startup RPC lookup.
    pub fn with_l1_chain_id(mut self, chain_id: u64) -> Self {
        self.l1_state_provider_config.chain_id = Some(chain_id);
        self
    }

    /// Bound L1 state-provider retries for callers that must fail finitely on cache misses.
    pub fn with_l1_state_provider_retry_limits(
        mut self,
        transport_retries: u32,
        sync_attempts: NonZeroU32,
    ) -> Self {
        self.l1_state_provider_config.max_retries = transport_retries;
        self.l1_state_provider_config.max_sync_attempts = Some(sync_attempts);
        self
    }

    /// Set the number of zone blocks between empty withdrawal batch
    /// finalization.
    pub fn with_withdrawal_batch_interval_blocks(mut self, interval_blocks: u64) -> Self {
        self.withdrawal_batch_interval_blocks = interval_blocks.max(1);
        self
    }

    /// Returns the current deposit queue
    pub fn deposit_queue(&self) -> DepositQueue {
        self.deposit_queue.clone()
    }

    /// Returns the current l1 state cache
    pub fn l1_state_cache(&self) -> L1StateCache {
        self.l1_state_cache.clone()
    }

    /// Returns the shared enabled-token registry.
    pub fn enabled_tokens(&self) -> EnabledTokenRegistry {
        self.enabled_tokens.clone()
    }

    /// Returns the L1 block observation tracker.
    pub fn l1_block_tracker(&self) -> L1BlockTracker {
        self.l1_block_tracker.clone()
    }

    /// Returns the shared encrypted-deposit key ring, when configured.
    pub fn deposit_decryption_keys(&self) -> Option<EncryptionKeyRing> {
        self.encryption_keys.clone()
    }
}

impl NodeTypes for ZoneNode {
    type Primitives = TempoPrimitives;
    type ChainSpec = ZoneChainSpec;
    type Storage = EmptyBodyStorage<TempoTxEnvelope, TempoHeader>;
    type Payload = ZonePayloadTypes;
}

/// Addons for Tempo Zone nodes.
pub struct ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    inner: RpcAddOns<
        N,
        TempoEthApiBuilder<N>,
        ZoneEngineValidatorBuilder,
        NoopEngineApiBuilder,
        BasicEngineValidatorBuilder<ZoneEngineValidatorBuilder>,
        Identity,
    >,
    /// Queue of L1 deposit messages to be included in the next zone block.
    deposit_queue: DepositQueue,
    /// Configuration for the L1 event subscriber
    l1_config: L1SubscriberConfig,
    /// Shared L1 state cache updated by the subscriber.
    l1_state_cache: L1StateCache,
    /// Shared registry of tokens enabled for this zone.
    enabled_tokens: EnabledTokenRegistry,
    /// L1 anchors independently observed and applied by the subscriber.
    l1_block_tracker: L1BlockTracker,
    /// Private encryption keys bound by finalized Portal rotation events.
    encryption_keys: Option<EncryptionKeyRing>,
    /// ZonePortal address on L1.
    portal_address: Address,
    /// Redacted RPC configuration.
    redacted_rpc_config: ZoneRedactedRpcConfig,
    /// Sequencer configuration.
    sequencer_config: Option<ZoneSequencerAddOnsConfig>,
    /// Remote provers routed by the live L1 hardfork.
    prover_config: Option<ProverAddresses>,
    /// Simplex participant configuration.
    p2p_config: Option<P2pConfig>,
    /// Whether a consumer outside this builder drains the deposit queue.
    external_deposit_consumer: bool,
}

impl<N> std::fmt::Debug for ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneAddOns").finish_non_exhaustive()
    }
}

impl<N> ZoneAddOns<NodeAdapter<N>>
where
    N: FullNodeTypes<Types = ZoneNode>,
{
    /// Creates a new ZoneAddOns instance.
    pub fn new(
        deposit_queue: DepositQueue,
        l1_config: L1SubscriberConfig,
        l1_state_cache: L1StateCache,
        enabled_tokens: EnabledTokenRegistry,
        l1_block_tracker: L1BlockTracker,
        encryption_keys: Option<EncryptionKeyRing>,
        portal_address: Address,
        redacted_rpc_config: ZoneRedactedRpcConfig,
        sequencer_config: Option<ZoneSequencerAddOnsConfig>,
        prover_config: Option<ProverAddresses>,
        p2p_config: Option<P2pConfig>,
        external_deposit_consumer: bool,
    ) -> Self {
        Self {
            inner: RpcAddOns::new(
                TempoEthApiBuilder::default(),
                ZoneEngineValidatorBuilder,
                NoopEngineApiBuilder::default(),
                BasicEngineValidatorBuilder::default(),
                Identity::default(),
                Default::default(),
            ),
            deposit_queue,
            l1_config,
            l1_state_cache,
            enabled_tokens,
            l1_block_tracker,
            encryption_keys,
            portal_address,
            redacted_rpc_config,
            sequencer_config,
            prover_config,
            p2p_config,
            external_deposit_consumer,
        }
    }
}

impl<N> NodeAddOns<N> for ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    type Handle = <RpcAddOns<
        N,
        TempoEthApiBuilder<N>,
        ZoneEngineValidatorBuilder,
        NoopEngineApiBuilder,
        BasicEngineValidatorBuilder<ZoneEngineValidatorBuilder>,
        Identity,
    > as NodeAddOns<N>>::Handle;

    async fn launch_add_ons(mut self, ctx: AddOnsContext<'_, N>) -> eyre::Result<Self::Handle> {
        eyre::ensure!(
            self.sequencer_config.is_some()
                || self.p2p_config.is_some()
                || self.external_deposit_consumer,
            "no Zone chain advancement mechanism configured: enable a sequencer, configure P2P, or register an external deposit consumer"
        );

        // Simplex nodes resume from the finalized block: their canonical head may be replaced.
        let checkpoint_block = self
            .p2p_config
            .is_some()
            .then(|| crate::simplex::checkpoint_block(ctx.node.provider()))
            .transpose()?;
        let tempo_block_number = match checkpoint_block {
            Some(block) => ctx
                .node
                .provider()
                .history_by_block_number(block)?
                .tempo_block_number()?,
            None => ctx.node.provider().latest()?.tempo_block_number()?,
        };
        let last_operational_tempo_block =
            latest_operational_tempo_block(ctx.node.provider(), checkpoint_block)?;
        if last_operational_tempo_block < tempo_block_number {
            self.l1_config.deferred_work_start =
                Some(last_operational_tempo_block.saturating_add(1));
        }
        if let Some(block) = checkpoint_block {
            let checkpoint = crate::simplex::seed_deposit_queue(
                ctx.node.provider(),
                &self.deposit_queue,
                block,
                self.l1_config.deferred_work_start.is_some(),
            )?;
            info!(target: "reth::cli", zone_block = block, ?checkpoint, "Resuming Simplex node from its finalized block");
            self.l1_config.checkpoint_zone_block = Some(block);
        }
        let l1_provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_with_config(
                &self.l1_config.l1_rpc_url,
                rpc_connection_config(self.l1_config.retry_connection_interval),
            )
            .await?
            .erased();
        let l1_chain_id = l1_provider.get_chain_id().await?;
        let chain_spec = ctx.node.provider().chain_spec();
        let chain_id = chain_spec.genesis().config.chain_id;
        let genesis_zone_id = chain_spec.zone_id();
        // The CLI rejects a zero portal address. Programmatic test/dev nodes use it as an
        // explicit sentinel because they have no on-chain portal to bind against.
        if self.portal_address.is_zero() {
            warn!(
                target: "reth::cli",
                "Skipping portal-bound zone identity validation for a zero-address test/dev portal"
            );
        } else {
            let portal_zone_id = ZonePortal::new(self.portal_address, &l1_provider)
                .zoneId()
                .call()
                .await
                .map_err(|err| {
                    eyre::eyre!(
                        "failed to read zone ID from portal {}: {err}",
                        self.portal_address
                    )
                })?;

            validate_configured_zone_id("genesis", genesis_zone_id, portal_zone_id)?;
            validate_configured_zone_id(
                "redacted RPC configuration",
                self.redacted_rpc_config.zone_id,
                portal_zone_id,
            )?;
            if let Some(config) = self.sequencer_config.as_ref() {
                validate_configured_zone_id(
                    "sequencer configuration",
                    config.zone_id,
                    portal_zone_id,
                )?;
            }
            if let Some(config) = self.p2p_config.as_ref() {
                validate_configured_zone_id("P2P configuration", config.zone_id(), portal_zone_id)?;
            }
            validate_zone_chain_id(l1_chain_id, portal_zone_id, chain_id)?;
        }

        self.resolve_and_seed_tokens(&l1_provider, tempo_block_number)
            .await?;
        if let Some(keys) = self.encryption_keys.clone() {
            self.resolve_and_seed_encryption_keys(&l1_provider, tempo_block_number, &keys)
                .await?;
        }

        let task_executor = ctx.node.task_executor().clone();
        if !self.portal_address.is_zero() {
            // Initialize the pause gate before block production starts, so a restart during a
            // pause does not produce blocks while ingestion catches up.
            initialize_portal_pause(&l1_provider, self.portal_address, &self.l1_block_tracker)
                .await;
            task_executor.spawn_critical_task(
                "portal-pause-watcher",
                watch_portal_pause(
                    l1_provider.clone(),
                    self.portal_address,
                    self.l1_block_tracker.clone(),
                ),
            );
        }

        let l1_subscriber = L1Subscriber::new(
            self.l1_config.clone(),
            ctx.node.provider().clone(),
            self.deposit_queue.clone(),
            self.enabled_tokens.clone(),
            self.l1_state_cache.clone(),
            self.l1_block_tracker.clone(),
            None,
            self.encryption_keys.clone(),
        );
        task_executor.spawn_critical_task("l1-block-subscriber", Box::pin(l1_subscriber.run()));
        info!(target: "reth::cli", "L1 subscriber started with deposit enqueueing");

        let chain_id = ctx.node.provider().chain_spec().genesis().config.chain_id;
        let max_response_size = ctx
            .config
            .rpc
            .rpc_max_response_size
            .get()
            .saturating_mul(1024 * 1024) as usize;
        let provider = ctx.node.provider().clone();
        let zone_provider = provider.clone();
        let pool = ctx.node.pool().clone();
        let engine_handle = ctx.beacon_engine_handle.clone();
        let payload_builder = ctx.node.payload_builder_handle().clone();
        let operator_rpc_provider = provider.clone();
        let operator_zone_api = OperatorZoneApi::new(
            self.redacted_rpc_config.zone_id,
            chain_id,
            self.portal_address,
            l1_provider.clone(),
            provider.clone(),
        );
        let debug_l1_provider = l1_provider.clone();
        let evm_chain_spec = ctx.node.evm_config().chain_spec().clone();
        let datadir = ctx.config.datadir().data_dir().to_path_buf();
        let handle = self
            .inner
            .launch_add_ons_with(ctx, move |container| {
                container.modules.add_or_replace_if_module_configured(
                    reth_rpc_builder::RethRpcModule::Web3,
                    OperatorWeb3Api.into_rpc(),
                )?;
                container
                    .modules
                    .merge_configured(operator_zone_api.into_rpc())?;
                container.modules.merge_configured(
                    NodeZoneDebugApi::new(container.registry.eth_api().clone(), debug_l1_provider)
                        .into_rpc(),
                )?;
                container
                    .modules
                    .merge_http(operator_zone_rpc_module(operator_rpc_provider)?)?;
                Ok(())
            })
            .await?;

        // One proof collector and prover per node.
        let mut proof_collector = None;
        let mut settlement_prover = None;
        if let Some(prover_addresses) = self.prover_config.as_ref() {
            let debug_api = Arc::new(NodeZoneDebugApi::new(
                handle.eth_handlers().api.clone(),
                l1_provider.clone(),
            ));
            let proof_collector_config = ProofCollectorConfig {
                directory: datadir.join("proofs"),
                debug_api: debug_api.clone(),
                portal_address: self.portal_address,
                l1_provider: l1_provider.clone(),
                retain_for_shadow_proving: false,
            };
            let (collector, collector_task) =
                create_proof_collector(proof_collector_config, provider.clone()).await?;
            task_executor.spawn_critical_task("zone-proof-collector", collector_task);

            let addresses = prover_addresses.clone();
            let chain_spec = evm_chain_spec.clone();
            task_executor.spawn_critical_task("prover-upgrade-readiness", async move {
                addresses.monitor_upgrade_readiness(chain_spec).await;
            });
            let spf_config = SettlementProverConfig {
                parent_chain_id: l1_chain_id,
                zone_id: genesis_zone_id,
                chain_spec: evm_chain_spec,
                debug_api,
                prover_addresses: Some(prover_addresses.clone()),
                proof_verifier: None,
            };
            // Repair a pre-existing canonical tail before admitting new blocks or starting
            // settlement.
            collector.collect_canonical_tail(&provider).await?;
            settlement_prover = Some(spawn_settlement_prover(
                spf_config,
                collector.clone(),
                provider.clone(),
                l1_provider.clone(),
            ));
            proof_collector = Some(collector);
        }

        Self::launch_redacted_rpc(
            self.redacted_rpc_config,
            &handle,
            self.l1_config.l1_rpc_url.clone(),
            self.l1_config.retry_connection_interval,
            self.l1_config.portal_address,
            self.enabled_tokens.clone(),
            chain_id,
            max_response_size,
        )
        .await?;

        if let Some(p2p) = self.p2p_config.take() {
            let sequencer = self
                .sequencer_config
                .take()
                .ok_or_else(|| eyre::eyre!("Simplex nodes require the shared sequencer key"))?;
            crate::simplex::validate_portal_sequencer_set(
                p2p.manifest(),
                self.portal_address,
                &l1_provider,
            )
            .await?;
            crate::simplex::launch(
                crate::simplex::Services {
                    p2p,
                    sequencer,
                    provider: provider.clone(),
                    pool,
                    engine: engine_handle,
                    payload_builder,
                    chain_spec: provider.chain_spec(),
                    deposit_queue: self.deposit_queue.clone(),
                    l1_block_tracker: self.l1_block_tracker.clone(),
                    encryption_keys: self.encryption_keys.clone().unwrap_or_default(),
                    portal_address: self.portal_address,
                    l1_chain_id,
                    l1_rpc_url: self.l1_config.l1_rpc_url.clone(),
                    retry_connection_interval: self.l1_config.retry_connection_interval,
                    proof_collector: proof_collector.clone(),
                    settlement_prover,
                },
                &datadir,
                &task_executor,
            )
            .await?;

            // Flush unpersisted blocks on shutdown.
            let engine_shutdown = handle.engine_shutdown.clone();
            task_executor.spawn_critical_with_graceful_shutdown_signal(
                "zone-engine-shutdown",
                |shutdown| async move {
                    let _guard = shutdown.await;
                    info!(target: "reth::cli", "Shutdown signal received — flushing engine state");
                    if let Some(done) = engine_shutdown.shutdown() {
                        let _ = done.await;
                    }
                },
            );
        } else if let Some(config) = self.sequencer_config.take() {
            let sequencer_addr = config.sequencer_signer.address();
            let last_header = provider
                .sealed_header(provider.best_block_number()?)?
                .ok_or_else(|| eyre::eyre!("no latest block header"))?;
            let engine = ZoneEngine::new(
                provider.chain_spec(),
                engine_handle,
                payload_builder,
                self.deposit_queue.clone(),
                self.l1_block_tracker.clone(),
                last_header,
                sequencer_addr,
                self.encryption_keys
                    .clone()
                    .expect("sequencer mode configures deposit decryption keys"),
                self.portal_address,
                proof_collector.clone(),
            );
            task_executor.spawn_critical_task("zone-engine", engine.run());

            Self::launch_sequencer_tasks(
                config,
                &handle,
                zone_provider,
                &task_executor,
                self.l1_config.l1_rpc_url,
                self.l1_config.portal_address,
                self.l1_config.retry_connection_interval,
                sequencer_addr,
                settlement_prover,
            )
            .await?;
        }

        Ok(handle)
    }
}

impl<N> ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    /// Seed the enabled-token registry from the zone's current L1 snapshot.
    async fn resolve_and_seed_tokens(
        &mut self,
        l1_provider: &alloy_provider::DynProvider<TempoNetwork>,
        block_number: u64,
    ) -> eyre::Result<()> {
        let portal = self.portal_address;
        let block_id = alloy_rpc_types_eth::BlockId::number(block_number);
        let portal_code = l1_provider
            .get_code_at(portal)
            .block_id(block_id)
            .await
            .map_err(|err| {
                eyre::eyre!(
                    "failed to check portal {portal} deployment at L1 block {block_number}: {err}"
                )
            })?;
        let enabled_tokens = if portal_code.is_empty() {
            info!(
                target: "reth::cli",
                %portal,
                block_number,
                "Portal is not deployed at the L1 anchor, starting with an empty enabled-token registry"
            );
            Vec::new()
        } else {
            ZonePortal::new(portal, l1_provider)
                .enabled_tokens_at(block_id)
                .await
                .map_err(|err| {
                    eyre::eyre!(
                        "failed to discover enabled tokens from portal {portal} at L1 block \
                         {block_number}: {err}"
                    )
                })?
        };
        info!(
            target: "reth::cli",
            count = enabled_tokens.len(),
            ?enabled_tokens,
            block_number,
            "Discovered enabled tokens from L1"
        );

        let mut registry = self.enabled_tokens.write();
        registry.clear();
        registry.extend(enabled_tokens);
        Ok(())
    }

    /// Bind configured private keys to the Portal key history at the persisted L1 anchor.
    async fn resolve_and_seed_encryption_keys(
        &mut self,
        l1_provider: &alloy_provider::DynProvider<TempoNetwork>,
        block_number: u64,
        keys: &EncryptionKeyRing,
    ) -> eyre::Result<()> {
        // Synthetic-L1 nodes use the zero address to mean that no Portal is configured.
        if self.portal_address.is_zero() {
            return Ok(());
        }

        let block_id = alloy_rpc_types_eth::BlockId::number(block_number);
        let portal_code = l1_provider
            .get_code_at(self.portal_address)
            .block_id(block_id)
            .await?;
        if portal_code.is_empty() {
            return Ok(());
        }

        let portal = ZonePortal::new(self.portal_address, l1_provider);
        let count = portal.encryptionKeyCount().block(block_id).call().await?;
        let count: u64 = count
            .try_into()
            .map_err(|_| eyre::eyre!("Portal encryption key count does not fit in u64"))?;

        for index in 0..count {
            let key_index = U256::from(index);
            let entry = portal
                .encryptionKeyAt(key_index)
                .block(block_id)
                .call()
                .await?;
            let rotation = EncryptionKeyRotation {
                x: entry.x,
                y_parity: entry.yParity,
                pubkey: encryption_key_address(entry.x, entry.yParity)?,
                key_index,
                activation_block: entry.activationBlock,
            };
            if keys.has_candidate(rotation.x, rotation.y_parity) {
                keys.apply_rotation(&rotation)?;
                continue;
            }

            let validity = portal
                .isEncryptionKeyValid(key_index)
                .block(block_id)
                .call()
                .await?;
            eyre::ensure!(
                !validity.valid
                // A key that has expired at the persisted checkpoint may still be needed by a deposit in the
                // deferred Portal-work range.
                    && self
                        .l1_config
                        .deferred_work_start.is_none_or(|from| validity.expiresAtBlock <= from),
                "missing private decryption key for Portal key index {key_index} required at L1 \
                 checkpoint {block_number} or by deferred work starting at {:?} (expires at L1 \
                 block {})",
                self.l1_config.deferred_work_start,
                validity.expiresAtBlock,
            );
        }

        Ok(())
    }

    /// Launch the redacted RPC server.
    async fn launch_redacted_rpc(
        config: ZoneRedactedRpcConfig,
        handle: &<Self as NodeAddOns<N>>::Handle,
        l1_rpc_url: String,
        retry_connection_interval: Duration,
        portal_address: Address,
        enabled_tokens: EnabledTokenRegistry,
        chain_id: u64,
        max_response_size: usize,
    ) -> eyre::Result<()> {
        let eth_handlers = handle.eth_handlers().clone();
        let l1_provider = alloy_provider::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_with_config(
                &l1_rpc_url,
                rpc_connection_config(retry_connection_interval),
            )
            .await?
            .erased();
        let redacted_rpc_config = zone_rpc::RedactedRpcConfig {
            listen_addr: ([0, 0, 0, 0], config.redacted_rpc_port).into(),
            zone_id: config.zone_id,
            chain_id,
            max_auth_token_validity: config.max_auth_token_validity,
            max_response_size,
            zone_portal: portal_address,
        };
        let api: Arc<dyn ZoneRpcApi> = Arc::new(ZoneRpc::new(
            eth_handlers,
            redacted_rpc_config.clone(),
            enabled_tokens,
            l1_provider,
        ));
        let local_addr = start_redacted_rpc(redacted_rpc_config, api).await?;
        info!(target: "reth::cli", %local_addr, "Redacted zone RPC server started");

        Ok(())
    }

    /// Launch sequencer background tasks: batch submission, withdrawal processing,
    /// and engine shutdown hook.
    async fn launch_sequencer_tasks(
        config: ZoneSequencerAddOnsConfig,
        handle: &<Self as NodeAddOns<N>>::Handle,
        zone_provider: N::Provider,
        task_executor: &reth_tasks::TaskExecutor,
        l1_rpc_url: String,
        portal_address: Address,
        retry_connection_interval: Duration,
        sequencer_addr: Address,
        settlement_prover: Option<SettlementProver>,
    ) -> eyre::Result<()> {
        info!(target: "reth::cli", %sequencer_addr, "Starting sequencer background tasks");
        let sequencer_config = ZoneSequencerConfig {
            chain_spec: zone_provider.chain_spec(),
            portal_address,
            l1_rpc_url,
            retry_connection_interval,
            zone_poll_interval: config.zone_poll_interval,
            withdrawal_poll_interval: config.withdrawal_poll_interval,
            withdrawal_batch_limits: config.withdrawal_batch_limits,
            outbox_address: ZONE_OUTBOX_ADDRESS,
            inbox_address: ZONE_INBOX_ADDRESS,
            batch_anchor_config: config.batch_anchor_config,
            settlement_duty: None,
        };
        let seq_handle = spawn_zone_sequencer(
            sequencer_config,
            config.sequencer_signer,
            zone_provider,
            settlement_prover,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
        info!(target: "reth::cli", "Sequencer tasks spawned");

        // Critical task — node shuts down if any sequencer child exits.
        task_executor.spawn_critical_task("zone-monitor", async move {
            tokio::select! {
                res = seq_handle.withdrawal_handle => {
                    tracing::error!(target: "reth::cli", ?res, "Withdrawal processor task exited");
                }
                res = seq_handle.monitor_handle => {
                    tracing::error!(target: "reth::cli", ?res, "Zone monitor task exited");
                }
            }
        });

        // Flush unpersisted blocks on shutdown.
        let engine_shutdown = handle.engine_shutdown.clone();
        task_executor.spawn_critical_with_graceful_shutdown_signal(
            "zone-engine-shutdown",
            |shutdown| async move {
                let _guard = shutdown.await;
                info!(target: "reth::cli", "Shutdown signal received — flushing engine state");
                if let Some(done) = engine_shutdown.shutdown() {
                    let _ = done.await;
                }
            },
        );

        Ok(())
    }
}

impl<N> RethRpcAddOns<N> for ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    type EthApi = <TempoEthApiBuilder<N> as EthApiBuilder<N>>::EthApi;

    fn hooks_mut(&mut self) -> &mut reth_node_builder::rpc::RpcHooks<N, Self::EthApi> {
        self.inner.hooks_mut()
    }
}

impl<N> EngineValidatorAddOn<N> for ZoneAddOns<N>
where
    N: FullNodeComponents<Types = ZoneNode, Evm = ZoneEvmConfig>,
    N::Pool: TempoTransactionPoolExt<Transaction = TempoPooledTransaction>,
{
    type ValidatorBuilder = BasicEngineValidatorBuilder<ZoneEngineValidatorBuilder>;

    fn engine_validator_builder(&self) -> Self::ValidatorBuilder {
        self.inner.engine_validator_builder()
    }
}

impl<N> Node<N> for ZoneNode
where
    N: FullNodeTypes<Types = Self>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        ZonePoolBuilder,
        BasicPayloadServiceBuilder<ZonePayloadFactory>,
        NoopNetworkBuilder<ZoneNetworkPrimitives>,
        ZoneExecutorBuilder,
        ZoneConsensusBuilder,
    >;
    type AddOns = ZoneAddOns<NodeAdapter<N>>;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        let executor_builder = ZoneExecutorBuilder::new(
            self.l1_state_provider_config.clone(),
            self.l1_state_cache.clone(),
            self.enabled_tokens.clone(),
        );
        let mut payload_factory = ZonePayloadFactory::new(self.withdrawal_batch_interval_blocks);
        if let Some(encryptor) = self.withdrawal_reveal_encryptor.clone() {
            payload_factory = payload_factory.with_withdrawal_reveal_encryptor(encryptor);
        }
        ComponentsBuilder::default()
            .node_types::<N>()
            .pool(ZonePoolBuilder::new(
                executor_builder.enabled_tokens.clone(),
            ))
            .executor(executor_builder)
            .payload(BasicPayloadServiceBuilder::new(payload_factory))
            .network(NoopNetworkBuilder::<ZoneNetworkPrimitives>::default())
            .consensus(ZoneConsensusBuilder::default())
    }

    fn add_ons(&self) -> Self::AddOns {
        ZoneAddOns::new(
            self.deposit_queue.clone(),
            self.l1_config.clone(),
            self.l1_state_cache.clone(),
            self.enabled_tokens.clone(),
            self.l1_block_tracker.clone(),
            self.encryption_keys.clone(),
            self.portal_address,
            self.redacted_rpc_config.clone(),
            self.sequencer_config.clone(),
            self.prover_config.clone(),
            self.p2p_config.clone(),
            self.external_deposit_consumer,
        )
    }
}

impl<N: FullNodeComponents<Types = Self>> DebugNode<N> for ZoneNode {
    type RpcBlock =
        alloy_rpc_types_eth::Block<alloy_rpc_types_eth::Transaction<TempoTxEnvelope>, TempoHeader>;

    fn rpc_to_primitive_block(rpc_block: Self::RpcBlock) -> primitives::Block {
        rpc_block
            .into_consensus_block()
            .map_transactions(|tx| tx.into_inner())
    }

    fn local_payload_attributes_builder(
        chain_spec: &Self::ChainSpec,
    ) -> impl PayloadAttributesBuilder<<Self::Payload as PayloadTypes>::PayloadAttributes, TempoHeader>
    {
        ZonePayloadAttributesBuilder::new(Arc::new(chain_spec.clone()))
    }
}

/// Builds [`ZonePayloadAttributes`] with `l1_block: None` — suitable for
/// debug/test scenarios where no L1 data is available.
#[derive(Debug)]
pub(crate) struct ZonePayloadAttributesBuilder;

impl ZonePayloadAttributesBuilder {
    pub(crate) fn new(_chain_spec: Arc<ZoneChainSpec>) -> Self {
        Self
    }
}

impl PayloadAttributesBuilder<ZonePayloadAttributes, TempoHeader> for ZonePayloadAttributesBuilder {
    fn build(&self, _parent: &SealedHeader<TempoHeader>) -> ZonePayloadAttributes {
        unimplemented!("zone blocks require L1 data — use ZoneEngine instead")
    }
}

/// Builder that constructs the [`ZoneEvmConfig`] used during block execution.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ZoneExecutorBuilder {
    l1_state_provider_config: L1StateProviderConfig,
    l1_state_cache: L1StateCache,
    enabled_tokens: EnabledTokenRegistry,
}

impl ZoneExecutorBuilder {
    /// Create a zone executor builder with the shared L1 state cache.
    pub fn new(
        l1_state_provider_config: L1StateProviderConfig,
        l1_state_cache: L1StateCache,
        enabled_tokens: EnabledTokenRegistry,
    ) -> Self {
        Self {
            l1_state_provider_config,
            l1_state_cache,
            enabled_tokens,
        }
    }
}

/// Builds Tempo consensus from the Zone chain spec with Tempo fork activations inherited from L1.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ZoneConsensusBuilder;

impl Default for ZoneConsensusBuilder {
    fn default() -> Self {
        Self
    }
}

impl<Node> ConsensusBuilder<Node> for ZoneConsensusBuilder
where
    Node: FullNodeTypes<Types = ZoneNode>,
{
    type Consensus = TempoConsensus<ZoneChainSpec>;

    async fn build_consensus(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::Consensus> {
        Ok(TempoConsensus::new(ctx.chain_spec()).with_allow_equal_timestamps(true))
    }
}

impl<Node> ExecutorBuilder<Node> for ZoneExecutorBuilder
where
    Node: FullNodeTypes<Types = ZoneNode>,
{
    type EVM = ZoneEvmConfig;

    async fn build_evm(self, ctx: &BuilderContext<Node>) -> eyre::Result<Self::EVM> {
        let runtime_handle = tokio::runtime::Handle::current();
        let portal_address = self.l1_state_provider_config.portal_address;
        let l1_provider = L1StateProvider::new(
            self.l1_state_provider_config.clone(),
            self.l1_state_cache,
            runtime_handle.clone(),
        )
        .await?;

        let l1_chain_id = l1_provider.chain_id().await?;
        let genesis_l1_chain_id = decode_l1_chain_id(ctx.chain_spec().genesis().config.chain_id)?;
        eyre::ensure!(
            l1_chain_id == genesis_l1_chain_id,
            "L1 chain ID mismatch: genesis requires {genesis_l1_chain_id}, but L1 RPC reports {l1_chain_id}"
        );
        let evm_config = ZoneEvmConfig::new(ctx.chain_spec(), l1_provider, portal_address);
        info!(target: "reth::cli", "Zone EVM initialized with L1-backed Tempo precompiles");

        Ok(evm_config)
    }
}

/// Engine validator builder for Zone.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ZoneEngineValidatorBuilder;

impl<Node> PayloadValidatorBuilder<Node> for ZoneEngineValidatorBuilder
where
    Node: FullNodeComponents<Types = ZoneNode>,
{
    type Validator = TempoEngineValidator;

    async fn build(self, _ctx: &AddOnsContext<'_, Node>) -> eyre::Result<Self::Validator> {
        Ok(TempoEngineValidator::new())
    }
}

/// Transaction pool builder for Zone - uses Tempo pool with defaults.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ZonePoolBuilder {
    enabled_tokens: EnabledTokenRegistry,
}

impl ZonePoolBuilder {
    /// Create a pool builder using the shared enabled-token registry.
    pub fn new(enabled_tokens: EnabledTokenRegistry) -> Self {
        Self { enabled_tokens }
    }
}

fn validate_has_enabled_token_balance(
    provider: &impl StateProviderFactory,
    enabled_tokens: &EnabledTokenRegistry,
    sender: Address,
) -> Result<(), InvalidPoolTransactionError> {
    let state = provider.latest().map_err(|err| {
        warn!(%err, "Failed to read latest state for zone token-balance admission check");
        InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(
            TempoInvalidTransaction::EthInvalidTransaction(
                "could not verify balance of an enabled zone token".into(),
            ),
        ))
    })?;

    for token in enabled_tokens.read().iter().copied() {
        let slot = TIP20Token::from_address_unchecked(token).balances[sender].slot();
        let balance = state.storage(token, slot.into()).map_err(|err| {
            warn!(%err, %sender, "Failed to read zone token balance during pool admission");
            InvalidPoolTransactionError::other(TempoPoolTransactionError::Evm(
                TempoInvalidTransaction::EthInvalidTransaction(
                    "could not verify balance of an enabled zone token".into(),
                ),
            ))
        })?;
        if balance.is_some_and(|balance| !balance.is_zero()) {
            return Ok(());
        }
    }

    Err(InvalidPoolTransactionError::other(
        TempoPoolTransactionError::Evm(TempoInvalidTransaction::EthInvalidTransaction(
            "sender must hold a nonzero balance of an enabled zone token".into(),
        )),
    ))
}

impl<Node> PoolBuilder<Node, ZoneEvmConfig> for ZonePoolBuilder
where
    Node: FullNodeTypes<Types = ZoneNode>,
{
    type Pool = TempoTransactionPool<Node::Provider, ZoneEvmConfig>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: ZoneEvmConfig,
    ) -> eyre::Result<Self::Pool> {
        // Zone blocks have no protocol base fee, so allow zero-fee transactions into the pool.
        let mut pool_config = ctx.pool_config().with_disabled_protocol_base_fee();
        pool_config.max_inflight_delegated_slot_limit = pool_config.max_account_slots;

        // this store is effectively a noop
        let blob_store = InMemoryBlobStore::default();
        let additional_tasks = ctx.config().txpool.additional_validation_tasks;
        let task_executor = ctx.task_executor().clone();
        let mut validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .set_block_gas_limit(ctx.chain_spec().genesis().gas_limit)
                .disable_balance_check()
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .with_custom_tx_type(TempoTxType::AA as u8)
                .no_eip4844()
                .build::<TempoPooledTransaction, _>(blob_store.clone());

        let provider = ctx.provider().clone();
        let enabled_tokens = self.enabled_tokens;
        validator.set_additional_stateful_validation(move |_origin, tx, _account_state| {
            validate_has_enabled_token_balance(&provider, &enabled_tokens, *tx.sender_ref())
        });

        let validator =
            TransactionValidationTaskExecutor::spawn(validator, &task_executor, additional_tasks);

        let aa_2d_config = AA2dPoolConfig {
            price_bump_config: pool_config.price_bumps,
            pending_limit: pool_config.pending_limit,
            queued_limit: pool_config.queued_limit,
            max_txs_per_sender: pool_config.max_account_slots,
            ..Default::default()
        };
        let aa_2d_pool = AA2dPool::new(aa_2d_config);
        let amm_liquidity_cache = AmmLiquidityCache::new(ctx.provider())?;

        let validator = validator.map(|v| {
            TempoTransactionValidator::new(
                v,
                DEFAULT_AA_VALID_AFTER_MAX_SECS,
                DEFAULT_MAX_TEMPO_AUTHORIZATIONS,
                amm_liquidity_cache.clone(),
            )
            .with_minimum_fee_cap(0)
            // Zones collect the selected fee token directly and never route through FeeAMM.
            .with_disable_fee_amm_check(true)
        });
        let protocol_pool = Pool::new(
            validator,
            TempoTipOrdering::default(),
            blob_store,
            pool_config.clone(),
        );

        let transaction_pool = TempoTransactionPool::new(protocol_pool, aa_2d_pool);

        spawn_maintenance_tasks(ctx, transaction_pool.clone(), &pool_config)?;

        // Spawn unified Tempo pool maintenance task
        // This consolidates: expired AA txs, 2D nonce updates, AMM cache, and keychain revocations
        ctx.task_executor().spawn_critical_task(
            "txpool maintenance - tempo pool",
            tempo_transaction_pool::maintain::maintain_tempo_pool(transaction_pool.clone()),
        );

        info!(target: "reth::cli", "Transaction pool initialized");
        debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}

/// Returns the latest Tempo block whose portal work was processed by a full `advanceTempo` import.
///
/// Checkpoint-only `advanceTempoHeaders` imports move the Zone's Tempo checkpoint without consuming
/// their deposits, withdrawals, token updates, key rotations, or leader transitions. On restart,
/// the caller uses the block after this operational boundary as the beginning of the deferred-work
/// recovery range. If no operational import exists after genesis, the genesis Tempo anchor is the
/// boundary. The scan starts at `through`, or at the canonical head when `None`.
fn latest_operational_tempo_block<P>(provider: &P, through: Option<u64>) -> eyre::Result<u64>
where
    P: ReceiptProvider + StateProviderFactory,
{
    let best = match through {
        Some(through) => through,
        None => provider.best_block_number()?,
    };
    for number in (1..=best).rev() {
        let Some(receipts) = provider.receipts_by_block(BlockHashOrNumber::Number(number))? else {
            continue;
        };
        for receipt in receipts {
            for log in receipt.logs() {
                if log.address != ZONE_INBOX_ADDRESS {
                    continue;
                }
                match log.topics().first() {
                    Some(topic) if topic == &TempoAdvanced::SIGNATURE_HASH => {
                        return Ok(TempoAdvanced::decode_log(log)?.tempoBlockNumber);
                    }
                    Some(topic) if topic == &LegacyTempoAdvanced::SIGNATURE_HASH => {
                        return Ok(LegacyTempoAdvanced::decode_log(log)?.tempoBlockNumber);
                    }
                    _ => {}
                }
            }
        }
    }

    let genesis_hash = provider
        .block_hash(0)?
        .ok_or_else(|| eyre::eyre!("zone genesis block hash is unavailable"))?;
    Ok(provider
        .state_by_block_hash(genesis_hash)?
        .tempo_num_hash()?
        .number)
}

#[cfg(test)]
mod tests {

    use super::*;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Bytes, Signature, TxKind, U256};
    use reth_chainspec::EthChainSpec;
    use reth_primitives_traits::Recovered;
    use tempo_primitives::transaction::{Call, TempoTransaction};
    use zone_chainspec::tempo_chain_spec_for_l1;

    fn pooled_transaction(envelope: TempoTxEnvelope, sender: Address) -> TempoPooledTransaction {
        TempoPooledTransaction::new(Recovered::new_unchecked(envelope, sender))
    }

    fn aa_transaction(sender: Address, calls: Vec<Call>) -> TempoPooledTransaction {
        let transaction = TempoTransaction {
            calls,
            ..Default::default()
        };
        pooled_transaction(
            transaction
                .into_signed(Signature::test_signature().into())
                .into(),
            sender,
        )
    }

    #[test]
    fn resolves_public_and_local_tempo_l1_specs() {
        assert_eq!(tempo_chain_spec_for_l1(4217).unwrap().chain_id(), 4217);
        assert_eq!(tempo_chain_spec_for_l1(42431).unwrap().chain_id(), 42431);
        assert_eq!(tempo_chain_spec_for_l1(1337).unwrap().chain_id(), 1337);
        assert_eq!(tempo_chain_spec_for_l1(31337).unwrap().chain_id(), 1337);
        assert!(tempo_chain_spec_for_l1(999_999).is_none());

        assert!(tempo_chain_spec_for_l1(31318).is_none());
        assert!(tempo_chain_spec_for_l1(31319).is_none());
    }

    #[test]
    fn validates_genesis_chain_id_against_parent_and_zone() {
        let expected = zone_chain_id(42_431, 7).unwrap();
        assert!(validate_zone_chain_id(42_431, 7, expected).is_ok());
        assert!(validate_zone_chain_id(4_217, 7, expected).is_err());
        assert!(validate_zone_chain_id(42_431, 7, expected + 1).is_err());
        assert!(validate_zone_chain_id(42_431, 0, 123).is_err());
    }

    #[test]
    fn requires_every_configured_zone_id_to_match_the_portal() {
        assert!(validate_configured_zone_id("test", 7, 7).is_ok());
        assert!(validate_configured_zone_id("test", 0, 7).is_err());
        assert!(validate_configured_zone_id("test", 8, 7).is_err());
    }

    #[test]
    fn pool_policy_allows_allowlisted_plain_create() {
        let sender = Address::repeat_byte(0x11);
        let envelope = TempoTxEnvelope::Eip1559(Signed::new_unhashed(
            TxEip1559 {
                to: TxKind::Create,
                ..Default::default()
            },
            Signature::test_signature(),
        ));
        let transaction = pooled_transaction(envelope, sender);

        let err = zone_evm::validate_transaction(transaction.tx_env(), &[]).unwrap_err();
        assert!(matches!(
            err,
            tempo_revm::TempoInvalidTransaction::CallsValidation(_)
        ));
        assert!(zone_evm::validate_transaction(transaction.tx_env(), &[sender]).is_ok());
    }

    #[test]
    fn pool_policy_rejects_create_in_non_first_aa_call() {
        let transaction = aa_transaction(
            Address::repeat_byte(0x11),
            vec![
                Call {
                    to: TxKind::Call(Address::repeat_byte(0x22)),
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
                Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Bytes::new(),
                },
            ],
        );

        assert!(zone_evm::validate_transaction(transaction.tx_env(), &[]).is_err());
    }
}
