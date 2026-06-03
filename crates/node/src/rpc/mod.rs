pub mod admin;
pub mod consensus;
pub mod error;
pub mod eth_ext;
pub mod fork_schedule;
pub mod operator;
pub mod simulate;
pub mod token;

pub use admin::{TempoAdminApi, TempoAdminApiServer};
use alloy_primitives::{Address, B256};
use alloy_rpc_types_eth::{Log, ReceiptWithBloom};
pub use consensus::{TempoConsensusApiServer, TempoConsensusRpc};
pub use eth_ext::{TempoEthExt, TempoEthExtApiServer};
pub use fork_schedule::{TempoForkScheduleApiServer, TempoForkScheduleRpc};
use futures::{TryFutureExt, future::Either};
pub use operator::{TempoOperatorApiServer, TempoOperatorRpc};
use reth_errors::RethError;
use reth_primitives_traits::{
    AlloyBlockHeader as _, HeaderTy, NodePrimitives, Recovered, TransactionMeta, TxTy, WithEncoded,
};
use reth_rpc_eth_api::{FromEthApiError, IntoEthApiError, RpcTxReq};
use reth_transaction_pool::{PoolTransaction, PoolTx, TransactionOrigin, TransactionPool};
pub use simulate::{TempoSimulate, TempoSimulateApiServer, TempoSimulateV1Response};
use std::{marker::PhantomData, sync::Arc};
pub use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::TempoStateAccess;
use tempo_precompiles::{
    NATIVE_MULTISIG_ADDRESS, NONCE_PRECOMPILE_ADDRESS,
    native_multisig::NativeMultisig,
    nonce::NonceManager,
    storage::{StorageActions, packing::extract_from_word},
};
use tempo_primitives::transaction::{MAX_MULTISIG_OWNERS, TEMPO_EXPIRING_NONCE_KEY};
pub use token::{TempoToken, TempoTokenApiServer};

use crate::rpc::error::TempoEthApiError;
use alloy::primitives::{U256, uint};
use alloy_eips::{BlockId, eip2718::Encodable2718};
use alloy_evm::{EvmFactory, block::BlockExecutorFactory};
use alloy_network::{TransactionBuilder, TransactionBuilder4844};
use alloy_rpc_types_eth::state::EvmOverrides;
use reth_chainspec::{EthereumHardforks, Hardforks};
use reth_ethereum::{
    evm::revm::database::StateProviderDatabase,
    tasks::{
        Runtime,
        pool::{BlockingTaskGuard, BlockingTaskPool},
    },
};
use reth_evm::{
    ConfigureEvm, EvmEnvFor, TxEnvFor,
    revm::{Database, context::result::EVMError, database_interface::bal::EvmDatabaseError},
};
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeTypes};
use reth_node_builder::rpc::{EthApiBuilder, EthApiCtx};
use reth_provider::{ChainSpecProvider, ProviderError};
use reth_rpc::{DynRpcConverter, eth::EthApi};
use reth_rpc_eth_api::{
    EthApiTypes, RpcConvert, RpcConverter, RpcNodeCore, RpcNodeCoreExt,
    helpers::{
        Call, EthApiSpec, EthBlocks, EthCall, EthFees, EthState, EthTransactions, LoadBlock,
        LoadFee, LoadPendingBlock, LoadReceipt, LoadState, LoadTransaction, SpawnBlocking, Trace,
        bal::GetBlockAccessList,
        estimate::EstimateCall,
        pending_block::{BuildPendingEnv, PendingEnvBuilder},
        spec::SignersForRpc,
    },
    transaction::{ConvertReceiptInput, ReceiptConverter},
};
use reth_rpc_eth_types::{
    EthApiError, EthStateCache, FeeHistoryCache, FillTransaction, GasPriceOracle, PendingBlock,
    SignError, builder::config::PendingBlockKind, receipt::EthReceiptConverter,
};
use reth_storage_api::BlockReaderIdExt;
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionReceipt};
use tempo_evm::{TempoBlockEnv, TempoHaltReason, TempoInvalidTransaction};
use tempo_primitives::{
    TEMPO_GAS_PRICE_SCALING_FACTOR, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
    subblock::PartialValidatorKey,
};
use tempo_revm::TempoTxEnv;
use tokio::sync::{Mutex, broadcast};

/// Placeholder constant for `eth_getBalance` calls because the native token balance is N/A on
/// Tempo.
pub const NATIVE_BALANCE_PLACEHOLDER: U256 =
    uint!(4242424242424242424242424242424242424242424242424242424242424242424242424242_U256);

/// Capacity of the subblock transactions broadcast channel.
///
/// This is set high enough to prevent legitimate transactions from being evicted
/// during high-load scenarios. Transactions are filtered by validator key before
/// being added to the channel to prevent DoS attacks.
pub const SUBBLOCK_TX_CHANNEL_CAPACITY: usize = 10_000;

/// Helper trait that groups the component bounds required by [`TempoEthApi`].
///
/// This trait has no methods. It exists so the generic Tempo RPC implementation
/// and builder can name the required Tempo primitives, pooled transaction type,
/// and EVM configuration in one place.
pub trait TempoEthApiBounds:
    RpcNodeCore<
        Primitives = TempoPrimitives,
        Pool: TransactionPool<Transaction: PoolTransaction<Pooled = TempoTxEnvelope>>,
        Evm: ConfigureEvm<
            Primitives = TempoPrimitives,
            BlockExecutorFactory: BlockExecutorFactory<
                EvmFactory: EvmFactory<
                    Tx = TempoTxEnv,
                    Spec = TempoHardfork,
                    BlockEnv = TempoBlockEnv,
                    HaltReason = TempoHaltReason,
                    Error<EvmDatabaseError<ProviderError>> = EVMError<
                        EvmDatabaseError<ProviderError>,
                        TempoInvalidTransaction,
                    >,
                >,
            >,
        >,
    >
{
}

impl<N> TempoEthApiBounds for N where
    N: RpcNodeCore<
            Primitives = TempoPrimitives,
            Pool: TransactionPool<Transaction: PoolTransaction<Pooled = TempoTxEnvelope>>,
            Evm: ConfigureEvm<
                Primitives = TempoPrimitives,
                BlockExecutorFactory: BlockExecutorFactory<
                    EvmFactory: EvmFactory<
                        Tx = TempoTxEnv,
                        Spec = TempoHardfork,
                        BlockEnv = TempoBlockEnv,
                        HaltReason = TempoHaltReason,
                        Error<EvmDatabaseError<ProviderError>> = EVMError<
                            EvmDatabaseError<ProviderError>,
                            TempoInvalidTransaction,
                        >,
                    >,
                >,
            >,
        >
{
}

/// Generic Tempo `Eth` API implementation.
///
/// This type provides the functionality for handling `eth_` related requests.
///
/// This wraps a default `Eth` implementation, and provides additional functionality where the
/// Tempo spec deviates from the default ethereum spec, e.g. gas estimation denominated in
/// `feeToken`
///
/// This type implements the [`FullEthApi`](reth_rpc_eth_api::helpers::FullEthApi) by implemented
/// all the `Eth` helper traits and prerequisite traits.
#[derive(Debug, Clone)]
pub struct TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    /// Gateway to node's core components.
    inner: EthApi<N, DynRpcConverter<N::Evm, TempoNetwork>>,

    /// Channel for sending subblock transactions to the subblocks service.
    subblock_transactions_tx: broadcast::Sender<Recovered<TempoTxEnvelope>>,

    /// Validator public key used to filter subblock transactions.
    ///
    /// Only subblock transactions targeting this validator will be accepted.
    /// This prevents DoS attacks via channel flooding with transactions
    /// targeting other validators.
    validator_key: Option<B256>,
}

impl<N> TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    /// Creates a new `TempoEthApi`.
    pub fn new(
        eth_api: EthApi<N, DynRpcConverter<N::Evm, TempoNetwork>>,
        validator_key: Option<B256>,
    ) -> Self {
        Self {
            inner: eth_api,
            subblock_transactions_tx: broadcast::channel(SUBBLOCK_TX_CHANNEL_CAPACITY).0,
            validator_key,
        }
    }

    /// Returns a [`broadcast::Receiver`] for subblock transactions.
    pub fn subblock_transactions_rx(&self) -> broadcast::Receiver<Recovered<TempoTxEnvelope>> {
        self.subblock_transactions_tx.subscribe()
    }

    /// Returns `true` if the given partial validator key matches this node's validator key.
    ///
    /// Returns `false` if no validator key is configured (non-validator nodes reject
    /// all subblock transactions).
    fn matches_validator_key(&self, partial_key: &PartialValidatorKey) -> bool {
        self.validator_key
            .is_some_and(|key| partial_key.matches(key.as_slice()))
    }
}

impl<N> EthApiTypes for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    type Error = TempoEthApiError;
    type NetworkTypes = TempoNetwork;
    type RpcConvert = DynRpcConverter<N::Evm, TempoNetwork>;

    fn converter(&self) -> &Self::RpcConvert {
        self.inner.converter()
    }
}

impl<N> RpcNodeCore for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    type Primitives = N::Primitives;
    type Provider = N::Provider;
    type Pool = N::Pool;
    type Evm = N::Evm;
    type Network = N::Network;

    #[inline]
    fn pool(&self) -> &Self::Pool {
        self.inner.pool()
    }

    #[inline]
    fn evm_config(&self) -> &Self::Evm {
        self.inner.evm_config()
    }

    #[inline]
    fn network(&self) -> &Self::Network {
        self.inner.network()
    }

    #[inline]
    fn provider(&self) -> &Self::Provider {
        self.inner.provider()
    }
}

impl<N> RpcNodeCoreExt for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn cache(&self) -> &EthStateCache<N::Primitives> {
        self.inner.cache()
    }
}

impl<N> EthApiSpec for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn starting_block(&self) -> U256 {
        self.inner.starting_block()
    }
}

impl<N> SpawnBlocking for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn io_task_spawner(&self) -> &Runtime {
        self.inner.task_spawner()
    }

    #[inline]
    fn tracing_task_pool(&self) -> &BlockingTaskPool {
        self.inner.blocking_task_pool()
    }

    #[inline]
    fn tracing_task_guard(&self) -> &BlockingTaskGuard {
        self.inner.blocking_task_guard()
    }

    #[inline]
    fn blocking_io_task_guard(&self) -> &Arc<tokio::sync::Semaphore> {
        self.inner.blocking_io_task_guard()
    }
}

impl<N> LoadPendingBlock for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn pending_block(&self) -> &Mutex<Option<PendingBlock<Self::Primitives>>> {
        self.inner.pending_block()
    }

    #[inline]
    fn pending_env_builder(&self) -> &dyn PendingEnvBuilder<Self::Evm> {
        self.inner.pending_env_builder()
    }

    #[inline]
    fn pending_block_kind(&self) -> PendingBlockKind {
        // Don't build a local pending block because the Tempo node can't build
        // one without consensus data (system transaction).
        PendingBlockKind::None
    }
}

impl<N> LoadFee for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn gas_oracle(&self) -> &GasPriceOracle<Self::Provider> {
        self.inner.gas_oracle()
    }

    #[inline]
    fn fee_history_cache(&self) -> &FeeHistoryCache<HeaderTy<N::Primitives>> {
        self.inner.fee_history_cache()
    }
}

impl<N> LoadState for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    async fn next_available_nonce_for(
        &self,
        request: &RpcTxReq<Self::NetworkTypes>,
    ) -> Result<u64, Self::Error> {
        if let Some(nonce_key) = request.nonce_key
            && !nonce_key.is_zero()
        {
            let nonce = if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                0 // expiring nonce must be 0
            } else {
                // 2D nonce: fetch from storage
                let from = if let Some(from) = request.from {
                    from
                } else {
                    return Err(SignError::NoAccount.into_eth_err());
                };
                let slot = NonceManager::new().nonces[from][nonce_key].slot();
                self.spawn_blocking_io(move |this| {
                    this.latest_state()?
                        .storage(NONCE_PRECOMPILE_ADDRESS, slot.into())
                        .map_err(Self::Error::from_eth_err)
                })
                .await?
                .unwrap_or_default()
                .saturating_to()
            };

            Ok(nonce)
        } else {
            Ok(self.inner.next_available_nonce_for(request).await?)
        }
    }
}

impl<N> EthState for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    async fn balance(
        &self,
        _address: alloy_primitives::Address,
        _block_id: Option<alloy_eips::BlockId>,
    ) -> Result<U256, Self::Error> {
        Ok(NATIVE_BALANCE_PLACEHOLDER)
    }

    #[inline]
    fn max_proof_window(&self) -> u64 {
        self.inner.eth_proof_window()
    }
}

fn populate_native_multisig_simulation_hints(
    request: &mut TempoTransactionRequest,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<(), EthApiError> {
    if request.multisig_init.is_some()
        || (request.multisig_config_id.is_some() && request.multisig_signature_count.is_some())
    {
        return Ok(());
    }

    let Some(from) = request.from else {
        return Ok(());
    };

    let Some((config_id, signature_count)) = load_native_multisig_simulation_hints(
        from,
        request.multisig_config_id,
        request.multisig_signature_count,
        db,
    )?
    else {
        return Ok(());
    };

    request.multisig_config_id.get_or_insert(config_id);
    request
        .multisig_signature_count
        .get_or_insert(signature_count);

    Ok(())
}

fn load_native_multisig_simulation_hints(
    from: Address,
    multisig_config_id: Option<B256>,
    multisig_signature_count: Option<usize>,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<Option<(B256, usize)>, EthApiError> {
    let config_id_slot = NativeMultisig::config_id_storage_slot(from);
    let config_id_word = db
        .storage(NATIVE_MULTISIG_ADDRESS, config_id_slot)
        .map_err(Into::into)?;
    if config_id_word.is_zero() {
        return Ok(None);
    }

    let config_id = if let Some(config_id) = multisig_config_id {
        config_id
    } else {
        let config_id = B256::from(config_id_word.to_be_bytes::<32>());
        if config_id.is_zero() {
            return Err(EthApiError::InvalidParams(
                "native multisig account is missing config_id".to_string(),
            ));
        }
        config_id
    };

    let signature_count = match multisig_signature_count {
        Some(signature_count) => signature_count,
        None => native_multisig_signature_count_for_threshold(from, config_id, db)?,
    };

    Ok(Some((config_id, signature_count)))
}

fn native_multisig_signature_count_for_threshold(
    account: Address,
    config_id: B256,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<usize, EthApiError> {
    let (threshold_slot, threshold_offset) =
        NativeMultisig::config_threshold_storage_slot(account, config_id);
    let threshold = read_native_multisig_u32(db, threshold_slot, threshold_offset)?;
    if threshold == 0 {
        return Err(EthApiError::InvalidParams(
            "native multisig config has zero threshold".to_string(),
        ));
    }

    let (owners_len_slot, owners_len_offset) =
        NativeMultisig::config_owners_len_storage_slot(account, config_id);
    let owner_count = read_native_multisig_u32(db, owners_len_slot, owners_len_offset)? as usize;
    if owner_count == 0 {
        return Err(EthApiError::InvalidParams(
            "native multisig config has no owners".to_string(),
        ));
    }
    if owner_count > MAX_MULTISIG_OWNERS {
        return Err(EthApiError::InvalidParams(
            "native multisig config has too many owners".to_string(),
        ));
    }

    let mut signed_weight = 0u64;
    for index in 0..owner_count {
        let (weight_slot, weight_offset) =
            NativeMultisig::config_owner_weight_storage_slot(account, config_id, index);
        let weight = read_native_multisig_u32(db, weight_slot, weight_offset)?;
        signed_weight = signed_weight
            .checked_add(u64::from(weight))
            .ok_or_else(|| {
                EthApiError::InvalidParams("native multisig owner weight overflow".to_string())
            })?;
        if signed_weight >= u64::from(threshold) {
            return Ok(index + 1);
        }
    }

    Err(EthApiError::InvalidParams(
        "native multisig signature weight below threshold".to_string(),
    ))
}

fn read_native_multisig_u32(
    db: &mut impl Database<Error: Into<EthApiError>>,
    slot: U256,
    offset: Option<usize>,
) -> Result<u32, EthApiError> {
    let word = db
        .storage(NATIVE_MULTISIG_ADDRESS, slot)
        .map_err(Into::into)?;
    extract_from_word::<u32>(word, offset.unwrap_or_default(), 4)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))
}

impl<N> EthFees for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> Trace for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> EthCall for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> GetBlockAccessList for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> Call for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    #[inline]
    fn compute_state_root_for_eth_simulate(&self) -> bool {
        self.inner.compute_state_root_for_eth_simulate()
    }

    #[inline]
    fn evm_memory_limit(&self) -> u64 {
        self.inner.evm_memory_limit()
    }

    /// Returns the max gas limit that the caller can afford given a transaction environment.
    fn caller_gas_allowance(
        &self,
        mut db: impl Database<Error: Into<EthApiError>>,
        evm_env: &EvmEnvFor<Self::Evm>,
        tx_env: &TxEnvFor<Self::Evm>,
    ) -> Result<u64, Self::Error> {
        let fee_payer = tx_env
            .fee_payer()
            .map_err(EVMError::<ProviderError, _>::from)?;

        let fee_token = db
            .get_fee_token(
                tx_env,
                fee_payer,
                evm_env.cfg_env.spec,
                StorageActions::disabled(),
            )
            .map_err(ProviderError::other)?;
        let fee_token_balance = db
            .get_token_balance(
                fee_token,
                fee_payer,
                evm_env.cfg_env.spec,
                StorageActions::disabled(),
            )
            .map_err(ProviderError::other)?;

        Ok(fee_token_balance
            // multiply by the scaling factor
            .saturating_mul(TEMPO_GAS_PRICE_SCALING_FACTOR)
            // Calculate the amount of gas the caller can afford with the specified gas price.
            .checked_div(U256::from(tx_env.inner.gas_price))
            // This will be 0 if gas price is 0. It is fine, because we check it before.
            .unwrap_or_default()
            .saturating_to())
    }

    fn create_txn_env(
        &self,
        evm_env: &EvmEnvFor<Self::Evm>,
        mut request: TempoTransactionRequest,
        mut db: impl Database<Error: Into<EthApiError>>,
    ) -> Result<TxEnvFor<Self::Evm>, Self::Error> {
        populate_native_multisig_simulation_hints(&mut request, &mut db)
            .map_err(Self::Error::from_eth_err)?;

        if let Some(nonce_key) = request.nonce_key
            && !nonce_key.is_zero()
            && request.nonce.is_none()
        {
            let nonce = if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
                0 // expiring nonce must be 0
            } else {
                // 2D nonce: fetch from storage
                let slot =
                    NonceManager::new().nonces[request.from.unwrap_or_default()][nonce_key].slot();
                db.storage(NONCE_PRECOMPILE_ADDRESS, slot)
                    .map_err(Into::into)?
                    .saturating_to()
            };
            request.nonce = Some(nonce);
        }

        Ok(self.inner.create_txn_env(evm_env, request, db)?)
    }
}

impl<N> EstimateCall for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadBlock for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadReceipt for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> EthBlocks for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadTransaction for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> EthTransactions for TempoEthApi<N>
where
    N: TempoEthApiBounds,
    <Self as RpcNodeCore>::Primitives: NodePrimitives<SignedTx = TempoTxEnvelope>,
{
    #[allow(clippy::manual_async_fn)]
    fn fill_transaction(
        &self,
        mut request: RpcTxReq<Self::NetworkTypes>,
    ) -> impl Future<Output = Result<FillTransaction<TxTy<Self::Primitives>>, Self::Error>> + Send
    where
        Self: EthApiSpec + LoadBlock + EstimateCall + LoadFee,
    {
        async move {
            if request.as_ref().value().is_none() {
                request.as_mut().set_value(U256::ZERO);
            }

            if request.as_ref().nonce().is_none() {
                let nonce = self.next_available_nonce_for(&request).await?;
                request.as_mut().set_nonce(nonce);
            }

            let chain_id = self.chain_id();
            request.as_mut().set_chain_id(chain_id.to());

            if let Some(from) = request.as_ref().from {
                let mut value = serde_json::to_value(&request).map_err(|err| {
                    Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                })?;
                let (needs_hints, config_id_hint, signature_count_hint) = {
                    let object = value.as_object().ok_or_else(|| {
                        Self::Error::from_eth_err(EthApiError::InvalidParams(
                            "transaction request must serialize as an object".to_string(),
                        ))
                    })?;
                    let has_init = object.contains_key("multisigInit");
                    let has_config_id = object.contains_key("multisigConfigId");
                    let has_signature_count = object.contains_key("multisigSignatureCount");
                    let config_id_hint = object
                        .get("multisigConfigId")
                        .map(|value| serde_json::from_value(value.clone()))
                        .transpose()
                        .map_err(|err| {
                            Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                        })?;
                    let signature_count_hint = object
                        .get("multisigSignatureCount")
                        .map(|value| serde_json::from_value(value.clone()))
                        .transpose()
                        .map_err(|err| {
                            Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                        })?;
                    (
                        !(has_init || has_config_id && has_signature_count),
                        config_id_hint,
                        signature_count_hint,
                    )
                };

                if needs_hints {
                    let hints = self
                        .spawn_blocking_io(move |this| {
                            let state = this.latest_state()?;
                            let mut db = StateProviderDatabase::new(state);
                            load_native_multisig_simulation_hints(
                                from,
                                config_id_hint,
                                signature_count_hint,
                                &mut db,
                            )
                            .map_err(Self::Error::from_eth_err)
                        })
                        .await?;

                    if let Some((config_id, signature_count)) = hints {
                        let object = value.as_object_mut().expect("checked as object above");
                        object.entry("multisigConfigId".to_string()).or_insert(
                            serde_json::to_value(config_id).map_err(|err| {
                                Self::Error::from_eth_err(EthApiError::InvalidParams(
                                    err.to_string(),
                                ))
                            })?,
                        );
                        object
                            .entry("multisigSignatureCount".to_string())
                            .or_insert(serde_json::to_value(signature_count).map_err(|err| {
                                Self::Error::from_eth_err(EthApiError::InvalidParams(
                                    err.to_string(),
                                ))
                            })?);
                        request = serde_json::from_value(value).map_err(|err| {
                            Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                        })?;
                    }
                }
            }

            if request.as_ref().has_eip4844_fields()
                && request.as_ref().max_fee_per_blob_gas().is_none()
            {
                let blob_fee = <Self as LoadFee>::blob_base_fee(self).await?;
                request.as_mut().set_max_fee_per_blob_gas(blob_fee.to());
            }

            if request.as_ref().sidecar.is_some()
                && request.as_ref().blob_versioned_hashes.is_none()
            {
                request.as_mut().populate_blob_hashes();
            }

            if request.as_ref().gas_limit().is_none() {
                let estimated_gas = <Self as EstimateCall>::estimate_gas_at(
                    self,
                    request.clone(),
                    BlockId::pending(),
                    EvmOverrides::default(),
                )
                .await?;
                request.as_mut().set_gas_limit(estimated_gas.to());
            }

            if request.as_ref().gas_price().is_none() {
                let tip = if let Some(tip) = request.as_ref().max_priority_fee_per_gas() {
                    tip
                } else {
                    let tip = <Self as LoadFee>::suggested_priority_fee(self)
                        .await?
                        .to::<u128>();
                    request.as_mut().set_max_priority_fee_per_gas(tip);
                    tip
                };
                if request.as_ref().max_fee_per_gas().is_none() {
                    let header = self
                        .provider()
                        .latest_header()
                        .map_err(Self::Error::from_eth_err)?;
                    let base_fee = header
                        .and_then(|h| h.base_fee_per_gas())
                        .unwrap_or_default();
                    request
                        .as_mut()
                        .set_max_fee_per_gas(u128::from(base_fee) + tip);
                }
            }

            let request: TempoTransactionRequest =
                serde_json::from_value(serde_json::to_value(request).map_err(|err| {
                    Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                })?)
                .map_err(|err| {
                    Self::Error::from_eth_err(EthApiError::InvalidParams(err.to_string()))
                })?;
            let tx: TxTy<Self::Primitives> = self
                .inner
                .converter()
                .build_simulate_v1_transaction(request)?;
            let raw = tx.encoded_2718().into();

            Ok(FillTransaction { raw, tx })
        }
    }

    fn signers(&self) -> &SignersForRpc<Self::Provider, Self::NetworkTypes> {
        self.inner.signers()
    }

    fn send_raw_transaction_sync_timeout(&self) -> std::time::Duration {
        self.inner.send_raw_transaction_sync_timeout()
    }

    fn send_pool_transaction(
        &self,
        origin: TransactionOrigin,
        tx: WithEncoded<PoolTx<Self::Pool>>,
    ) -> impl Future<Output = Result<B256, Self::Error>> + Send {
        match tx.value().consensus_ref().subblock_proposer() {
            Some(proposer) if self.matches_validator_key(&proposer) => {
                let subblock_tx = self.subblock_transactions_tx.clone();
                Either::Left(Either::Left(async move {
                    let tx_hash = *tx.value().hash();

                    subblock_tx
                        .send(tx.into_value().into_consensus())
                        .map_err(|_| {
                            EthApiError::from(RethError::msg("subblocks service channel closed"))
                        })?;

                    Ok(tx_hash)
                }))
            }
            Some(_) => Either::Left(Either::Right(futures::future::err(
                EthApiError::from(RethError::msg(
                    "subblock transaction rejected: target validator mismatch",
                ))
                .into(),
            ))),
            None => Either::Right(
                self.inner
                    .send_pool_transaction(origin, tx)
                    .map_err(Into::into),
            ),
        }
    }
}

/// Converter for Tempo receipts.
#[derive(Debug, Clone)]
#[expect(clippy::type_complexity)]
pub struct TempoReceiptConverter {
    inner: EthReceiptConverter<
        TempoChainSpec,
        fn(TempoReceipt, usize, TransactionMeta) -> ReceiptWithBloom<TempoReceipt<Log>>,
    >,
}

impl TempoReceiptConverter {
    pub fn new(chain_spec: Arc<TempoChainSpec>) -> Self {
        Self {
            inner: EthReceiptConverter::new(chain_spec).with_builder(
                |receipt: TempoReceipt, next_log_index, meta| {
                    let mut log_index = next_log_index;
                    receipt
                        .map_logs(|log| {
                            let idx = log_index;
                            log_index += 1;
                            Log {
                                inner: log,
                                block_hash: Some(meta.block_hash),
                                block_number: Some(meta.block_number),
                                block_timestamp: Some(meta.timestamp),
                                transaction_hash: Some(meta.tx_hash),
                                transaction_index: Some(meta.index),
                                log_index: Some(idx as u64),
                                removed: false,
                            }
                        })
                        .into()
                },
            ),
        }
    }
}

impl ReceiptConverter<TempoPrimitives> for TempoReceiptConverter {
    type RpcReceipt = TempoTransactionReceipt;
    type Error = EthApiError;

    fn convert_receipts(
        &self,
        receipts: Vec<ConvertReceiptInput<'_, TempoPrimitives>>,
    ) -> Result<Vec<Self::RpcReceipt>, Self::Error> {
        let receipt_context = receipts.iter().map(|r| r.tx).collect::<Vec<_>>();
        self.inner
            .convert_receipts(receipts)?
            .into_iter()
            .zip(receipt_context)
            .map(|(inner, tx)| {
                let mut receipt = TempoTransactionReceipt {
                    inner,
                    fee_token: None,
                    // should never fail, we only deal with valid transactions here
                    fee_payer: tx
                        .fee_payer(tx.signer())
                        .map_err(|_| EthApiError::InvalidTransactionSignature)?,
                };

                if receipt.effective_gas_price == 0 || receipt.gas_used == 0 {
                    return Ok(receipt);
                }

                // Set fee token to the address that emitted the last log.
                //
                // Assumption is that every non-free transaction will end with a
                // fee token transfer to TIPFeeManager.
                receipt.fee_token = receipt.logs().last().map(|log| log.address());
                Ok(receipt)
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct TempoEthApiBuilder<N = ()> {
    /// Validator public key used to filter subblock transactions.
    pub validator_key: Option<B256>,
    _marker: PhantomData<fn() -> N>,
}

impl<N> Default for TempoEthApiBuilder<N> {
    fn default() -> Self {
        Self {
            validator_key: None,
            _marker: PhantomData,
        }
    }
}

impl<N> TempoEthApiBuilder<N> {
    /// Creates a new builder with the given validator key.
    pub fn new(validator_key: Option<B256>) -> Self {
        Self {
            validator_key,
            ..Self::default()
        }
    }
}

impl<N> EthApiBuilder<N> for TempoEthApiBuilder<N>
where
    N: FullNodeComponents<
            Types: NodeTypes<ChainSpec = TempoChainSpec, Primitives = TempoPrimitives>,
            Pool = <N as RpcNodeCore>::Pool,
            Evm = <N as RpcNodeCore>::Evm,
        > + FullNodeTypes<Provider = <N as RpcNodeCore>::Provider>
        + TempoEthApiBounds,
    <N as RpcNodeCore>::Provider: ChainSpecProvider<ChainSpec = TempoChainSpec>,
    <<N as RpcNodeCore>::Evm as ConfigureEvm>::NextBlockEnvCtx: BuildPendingEnv<TempoHeader>,
    <N::Types as NodeTypes>::ChainSpec: Hardforks + EthereumHardforks,
{
    type EthApi = TempoEthApi<N>;

    async fn build_eth_api(self, ctx: EthApiCtx<'_, N>) -> eyre::Result<Self::EthApi> {
        let chain_spec = FullNodeComponents::provider(ctx.components).chain_spec();
        let eth_api = ctx
            .eth_api_builder()
            .modify_gas_oracle_config(|config| config.default_suggested_fee = Some(U256::ZERO))
            .map_converter(|_| RpcConverter::new(TempoReceiptConverter::new(chain_spec)).erased())
            .build();

        Ok(TempoEthApi::new(eth_api, self.validator_key))
    }
}
