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
use reth_primitives_traits::{HeaderTy, Recovered, TransactionMeta, WithEncoded};
use reth_rpc_eth_api::{FromEthApiError, IntoEthApiError, RpcTxReq};
use reth_transaction_pool::{PoolTransaction, PoolTx, TransactionOrigin, TransactionPool};
pub use simulate::{TempoSimulate, TempoSimulateApiServer, TempoSimulateV1Response};
use std::{marker::PhantomData, sync::Arc};
pub use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::rpc::{MultisigSimulationApproval, MultisigSimulationHint};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::{FeeTokenResolver, TempoStateAccess};
use tempo_precompiles::{
    ECRECOVER_GAS, NATIVE_MULTISIG_ADDRESS, NONCE_PRECOMPILE_ADDRESS,
    native_multisig::NativeMultisig,
    nonce::NonceManager,
    storage::{StorageActions, packing::extract_from_word},
};
use tempo_primitives::transaction::{
    InitMultisig, MAX_MULTISIG_NESTING_DEPTH, MAX_MULTISIG_OWNERS, MAX_MULTISIG_SIGNATURES,
    MAX_WEBAUTHN_SIGNATURE_LENGTH, MultisigOwner, SignatureType, TEMPO_EXPIRING_NONCE_KEY,
};
pub use token::{TempoToken, TempoTokenApiServer};

use crate::rpc::error::TempoEthApiError;
use alloy::primitives::{U256, uint};
use alloy_evm::{EvmFactory, block::BlockExecutorFactory};
use reth_chainspec::{EthChainSpec, EthereumHardforks, Hardforks};
use reth_ethereum::tasks::{
    Runtime,
    pool::{BlockingTaskGuard, BlockingTaskPool},
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
    EthApiTypes, RpcConverter, RpcNodeCore, RpcNodeCoreExt,
    helpers::{
        Call, EthApiSpec, EthBlocks, EthCall, EthFees, EthState, EthSubscriptions, EthTransactions,
        LoadBlock, LoadFee, LoadPendingBlock, LoadReceipt, LoadState, LoadTransaction,
        SpawnBlocking, Trace,
        bal::GetBlockAccessList,
        estimate::EstimateCall,
        pending_block::{BuildPendingEnv, PendingEnvBuilder},
        spec::SignersForRpc,
    },
    transaction::{ConvertReceiptInput, ReceiptConverter},
};
use reth_rpc_eth_types::{
    EthApiError, EthStateCache, FeeHistoryCache, GasPriceOracle, PendingBlock, SignError,
    builder::config::PendingBlockKind, receipt::EthReceiptConverter,
};
use tempo_alloy::{TempoNetwork, rpc::TempoTransactionReceipt};
use tempo_evm::{TempoBlockEnv, TempoHaltReason, TempoInvalidTransaction};
use tempo_primitives::{
    TEMPO_GAS_PRICE_SCALING_FACTOR, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope,
    subblock::PartialValidatorKey,
};
use tempo_revm::{
    NATIVE_MULTISIG_NESTED_ACCOUNT_GAS, NATIVE_MULTISIG_OWNER_WEIGHT_GAS,
    NATIVE_MULTISIG_VALIDATION_GAS, P256_VERIFY_GAS, TempoTxEnv,
    native_multisig_complete_config_validation_gas,
};
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
        > + FeeTokenResolver,
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
            > + FeeTokenResolver,
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
    let Some(from) = request.from else {
        return Ok(());
    };

    if request.key_id.is_some() {
        return Ok(());
    }

    if request.multisig_simulation_hint.is_some() {
        return Ok(());
    }

    if let Some(hint) =
        load_native_multisig_simulation_hint(from, request.multisig_signature_count, db)?
    {
        // `multisig_init` is advisory: a registered sender cannot re-init, so the
        // stored config wins and the bootstrap hint is dropped.
        request.multisig_init = None;
        if request.multisig_signature_count.is_none() {
            request.multisig_signature_count = Some(hint.approvals.len());
        }
        request.multisig_simulation_hint = Some(hint);
        return Ok(());
    }

    if let Some(init) = request.multisig_init.as_ref() {
        let hint = native_multisig_simulation_hint_for_config(
            init.account()
                .map_err(|err| EthApiError::InvalidParams(err.to_string()))?,
            init,
            db,
            1,
            request.multisig_signature_count,
        )?;
        if request.multisig_signature_count.is_none() {
            request.multisig_signature_count = Some(hint.approvals.len());
        }
        request.multisig_simulation_hint = Some(hint);
    }

    Ok(())
}

fn load_native_multisig_simulation_hint(
    from: Address,
    signature_count: Option<usize>,
    db: &mut impl Database<Error: Into<EthApiError>>,
) -> Result<Option<MultisigSimulationHint>, EthApiError> {
    load_native_multisig_simulation_hint_at_depth(from, db, 1, signature_count)
}

fn load_native_multisig_simulation_hint_at_depth(
    account: Address,
    db: &mut impl Database<Error: Into<EthApiError>>,
    depth: usize,
    signature_count: Option<usize>,
) -> Result<Option<MultisigSimulationHint>, EthApiError> {
    let (threshold_slot, threshold_offset) =
        NativeMultisig::account_threshold_storage_slot(account);
    let (owner_count_slot, owner_count_offset) =
        NativeMultisig::account_owners_len_storage_slot(account);
    let (version_slot, version_offset) = NativeMultisig::account_version_storage_slot(account);
    debug_assert_eq!(threshold_slot, owner_count_slot);
    debug_assert_eq!(threshold_slot, version_slot);
    let header = db
        .storage(NATIVE_MULTISIG_ADDRESS, threshold_slot)
        .map_err(Into::into)?;
    const HEADER_USED_BYTES: usize = 10;
    validate_native_multisig_storage_word(header, HEADER_USED_BYTES)?;
    let threshold = extract_from_word::<u8>(header, threshold_offset.unwrap_or_default(), 1)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))?;
    let owner_count = extract_from_word::<u8>(header, owner_count_offset.unwrap_or_default(), 1)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))? as usize;
    let version = extract_from_word::<u64>(header, version_offset.unwrap_or_default(), 8)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))?;
    if threshold == 0 && owner_count == 0 && version == 0 {
        return Ok(None);
    }
    if threshold == 0 || owner_count == 0 || version == 0 || owner_count > MAX_MULTISIG_OWNERS {
        return Err(EthApiError::InvalidParams(
            "native multisig config has an invalid header".to_string(),
        ));
    }

    let mut owners = Vec::with_capacity(owner_count);
    for index in 0..owner_count {
        let owner = read_native_multisig_owner(db, account, index)?;
        let (weight_slot, weight_offset) =
            NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner.owner);
        if read_native_multisig_weight(db, weight_slot, weight_offset)? != owner.weight {
            return Err(EthApiError::InvalidParams(
                "native multisig config has mismatched owner weights".to_string(),
            ));
        }
        owners.push(owner);
    }

    let config = InitMultisig {
        salt: B256::ZERO,
        threshold,
        owners,
    };
    config
        .validate()
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))?;

    native_multisig_simulation_hint_for_config(account, &config, db, depth, signature_count)
        .map(Some)
}

fn native_multisig_simulation_hint_for_config(
    account: Address,
    config: &InitMultisig,
    db: &mut impl Database<Error: Into<EthApiError>>,
    depth: usize,
    signature_count: Option<usize>,
) -> Result<MultisigSimulationHint, EthApiError> {
    if signature_count.is_some_and(|count| count == 0 || count > MAX_MULTISIG_SIGNATURES) {
        return Err(EthApiError::InvalidParams(
            "invalid native multisig signature count".to_string(),
        ));
    }

    let mut owner_approvals = Vec::with_capacity(config.owners.len());
    for owner in &config.owners {
        let approval = if depth < MAX_MULTISIG_NESTING_DEPTH {
            load_native_multisig_simulation_hint_at_depth(owner.owner, db, depth + 1, None)?
                .map(Box::new)
                .map(MultisigSimulationApproval::Multisig)
                .unwrap_or(MultisigSimulationApproval::UnknownPrimitive)
        } else {
            MultisigSimulationApproval::UnknownPrimitive
        };
        owner_approvals.push(approval);
    }

    let approvals =
        select_native_multisig_simulation_approvals(config, owner_approvals, signature_count)?;

    Ok(MultisigSimulationHint {
        account,
        owner_count: config.owners.len(),
        approvals,
    })
}

#[derive(Clone, Copy)]
struct MultisigSimulationSelection {
    gas: u64,
    owner_indices: [usize; MAX_MULTISIG_SIGNATURES],
    len: usize,
}

fn select_native_multisig_simulation_approvals(
    config: &InitMultisig,
    owner_approvals: Vec<MultisigSimulationApproval>,
    signature_count: Option<usize>,
) -> Result<Vec<MultisigSimulationApproval>, EthApiError> {
    let threshold = usize::from(config.threshold);
    // Retain the highest-gas partial quorum for each signature-count and weight pair.
    // Completed candidates stop when they first reach the threshold, matching validation.
    let mut states = vec![vec![None; threshold]; MAX_MULTISIG_SIGNATURES + 1];
    states[0][0] = Some(MultisigSimulationSelection {
        gas: 0,
        owner_indices: [0; MAX_MULTISIG_SIGNATURES],
        len: 0,
    });
    let mut best: Option<MultisigSimulationSelection> = None;

    for (owner_index, (owner, approval)) in config.owners.iter().zip(&owner_approvals).enumerate() {
        // Walk backwards so this owner cannot be selected more than once.
        for count in (0..MAX_MULTISIG_SIGNATURES).rev() {
            for weight in (0..threshold).rev() {
                let Some(selection) = states[count][weight] else {
                    continue;
                };
                let next_count = count + 1;
                let mut candidate = selection;
                candidate.gas = candidate
                    .gas
                    .saturating_add(native_multisig_simulation_approval_gas(approval));
                candidate.owner_indices[count] = owner_index;
                candidate.len = next_count;

                let next_weight = weight.saturating_add(usize::from(owner.weight));
                if next_weight >= threshold {
                    if signature_count.is_none_or(|expected| expected == next_count)
                        && best
                            .as_ref()
                            .is_none_or(|current| candidate.gas > current.gas)
                    {
                        best = Some(candidate);
                    }
                } else if states[next_count][next_weight]
                    .as_ref()
                    .is_none_or(|current| candidate.gas > current.gas)
                {
                    states[next_count][next_weight] = Some(candidate);
                }
            }
        }
    }

    best.map(|selection| {
        selection.owner_indices[..selection.len]
            .iter()
            .map(|&index| owner_approvals[index].clone())
            .collect()
    })
    .ok_or_else(|| {
        let reason = signature_count.map_or_else(
            || "native multisig config cannot satisfy its threshold".to_string(),
            |count| format!("native multisig threshold cannot be satisfied by {count} signatures"),
        );
        EthApiError::InvalidParams(reason)
    })
}

fn native_multisig_simulation_approval_gas(approval: &MultisigSimulationApproval) -> u64 {
    const P256_OWNER_GAS: u64 = ECRECOVER_GAS + P256_VERIFY_GAS;
    const MAX_WEBAUTHN_GAS: u64 =
        P256_OWNER_GAS + (MAX_WEBAUTHN_SIGNATURE_LENGTH as u64 - 128) * 16;

    let verification_gas = match approval {
        MultisigSimulationApproval::Primitive { key_type, .. } => match key_type {
            SignatureType::Secp256k1 => ECRECOVER_GAS,
            SignatureType::P256 => P256_OWNER_GAS,
            SignatureType::WebAuthn => MAX_WEBAUTHN_GAS,
        },
        MultisigSimulationApproval::UnknownPrimitive => MAX_WEBAUTHN_GAS,
        MultisigSimulationApproval::Multisig(hint) => NATIVE_MULTISIG_NESTED_ACCOUNT_GAS
            .saturating_add(NATIVE_MULTISIG_VALIDATION_GAS)
            .saturating_add(native_multisig_complete_config_validation_gas(
                hint.owner_count,
            ))
            .saturating_add(
                hint.approvals
                    .iter()
                    .map(native_multisig_simulation_approval_gas)
                    .fold(0u64, u64::saturating_add),
            ),
    };

    NATIVE_MULTISIG_OWNER_WEIGHT_GAS.saturating_add(verification_gas)
}

fn read_native_multisig_owner(
    db: &mut impl Database<Error: Into<EthApiError>>,
    account: Address,
    index: usize,
) -> Result<MultisigOwner, EthApiError> {
    let (slot, owner_offset) = NativeMultisig::config_owner_address_storage_slot(account, index);
    let word = db
        .storage(NATIVE_MULTISIG_ADDRESS, slot)
        .map_err(Into::into)?;
    const OWNER_USED_BYTES: usize = 21;
    validate_native_multisig_storage_word(word, OWNER_USED_BYTES)?;
    let owner = extract_from_word::<Address>(word, owner_offset.unwrap_or_default(), 20)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))?;
    let (weight_slot, weight_offset) =
        NativeMultisig::config_owner_weight_storage_slot(account, index);
    debug_assert_eq!(slot, weight_slot);
    let weight = extract_from_word::<u8>(word, weight_offset.unwrap_or_default(), 1)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))?;
    Ok(MultisigOwner { owner, weight })
}

fn read_native_multisig_weight(
    db: &mut impl Database<Error: Into<EthApiError>>,
    slot: U256,
    offset: Option<usize>,
) -> Result<u8, EthApiError> {
    let word = db
        .storage(NATIVE_MULTISIG_ADDRESS, slot)
        .map_err(Into::into)?;
    validate_native_multisig_storage_word(word, 1)?;
    extract_from_word::<u8>(word, offset.unwrap_or_default(), 1)
        .map_err(|err| EthApiError::InvalidParams(err.to_string()))
}

fn validate_native_multisig_storage_word(word: U256, used_bytes: usize) -> Result<(), EthApiError> {
    if word >> (used_bytes * 8) != U256::ZERO {
        return Err(EthApiError::InvalidParams(
            "native multisig config has nonzero reserved bits".to_string(),
        ));
    }
    Ok(())
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

        let actions = StorageActions::disabled();
        let fee_token = self
            .evm_config()
            .resolve_fee_token(
                &mut db,
                tx_env,
                fee_payer,
                evm_env.cfg_env.spec,
                actions.clone(),
            )
            .map_err(ProviderError::other)?;
        let fee_token_balance = db
            .get_token_balance(fee_token, fee_payer, evm_env.cfg_env.spec, actions)
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
impl<N> EthSubscriptions for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadBlock for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadReceipt for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> EthBlocks for TempoEthApi<N> where N: TempoEthApiBounds {}
impl<N> LoadTransaction for TempoEthApi<N> where N: TempoEthApiBounds {}

impl<N> EthTransactions for TempoEthApi<N>
where
    N: TempoEthApiBounds,
{
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
pub struct TempoReceiptConverter<ChainSpec = TempoChainSpec> {
    inner: EthReceiptConverter<
        ChainSpec,
        fn(TempoReceipt, usize, TransactionMeta) -> ReceiptWithBloom<TempoReceipt<Log>>,
    >,
}

impl<ChainSpec> TempoReceiptConverter<ChainSpec> {
    pub fn new(chain_spec: Arc<ChainSpec>) -> Self {
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

impl<ChainSpec> ReceiptConverter<TempoPrimitives> for TempoReceiptConverter<ChainSpec>
where
    ChainSpec: EthChainSpec + 'static,
{
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
            Types: NodeTypes<Primitives = TempoPrimitives>,
            Pool = <N as RpcNodeCore>::Pool,
            Evm = <N as RpcNodeCore>::Evm,
        > + FullNodeTypes<Provider = <N as RpcNodeCore>::Provider>
        + TempoEthApiBounds,
    <N as RpcNodeCore>::Provider: ChainSpecProvider<ChainSpec = <N::Types as NodeTypes>::ChainSpec>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, B256, TxKind};
    use alloy_rpc_types_eth::TransactionRequest;
    use reth_evm::revm::{bytecode::Bytecode, state::AccountInfo};
    use std::collections::HashMap;
    use tempo_primitives::transaction::{InitMultisig, MultisigOwner};

    /// Storage-only test DB for `NATIVE_MULTISIG_ADDRESS` slots.
    #[derive(Default)]
    struct SlotDb(HashMap<U256, U256>);

    impl SlotDb {
        /// Packs `value` into `slot` at `offset`, mirroring `extract_from_word`.
        fn insert_u8(&mut self, (slot, offset): (U256, Option<usize>), value: u8) {
            *self.0.entry(slot).or_default() |=
                U256::from(value) << (offset.unwrap_or_default() * 8);
        }

        fn insert_address(&mut self, (slot, offset): (U256, Option<usize>), value: Address) {
            *self.0.entry(slot).or_default() |=
                U256::from_be_slice(value.as_slice()) << (offset.unwrap_or_default() * 8);
        }

        fn insert_config(&mut self, account: Address, threshold: u8, owners: &[(Address, u8)]) {
            self.insert_u8(
                NativeMultisig::account_threshold_storage_slot(account),
                threshold,
            );
            self.insert_u8(
                NativeMultisig::account_owners_len_storage_slot(account),
                owners.len() as u8,
            );
            let (version_slot, version_offset) =
                NativeMultisig::account_version_storage_slot(account);
            *self.0.entry(version_slot).or_default() |=
                U256::from(1) << (version_offset.unwrap_or_default() * 8);
            for (index, &(owner, weight)) in owners.iter().enumerate() {
                self.insert_address(
                    NativeMultisig::config_owner_address_storage_slot(account, index),
                    owner,
                );
                self.insert_u8(
                    NativeMultisig::config_owner_weight_storage_slot(account, index),
                    weight,
                );
                self.insert_u8(
                    NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner),
                    weight,
                );
            }
        }

        fn registered_one_of_one(account: Address) -> Self {
            let mut db = Self::default();
            db.insert_config(account, 1, &[(Address::from([0x11; 20]), 1)]);
            db
        }
    }

    impl Database for SlotDb {
        type Error = ProviderError;

        fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(None)
        }

        fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
            Ok(Bytecode::default())
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            debug_assert_eq!(address, NATIVE_MULTISIG_ADDRESS);
            Ok(self.0.get(&index).copied().unwrap_or_default())
        }

        fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    fn init_request(from: Address) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(from),
                ..Default::default()
            },
            multisig_init: Some(InitMultisig {
                salt: B256::ZERO,
                threshold: 1,
                owners: vec![MultisigOwner {
                    owner: Address::from([0x11; 20]),
                    weight: 1,
                }],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn populate_drops_multisig_init_for_registered_senders() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::registered_one_of_one(account);
        let hint = load_native_multisig_simulation_hint(account, None, &mut db)
            .unwrap()
            .expect("registered account hint");
        assert_eq!(hint.account, account);
        assert_eq!(hint.owner_count, 1);
        assert_eq!(
            hint.approvals,
            vec![MultisigSimulationApproval::UnknownPrimitive]
        );

        let mut request = init_request(account);
        populate_native_multisig_simulation_hints(&mut request, &mut db).unwrap();
        assert!(request.multisig_init.is_none());
        assert_eq!(request.multisig_signature_count, Some(1));
        assert_eq!(request.multisig_simulation_hint, Some(hint));
    }

    #[test]
    fn populate_keeps_multisig_init_for_unregistered_senders() {
        let account = Address::from([0xbb; 20]);
        let mut db = SlotDb::default();

        let mut request = init_request(account);
        populate_native_multisig_simulation_hints(&mut request, &mut db).unwrap();
        assert!(request.multisig_init.is_some());
        assert_eq!(request.multisig_signature_count, Some(1));
        assert!(request.multisig_simulation_hint.is_some());
    }

    #[test]
    fn populate_preserves_access_key_simulation_for_registered_multisig_sender() {
        let account = Address::from([0xaa; 20]);
        let key_id = Address::from([0xbb; 20]);
        let mut db = SlotDb::registered_one_of_one(account);
        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                to: Some(TxKind::Call(Address::from([0xcc; 20]))),
                ..Default::default()
            },
            key_id: Some(key_id),
            ..Default::default()
        };

        populate_native_multisig_simulation_hints(&mut request, &mut db).unwrap();
        assert!(request.multisig_signature_count.is_none());
        assert!(request.multisig_simulation_hint.is_none());

        let tx_env = request
            .try_into_tempo_tx_env(TempoTxEnv::default(), true)
            .expect("valid access-key simulation request");
        let aa_env = tx_env.tempo_tx_env.expect("AA simulation env");
        assert_eq!(aa_env.override_key_id, Some(key_id));
        assert!(aa_env.signature.is_v2_keychain());
    }

    #[test]
    fn populate_models_nested_multisig_approvals() {
        let account = Address::from([0xaa; 20]);
        let nested_account = Address::from([0x11; 20]);
        let mut db = SlotDb::default();
        db.insert_config(account, 1, &[(nested_account, 1)]);
        db.insert_config(
            nested_account,
            2,
            &[
                (Address::from([0x21; 20]), 1),
                (Address::from([0x22; 20]), 1),
            ],
        );

        for signature_count in [None, Some(1)] {
            let mut request = TempoTransactionRequest {
                inner: TransactionRequest {
                    from: Some(account),
                    ..Default::default()
                },
                multisig_signature_count: signature_count,
                ..Default::default()
            };
            populate_native_multisig_simulation_hints(&mut request, &mut db).unwrap();

            assert_eq!(request.multisig_signature_count, Some(1));
            let hint = request
                .multisig_simulation_hint
                .expect("registered account hint");
            assert_eq!(hint.account, account);
            assert_eq!(hint.owner_count, 1);
            assert_eq!(hint.approvals.len(), 1);
            let MultisigSimulationApproval::Multisig(nested) = &hint.approvals[0] else {
                panic!("registered threshold owner should use a nested approval");
            };
            assert_eq!(nested.account, nested_account);
            assert_eq!(nested.owner_count, 2);
            assert_eq!(
                nested.approvals,
                vec![
                    MultisigSimulationApproval::UnknownPrimitive,
                    MultisigSimulationApproval::UnknownPrimitive,
                ]
            );
        }
    }

    #[test]
    fn populate_uses_the_most_expensive_valid_quorum() {
        let account = Address::from([0xaa; 20]);
        let owners = (0..9)
            .map(|index| {
                (
                    Address::from([0x11 + index as u8; 20]),
                    if index == 0 { 8 } else { 1 },
                )
            })
            .collect::<Vec<_>>();
        let mut db = SlotDb::default();
        db.insert_config(account, 8, &owners);

        let mut conservative = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            ..Default::default()
        };
        populate_native_multisig_simulation_hints(&mut conservative, &mut db).unwrap();
        assert_eq!(conservative.multisig_signature_count, Some(8));
        assert_eq!(
            conservative
                .multisig_simulation_hint
                .as_ref()
                .unwrap()
                .approvals
                .len(),
            8
        );

        let mut explicit = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            multisig_signature_count: Some(1),
            ..Default::default()
        };
        populate_native_multisig_simulation_hints(&mut explicit, &mut db).unwrap();
        assert_eq!(explicit.multisig_signature_count, Some(1));
        assert_eq!(
            explicit
                .multisig_simulation_hint
                .as_ref()
                .unwrap()
                .approvals
                .len(),
            1
        );
    }

    #[test]
    fn populate_supports_threshold_above_signature_cap() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::default();
        db.insert_config(account, u8::MAX, &[(Address::from([0x11; 20]), u8::MAX)]);

        let hint = load_native_multisig_simulation_hint(account, None, &mut db)
            .unwrap()
            .expect("registered account hint");

        assert_eq!(hint.approvals.len(), 1);
    }

    #[test]
    fn populate_prefers_the_more_expensive_approval_shape() {
        let account = Address::from([0xaa; 20]);
        let nested_account = Address::from([0x22; 20]);
        let mut db = SlotDb::default();
        db.insert_config(
            account,
            1,
            &[(Address::from([0x11; 20]), 1), (nested_account, 1)],
        );
        let nested_owners = (0..8)
            .map(|index| (Address::from([0x31 + index as u8; 20]), 1))
            .collect::<Vec<_>>();
        db.insert_config(nested_account, 8, &nested_owners);

        let mut request = TempoTransactionRequest {
            inner: TransactionRequest {
                from: Some(account),
                ..Default::default()
            },
            ..Default::default()
        };
        populate_native_multisig_simulation_hints(&mut request, &mut db).unwrap();

        assert_eq!(request.multisig_signature_count, Some(1));
        let hint = request
            .multisig_simulation_hint
            .expect("registered account hint");
        assert_eq!(hint.approvals.len(), 1);
        let MultisigSimulationApproval::Multisig(nested) = &hint.approvals[0] else {
            panic!("the higher-gas nested approval should be selected");
        };
        assert_eq!(nested.account, nested_account);
        assert_eq!(nested.approvals.len(), 8);
    }

    #[test]
    fn nested_simulation_approval_includes_account_access_gas() {
        let approval = MultisigSimulationApproval::Multisig(Box::new(MultisigSimulationHint {
            account: Address::from([0x22; 20]),
            owner_count: 1,
            approvals: vec![MultisigSimulationApproval::Primitive {
                key_type: SignatureType::Secp256k1,
                key_data: None,
            }],
        }));

        assert_eq!(
            native_multisig_simulation_approval_gas(&approval),
            2_100 + NATIVE_MULTISIG_NESTED_ACCOUNT_GAS + 2_100 + 4_200 + 2_100 + 3_000
        );
    }

    #[test]
    fn simulation_hints_reject_zero_config_version() {
        let account = Address::from([0xaa; 20]);
        let mut db = SlotDb::default();
        db.insert_u8(NativeMultisig::account_threshold_storage_slot(account), 1);
        db.insert_u8(NativeMultisig::account_owners_len_storage_slot(account), 1);

        assert!(matches!(
            load_native_multisig_simulation_hint(account, None, &mut db),
            Err(EthApiError::InvalidParams(reason)) if reason.contains("invalid header")
        ));
    }

    #[test]
    fn simulation_hints_reject_nonzero_reserved_storage_bits() {
        let account = Address::from([0xaa; 20]);
        let owner = Address::from([0x11; 20]);
        let corrupted_slots = [
            NativeMultisig::account_threshold_storage_slot(account).0,
            NativeMultisig::config_owner_address_storage_slot(account, 0).0,
            NativeMultisig::config_owner_lookup_weight_storage_slot(account, owner).0,
        ];

        for corrupted_slot in corrupted_slots {
            let mut db = SlotDb::registered_one_of_one(account);
            *db.0.entry(corrupted_slot).or_default() |= U256::ONE << 255;
            assert!(matches!(
                load_native_multisig_simulation_hint(account, None, &mut db),
                Err(EthApiError::InvalidParams(reason))
                    if reason.contains("nonzero reserved bits")
            ));
        }
    }
}
