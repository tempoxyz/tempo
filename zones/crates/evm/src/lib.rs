//! Zone-specific EVM configuration.
//!
//! Wraps [`TempoEvmConfig`] with a [`ZoneEvmFactory`] that installs the L1-anchored database,
//! registers Zone-native precompiles, and preserves the original database at the [`Evm`] boundary.

#![cfg_attr(not(test), warn(unused_crate_dependencies))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(unnameable_types)]

mod database;
mod executor;
mod fee_manager;
pub mod precompiles;
mod zone_evm;

pub use database::{L1OverlayDB, ZoneDbError};
pub use executor::{ZoneBlockExecutor, ZoneTxResult};
pub use zone_evm::{ZoneEvm, validate_transaction};

use crate::{
    fee_manager::ZoneProtocolFeeManager,
    precompiles::{L1State, L1StorageReader, extend_zone_precompiles},
};
use alloy_evm::{
    Database, Evm, EvmEnv, EvmFactory,
    block::BlockExecutorFactory,
    precompiles::PrecompilesMap,
    revm::{Inspector, context::DBErrorMarker, inspector::NoOpInspector},
};
use alloy_primitives::{Address, B256};
use alloy_provider::{Provider, ProviderBuilder};
use reth_chainspec::EthChainSpec;
use reth_evm::{
    ConfigureEngineEvm, ConfigureEvm, EvmEnvFor, ExecutableTxIterator, ExecutionCtxFor,
    block::StateDB,
    execute::{BlockAssembler, BlockAssemblerInput},
};
use reth_primitives_traits::{SealedBlock, SealedHeader};
use revm::context::result::HaltReason;
use std::{
    collections::HashSet,
    fmt,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};
use tempo_alloy::TempoNetwork;
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_evm::{
    FeeTokenResolver, TempoBlockAssembler, TempoBlockEnv, TempoBlockExecutionCtx, TempoEvmConfig,
    TempoEvmError, TempoNextBlockEnvAttributes, TempoStateAccess,
    evm::{TempoEvm, TempoEvmFactory},
};
use tempo_payload_types::TempoExecutionData;
use tempo_precompiles::{error::Result as TempoResult, storage::actions::StorageActions};
use tempo_primitives::{
    Block, TempoHeader, TempoPrimitives, TempoReceipt, TempoTxEnvelope, TempoTxType,
};
use tempo_revm::TempoTxEnv;
use tempo_zone_contracts as _;
use zone_chainspec::ZoneChainSpec;
use zone_l1::state::{L1StateCache, L1StateProvider, L1StateProviderConfig};

type TempoCtx<DB> = <TempoEvmFactory as EvmFactory>::Context<DB>;

/// Zone EVM factory that adapts caller databases and registers the zone-native precompiles.
#[derive(Debug, Clone)]
pub struct ZoneEvmFactory<L1 = L1StateProvider> {
    l1_reader: L1,
    portal_address: Address,
}

impl<L1> ZoneEvmFactory<L1>
where
    L1: L1StorageReader,
{
    /// Creates a factory with the L1 reader and portal address.
    pub fn new(l1_reader: L1, portal_address: Address) -> Self {
        Self {
            l1_reader,
            portal_address,
        }
    }

    fn register_precompiles<DB: Database, I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>>(
        &self,
        evm: TempoEvm<L1OverlayDB<DB, L1>, I>,
        l1: L1State<L1>,
    ) -> TempoEvm<L1OverlayDB<DB, L1>, I> {
        let mut evm = evm.with_fee_manager(ZoneProtocolFeeManager::new());
        let cfg = evm.ctx().cfg.clone();
        let actions = StorageActions::disabled();
        let non_creditable_slots = evm.non_creditable_slots();
        let (_, _, precompiles) = evm.components_mut();
        extend_zone_precompiles(precompiles, &cfg, l1, actions, non_creditable_slots);
        evm
    }
}

impl<L1> EvmFactory for ZoneEvmFactory<L1>
where
    L1: L1StorageReader,
{
    type Evm<DB: Database, I: Inspector<Self::Context<DB>>> = ZoneEvm<DB, I, L1>;
    type Context<DB: Database> = TempoCtx<L1OverlayDB<DB, L1>>;
    type Tx = <TempoEvmFactory as EvmFactory>::Tx;
    type Error<DBError: DBErrorMarker> = <TempoEvmFactory as EvmFactory>::Error<DBError>;
    type HaltReason = HaltReason;
    type Spec = tempo_chainspec::hardfork::TempoHardfork;
    type BlockEnv = TempoBlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
    ) -> Self::Evm<DB, NoOpInspector> {
        let db = L1OverlayDB::new(db, self.l1_reader.clone(), self.portal_address);
        let l1 = db.l1_state().clone();
        let evm = TempoEvm::new(db, input);
        ZoneEvm::new(self.register_precompiles(evm, l1))
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv<Self::Spec, Self::BlockEnv>,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        let db = L1OverlayDB::new(db, self.l1_reader.clone(), self.portal_address);
        let l1 = db.l1_state().clone();
        let evm = TempoEvm::new(db, input).with_inspector(inspector);
        ZoneEvm::new(self.register_precompiles(evm, l1))
    }
}

/// Assembler for Zone blocks - delegates to [`TempoBlockAssembler`] after converting input types.
#[derive(Debug, Clone)]
pub struct ZoneBlockAssembler {
    inner: TempoBlockAssembler,
}

impl ZoneBlockAssembler {
    /// Create a new [`ZoneBlockAssembler`] with the given chain spec.
    pub fn new(chain_spec: Arc<ZoneChainSpec>) -> Self {
        Self {
            inner: TempoBlockAssembler::new(chain_spec.inner.clone()),
        }
    }
}

impl<L1> BlockAssembler<ZoneEvmConfig<L1>> for ZoneBlockAssembler
where
    L1: L1StorageReader,
{
    type Block = Block;

    fn assemble_block(
        &self,
        input: BlockAssemblerInput<'_, '_, ZoneEvmConfig<L1>, TempoHeader>,
    ) -> Result<Self::Block, alloy_evm::block::BlockExecutionError> {
        let BlockAssemblerInput {
            evm_env,
            execution_ctx,
            parent,
            transactions,
            output,
            bundle_state,
            state_provider,
            state_root,
            block_access_list_hash,
            ..
        } = input;

        self.inner.assemble_block(
            BlockAssemblerInput::<TempoEvmConfig, TempoHeader>::new(
                evm_env,
                execution_ctx,
                parent,
                transactions,
                output,
                bundle_state,
                state_provider,
                state_root,
                block_access_list_hash,
            ),
            None,
            None,
            None,
        )
    }
}

/// Zone EVM configuration with Zone precompiles and parent Tempo hardfork conditions.
#[derive(Clone)]
pub struct ZoneEvmConfig<L1 = L1StateProvider> {
    inner: TempoEvmConfig,
    chain_spec: Arc<ZoneChainSpec>,
    zone_factory: ZoneEvmFactory<L1>,
    block_assembler: ZoneBlockAssembler,
}

impl<L1> FeeTokenResolver for ZoneEvmConfig<L1> {
    fn resolve_fee_token<S, M>(
        &self,
        state: &mut S,
        tx: &TempoTxEnv,
        _fee_payer: Address,
        spec: TempoHardfork,
        actions: StorageActions,
    ) -> TempoResult<Address>
    where
        S: TempoStateAccess<M>,
    {
        fee_manager::resolve_fee_token(state, tx, spec, actions)
    }
}

impl<L1> ZoneEvmConfig<L1>
where
    L1: L1StorageReader,
{
    /// Creates a Zone EVM config from the node's canonical, composed chain specification.
    pub fn new(chain_spec: Arc<ZoneChainSpec>, l1_provider: L1, portal_address: Address) -> Self {
        let zone_factory = ZoneEvmFactory::new(l1_provider, portal_address);
        let tempo_chain_spec = chain_spec.inner.clone();
        let inner = TempoEvmConfig::new(tempo_chain_spec);
        let block_assembler = ZoneBlockAssembler::new(chain_spec.clone());
        Self {
            inner,
            chain_spec,
            zone_factory,
            block_assembler,
        }
    }

    /// Returns the Zone chain specification.
    pub fn chain_spec(&self) -> &Arc<ZoneChainSpec> {
        &self.chain_spec
    }

    /// Returns the underlying chain specification used by Tempo execution.
    pub fn tempo_chain_spec(&self) -> &Arc<TempoChainSpec> {
        self.inner.chain_spec()
    }

    /// Clones this configuration with a Tempo L1 storage-read recorder.
    pub fn with_l1_storage_recorder(
        &self,
    ) -> (
        ZoneEvmConfig<RecordingL1StorageReader<L1>>,
        RecordingL1StorageReader<L1>,
    ) {
        let reader = RecordingL1StorageReader::new(self.zone_factory.l1_reader.clone());
        let config = ZoneEvmConfig::new(
            self.chain_spec.clone(),
            reader.clone(),
            self.zone_factory.portal_address,
        );
        (config, reader)
    }
}

impl ZoneEvmConfig {
    /// Creates a Zone EVM config without a usable L1 provider.
    ///
    /// Intended for CLI subcommands (import, stage, re-execute) that need a type-compatible
    /// EVM config but don't have access to an L1 RPC connection. Tempo hardfork conditions come
    /// from `chain_spec` because the parent L1 spec cannot be resolved in this mode.
    pub fn new_without_l1(chain_spec: Arc<ZoneChainSpec>) -> Self {
        let cache = L1StateCache::default();
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().expect("valid fallback URL"))
            .erased();
        let runtime_handle = tokio::runtime::Handle::current();
        let config = L1StateProviderConfig {
            max_sync_attempts: Some(NonZeroU32::MIN),
            ..Default::default()
        };
        let l1_provider = L1StateProvider::new_raw(config, cache, provider, runtime_handle);
        Self::new(chain_spec, l1_provider, Address::ZERO)
    }
}

impl<L1> fmt::Debug for ZoneEvmConfig<L1> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZoneEvmConfig")
            .field("inner", &self.inner)
            .field("chain_spec", &self.chain_spec)
            .field("block_assembler", &self.block_assembler)
            .finish_non_exhaustive()
    }
}

impl<L1> BlockExecutorFactory for ZoneEvmConfig<L1>
where
    L1: L1StorageReader,
{
    type EvmFactory = ZoneEvmFactory<L1>;
    type ExecutionCtx<'a> = TempoBlockExecutionCtx<'a>;
    type Transaction = TempoTxEnvelope;
    type Receipt = TempoReceipt;
    type TxExecutionResult = ZoneTxResult<HaltReason, TempoTxType>;
    type Executor<'a, DB: StateDB, I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>> =
        ZoneBlockExecutor<'a, DB, I, L1>;

    fn evm_factory(&self) -> &Self::EvmFactory {
        &self.zone_factory
    }

    fn create_executor<'a, DB, I>(
        &'a self,
        evm: ZoneEvm<DB, I, L1>,
        ctx: Self::ExecutionCtx<'a>,
    ) -> Self::Executor<'a, DB, I>
    where
        DB: StateDB,
        I: Inspector<TempoCtx<L1OverlayDB<DB, L1>>>,
    {
        ZoneBlockExecutor::new(evm, ctx, self.chain_spec())
    }
}

impl<L1> ConfigureEvm for ZoneEvmConfig<L1>
where
    L1: L1StorageReader + Unpin,
{
    type Primitives = TempoPrimitives;
    type Error = TempoEvmError;
    type NextBlockEnvCtx = TempoNextBlockEnvAttributes;
    type BlockExecutorFactory = Self;
    type BlockAssembler = ZoneBlockAssembler;

    fn block_executor_factory(&self) -> &Self::BlockExecutorFactory {
        self
    }

    fn block_assembler(&self) -> &Self::BlockAssembler {
        &self.block_assembler
    }

    fn evm_env(&self, header: &TempoHeader) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env(header)
    }

    fn next_evm_env(
        &self,
        parent: &TempoHeader,
        attributes: &Self::NextBlockEnvCtx,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        let mut env = self.inner.next_evm_env(parent, attributes)?;
        // TempoEvmConfig is concrete over TempoChainSpec, so apply the Zone fee policy after
        // delegating the rest of the environment construction.
        env.block_env.inner.basefee = self
            .chain_spec
            .next_block_base_fee(parent, attributes.timestamp)
            .unwrap_or_default();
        Ok(env)
    }

    fn context_for_block<'a>(
        &self,
        block: &'a SealedBlock<Block>,
    ) -> Result<TempoBlockExecutionCtx<'a>, Self::Error> {
        use alloy_consensus::BlockHeader;
        use alloy_evm::eth::EthBlockExecutionCtx;
        use std::borrow::Cow;

        Ok(TempoBlockExecutionCtx {
            inner: EthBlockExecutionCtx {
                parent_hash: block.header().parent_hash(),
                parent_beacon_block_root: block.header().parent_beacon_block_root(),
                ommers: &[],
                withdrawals: block
                    .body()
                    .withdrawals
                    .as_ref()
                    .map(|withdrawals| Cow::Borrowed(withdrawals.as_slice())),
                extra_data: block.header().extra_data().clone(),
                tx_count_hint: Some(block.transaction_count()),
                slot_number: block.slot_number(),
            },
            general_gas_limit: 0,
            shared_gas_limit: 0,
            consensus_context: block.header().consensus_context,
        })
    }

    fn context_for_next_block(
        &self,
        parent: &SealedHeader<TempoHeader>,
        attributes: Self::NextBlockEnvCtx,
    ) -> Result<TempoBlockExecutionCtx<'_>, Self::Error> {
        self.inner.context_for_next_block(parent, attributes)
    }
}

impl<L1> ConfigureEngineEvm<TempoExecutionData> for ZoneEvmConfig<L1>
where
    L1: L1StorageReader + Unpin,
{
    fn evm_env_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<EvmEnvFor<Self>, Self::Error> {
        self.inner.evm_env_for_payload(payload)
    }

    fn context_for_payload<'a>(
        &self,
        payload: &'a TempoExecutionData,
    ) -> Result<ExecutionCtxFor<'a, Self>, Self::Error> {
        self.context_for_block(&payload.block)
    }

    fn tx_iterator_for_payload(
        &self,
        payload: &TempoExecutionData,
    ) -> Result<impl ExecutableTxIterator<Self>, Self::Error> {
        self.inner.tx_iterator_for_payload(payload)
    }
}

/// An [`L1StorageReader`] wrapper that records successful Tempo storage reads.
#[derive(Clone, Debug)]
pub struct RecordingL1StorageReader<L1> {
    inner: L1,
    reads: Arc<Mutex<HashSet<TempoStorageRead>>>,
}

impl<L1> RecordingL1StorageReader<L1> {
    fn new(inner: L1) -> Self {
        Self {
            inner,
            reads: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Takes and returns the deduplicated storage reads recorded so far.
    pub fn take_reads(&self) -> HashSet<TempoStorageRead> {
        std::mem::take(&mut self.reads.lock().expect("L1 read recorder lock poisoned"))
    }
}

impl<L1: L1StorageReader> L1StorageReader for RecordingL1StorageReader<L1> {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, zone_precompiles::L1StateError> {
        let value = self.inner.read_l1_storage(account, slot, block_number)?;
        self.reads
            .lock()
            .expect("L1 read recorder lock poisoned")
            .insert(TempoStorageRead { account, slot });
        Ok(value)
    }
}

/// A Tempo L1 storage slot accessed while replaying a Zone block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TempoStorageRead {
    /// Tempo account whose storage was accessed.
    pub account: Address,
    /// Storage slot that was accessed.
    pub slot: B256,
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_consensus::Sealable as _;
    use alloy_primitives::{B256, U256, address};
    use alloy_sol_types::SolCall;
    use reth_chainspec::EthChainSpec;
    use revm::database::{EmptyDB, InMemoryDB};
    use tempo_chainspec::{
        hardfork::TempoHardfork,
        spec::{MODERATO, TempoHardforks},
    };
    use tempo_precompiles::{
        TIP403_REGISTRY_ADDRESS, storage::StorageKey, tip403_registry::tip403_registry_slots,
        zone_factory::ZonePortalStorage,
    };
    use tempo_zone_contracts::IZoneInbox;
    use zone_precompiles::{
        tempo_state::{TEMPO_BLOCK_NUMBER_SLOT, slots::TEMPO_BLOCK_HASH},
        test_utils::MockL1Reader,
    };
    use zone_primitives::constants::{TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, zone_chain_id};

    #[test]
    fn l1_storage_recorder_deduplicates_successful_reads() {
        let account = Address::repeat_byte(0xaa);
        let slot = B256::repeat_byte(0xbb);
        let value = B256::repeat_byte(0xcc);
        let reader = RecordingL1StorageReader::new(MockL1Reader::returning(value));

        assert_eq!(reader.read_l1_storage(account, slot, 10).unwrap(), value);
        assert_eq!(reader.read_l1_storage(account, slot, 10).unwrap(), value);
        assert_eq!(
            reader.take_reads(),
            HashSet::from_iter([TempoStorageRead { account, slot }])
        );

        let failing = RecordingL1StorageReader::new(MockL1Reader::failing_storage());
        assert!(failing.read_l1_storage(account, slot, 10).is_err());
        assert!(failing.take_reads().is_empty());
    }

    #[test]
    fn advance_tempo_keeps_overlay_reads_on_child_anchor() {
        const PARENT: u64 = 0;
        const CHILD: u64 = 1;
        let portal = Address::repeat_byte(0x42);
        let sequencer = Address::repeat_byte(0xa1);
        let token = address!("0x20C00000000000000000000000000000000000AA");
        let reader = MockL1Reader::default();

        reader.seed_active_sequencer(portal, CHILD, sequencer);
        let enabled_token = IZoneInbox::EnabledToken {
            token,
            name: "Adversarial Token".into(),
            symbol: "ADV".into(),
            currency: "USD".into(),
        };
        let portal_storage = ZonePortalStorage::new(portal);
        reader.insert(
            portal,
            portal_storage.token_enablement_hash.slot(),
            CHILD,
            enabled_token.hash_with_previous(B256::ZERO).into(),
        );

        let policy_slot = token.mapping_slot(tip403_registry_slots::TOKEN_TRANSFER_POLICIES);
        let parent_policy = U256::from(0xaaaa);
        let child_policy = U256::from(0xbbbb);
        reader.insert(TIP403_REGISTRY_ADDRESS, policy_slot, PARENT, parent_policy);
        reader.insert(TIP403_REGISTRY_ADDRESS, policy_slot, CHILD, child_policy);

        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let child = TempoHeader {
            inner: alloy_consensus::Header {
                parent_hash: genesis_hash,
                number: CHILD,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut db = InMemoryDB::default();
        db.insert_account_storage(TEMPO_STATE_ADDRESS, TEMPO_BLOCK_HASH, genesis_hash.into())
            .unwrap();
        db.insert_account_storage(
            TEMPO_STATE_ADDRESS,
            TEMPO_BLOCK_NUMBER_SLOT,
            U256::from(PARENT),
        )
        .unwrap();

        let factory = ZoneEvmFactory::new(reader.clone(), portal);
        let mut env = EvmEnv::<TempoHardfork, TempoBlockEnv>::default();
        env.block_env.inner.timestamp = U256::from(child.inner.timestamp);
        env.block_env.timestamp_millis_part = child.timestamp_millis_part;
        let mut evm = factory.create_evm(db, env);
        let calldata = IZoneInbox::advanceTempoCall {
            header: alloy_rlp::encode(&child).into(),
            deposits: Vec::new(),
            decryptions: Vec::new(),
            enabledTokens: vec![enabled_token],
        }
        .abi_encode();

        let result = evm
            .transact_system_call(Address::ZERO, ZONE_INBOX_ADDRESS, calldata.into())
            .expect("advanceTempo execution must not fail");
        assert!(result.result.is_success());
        assert_eq!(
            evm.ctx().journaled_state.database.l1_state().get_anchor(),
            None,
            "transaction completion must clear the shared L1 anchor"
        );

        let requests = reader.storage_requests();
        let portal = ZonePortalStorage::new(portal);
        let child_policy_request = (TIP403_REGISTRY_ADDRESS, B256::from(policy_slot), CHILD);
        let parent_policy_request = (TIP403_REGISTRY_ADDRESS, B256::from(policy_slot), PARENT);
        assert!(!reader.requested(CHILD, &portal.role[sequencer]));
        assert!(!reader.requested(PARENT, &portal.role[sequencer]));
        assert!(requests.contains(&child_policy_request));
        assert!(!requests.contains(&parent_policy_request));
        assert!(reader.requested(CHILD, &portal.current_deposit_queue_hash));
    }

    #[test]
    fn tempo_evm_selects_parent_fork_from_zone_block_timestamp() {
        let mut genesis = MODERATO.genesis().clone();
        genesis
            .config
            .extra_fields
            .retain(|name, _| !name.ends_with("Time"));
        genesis.config.chain_id = zone_chain_id(MODERATO.chain_id(), 1).unwrap();
        let composed = Arc::new(ZoneChainSpec::from_genesis(genesis).unwrap());
        let activation_timestamp = TempoHardfork::VARIANTS
            .iter()
            .filter_map(|&hardfork| MODERATO.tempo_fork_activation(hardfork).as_timestamp())
            .find(|&timestamp| timestamp > 0)
            .expect("Moderato must have a post-genesis Tempo hardfork");
        let config = ZoneEvmConfig::new(composed, MockL1Reader::default(), Address::ZERO);
        for timestamp in [activation_timestamp - 1, activation_timestamp] {
            let header = TempoHeader {
                inner: alloy_consensus::Header {
                    timestamp,
                    ..Default::default()
                },
                ..Default::default()
            };
            let env = config.evm_env(&header).expect("valid EVM environment");
            let expected = MODERATO.tempo_hardfork_at(timestamp);
            assert_eq!(env.cfg_env.spec, expected);

            let evm = config
                .zone_factory
                .create_evm(EmptyDB::default(), env.clone());
            assert_eq!(evm.ctx().cfg.spec, expected);
            let evm = config.zone_factory.create_evm_with_inspector(
                EmptyDB::default(),
                env,
                NoOpInspector,
            );
            assert_eq!(evm.ctx().cfg.spec, expected);
        }
    }
}
