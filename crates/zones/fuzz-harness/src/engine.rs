//! The zone [`Engine`]: a zone's chain spec, EVM and consensus, its genesis, and the system
//! transactions its sequencer opens and closes every block with.

use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock},
};

use alloy_consensus::{Header, TxLegacy, transaction::Recovered};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;
use evm2::evm::{Cache, SystemTx};
use reth_evm::{BlockExecutionError, BlockValidationError};
use tempo_contracts::{
    precompiles::STABLECOIN_DEX_ADDRESS,
    zones::{outbox::IZoneOutbox, tempo_state::TempoState, zone_inbox::IZoneInbox},
};
use tempo_evm::{TempoEvm, consensus::TempoConsensus};
use tempo_fuzz_engine::{Chain, Engine, chain_spec_on};
use tempo_fuzz_types::{ChainSpecInput, ErrorClass};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use zone_chainspec::ZoneChainSpec;
use zone_evm::ZoneEvmConfig;
use zone_precompiles::{L1StateError, L1StorageReader};
use zone_primitives::constants::{
    TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, decode_zone_chain_id,
};

use crate::types::L1StateInput;

/// The zone genesis the node ships, which every zone input's chain starts from.
const GENESIS_JSON: &str = include_str!("../../node/assets/zone-dev-genesis.json");

static GENESIS: LazyLock<Genesis> =
    LazyLock::new(|| serde_json::from_str(GENESIS_JSON).expect("the zone genesis parses"));

/// The zone genesis allocation, seeded once per process, as the Tempo harness seeds its own.
static GENESIS_STATE: LazyLock<Cache> =
    LazyLock::new(|| tempo_fuzz_engine::genesis_state(&GENESIS));

/// A zone reading `l1`, executed as its node executes it.
#[derive(Debug, Clone)]
pub struct Zone {
    l1: L1,
}

impl Zone {
    /// A zone that reads `l1` at every anchor.
    pub fn new(l1: &L1StateInput) -> Self {
        Self { l1: L1::new(l1) }
    }
}

impl Engine for Zone {
    type ChainSpec = ZoneChainSpec;
    type EvmConfig = ZoneEvmConfig<L1>;
    type Consensus = TempoConsensus<ZoneChainSpec>;

    fn chain(
        &self,
        input: &ChainSpecInput,
    ) -> Result<Chain<ZoneChainSpec, Self::EvmConfig, Self::Consensus>, ErrorClass> {
        let (_, zone_id) =
            decode_zone_chain_id(input.chain_id).map_err(|_| ErrorClass::InvalidInput)?;
        let mut genesis = GENESIS.clone();
        genesis.config.chain_id = input.chain_id;
        let base = ZoneChainSpec::from_genesis(genesis).map_err(|_| ErrorClass::InvalidInput)?;
        let spec = Arc::new(chain_spec_on(base.inner.as_ref().clone(), input)?);
        let zone_spec = Arc::new(ZoneChainSpec {
            inner: Arc::clone(&spec),
        });
        let portal = tempo_precompiles::zone_factory::portal_address(zone_id);
        Ok(Chain {
            spec: Arc::clone(&zone_spec),
            evm_config: ZoneEvmConfig::new(Arc::clone(&zone_spec), self.l1.clone(), portal),
            // As `ZoneConsensus` validates them: zone blocks may share a timestamp.
            consensus: TempoConsensus::new(zone_spec).with_allow_equal_timestamps(true),
        })
    }

    fn genesis(&self) -> &Cache {
        &GENESIS_STATE
    }

    /// Zones run no stablecoin DEX: its address holds only the genesis code marker.
    fn runs(&self, contract: &Address) -> bool {
        *contract != STABLECOIN_DEX_ADDRESS
    }

    /// `advanceTempo` to the direct child of the Tempo block the zone last imported, at the zone
    /// block's timestamp, with no deposits, decryptions or newly enabled tokens.
    fn open_block(
        &self,
        evm: &mut TempoEvm<'_>,
        header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        let parent_hash = view(evm, TEMPO_STATE_ADDRESS, TempoState::tempoBlockHashCall {})?;
        let number = view(
            evm,
            TEMPO_STATE_ADDRESS,
            TempoState::tempoBlockNumberCall {},
        )?;
        let tempo = TempoHeader {
            inner: Header {
                number: number + 1,
                parent_hash,
                timestamp: header.inner.timestamp,
                ..Default::default()
            },
            timestamp_millis_part: header.timestamp_millis_part,
            ..Default::default()
        };
        let call = IZoneInbox::advanceTempoCall {
            header: alloy_rlp::encode(&tempo).into(),
            deposits: vec![],
            decryptions: vec![],
            enabledTokens: vec![],
        };
        Ok(vec![system_tx(
            self.chain_id(evm),
            ZONE_INBOX_ADDRESS,
            call.abi_encode(),
        )])
    }

    /// `finalizeWithdrawalBatch` over the withdrawals the block left pending, as the sequencer
    /// closes a block that requested any. A block that requested none needs no batch.
    fn close_block(
        &self,
        evm: &mut TempoEvm<'_>,
        header: &TempoHeader,
    ) -> Result<Vec<Recovered<TempoTxEnvelope>>, BlockExecutionError> {
        let pending = view(
            evm,
            ZONE_OUTBOX_ADDRESS,
            IZoneOutbox::getPendingWithdrawalsCall {},
        )?;
        if pending.is_empty() {
            return Ok(Vec::new());
        }
        let call = IZoneOutbox::finalizeWithdrawalBatchCall {
            count: U256::from(pending.len()),
            blockNumber: header.inner.number,
            encryptedSenders: vec![Bytes::new(); pending.len()],
        };
        Ok(vec![system_tx(
            self.chain_id(evm),
            ZONE_OUTBOX_ADDRESS,
            call.abi_encode(),
        )])
    }
}

/// Calls the view `call` on `to` as the system sender, without committing.
fn view<C: SolCall>(
    evm: &mut TempoEvm<'_>,
    to: Address,
    call: C,
) -> Result<C::Return, BlockExecutionError> {
    let fail = |why: String| BlockValidationError::msg(why).into();
    let result = evm
        .system_call(
            SystemTx::new(to, call.abi_encode().into()).with_caller(TEMPO_SYSTEM_TX_SENDER),
        )
        .map_err(|err| fail(format!("{} view failed: {err:?}", C::SIGNATURE)))?;
    if !result.result().status {
        return Err(fail(format!("{} view reverted", C::SIGNATURE)));
    }
    C::abi_decode_returns(&result.discard().output)
        .map_err(|err| fail(format!("{} view returned garbage: {err}", C::SIGNATURE)))
}

impl Zone {
    /// The chain ID `evm` executes for.
    fn chain_id(&self, evm: &TempoEvm<'_>) -> u64 {
        evm.version().chain_id
    }
}

/// A system transaction calling `to` with `input`, as the sequencer builds them.
fn system_tx(chain_id: u64, to: Address, input: Vec<u8>) -> Recovered<TempoTxEnvelope> {
    use alloy_consensus::SignableTransaction as _;
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce: 0,
        gas_price: 0,
        gas_limit: 0,
        to: to.into(),
        value: U256::ZERO,
        input: input.into(),
    };
    Recovered::new_unchecked(
        TempoTxEnvelope::Legacy(tx.into_signed(TEMPO_SYSTEM_TX_SIGNATURE)),
        TEMPO_SYSTEM_TX_SENDER,
    )
}

/// Tempo L1 as an input describes it: the same storage at every block.
#[derive(Debug, Clone, Default)]
pub struct L1 {
    storage: Arc<BTreeMap<(Address, B256), B256>>,
    commitments: Arc<BTreeMap<Address, B256>>,
}

impl L1 {
    fn new(input: &L1StateInput) -> Self {
        let storage = input
            .storage
            .iter()
            .flat_map(|(account, slots)| {
                slots
                    .iter()
                    .map(|(slot, value)| ((*account, B256::from(*slot)), B256::from(*value)))
            })
            .collect();
        Self {
            storage: Arc::new(storage),
            commitments: Arc::new(input.commitments.clone()),
        }
    }
}

impl L1StorageReader for L1 {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        _block_number: u64,
    ) -> Result<B256, L1StateError> {
        Ok(self
            .storage
            .get(&(account, slot))
            .copied()
            .unwrap_or_default())
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        _block_number: u64,
    ) -> Result<B256, L1StateError> {
        Ok(self.commitments.get(&account).copied().unwrap_or_default())
    }
}
