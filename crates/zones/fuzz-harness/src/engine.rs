//! The zone [`Engine`]: a zone's chain spec, EVM and consensus, its genesis, and the system
//! transactions its sequencer opens and closes every block with.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    sync::{Arc, LazyLock},
};

use alloy_consensus::{Header, Sealable as _, TxLegacy, transaction::Recovered};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;
use evm2::evm::{Cache, SystemTx};
use invariants_core::Report;
use reth_evm::{BlockExecutionError, BlockValidationError};
use tempo_contracts::{
    precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, STABLECOIN_DEX_ADDRESS},
    zones::{outbox::IZoneOutbox, tempo_state::TempoState},
};
use tempo_evm::{TempoEvm, consensus::TempoConsensus};
use tempo_fuzz_engine::{Anchor, Chain, Engine, EvmConfig, StepState, chain_spec_on};
use tempo_fuzz_types::{ChainSpecInput, ErrorClass};
use tempo_precompiles::storage::account_config_commitment;
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use zone_chainspec::ZoneChainSpec;
use zone_evm::{ZoneEvmConfig, build_advance_tempo_tx_from_parts};
use zone_precompiles::{
    L1StateError, L1StorageReader,
    tempo_state::{TEMPO_BLOCK_NUMBER_SLOT, slots::TEMPO_BLOCK_HASH},
};
use zone_primitives::constants::{TEMPO_STATE_ADDRESS, ZONE_OUTBOX_ADDRESS, decode_zone_chain_id};

use crate::{accounts::AccountChecks, types::L1StateInput};

/// The zone genesis the node ships, which every zone input's chain starts from.
const GENESIS_JSON: &str = include_str!("../../node/assets/zone-dev-genesis.json");

static GENESIS: LazyLock<Genesis> =
    LazyLock::new(|| serde_json::from_str(GENESIS_JSON).expect("the zone genesis parses"));

/// The zone genesis allocation, seeded once per process, as the Tempo harness seeds its own.
pub(crate) static GENESIS_STATE: LazyLock<Cache> =
    LazyLock::new(|| tempo_fuzz_engine::genesis_state(&GENESIS));

/// A zone reading `l1`, executed as its node executes it, checking the zone's configurable
/// accounts (TIP-1154) against Tempo after every step.
#[derive(Debug)]
pub struct Zone {
    l1: L1,
    genesis: Cow<'static, Cache>,
    accounts: AccountChecks,
}

impl Zone {
    /// A zone that reads `l1` and watches the configurable accounts of `watched`.
    pub fn new(l1: L1, watched: Vec<Address>) -> Self {
        let genesis = match &l1 {
            L1::State { .. } => Cow::Borrowed(&*GENESIS_STATE),
            // The zone starts anchored to the Tempo genesis.
            L1::Chain(chain) => {
                let mut genesis = GENESIS_STATE.clone();
                let hash = chain.anchors[0].header().hash_slow();
                genesis
                    .storage
                    .entry(TEMPO_STATE_ADDRESS)
                    .or_default()
                    .slots
                    .extend([
                        (TEMPO_BLOCK_HASH, hash.into()),
                        (TEMPO_BLOCK_NUMBER_SLOT, U256::ZERO),
                    ]);
                Cow::Owned(genesis)
            }
        };
        let accounts = AccountChecks::new(&l1, watched);
        Self {
            l1,
            genesis,
            accounts,
        }
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
        &self.genesis
    }

    /// Zones run no stablecoin DEX: its address holds only the genesis code marker.
    /// A zone runs no stablecoin DEX, and mirrors Tempo's configurable account commitments, which
    /// [`Engine::check_step`] checks against Tempo, rather than keeping its own.
    fn runs(&self, contract: &Address) -> bool {
        ![STABLECOIN_DEX_ADDRESS, CONFIGURABLE_ACCOUNT_ADDRESS].contains(contract)
    }

    /// `advanceTempo` to the next Tempo block, with no deposits, decryptions or newly enabled tokens,
    /// built as the sequencer builds it. On a fixed L1 state, the next block is a header made up as
    /// the direct child of the one the zone last imported, at the zone block's timestamp.
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
        let tempo = match &self.l1 {
            L1::State { .. } => TempoHeader {
                inner: Header {
                    number: number + 1,
                    parent_hash,
                    timestamp: header.inner.timestamp,
                    ..Default::default()
                },
                timestamp_millis_part: header.timestamp_millis_part,
                ..Default::default()
            },
            L1::Chain(chain) => usize::try_from(number + 1)
                .ok()
                .and_then(|next| chain.anchors.get(next))
                .ok_or_else(|| BlockValidationError::msg("no Tempo block to advance to"))?
                .header()
                .clone(),
        };
        Ok(vec![build_advance_tempo_tx_from_parts(
            &tempo,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            self.chain_id(evm),
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

    fn check_step<C: EvmConfig>(&self, state: &StepState<'_, C>, report: &mut Report) {
        self.accounts.check(&self.l1, state, report);
    }

    /// The sequencer leaves out the transactions the zone rejects.
    fn skips_invalid_txs(&self) -> bool {
        true
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

/// The Tempo L1 a zone reads.
#[derive(Debug, Clone)]
pub enum L1 {
    /// The same storage at every block.
    State {
        storage: Arc<BTreeMap<(Address, B256), B256>>,
        commitments: Arc<BTreeMap<Address, B256>>,
    },
    /// A Tempo chain the harness executed, read at each block.
    Chain(Arc<L1Chain>),
}

/// A Tempo chain the harness executed, which a zone reads.
#[derive(Debug)]
pub struct L1Chain {
    /// The genesis, then each block that applied, by number.
    pub(crate) anchors: Vec<Anchor>,
    /// The chain's EVM configuration, to read its state with view calls.
    pub(crate) evm_config: tempo_evm::TempoEvmConfig,
}

impl L1 {
    /// The L1 `input` describes: the same storage at every block.
    pub fn state(input: &L1StateInput) -> Self {
        let storage = input
            .storage
            .iter()
            .flat_map(|(account, slots)| {
                slots
                    .iter()
                    .map(|(slot, value)| ((*account, B256::from(*slot)), B256::from(*value)))
            })
            .collect();
        Self::State {
            storage: Arc::new(storage),
            commitments: Arc::new(input.commitments.clone()),
        }
    }

    /// A Tempo chain's `anchors`, from its genesis, read with view calls on `evm_config`.
    pub fn chain(anchors: Vec<Anchor>, evm_config: tempo_evm::TempoEvmConfig) -> Self {
        assert!(!anchors.is_empty(), "a Tempo chain has a genesis");
        Self::Chain(Arc::new(L1Chain {
            anchors,
            evm_config,
        }))
    }

    /// The Tempo block `number` of a chain, or the reason it has none.
    fn anchor(&self, number: u64) -> Result<Option<&Anchor>, String> {
        match self {
            Self::State { .. } => Ok(None),
            Self::Chain(chain) => usize::try_from(number)
                .ok()
                .and_then(|number| chain.anchors.get(number))
                .map(Some)
                .ok_or_else(|| "no such Tempo block".to_string()),
        }
    }
}

impl L1StorageReader for L1 {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let unavailable = |reason| L1StateError::StorageUnavailable {
            account,
            slot,
            block_number,
            reason,
        };
        match self {
            Self::State { storage, .. } => {
                Ok(storage.get(&(account, slot)).copied().unwrap_or_default())
            }
            Self::Chain(_) => {
                let anchor = self.anchor(block_number).map_err(unavailable)?;
                Ok(anchor.expect("a chain has blocks").storage(&account, slot))
            }
        }
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        block_number: u64,
    ) -> Result<B256, L1StateError> {
        let unavailable = |reason| L1StateError::AccountUnavailable {
            account,
            block_number,
            reason,
        };
        match self {
            Self::State { commitments, .. } => {
                Ok(commitments.get(&account).copied().unwrap_or_default())
            }
            Self::Chain(_) => {
                let anchor = self
                    .anchor(block_number)
                    .map_err(unavailable)?
                    .expect("a chain has blocks");
                match anchor.account(&account) {
                    Some(info) => account_config_commitment(info, anchor.spec())
                        .map_err(|err| unavailable(err.to_string())),
                    None => Ok(B256::ZERO),
                }
            }
        }
    }
}
