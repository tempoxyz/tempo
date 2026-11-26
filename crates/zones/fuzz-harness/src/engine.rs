//! The zone [`Engine`]: a zone's chain spec, EVM and consensus, its genesis, and the system
//! transactions its sequencer opens and closes every block with.

use std::sync::{Arc, LazyLock};

use alloy_consensus::{Header, SignableTransaction as _, TxLegacy, transaction::Recovered};
use alloy_genesis::Genesis;
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;
use evm2::evm::{Cache, SystemTx};
use reth_evm::{BlockExecutionError, BlockValidationError};
use tempo_chainspec::{TempoChainSpec, hardfork::TempoHardfork};
use tempo_contracts::{
    precompiles::{IAccountKeychain, INonce, IStorageCredits, ITIP20},
    zones::{IZoneInbox, IZoneOutbox, tempo_state::TempoState},
};
use tempo_evm::TempoEvm;
use tempo_fuzz_engine::{Chain, Engine, Rejection, chain_spec_on, genesis_cache};
use tempo_fuzz_types::{ChainSpecInput, ErrorClass, HarnessInputKind};
use tempo_precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS, NONCE_PRECOMPILE_ADDRESS, STORAGE_CREDITS_ADDRESS,
    tip20::is_tip20_prefix,
};
use tempo_primitives::{
    TempoHeader, TempoTxEnvelope,
    transaction::envelope::{TEMPO_SYSTEM_TX_SENDER, TEMPO_SYSTEM_TX_SIGNATURE},
};
use zone_chainspec::ZoneChainSpec;
use zone_evm::ZoneEvmConfig;
use zone_precompiles::{
    L1StateError, L1StorageReader, ecies::AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE,
};
use zone_primitives::constants::{
    TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS, decode_zone_chain_id,
};

use crate::{consensus::ZoneConsensus, types::L1StateInput};

/// The zone genesis the node ships, which every zone input's chain starts from.
const GENESIS_JSON: &str = include_str!("../../node/assets/zone-dev-genesis.json");

pub(crate) static GENESIS: LazyLock<Genesis> =
    LazyLock::new(|| serde_json::from_str(GENESIS_JSON).expect("the zone genesis parses"));

/// The zone genesis allocation, seeded once per process, as the Tempo harness seeds its own.
static GENESIS_STATE: LazyLock<Cache> = LazyLock::new(|| genesis_cache(&GENESIS));

/// The zone genesis's chain spec.
static GENESIS_SPEC: LazyLock<TempoChainSpec> =
    LazyLock::new(|| TempoChainSpec::from_genesis(GENESIS.clone()));

/// A zone reading `l1`, executed as its node executes it.
#[derive(Debug, Clone)]
pub struct Zone {
    l1: L1,
}

impl Zone {
    /// A zone that reads `l1` at every anchor.
    pub fn new(l1: L1StateInput) -> Self {
        Self {
            l1: L1(Arc::new(l1)),
        }
    }
}

impl Engine for Zone {
    type ChainSpec = ZoneChainSpec;
    type EvmConfig = ZoneEvmConfig<L1>;
    type Consensus = ZoneConsensus;

    const IMPLEMENTATION: &'static str = "tempo-zone";
    const HARDFORKS: &'static [TempoHardfork] = TempoHardfork::VARIANTS
        .split_at(TempoHardfork::T13 as usize)
        .1;
    const INPUTS: &'static [HarnessInputKind] =
        &[HarnessInputKind::State, HarnessInputKind::Blockchain];
    const FEE_AMM: Option<Address> = None;
    const DEX: Option<Address> = None;

    fn chain(&self, input: &ChainSpecInput) -> Result<Chain<Self>, Rejection> {
        let (_, zone_id) = decode_zone_chain_id(input.chain_id)
            .map_err(|err| Rejection::new(ErrorClass::InvalidInput, err))?;
        let mut spec = chain_spec_on(GENESIS_SPEC.clone(), input)?;
        spec.inner.genesis.config.chain_id = input.chain_id;
        let spec = Arc::new(ZoneChainSpec {
            inner: Arc::new(spec),
        });
        let portal = tempo_precompiles::zone_factory::portal_address(zone_id);
        Ok(Chain {
            spec: Arc::clone(&spec),
            evm_config: ZoneEvmConfig::new(Arc::clone(&spec), self.l1.clone(), portal),
            consensus: ZoneConsensus::new(spec),
        })
    }

    fn genesis(&self) -> &Cache {
        &GENESIS_STATE
    }

    /// First argument of an account-scoped getter, which every one takes as the account it reads.
    /// These are the getters zone-precompiles' read rules (`check_caller`) restrict to.
    fn view_caller(&self, target: Address, input: &[u8]) -> Address {
        let scoped: &[[u8; 4]] = match target {
            _ if is_tip20_prefix(target) => &[
                ITIP20::balanceOfCall::SELECTOR,
                ITIP20::allowanceCall::SELECTOR,
                ITIP20::noncesCall::SELECTOR,
            ],
            NONCE_PRECOMPILE_ADDRESS => &[INonce::getNonceCall::SELECTOR],
            ACCOUNT_KEYCHAIN_ADDRESS => &[
                IAccountKeychain::getKeyCall::SELECTOR,
                IAccountKeychain::getRemainingLimitCall::SELECTOR,
                IAccountKeychain::getRemainingLimitWithPeriodCall::SELECTOR,
                IAccountKeychain::getAllowedCallsCall::SELECTOR,
                IAccountKeychain::isKeyAuthorizationWitnessBurnedCall::SELECTOR,
                IAccountKeychain::isAdminKeyCall::SELECTOR,
            ],
            STORAGE_CREDITS_ADDRESS => &[
                IStorageCredits::balanceOfCall::SELECTOR,
                IStorageCredits::modeOfCall::SELECTOR,
                IStorageCredits::budgetOfCall::SELECTOR,
            ],
            _ => return Address::ZERO,
        };
        match input.split_first_chunk::<4>() {
            Some((selector, args)) if scoped.contains(selector) => {
                args.first_chunk::<32>().map_or(Address::ZERO, |account| {
                    Address::from_word(B256::from(*account))
                })
            }
            _ => Address::ZERO,
        }
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
        )?
        .checked_add(1)
        .ok_or_else(|| BlockValidationError::msg("the next Tempo block number overflows"))?;
        let tempo = TempoHeader {
            inner: Header {
                number,
                parent_hash,
                timestamp: header.inner.timestamp,
                ..Default::default()
            },
            timestamp_millis_part: header.timestamp_millis_part,
            ..Default::default()
        };
        Ok(vec![advance_tempo_tx(&tempo, evm.version().chain_id)])
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
        // The sequencer encrypts each sender to its withdrawal's `revealTo` key. Zone execution
        // checks only the ciphertext's length, so zeros of that length stand in for it.
        let encrypted_senders = pending
            .iter()
            .map(|withdrawal| match withdrawal.revealTo.is_empty() {
                true => Bytes::new(),
                false => Bytes::from(vec![0; AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE]),
            })
            .collect();
        let call = IZoneOutbox::finalizeWithdrawalBatchCall {
            count: U256::from(pending.len()),
            blockNumber: header.inner.number,
            encryptedSenders: encrypted_senders,
        };
        Ok(vec![system_tx(
            evm.version().chain_id,
            ZONE_OUTBOX_ADDRESS,
            call.abi_encode(),
        )])
    }
}

/// Tempo L1 as an input describes it: the same storage at every block.
#[derive(Debug, Clone)]
pub struct L1(Arc<L1StateInput>);

impl L1StorageReader for L1 {
    fn read_l1_storage(
        &self,
        account: Address,
        slot: B256,
        _block_number: u64,
    ) -> Result<B256, L1StateError> {
        let value = self
            .0
            .storage
            .get(&account)
            .and_then(|slots| slots.get(&U256::from_be_bytes(slot.0)));
        Ok(value.copied().map(B256::from).unwrap_or_default())
    }

    fn read_l1_commitment(
        &self,
        account: Address,
        _block_number: u64,
    ) -> Result<B256, L1StateError> {
        Ok(self
            .0
            .commitments
            .get(&account)
            .copied()
            .unwrap_or_default())
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

/// The `advanceTempo` system transaction importing `tempo` with no deposits, decryptions or newly
/// enabled tokens, as the sequencer builds it.
fn advance_tempo_tx(tempo: &TempoHeader, chain_id: u64) -> Recovered<TempoTxEnvelope> {
    let call = IZoneInbox::advanceTempoCall {
        header: alloy_rlp::encode(tempo).into(),
        deposits: Vec::new(),
        decryptions: Vec::new(),
        enabledTokens: Vec::new(),
    };
    system_tx(chain_id, ZONE_INBOX_ADDRESS, call.abi_encode())
}

/// A system transaction calling `to` with `input`, as the sequencer builds them.
fn system_tx(chain_id: u64, to: Address, input: Vec<u8>) -> Recovered<TempoTxEnvelope> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use tempo_contracts::precompiles::PATH_USD_ADDRESS;
    use test_case::test_case;

    const OWNER: Address = address!("0000000000000000000000000000000000001111");
    const OTHER: Address = address!("0000000000000000000000000000000000002222");

    #[test_case(PATH_USD_ADDRESS, ITIP20::balanceOfCall { account: OWNER }.abi_encode() => OWNER)]
    #[test_case(PATH_USD_ADDRESS, ITIP20::totalSupplyCall {}.abi_encode() => Address::ZERO)]
    #[test_case(ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain::getKeyCall { account: OWNER, keyId: OTHER }.abi_encode() => OWNER)]
    fn views_run_as_the_account_a_scoped_getter_reads(target: Address, data: Vec<u8>) -> Address {
        Zone::new(L1StateInput::default()).view_caller(target, &data)
    }
}
