//! Native `TempoState` precompile.
//!
//! Replaces the Solidity TempoState predeploy at `0x1c00...0000` while
//! preserving the zone-facing checkpoint ABI.

use alloc::format;

use crate::{
    ZoneResult,
    storage::{L1State, L1StorageReader},
};
use alloy_consensus::BlockHeader;
use alloy_evm::precompiles::DynPrecompile;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_rlp::Decodable as _;
use alloy_sol_types::SolError;
use revm::precompile::PrecompileResult;
use tempo_precompiles::{
    EncodePrecompileResult, charge_input_cost, dispatch, error::TempoPrecompileError,
    storage::Handler, view,
};
use tempo_precompiles_macros::contract;
use tempo_primitives::TempoHeader;
use tempo_contracts::zones::{StaticCallNotAllowed, TempoState as TempoStateAbi, TempoStateError};
use zone_primitives::constants::{
    MAX_TEMPO_HEADERS_PER_ZONE_BLOCK, TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS,
};

#[contract(addr = TEMPO_STATE_ADDRESS)]
pub struct TempoState {
    tempo_block_hash: B256,
    pub(crate) tempo_block_number: u64,
}

/// Storage slot containing the finalized Tempo block number in Zone state.
pub const TEMPO_BLOCK_NUMBER_SLOT: alloy_primitives::U256 = slots::TEMPO_BLOCK_NUMBER;

impl TempoState {
    /// Creates the direct-call-only `TempoState` precompile with checkpoint storage.
    ///
    /// The shared L1 storage state is anchored by this precompile's finalized checkpoint.
    pub fn create<P: L1StorageReader>(
        l1: L1State<P>,
        env: &crate::ZonePrecompileEnv,
    ) -> DynPrecompile {
        crate::execution::create_precompile(
            "TempoState",
            env,
            crate::execution::NoCallRules,
            move |data, caller| Self::new().call_with_l1_state(&l1, data, caller),
        )
    }

    /// Initializes the predeploy account code and checkpoint from the genesis Tempo header.
    pub fn initialize(&mut self, header_rlp: &[u8]) -> tempo_precompiles::Result<()> {
        self.__initialize()?;
        let mut cursor = header_rlp;
        let header = TempoHeader::decode(&mut cursor).map_err(|err| {
            TempoPrecompileError::Fatal(format!("invalid Tempo genesis header RLP: {err}"))
        })?;
        if !cursor.is_empty() {
            return Err(TempoPrecompileError::Fatal(
                "invalid Tempo genesis header RLP: trailing bytes after header".into(),
            ));
        }
        self.write_checkpoint(keccak256(header_rlp), header.number())?;
        Ok(())
    }

    fn write_checkpoint(
        &mut self,
        block_hash: B256,
        block_number: u64,
    ) -> tempo_precompiles::Result<()> {
        self.tempo_block_hash.write(block_hash)?;
        self.tempo_block_number.write(block_number)?;
        Ok(())
    }

    fn revert_error<E: SolError>(&self, error: E) -> PrecompileResult {
        Ok(self.storage.revert_output(error.abi_encode().into()))
    }

    /// Validate and apply a finalized Tempo checkpoint transition.
    ///
    /// IMPORTANT: this operation only enforces local continuity and Zone-time alignment. The
    /// first header must directly extend the stored Tempo checkpoint, and every subsequent header
    /// must directly extend the preceding header. The final Tempo timestamp is a lower bound for
    /// the Zone block timestamp.
    ///
    /// Canonicality is a separate proof obligation: the batch proof must bind the imported header
    /// hash and state root to the canonical settlement anchor and authenticate every Tempo storage
    /// read against that exact root.
    ///
    /// This typed operation is shared by the public `finalizeTempo` ABI and the native Inbox.
    pub(crate) fn finalize_checkpoints<P>(
        &mut self,
        l1: &L1State<P>,
        headers: &[Bytes],
    ) -> ZoneResult<()> {
        if headers.is_empty() || headers.len() > MAX_TEMPO_HEADERS_PER_ZONE_BLOCK {
            return Err(TempoStateError::invalid_rlp_data().into());
        }

        let initial_block_number = self.tempo_block_number.read()?;
        let mut previous_block_number = initial_block_number;
        let mut previous_block_hash = self.tempo_block_hash.read()?;
        if previous_block_hash.is_zero() {
            return Err(TempoStateError::invalid_parent_hash().into());
        }
        let mut final_state_root = B256::ZERO;
        let mut final_timestamp = 0;
        let mut final_timestamp_millis_part = 0;

        for header_rlp in headers {
            let header: TempoHeader = alloy_rlp::decode_exact(header_rlp)
                .map_err(|_| TempoStateError::invalid_rlp_data())?;
            if header.parent_hash() != previous_block_hash {
                return Err(TempoStateError::invalid_parent_hash().into());
            }
            if previous_block_number.checked_add(1) != Some(header.number()) {
                return Err(TempoStateError::invalid_block_number().into());
            }
            previous_block_hash = keccak256(header_rlp);
            previous_block_number = header.number();
            final_state_root = header.state_root();
            final_timestamp = header.timestamp();
            final_timestamp_millis_part = header.timestamp_millis_part;
        }

        self.storage.with_block_env(|zone_block| {
            let final_timestamp_millis = U256::from(final_timestamp)
                .saturating_mul(U256::from(1000))
                .saturating_add(U256::from(final_timestamp_millis_part));
            if zone_block.timestamp_millis() < final_timestamp_millis {
                return Err(TempoStateError::invalid_timestamp());
            }
            Ok(())
        })?;

        l1.advance_anchor(initial_block_number, previous_block_number)?;
        self.write_checkpoint(previous_block_hash, previous_block_number)?;
        self.emit_event(TempoStateAbi::TempoBlockFinalized {
            blockHash: previous_block_hash,
            blockNumber: previous_block_number,
            stateRoot: final_state_root,
        })?;
        Ok(())
    }

    fn apply_checkpoints<P>(
        &mut self,
        l1: &L1State<P>,
        sender: Address,
        headers: &[Bytes],
    ) -> PrecompileResult {
        if self.storage.is_static() {
            return self.revert_error(StaticCallNotAllowed {});
        }
        if sender != ZONE_INBOX_ADDRESS {
            return self.revert_error(TempoStateAbi::OnlyZoneInbox {});
        }

        self.finalize_checkpoints(l1, headers)
            .encode_precompile_result(0, 0, |()| Bytes::new())
    }

    /// Returns the currently finalized Tempo block number from Zone state.
    pub fn tempo_block_number(&mut self) -> tempo_precompiles::Result<u64> {
        self.tempo_block_number.read()
    }

    /// Returns the currently finalized Tempo block hash from Zone state.
    pub fn tempo_block_hash(&mut self) -> tempo_precompiles::Result<B256> {
        self.tempo_block_hash.read()
    }

    /// Dispatch a `TempoState` call using execution-local L1 state.
    pub(crate) fn call_with_l1_state<P: L1StorageReader>(
        &mut self,
        l1: &L1State<P>,
        calldata: &[u8],
        msg_sender: Address,
    ) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                TempoStateAbi::TempoStateCalls {
                    tempoBlockHash(call) => view(call, |_| self.tempo_block_hash.read()),
                    tempoBlockNumber(call) => view(call, |_| self.tempo_block_number.read()),
                    #[schedule(until = T13)]
                    finalizeTempo_0(call) => {
                        self.apply_checkpoints(l1, msg_sender, core::slice::from_ref(&call.header))
                    },
                    #[schedule(since = T13)]
                    finalizeTempo_1(call) => {
                        self.apply_checkpoints(l1, msg_sender, &call.headers)
                    },
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use crate::test_utils::{
        MockL1Reader, TestContext, call_precompile, test_context, test_context_with_hardfork,
        test_env, test_storage_provider,
    };
    use alloc::{vec, vec::Vec};
    use alloy_consensus::Sealable as _;
    use alloy_evm::precompiles::DynPrecompile;
    use alloy_primitives::address;
    use alloy_sol_types::SolCall;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::storage::StorageCtx;
    use tempo_contracts::zones::{finalizeTempoCall, legacyFinalizeTempoCall};

    struct TempoStateHarness {
        ctx: TestContext,
        l1: L1State<MockL1Reader>,
        precompile: DynPrecompile,
    }

    impl TempoStateHarness {
        fn new(header: &TempoHeader) -> eyre::Result<Self> {
            Self::new_with_context(header, test_context())
        }

        fn new_with_hardfork(header: &TempoHeader, hardfork: TempoHardfork) -> eyre::Result<Self> {
            Self::new_with_context(header, test_context_with_hardfork(hardfork))
        }

        fn new_with_context(header: &TempoHeader, mut ctx: TestContext) -> eyre::Result<Self> {
            let encoded = alloy_rlp::encode(header);
            {
                let mut storage = test_storage_provider(&mut ctx, u64::MAX, false);
                StorageCtx::enter(&mut storage, || TempoState::new().initialize(&encoded))?;
            }
            let l1 = L1State::new(MockL1Reader::default(), Address::ZERO);
            let precompile = TempoState::create(l1.clone(), &test_env(&ctx));
            Ok(Self {
                ctx,
                l1,
                precompile,
            })
        }

        fn set_block_timestamp(&mut self, header: &TempoHeader) {
            self.ctx.block.inner.timestamp = U256::from(header.timestamp());
            self.ctx.block.timestamp_millis_part = header.timestamp_millis_part;
        }

        fn call(
            &mut self,
            caller: Address,
            calldata: impl Into<Bytes>,
            is_static: bool,
        ) -> PrecompileResult {
            self.call_as(
                caller,
                calldata,
                is_static,
                TEMPO_STATE_ADDRESS,
                TEMPO_STATE_ADDRESS,
            )
        }

        fn call_as(
            &mut self,
            caller: Address,
            calldata: impl Into<Bytes>,
            is_static: bool,
            target: Address,
            bytecode_address: Address,
        ) -> PrecompileResult {
            let calldata = calldata.into();
            call_precompile(
                &mut self.ctx,
                &self.precompile,
                caller,
                &calldata,
                u64::MAX,
                is_static,
                target,
                bytecode_address,
            )
        }

        fn finalize_raw(
            &mut self,
            caller: Address,
            header: Bytes,
            is_static: bool,
        ) -> PrecompileResult {
            let data = finalizeTempoCall {
                headers: vec![header],
            }
            .abi_encode();
            self.call(caller, data, is_static)
        }

        fn finalize_many(&mut self, caller: Address, headers: Vec<Bytes>) -> PrecompileResult {
            let data = finalizeTempoCall { headers }.abi_encode();
            self.call(caller, data, false)
        }

        fn finalize_legacy(
            &mut self,
            caller: Address,
            header: &TempoHeader,
            is_static: bool,
        ) -> PrecompileResult {
            self.call(
                caller,
                legacyFinalizeTempoCall {
                    header: alloy_rlp::encode(header).into(),
                }
                .abi_encode(),
                is_static,
            )
        }

        fn finalize(
            &mut self,
            caller: Address,
            header: &TempoHeader,
            is_static: bool,
        ) -> PrecompileResult {
            self.finalize_raw(caller, alloy_rlp::encode(header).into(), is_static)
        }

        fn assert_checkpoint(
            &mut self,
            expected_hash: B256,
            expected_number: u64,
        ) -> eyre::Result<()> {
            let hash_call = TempoStateAbi::tempoBlockHashCall {};
            let block_hash = self.call(Address::ZERO, hash_call.abi_encode(), true)?;
            assert_eq!(
                TempoStateAbi::tempoBlockHashCall::abi_decode_returns(&block_hash.bytes)?,
                expected_hash
            );

            let number_call = TempoStateAbi::tempoBlockNumberCall {};
            let block_number = self.call(Address::ZERO, number_call.abi_encode(), true)?;
            assert_eq!(
                TempoStateAbi::tempoBlockNumberCall::abi_decode_returns(&block_number.bytes)?,
                expected_number
            );
            Ok(())
        }
    }

    fn child_header(parent_hash: B256, number: u64) -> TempoHeader {
        TempoHeader {
            general_gas_limit: 1_000_000,
            shared_gas_limit: 2_000_000,
            timestamp_millis_part: 123,
            inner: alloy_consensus::Header {
                parent_hash,
                beneficiary: address!("0x000000000000000000000000000000000000bEEF"),
                state_root: B256::repeat_byte(0x11),
                transactions_root: B256::repeat_byte(0x22),
                receipts_root: B256::repeat_byte(0x33),
                number,
                gas_limit: 30_000_000,
                gas_used: 21_000,
                timestamp: 1_700_000_000,
                mix_hash: B256::repeat_byte(0x44),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn initialize_sets_checkpoint() -> eyre::Result<()> {
        let header = child_header(B256::repeat_byte(0xaa), 42);
        let mut harness = TempoStateHarness::new(&header)?;
        harness.assert_checkpoint(header.hash_slow(), 42)
    }

    #[test]
    fn finalize_tempo_updates_checkpoint() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);
        harness.set_block_timestamp(&child);

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_success());
        harness.assert_checkpoint(child.hash_slow(), 1)
    }

    #[test]
    fn finalize_tempo_selectors_switch_at_t13() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T12, TempoHardfork::T13] {
            let genesis = TempoHeader::default();
            let genesis_hash = genesis.hash_slow();
            let mut harness = TempoStateHarness::new_with_hardfork(&genesis, hardfork)?;
            let child = child_header(genesis_hash, 1);
            harness.set_block_timestamp(&child);

            let retired = if hardfork == TempoHardfork::T12 {
                harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?
            } else {
                harness.finalize_legacy(ZONE_INBOX_ADDRESS, &child, false)?
            };
            assert!(retired.is_revert());
            harness.assert_checkpoint(genesis_hash, genesis.number())?;

            let active = if hardfork == TempoHardfork::T12 {
                harness.finalize_legacy(ZONE_INBOX_ADDRESS, &child, false)?
            } else {
                harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?
            };
            assert!(active.is_success());
            harness.assert_checkpoint(child.hash_slow(), 1)?;
        }
        Ok(())
    }

    #[test]
    fn legacy_finalize_tempo_works_before_t13() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new_with_hardfork(&genesis, TempoHardfork::T12)?;
        let child = child_header(genesis_hash, 1);
        harness.set_block_timestamp(&child);

        let output = harness.finalize_legacy(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_success());
        harness.assert_checkpoint(child.hash_slow(), 1)
    }

    #[test]
    fn finalize_tempo_accepts_consecutive_header_range() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut first = child_header(genesis_hash, 1);
        let first_hash = first.hash_slow();
        let second = child_header(first_hash, 2);
        first.inner.timestamp = second.inner.timestamp;
        first.timestamp_millis_part = second.timestamp_millis_part;

        let mut harness = TempoStateHarness::new(&genesis)?;
        harness.set_block_timestamp(&second);
        let output = harness.finalize_many(
            ZONE_INBOX_ADDRESS,
            vec![
                alloy_rlp::encode(&first).into(),
                alloy_rlp::encode(&second).into(),
            ],
        )?;
        assert!(output.is_success());
        harness.assert_checkpoint(second.hash_slow(), 2)
    }

    #[test]
    fn finalize_tempo_accepts_later_zone_timestamp() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);
        harness.set_block_timestamp(&child);
        harness.ctx.block.inner.timestamp += U256::ONE;

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_success());
        harness.assert_checkpoint(child.hash_slow(), 1)
    }

    #[test]
    fn finalize_tempo_reverts_on_earlier_zone_timestamp_seconds() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);
        harness.set_block_timestamp(&child);
        harness.ctx.block.inner.timestamp -= U256::ONE;

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_revert());
        assert_eq!(
            output.bytes,
            TempoStateAbi::InvalidTimestamp {}.abi_encode()
        );
        assert_eq!(harness.l1.get_anchor(), None);
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_on_earlier_zone_timestamp_millis() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);
        harness.set_block_timestamp(&child);
        harness.ctx.block.timestamp_millis_part -= 1;

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_revert());
        assert_eq!(
            output.bytes,
            TempoStateAbi::InvalidTimestamp {}.abi_encode()
        );
        assert_eq!(harness.l1.get_anchor(), None);
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_for_non_inbox_caller() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);

        assert!(harness.finalize(Address::ZERO, &child, false)?.is_revert());
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn delegate_call_reverts() -> eyre::Result<()> {
        let mut harness = TempoStateHarness::new(&TempoHeader::default())?;
        let output = harness.call_as(
            Address::ZERO,
            TempoStateAbi::tempoBlockHashCall {}.abi_encode(),
            true,
            TEMPO_STATE_ADDRESS,
            address!("0x000000000000000000000000000000000000dEaD"),
        )?;

        assert!(output.is_revert());
        assert_eq!(output.gas_used, 0);
        Ok(())
    }

    #[test]
    fn finalize_tempo_reverts_on_static_call() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 1);

        assert!(
            harness
                .finalize(ZONE_INBOX_ADDRESS, &child, true)?
                .is_revert()
        );
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_on_invalid_rlp() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;

        let output = harness.finalize_raw(ZONE_INBOX_ADDRESS, Bytes::from(vec![0xff]), false)?;
        assert!(output.is_revert());
        assert_eq!(output.bytes, TempoStateAbi::InvalidRlpData {}.abi_encode());
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_on_trailing_header_bytes() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let mut malformed = alloy_rlp::encode(child_header(genesis_hash, 1));
        malformed.push(0);

        let output = harness.finalize_raw(ZONE_INBOX_ADDRESS, Bytes::from(malformed), false)?;
        assert!(output.is_revert());
        assert_eq!(output.bytes, TempoStateAbi::InvalidRlpData {}.abi_encode());
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_on_invalid_parent_hash() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(B256::ZERO, 1);
        harness.set_block_timestamp(&child);

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_revert());
        assert_eq!(
            output.bytes,
            TempoStateAbi::InvalidParentHash {}.abi_encode()
        );
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }

    #[test]
    fn finalize_tempo_reverts_on_invalid_block_number() -> eyre::Result<()> {
        let genesis = TempoHeader::default();
        let genesis_hash = genesis.hash_slow();
        let mut harness = TempoStateHarness::new(&genesis)?;
        let child = child_header(genesis_hash, 2);
        harness.set_block_timestamp(&child);

        let output = harness.finalize(ZONE_INBOX_ADDRESS, &child, false)?;
        assert!(output.is_revert());
        assert_eq!(
            output.bytes,
            TempoStateAbi::InvalidBlockNumber {}.abi_encode()
        );
        harness.assert_checkpoint(genesis_hash, genesis.number())
    }
}
