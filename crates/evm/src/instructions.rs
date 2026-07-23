//! Tempo opcode overrides.

use alloy_primitives::{Address, U256};
use evm2::{
    EvmFeatures,
    evm::{SLoad, SStore},
    interpreter::{Gas, GasTracker, Host, InstrStop, InterpreterState, Result},
    version::{GasId, GasParams},
};
use evm2_macros::instruction;
use tempo_precompiles::storage_credits::{StorageCreditsBackend, sstore_storage_credits};

use crate::TempoEvmTypes;

/// Opcode returning the block timestamp in milliseconds before T1C.
#[instruction(EvmTypes = TempoEvmTypes, dynamic_gas)]
pub fn millis_timestamp(cx: _) -> Result<out> {
    if cx.state.host().config_spec_id().is_t1c() {
        return Err(InstrStop::InvalidOpcode);
    }
    cx.gas.spend(2)?;
    let block = cx.state.host().block_env();
    *out = block.ext.timestamp_millis(block.timestamp);
}

struct StorageCreditsContext<'a, 'state, 'host> {
    gas: &'a mut Gas,
    state: &'a mut InterpreterState<'state, 'host, TempoEvmTypes>,
}

impl StorageCreditsBackend for StorageCreditsContext<'_, '_, '_> {
    type Error = InstrStop;

    fn gas_params(&self) -> &GasParams {
        self.state.gas_params()
    }

    fn gas_tracker(&mut self) -> &mut GasTracker {
        self.gas.tracker_mut()
    }

    fn sload(
        &mut self,
        address: Address,
        key: U256,
        skip_cold_load: bool,
    ) -> Result<SLoad, Self::Error> {
        self.state.host().sload(&address, &key, skip_cold_load)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
        skip_cold_load: bool,
    ) -> Result<SStore, Self::Error> {
        self.state
            .host()
            .sstore(&address, &key, &value, skip_cold_load)
    }

    fn tload(&mut self, address: Address, key: U256) -> U256 {
        self.state.host().tload(&address, &key)
    }

    fn tstore(&mut self, address: Address, key: U256, value: U256) {
        self.state.host().tstore(&address, &key, &value);
    }
}

/// SSTORE with Tempo's TIP-1060 storage-credit accounting.
#[instruction(EvmTypes = TempoEvmTypes, dynamic_gas)]
pub fn sstore(cx: _, [key, value]: [Word]) -> Result {
    if cx.state.is_static() {
        return Err(InstrStop::StateChangeDuringStaticCall);
    }

    let is_eip2200 = cx.state.feature(EvmFeatures::EIP2200);
    if is_eip2200 && cx.gas.remaining() <= u64::from(cx.state.gas_params().get(GasId::CallStipend))
    {
        return Err(InstrStop::ReentrancySentryOOG);
    }

    cx.gas
        .spend(cx.state.gas_params().get(GasId::SstoreStatic).into())?;

    let skip_cold_load = cx.state.feature(EvmFeatures::EIP2929)
        && cx.gas.remaining()
            < u64::from(cx.state.gas_params().get(GasId::ColdStorageAdditionalCost));
    let destination = cx.state.message().destination;
    let state_load = cx
        .state
        .host()
        .sstore(&destination, key, value, skip_cold_load)?;

    if cx.state.host().config_spec_id().is_t7() {
        sstore_storage_credits(
            &mut StorageCreditsContext {
                gas: cx.gas,
                state: cx.state,
            },
            destination,
            None,
            &state_load,
        )?;
    }

    cx.gas.spend(
        cx.state
            .gas_params()
            .sstore_dynamic_gas(is_eip2200, &state_load),
    )?;

    if cx.state.feature(EvmFeatures::EIP8037) {
        cx.gas
            .spend_state(cx.state.gas_params().sstore_state_gas(&state_load))?;
        cx.gas
            .refill_reservoir(cx.state.gas_params().sstore_state_gas_refill(&state_load));
    }

    cx.gas
        .record_refund(cx.state.gas_params().sstore_refund(is_eip2200, &state_load));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TempoBlockEnv, TempoEvmExt, TempoTxEnv, build_tempo_evm};
    use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Bytes, Signature, TxKind};
    use evm2::{
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB, precompile::NoPrecompiles},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_precompiles::{STORAGE_CREDITS_ADDRESS, storage_credits::StorageCredits};
    use tempo_primitives::TempoTxEnvelope;

    #[test]
    fn sstore_consumes_tip1060_storage_credit() {
        let caller = Address::repeat_byte(0x11);
        let contract = Address::repeat_byte(0x22);
        let credit_slot = StorageCredits::slot(contract);
        let mut database = InMemoryDB::default();
        database.insert_account_info(
            &contract,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[
                0x60, 0x01, // PUSH1 1
                0x60, 0x00, // PUSH1 0
                0x55, // SSTORE
                0x00, // STOP
            ]))),
        );
        database.insert_account_storage(&STORAGE_CREDITS_ADDRESS, &credit_slot, &U256::ONE);

        let mut evm = build_tempo_evm(
            TempoHardfork::T7,
            1,
            TempoBlockEnv::default(),
            database,
            NoPrecompiles::default(),
            TempoEvmExt::default(),
        );
        let tx = TempoTxEnv::from(Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(1),
                    nonce: 0,
                    gas_price: 0,
                    gas_limit: 1_000_000,
                    to: TxKind::Call(contract),
                    ..TxLegacy::default()
                },
                Signature::test_signature(),
            )),
            caller,
        ));

        let result = evm
            .transact(&Recovered::new_unchecked(tx, caller))
            .unwrap()
            .commit();
        assert!(result.status);
        assert_eq!(
            evm.sload(&STORAGE_CREDITS_ADDRESS, &credit_slot, false)
                .unwrap()
                .value,
            U256::ZERO,
        );
        assert_eq!(
            evm.sload(&contract, &U256::ZERO, false).unwrap().value,
            U256::ONE,
        );
    }
}
