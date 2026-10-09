//! Executes the draft through Tempo's actual opcode configuration and system entry.

use crate::{TempoBlockEnv, TempoEvmConfig, TempoEvmEnv};
use alloy_primitives::{Address, Bytes, U256};
use evm2::{
    bytecode::{Bytecode, code_metadata},
    evm::{AccountInfo, InMemoryDB, SystemTx},
};
use reth_evm::BlockExecutorFactory;
use tempo_chainspec::TempoHardfork;

#[test]
fn jump_and_taken_jumpi_enter_replacement_prefix_through_tempo() {
    const STRIDE: usize = 24_541;
    let contract = Address::repeat_byte(0x83);
    for conditional in [false, true] {
        let target = (STRIDE + 5) as u32;
        let mut raw = vec![0; STRIDE + 32];
        let mut entry = vec![];
        if conditional {
            entry.extend_from_slice(&[0x60, 1]);
        }
        entry.push(0x62); // PUSH3 original global target
        entry.extend_from_slice(&target.to_be_bytes()[1..]);
        entry.push(if conditional { 0x57 } else { 0x56 });
        raw[..entry.len()].copy_from_slice(&entry);
        raw[STRIDE - 1] = 0x7f; // PUSH32: leading 32 bytes become valid JUMPDESTs.
        raw[STRIDE..].fill(0xaa);
        raw.extend_from_slice(&[0x60, 42, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3]);
        let code = Bytecode::new_legacy(Bytes::from(raw.clone()));
        let info = AccountInfo {
            code_metadata: code_metadata(&raw).unwrap(),
            ..AccountInfo::default().with_code(code)
        };
        let mut db = InMemoryDB::default();
        db.insert_account_info(&contract, info);
        let spec = TempoHardfork::T13;
        let version = crate::tempo_execution_config(spec, 1)
            .version()
            .with_tip1143(true);
        let mut evm = TempoEvmConfig::moderato().evm_with_env(
            db,
            TempoEvmEnv::new_with_version(spec, TempoBlockEnv::default(), version),
        );
        let result = evm
            .system_call(SystemTx::new(contract, Bytes::new()))
            .unwrap()
            .discard();
        assert!(result.status, "{conditional:?}: {:?}", result.stop);
        assert_eq!(U256::from_be_slice(&result.output), U256::from(42));
    }
}

#[test]
fn generated_and_split_relative_jumps_execute_through_tempo() {
    const STRIDE: usize = 24_541;
    let contract = Address::repeat_byte(0x84);
    for (condition, boundary) in [
        (None, [0x60, 0xab, 0x50]),
        (None, [0xe0, 0x80, 0x80]),
        (Some(0), [0xe1, 0x80, 0x80]),
        (Some(1), [0xe1, 0x80, 0x80]),
    ] {
        let mut raw = vec![0; STRIDE - 1];
        let mut entry = Vec::new();
        if let Some(condition) = condition {
            entry.extend([0x60, condition]);
        }
        entry.extend([0x61, 0x5f, 0xdb, 0x56]);
        raw[..entry.len()].copy_from_slice(&entry);
        raw[STRIDE - 2] = 0x5b;
        raw.extend_from_slice(&boundary);
        raw.extend_from_slice(&[0x60, 42, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3]);
        let code = Bytecode::new_legacy(Bytes::from(raw.clone()));
        let info = AccountInfo {
            code_metadata: code_metadata(&raw).unwrap(),
            ..AccountInfo::default().with_code(code)
        };
        let mut db = InMemoryDB::default();
        db.insert_account_info(&contract, info);
        let spec = TempoHardfork::T13;
        let version = crate::tempo_execution_config(spec, 1)
            .version()
            .with_tip1143(true);
        let mut evm = TempoEvmConfig::moderato().evm_with_env(
            db,
            TempoEvmEnv::new_with_version(spec, TempoBlockEnv::default(), version),
        );
        let result = evm
            .system_call(SystemTx::new(contract, Bytes::new()))
            .unwrap()
            .discard();
        assert!(result.status, "{boundary:?}: {:?}", result.stop);
        assert_eq!(U256::from_be_slice(&result.output), U256::from(42));
    }
}
