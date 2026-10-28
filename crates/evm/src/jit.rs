//! Native EVM2 JIT execution for Tempo.

use crate::{TempoEvmTypes, tempo_execution_config};
use evm2_jit::runtime::HostConfig;
use tempo_chainspec::hardfork::TempoHardfork;

pub use evm2_jit::runtime::{
    JitBackend, JitMode, RuntimeConfig, RuntimeTuning, maybe_run_jit_helper,
};
pub use reth_evm_ethereum::factory::JitMetrics;

/// Returns a JIT runtime configuration for `spec`'s gas schedule and opcode table.
///
/// Compiled code runs Tempo's own instructions for overridden opcodes such as SSTORE, which check
/// the active hardfork at runtime. Frames under another opcode table or gas schedule, and
/// contracts that can reach an opcode Tempo adds, such as MILLISTIMESTAMP, stay on the
/// interpreter.
pub fn runtime_config(spec: TempoHardfork) -> RuntimeConfig {
    let config = tempo_execution_config(spec, 0);
    RuntimeConfig {
        // Keep distinct stop reasons, which transaction results expose.
        single_error: false,
        gas_params: Some(config.version().gas_params),
        host: HostConfig::for_config::<TempoEvmTypes>(&config),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TempoBlockEnv, TempoEvmConfig, TempoEvmEnv, TempoEvmFactory, TempoTxEnv,
        test_utils::test_chainspec,
    };
    use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Address, Bytes, Signature, TxKind, U256};
    use evm2::{
        TxResultWithState,
        bytecode::Bytecode,
        evm::{AccountInfo, InMemoryDB, precompile::NoPrecompiles},
        interpreter::{InstrStop, op},
    };
    use reth_evm::ConfigureEvm;
    use tempo_precompiles::{STORAGE_CREDITS_ADDRESS, storage_credits::StorageCredits};
    use tempo_primitives::{TempoBlockExt, TempoTxEnvelope};

    const CALLER: Address = Address::repeat_byte(0x11);
    const CONTRACT: Address = Address::repeat_byte(0x22);

    /// Returns the word on top of the stack after `code`.
    fn returning_top(code: &[u8]) -> Vec<u8> {
        [
            code,
            &[op::PUSH0, op::MSTORE, op::PUSH1, 32, op::PUSH0, op::RETURN],
        ]
        .concat()
    }

    fn backend(spec: TempoHardfork) -> JitBackend {
        JitBackend::new(RuntimeConfig {
            blocking: true,
            ..runtime_config(spec)
        })
        .unwrap()
    }

    /// Runs a call to `CONTRACT` holding `code`, compiled with `jit` if set.
    fn run(
        spec: TempoHardfork,
        mut db: InMemoryDB,
        code: Vec<u8>,
        jit: Option<&JitBackend>,
    ) -> Result<TxResultWithState<TempoEvmTypes>, String> {
        db.insert_account_info(
            &CONTRACT,
            AccountInfo::default().with_code(Bytecode::new_raw(code.into())),
        );
        let block = TempoBlockEnv {
            timestamp: U256::from(1_000),
            ext: TempoBlockExt {
                timestamp_millis_part: 123,
                ..Default::default()
            },
            ..Default::default()
        };
        let env =
            TempoEvmEnv::new_with_version(spec, block, *tempo_execution_config(spec, 1).version());
        let mut factory =
            TempoEvmFactory::new_with_precompiles(|_, _| Box::new(NoPrecompiles::default()));
        if let Some(backend) = jit {
            factory = factory.with_jit(backend.clone(), JitMetrics::default());
        }
        let config = TempoEvmConfig::new(test_chainspec())
            .with_evm_factory(factory)
            .with_jit_support();
        let mut evm = ConfigureEvm::evm_with_env(&config, db, env);
        let tx = TempoTxEnv::from(Recovered::new_unchecked(
            TempoTxEnvelope::Legacy(Signed::new_unhashed(
                TxLegacy {
                    chain_id: Some(1),
                    gas_limit: 1_000_000,
                    to: TxKind::Call(CONTRACT),
                    ..TxLegacy::default()
                },
                Signature::test_signature(),
            )),
            CALLER,
        ));
        evm.transact(&Recovered::new_unchecked(tx, CALLER))
            .map(|result| result.detach())
            .map_err(|error| error.to_string())
    }

    /// Asserts that compiled execution matches the interpreter and returns its result.
    fn assert_compiled_matches(
        spec: TempoHardfork,
        db: InMemoryDB,
        code: Vec<u8>,
    ) -> Result<TxResultWithState<TempoEvmTypes>, String> {
        let interpreted = run(spec, db.clone(), code.clone(), None);
        let backend = backend(spec);
        let compiled = run(spec, db, code, Some(&backend));
        assert_eq!(compiled, interpreted);
        let stats = backend.stats();
        assert!(stats.lookup_hits > 0, "compiled code must run: {stats:?}");
        assert_eq!(stats.compilations_failed, 0);
        compiled
    }

    fn storage_credit_db(initial_value: u8, initial_credit: U256) -> InMemoryDB {
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            &STORAGE_CREDITS_ADDRESS,
            AccountInfo::default().with_code(Bytecode::new_raw(Bytes::from_static(&[0xef]))),
        );
        db.insert_account_storage(&CONTRACT, &U256::ZERO, &U256::from(initial_value));
        db.insert_account_storage(
            &STORAGE_CREDITS_ADDRESS,
            &StorageCredits::slot(CONTRACT),
            &initial_credit,
        );
        db
    }

    #[test]
    fn compiled_sstore_matches_storage_credits_and_gas() {
        // Consume a credit, mint a credit, set without credit, and modify a nonzero slot.
        // Storage credits start at T7.
        for spec in [TempoHardfork::T1B, TempoHardfork::T7] {
            for (initial, value, credit) in [(0, 1, 1), (1, 0, 0), (0, 1, 0), (1, 2, 1)] {
                let code = returning_top(&[op::PUSH1, value, op::PUSH0, op::SSTORE, op::GAS]);
                let db = storage_credit_db(initial, U256::from(credit));
                let result = assert_compiled_matches(spec, db, code);
                assert!(result.unwrap().result.status);
            }
        }
    }

    #[test]
    fn compiled_sstore_matches_invalid_storage_credit_state() {
        let code = vec![op::PUSH1, 1, op::PUSH0, op::SSTORE, op::STOP];
        let result =
            assert_compiled_matches(TempoHardfork::T7, storage_credit_db(0, U256::MAX), code);
        assert_eq!(
            result.unwrap_err(),
            "fatal error: invalid storage credits state"
        );
    }

    #[test]
    fn millis_timestamp_stays_interpreted() {
        let code = returning_top(&[0x4f]);
        for (spec, stop, output) in [
            (TempoHardfork::T1B, InstrStop::Return, U256::from(1_000_123)),
            (TempoHardfork::T7, InstrStop::OpcodeNotFound, U256::ZERO),
        ] {
            let interpreted = run(spec, InMemoryDB::default(), code.clone(), None);
            let backend = backend(spec);
            let result = run(spec, InMemoryDB::default(), code.clone(), Some(&backend));
            assert_eq!(result, interpreted);
            let result = result.unwrap().result;
            assert_eq!(result.stop, stop);
            assert_eq!(U256::from_be_slice(&result.output), output);
            assert_eq!(backend.stats().lookup_hits, 0);
        }
    }

    #[test]
    fn compiled_code_ignores_unreachable_millis_timestamp() {
        // Trailing data such as Solidity metadata may contain the opcode byte.
        let code = [returning_top(&[op::GAS]), vec![0x4f]].concat();
        let result = assert_compiled_matches(TempoHardfork::T7, InMemoryDB::default(), code);
        assert!(result.unwrap().result.status);
    }

    #[test]
    fn latest_backend_runs_hardforks_with_the_same_gas_schedule() {
        let code = returning_top(&[op::PUSH1, 1, op::PUSH0, op::SSTORE, op::GAS]);
        let db = storage_credit_db(0, U256::ONE);
        let interpreted = run(TempoHardfork::T7, db.clone(), code.clone(), None);
        let backend = backend(TempoHardfork::T14);
        let result = run(TempoHardfork::T7, db, code, Some(&backend));
        assert_eq!(result, interpreted);
        assert!(backend.stats().lookup_hits > 0);
    }

    #[test]
    fn other_hardfork_stays_interpreted() {
        let code = returning_top(&[op::PUSH1, 1, op::PUSH0, op::SSTORE, op::GAS]);
        let db = storage_credit_db(0, U256::ONE);
        let interpreted = run(TempoHardfork::T1B, db.clone(), code.clone(), None);
        let backend = backend(TempoHardfork::T7);
        let result = run(TempoHardfork::T1B, db, code, Some(&backend));
        assert_eq!(result, interpreted);
        let stats = backend.stats();
        assert_eq!(stats.lookup_hits + stats.lookup_misses, 0, "{stats:?}");
    }
}
