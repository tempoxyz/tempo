//! Execution ceiling enforced by the frozen worker.

use alloy_evm::{Evm, EvmFactory, revm::database::EmptyDB};
use alloy_primitives::{Address, B256, Bytes};
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use tempo_chainspec::{
    TempoHardfork,
    hardfork::TempoHardforks,
    spec::{MODERATO, PRESTO},
};
use tempo_evm::{TempoEvmConfig, TempoEvmFactory, TempoNextBlockEnvAttributes};
use tempo_primitives::TempoHeader;

#[test]
fn frozen_era_accepts_history_and_rejects_the_successor_boundary() {
    for chain in [PRESTO.clone(), MODERATO.clone()] {
        let boundary = chain.info.fork_time(TempoHardfork::T11).unwrap();
        let config = TempoEvmConfig::new(chain.clone());
        let mut header = TempoHeader {
            inner: alloy_consensus::Header {
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(1000),
                ..Default::default()
            },
            general_gas_limit: 10_000_000,
            shared_gas_limit: 3_000_000,
            ..Default::default()
        };
        assert!(config.evm_env(&header).is_ok());
        header.inner.timestamp = boundary - 1;
        assert_eq!(
            chain.tempo_hardfork_at(header.inner.timestamp),
            TempoHardfork::T10
        );
        assert_eq!(
            config.evm_env(&header).unwrap().cfg_env.spec,
            TempoHardfork::T10
        );
        header.inner.timestamp = boundary;
        let error = config.evm_env(&header).unwrap_err();
        assert!(error.to_string().contains("does not support T11"));

        let mut attributes = TempoNextBlockEnvAttributes {
            inner: NextBlockEnvAttributes {
                timestamp: boundary - 1,
                suggested_fee_recipient: Address::ZERO,
                prev_randao: B256::ZERO,
                gas_limit: 30_000_000,
                parent_beacon_block_root: None,
                withdrawals: None,
                extra_data: Bytes::new(),
                slot_number: None,
            },
            general_gas_limit: 10_000_000,
            shared_gas_limit: 3_000_000,
            timestamp_millis_part: 0,
            consensus_context: None,
        };
        header.inner.timestamp = boundary - 2;
        assert!(config.next_evm_env(&header, &attributes).is_ok());
        attributes.inner.timestamp = boundary;
        assert!(config.next_evm_env(&header, &attributes).is_err());
    }
}

#[test]
fn frozen_era_rechecks_execution_after_environment_changes() {
    let config = TempoEvmConfig::new(PRESTO.clone());
    let mut header = TempoHeader::default();
    header.inner.timestamp = PRESTO.info.fork_time(TempoHardfork::T11).unwrap() - 1;
    for spec in [
        TempoHardfork::T11,
        TempoHardfork::T12,
        TempoHardfork::T13,
        TempoHardfork::T14,
    ] {
        let mut env = config.evm_env(&header).unwrap();
        env.cfg_env.spec = spec;
        let mut evm = TempoEvmFactory::default().create_evm(EmptyDB::default(), env);
        for inspected in [false, true] {
            evm.set_inspector_enabled(inspected);
            let error = evm.transact_raw(Default::default()).unwrap_err();
            assert!(error.to_string().contains("maximum supported fork is T10"));
        }
        let error = evm
            .transact_system_call(Address::ZERO, Address::ZERO, Bytes::new())
            .unwrap_err();
        assert!(error.to_string().contains("maximum supported fork is T10"));
    }
}
