use std::sync::Arc;

use alloy_primitives::{Address, B256};
use reth_chainspec::EthChainSpec;
use reth_evm::{ConfigureEvm, NextBlockEnvAttributes};
use serde_json::json;
use tempo_chainspec::{TempoChainSpec, spec::MODERATO};
use tempo_evm::{TempoEvmConfig, TempoNextBlockEnvAttributes};
use tempo_primitives::TempoHeader;

#[test]
fn configured_genesis_factory_reaches_the_block_env() {
    let factory = Address::repeat_byte(0x71);
    let mut genesis = MODERATO.genesis().clone();
    genesis
        .config
        .extra_fields
        .insert("configurableAccountRecoveryFactory".into(), json!(factory));
    let evm_config = TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(genesis)));

    let parent = TempoHeader {
        inner: alloy_consensus::Header {
            number: 99,
            timestamp: 900,
            gas_limit: 30_000_000,
            base_fee_per_gas: Some(1000),
            ..Default::default()
        },
        general_gas_limit: 10_000_000,
        timestamp_millis_part: 0,
        shared_gas_limit: 3_000_000,
        ..Default::default()
    };
    let attributes = TempoNextBlockEnvAttributes {
        inner: NextBlockEnvAttributes {
            timestamp: 1000,
            suggested_fee_recipient: Address::repeat_byte(0x02),
            prev_randao: B256::repeat_byte(0x03),
            gas_limit: 30_000_000,
            parent_beacon_block_root: Some(B256::ZERO),
            withdrawals: None,
            extra_data: Default::default(),
            slot_number: None,
        },
        general_gas_limit: 10_000_000,
        shared_gas_limit: 3_000_000,
        timestamp_millis_part: 750,
        consensus_context: None,
    };

    let evm_env = evm_config.next_evm_env(&parent, &attributes).unwrap();
    assert_eq!(
        evm_env.block.ext.configurable_account_recovery_factory,
        Some(factory)
    );
    assert_eq!(
        evm_config
            .evm_env(&parent)
            .unwrap()
            .block
            .ext
            .configurable_account_recovery_factory,
        Some(factory)
    );
}
