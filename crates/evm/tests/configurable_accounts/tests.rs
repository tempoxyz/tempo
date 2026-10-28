use super::*;
use alloy_consensus::Header;
use alloy_primitives::KECCAK256_EMPTY;
use evm2::evm::DynDatabase;
use reth_chainspec::EthChainSpec;
use reth_evm::{BlockExecutor, ConfigureEvm};
use reth_execution_types::BundleSource;
use reth_primitives_traits::Block as _;
use serde_json::json;
use std::sync::Arc;
use tempo_chainspec::{TempoChainSpec, spec::DEV};
use tempo_evm::TempoEvmConfig;
use tempo_primitives::{Block as TempoBlock, TempoHeader};

fn activation_config() -> TempoEvmConfig {
    let mut genesis = DEV.genesis().clone();
    genesis.config.chain_id = 1;
    for (field, value) in [
        ("t12Time", 0),
        ("t13Time", 0),
        ("t14Time", 10),
        ("t15Time", 1_000),
    ] {
        genesis
            .config
            .extra_fields
            .insert(field.into(), json!(value));
    }
    TempoEvmConfig::new(Arc::new(TempoChainSpec::from_genesis(genesis)))
}

#[test]
fn configurable_account_marker_is_installed_at_t14() {
    let config = activation_config();
    let mut db = InMemoryDB::default();
    for (number, timestamp) in [(1, 9), (2, 10), (3, 11)] {
        let block = TempoBlock::uncle(TempoHeader {
            inner: Header {
                number,
                timestamp,
                gas_limit: 30_000_000,
                base_fee_per_gas: Some(0),
                parent_beacon_block_root: Some(B256::ZERO),
                ..Default::default()
            },
            general_gas_limit: 30_000_000,
            ..Default::default()
        })
        .seal_slow();
        let mut executor = config.executor_for_block(db.clone(), &block).unwrap();
        assert_eq!(
            executor.evm().config_spec_id(),
            if timestamp < 10 {
                TempoHardfork::T13
            } else {
                TempoHardfork::T14
            }
        );
        executor.apply_pre_execution_changes().unwrap();
        let output = executor.finish().unwrap();
        db.commit_source(&BundleSource(&output.state));
        let marker = db
            .get_account(&CONFIGURABLE_ACCOUNT_ADDRESS)
            .unwrap()
            .unwrap_or_default();
        assert_eq!(marker.code_hash == KECCAK256_EMPTY, timestamp < 10);
    }
}
