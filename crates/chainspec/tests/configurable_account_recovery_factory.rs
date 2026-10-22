#![cfg(feature = "reth")]

use alloy_primitives::Address;
use reth_chainspec::EthChainSpec;
use serde_json::json;
use tempo_chainspec::{
    TempoChainSpec,
    spec::{MODERATO, PRESTO},
};

/// The factory is read from the genesis config, and the allocation is used as given even with T14
/// active at genesis.
#[test]
fn genesis_info_reads_the_configurable_account_recovery_factory() {
    let factory = Address::repeat_byte(0x71);
    let mut genesis = MODERATO.genesis().clone();
    genesis
        .config
        .extra_fields
        .insert("configurableAccountRecoveryFactory".into(), json!(factory));
    genesis
        .config
        .extra_fields
        .insert("t14Time".into(), json!(0));

    let spec = TempoChainSpec::from_genesis(genesis.clone());

    assert_eq!(
        spec.info.configurable_account_recovery_factory(),
        Some(factory)
    );
    assert_eq!(spec.genesis().alloc, genesis.alloc);
}

#[test]
fn public_networks_configure_no_configurable_account_recovery_factory() {
    assert_eq!(PRESTO.info.configurable_account_recovery_factory(), None);
    assert_eq!(MODERATO.info.configurable_account_recovery_factory(), None);
}
