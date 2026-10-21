#![cfg(feature = "reth")]

use alloy_primitives::{Address, Bytes};
use reth_chainspec::EthChainSpec;
use serde_json::json;
use tempo_chainspec::{
    TempoChainSpec,
    spec::{DEV, MODERATO, PRESTO},
};
use tempo_contracts::precompiles::CONFIGURABLE_ACCOUNT_ADDRESS;

#[test]
fn genesis_info_reads_the_configurable_account_recovery_factory() {
    let factory = Address::repeat_byte(0x71);
    let mut genesis = MODERATO.genesis().clone();
    genesis
        .config
        .extra_fields
        .insert("configurableAccountRecoveryFactory".into(), json!(factory));

    let spec = TempoChainSpec::from_genesis(genesis);

    assert_eq!(
        spec.info.configurable_account_recovery_factory(),
        Some(factory)
    );
}

#[test]
fn public_networks_configure_no_configurable_account_recovery_factory() {
    assert_eq!(PRESTO.info.configurable_account_recovery_factory(), None);
    assert_eq!(MODERATO.info.configurable_account_recovery_factory(), None);
}

#[test]
fn t14_genesis_reserves_the_marker_and_an_unallocated_recovery_factory() {
    let factory = Address::repeat_byte(0x72);
    let mut genesis = DEV.genesis().clone();
    genesis
        .config
        .extra_fields
        .insert("t14Time".into(), json!(0));
    genesis
        .config
        .extra_fields
        .insert("configurableAccountRecoveryFactory".into(), json!(factory));
    genesis.alloc.remove(&CONFIGURABLE_ACCOUNT_ADDRESS);
    genesis.alloc.remove(&factory);

    let spec = TempoChainSpec::from_genesis(genesis);

    let alloc = &spec.genesis().alloc;
    let marker = &alloc[&CONFIGURABLE_ACCOUNT_ADDRESS];
    assert_eq!(marker.code, Some(Bytes::from_static(&[0xef])));
    let factory = &alloc[&factory];
    assert_eq!(factory.code, Some(Bytes::from_static(&[0xef])));
    assert_eq!(factory.nonce, Some(1));
}

#[test]
fn t14_genesis_treats_a_zero_recovery_factory_as_unset() {
    let mut genesis = DEV.genesis().clone();
    genesis
        .config
        .extra_fields
        .insert("t14Time".into(), json!(0));
    let unset = TempoChainSpec::from_genesis(genesis.clone());
    genesis.config.extra_fields.insert(
        "configurableAccountRecoveryFactory".into(),
        json!(Address::ZERO),
    );

    let zero = TempoChainSpec::from_genesis(genesis);

    assert_eq!(
        zero.genesis_header().inner.state_root,
        unset.genesis_header().inner.state_root
    );
}
