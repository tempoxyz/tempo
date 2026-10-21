#![cfg(feature = "reth")]

use alloy_primitives::{Address, B256, Bytes, U256};
use reth_chainspec::{ChainSpec, EthChainSpec};
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
fn t14_genesis_reserves_the_marker_and_the_recovery_factory() {
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

    // An unallocated factory is created with the marker's code and nonce one.
    let spec = TempoChainSpec::from_genesis(genesis.clone());

    let alloc = &spec.genesis().alloc;
    let marker = &alloc[&CONFIGURABLE_ACCOUNT_ADDRESS];
    assert_eq!(marker.code, Some(Bytes::from_static(&[0xef])));
    let account = &alloc[&factory];
    assert_eq!(account.code, Some(Bytes::from_static(&[0xef])));
    assert_eq!(account.nonce, Some(1));

    // An allocated factory only gains the marker's code.
    let account = genesis.alloc.entry(factory).or_default();
    account.balance = U256::from(42);
    account.nonce = Some(7);
    account.storage = Some([(B256::ZERO, B256::repeat_byte(9))].into());

    let spec = TempoChainSpec::from_genesis(genesis.clone());

    let account = &spec.genesis().alloc[&factory];
    assert_eq!(account.balance, U256::from(42));
    assert_eq!(account.nonce, Some(7));
    assert_eq!(account.code, Some(Bytes::from_static(&[0xef])));
    assert_eq!(
        account.storage.as_ref().unwrap()[&B256::ZERO],
        B256::repeat_byte(9)
    );
    assert_eq!(
        spec.info.configurable_account_recovery_factory(),
        Some(factory)
    );
    assert_ne!(
        spec.genesis_header().inner.state_root,
        ChainSpec::from_genesis(genesis).genesis_header().state_root
    );
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
