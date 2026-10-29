//! The zone-side invariants the checker ExEx judges, armed and holding on a zone's ordinary
//! activity: deposits, an approval and a withdrawal batch.

use alloy::primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};
use tempo_invariants::zones::zone::{
    ACCOUNT_GETTER_PRIVACY, ADVANCE_TEMPO_FIRST, BALANCE_ALLOWANCE_PRIVACY,
    BLOCK_TIMESTAMP_MONOTONIC, CONTRACT_CREATION_DISABLED, DEPOSIT_NUMBER_MONOTONIC,
    DEPOSIT_PROCESSED_PREFIX, MINT_BURN_AUTHORITY, PREDEPLOY_ADDRESSES, REFUND_READ_PRIVACY,
    SUPPLY_SOLVENCY, TEMPO_HEADER_CONTINUITY, THIRD_PARTY, WITHDRAWAL_BATCH_INDEX,
};
use tempo_precompiles::{PATH_USD_ADDRESS, storage::StorageKey, zone_factory::portal};

use crate::utils::{
    DEFAULT_TIMEOUT, WITHDRAWAL_TX_GAS, approve_outbox, local_dev_zone_account,
    start_local_zone_with_fixture,
};

/// Every zone-side check judged on local state arms on a zone that processes deposits across
/// blocks, moves tokens, and finalizes a withdrawal batch, and none fires.
#[tokio::test(flavor = "multi_thread")]
async fn test_zone_invariants_hold_on_ordinary_activity() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    // `refunds` asks the portal (at the zero address in local fixtures) whether its caller is a
    // sequencer; with no Tempo RPC to ask, seed that the third party holds no role.
    {
        let mut cache = zone.l1_state_cache().lock();
        let role: B256 = THIRD_PARTY.mapping_slot(portal::slots::ROLE).into();
        for block in 0..=10 {
            cache.set(Address::ZERO, role, block, B256::ZERO);
        }
    }
    let (provider, dev) = local_dev_zone_account(&zone)?;

    // Deposits in two Tempo blocks.
    for amount in [2_000_000u128, 1_000_000] {
        let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev, dev, amount);
        fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    }
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev,
        U256::from(3_000_000),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // An approval (zones do not allow user transfers yet).
    approve_outbox(&mut fixture, &zone, &provider).await?;

    // A withdrawal, which burns and is finalized in its block.
    let pending = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, provider.clone())
        .requestWithdrawal(
            PATH_USD_ADDRESS,
            dev,
            250_000,
            B256::ZERO,
            0,
            dev,
            Bytes::new(),
            Bytes::new(),
        )
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(WITHDRAWAL_TX_GAS)
        .send()
        .await?;
    fixture.inject_empty_block(zone.deposit_queue());
    assert!(
        pending.get_receipt().await?.status(),
        "withdrawal should succeed"
    );
    fixture.inject_empty_block(zone.deposit_queue());
    let head = provider.get_block_number().await?;
    zone.wait_for_block_number(head + 1, DEFAULT_TIMEOUT)
        .await?;

    let report = zone.check_zone_invariants(false).await?;
    for (id, counts) in &report.counts {
        tracing::info!(id, ?counts, "zone invariant");
    }
    assert!(
        report.violations.is_empty(),
        "zone invariants fired: {:#?}",
        report.violations
    );
    for id in [
        PREDEPLOY_ADDRESSES,
        BLOCK_TIMESTAMP_MONOTONIC,
        ADVANCE_TEMPO_FIRST,
        CONTRACT_CREATION_DISABLED,
        MINT_BURN_AUTHORITY,
        TEMPO_HEADER_CONTINUITY,
        DEPOSIT_NUMBER_MONOTONIC,
        DEPOSIT_PROCESSED_PREFIX,
        WITHDRAWAL_BATCH_INDEX,
        SUPPLY_SOLVENCY,
        BALANCE_ALLOWANCE_PRIVACY,
        ACCOUNT_GETTER_PRIVACY,
        REFUND_READ_PRIVACY,
    ] {
        let armed = report.counts.get(id).map_or(0, |counts| counts.armed);
        assert!(armed > 0, "{id} never armed: {:?}", report.counts);
    }
    Ok(())
}
