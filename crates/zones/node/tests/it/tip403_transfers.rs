//! TIP-20 transfer tests on the zone with deposit-queue injection.
//!
//! These tests verify that TIP-20 transfers work correctly on the zone L2 after
//! depositing pathUSD via the fixture, including sequential transfers between
//! accounts and event emission.
//!
//! The zone only produces blocks when L1 blocks arrive via the deposit queue.
//! Pool transactions (transfers) are included in the next block after injection.
//! We must inject an L1 block *after* submitting a pool tx so the zone produces
//! a block that includes it.

use alloy::primitives::{B256, U256, address};
use alloy_provider::{Provider, ProviderBuilder};
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_node::rpc::NATIVE_BALANCE_PLACEHOLDER;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_zone_contracts::{IZoneOutbox, ZONE_OUTBOX_ADDRESS};

use crate::utils::{
    DEFAULT_TIMEOUT, TIP20_TX_GAS, WITHDRAWAL_TX_GAS, approve_outbox, l1_dev_signer,
    local_dev_zone_account, signer_at, start_local_zone_with_fixture,
};

/// Deposit pathUSD to the dev account, then transfer a portion to Bob.
///
/// Verifies sender balance decreased (minus gas) and recipient received the
/// exact transfer amount.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_deposit_then_transfer() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let (provider, dev_address) = local_dev_zone_account(&zone)?;

    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let deposit_amount: u128 = 1_000_000;

    // Deposit pathUSD to the dev account
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Dev transfers 400,000 to Bob.
    // Submit the tx then inject an L1 block so the zone produces a block including it.
    let transfer_amount: u128 = 400_000;
    // Seed the current anchor before estimation/pool validation. The next empty block inherits it.
    fixture.seed_no_receive_policy(bob)?;
    let tip20 = ITIP20::new(PATH_USD_ADDRESS, &provider);

    let native_balance = provider.get_balance(dev_address).await?;
    assert_eq!(
        native_balance, NATIVE_BALANCE_PLACEHOLDER,
        "zone should expose Tempo's placeholder native balance"
    );

    let estimated_gas = tip20
        .transfer(bob, U256::from(transfer_amount))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .estimate_gas()
        .await?;
    assert!(estimated_gas > 0, "transfer gas estimate should be nonzero");

    let pending = tip20
        .transfer(bob, U256::from(transfer_amount))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .send()
        .await?;

    // Inject an empty L1 block to trigger block production including the pool tx
    fixture.inject_empty_block(zone.deposit_queue());

    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "transfer should succeed");

    // Wait for Bob's balance
    let bob_balance = zone
        .wait_for_balance(
            PATH_USD_ADDRESS,
            bob,
            U256::from(transfer_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(bob_balance, U256::from(transfer_amount));

    // Dev should have remaining balance minus gas
    let dev_balance = zone.balance_of(PATH_USD_ADDRESS, dev_address).await?;
    let expected_remaining = deposit_amount - transfer_amount;
    assert!(
        dev_balance <= U256::from(expected_remaining),
        "dev should have at most {expected_remaining} (got {dev_balance})"
    );
    let gas_buffer = 100_000u128;
    assert!(
        dev_balance >= U256::from(expected_remaining.saturating_sub(gas_buffer)),
        "dev balance {dev_balance} too low — unexpected gas usage"
    );

    Ok(())
}

/// Deposit pathUSD to the dev account, then request a withdrawal through the
/// ZoneOutbox. Verifies the approval + outbox flow still succeeds and the
/// token does not remain stranded on the outbox after burn.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_then_request_withdrawal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(20).await?;

    let (provider, dev_address) = local_dev_zone_account(&zone)?;

    let withdrawal_amount: u128 = 250_000;

    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, &provider);

    let withdrawal_fee = outbox.calculateWithdrawalFee(0).call().await?;
    let gas_buffer = u128::from(TIP20_TX_GAS)
        .checked_add(u128::from(WITHDRAWAL_TX_GAS))
        .expect("test gas buffer should not overflow");
    let deposit_amount = withdrawal_amount
        .checked_add(withdrawal_fee)
        .and_then(|value| value.checked_add(gas_buffer))
        .expect("test deposit amount should not overflow");

    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    approve_outbox(&mut fixture, &zone, &provider).await?;

    let balance_before = zone.balance_of(PATH_USD_ADDRESS, dev_address).await?;
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, ZONE_OUTBOX_ADDRESS)
            .await?,
        U256::ZERO,
        "outbox should start with zero token balance"
    );

    let withdrawal_pending = outbox
        .requestWithdrawal(
            PATH_USD_ADDRESS,
            dev_address,
            withdrawal_amount,
            B256::ZERO,
            0,
            dev_address,
            alloy_primitives::Bytes::new(),
            alloy_primitives::Bytes::new(),
        )
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .send()
        .await?;
    fixture.inject_empty_block(zone.deposit_queue());
    let withdrawal_receipt = withdrawal_pending.get_receipt().await?;
    assert!(
        withdrawal_receipt.status(),
        "withdrawal request should succeed"
    );

    let balance_after = zone.balance_of(PATH_USD_ADDRESS, dev_address).await?;
    assert!(
        balance_after < balance_before,
        "withdrawal should reduce the user balance"
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, ZONE_OUTBOX_ADDRESS)
            .await?,
        U256::ZERO,
        "outbox should not retain funds after transferFrom + burn"
    );

    Ok(())
}

/// Sequential transfers: Alice → Bob → Charlie.
///
/// Verifies that chained transfers work correctly and each intermediate balance
/// is accurate after accounting for gas.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_sequential_transfers() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(20).await?;

    // Alice = dev account (mnemonic index 0)
    let alice_signer = l1_dev_signer();
    let alice = alice_signer.address();

    // Bob = mnemonic index 1
    let bob_signer = signer_at(1);
    let bob = bob_signer.address();

    // Charlie = mnemonic index 2
    let charlie_signer = signer_at(2);
    let charlie = charlie_signer.address();

    let deposit_amount: u128 = 2_000_000;

    // Deposit to Alice
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, alice, alice, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        alice,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Alice transfers 1,000,000 to Bob
    let alice_to_bob: u128 = 1_000_000;
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(zone.http_url().clone());
    fixture.seed_no_receive_policy(bob)?;
    let tip20_alice = ITIP20::new(PATH_USD_ADDRESS, &alice_provider);

    let pending = tip20_alice
        .transfer(bob, U256::from(alice_to_bob))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    // Inject L1 block to include Alice's transfer
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "Alice→Bob transfer should succeed");

    // Wait for Bob to receive funds
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        bob,
        U256::from(alice_to_bob),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Bob transfers 500,000 to Charlie
    let bob_to_charlie: u128 = 500_000;
    let bob_provider = ProviderBuilder::new()
        .wallet(bob_signer)
        .connect_http(zone.http_url().clone());
    fixture.seed_no_receive_policy(charlie)?;
    let tip20_bob = ITIP20::new(PATH_USD_ADDRESS, &bob_provider);

    let pending = tip20_bob
        .transfer(charlie, U256::from(bob_to_charlie))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    // Inject L1 block to include Bob's transfer
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "Bob→Charlie transfer should succeed");

    // Wait for Charlie to receive funds
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        charlie,
        U256::from(bob_to_charlie),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Verify final balances
    let gas_buffer = 100_000u128;

    let alice_balance = zone.balance_of(PATH_USD_ADDRESS, alice).await?;
    let alice_expected = deposit_amount - alice_to_bob;
    assert!(
        alice_balance <= U256::from(alice_expected),
        "Alice should have at most {alice_expected} (got {alice_balance})"
    );
    assert!(
        alice_balance >= U256::from(alice_expected.saturating_sub(gas_buffer)),
        "Alice balance {alice_balance} too low"
    );

    let bob_balance = zone.balance_of(PATH_USD_ADDRESS, bob).await?;
    let bob_expected = alice_to_bob - bob_to_charlie;
    assert!(
        bob_balance <= U256::from(bob_expected),
        "Bob should have at most {bob_expected} (got {bob_balance})"
    );
    assert!(
        bob_balance >= U256::from(bob_expected.saturating_sub(gas_buffer)),
        "Bob balance {bob_balance} too low"
    );

    let charlie_balance = zone.balance_of(PATH_USD_ADDRESS, charlie).await?;
    assert_eq!(
        charlie_balance,
        U256::from(bob_to_charlie),
        "Charlie should have exactly {bob_to_charlie}"
    );

    Ok(())
}

/// Transfer emits a `Transfer` event with correct fields.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_transfer_emits_events() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let (provider, dev_address) = local_dev_zone_account(&zone)?;

    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let deposit_amount: u128 = 1_000_000;
    let transfer_amount: u128 = 250_000;

    // Deposit to dev
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Transfer to Bob. Seed its receive-policy baseline before pool validation.
    fixture.seed_no_receive_policy(bob)?;
    let tip20 = ITIP20::new(PATH_USD_ADDRESS, &provider);

    let pending = tip20
        .transfer(bob, U256::from(transfer_amount))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    // Inject L1 block to finalize the transfer
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "transfer should succeed");

    // Wait for Bob's balance to confirm inclusion
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        bob,
        U256::from(transfer_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Query Transfer events from pathUSD
    let tip20_readonly = ITIP20::new(PATH_USD_ADDRESS, zone.provider());
    let transfer_filter = tip20_readonly.Transfer_filter().from_block(0);
    let events = transfer_filter.query().await?;

    // Find our transfer event (from dev to Bob)
    let found = events.iter().any(|(e, _)| {
        e.from == dev_address && e.to == bob && e.amount == U256::from(transfer_amount)
    });
    assert!(
        found,
        "should find Transfer event from {dev_address} to {bob} for {transfer_amount}"
    );

    Ok(())
}

/// `transferWithMemo` emits a `TransferWithMemo` event with the correct memo.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_transfer_with_memo() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let (provider, dev_address) = local_dev_zone_account(&zone)?;

    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let deposit_amount: u128 = 1_000_000;
    let transfer_amount: u128 = 300_000;
    let memo = B256::with_last_byte(0x42);

    // Deposit to dev
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, dev_address, dev_address, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        dev_address,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Transfer with memo. Seed its receive-policy baseline before pool validation.
    fixture.seed_no_receive_policy(bob)?;
    let tip20 = ITIP20::new(PATH_USD_ADDRESS, &provider);

    let pending = tip20
        .transferWithMemo(bob, U256::from(transfer_amount), memo)
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    // Inject L1 block to finalize
    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "transferWithMemo should succeed");

    // Wait for Bob's balance
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        bob,
        U256::from(transfer_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Query TransferWithMemo events
    let tip20_readonly = ITIP20::new(PATH_USD_ADDRESS, zone.provider());
    let memo_filter = tip20_readonly.TransferWithMemo_filter().from_block(0);
    let events = memo_filter.query().await?;

    let found = events.iter().any(|(e, _)| {
        e.from == dev_address
            && e.to == bob
            && e.amount == U256::from(transfer_amount)
            && e.memo == memo
    });
    assert!(found, "should find TransferWithMemo event with memo {memo}");

    Ok(())
}
