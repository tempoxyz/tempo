//! E2e tests for native TIP-20 token initialization via `TokenEnabled` events.
//!
//! These tests verify that new tokens can be enabled on L2 by injecting
//! `TokenEnabled` events from L1, and that deposits of the newly-enabled
//! tokens are correctly minted.

use alloy::primitives::{U256, address};
use alloy_network::ReceiptResponse;
use zone_l1::EnabledToken;

use crate::utils::{
    DEFAULT_TIMEOUT, L1Fixture, TIP20_TX_GAS, local_dev_tempo_zone_account,
    start_local_zone_with_fixture,
};

// Imports for real-L1 tests
use crate::utils::{L1_TIMEOUT, Network};
use alloy::primitives::B256;
use tempo_alloy::rpc::TempoCallBuilderExt;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::test_util::TIP20Setup;

/// Enable a new token (AlphaUSD) via a `TokenEnabled` event, then deposit it
/// and verify the recipient receives the minted balance.
#[tokio::test(flavor = "multi_thread")]
async fn test_enable_token_then_deposit() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alpha_token = address!("0x20C0000000000000000000000000000000AA0001");
    let enabled = EnabledToken {
        token: alpha_token,
        name: "AlphaUSD".to_string(),
        symbol: "aUSD".to_string(),
        currency: "USD".to_string(),
    };

    // Block N: enable the token
    fixture.inject_enabled_tokens(zone.deposit_queue(), vec![enabled]);

    // Block N+1: deposit AlphaUSD to a recipient
    let sender = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x0000000000000000000000000000000000005678");
    let deposit_amount: u128 = 1_000_000;

    let deposit = fixture.make_deposit(alpha_token, sender, recipient, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    // Verify the recipient received the AlphaUSD
    let balance = zone
        .wait_for_balance(
            alpha_token,
            recipient,
            U256::from(deposit_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(
        balance,
        U256::from(deposit_amount),
        "minted amount should equal deposit amount"
    );

    Ok(())
}

/// Enable a new token and deposit it in the **same** L1 block.
///
/// The builder must initialize the token before executing `advanceTempo` so
/// that the deposit mint succeeds within a single block.
#[tokio::test(flavor = "multi_thread")]
async fn test_enable_token_and_deposit_same_block() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let beta_token = address!("0x20C0000000000000000000000000000000BB0001");
    let enabled = EnabledToken {
        token: beta_token,
        name: "BetaUSD".to_string(),
        symbol: "bUSD".to_string(),
        currency: "USD".to_string(),
    };

    let sender = address!("0x0000000000000000000000000000000000001234");
    let recipient = address!("0x0000000000000000000000000000000000005678");
    let deposit_amount: u128 = 2_500_000;

    // Single L1 block with both TokenEnabled + deposit
    let block = fixture.next_block();
    let deposit = L1Fixture::make_deposit_for_block(beta_token, sender, recipient, deposit_amount);
    let mut events = fixture.portal_events_from_deposits(&[deposit]);
    events.enabled_tokens = vec![enabled];
    fixture.enqueue_events(&block, zone.deposit_queue(), events);

    // Verify the recipient received the BetaUSD
    let balance = zone
        .wait_for_balance(
            beta_token,
            recipient,
            U256::from(deposit_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(
        balance,
        U256::from(deposit_amount),
        "minted amount should equal deposit amount"
    );

    Ok(())
}

/// Pool validation must observe the same L1-anchored policy state as execution.
///
/// The enabled token is used for direct fee collection. The regression assertion checks that pool
/// admission accepts its anchored policy without requiring FeeAMM liquidity.
#[tokio::test(flavor = "multi_thread")]
async fn test_pool_validation_uses_enabled_token_anchored_policy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let (provider, sender) = local_dev_tempo_zone_account(&zone)?;
    let recipient = address!("0x000000000000000000000000000000000000B0B0");
    let token_address = address!("0x20C0000000000000000000000000000000CC0001");
    let deposit_amount = 1_000_000u128;
    let transfer_amount = 100_000u128;

    let block = fixture.next_block();
    let deposit = L1Fixture::make_deposit_for_block(token_address, sender, sender, deposit_amount);
    let mut events = fixture.portal_events_from_deposits(&[deposit]);
    events.enabled_tokens = vec![EnabledToken {
        token: token_address,
        name: "PoolPolicyUSD".to_string(),
        symbol: "ppUSD".to_string(),
        currency: "USD".to_string(),
    }];
    fixture.enqueue_events(&block, zone.deposit_queue(), events);

    zone.wait_for_balance(
        token_address,
        sender,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;
    fixture.seed_transfer_recipient(recipient)?;

    let token = ITIP20::new(token_address, &provider);
    assert_eq!(
        token.transferPolicyId().call().await?,
        1,
        "execution should observe the anchored allow-all policy"
    );

    // Stateful RPC simulation uses ZoneEvmConfig and therefore the L1 overlay.
    let simulated = token
        .transfer(recipient, U256::from(transfer_amount))
        .fee_token(token_address)
        .max_fee_per_gas(u128::from(TEMPO_T0_BASE_FEE))
        .max_priority_fee_per_gas(0)
        .gas(TIP20_TX_GAS)
        .call()
        .await?;
    assert!(simulated, "the anchored policy should allow execution");

    let pending = token
        .transfer(recipient, U256::from(transfer_amount))
        .fee_token(token_address)
        .max_fee_per_gas(u128::from(TEMPO_T0_BASE_FEE))
        .max_priority_fee_per_gas(0)
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    fixture.inject_empty_block(zone.deposit_queue());
    let receipt = pending.get_receipt().await?;
    assert!(
        receipt.status(),
        "transfer should succeed without FeeAMM liquidity"
    );
    zone.wait_for_balance(
        token_address,
        recipient,
        U256::from(transfer_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    Ok(())
}

/// A token enabled on a real L1 after zone startup can be deposited and withdrawn.
#[tokio::test(flavor = "multi_thread")]
async fn test_enable_token_via_real_l1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 and a zone, funding the user with pathUSD for L2 gas ---
    let pathusd_gas_amount: u128 = 5_000_000; // 5 pathUSD for L2 gas
    let (l1, [zone], [user]) = &Network::default()
        .fund(pathusd_gas_amount * 2)
        .start()
        .await?;

    // --- Step 2: Create AlphaUSD on L1 ---
    // --- Step 3: Mint AlphaUSD to the user ---
    let alpha_deposit_amount: u128 = 2_000_000; // 2 AlphaUSD
    let l1_alpha_usd = TIP20Setup::create("AlphaUSD", "aUSD", l1.dev_address())
        .with_salt(B256::with_last_byte(0x63))
        .with_mint(user.address(), U256::from(alpha_deposit_amount * 2))
        .apply_rpc(&l1.dev_provider())
        .await?;

    // --- Step 4: Enable AlphaUSD on the portal ---
    // Must happen AFTER zone startup so the zone's L1 subscriber picks up the
    // TokenEnabled event from a live block (events in blocks <= genesis are not
    // backfilled).
    zone.enable_token(l1_alpha_usd).await?;

    // --- Step 6: Deposit pathUSD (gas) then AlphaUSD ---
    zone.deposit(user, pathusd_gas_amount).await?;

    // The L2 token address is deterministic — same factory sender + salt means
    // l1_alpha_usd == l2_alpha_usd.
    let l2_alpha_usd = l1_alpha_usd;

    let alpha_minted = zone
        .account(user)
        .deposit_token(
            l1_alpha_usd,
            l2_alpha_usd,
            alpha_deposit_amount,
            L1_TIMEOUT,
            zone,
        )
        .await?;

    // --- Step 8: Verify AlphaUSD balance on L2 ---
    assert_eq!(
        alpha_minted,
        U256::from(alpha_deposit_amount),
        "AlphaUSD minted balance should equal deposit amount"
    );

    // --- Step 9: Spawn sequencer and withdraw AlphaUSD, waiting for L1 processing ---
    let _sequencer_handle = zone.spawn_sequencer().await;
    let alpha_withdrawal: u128 = 1_000_000; // 1 AlphaUSD
    zone.withdraw(user, l2_alpha_usd, alpha_withdrawal).await?;

    // Verify the L2 AlphaUSD balance decreased
    let final_alpha = zone.balance_of(l2_alpha_usd, user.address()).await?;
    assert!(
        final_alpha <= U256::from(alpha_deposit_amount - alpha_withdrawal),
        "L2 AlphaUSD balance should decrease by at least the withdrawal amount (got {final_alpha})"
    );

    Ok(())
}
