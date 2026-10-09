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
use crate::utils::{L1TestNode, ZoneAccount, ZoneTestNode, spawn_sequencer};
use alloy::primitives::B256;
use alloy_provider::Provider;
use tempo_alloy::rpc::TempoCallBuilderExt;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::ITIP20;

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
#[ignore = "TODO: re-enable once zones allow user transfers"]
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
    fixture.seed_no_receive_policy(recipient)?;

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
        .max_fee_per_gas(TEMPO_T0_BASE_FEE as u128)
        .max_priority_fee_per_gas(0)
        .gas(TIP20_TX_GAS)
        .call()
        .await?;
    assert!(simulated, "the anchored policy should allow execution");

    let pending = token
        .transfer(recipient, U256::from(transfer_amount))
        .fee_token(token_address)
        .max_fee_per_gas(TEMPO_T0_BASE_FEE as u128)
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

/// Longer timeout for real L1 tests — the L1 dev node produces blocks every
/// 500ms and the L1Subscriber needs to connect, backfill, and subscribe.
const L1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Full TokenEnabled pipeline with a real in-process L1 node:
///
///  1. Start L1 dev node.
///  2. Create a second TIP-20 token ("AlphaUSD" / "aUSD") on L1.
///  3. Mint AlphaUSD to the dev account.
///  4. Create a zone through the native ZoneFactory.
///  5. Start zone node connected to L1.
///  6. Enable AlphaUSD on the portal (emits `TokenEnabled` event) — must
///     happen AFTER zone startup so the live L1 subscriber picks it up
///     (events in blocks ≤ genesis are not backfilled).
///  7. Wait for the zone to finalize past the `enableToken` L1 block.
///  8. Fund user with pathUSD (for L2 gas) and AlphaUSD on L1.
///  9. Deposit pathUSD first (for L2 gas), then deposit AlphaUSD.
/// 10. Verify AlphaUSD balance on L2.
/// 11. Spawn sequencer, withdraw AlphaUSD back to L1.
/// 12. Wait for the withdrawal to be processed on L1.
///
/// ```text
///  L1 (TokenEnabled + deposit)          Zone L2
///    |--- enableToken("AlphaUSD") ---->|  ✓ token initialized via builder
///    |--- deposit pathUSD ------------>|  ✓ pathUSD minted (gas)
///    |--- deposit AlphaUSD ----------->|  ✓ AlphaUSD minted
///    |<-- withdraw AlphaUSD -----------|  ✓ AlphaUSD burned
/// ```
///
/// NOTE: Requires `forge build` in `crates/zones/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_enable_token_via_real_l1() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;

    // --- Step 2: Create AlphaUSD on L1 ---
    let alpha_salt = B256::with_last_byte(0x63);
    let l1_alpha_usd = l1.create_tip20("AlphaUSD", "aUSD", alpha_salt).await?;

    // --- Step 3: Mint AlphaUSD to the dev account ---
    let mint_amount: u128 = 100_000_000; // 100 AlphaUSD (6 decimals)
    l1.mint_tip20(l1_alpha_usd, l1.dev_address(), mint_amount)
        .await?;

    // --- Step 4: Deploy L1 infrastructure and create a zone ---
    let portal_address = l1.deploy_zone().await?;

    // --- Step 5: Start zone node connected to L1 ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;

    // --- Step 6: Enable AlphaUSD on the portal ---
    // Must happen AFTER zone startup so the zone's L1 subscriber picks up the
    // TokenEnabled event from a live block (events in blocks <= genesis are not
    // backfilled).
    l1.enable_token_on_portal(portal_address, l1_alpha_usd)
        .await?;
    let enable_block = l1.provider().get_block_number().await?;

    // --- Step 7: Wait for the zone to finalize past the enableToken block ---
    zone.wait_for_l2_tempo_finalized(enable_block, L1_TIMEOUT)
        .await?;

    // --- Step 8: Fund user account on L1 ---
    let mut account = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let pathusd_gas_amount: u128 = 5_000_000; // 5 pathUSD for L2 gas
    let alpha_deposit_amount: u128 = 2_000_000; // 2 AlphaUSD

    l1.fund_user(account.address(), pathusd_gas_amount * 2)
        .await?;
    l1.fund_user_token(l1_alpha_usd, account.address(), alpha_deposit_amount * 2)
        .await?;

    // --- Step 9: Deposit pathUSD (gas) then AlphaUSD ---
    account
        .deposit(pathusd_gas_amount, L1_TIMEOUT, &zone)
        .await?;

    // The L2 token address is deterministic — same factory sender + salt means
    // l1_alpha_usd == l2_alpha_usd.
    let l2_alpha_usd = l1_alpha_usd;

    let alpha_minted = account
        .deposit_token(
            l1_alpha_usd,
            l2_alpha_usd,
            alpha_deposit_amount,
            L1_TIMEOUT,
            &zone,
        )
        .await?;

    // --- Step 10: Verify AlphaUSD balance on L2 ---
    assert_eq!(
        alpha_minted,
        U256::from(alpha_deposit_amount),
        "AlphaUSD minted balance should equal deposit amount"
    );

    // --- Step 11: Spawn sequencer and withdraw AlphaUSD ---
    let _sequencer_handle = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let withdrawal_timeout = std::time::Duration::from_secs(60);

    let alpha_withdrawal: u128 = 1_000_000; // 1 AlphaUSD
    let alpha_balance_before = l1.balance_of(l1_alpha_usd, account.address()).await?;
    account
        .withdraw_token(l2_alpha_usd, alpha_withdrawal)
        .await?;

    // --- Step 12: Wait for the withdrawal to be processed on L1 ---
    l1.wait_for_withdrawal_on_l1_token(
        portal_address,
        l1_alpha_usd,
        account.address(),
        alpha_balance_before,
        alpha_withdrawal,
        withdrawal_timeout,
    )
    .await?;

    // Verify the L2 AlphaUSD balance decreased
    let final_alpha = zone.balance_of(l2_alpha_usd, account.address()).await?;
    assert!(
        final_alpha <= U256::from(alpha_deposit_amount - alpha_withdrawal),
        "L2 AlphaUSD balance should decrease by at least the withdrawal amount (got {final_alpha})"
    );

    Ok(())
}
