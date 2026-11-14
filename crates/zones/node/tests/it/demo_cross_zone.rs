//! Demo Flow 3: Cross-Zone Transfer

use crate::utils::{Network, WithdrawalArgs, ZoneCreationConfig};
use alloy::primitives::U256;
use tempo_contracts::zones::ZONE_TOKEN_ADDRESS;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::test_utils::actors;

/// Cross-zone transfer via SwapAndDepositRouter:
///
/// 1. Start L1 dev node.
/// 2. Create open zone_a and zone_b through the native factory, then deploy SwapAndDepositRouter.
/// 3. Start both zone nodes connected to L1.
/// 4. Alice deposits pathUSD into zone_a.
/// 5. Spawn sequencers for both zones.
/// 6. Alice withdraws from zone_a with router callback that deposits into zone_b for Bob.
/// 7. Verify Bob received the deposit on zone_b.
/// 8. Verify Alice's zone_a balance decreased.
///
/// ```text
///  Zone A (Alice)       L1 (Router)         Zone B (Bob)
///   |--- withdraw 500 -->|                    |
///   |                    |--- deposit 500 --->|
///   |                    |                    |
///   |  ✓ Alice -= 500                  ✓ Bob += 500
/// ```
///
/// NOTE: Requires `forge build` in `crates/zones/contracts/` for shared runtime and router artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_cross_zone_send() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Steps 1-3: L1, both zones with their own sequencer keys, and the router ---
    let net = Network::builder()
        .zone(ZoneCreationConfig::open())
        .zone(ZoneCreationConfig::open())
        .accounts(2, 2_000_000)
        .start()
        .await?;
    let (l1, [zone_a, zone_b], [alice, bob]) = (net.l1(), net.zones(), net.accounts());
    let [refund_burner] = actors();
    let router = l1.deploy_router(l1.native_zone_factory().await?).await?;
    zone_a.assert_access_enforced(false).await?;
    zone_b.assert_access_enforced(false).await?;
    zone_a.assert_gateway_open(true).await?;
    zone_b.assert_gateway_open(true).await?;

    // --- Step 4: Alice deposits into zone_a ---
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD
    zone_a.deposit(alice, deposit_amount).await?;

    // --- Step 5: Spawn sequencers for both zones ---
    let _seq_a = zone_a.spawn_sequencer().await;
    let _seq_b = zone_b.spawn_sequencer().await;

    // Verify Bob starts with zero on zone_b
    let bob_before = zone_b.balance_of(ZONE_TOKEN_ADDRESS, bob.address()).await?;
    assert_eq!(
        bob_before,
        U256::ZERO,
        "Bob should start with zero on zone_b"
    );

    // --- Step 6: Alice withdraws from zone_a → router → zone_b (for Bob) ---
    let cross_amount: u128 = 500_000; // 0.5 pathUSD

    // Use the cross_zone_via_router helper but with Bob as the recipient
    let args = WithdrawalArgs::cross_zone_via_router(
        l1,
        cross_amount,
        router,
        zone_b.portal_address(),
        PATH_USD_ADDRESS,
        bob.address(), // recipient on zone_b is Bob
        refund_burner, // Tempo refund target if Zone B later bounces the deposit
    )
    .await?;
    zone_a.account(alice).withdraw_with(args).await?;
    let callback_succeeded = l1
        .wait_for_withdrawal_processed_status(
            zone_a.portal_address(),
            router,
            PATH_USD_ADDRESS,
            cross_amount,
            std::time::Duration::from_secs(60),
        )
        .await?;
    eyre::ensure!(callback_succeeded, "cross-zone router callback failed");

    // --- Step 7: Verify Bob received deposit on zone_b ---
    let cross_timeout = std::time::Duration::from_secs(60);
    zone_b
        .wait_for_balance(
            ZONE_TOKEN_ADDRESS,
            bob.address(),
            U256::from(cross_amount),
            cross_timeout,
        )
        .await?;

    let bob_final = zone_b.balance_of(ZONE_TOKEN_ADDRESS, bob.address()).await?;
    assert_eq!(
        bob_final,
        U256::from(cross_amount),
        "Bob should have received the cross-zone deposit on zone_b"
    );

    // --- Step 8: Verify Alice's zone_a balance decreased ---
    let alice_final = zone_a
        .balance_of(ZONE_TOKEN_ADDRESS, alice.address())
        .await?;
    assert!(
        alice_final <= U256::from(deposit_amount - cross_amount),
        "Alice's zone_a balance should decrease by at least the cross-zone amount (got {alice_final})"
    );

    Ok(())
}
