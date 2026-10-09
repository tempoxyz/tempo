use crate::utils::{L1TestNode, ZoneAccount, ZoneTestNode};
use alloy::{primitives::U256, providers::ProviderBuilder};
use tempo_zone_contracts::ZONE_TOKEN_ADDRESS;

/// Longer timeout for real L1 tests.
const L1_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Shield + in-zone send:
///
/// 1. Start L1 dev node.
/// 2. Create a zone through the native ZoneFactory.
/// 3. Start zone node connected to L1.
/// 4. Alice deposits 1 pathUSD into the zone (shield).
/// 5. Alice transfers 0.5 pathUSD to Bob within the zone (L2 transfer).
/// 6. Verify Alice has 0.5 and Bob has 0.5 on L2.
///
/// ```text
///  L1                         Zone L2
///   |--- Alice deposits 1 ------>|  ✓ Alice has 1
///   |                            |
///   |                            |-- Alice sends 0.5 to Bob
///   |                            |  ✓ Alice has 0.5
///   |                            |  ✓ Bob has 0.5
/// ```
///
/// NOTE: Requires `forge build` in `crates/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_shield_and_send() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 ---
    let l1 = L1TestNode::start().await?;

    // --- Step 2: Deploy L1 infrastructure and create a zone ---
    let portal_address = l1.deploy_zone().await?;

    // --- Step 3: Start zone node connected to L1 ---
    let zone = ZoneTestNode::start_from_l1(l1.http_url(), l1.ws_url(), portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;

    // --- Step 4: Alice deposits 1 pathUSD (shield) ---
    let mut alice = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD (6 decimals)
    l1.fund_user(alice.address(), deposit_amount * 2).await?;

    let alice_balance = alice.deposit(deposit_amount, L1_TIMEOUT, &zone).await?;
    assert_eq!(
        alice_balance,
        U256::from(deposit_amount),
        "Alice should have 1 pathUSD on L2 after deposit"
    );

    // --- Step 5: Alice transfers 0.5 pathUSD to Bob on L2 ---
    // Bob is derived from mnemonic index 2 (Alice is index 1 via user_signer)
    let bob_address = l1.signer_at(2).address();

    // Verify Bob starts with zero
    let bob_balance_before = zone.balance_of(ZONE_TOKEN_ADDRESS, bob_address).await?;
    assert_eq!(
        bob_balance_before,
        U256::ZERO,
        "Bob should start with zero on L2"
    );

    // Alice transfers on L2 using the TIP-20 transfer function
    let transfer_amount: u128 = 500_000; // 0.5 pathUSD
    {
        use tempo_contracts::precompiles::ITIP20;

        let alice_signer = l1.user_signer();
        let alice_l2_provider = ProviderBuilder::new()
            .wallet(alice_signer)
            .connect_http(zone.http_url().clone());

        let zone_token = ITIP20::new(ZONE_TOKEN_ADDRESS, &alice_l2_provider);
        let receipt = zone_token
            .transfer(bob_address, U256::from(transfer_amount))
            .send()
            .await?
            .get_receipt()
            .await?;
        eyre::ensure!(receipt.status(), "L2 transfer from Alice to Bob failed");
    }

    // --- Step 6: Verify balances ---
    let alice_final = zone.balance_of(ZONE_TOKEN_ADDRESS, alice.address()).await?;
    let bob_final = zone.balance_of(ZONE_TOKEN_ADDRESS, bob_address).await?;

    // Alice pays gas for the L2 transfer, so her balance is slightly less
    assert!(
        alice_final <= U256::from(deposit_amount - transfer_amount),
        "Alice should have at most 0.5 pathUSD after sending 0.5 to Bob (got {alice_final})"
    );
    assert_eq!(
        bob_final,
        U256::from(transfer_amount),
        "Bob should have exactly 0.5 pathUSD after receiving from Alice"
    );

    Ok(())
}
