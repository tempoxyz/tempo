use crate::utils::{L1_TIMEOUT, Network};
use alloy::{primitives::U256, providers::ProviderBuilder};
use tempo_alloy::test_utils::CallBuilderExt;
use tempo_contracts::{precompiles::ITIP20, zones::ZONE_TOKEN_ADDRESS};

/// Shield + in-zone send:
///
/// 1. Start L1 dev node.
/// 2. Create a zone through the native ZoneFactory.
/// 3. Start zone node connected to L1.
/// 4. Alice deposits 1 pathUSD into the zone (shield).
/// 5. Alice's transfer is rejected until the portal admin opts the zone into transfers.
/// 6. Alice transfers 0.5 pathUSD to Bob within the zone (L2 transfer).
/// 7. Verify Alice has 0.5 and Bob has 0.5 on L2.
///
/// ```text
///  L1                         Zone L2
///   |--- Alice deposits 1 ------>|  ✓ Alice has 1
///   |                            |  ✗ Alice cannot send yet
///   |--- setTransfersEnabled --->|
///   |                            |-- Alice sends 0.5 to Bob
///   |                            |  ✓ Alice has 0.5
///   |                            |  ✓ Bob has 0.5
/// ```
///
/// NOTE: Requires `forge build` in `crates/zones/contracts/` for shared runtime artifacts.
#[tokio::test(flavor = "multi_thread")]
async fn test_shield_and_send() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Steps 1-3: Start L1 and a zone connected to it ---
    let net = Network::builder().accounts(2, 2_000_000).start().await?;
    let (l1, [zone], [alice, bob]) = net.parts();

    // --- Step 4: Alice deposits 1 pathUSD (shield) ---
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD (6 decimals)
    let alice_balance = zone.deposit(alice, deposit_amount).await?;
    assert_eq!(
        alice_balance,
        U256::from(deposit_amount),
        "Alice should have 1 pathUSD on L2 after deposit"
    );

    // --- Step 5: Alice transfers 0.5 pathUSD to Bob on L2 ---

    // Verify Bob starts with zero
    let bob_balance_before = zone.balance_of(ZONE_TOKEN_ADDRESS, bob.address()).await?;
    assert_eq!(
        bob_balance_before,
        U256::ZERO,
        "Bob should start with zero on L2"
    );

    // Alice transfers on L2 using the TIP-20 transfer function
    let transfer_amount: u128 = 500_000; // 0.5 pathUSD
    {
        let alice_l2_provider = ProviderBuilder::new()
            .wallet(alice.clone())
            .connect_http(zone.http_url().clone());

        let zone_token = ITIP20::new(ZONE_TOKEN_ADDRESS, &alice_l2_provider);

        // --- Step 5: Transfers stay disabled until the portal admin opts in ---
        let disabled = zone_token
            .transfer(bob.address(), U256::from(transfer_amount))
            .call()
            .await
            .expect_err("L2 transfer must revert before the portal opts into transfers");
        assert_eq!(
            disabled.as_revert_data().unwrap(),
            alloy::sol_types::SolError::abi_encode(&tempo_contracts::zones::Unauthorized {}),
            "L2 transfer must be rejected as unauthorized before the opt-in"
        );
        let opt_in_block = l1
            .set_transfers_enabled_on_portal(zone.portal_address(), true)
            .await?;
        zone.wait_for_l2_tempo_finalized(opt_in_block, L1_TIMEOUT)
            .await?;

        let receipt = zone_token
            .transfer(bob.address(), U256::from(transfer_amount))
            .mined()
            .await?;
        eyre::ensure!(receipt.status(), "L2 transfer from Alice to Bob failed");
    }

    // --- Step 7: Verify balances ---
    let alice_final = zone.balance_of(ZONE_TOKEN_ADDRESS, alice.address()).await?;
    let bob_final = zone.balance_of(ZONE_TOKEN_ADDRESS, bob.address()).await?;

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
