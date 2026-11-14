//! Multi-asset zone deposit and withdrawal.

use crate::utils::{L1_TIMEOUT, Network, ZoneCreationConfig};
use alloy::{
    primitives::{B256, U256},
    providers::Provider,
};
use tempo_precompiles::test_util::TIP20Setup;

/// Alice deposits AlphaUSD and BetaUSD into a zone and withdraws both back to L1.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiasset_deposit_and_withdraw() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // --- Step 1: Start L1 and a zone ---
    let net = Network::builder()
        .zone(ZoneCreationConfig::closed(Vec::new()))
        .accounts(1, 10_000_000) // pathUSD for gas
        .start()
        .await?;
    let (l1, [zone], [alice]) = (net.l1(), net.zones(), net.accounts());

    // --- Step 2: Create two TIP-20 tokens on L1 ---
    let alpha_salt = B256::with_last_byte(100);
    let beta_salt = B256::with_last_byte(101);

    let alpha_deposit: u128 = 1_000_000; // 1 AlphaUSD
    let beta_deposit: u128 = 2_000_000; // 2 BetaUSD

    let l1_alpha = TIP20Setup::create("AlphaUSD", "aUSD", l1.dev_address())
        .with_salt(alpha_salt)
        .with_mint(alice.address(), U256::from(alpha_deposit * 2))
        .apply_rpc(&l1.dev_provider())
        .await?;
    let l1_beta = TIP20Setup::create("BetaUSD", "bUSD", l1.dev_address())
        .with_salt(beta_salt)
        .with_mint(alice.address(), U256::from(beta_deposit * 2))
        .apply_rpc(&l1.dev_provider())
        .await?;

    // --- Step 3: Enable both tokens on the portal ---
    // Must happen AFTER zone startup so the zone's L1 subscriber picks up the
    // TokenEnabled events from live blocks.
    l1.enable_token_on_portal(zone.portal_address(), l1_alpha)
        .await?;
    l1.enable_token_on_portal(zone.portal_address(), l1_beta)
        .await?;
    let enable_block = l1.provider().get_block_number().await?;

    // Wait for the zone to finalize past the enableToken blocks
    zone.wait_for_l2_tempo_finalized(enable_block, L1_TIMEOUT)
        .await?;

    // L1 and L2 token addresses are the same by design
    let l2_alpha = l1_alpha;
    let l2_beta = l1_beta;

    // --- Step 4: Alice deposits both tokens ---
    // Deposit pathUSD for L2 gas
    zone.deposit(alice, 5_000_000).await?;

    // Deposit AlphaUSD
    let alpha_minted = zone
        .account(alice)
        .deposit_token(l1_alpha, l2_alpha, alpha_deposit, L1_TIMEOUT, zone)
        .await?;
    assert_eq!(
        alpha_minted,
        U256::from(alpha_deposit),
        "AlphaUSD minted should equal deposit"
    );

    // Deposit BetaUSD
    let beta_minted = zone
        .account(alice)
        .deposit_token(l1_beta, l2_beta, beta_deposit, L1_TIMEOUT, zone)
        .await?;
    assert_eq!(
        beta_minted,
        U256::from(beta_deposit),
        "BetaUSD minted should equal deposit"
    );

    // --- Step 5: Spawn zone sequencer (batch submitter + withdrawal processor) ---
    let _sequencer_handle = zone.spawn_sequencer().await;
    let alpha_withdrawal: u128 = 500_000; // 0.5 AlphaUSD
    zone.withdraw(alice, l2_alpha, alpha_withdrawal).await?;
    let beta_withdrawal: u128 = 1_000_000; // 1 BetaUSD
    zone.withdraw(alice, l2_beta, beta_withdrawal).await?;

    // --- Step 6: Verify L2 balances decreased ---
    let final_alpha = zone.balance_of(l2_alpha, alice.address()).await?;
    assert!(
        final_alpha <= U256::from(alpha_deposit - alpha_withdrawal),
        "L2 AlphaUSD should decrease after withdrawal (got {final_alpha})"
    );

    let final_beta = zone.balance_of(l2_beta, alice.address()).await?;
    assert!(
        final_beta <= U256::from(beta_deposit - beta_withdrawal),
        "L2 BetaUSD should decrease after withdrawal (got {final_beta})"
    );

    Ok(())
}
