//! E2E tests for the TIP-403 policy proxy precompile on the zone.
//!
//! These tests verify that the zone TIP-403 precompile correctly serves authorization queries from
//! finalized raw L1 storage via `L1StateCache` and rejects mutating calls. The cache is populated
//! directly in tests (no L1 subscriber).

use alloy::primitives::{Address, U256, address};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::TransactionRequest;
use tempo_chainspec::spec::TEMPO_T0_BASE_FEE;
use tempo_contracts::precompiles::{
    ITIP20,
    ITIP403Registry::{self, PolicyType},
};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP403_REGISTRY_ADDRESS, tip403_registry::AuthRole};
use zone_precompiles::ZONE_FEE_MANAGER_ADDRESS;

use crate::utils::{
    DEFAULT_TIMEOUT, PolicySeed, TIP20_TX_GAS, l1_dev_signer, seed_raw_tip403_policy,
    seed_raw_tip403_token_policy, start_local_zone_with_fixture,
};

/// Deposit pathUSD to Alice, then transfer a portion to Bob on the zone.
///
/// TIP-20 transfers use the default anchored `transferPolicyId` of 1 (allow all).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO: re-enable once zones allow user transfers"]
async fn test_tip20_transfer_on_zone() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice_signer = l1_dev_signer();
    let alice = alice_signer.address();

    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let deposit_amount: u128 = 1_000_000; // 1 pathUSD (6 decimals)

    // Deposit pathUSD to Alice
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, alice, alice, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);

    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        alice,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;

    // Alice transfers 400,000 to Bob
    let transfer_amount: u128 = 400_000;
    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(zone.http_url().clone());

    // T6+ transfers also consult the recipient's address-level receive policy on L1.
    // Seed the anchor before pool validation; the next execution block inherits this baseline.
    fixture.seed_no_receive_policy(bob)?;

    let tip20 = ITIP20::new(PATH_USD_ADDRESS, &alice_provider);
    let pending = tip20
        .transfer(bob, U256::from(transfer_amount))
        .gas_price(u128::from(TEMPO_T0_BASE_FEE))
        .gas(TIP20_TX_GAS)
        .send()
        .await?;

    // Inject an empty L1 block to trigger block production including the pool tx.
    fixture.inject_empty_block(zone.deposit_queue());

    let receipt = pending.get_receipt().await?;
    assert!(receipt.status(), "transfer should succeed");

    // Verify Bob received the transfer
    let bob_balance = zone
        .wait_for_balance(
            PATH_USD_ADDRESS,
            bob,
            U256::from(transfer_amount),
            DEFAULT_TIMEOUT,
        )
        .await?;
    assert_eq!(bob_balance, U256::from(transfer_amount));

    // Alice should have remaining balance minus gas
    let alice_balance = zone.balance_of(PATH_USD_ADDRESS, alice).await?;
    let expected_remaining = deposit_amount - transfer_amount;
    assert!(
        alice_balance <= U256::from(expected_remaining),
        "alice should have at most {expected_remaining} (got {alice_balance})"
    );

    Ok(())
}

/// Protocol fee collection must use the finalized L1 policy even when the tx does not call TIP-20.
#[tokio::test(flavor = "multi_thread")]
async fn test_l1_blacklisted_sender_cannot_pay_for_empty_transaction() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
    let alice_signer = l1_dev_signer();
    let alice = alice_signer.address();

    let deposit_amount = 1_000_000u128;
    let deposit = fixture.make_deposit(PATH_USD_ADDRESS, alice, alice, deposit_amount);
    fixture.inject_deposits(zone.deposit_queue(), vec![deposit]);
    zone.wait_for_balance(
        PATH_USD_ADDRESS,
        alice,
        U256::from(deposit_amount),
        DEFAULT_TIMEOUT,
    )
    .await?;
    let anchor = zone.wait_for_tempo_block_number(1, DEFAULT_TIMEOUT).await?;

    const BLACKLIST_POLICY_ID: u64 = 42;
    seed_raw_tip403_token_policy(
        &mut zone.l1_state_cache().lock(),
        anchor,
        PATH_USD_ADDRESS,
        BLACKLIST_POLICY_ID,
    );
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        anchor,
        &[PolicySeed::simple(
            BLACKLIST_POLICY_ID,
            PolicyType::BLACKLIST,
            &[(alice, true), (ZONE_FEE_MANAGER_ADDRESS, false)],
        )],
    )?;

    let alice_provider = ProviderBuilder::new()
        .wallet(alice_signer)
        .connect_http(zone.http_url().clone());
    let request = TransactionRequest::default()
        .to(alice)
        .gas_limit(TIP20_TX_GAS)
        .gas_price(u128::from(TEMPO_T0_BASE_FEE));

    let nonce_before = alice_provider.get_transaction_count(alice).await?;
    let error = alice_provider
        .send_transaction(request)
        .await
        .expect_err("L1-blacklisted fee payer transaction must be rejected by the pool");
    assert!(
        error.to_string().contains("PolicyForbids"),
        "unexpected pool rejection: {error}"
    );
    assert_eq!(
        alice_provider.get_transaction_count(alice).await?,
        nonce_before,
        "rejected fee payment must not consume the sender nonce"
    );
    assert_eq!(
        zone.balance_of(PATH_USD_ADDRESS, alice).await?,
        U256::from(deposit_amount),
        "rejected fee payment must leave the sender balance unchanged"
    );

    Ok(())
}

/// Whitelist policy: set entries are authorized, non-set entries are not (fail-closed).
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_whitelist_authorization() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");

    // Populate raw L1 state at block 1.
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        1,
        &[
            PolicySeed::simple(5, PolicyType::WHITELIST, &[(alice, true)]),
            PolicySeed::simple(5, PolicyType::WHITELIST, &[(bob, false)]),
        ],
    )?;

    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice, bob], 1, 5)?;

    // Alice is whitelisted → authorized
    let alice_authorized = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(alice_authorized, "alice should be authorized (whitelisted)");
    // Bob is NOT in whitelist → not authorized (fail-closed)
    let bob_authorized = registry.is_auth_as(bob, AuthRole::Transfer).await;
    assert!(
        !bob_authorized,
        "bob should NOT be authorized (not in whitelist)"
    );

    Ok(())
}

/// Blacklist policy: set entries are NOT authorized, non-set entries ARE authorized.
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_blacklist_authorization() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");

    // Populate raw L1 state at block 1.
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        1,
        &[
            PolicySeed::simple(5, PolicyType::BLACKLIST, &[(alice, true)]),
            PolicySeed::simple(5, PolicyType::BLACKLIST, &[(bob, false)]),
        ],
    )?;

    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice, bob], 1, 5)?;

    // Alice is in blacklist → NOT authorized
    let alice_authorized = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(
        !alice_authorized,
        "alice should NOT be authorized (blacklisted)"
    );

    // Bob is NOT in blacklist → authorized
    let bob_authorized = registry.is_auth_as(bob, AuthRole::Transfer).await;
    assert!(bob_authorized, "bob should be authorized (not blacklisted)");

    Ok(())
}

/// Compound policy: delegates to sub-policies based on role.
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_compound_policy() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");

    // Seed the compound policy graph at block 1.
    // Policy 5 = sender whitelist, policy 6 = recipient blacklist; compound policy 10
    // references them.
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        1,
        &[
            PolicySeed::simple(5, PolicyType::WHITELIST, &[(alice, true)]),
            PolicySeed::simple(6, PolicyType::BLACKLIST, &[(alice, false), (bob, true)]),
            PolicySeed::compound(10, 5, 6, 1),
        ],
    )?;

    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice, bob], 1, 10)?;

    // Alice is in sender whitelist → authorized as sender
    let alice_sender = registry.is_auth_as(alice, AuthRole::Sender).await;
    assert!(alice_sender, "alice should be authorized as sender");

    // Bob is in recipient blacklist → NOT authorized as recipient
    let bob_recipient = registry.is_auth_as(bob, AuthRole::Recipient).await;
    assert!(
        !bob_recipient,
        "bob should NOT be authorized as recipient (blacklisted)"
    );

    Ok(())
}

/// Builtin policies: policy 0 = reject all, policy 1 = allow all.
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_builtin_policies() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice], 1, 0)?;

    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(1, DEFAULT_TIMEOUT).await?;
    assert!(
        !registry.is_auth_as(alice, AuthRole::Transfer).await,
        "policy 0 should reject all"
    );

    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice], 2, 1)?;
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(2, DEFAULT_TIMEOUT).await?;
    assert!(
        registry.is_auth_as(alice, AuthRole::Transfer).await,
        "policy 1 should allow all"
    );

    Ok(())
}

/// Mutating calls (e.g. createPolicy) should revert with ReadOnlyRegistry.
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_reverts_mutating_calls() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    let registry = ITIP403Registry::new(TIP403_REGISTRY_ADDRESS, zone.provider());

    // createPolicy should revert
    let result = registry
        .createPolicy(Address::with_last_byte(1), PolicyType::WHITELIST)
        .call()
        .await;

    assert!(result.is_err(), "createPolicy should revert on zone proxy");

    Ok(())
}

/// Compound policy `isAuthorized` checks BOTH sender AND recipient sub-policies (Transfer role).
#[tokio::test(flavor = "multi_thread")]
async fn test_compound_policy_transfer_role_authorization() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    let bob = address!("0x0000000000000000000000000000000000000B0B");
    let carol = address!("0x000000000000000000000000000000000000CA01");

    // Seed the complete policy membership at block 1.
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        1,
        &[
            PolicySeed::simple(
                5,
                PolicyType::WHITELIST,
                &[(alice, true), (bob, false), (carol, true)],
            ),
            PolicySeed::simple(
                6,
                PolicyType::BLACKLIST,
                &[(alice, false), (bob, true), (carol, true)],
            ),
            PolicySeed::compound(10, 5, 6, 1),
        ],
    )?;

    fixture.inject_empty_blocks(zone.deposit_queue(), 3);
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    let registry =
        fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice, bob, carol], 1, 10)?;

    // Alice: whitelisted as sender + NOT in recipient blacklist → true
    let alice_auth = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(
        alice_auth,
        "alice should be authorized (passes both sender and recipient checks)"
    );

    // Bob: NOT in sender whitelist → false (short-circuits before recipient check)
    let bob_auth = registry.is_auth_as(bob, AuthRole::Transfer).await;
    assert!(
        !bob_auth,
        "bob should NOT be authorized (not in sender whitelist)"
    );

    // Carol is whitelisted as sender but blacklisted as recipient, so transfer auth fails.
    let carol_auth = registry.is_auth_as(carol, AuthRole::Transfer).await;
    assert!(
        !carol_auth,
        "carol should NOT be authorized (passes sender but fails recipient blacklist)"
    );

    Ok(())
}

/// Block-versioned raw L1 policy writes update the proxy's responses.
#[tokio::test(flavor = "multi_thread")]
async fn test_policy_proxy_uses_block_versioned_raw_state() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;

    let alice = address!("0x000000000000000000000000000000000000A11C");
    // Step 1: materialize block-1 state before accepting block 1, then query at anchor 1.
    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice], 1, 5)?;
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        1,
        &[PolicySeed::simple(
            5,
            PolicyType::WHITELIST,
            &[(alice, true)],
        )],
    )?;
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(1, DEFAULT_TIMEOUT).await?;

    let authorized = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(authorized, "alice should be authorized at block 1");

    // Step 2: materialize block-2 state before accepting block 2, then query at anchor 2.
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        2,
        &[PolicySeed::simple(
            5,
            PolicyType::WHITELIST,
            &[(alice, false)],
        )],
    )?;
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(2, DEFAULT_TIMEOUT).await?;

    let authorized = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(!authorized, "alice should NOT be authorized at block 2");

    // Step 3: materialize the compound policy before accepting block 3.
    let registry = fixture.tip403_registry_check(&zone, PATH_USD_ADDRESS, &[alice], 3, 10)?;
    seed_raw_tip403_policy(
        zone.l1_state_cache(),
        3,
        &[PolicySeed::compound(10, 5, 1, 1)],
    )?;
    fixture.inject_empty_block(zone.deposit_queue());
    zone.wait_for_tempo_block_number(3, DEFAULT_TIMEOUT).await?;

    // Policy 10 uses the block-2 whitelist where Alice was removed.
    let authorized = registry.is_auth_as(alice, AuthRole::Transfer).await;
    assert!(!authorized, "compound policy 10 should reject alice");

    Ok(())
}
