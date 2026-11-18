//! TIP-1022 virtual addresses on a Zone, end to end against a real Tempo L1 dev node.
//!
//! From T15 the Zone reads the address registry from Tempo, so a master registered on Tempo
//! receives Zone transfers and deposits sent to its virtual addresses.

use crate::{
    l1_e2e::{get_deposit_allowlist, send_set, sign_set},
    utils::{
        AllowlistSetup, ClusterConfig, L1_TIMEOUT, L1TestNode, ZoneAccount, ZoneTestNode,
        deposit_allowlist_admin, poll_until, spawn_sequencer, start_real_p2p_cluster,
    },
};
use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    sol_types::{SolError, SolEvent, SolValue},
};
use std::time::Duration;
use tempo_alloy::test_utils::CallBuilderExt;
use tempo_contracts::{
    precompiles::{ADDRESS_REGISTRY_ADDRESS, IAddressRegistry, ITIP20},
    zones::{IZoneOutbox, ZONE_OUTBOX_ADDRESS, ZONE_TOKEN_ADDRESS, ZonePortal},
};
use tempo_precompiles::test_util::{VIRTUAL_MASTER, VIRTUAL_SALT};
use tempo_primitives::{MasterId, TempoAddressExt as _, UserTag, test_utils::signers};

const AMOUNT: u128 = 1_000_000;
const TRANSFER_GAS: u64 = 500_000;

/// The master ID [`VIRTUAL_MASTER`] gets when it registers with [`VIRTUAL_SALT`].
fn registered_master_id() -> MasterId {
    let hash = keccak256((VIRTUAL_MASTER, B256::from(VIRTUAL_SALT)).abi_encode_packed());
    MasterId::from_slice(&hash[4..8])
}

fn virtual_address(master_id: MasterId, tag: u8) -> Address {
    Address::new_virtual(master_id, UserTag::repeat_byte(tag))
}

/// Registers [`VIRTUAL_MASTER`], the L1 dev signer, on Tempo and returns the registration block.
async fn register_master_on_tempo(l1: &L1TestNode) -> eyre::Result<u64> {
    assert_eq!(l1.dev_address(), VIRTUAL_MASTER);
    let provider = l1.dev_provider();
    let receipt = IAddressRegistry::new(ADDRESS_REGISTRY_ADDRESS, &provider)
        .registerVirtualMaster(FixedBytes::from(VIRTUAL_SALT))
        .mined()
        .await?;
    eyre::ensure!(receipt.status(), "registerVirtualMaster reverted");
    let master = IAddressRegistry::new(ADDRESS_REGISTRY_ADDRESS, &provider)
        .getMaster(registered_master_id())
        .call()
        .await?;
    assert_eq!(master, VIRTUAL_MASTER, "unexpected master ID");
    Ok(receipt.block_number.expect("mined receipt has a block"))
}

/// Opens portal access so fresh test keys can deposit; the zone isn't launched yet, so the
/// admin sets it on Tempo directly.
async fn open_portal(l1: &L1TestNode, portal_address: Address) -> eyre::Result<()> {
    let receipt = ZonePortal::new(portal_address, l1.admin_provider())
        .setAccessMode(false)
        .mined()
        .await?;
    eyre::ensure!(receipt.status(), "setAccessMode reverted");
    Ok(())
}

/// Waits for the portal to bounce an `amount` deposit made at or after L1 block `from` back to
/// `refund_recipient`.
async fn wait_for_deposit_bounce<P: Provider>(
    portal: &ZonePortal::ZonePortalInstance<P>,
    from: u64,
    refund_recipient: Address,
    amount: u128,
) -> eyre::Result<()> {
    poll_until(
        Duration::from_secs(60),
        Duration::from_millis(250),
        "deposit bounce-back on L1",
        || async move {
            let bounced = portal
                .DepositBounceBack_filter()
                .from_block(from)
                .query()
                .await?
                .into_iter()
                .any(|(event, _)| {
                    event.tempoRefundRecipient == refund_recipient
                        && event.amount + event.bouncebackFee == amount
                });
            Ok(bounced.then_some(()))
        },
    )
    .await
}

/// A Zone transfer or deposit to a virtual address credits the master registered on Tempo, from
/// the first Tempo block after it registers. Deposits to unregistered virtual addresses bounce
/// back, and withdrawals refuse a virtual fallback recipient.
#[tokio::test(flavor = "multi_thread")]
async fn virtual_addresses_resolve_through_the_tempo_registry() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start().await?;
    let portal_address = l1.deploy_zone().await?;
    open_portal(&l1, portal_address).await?;
    let zone = ZoneTestNode::start_from_l1(&l1, portal_address).await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    zone.enable_transfers(true).await?;

    let [alice_signer] = signers();
    let mut alice = ZoneAccount::with_signer(alice_signer.clone(), &l1, &zone, portal_address);
    l1.fund_user(alice.address(), 10 * AMOUNT).await?;
    alice.deposit(4 * AMOUNT, L1_TIMEOUT, &zone).await?;
    let token = ITIP20::new(
        ZONE_TOKEN_ADDRESS,
        ProviderBuilder::new()
            .wallet(alice_signer)
            .connect_http(zone.http_url().clone()),
    );

    let master_id = registered_master_id();
    let (transfer_target, deposit_target) = (
        virtual_address(master_id, 0x01),
        virtual_address(master_id, 0x02),
    );
    let unregistered = virtual_address(MasterId::from(!u32::from_be_bytes(master_id.0)), 0x03);
    let master_balance = || zone.balance_of(ZONE_TOKEN_ADDRESS, VIRTUAL_MASTER);
    let master_before = master_balance().await?;

    // Before the master registers on Tempo, the Zone reads its ID as unregistered.
    let error = token
        .transfer(transfer_target, U256::from(AMOUNT))
        .from(alice.address())
        .call()
        .await
        .expect_err("a transfer to an unregistered virtual address must revert");
    assert_eq!(
        error.as_revert_data().unwrap(),
        IAddressRegistry::VirtualAddressUnregistered {}.abi_encode(),
    );

    let registered_at = register_master_on_tempo(&l1).await?;
    zone.wait_for_l2_tempo_finalized(registered_at, L1_TIMEOUT)
        .await?;

    // The same transfer now reaches the master.
    let receipt = token
        .transfer(transfer_target, U256::from(AMOUNT))
        .gas(TRANSFER_GAS)
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(
        receipt.status(),
        "transfer to a registered virtual address reverted"
    );
    // The master is also the block's fee recipient, so check the forwarding events, not its
    // exact balance.
    let transfers: Vec<_> = receipt
        .logs()
        .iter()
        .filter_map(|log| ITIP20::Transfer::decode_log(&log.inner).ok())
        .map(|log| (log.from, log.to, log.amount))
        .collect();
    // The fee transfer to the block's fee recipient follows the two forwarding hops.
    assert_eq!(
        transfers[..2],
        [
            (alice.address(), transfer_target, U256::from(AMOUNT)),
            (transfer_target, VIRTUAL_MASTER, U256::from(AMOUNT)),
        ]
    );
    assert!(master_balance().await? >= master_before + U256::from(AMOUNT));
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, transfer_target).await?,
        U256::ZERO
    );

    // An encrypted deposit to a registered virtual address credits the master.
    alice
        .submit_deposit_with_memo(AMOUNT, deposit_target, B256::ZERO)
        .await?;
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        VIRTUAL_MASTER,
        master_before + U256::from(2 * AMOUNT),
        L1_TIMEOUT,
    )
    .await?;
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, deposit_target).await?,
        U256::ZERO
    );

    // Bounce-backs settle through the sequencer, which shares the dev signer, so it starts only
    // once the dev signer's registration is done.
    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let bounce_from = alice
        .submit_deposit_with_memo(AMOUNT, unregistered, B256::ZERO)
        .await?;
    wait_for_deposit_bounce(&portal, bounce_from, alice.address(), AMOUNT).await?;
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, unregistered).await?,
        U256::ZERO
    );

    // A bounced withdrawal is parked for its fallback recipient, which a virtual address can't
    // claim, so the outbox refuses one.
    alice.approve_outbox(ZONE_TOKEN_ADDRESS).await?;
    let alice_address = alice.address();
    let outbox = IZoneOutbox::new(ZONE_OUTBOX_ADDRESS, token.provider());
    let withdraw_with_fallback = |fallback| {
        outbox
            .requestWithdrawal(
                ZONE_TOKEN_ADDRESS,
                alice_address,
                AMOUNT,
                B256::ZERO,
                0,
                fallback,
                Bytes::new(),
                Bytes::new(),
            )
            .from(alice_address)
    };
    let error = withdraw_with_fallback(transfer_target)
        .call()
        .await
        .expect_err("a virtual fallback recipient must be refused");
    assert_eq!(
        error.as_revert_data().unwrap(),
        IZoneOutbox::InvalidFallbackRecipient {}.abi_encode(),
    );
    withdraw_with_fallback(alice_address).call().await?;

    Ok(())
}

/// Sequencer allowlists refuse virtual addresses: the Zone credits a virtual address's master,
/// which the screens can't resolve, so the admin can't list one. Even a listed master is then
/// unreachable through its virtual addresses, for transfers (screened by the P2P sequencers'
/// pools) and deposits.
#[tokio::test(flavor = "multi_thread")]
async fn sequencer_allowlists_refuse_virtual_addresses() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let [alice] = signers();
    let target = virtual_address(registered_master_id(), 0x01);
    let cluster = start_real_p2p_cluster(ClusterConfig {
        deposit_allowlist: Some(AllowlistSetup {
            seed: vec![alice.address(), VIRTUAL_MASTER],
            rpc_relays_writes: false,
        }),
        ..Default::default()
    })
    .await?;
    let (l1, leader) = (&cluster.l1, &cluster.nodes[0]);

    let write = sign_set(
        &deposit_allowlist_admin(),
        cluster.zone_chain_id,
        &[target],
        true,
        1,
    )?;
    for node in &cluster.nodes {
        let error = send_set(node, &write)
            .await
            .expect_err("an allowlist write must refuse a virtual address")
            .to_string();
        assert!(
            error.contains("is a TIP-1022 virtual address and cannot be allowlisted"),
            "{error}"
        );
        let mut listed = get_deposit_allowlist(node).await?;
        listed.sort();
        let mut expected = vec![alice.address(), VIRTUAL_MASTER];
        expected.sort();
        assert_eq!(listed, expected, "a rejected write changed the allowlist");
    }

    let registered_at = register_master_on_tempo(l1).await?;
    let opt_in_block = leader.enable_transfers(true).await?;

    let mut account = ZoneAccount::with_signer(alice.clone(), l1, leader, cluster.portal_address);
    l1.fund_user(alice.address(), 4 * AMOUNT).await?;
    account.deposit(AMOUNT, L1_TIMEOUT, leader).await?;
    for node in &cluster.nodes {
        node.wait_for_l2_tempo_finalized(opt_in_block.max(registered_at), L1_TIMEOUT)
            .await?;
    }

    for node in &cluster.nodes {
        let error = ITIP20::new(
            ZONE_TOKEN_ADDRESS,
            ProviderBuilder::new()
                .wallet(alice.clone())
                .connect_http(node.http_url().clone()),
        )
        .transfer(target, U256::ONE)
        .gas(TRANSFER_GAS)
        .send()
        .await
        .expect_err("a sequencer must refuse a transfer to a virtual address")
        .to_string();
        assert!(
            error.contains("transfer sender or recipient is not allowlisted"),
            "{error}"
        );
    }

    let portal = ZonePortal::new(cluster.portal_address, l1.provider());
    let bounce_from = account
        .submit_deposit_with_memo(AMOUNT, target, B256::ZERO)
        .await?;
    wait_for_deposit_bounce(&portal, bounce_from, alice.address(), AMOUNT).await?;
    assert_eq!(
        leader.balance_of(ZONE_TOKEN_ADDRESS, target).await?,
        U256::ZERO,
    );

    Ok(())
}
