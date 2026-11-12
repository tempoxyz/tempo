//! TIP-1094 end to end: a plain TIP-20 transfer on a real L1 to a zone deposit address credits
//! the registered recipient on the zone, and a deposit to an unregistered master refunds the
//! sender on L1.

use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::time::Duration;
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        IZoneAddressRegistry, ZONE_ADDRESS_REGISTRY_ADDRESS, ZONE_TOKEN_ADDRESS,
        ZoneDepositAddress, ZonePortal,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;

use crate::utils::{L1TestNode, TIP20_TX_GAS, ZoneAccount, ZoneTestNode, spawn_sequencer};
use zone_node::{DepositAllowlist, DepositAllowlistAdmin};

const L1_TIMEOUT: Duration = Duration::from_secs(30);
const KEY: B256 = B256::repeat_byte(0x5a);

fn deposit_address(zone_id: u32, master_id: [u8; 4], tag: u16) -> Address {
    let mut plaintext = [0u8; 6];
    plaintext[..4].copy_from_slice(&master_id);
    plaintext[4..].copy_from_slice(&tag.to_be_bytes());
    ZoneDepositAddress {
        zone_id,
        version: 1,
        ciphertext: zone_precompiles::ff1::encrypt(&KEY.0, 1, zone_id, plaintext).into(),
    }
    .encode()
}

#[tokio::test(flavor = "multi_thread")]
async fn test_transfer_to_zone_deposit_address() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start_at_t15().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::start_from_l1_with_virtual_address_key(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        KEY,
    )
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    let zone_id = ZonePortal::new(portal_address, l1.provider())
        .zoneId()
        .call()
        .await?;

    // The sender deposits normally first so it can pay for its zone registration.
    let mut sender = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(sender.address(), 10_000_000).await?;
    sender.deposit(1_000_000, L1_TIMEOUT, &zone).await?;

    // Register a fresh recipient; the registry returns its master ID.
    let recipient = Address::repeat_byte(0xbe);
    let registry = IZoneAddressRegistry::new(ZONE_ADDRESS_REGISTRY_ADDRESS, sender.l2_provider());
    let master_id: FixedBytes<4> = registry
        .registerMaster(recipient, B256::repeat_byte(1))
        .call()
        .await?;
    let receipt = registry
        .registerMaster(recipient, B256::repeat_byte(1))
        .gas(TIP20_TX_GAS * 10)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        receipt.status(),
        "registerMaster failed (gas used: {})",
        receipt.gas_used
    );

    // The portal admin turns virtual deposits on.
    let admin = l1.provider_with_signer(l1.admin_signer());
    let receipt = ZonePortal::new(portal_address, &admin)
        .setVirtualDepositsEnabled(true)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "setVirtualDepositsEnabled failed");

    // A plain TIP-20 transfer on L1 to the recipient's deposit address.
    let amount = 2_000_000u128;
    let fee = ZonePortal::new(portal_address, l1.provider())
        .calculateDepositFee()
        .call()
        .await?;
    let l1_token = ITIP20::new(PATH_USD_ADDRESS, sender.l1_provider());
    let receipt = l1_token
        .transfer(deposit_address(zone_id, master_id.0, 7), U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "transfer to deposit address failed");
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        recipient,
        U256::from(amount - fee),
        L1_TIMEOUT,
    )
    .await?;

    // A deposit to an unregistered master refunds the sender on L1 once the batch settles.
    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let receipt = l1_token
        .transfer(deposit_address(zone_id, [0xff; 4], 0), U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        receipt.status(),
        "transfer to unregistered deposit address failed"
    );
    // Measured after the transfer, so the pathUSD the sender paid for gas doesn't count. The
    // refund returns the net amount minus the portal's bounce-back fee.
    let before = l1.balance_of(PATH_USD_ADDRESS, sender.address()).await?;
    let bounceback_fee = ZonePortal::new(portal_address, l1.provider())
        .calculateBouncebackFee()
        .call()
        .await?;
    l1.wait_for_balance(
        PATH_USD_ADDRESS,
        sender.address(),
        before + U256::from(amount - fee - bounceback_fee),
        Duration::from_secs(60),
    )
    .await?;
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, Address::repeat_byte(0xff))
            .await?,
        U256::ZERO
    );

    Ok(())
}

/// With the sequencer deposit allowlist written, a virtual deposit to a registered but unlisted
/// recipient is refunded to the originator on L1, and is credited once the recipient is listed.
#[tokio::test(flavor = "multi_thread")]
async fn test_deposit_allowlist_rejects_virtual_deposits_to_unlisted_recipients() -> eyre::Result<()>
{
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start_at_t15().await?;
    let portal_address = l1.deploy_zone().await?;
    l1.set_access_mode_on_portal(portal_address, false).await?;
    let datadir = tempfile::tempdir()?;
    // This test changes the list in process, so no admin signs RPC writes.
    let allowlist = DepositAllowlist::load(
        datadir.path().join("deposit-allowlist.json"),
        DepositAllowlistAdmin {
            address: Address::ZERO,
            zone_chain_id: 0,
        },
    )?;
    let zone = ZoneTestNode::start_from_l1_with_virtual_address_key_and_deposit_allowlist(
        l1.http_url(),
        l1.ws_url(),
        portal_address,
        KEY,
        allowlist.clone(),
    )
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    let zone_id = ZonePortal::new(portal_address, l1.provider())
        .zoneId()
        .call()
        .await?;

    let mut sender = ZoneAccount::with_signer(l1.signer_at(3), &l1, &zone, portal_address);
    l1.fund_user(sender.address(), 10_000_000).await?;
    sender.deposit(1_000_000, L1_TIMEOUT, &zone).await?;

    let recipient = Address::repeat_byte(0xbe);
    let registry = IZoneAddressRegistry::new(ZONE_ADDRESS_REGISTRY_ADDRESS, sender.l2_provider());
    let master_id: FixedBytes<4> = registry
        .registerMaster(recipient, B256::repeat_byte(1))
        .call()
        .await?;
    let receipt = registry
        .registerMaster(recipient, B256::repeat_byte(1))
        .gas(TIP20_TX_GAS * 10)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "registerMaster failed");

    let admin = l1.provider_with_signer(l1.admin_signer());
    let receipt = ZonePortal::new(portal_address, &admin)
        .setVirtualDepositsEnabled(true)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "setVirtualDepositsEnabled failed");

    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    allowlist.replace(vec![sender.address()])?;

    let amount = 2_000_000u128;
    let portal = ZonePortal::new(portal_address, l1.provider());
    let fee = portal.calculateDepositFee().call().await?;
    let bounceback_fee = portal.calculateBouncebackFee().call().await?;
    let l1_token = ITIP20::new(PATH_USD_ADDRESS, sender.l1_provider());
    let to = deposit_address(zone_id, master_id.0, 7);

    // The recipient is not listed: the sender is refunded on L1 and the recipient gets nothing.
    let receipt = l1_token
        .transfer(to, U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "transfer to deposit address failed");
    let before = l1.balance_of(PATH_USD_ADDRESS, sender.address()).await?;
    l1.wait_for_balance(
        PATH_USD_ADDRESS,
        sender.address(),
        before + U256::from(amount - fee - bounceback_fee),
        Duration::from_secs(60),
    )
    .await?;
    assert_eq!(
        zone.balance_of(ZONE_TOKEN_ADDRESS, recipient).await?,
        U256::ZERO
    );

    // Once the recipient is listed, the same transfer is credited.
    allowlist.set(&[recipient], true)?;
    let receipt = l1_token
        .transfer(to, U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "transfer to deposit address failed");
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        recipient,
        U256::from(amount - fee),
        L1_TIMEOUT,
    )
    .await?;

    Ok(())
}
