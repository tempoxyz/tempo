//! TIP-1094 end to end: a plain TIP-20 transfer on a real L1 to a zone deposit address credits
//! the registered recipient on the zone, and a deposit to an unregistered master refunds the
//! sender on L1.

use alloy::primitives::{Address, B256, FixedBytes, U256};
use std::time::Duration;
use tempo_contracts::{
    precompiles::ITIP20,
    zones::{
        IZoneAddressRegistry, IZoneInbox, ZONE_ADDRESS_REGISTRY_ADDRESS, ZONE_TOKEN_ADDRESS,
        ZoneDepositAddress, ZonePortal,
    },
};
use tempo_precompiles::PATH_USD_ADDRESS;

use alloy::{providers::Provider as _, sol_types::SolEvent as _};

use crate::utils::{
    L1TestNode, TIP20_TX_GAS, ZoneAccount, ZoneLaunch, ZoneTestNode, build_auth_token, signer_at,
    spawn_sequencer,
};
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
    let zone = ZoneTestNode::launch(ZoneLaunch {
        virtual_address_keys: vec![KEY],
        ..ZoneLaunch::from_l1(&l1, portal_address)
    })
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
    let receipt = ZonePortal::new(portal_address, l1.provider_with_signer(l1.admin_signer()))
        .setAccessMode(false)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "setAccessMode failed");
    let datadir = tempfile::tempdir()?;
    // This test changes the list in process, so no admin signs RPC writes.
    let allowlist = DepositAllowlist::load(
        datadir.path().join("deposit-allowlist.json"),
        DepositAllowlistAdmin {
            address: Address::ZERO,
            zone_chain_id: 0,
        },
    )?;
    let zone = ZoneTestNode::launch(ZoneLaunch {
        virtual_address_keys: vec![KEY],
        deposit_allowlist: Some(allowlist.clone()),
        ..ZoneLaunch::from_l1(&l1, portal_address)
    })
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    let zone_id = ZonePortal::new(portal_address, l1.provider())
        .zoneId()
        .call()
        .await?;

    let mut sender = ZoneAccount::with_signer(signer_at(3), &l1, &zone, portal_address);
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

/// A registered recipient gets its deposit address from `zone_deriveDepositAddresses` once the
/// registration settles, and reads the credit's tag from its own `eth_getLogs`, all over the
/// authenticated zone RPC and without the address key.
#[tokio::test(flavor = "multi_thread")]
async fn test_recipient_derives_addresses_and_reads_results_over_rpc() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let l1 = L1TestNode::start_at_t15().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::launch(ZoneLaunch {
        virtual_address_keys: vec![KEY],
        ..ZoneLaunch::from_l1(&l1, portal_address)
    })
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    let zone_id = ZonePortal::new(portal_address, l1.provider())
        .zoneId()
        .call()
        .await?;
    let config = zone_node::rpc::RedactedRpcConfig {
        listen_addr: ([127, 0, 0, 1], 0).into(),
        zone_id,
        chain_id: zone.provider().get_chain_id().await?,
        max_auth_token_validity: zone_node::rpc::auth::DEFAULT_MAX_AUTH_TOKEN_VALIDITY,
        max_response_size: 16 * 1024 * 1024,
        max_connections: 500,
        zone_portal: portal_address,
    };
    let rpc_url = format!(
        "http://{}",
        zone_node::rpc::start_redacted_rpc(config.clone(), zone.rpc_api(config.clone()).await?)
            .await?
    );
    let recipient = alloy_signer_local::PrivateKeySigner::random();
    let token = build_auth_token(&recipient, config.zone_id, config.chain_id);
    let call = |method: &'static str, params: serde_json::Value| {
        let (rpc_url, token) = (rpc_url.clone(), token.clone());
        async move {
            let response: serde_json::Value = reqwest::Client::new()
                .post(rpc_url)
                .header("x-authorization-token", token)
                .json(&serde_json::json!({
                    "jsonrpc": "2.0", "method": method, "params": params, "id": 1
                }))
                .send()
                .await?
                .json()
                .await?;
            eyre::Ok(response)
        }
    };

    // Someone else registers the recipient and passes on the returned master ID.
    let mut sender = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(sender.address(), 10_000_000).await?;
    sender.deposit(1_000_000, L1_TIMEOUT, &zone).await?;
    let registry = IZoneAddressRegistry::new(ZONE_ADDRESS_REGISTRY_ADDRESS, sender.l2_provider());
    let master_id: FixedBytes<4> = registry
        .registerMaster(recipient.address(), B256::repeat_byte(2))
        .call()
        .await?;
    let receipt = registry
        .registerMaster(recipient.address(), B256::repeat_byte(2))
        .gas(TIP20_TX_GAS * 10)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "registerMaster failed");

    // Derivation waits for the registration to settle on Tempo.
    let _sequencer = spawn_sequencer(&l1, &zone, portal_address, l1.dev_signer()).await;
    let params = serde_json::json!([{ "masterId": master_id, "userTags": [7, 8] }]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let derived = loop {
        let response = call("zone_deriveDepositAddresses", params.clone()).await?;
        if let Some(result) = response.get("result") {
            break result.clone();
        }
        eyre::ensure!(
            tokio::time::Instant::now() < deadline,
            "registration never settled: {response}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert_eq!(derived["version"], 1);
    let addresses: Vec<Address> = serde_json::from_value(derived["addresses"].clone())?;
    assert_eq!(
        addresses,
        vec![
            deposit_address(zone_id, master_id.0, 7),
            deposit_address(zone_id, master_id.0, 8)
        ]
    );

    // Another caller can't derive the recipient's addresses.
    let other = alloy_signer_local::PrivateKeySigner::random();
    let response: serde_json::Value = reqwest::Client::new()
        .post(rpc_url.clone())
        .header(
            "x-authorization-token",
            build_auth_token(&other, config.zone_id, config.chain_id),
        )
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "method": "zone_deriveDepositAddresses", "params": params, "id": 1
        }))
        .send()
        .await?
        .json()
        .await?;
    assert!(response.get("result").is_none(), "{response}");

    // Pay the second address and read the result as the recipient.
    let amount = 2_000_000u128;
    let fee = ZonePortal::new(portal_address, l1.provider())
        .calculateDepositFee()
        .call()
        .await?;
    let receipt = ITIP20::new(PATH_USD_ADDRESS, sender.l1_provider())
        .transfer(addresses[1], U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "transfer to deposit address failed");
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        recipient.address(),
        U256::from(amount - fee),
        L1_TIMEOUT,
    )
    .await?;
    let logs = call(
        "eth_getLogs",
        serde_json::json!([{
            "fromBlock": "0x0",
            "toBlock": "latest",
            "topics": [
                IZoneInbox::VirtualDepositProcessed::SIGNATURE_HASH,
                recipient.address().into_word(),
            ],
        }]),
    )
    .await?;
    let logs: Vec<alloy::rpc::types::Log> = serde_json::from_value(logs["result"].clone())?;
    assert_eq!(logs.len(), 1);
    let event = IZoneInbox::VirtualDepositProcessed::decode_log(&logs[0].inner)?.data;
    assert_eq!(event.to, recipient.address());
    assert_eq!(event.originator, sender.address());
    assert_eq!(event.masterId, master_id);
    assert_eq!(event.userTag, FixedBytes::from(8u16.to_be_bytes()));
    assert_eq!(event.amount, amount - fee);

    Ok(())
}

/// With two key files configured, the sequencer initializes version 1 and then version 2, and a
/// transfer to a version-2 address is credited.
#[tokio::test(flavor = "multi_thread")]
async fn test_second_key_version_is_initialized_and_used() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    const KEY_V2: B256 = B256::repeat_byte(0x6b);

    let l1 = L1TestNode::start_at_t15().await?;
    let portal_address = l1.deploy_zone().await?;
    let zone = ZoneTestNode::launch(ZoneLaunch {
        virtual_address_keys: vec![KEY, KEY_V2],
        ..ZoneLaunch::from_l1(&l1, portal_address)
    })
    .await?;
    zone.wait_for_l2_tempo_finalized(0, L1_TIMEOUT).await?;
    let zone_id = ZonePortal::new(portal_address, l1.provider())
        .zoneId()
        .call()
        .await?;

    let mut sender = ZoneAccount::from_l1_and_zone(&l1, &zone, portal_address);
    l1.fund_user(sender.address(), 10_000_000).await?;
    sender.deposit(1_000_000, L1_TIMEOUT, &zone).await?;

    let recipient = Address::repeat_byte(0xc7);
    let registry = IZoneAddressRegistry::new(ZONE_ADDRESS_REGISTRY_ADDRESS, sender.l2_provider());
    let master_id: FixedBytes<4> = registry
        .registerMaster(recipient, B256::repeat_byte(3))
        .call()
        .await?;
    let receipt = registry
        .registerMaster(recipient, B256::repeat_byte(3))
        .gas(TIP20_TX_GAS * 10)
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "registerMaster failed");

    let initialized: Vec<u8> = zone
        .provider()
        .get_logs(
            &alloy::rpc::types::Filter::new()
                .address(zone_primitives::constants::ZONE_INBOX_ADDRESS)
                .event_signature(IZoneInbox::VirtualAddressKeyInitialized::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?
        .iter()
        .map(|log| {
            IZoneInbox::VirtualAddressKeyInitialized::decode_log(&log.inner)
                .map(|event| event.data.version)
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(initialized, vec![1, 2]);

    let mut plaintext = [0u8; 6];
    plaintext[..4].copy_from_slice(&master_id.0);
    plaintext[4..].copy_from_slice(&9u16.to_be_bytes());
    let to = ZoneDepositAddress {
        zone_id,
        version: 2,
        ciphertext: zone_precompiles::ff1::encrypt(&KEY_V2.0, 2, zone_id, plaintext).into(),
    }
    .encode();
    let amount = 2_000_000u128;
    let fee = ZonePortal::new(portal_address, l1.provider())
        .calculateDepositFee()
        .call()
        .await?;
    let receipt = ITIP20::new(PATH_USD_ADDRESS, sender.l1_provider())
        .transfer(to, U256::from(amount))
        .send()
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(
        receipt.status(),
        "transfer to version-2 deposit address failed"
    );
    zone.wait_for_balance(
        ZONE_TOKEN_ADDRESS,
        recipient,
        U256::from(amount - fee),
        L1_TIMEOUT,
    )
    .await?;

    Ok(())
}
