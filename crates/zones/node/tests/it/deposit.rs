use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use tempo_contracts::precompiles::ITIP20;
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_zone_contracts::{DepositPayload, ZonePortal};
use zone_precompiles::ecies::encrypt_deposit;

use crate::utils::{DEFAULT_POLL, ZoneTestNode, poll_until};

const L1_WS_RPC_URL: &str = "wss://rpc.testnet.tempo.xyz";
const L1_HTTP_RPC_URL: &str = "https://rpc.testnet.tempo.xyz";

/// Fund an address on L1 via the testnet faucet (`tempo_fundAddress`).
async fn fund_l1_wallet(address: Address) -> eyre::Result<()> {
    let provider = ProviderBuilder::new().connect_http(L1_HTTP_RPC_URL.parse()?);
    let _: Vec<B256> = provider
        .raw_request("tempo_fundAddress".into(), (address,))
        .await?;
    Ok(())
}

/// End-to-end: deposit on an existing L1 ZonePortal, verify mint on zone.
///
/// Uses an existing ZonePortal deployed on testnet. The zone node starts
/// locally with the L1 subscriber pointing at testnet to pick up deposit
/// events, then mints on its local chain.
///
/// Requires env var:
/// - `L1_PORTAL_ADDRESS`: existing ZonePortal contract address on testnet
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires testnet: L1_PORTAL_ADDRESS"]
async fn test_l1_deposit_mints_on_zone() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let portal_address: Address = std::env::var("L1_PORTAL_ADDRESS")?.parse()?;

    // Fresh L1 wallet, funded via faucet
    let l1_signer = PrivateKeySigner::random();
    let depositor = l1_signer.address();
    fund_l1_wallet(depositor).await?;

    // Start the zone node pointing at the existing portal on testnet
    let zone = ZoneTestNode::start(L1_WS_RPC_URL.to_string(), portal_address).await?;

    let zone_provider = ProviderBuilder::new().connect_http(zone.http_url().clone());
    let zone_token = ITIP20::new(PATH_USD_ADDRESS, zone_provider.clone());

    // --- L1: deposit on the existing portal ---

    let l1_provider = ProviderBuilder::new()
        .wallet(l1_signer)
        .connect_http(L1_HTTP_RPC_URL.parse()?);

    let portal = ZonePortal::new(portal_address, &l1_provider);
    let l1_token_address = PATH_USD_ADDRESS;
    let fee = portal.calculateDepositFee().call().await?;

    let deposit_amount: u128 = fee + 1_000_000;
    let expected_net = deposit_amount - fee;

    // Approve portal to transfer our L1 tokens
    let l1_token = ITIP20::new(l1_token_address, &l1_provider);
    l1_token
        .approve(portal_address, U256::from(deposit_amount))
        .send()
        .await?
        .get_receipt()
        .await?;

    let recipient = depositor;

    // Zone balance before deposit
    let balance_before = zone_token
        .balanceOf(recipient)
        .call()
        .await
        .unwrap_or(U256::ZERO);

    let (key, key_index) = portal.encryption_key().await?;
    let y_parity = key
        .normalized_y_parity()
        .ok_or_else(|| eyre::eyre!("invalid portal encryption key parity"))?;
    let encrypted = encrypt_deposit(
        &key.x,
        y_parity,
        recipient,
        B256::ZERO,
        depositor,
        portal_address,
        key_index,
    )
    .ok_or_else(|| eyre::eyre!("failed to encrypt deposit"))?;

    // Execute encrypted deposit on L1
    let deposit_receipt = portal
        .deposit(
            l1_token_address,
            deposit_amount,
            key_index,
            DepositPayload {
                ephemeralPubkeyX: encrypted.eph_pub_x,
                ephemeralPubkeyYParity: encrypted.eph_pub_y_parity,
                ciphertext: Bytes::from(encrypted.ciphertext),
                nonce: encrypted.nonce.into(),
                tag: encrypted.tag.into(),
            },
            depositor,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    assert!(deposit_receipt.status(), "L1 deposit tx failed");

    // --- Poll zone for the minted balance ---

    let minted = poll_until(
        std::time::Duration::from_secs(5),
        DEFAULT_POLL,
        "deposit mint on zone",
        || {
            let zone_token = &zone_token;
            async move {
                let balance_now = zone_token
                    .balanceOf(recipient)
                    .call()
                    .await
                    .unwrap_or(U256::ZERO);
                if balance_now > balance_before {
                    Ok(Some(balance_now - balance_before))
                } else {
                    Ok(None)
                }
            }
        },
    )
    .await?;

    assert_eq!(
        minted,
        U256::from(expected_net),
        "minted amount should equal net deposit (deposit {deposit_amount} - fee {fee})",
    );

    Ok(())
}
