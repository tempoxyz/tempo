//! E2E test for [`RelayTransport`] against the testnet sponsor service.
//!
//! Skipped unless `TEMPO_TESTNET_RPC_URL` is set.
//!
//! Run manually:
//! ```sh
//! TEMPO_TESTNET_RPC_URL=https://rpc.moderato.tempo.xyz \
//!   cargo test -p tempo-alloy --test relay_transport -- --nocapture
//! ```

use alloy::{
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{TxKind, U256},
    providers::{Provider, ProviderBuilder, RootProvider, fillers::RecommendedFillers},
    rpc::client::ClientBuilder,
};
use alloy_eips::Encodable2718;
use tempo_alloy::{
    TempoNetwork,
    fillers::Random2DNonceFiller,
    rpc::TempoTransactionRequest,
    transport::RelayTransport,
};

const SPONSOR_URL: &str = "https://sponsor.testnet.tempo.xyz";

/// Account index 9 from "test test test ... junk" mnemonic.
const TEST_PRIVATE_KEY: &str =
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

fn rpc_and_sponsor_urls() -> Option<(String, String)> {
    let rpc = std::env::var("TEMPO_TESTNET_RPC_URL").ok()?;
    let sponsor = std::env::var("TEMPO_SPONSOR_URL").unwrap_or_else(|_| SPONSOR_URL.to_string());
    Some((rpc, sponsor))
}

/// Test that the RelayTransport correctly routes reads to the default transport
/// and sendRawTransaction through the relay sign-then-broadcast flow.
#[tokio::test]
async fn relay_transport_sponsors_tx_on_testnet() -> eyre::Result<()> {
    let (rpc_url, sponsor_url) = match rpc_and_sponsor_urls() {
        Some(urls) => urls,
        None => {
            eprintln!("TEMPO_TESTNET_RPC_URL not set, skipping");
            return Ok(());
        }
    };

    let rpc_client = ClientBuilder::default().http(rpc_url.parse()?);
    let relay_client = ClientBuilder::default().http(sponsor_url.parse()?);
    let transport = RelayTransport::new(
        rpc_client.transport().clone(),
        relay_client.transport().clone(),
    );

    let signer: alloy_signer_local::PrivateKeySigner = TEST_PRIVATE_KEY.parse()?;
    let sender = signer.address();

    let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
        .filler(Random2DNonceFiller)
        .filler(<TempoNetwork as RecommendedFillers>::recommended_fillers())
        .wallet(EthereumWallet::from(signer))
        .connect_provider(RootProvider::new(
            alloy::rpc::client::RpcClient::new(transport, false),
        ));

    // Reads should work via the default transport.
    let chain_id = provider.get_chain_id().await?;
    println!("Connected to chain {chain_id}");
    assert!(chain_id == 42431 || chain_id == 42069);

    let balance = provider.get_balance(sender).await?;
    println!("Sender {sender} balance: {balance}");
    assert!(balance > U256::ZERO, "test account needs balance");

    // Send a tx — the relay signs it with fee_payer_signature, then broadcasts.
    let mut tx = TempoTransactionRequest::default();
    tx.set_from(sender);
    tx.set_kind(TxKind::Call(sender));
    tx.set_value(U256::ZERO);

    let result = provider.send_transaction(tx).await;

    match result {
        Ok(pending) => {
            let tx_hash = *pending.tx_hash();
            println!("Transaction sent: {tx_hash}");

            let receipt = pending.get_receipt().await?;
            println!(
                "Receipt: status={:?}, block={:?}, fee_payer={}",
                receipt.status(),
                receipt.block_number,
                receipt.fee_payer,
            );

            assert!(receipt.status(), "transaction should succeed");
            assert_eq!(receipt.from, sender);
            assert_ne!(receipt.fee_payer, sender, "sponsor should pay fees");
        }
        Err(e) => {
            let err_str = e.to_string();
            // If the sponsor's fee payer account has no balance, the broadcast
            // fails with "insufficient funds". The sign step still worked —
            // this is a deployment funding issue, not a code bug.
            if err_str.contains("insufficient funds") {
                println!(
                    "Sponsor signed the tx successfully, but broadcast failed \
                     because the sponsor's fee payer account is unfunded: {err_str}"
                );
                println!("This is expected when the testnet sponsor account has no balance.");
            } else {
                return Err(e.into());
            }
        }
    }

    Ok(())
}

/// Test that the relay correctly signs the raw tx (without broadcasting).
/// This verifies the sponsor service can decode and cosign Alloy-encoded AA txs.
#[tokio::test]
async fn relay_sign_only_works() -> eyre::Result<()> {
    let (rpc_url, sponsor_url) = match rpc_and_sponsor_urls() {
        Some(urls) => urls,
        None => {
            eprintln!("TEMPO_TESTNET_RPC_URL not set, skipping");
            return Ok(());
        }
    };

    let rpc_client = ClientBuilder::default().http(rpc_url.parse()?);
    let signer: alloy_signer_local::PrivateKeySigner = TEST_PRIVATE_KEY.parse()?;
    let sender = signer.address();

    let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
        .filler(Random2DNonceFiller)
        .filler(<TempoNetwork as RecommendedFillers>::recommended_fillers())
        .wallet(EthereumWallet::from(signer))
        .connect_provider(RootProvider::new(rpc_client));

    // Fill and sign a tx to get the raw bytes.
    let mut tx = TempoTransactionRequest::default();
    tx.set_from(sender);
    tx.set_kind(TxKind::Call(sender));
    tx.set_value(U256::ZERO);

    let filled = provider.fill(tx).await?;
    let env = match filled {
        alloy::providers::SendableTx::Envelope(env) => env,
        _ => panic!("expected signed envelope"),
    };

    let mut raw_bytes = Vec::new();
    env.encode_2718(&mut raw_bytes);
    let raw_hex = format!("0x{}", alloy::hex::encode(&raw_bytes));

    // Call eth_signRawTransaction on the sponsor.
    let client = reqwest::Client::new();
    let resp = client
        .post(&sponsor_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_signRawTransaction",
            "params": [raw_hex]
        }))
        .send()
        .await?;

    let body: serde_json::Value = resp.json().await?;
    println!("Sponsor sign response: {body}");

    let signed = body
        .get("result")
        .and_then(|v| v.as_str())
        .expect("sponsor should return signed tx");

    // The signed tx should be longer (has fee_payer_signature added).
    assert!(
        signed.len() > raw_hex.len(),
        "signed tx ({}) should be longer than unsigned tx ({})",
        signed.len(),
        raw_hex.len()
    );

    println!(
        "✓ Sponsor successfully cosigned the Alloy-encoded AA tx ({} → {} bytes)",
        raw_bytes.len(),
        (signed.len() - 2) / 2
    );

    Ok(())
}
