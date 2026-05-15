//! E2E test for [`RelayTransport`] against the testnet sponsor service.
//!
//! Skipped unless `TEMPO_TESTNET_RPC_URL` is set (defaults to moderato RPC).
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
use tempo_alloy::{
    TempoNetwork,
    fillers::Random2DNonceFiller,
    rpc::TempoTransactionRequest,
    transport::RelayTransport,
};

/// The testnet sponsor URL (moderato).
const SPONSOR_URL: &str = "https://sponsor.testnet.tempo.xyz";

/// Account index 9 from "test test test ... junk" mnemonic.
const TEST_PRIVATE_KEY: &str =
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

#[tokio::test]
async fn relay_transport_routes_correctly() -> eyre::Result<()> {
    let rpc_url = match std::env::var("TEMPO_TESTNET_RPC_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("TEMPO_TESTNET_RPC_URL not set, skipping relay transport e2e test");
            return Ok(());
        }
    };

    let sponsor_url =
        std::env::var("TEMPO_SPONSOR_URL").unwrap_or_else(|_| SPONSOR_URL.to_string());

    // Build two RpcClients
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

    // Verify reads go through the default (RPC) transport
    let chain_id = provider.get_chain_id().await?;
    println!("Connected to chain {chain_id} via relay transport");
    assert!(
        chain_id == 42431 || chain_id == 42069,
        "unexpected chain id: {chain_id}"
    );

    let balance = provider.get_balance(sender).await?;
    println!("Account {sender} balance: {balance}");
    assert!(balance > U256::ZERO, "test account should have balance");

    // Build a minimal AA tx
    let mut tx = TempoTransactionRequest::default();
    tx.set_from(sender);
    tx.set_kind(TxKind::Call(sender));
    tx.set_value(U256::ZERO);

    // Send through the relay — the sponsor service adds fee_payer_signature
    let pending = provider.send_transaction(tx).await?;
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
    assert_eq!(receipt.from, sender, "receipt.from should match sender");
    assert_ne!(
        receipt.fee_payer, sender,
        "fee payer should be the sponsor, not the sender"
    );

    Ok(())
}
