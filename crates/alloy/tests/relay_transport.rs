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
    providers::{Provider, ProviderBuilder, fillers::RecommendedFillers},
};
use tempo_alloy::{
    TempoNetwork, fillers::Random2DNonceFiller, provider::TempoProviderBuilderExt,
    rpc::TempoTransactionRequest,
};

const SPONSOR_URL: &str = "https://sponsor.moderato.tempo.xyz";

/// Account index 9 from "test test test ... junk" mnemonic.
const TEST_PRIVATE_KEY: &str = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

fn rpc_and_sponsor_urls() -> Option<(String, String)> {
    let rpc = std::env::var("TEMPO_TESTNET_RPC_URL").ok()?;
    let sponsor = std::env::var("TEMPO_SPONSOR_URL").unwrap_or_else(|_| SPONSOR_URL.to_string());
    Some((rpc, sponsor))
}

/// Test that the RelayTransport correctly routes reads to the default transport
/// and sendRawTransaction through the sponsor relay.
#[tokio::test]
async fn relay_transport_sponsors_tx_on_testnet() -> eyre::Result<()> {
    let (rpc_url, sponsor_url) = match rpc_and_sponsor_urls() {
        Some(urls) => urls,
        None => {
            eprintln!("TEMPO_TESTNET_RPC_URL not set, skipping");
            return Ok(());
        }
    };

    let signer: alloy_signer_local::PrivateKeySigner = TEST_PRIVATE_KEY.parse()?;
    let sender = signer.address();

    let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
        .filler(Random2DNonceFiller)
        .filler(<TempoNetwork as RecommendedFillers>::recommended_fillers())
        .wallet(EthereumWallet::from(signer))
        .sponsor(sponsor_url)
        .connect(&rpc_url)
        .await?;

    // Reads should work via the default transport.
    let chain_id = provider.get_chain_id().await?;
    println!("Connected to chain {chain_id}");
    assert!(chain_id == 42431 || chain_id == 42069);

    // Send a tx — the sponsor relay adds fee_payer_signature and broadcasts.
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
            if err_str.contains("insufficient funds") {
                println!(
                    "Sponsor relay broadcast failed because the sponsor's fee payer account is unfunded: {err_str}"
                );
            } else {
                return Err(e.into());
            }
        }
    }

    Ok(())
}
