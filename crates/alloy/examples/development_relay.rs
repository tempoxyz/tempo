//! Local development relay interoperability. Run `tempo node --dev` first.

use alloy::{
    network::{EthereumWallet, ReceiptResponse},
    primitives::TxKind,
    providers::{Provider, ProviderBuilder},
};
use alloy_signer_local::PrivateKeySigner;
use tempo_alloy::{
    TempoNetwork,
    provider::{TempoProviderBuilderExt, TempoRelayProviderExt, relay::RelayFillRequest},
    rpc::TempoTransactionRequest,
};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rpc = std::env::var("TEMPO_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".into());
    let relay = std::env::var("TEMPO_RELAY_URL").unwrap_or_else(|_| "http://127.0.0.1:8547".into());
    for endpoint in [&rpc, &relay] {
        let url: reqwest::Url = endpoint.parse()?;
        eyre::ensure!(
            matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost")),
            "Use loopback endpoints only"
        );
    }
    let signer = PrivateKeySigner::from_bytes(&alloy::primitives::B256::repeat_byte(4))?;
    let sender = signer.address();
    let relay_provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(relay.parse()?);
    eyre::ensure!(
        relay_provider.get_chain_id().await? == 1337,
        "Use a development chain only"
    );
    let mut fill_request = TempoTransactionRequest::default();
    fill_request.inner.from = Some(sender);
    fill_request.inner.to = Some(TxKind::Call(sender));
    let filled = relay_provider
        .relay_fill_transaction(RelayFillRequest {
            transaction: fill_request,
            fee_payer: Some(tempo_alloy::provider::relay::RelayFeePayer::Enabled(true)),
            ..Default::default()
        })
        .await?;
    eyre::ensure!(
        filled.capabilities.sponsored,
        "Relay did not approve sponsorship"
    );
    let payer = filled.tx.build_aa()?.recover_fee_payer(sender)?;
    eyre::ensure!(payer != sender, "Fill is not signed by a fee payer");
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .wallet(EthereumWallet::new(signer))
        .sponsor(relay)
        .connect(&rpc)
        .await?;
    eyre::ensure!(
        provider.get_chain_id().await? == 1337,
        "Use a development chain only"
    );
    let mut request = TempoTransactionRequest::default();
    request.inner.to = Some(TxKind::Call(sender));
    let receipt = provider
        .send_transaction(request)
        .await?
        .get_receipt()
        .await?;
    eyre::ensure!(receipt.status(), "Sponsored transaction failed");
    eyre::ensure!(
        receipt.fee_payer != sender,
        "Sender paid fees instead of sponsor"
    );
    println!(
        "Alloy relay sponsorship: {}",
        receipt.inner.transaction_hash
    );
    Ok(())
}
