//! Send a Tempo transaction through the sponsor transport.
//!
//! Run with:
//! ```sh
//! RPC_URL=https://rpc.moderato.tempo.xyz \
//! SPONSOR_URL=https://sponsor.testnet.tempo.xyz \
//! PRIVATE_KEY=0x... \
//! cargo run -p tempo-alloy --example sponsored_transaction
//! ```

use alloy::{
    network::{EthereumWallet, ReceiptResponse, TransactionBuilder},
    primitives::{TxKind, U256},
    providers::{Provider, ProviderBuilder, fillers::RecommendedFillers},
};
use tempo_alloy::{
    TempoNetwork, fillers::Random2DNonceFiller, provider::ext::TempoProviderBuilderExt,
    rpc::TempoTransactionRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL must be set");
    let sponsor_url = std::env::var("SPONSOR_URL").expect("SPONSOR_URL must be set");
    let signer: alloy::signers::local::PrivateKeySigner = std::env::var("PRIVATE_KEY")?
        .parse()
        .expect("PRIVATE_KEY must be a hex private key");
    let sender = signer.address();

    let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
        .filler(Random2DNonceFiller)
        .filler(<TempoNetwork as RecommendedFillers>::recommended_fillers())
        .wallet(EthereumWallet::from(signer))
        // Default is `SponsorConfig::sign_and_relay()`: the sponsor signs and broadcasts the tx.
        // For sign-only mode, where the sponsor signs and the client broadcasts through `RPC_URL`,
        // use the builder method `.sponsor_with_config(sponsor_rpc, SponsorConfig::sign_only())`.
        .sponsor(sponsor_url)
        .connect(&rpc_url)
        .await?;

    let mut tx = TempoTransactionRequest::default();
    tx.set_from(sender);
    tx.set_kind(TxKind::Call(sender));
    tx.set_value(U256::ZERO);

    let pending = provider.send_transaction(tx).await?;
    println!("sponsored transaction submitted: {}", pending.tx_hash());

    let receipt = pending.get_receipt().await?;
    println!(
        "receipt: status={:?}, block={:?}, fee_payer={}",
        receipt.status(),
        receipt.block_number,
        receipt.fee_payer,
    );

    Ok(())
}
