//! Send a transaction using an access key.
//!
//! Demonstrates the ergonomic access key flow:
//! 1. Create a root account and an access key signer
//! 2. Authorize the access key with the root signer
//! 3. Build a provider with the access key
//! 4. Send transactions — key provisioning and signing happen automatically
//!
//! Run with:
//! ```sh
//! RPC_URL=https://rpc.tempo.xyz \
//!   ROOT_PRIVATE_KEY=0x... \
//!   cargo run --example access_key
//! ```

use alloy::{
    network::TransactionBuilder,
    primitives::{U256, address},
    providers::{Provider, ProviderBuilder, WalletProvider},
};
use alloy_signer_local::PrivateKeySigner;
use tempo_alloy::{
    AccessKeyAccount, TempoNetwork,
    contracts::precompiles::ITIP20,
    provider::{TempoProviderBuilderExt, TempoProviderExt},
    rpc::TempoTransactionRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("RPC_URL").expect("RPC_URL not set");

    // Root account signer
    let root: PrivateKeySigner = std::env::var("ROOT_PRIVATE_KEY")
        .expect("ROOT_PRIVATE_KEY not set")
        .parse()?;
    println!("Root address: {}", root.address());

    // Query chain ID from the network
    let bare_provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&rpc_url)
        .await?;
    let chain_id = bare_provider.get_chain_id().await?;
    println!("Chain ID: {chain_id}");

    // Create an access key and authorize it with the root signer.
    // For keys already provisioned on-chain, skip authorize_with:
    //   AccessKeyAccount::new(signer, root.address())
    let access_key_signer = PrivateKeySigner::random();
    let access_key_addr = access_key_signer.address();
    println!("Access key address: {access_key_addr}");

    let access_key =
        AccessKeyAccount::new(access_key_signer, root.address()).authorize_with(&root, chain_id)?;

    // Build a provider — fillers + wallet are wired automatically
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .with_access_key(access_key)
        .connect(&rpc_url)
        .await?;

    println!(
        "Provider default sender: {:?}",
        provider.default_signer_address()
    );

    // First transaction provisions the key and sends via keychain signature.
    // The key_authorization is consumed automatically after this.
    let receipt = provider
        .send_transaction(
            TempoTransactionRequest::default()
                .with_to(address!("0x000000000000000000000000000000000000dEaD"))
                .with_value(U256::ZERO),
        )
        .await?
        .get_receipt()
        .await?;

    println!(
        "Transaction sent via access key! Hash: {:?}",
        receipt.transaction_hash
    );

    // Verify the key was provisioned
    let key_info = provider
        .get_keychain_key(root.address(), access_key_addr)
        .await;
    println!("Access key info: {key_info:?}");

    // Second transaction — no key_authorization attached (already consumed)
    let receipt = provider
        .send_transaction(
            TempoTransactionRequest::default()
                .with_to(address!("0x000000000000000000000000000000000000dEaD"))
                .with_value(U256::ZERO),
        )
        .await?
        .get_receipt()
        .await?;

    println!(
        "Second transaction (existing key)! Hash: {:?}",
        receipt.transaction_hash
    );

    // Check root account balance
    let token = ITIP20::new(
        address!("0x20c0000000000000000000000000000000000001"),
        &provider,
    );
    let balance = token.balanceOf(root.address()).call().await?;
    println!("Root aUSD balance: {balance:?}");

    Ok(())
}
