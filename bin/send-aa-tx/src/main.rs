use alloy::{
    network::ReceiptResponse,
    primitives::{Address, Bytes, TxKind, U256},
    providers::{Provider, ProviderBuilder},
    signers::{local::PrivateKeySigner, SignerSync},
};
use alloy_eips::eip2718::Encodable2718;
use tempo_alloy::TempoNetwork;
use tempo_primitives::{
    transaction::{
        aa_signature::{AASignature, PrimitiveSignature},
        aa_signed::AASigned,
        account_abstraction::Call,
        TxAA,
    },
    TempoTxEnvelope,
};

const CHAIN_ID: u64 = 42429; // 0xa5bb - devnet chain ID
const BASE_FEE: u128 = 10_000_000_000; // 10 gwei

#[tokio::main]
async fn main() -> eyre::Result<()> {
    println!("🚀 Sending AA Transaction to Devnet\n");
    println!("Chain ID: {}\n", CHAIN_ID);

    // Generate a random private key for this test
    let signer = PrivateKeySigner::random();
    let sender_addr = signer.address();

    println!("Sender address: {}", sender_addr);

    // Create provider with TempoNetwork for proper AA tx type handling
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("RPC_URL environment variable not set"))
        .await?;

    // Fund the sender address using the faucet
    println!("\n💰 Requesting funds from faucet...");

    // The faucet returns an array of transaction hashes (for AlphaUSD, BetaUSD, ThetaUSD)
    let faucet_txs: Vec<String> = provider
        .raw_request("tempo_fundAddress".into(), [sender_addr.to_string()])
        .await?;

    println!("✓ Faucet request successful");
    println!("  Faucet transactions:");
    for (i, tx) in faucet_txs.iter().enumerate() {
        println!("    {}: {}", i + 1, tx);
    }

    // Wait for the faucet transaction to be mined
    println!("Waiting for faucet transaction to be mined...");
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Get nonce
    let nonce = provider.get_transaction_count(sender_addr).await?;
    println!("\n📊 Current nonce: {}", nonce);

    // Create a simple AA transaction - just a transfer to a random address
    let recipient = Address::random();
    println!("Recipient: {}", recipient);

    let tx = TxAA {
        chain_id: CHAIN_ID,
        max_priority_fee_per_gas: BASE_FEE,
        max_fee_per_gas: BASE_FEE,
        gas_limit: 100_000,
        calls: vec![Call {
            to: TxKind::Call(recipient),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        nonce_key: U256::ZERO, // Protocol nonce (key 0)
        nonce,
        fee_token: None, // Will use default fee token
        fee_payer_signature: None,
        valid_before: Some(u64::MAX),
        valid_after: None,
        access_list: Default::default(),
        key_authorization: None,       // No key provisioning
        aa_authorization_list: vec![], // No EIP-7702 delegations
    };

    println!("\n✍️  Signing transaction...");

    // Sign the transaction with secp256k1
    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash)?;
    let aa_signature = AASignature::Primitive(PrimitiveSignature::Secp256k1(signature));
    let signed_tx = AASigned::new_unhashed(tx, aa_signature);

    // Convert to envelope and encode
    let envelope: TempoTxEnvelope = signed_tx.into();
    let mut encoded = Vec::new();
    envelope.encode_2718(&mut encoded);

    println!("✓ Transaction signed");
    println!("  Transaction type: 0x{:02x} (AA)", encoded[0]);
    println!("  Encoded size: {} bytes", encoded.len());

    // Print the encoded transaction for debugging
    println!("  Encoded (hex): 0x{}", hex::encode(&encoded));

    // Send the transaction
    println!("\n📤 Sending transaction...");
    let pending_tx = provider.send_raw_transaction(&encoded).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("✓ Transaction sent!");
    println!("  Transaction hash: {}", tx_hash);

    // Wait for the transaction to be mined
    println!("\n⏳ Waiting for confirmation...");
    let receipt = pending_tx.get_receipt().await?;

    println!("✓ Transaction confirmed!");
    println!("  Block number: {:?}", receipt.block_number);
    println!("  Gas used: {}", receipt.gas_used);
    println!(
        "  Status: {}",
        if receipt.status() { "Success" } else { "Failed" }
    );

    println!("\nDone!");

    Ok(())
}
