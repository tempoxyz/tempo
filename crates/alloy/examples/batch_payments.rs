//! Send multiple payments in a single batch transaction.
//!
//! Run with: `cargo run --example batch_payments`

use alloy::{
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    sol_types::SolCall,
};
use tempo_alloy::{
    TempoNetwork, contracts::precompiles::ITIP20, primitives::transaction::Call,
    rpc::TempoTransactionRequest,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    let recipient1 = address!("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEbb");
    let recipient2 = address!("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    let token_address: Address = address!("0x20c0000000000000000000000000000000000001");

    let calls = vec![
        Call {
            to: token_address.into(),
            input: ITIP20::transferCall {
                to: recipient1,
                amount: U256::from(100_000_000),
            }
            .abi_encode()
            .into(),
            value: U256::ZERO,
        },
        Call {
            to: token_address.into(),
            input: ITIP20::transferCall {
                to: recipient2,
                amount: U256::from(50_000_000),
            }
            .abi_encode()
            .into(),
            value: U256::ZERO,
        },
    ];

    let pending = provider
        .send_transaction(TempoTransactionRequest {
            calls,
            ..Default::default()
        })
        .await?;
    let tx_hash = pending.tx_hash();

    println!("Batch transaction sent: {tx_hash:?}");

    Ok(())
}
