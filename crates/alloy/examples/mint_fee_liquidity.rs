//! Add liquidity to a fee pool to enable fee payments with your token.
//!
//! Run with: `cargo run --example mint_fee_liquidity`

use alloy::{
    primitives::{U256, address},
    providers::ProviderBuilder,
};
use tempo_alloy::{
    TempoNetwork,
    contracts::precompiles::{ITIPFeeAMM, TIP_FEE_MANAGER_ADDRESS},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    // Your issued token
    let your_token = address!("0x20c0000000000000000000000000000000000004");
    // AlphaUSD
    let validator_token = address!("0x20c0000000000000000000000000000000000001");

    let fee_amm = ITIPFeeAMM::new(TIP_FEE_MANAGER_ADDRESS, &provider);

    let recipient = address!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

    // Add 100 AlphaUSD of liquidity to the fee pool
    fee_amm
        .mint(
            your_token,
            validator_token,
            U256::from(100_000_000),
            recipient,
        )
        .send()
        .await?
        .get_receipt()
        .await?;

    println!("Fee liquidity added successfully");

    Ok(())
}
