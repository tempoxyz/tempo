//! Watch for incoming transfer events on a token.
//!
//! Run with: `cargo run --example watch_transfers`

use alloy::{primitives::address, providers::ProviderBuilder};
use futures::StreamExt;
use tempo_alloy::{TempoNetwork, contracts::precompiles::ITIP20};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect(&std::env::var("RPC_URL").expect("No RPC URL set"))
        .await?;

    let mut transfers = ITIP20::new(
        address!("0x20c0000000000000000000000000000000000001"),
        &provider,
    )
    .Transfer_filter()
    .watch()
    .await?
    .into_stream();

    while let Some(Ok((payment, _))) = transfers.next().await {
        println!("Received payment: {payment:?}")
    }

    Ok(())
}
