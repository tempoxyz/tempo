//! Watch for incoming transfers with memo for payment reconciliation.
//!
//! Run with: `cargo run --example watch_transfers_with_memo`

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
    .TransferWithMemo_filter()
    .watch()
    .await?
    .into_stream();

    while let Some(Ok((transfer, _))) = transfers.next().await {
        let invoice_id = transfer.memo;
        println!("Transfer received with memo: {invoice_id:?}");
    }

    Ok(())
}
