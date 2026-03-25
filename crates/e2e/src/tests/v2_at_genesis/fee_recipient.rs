//! Tests that the proposer reads the fee recipient from the V2 contract.

use std::time::Duration;

use alloy_primitives::Address;
use commonware_macros::test_traced;
use commonware_runtime::{Clock as _, Metrics as _, Runner as _, deterministic};
use futures::future::join_all;
use reth_ethereum::storage::BlockReader as _;

use crate::{CONSENSUS_NODE_PREFIX, Setup, setup_validators};

/// The fee recipient written into the V2 contract at genesis.
const ONCHAIN_FEE_RECIPIENT: Address = Address::new([0xFE; 20]);

/// The updated fee recipient set via `setFeeRecipient`.
const UPDATED_FEE_RECIPIENT: Address = Address::new([0xAB; 20]);

/// Waits until the marshal has processed at least `target` blocks.
async fn wait_for_height(context: &deterministic::Context, target: u64) {
    loop {
        let reached = context.encode().lines().any(|line| {
            line.starts_with(CONSENSUS_NODE_PREFIX)
                && line.contains("_marshal_processed_height")
                && line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
                    .is_some_and(|v| v >= target)
        });
        if reached {
            return;
        }
        context.sleep(Duration::from_secs(1)).await;
    }
}

/// Starts a single-node network with V2 active at genesis, sets a non-zero
/// fee recipient in the contract, and verifies that produced blocks use the
/// on-chain fee recipient as the block beneficiary.
///
/// Then calls `setFeeRecipient` with a new address and verifies that blocks
/// after the inclusion of that transaction use the updated address.
#[test_traced]
fn block_beneficiary_matches_v2_fee_recipient() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(100)
        .t2_time(0)
        .fee_recipient(ONCHAIN_FEE_RECIPIENT)
        .seed(0);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = deterministic::Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        // Wait for a few blocks and verify they use the genesis fee recipient.
        let initial_target = 5u64;
        wait_for_height(&context, initial_target).await;

        let provider = nodes[0].execution_provider();
        for height in 1..=initial_target {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, ONCHAIN_FEE_RECIPIENT,
                "block {height} beneficiary should match the genesis V2 fee recipient",
            );
        }

        // Call setFeeRecipient with a new address.
        let http_url = nodes[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        // Validator index is 1 (1-indexed in the V2 contract).
        let receipt = execution_runtime
            .set_fee_recipient_v2(http_url, 1, UPDATED_FEE_RECIPIENT)
            .await
            .unwrap();

        let change_height = receipt.block_number.unwrap();

        // Wait for a block after the setFeeRecipient inclusion.
        let post_change_target = change_height + 3;
        wait_for_height(&context, post_change_target).await;

        // Blocks after the change should use the updated fee recipient.
        for height in (change_height + 1)..=post_change_target {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, UPDATED_FEE_RECIPIENT,
                "block {height} beneficiary should match the updated V2 fee recipient",
            );
        }
    });
}
