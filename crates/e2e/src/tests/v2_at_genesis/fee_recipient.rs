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

/// Starts a single-node network with V2 active at genesis and a non-zero fee
/// recipient. Calls `setFeeRecipient` with a new address, waits for inclusion,
/// and verifies that blocks up to and including the inclusion height use the
/// old address, while the block immediately after uses the new one.
#[test_traced]
fn block_beneficiary_follows_v2_fee_recipient() {
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

        let http_url = loop {
            if let Some(url) = nodes[0]
                .execution_node
                .as_ref()
                .and_then(|n| n.node.rpc_server_handle().http_url())
            {
                break url.parse().unwrap();
            }
            context.sleep(Duration::from_millis(100)).await;
        };

        // Validator index is 1 (1-indexed in the V2 contract).
        let receipt = execution_runtime
            .set_fee_recipient_v2(http_url, 1, UPDATED_FEE_RECIPIENT)
            .await
            .unwrap();
        let change_height = receipt.block_number.unwrap();

        // Wait for the block after the inclusion.
        let target = change_height + 1;
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
                break;
            }
            context.sleep(Duration::from_secs(1)).await;
        }

        let provider = nodes[0].execution_provider();

        // Blocks up to and including the inclusion height use the old address.
        for height in 1..=change_height {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, ONCHAIN_FEE_RECIPIENT,
                "block {height} beneficiary should be the original fee recipient",
            );
        }

        // The block immediately after the inclusion uses the new address.
        let block = provider
            .block_by_number(target)
            .expect("provider error")
            .unwrap_or_else(|| panic!("block {target} not found"));
        assert_eq!(
            block.header.inner.beneficiary, UPDATED_FEE_RECIPIENT,
            "block {target} beneficiary should be the updated fee recipient",
        );
    });
}
