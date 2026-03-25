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

/// Starts a single-node network with V2 active at genesis, sets a non-zero
/// fee recipient in the contract, and verifies that produced blocks use the
/// on-chain fee recipient as the block beneficiary.
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
        let (mut nodes, _execution_runtime) = setup_validators(&mut context, setup).await;
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let target_height = 5u64;

        loop {
            let metrics = context.encode();
            let reached = metrics.lines().any(|line| {
                line.starts_with(CONSENSUS_NODE_PREFIX)
                    && line.contains("_marshal_processed_height")
                    && line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                        .is_some_and(|v| v >= target_height)
            });

            if reached {
                break;
            }

            context.sleep(Duration::from_secs(1)).await;
        }

        let provider = nodes[0].execution_provider();
        for height in 1..=target_height {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, ONCHAIN_FEE_RECIPIENT,
                "block {height} beneficiary should match the V2 contract fee recipient",
            );
        }
    });
}
