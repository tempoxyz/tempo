//! Tests that the proposer reads the fee recipient from the V2 contract.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::Address;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use futures::{StreamExt as _, future::join_all};
use reth_ethereum::storage::BlockReader as _;
use reth_provider::CanonStateSubscriptions as _;

use crate::{Setup, setup_validators};

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

        // Subscribe to canonical events and wait for a block past the change.
        let mut canonical_events = nodes[0].execution().provider.canonical_state_stream();

        let target = change_height + 1;
        while let Some(event) = canonical_events.next().await {
            let tip = event.committed().tip().number();
            if tip >= target {
                break;
            }
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
