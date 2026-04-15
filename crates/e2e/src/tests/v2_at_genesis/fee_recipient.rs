//! Tests that the proposer reads the fee recipient from the V2 contract.

use alloy::consensus::BlockHeader as _;
use alloy_primitives::Address;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, deterministic};
use futures::{StreamExt as _, future::join_all};
use reth_ethereum::{provider::CanonStateSubscriptions as _, storage::BlockReader as _};

use crate::{Setup, setup_validators};

const ORIGINAL_FEE_RECIPIENT: Address = Address::new([0xFE; 20]);
const UPDATED_FEE_RECIPIENT: Address = Address::new([0xAB; 20]);
const FALLBACK_FEE_RECIPIENT: Address = Address::new([0xCC; 20]);

/// Verifies that the block beneficiary follows the on-chain V2 fee recipient
/// across a `setFeeRecipient` update.
#[test_traced]
fn block_beneficiary_follows_v2_fee_recipient() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(100)
        .t2_time(0)
        .fee_recipient(ORIGINAL_FEE_RECIPIENT)
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

        let receipt = execution_runtime
            .set_fee_recipient_v2(http_url, 0, UPDATED_FEE_RECIPIENT)
            .await
            .unwrap();
        let change_height = receipt.block_number.unwrap();

        let mut canonical_events = nodes[0].execution().provider.canonical_state_stream();
        let target = change_height + 1;
        while let Some(event) = canonical_events.next().await {
            if event.committed().tip().number() >= target {
                break;
            }
        }

        let provider = nodes[0].execution_provider();

        for height in 1..=change_height {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, ORIGINAL_FEE_RECIPIENT,
                "block {height} beneficiary should be the original fee recipient",
            );
        }

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

/// Verifies that when the on-chain fee recipient is set to `Address::ZERO`,
/// the node falls back to the CLI-configured fee recipient.
#[test_traced]
fn falls_back_to_cli_fee_recipient_when_onchain_is_zero() {
    let _ = tempo_eyre::install();

    let setup = Setup::new()
        .how_many_signers(1)
        .epoch_length(100)
        .t2_time(0)
        .fee_recipient(ORIGINAL_FEE_RECIPIENT)
        .seed(0);

    let cfg = deterministic::Config::default().with_seed(setup.seed);
    let executor = deterministic::Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut nodes, execution_runtime) = setup_validators(&mut context, setup).await;
        nodes[0].consensus_config_mut().fee_recipient = Some(FALLBACK_FEE_RECIPIENT);
        join_all(nodes.iter_mut().map(|node| node.start(&context))).await;

        let http_url = nodes[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        let receipt = execution_runtime
            .set_fee_recipient_v2(http_url, 0, Address::ZERO)
            .await
            .unwrap();
        let change_height = receipt.block_number.unwrap();

        let mut canonical_events = nodes[0].execution().provider.canonical_state_stream();
        let target = change_height + 1;
        while let Some(event) = canonical_events.next().await {
            if event.committed().tip().number() >= target {
                break;
            }
        }

        let provider = nodes[0].execution_provider();

        for height in 1..=change_height {
            let block = provider
                .block_by_number(height)
                .expect("provider error")
                .unwrap_or_else(|| panic!("block {height} not found"));
            assert_eq!(
                block.header.inner.beneficiary, ORIGINAL_FEE_RECIPIENT,
                "block {height} beneficiary should be the original fee recipient",
            );
        }

        let block = provider
            .block_by_number(target)
            .expect("provider error")
            .unwrap_or_else(|| panic!("block {target} not found"));
        assert_eq!(
            block.header.inner.beneficiary, FALLBACK_FEE_RECIPIENT,
            "block {target} beneficiary should fall back to CLI fee recipient",
        );
    });
}
