//! Tests for fast sync after a full DKG ceremony.

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader as _;
use std::time::Duration;
use tracing::info;

use super::common::{
    assert_no_dkg_failures, assert_skipped_rounds, wait_for_outcome,
    wait_for_validators_to_reach_epoch,
};
use crate::{Setup, setup_validators};

/// Tests that a late-joining validator can sync and participate after a full DKG ceremony.
///
/// This verifies:
/// 1. A full DKG ceremony completes successfully (new polynomial, different public key)
/// 2. A validator that joins late (after full DKG) can sync the chain
/// 3. The late validator uses fast-sync to jump epoch boundaries (including the full DKG epoch)
/// 4. The late validator continues progressing after sync
#[test_traced]
fn validator_can_fast_sync_after_full_dkg() {
    let _ = tempo_eyre::install();

    let how_many_signers = 4;
    let epoch_length = 20;
    let full_dkg_epoch = 1;
    let blocks_before_late_join = 3 * epoch_length + 1;

    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length)
        .t2_time(0)
        .connect_execution_layer_nodes(true);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

        let mut late_validator = validators.pop().unwrap();
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;

        let http_url: Url = validators[0]
            .execution()
            .rpc_server_handle()
            .http_url()
            .unwrap()
            .parse()
            .unwrap();

        execution_runtime
            .set_next_full_dkg_ceremony_v2(http_url, full_dkg_epoch)
            .await
            .unwrap();

        let outcome_before =
            wait_for_outcome(&context, &validators, full_dkg_epoch - 1, epoch_length).await;
        assert!(
            outcome_before.is_next_full_dkg,
            "outcome.is_next_full_dkg should be `true`"
        );

        // wait for full DKG completion (-1 because late validator not started yet)
        wait_for_validators_to_reach_epoch(&context, full_dkg_epoch + 1, how_many_signers - 1)
            .await;

        let outcome_after =
            wait_for_outcome(&context, &validators, full_dkg_epoch, epoch_length).await;
        assert_ne!(
            outcome_before.sharing().public(),
            outcome_after.sharing().public(),
            "full DKG must create different public key"
        );

        // wait for chain to advance
        while validators[0]
            .execution_provider()
            .last_block_number()
            .unwrap()
            < blocks_before_late_join
        {
            context.sleep(Duration::from_secs(1)).await;
        }

        // start late validator
        late_validator.start(&context).await;
        info!(id = late_validator.uid, "started late validator",);
        assert_eq!(
            late_validator
                .execution_provider()
                .last_block_number()
                .unwrap(),
            0,
            "Late validator should start at block 0"
        );

        // wait for late validator to catch up
        while late_validator
            .execution_provider()
            .last_block_number()
            .unwrap()
            < blocks_before_late_join
        {
            context.sleep(Duration::from_millis(100)).await;
        }
        // ensure fast-sync was used to jump epoch boundaries (including from old to new sharing)
        assert_skipped_rounds(&context);

        // verify continued progress
        let block_after_sync = late_validator
            .execution_provider()
            .last_block_number()
            .unwrap();
        context.sleep(Duration::from_secs(2)).await;
        let block_later = late_validator
            .execution_provider()
            .last_block_number()
            .unwrap();
        assert!(
            block_later > block_after_sync,
            "Late validator should keep progressing after sync"
        );
        assert_no_dkg_failures(&context);
    })
}
