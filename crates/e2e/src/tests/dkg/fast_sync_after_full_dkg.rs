//! Tests for fast sync after a full DKG ceremony.

use alloy::transports::http::reqwest::Url;
use commonware_macros::test_traced;
use commonware_runtime::{
    Clock as _, Runner as _,
    deterministic::{Config, Runner},
};
use futures::future::join_all;
use reth_ethereum::storage::BlockNumReader as _;
use std::time::{Duration, Instant};
use tracing::info;

use super::common::{wait_for_outcome, wait_for_validators_to_reach_epoch};
use crate::{
    Setup, connect_execution_peers, connect_execution_to_peers, metrics::MetricsExt,
    setup_validators,
};

/// How long to wait (wall clock) for the late validator to build on top of the
/// chain it just synced.
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Tests that a late-joining validator can sync and participate after a full DKG ceremony.
///
/// This verifies:
/// 1. A full DKG ceremony completes successfully (new polynomial, different public key)
/// 2. A validator that joins late (after full DKG) can sync the chain
/// 3. The late validator replays across epoch boundaries, including the full DKG epoch
/// 4. The late validator continues progressing after sync
#[test_traced]
fn validator_can_fast_sync_after_full_dkg() {
    fast_sync_after_full_dkg(false);
}

/// A late joiner can also start with the identity produced by the full DKG ceremony.
#[test_traced]
fn validator_can_fast_sync_after_full_dkg_with_updated_network_identity() {
    fast_sync_after_full_dkg(true);
}

fn fast_sync_after_full_dkg(update_network_identity: bool) {
    let _ = tempo_eyre::install();

    let how_many_signers = 4;

    // MAX_REPAIR (concurrency) by default is 20, so keep enough finalized
    // history to exercise catch-up across the full DKG epoch.
    let epoch_length = 30;

    let full_dkg_epoch = 1;
    let blocks_before_late_join = 3 * epoch_length + 1;

    let setup = Setup::new()
        .how_many_signers(how_many_signers)
        .epoch_length(epoch_length);

    let cfg = Config::default().with_seed(setup.seed);
    let executor = Runner::from(cfg);

    executor.start(|mut context| async move {
        let (mut validators, execution_runtime) = setup_validators(&mut context, setup).await;

        let mut late_validator = validators.pop().unwrap();
        join_all(validators.iter_mut().map(|v| v.start(&context))).await;
        connect_execution_peers(&validators).await;

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

        if update_network_identity {
            late_validator.network_identity = tempo_chainspec::NetworkIdentity {
                from_epoch: outcome_after.epoch,
                identity: *outcome_after.network_identity(),
            };
        }

        // start late validator
        late_validator.start(&context).await;
        connect_execution_to_peers(&late_validator, &validators).await;

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
        // verify continued progress
        //
        // The runtime clock is virtual, so a fixed sleep can elapse long before the
        // execution nodes (which run on a real tokio runtime) build another block.
        // Poll against the wall clock instead, and only give up once the late
        // validator has really stopped making progress.
        let block_after_sync = late_validator
            .execution_provider()
            .last_block_number()
            .unwrap();
        let deadline = Instant::now() + PROGRESS_TIMEOUT;
        let block_later = loop {
            let block_later = late_validator
                .execution_provider()
                .last_block_number()
                .unwrap();
            if block_later > block_after_sync {
                break block_later;
            }
            assert!(
                Instant::now() < deadline,
                "Late validator should keep progressing after sync, but stayed at block \
                 {block_after_sync} for {PROGRESS_TIMEOUT:?}"
            );
            context.sleep(Duration::from_millis(100)).await;
        };
        info!(
            block_after_sync,
            block_later, "late validator progressed after sync"
        );
        context.to_metrics().assert_no_dkg_failures();
    })
}
