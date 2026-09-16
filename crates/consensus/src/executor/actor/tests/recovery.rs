//! Recovery from authoritative consensus storage paired with stale execution.

use alloy_consensus::Sealable as _;
use alloy_rpc_types_engine::PayloadStatusEnum;
use commonware_consensus::types::Height;
use commonware_macros::test_traced;
use commonware_runtime::{Runner as _, Storage as _, Supervisor as _, deterministic};
use futures::FutureExt as _;

use super::harness::{FakeExecution, GENESIS, Harness, HarnessOptions, make_block, round};
use crate::{
    consensus::{Digest, block::Block},
    executor::recovery::{Recovery, header_at},
};

fn chain(count: u64, parent: Digest) -> Vec<Block> {
    let mut parent = parent;
    (1..=count)
        .map(|height| {
            let block = make_block(height, height, parent);
            parent = block.digest();
            block
        })
        .collect()
}

fn peers(execution: &FakeExecution, blocks: &[Block]) {
    for block in blocks {
        execution.add_network_block(block.digest(), block.clone());
    }
}

fn options(floor: u64, tip: &Block, height: u64) -> HarnessOptions {
    HarnessOptions {
        finalized_floor: floor,
        finalized_tip: (round(height), height, tip.digest()),
        ..Default::default()
    }
}

#[test_traced]
fn cold_return_recovers_below_processed_floor_without_per_height_certificates() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(5, GENESIS);
        let execution = FakeExecution::new();
        execution.seed_canonical_block(&blocks[0]);
        execution.set_finalized(1, blocks[0].digest());
        peers(&execution, &blocks);
        // The consensus archive has a later anchor, but neither the missing
        // bodies nor a certificate at the processed floor (3).
        let mut h = Harness::builder()
            .execution(execution)
            .harness_options(options(3, &blocks[4], 5))
            .start(&context);
        h.wait_until(|| {
            h.metrics().contains("executor_recovery_active 0\n")
                && h.execution.finalized() == Some((3, blocks[2].digest()))
        })
        .await;
        assert_eq!(
            h.execution.new_payloads(),
            vec![blocks[1].digest(), blocks[2].digest()]
        );
        assert!(h.metrics().contains("executor_recovery_height 3\n"));
        assert!(h.metrics().contains("executor_recovery_target 3\n"));
        // Normal marshal delivery can now resume above its unchanged floor.
        h.deliver_finalized(blocks[3].clone()).await.unwrap();
        h.deliver_finalized(blocks[4].clone()).await.unwrap();
        assert_eq!(h.execution.finalized(), Some((5, blocks[4].digest())));
    });
}

#[test_traced]
fn fresh_execution_recovers_thousands_of_blocks_with_bounded_header_batches() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(4096, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        let h = Harness::builder()
            .execution(execution)
            .harness_options(options(4096, &blocks[4095], 4096))
            .start(&context);
        h.wait_until(|| {
            h.execution.finalized() == Some((4096, blocks[4095].digest()))
                && h.metrics().contains("executor_recovery_active 0\n")
        })
        .await;
        assert_eq!(h.execution.new_payloads().len(), 4096);
        let requests = h.execution.network_requests();
        assert!(requests.iter().all(|(_, count)| *count <= 128));
        assert_eq!(requests.iter().filter(|(_, count)| *count > 0).count(), 32);
        let (_, size) = context.open("executor-recovery", b"hashes").await.unwrap();
        assert_eq!(size, 0, "completed replay releases scratch storage");
    });
}

#[test_traced]
fn recovery_rejects_a_peer_header_with_the_wrong_hash_before_replay() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(3, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        execution.add_network_block(blocks[2].digest(), make_block(99, 3, blocks[1].digest()));
        let h = Harness::builder()
            .execution(execution)
            .harness_options(options(2, &blocks[2], 3))
            .start(&context);
        h.actor.await.unwrap();
        assert!(h.execution.new_payloads().is_empty());
        assert_eq!(
            h.execution.network_requests().len(),
            3,
            "peer failures have bounded retries"
        );
    });
}

#[test_traced]
fn recovery_rejects_a_finalized_anchor_on_a_conflicting_local_chain() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(3, GENESIS);
        let execution = FakeExecution::new();
        let conflicting = make_block(99, 1, GENESIS);
        execution.seed_canonical_block(&conflicting);
        execution.set_finalized(1, conflicting.digest());
        peers(&execution, &blocks);
        let h = Harness::builder()
            .execution(execution)
            .harness_options(options(2, &blocks[2], 3))
            .start(&context);
        h.actor.await.unwrap();
        assert!(h.execution.new_payloads().is_empty());
        assert_eq!(h.execution.finalized(), Some((1, conflicting.digest())));
    });
}

#[test_traced]
fn recovery_restarts_from_execution_progress_without_reusing_a_partial_index() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(4, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        let held_payload =
            execution.script_delayed_new_payload(blocks[2].digest(), Ok(PayloadStatusEnum::Valid));
        let h = Harness::builder()
            .execution(execution.clone())
            .harness_options(options(4, &blocks[3], 4))
            .start(&context);
        h.wait_until(|| h.execution.new_payloads().contains(&blocks[2].digest()))
            .await;
        assert_eq!(execution.finalized(), Some((2, blocks[1].digest())));
        assert!(h.metrics().contains("executor_recovery_active 1\n"));
        h.actor.abort();
        let _ = h.actor.await;
        drop(held_payload);
        execution.script_new_payload(blocks[2].digest(), Ok(PayloadStatusEnum::Valid));
        let restarted = Harness::builder()
            .execution(execution.clone())
            .harness_options(options(4, &blocks[3], 4))
            .start(&context.child("restart"));
        restarted
            .wait_until(|| execution.finalized() == Some((4, blocks[3].digest())))
            .await;
        assert_eq!(
            execution
                .new_payloads()
                .iter()
                .filter(|d| **d == blocks[0].digest())
                .count(),
            1
        );
        assert_eq!(
            execution
                .new_payloads()
                .iter()
                .filter(|d| **d == blocks[1].digest())
                .count(),
            1
        );
    });
}

#[test_traced]
fn startup_epoch_header_can_be_authenticated_before_marshal_starts() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(3, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        let header = header_at(
            &context,
            &execution,
            (Height::new(3), blocks[2].digest()),
            Height::new(1),
        )
        .await
        .unwrap();
        assert_eq!(header.hash_slow(), blocks[0].digest().0);
        assert!(
            execution.new_payloads().is_empty(),
            "reading DKG history must not execute it"
        );
        assert!(
            header_at(
                &context,
                &execution,
                (Height::new(3), blocks[2].digest()),
                Height::new(4)
            )
            .await
            .is_err()
        );
    });
}

#[test_traced]
fn signing_startup_waits_for_recovery_and_observes_failure() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(2, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        let release =
            execution.script_delayed_new_payload(blocks[1].digest(), Ok(PayloadStatusEnum::Valid));
        let h = Harness::builder()
            .execution(execution)
            .harness_options(options(2, &blocks[1], 2))
            .start(&context);
        let ready = h.mailbox.wait_for_startup();
        futures::pin_mut!(ready);
        assert!(ready.as_mut().now_or_never().is_none());
        h.wait_until(|| h.execution.new_payloads().contains(&blocks[1].digest()))
            .await;
        assert!(ready.as_mut().now_or_never().is_none());
        release.send(()).unwrap();
        ready.await.unwrap();
        assert_eq!(h.execution.finalized(), Some((2, blocks[1].digest())));

        let failed = Harness::builder()
            .harness_options(options(2, &blocks[1], 2))
            .start(&context.child("failed"));
        assert!(failed.mailbox.wait_for_startup().await.is_err());
        failed.actor.await.unwrap();
    });
}

#[test_traced]
fn downloaded_block_must_match_the_authenticated_header_index() {
    deterministic::Runner::default().start(|context| async move {
        let blocks = chain(2, GENESIS);
        let execution = FakeExecution::new();
        peers(&execution, &blocks);
        let recovery = Recovery::init(
            &context,
            &execution,
            "recovery",
            (Height::zero(), GENESIS),
            Height::new(2),
            (Height::new(2), blocks[1].digest()),
        )
        .await
        .unwrap();
        let wrong = make_block(99, 1, GENESIS);
        execution.add_network_block(blocks[0].digest(), wrong);
        let error = recovery
            .block(&context, &execution, Height::new(1))
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match authenticated history")
        );
        assert!(execution.new_payloads().is_empty());
    });
}
