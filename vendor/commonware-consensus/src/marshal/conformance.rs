//! Marshal storage conformance tests.

use super::mocks::{
    application::Application,
    harness::{
        self, CodingHarness, StandardHarness, TestHarness, ValidatorHandle, ValidatorSetup,
        BLOCKS_PER_EPOCH, NAMESPACE, NUM_VALIDATORS, QUORUM, V,
    },
};
use crate::{
    simplex::{scheme::bls12381_threshold::vrf as bls12381_threshold_vrf, types::Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::certificate::{mocks::Fixture, ConstantProvider};
use commonware_runtime::{deterministic, Clock, Runner, Supervisor as _};
use commonware_utils::NZUsize;
use rand::RngExt as _;
use std::time::Duration;

const CASES: usize = 32;

struct StandardStorageConformance;
struct CodingStorageConformance;

impl Conformance for StandardStorageConformance {
    async fn commit(seed: u64) -> Vec<u8> {
        marshal_commit::<StandardHarness>(seed)
    }
}

impl Conformance for CodingStorageConformance {
    async fn commit(seed: u64) -> Vec<u8> {
        marshal_commit::<CodingHarness>(seed)
    }
}

fn marshal_commit<H: TestHarness>(seed: u64) -> Vec<u8> {
    let runner = deterministic::Runner::new(
        deterministic::Config::default()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(30))),
    );
    runner.start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold_vrf::fixture::<V, _>(&mut context, NAMESPACE, NUM_VALIDATORS);
        let mut oracle = harness::setup_network_with_participants(
            context.child("network"),
            NZUsize!(1),
            participants.clone(),
        )
        .await;

        let validator = participants[0].clone();
        let provider = ConstantProvider::new(schemes[0].clone());
        let application = Application::<H::ApplicationBlock>::manual_ack();
        let setup = H::setup_validator_with(
            context.child("validator"),
            &mut oracle,
            validator,
            provider,
            NZUsize!(1),
            application,
        )
        .await;

        assert_eq!(setup.application.acknowledged().await, Height::zero());
        wait_processed(&mut context, &setup, Height::zero()).await;

        let mut handle = ValidatorHandle::<H> {
            mailbox: setup.mailbox.clone(),
            extra: setup.extra.clone(),
        };
        let mut peers = Vec::<ValidatorHandle<H>>::new();
        let mut parent = H::genesis_block(NUM_VALIDATORS as u16);
        let count = context.random_range(1..=BLOCKS_PER_EPOCH.get().min(4));
        for height in 1..=count {
            let height = Height::new(height);
            let round = Round::new(Epoch::zero(), View::new(height.get()));
            let parent_view = height
                .previous()
                .map_or(View::zero(), |h| View::new(h.get()));
            let block = H::make_test_block(
                H::digest(&parent),
                H::commitment(&parent),
                height,
                context.random(),
                NUM_VALIDATORS as u16,
            );
            H::verify(&mut handle, round, &block, &mut peers).await;

            let proposal = Proposal::new(round, parent_view, H::commitment(&block));
            let finalization = H::make_finalization(proposal, &schemes, QUORUM);
            let mut mailbox = setup.mailbox.clone();
            H::report_finalization(&mut mailbox, finalization).await;

            assert_eq!(setup.application.acknowledged().await, height);
            wait_processed(&mut context, &setup, height).await;
            parent = block;
        }

        setup.actor_handle.abort();
        let _ = setup.actor_handle.await;
        context.storage_audit().to_vec()
    })
}

async fn wait_processed<H: TestHarness>(
    context: &mut deterministic::Context,
    setup: &ValidatorSetup<H>,
    height: Height,
) {
    loop {
        if setup.mailbox.get_processed_height().await == Some(height) {
            break;
        }
        context.sleep(Duration::from_millis(1)).await;
    }
}

conformance_tests! {
    StandardStorageConformance => CASES,
    CodingStorageConformance => CASES,
}
