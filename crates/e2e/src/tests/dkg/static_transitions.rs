//! Tests for successful DKG ceremonies with static sets of validators.
//!
//! Contains test for DKG transition logic
//! at genesis.
use commonware_macros::test_traced;

use crate::{Setup, run};

#[test_traced]
fn single_validator_can_transition_once() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 5,
        transitions: 1,
    }
    .run();
}

#[test_traced]
fn single_validator_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 5,
        transitions: 2,
    }
    .run();
}

#[test_traced]
fn single_validator_can_transition_four_times() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 5,
        transitions: 4,
    }
    .run();
}

#[test_traced]
fn two_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 1,
    }
    .run();
}

#[test_traced]
fn two_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 2,
    }
    .run();
}

#[test_traced]
fn four_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 1,
    }
    .run();
}

#[test_traced]
fn four_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 2,
    }
    .run();
}

struct AssertStaticTransitions {
    how_many: u32,
    epoch_length: u64,
    transitions: u64,
}

impl AssertStaticTransitions {
    fn run(self) {
        let Self {
            how_many,
            epoch_length,
            transitions,
        } = self;
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(how_many)
            .epoch_length(epoch_length);

        let _first = run(setup, move |metrics| {
            metrics.assert_no_dkg_failures();

            let dkg_successful = metrics
                .values::<u64>("dkg_manager_ceremony_successes_total")
                .any(|successes| successes >= transitions);

            metrics.consensus_at_epoch(transitions) > 0 && dkg_successful
        });
    }
}
