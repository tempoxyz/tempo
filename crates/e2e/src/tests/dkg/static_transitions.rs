//! Tests for successful DKG ceremonies with static sets of validators.
//!
//! Contains test for both pre-allegretto logic, and allegretto logic active
//! at genesis.
use commonware_macros::test_traced;

use crate::{Setup, run};

#[test_traced]
fn genesis_allegretto_single_validator_can_transition_once() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_single_validator_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_single_validator_can_transition_four_times() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 4,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_two_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_two_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_four_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn genesis_allegretto_four_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: true,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_single_validator_can_transition_once() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_single_validator_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_single_validator_can_transition_four_times() {
    AssertStaticTransitions {
        how_many: 1,
        epoch_length: 20,
        transitions: 4,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_two_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_two_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 2,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_four_validators_can_transition_once() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 1,
        allegretto_at_geneseis: false,
    }
    .run();
}

#[test_traced]
fn pre_allegretto_four_validators_can_transition_twice() {
    AssertStaticTransitions {
        how_many: 4,
        epoch_length: 20,
        transitions: 2,
        allegretto_at_geneseis: false,
    }
    .run();
}

struct AssertStaticTransitions {
    how_many: u32,
    epoch_length: u64,
    transitions: u64,
    allegretto_at_geneseis: bool,
}

impl AssertStaticTransitions {
    fn run(self) {
        let Self {
            how_many,
            epoch_length,
            transitions,
            allegretto_at_geneseis: allegretto_time_at_geneseis,
        } = self;
        let _ = tempo_eyre::install();

        let setup = Setup::new()
            .how_many_signers(how_many)
            .epoch_length(epoch_length);
        let setup = if allegretto_time_at_geneseis {
            setup.allegretto_time(0)
        } else {
            setup
        };

        let mut epoch_reached = false;
        let mut dkg_successful = false;
        let _first = run(setup, move |metric, value| {
            if metric.ends_with("_dkg_manager_ceremony_failures_total") {
                let value = value.parse::<u64>().unwrap();
                assert_eq!(0, value);
            }

            if metric.ends_with("_epoch_manager_latest_epoch") {
                let value = value.parse::<u64>().unwrap();
                epoch_reached |= value >= transitions;
            }
            if metric.ends_with("_dkg_manager_ceremony_successes_total") {
                let value = value.parse::<u64>().unwrap();
                dkg_successful |= value >= transitions;
            }

            epoch_reached && dkg_successful
        });
    }
}
