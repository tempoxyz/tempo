//! Zones on a Tempo chain the harness executes: each zone block anchors to the next Tempo block.

use std::fmt;

use tempo_fuzz_engine::{Anchor, Rejection, execute_anchored};
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ErrorClass, TempoBlockchainInput, TempoExecutionOutcome,
    TempoHarnessInput, TempoHarnessOutcome,
};
use zone_primitives::constants::decode_zone_chain_id;

use crate::{
    engine::{L1, Zone},
    watched,
};

/// Executes `tempo`, then `input` on a zone anchored to it, as [`crate::L1Input::Chain`] describes.
///
/// The outcome is the zone's, with what the Tempo chain broke added to its invariant failures,
/// their subjects prefixed `on Tempo:`. A Tempo block that failed sets the error when every zone
/// block that ran applied.
pub(crate) fn run(
    tempo: &TempoBlockchainInput,
    mut input: TempoHarnessInput,
) -> (TempoHarnessOutcome, Option<Rejection>) {
    if let Some(why) = invalid(tempo, &input) {
        let rejection = Rejection::new(ErrorClass::InvalidInput, why);
        return (failed(&input, stopped(&rejection)), Some(rejection));
    }
    let (l1, l1_rejection, anchors) =
        execute_anchored(&tempo.chain_spec, &tempo.pre_state, tempo.blocks.as_slice());
    // The Tempo chain did not execute, or its pre-state already breaks an invariant.
    if anchors.len() < 2
        || matches!(
            l1.error,
            ErrorClass::InvalidInput | ErrorClass::BrokenPreState
        )
    {
        return (failed(&input, l1), l1_rejection);
    }
    if let Err(why) = anchor(&mut input, tempo, &anchors[1..]) {
        let rejection = Rejection::new(ErrorClass::InvalidInput, why);
        return (failed(&input, stopped(&rejection)), Some(rejection));
    }
    let zone = Zone::new(L1::chain(anchors), watched(&input));
    let (mut outcome, mut rejection) = tempo_fuzz_engine::run(&zone, input);
    if let TempoHarnessOutcome::State(zone) | TempoHarnessOutcome::Blockchain(zone) = &mut outcome
        && let Some(l1_rejection) = add(zone, l1, l1_rejection)
    {
        rejection = Some(l1_rejection);
    }
    (outcome, rejection)
}

/// Why a zone on `tempo` cannot run `input`, if it cannot: its chain ID is not one of `tempo`'s
/// zones, or it has more blocks than `tempo` to anchor them to.
fn invalid(tempo: &TempoBlockchainInput, input: &TempoHarnessInput) -> Option<&'static str> {
    let (chain_id, blocks) = match input {
        // The zone runs no transaction inputs, which its capabilities reject.
        TempoHarnessInput::Transaction(_) => return None,
        TempoHarnessInput::State(state) => (state.chain_spec.chain_id, 1),
        TempoHarnessInput::Blockchain(chain) => {
            (chain.chain_spec.chain_id, chain.blocks.as_slice().len())
        }
    };
    match decode_zone_chain_id(chain_id) {
        Ok((l1, _)) if l1 == tempo.chain_spec.chain_id => {}
        _ => return Some("the zone chain ID is not one of the Tempo chain's zones"),
    }
    (blocks > tempo.blocks.as_slice().len()).then_some("more zone blocks than Tempo blocks")
}

/// Anchors `input`'s zone blocks to `anchors`, the Tempo blocks that applied: each takes its
/// anchor's timestamp and hardfork, the zone takes the chain's schedule, and blocks past the last
/// anchor are dropped. Fails on a header that is not a context.
fn anchor(
    input: &mut TempoHarnessInput,
    tempo: &TempoBlockchainInput,
    anchors: &[Anchor],
) -> Result<(), &'static str> {
    let at = |context: &mut BlockContextInput, anchor: &Anchor| {
        context.timestamp = anchor.header().inner.timestamp;
        context.timestamp_millis_part = anchor.header().timestamp_millis_part;
        context.hardfork = anchor.spec();
    };
    match input {
        TempoHarnessInput::Transaction(_) => {}
        TempoHarnessInput::State(state) => {
            state.chain_spec.hardforks = tempo.chain_spec.hardforks.clone();
            at(&mut state.block_context, &anchors[0]);
        }
        TempoHarnessInput::Blockchain(chain) => {
            chain.chain_spec.hardforks = tempo.chain_spec.hardforks.clone();
            let mut blocks = chain.blocks.as_slice().to_vec();
            blocks.truncate(anchors.len());
            for (block, anchor) in blocks.iter_mut().zip(anchors) {
                let BlockHeaderInput::Context(context) = &mut block.header else {
                    return Err("a zone on a Tempo chain needs context headers");
                };
                at(context, anchor);
            }
            chain.blocks = blocks.try_into().expect("a chain keeps its first block");
        }
    }
    Ok(())
}

/// An outcome with only `rejection`'s error.
fn stopped(rejection: &Rejection) -> TempoExecutionOutcome {
    TempoExecutionOutcome {
        error: rejection.class(),
        ..Default::default()
    }
}

/// The outcome of `input`'s kind when its zone did not run: the Tempo chain's `l1` error and
/// invariants.
fn failed(input: &TempoHarnessInput, l1: TempoExecutionOutcome) -> TempoHarnessOutcome {
    let l1 = TempoExecutionOutcome {
        error: l1.error,
        invariant_failures: l1.invariant_failures,
        invariant_counts: l1.invariant_counts,
        ..Default::default()
    };
    match input {
        TempoHarnessInput::Transaction(_) | TempoHarnessInput::Blockchain(_) => {
            TempoHarnessOutcome::Blockchain(l1)
        }
        TempoHarnessInput::State(_) => TempoHarnessOutcome::State(l1),
    }
}

/// Adds what the Tempo chain `l1` broke to the zone's `outcome`. Returns why it stopped short
/// when the zone applied and the chain did not, which then sets the outcome's error.
fn add(
    outcome: &mut TempoExecutionOutcome,
    l1: TempoExecutionOutcome,
    rejection: Option<Rejection>,
) -> Option<Rejection> {
    outcome
        .invariant_failures
        .extend(l1.invariant_failures.into_iter().map(|mut failure| {
            failure.violation.subject = format!("on Tempo: {}", failure.violation.subject);
            failure
        }));
    for (id, counts) in l1.invariant_counts {
        outcome.invariant_counts.entry(id).or_default().add(counts);
    }
    if outcome.error != ErrorClass::None || l1.error == ErrorClass::None {
        return None;
    }
    let reason = rejection.map_or_else(String::new, |rejection| rejection.reason().to_string());
    let rejection = Rejection::new(l1.error, OnTempo(reason));
    outcome.error = rejection.class();
    Some(rejection)
}

/// Why the Tempo chain a zone ran on stopped short.
struct OnTempo(String);

impl fmt::Debug for OnTempo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tempo")
    }
}

impl fmt::Display for OnTempo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "on Tempo: {}", self.0)
    }
}
