//! Zones on a Tempo chain the harness executes: each zone block anchors to the next Tempo block.

use alloy_eips::eip2718::Decodable2718 as _;
use alloy_primitives::Address;
use reth_primitives_traits::SignedTransaction as _;
use tempo_fuzz_engine::{Engine as _, Tempo, execute_anchored, ffi, reject};
use tempo_fuzz_types::{
    BlockContextInput, BlockHeaderInput, ErrorClass, PreState, TempoBlockchainInput,
    TempoExecutionOutcome, TempoHarnessInput, TempoHarnessOutcome,
};
use tempo_primitives::TempoTxEnvelope;
use zone_primitives::constants::decode_zone_chain_id;

use crate::engine::{L1, Zone};

/// Executes `tempo`, then `input` on a zone anchored to it, as [`crate::L1Input::Chain`] describes.
///
/// The outcome is the zone's, with what the Tempo chain broke added to its invariant failures. A
/// Tempo block that failed sets `error` when every zone block that ran applied.
pub(crate) fn run(
    tempo: &TempoBlockchainInput,
    mut input: TempoHarnessInput,
) -> TempoHarnessOutcome {
    if let Some(why) = invalid(tempo, &input) {
        return crate::invalid(&input, why);
    }
    let (l1, anchors) = execute_anchored(
        &Tempo,
        &tempo.chain_spec,
        &tempo.pre_state,
        tempo.blocks.as_slice(),
    );
    let l1_rejection = ffi::last_rejection_string();
    let Some(l1_config) = Tempo
        .chain(&tempo.chain_spec)
        .ok()
        .map(|chain| chain.evm_config)
    else {
        return failed(&input, l1);
    };
    // The Tempo chain did not execute, or its pre-state already breaks an invariant.
    if anchors.is_empty() || l1.error == ErrorClass::InvalidInput {
        return failed(&input, l1);
    }
    if anchor(&mut input, tempo, &anchors[1..]).is_err() {
        let error = reject(
            ErrorClass::InvalidInput,
            "a zone on a Tempo chain needs context headers",
        );
        return failed(
            &input,
            TempoExecutionOutcome {
                error,
                ..Default::default()
            },
        );
    }
    let has_blocks = match &input {
        TempoHarnessInput::Transaction(_) => true,
        TempoHarnessInput::State(_) | TempoHarnessInput::Blockchain(_) => anchors.len() > 1,
    };
    if !has_blocks {
        return failed(&input, l1);
    }
    let zone = Zone::new(L1::chain(anchors, l1_config), crate::watched(&input));
    let mut outcome = tempo_fuzz_engine::run(&zone, input);
    if let TempoHarnessOutcome::State(zone) | TempoHarnessOutcome::Blockchain(zone) = &mut outcome {
        add(zone, l1, &l1_rejection);
    }
    outcome
}

/// Why a zone on `tempo` cannot run `input`, if it cannot: its chain ID is not one of `tempo`'s
/// zones, or it has more blocks than `tempo` to anchor them to.
fn invalid(tempo: &TempoBlockchainInput, input: &TempoHarnessInput) -> Option<&'static str> {
    let (chain_id, blocks) = match input {
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
    anchors: &[tempo_fuzz_engine::Anchor],
) -> Result<(), ()> {
    let at = |context: &mut BlockContextInput, anchor: &tempo_fuzz_engine::Anchor| {
        context.timestamp = anchor.header().inner.timestamp;
        context.timestamp_millis_part = anchor.header().timestamp_millis_part;
        context.hardfork = anchor.spec();
    };
    match input {
        TempoHarnessInput::Transaction(_) => {}
        TempoHarnessInput::State(state) => {
            state.chain_spec.hardforks = tempo.chain_spec.hardforks.clone();
            if let Some(anchor) = anchors.first() {
                at(&mut state.block_context, anchor);
            }
        }
        TempoHarnessInput::Blockchain(chain) => {
            chain.chain_spec.hardforks = tempo.chain_spec.hardforks.clone();
            let mut blocks = chain.blocks.as_slice().to_vec();
            blocks.truncate(anchors.len().max(1));
            for (block, anchor) in blocks.iter_mut().zip(anchors) {
                let BlockHeaderInput::Context(context) = &mut block.header else {
                    return Err(());
                };
                at(context, anchor);
            }
            chain.blocks = blocks.try_into().expect("a chain keeps its first block");
        }
    }
    Ok(())
}

/// The outcome of `input`'s kind when its zone did not run, the Tempo chain's `l1`.
pub(crate) fn failed(input: &TempoHarnessInput, l1: TempoExecutionOutcome) -> TempoHarnessOutcome {
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

/// Adds what the Tempo chain `l1` broke to the zone's `outcome`, and its error, rejected for
/// `rejection`, when the zone applied.
fn add(outcome: &mut TempoExecutionOutcome, l1: TempoExecutionOutcome, rejection: &str) {
    outcome
        .invariant_failures
        .extend(l1.invariant_failures.into_iter().map(|mut failure| {
            failure.message = format!("on Tempo: {}", failure.message);
            failure
        }));
    for (id, counts) in l1.invariant_counts {
        outcome.invariant_counts.entry(id).or_default().add(counts);
    }
    if outcome.error == ErrorClass::None && l1.error != ErrorClass::None {
        outcome.error = reject(l1.error, format!("Tempo: {rejection}"));
    }
}

/// The accounts `input`'s transactions are signed by or act for, and the accounts its pre-state
/// lists.
pub(crate) fn watched(input: &TempoHarnessInput) -> Vec<Address> {
    let (txs, pre_state): (Vec<&[u8]>, Vec<Address>) = match input {
        TempoHarnessInput::Transaction(_) => return Vec::new(),
        TempoHarnessInput::State(state) => (
            vec![state.tx.as_ref()],
            state.pre_state.accounts.keys().copied().collect(),
        ),
        TempoHarnessInput::Blockchain(chain) => {
            let (PreState::Genesis(listed) | PreState::Exact { state: listed, .. }) =
                &chain.pre_state;
            (
                chain
                    .blocks
                    .as_slice()
                    .iter()
                    .flat_map(|block| block.txs.iter().map(AsRef::as_ref))
                    .collect(),
                listed.accounts.keys().copied().collect(),
            )
        }
    };
    let mut accounts = Vec::new();
    for mut tx in txs {
        let Ok(tx) = TempoTxEnvelope::decode_2718(&mut tx) else {
            continue;
        };
        if let Ok(sender) = tx.try_recover() {
            accounts.push(sender);
            accounts.extend(tempo_fuzz_engine::authority(&tx, sender, true).accounts());
        }
    }
    accounts.extend(pre_state);
    accounts
}
