//! What a zone harness input adds to a Tempo one: the Tempo L1 the zone reads.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use tempo_fuzz_types::{TempoBlockchainInput, TempoHarnessInput};

/// A [`TempoHarnessInput`] executed on a zone, with the Tempo L1 the zone reads.
///
/// The input's chain ID must be a zone chain ID, which names the zone and so its portal on L1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZoneHarnessInput {
    /// The Tempo L1 the zone reads.
    pub l1: L1Input,
    /// The chain, pre-state and blocks, as the Tempo harness takes them.
    pub input: TempoHarnessInput,
}

/// The Tempo L1 a zone reads.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum L1Input {
    /// The same storage at every L1 block. Each zone block imports a header made up as the child
    /// of the last one the zone imported.
    State(L1StateInput),
    /// A Tempo chain, executed first by the Tempo harness, keeping its state after each block.
    /// Zone block `i` imports Tempo block `i`'s header and reads Tempo at it, as a sequencer anchors
    /// each zone block to the next Tempo block.
    ///
    /// The chain's pre-state must be `PreState::Genesis` and its headers `BlockHeaderInput::Context`:
    /// the harness numbers its blocks from 1 and links their parent hashes from the genesis header,
    /// ignoring `block_number`. The zone runs the chain's hardfork schedule, and each zone block
    /// takes its Tempo block's timestamp, ignoring the zone input's own; its block contexts must be
    /// `BlockHeaderInput::Context`. Zone blocks past the last Tempo block that applied do not run.
    Chain(TempoBlockchainInput),
}

/// Tempo L1 storage and TIP-1108 commitments, the same at every L1 block. Anything not listed
/// reads as zero.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct L1StateInput {
    /// Storage by account, then slot.
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    /// TIP-1108 configuration commitments by account.
    pub commitments: BTreeMap<Address, B256>,
}
