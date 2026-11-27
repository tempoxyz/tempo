//! What a zone harness input adds to a Tempo one: the Tempo L1 state the zone reads.

use serde::{Deserialize, Serialize};
pub use tempo_fuzz_types::zone::{L1RecordedInput, L1StateInput};
use tempo_fuzz_types::{TempoBlockchainInput, TempoHarnessInput};

/// A [`TempoHarnessInput`] executed on a zone, with the Tempo L1 state the zone reads.
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
    /// A Tempo chain, which the harness executes first with the Tempo engine, keeping its state
    /// after each block. Zone block `i` imports Tempo block `i`'s header and reads Tempo at it, as
    /// a sequencer anchors each zone block to the next Tempo block.
    ///
    /// The chain's pre-state must be `PreState::Genesis` and its headers `BlockHeaderInput::Context`:
    /// the harness numbers its blocks from 1 and links their parent hashes from the genesis header,
    /// ignoring `block_number`. The zone input's chain ID must be one of the chain's zones, its
    /// headers contexts too, and it runs the chain's hardfork schedule, each block at its Tempo
    /// block's timestamp. Zone blocks past the last Tempo block that applied do not run.
    Chain(TempoBlockchainInput),
    /// The state a zone read at each L1 block, as a zone corpus records it: a read at L1 block
    /// `n` is served from block `n`'s state. For a recorded zone block given as its RLP header,
    /// which imports the real Tempo headers it imported, replay reads exactly what the node read.
    /// A block whose header the harness builds imports a header made up as the child of the last
    /// one the zone imported, as with [`Self::State`].
    Recorded(L1RecordedInput),
}
