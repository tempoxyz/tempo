//! What a zone harness input adds to a Tempo one: the Tempo L1 state the zone reads.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use tempo_fuzz_types::TempoHarnessInput;

/// A [`TempoHarnessInput`] executed on a zone, with the Tempo L1 state the zone reads.
///
/// The input's chain ID must be a zone chain ID, which names the zone and so its portal on L1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ZoneHarnessInput {
    /// The Tempo L1 state every zone block reads, whatever its anchor.
    pub l1: L1StateInput,
    /// The chain, pre-state and blocks, as the Tempo harness takes them.
    pub input: TempoHarnessInput,
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
