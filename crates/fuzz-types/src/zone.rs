//! The Tempo L1 state a zone harness input carries for the zone to read.

use std::collections::BTreeMap;

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// Tempo L1 storage and TIP-1108 commitments. Anything not listed reads as zero.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct L1StateInput {
    /// Storage by account, then slot.
    pub storage: BTreeMap<Address, BTreeMap<U256, U256>>,
    /// TIP-1108 configuration commitments by account.
    pub commitments: BTreeMap<Address, B256>,
}

impl L1StateInput {
    /// The value of `account`'s storage `slot`, zero when not listed.
    pub fn storage(&self, account: &Address, slot: B256) -> B256 {
        self.storage
            .get(account)
            .and_then(|slots| slots.get(&U256::from_be_bytes(slot.0)))
            .copied()
            .map(B256::from)
            .unwrap_or_default()
    }

    /// `account`'s TIP-1108 configuration commitment, zero when not listed.
    pub fn commitment(&self, account: &Address) -> B256 {
        self.commitments.get(account).copied().unwrap_or_default()
    }
}

/// The Tempo L1 state a zone read at each L1 block, such as a corpus records for each zone block
/// it captures. A block or entry not listed reads as zero.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct L1RecordedInput {
    /// The state read at each L1 block, by block number.
    pub blocks: BTreeMap<u64, L1StateInput>,
}

impl L1RecordedInput {
    /// The state read at L1 block `number`, if any was recorded.
    pub fn at(&self, number: u64) -> Option<&L1StateInput> {
        self.blocks.get(&number)
    }
}
