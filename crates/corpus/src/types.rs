//! Corpus wire format: block inputs, transaction boundaries and output digests.
//!
//! Every type here is the stored representation; execution lives in other modules.

use crate::store::WINCODE;
use alloy_primitives::{Address, B128, B256, Bytes, U256};
use reth_primitives_traits::Account;
use std::collections::{BTreeMap, BTreeSet};
use wincode::{SchemaRead, SchemaWrite};

/// One block's input: its canonical block, the pre-state it reads and the historical
/// changesets used to check its state changes. All values originate in the archive DB.
#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct Input {
    pub number: u64,
    pub parent: [u8; 32],
    pub block: Block,
    /// Pre-block value of every account the block reads or changes.
    pub accounts: BTreeMap<[u8; 20], Option<Info>>,
    /// Pre-block value of every slot the block reads or changes.
    pub storage: BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>,
    /// Code hashes the block reads; the bytecode itself is stored once per corpus under
    /// `c` ‖ code hash.
    pub code: BTreeSet<[u8; 32]>,
    pub hashes: BTreeMap<u64, [u8; 32]>,
    pub phases: Option<Phases>,
}

/// Canonical block and historical pre-change expectations, not replay-derived outputs.
#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct Block {
    pub hash: [u8; 32],
    pub rlp: Vec<u8>,
    pub senders: Vec<[u8; 20]>,
    /// Historical account changeset as a bitmap over the input's account witness (in key
    /// order): bit `i` marks the `i`-th account as changed by the block. Its pre-value is the
    /// witness value before the block, which capture checked against the archive changeset.
    pub changed_accounts: Vec<u8>,
    /// Historical storage changeset as a bitmap over the input's storage witness (in key
    /// order). Slots wiped by a destroyed account stay in the witness so they can be marked.
    pub changed_storage: Vec<u8>,
}

/// A block's historical changeset: pre-values of every account and slot it changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub accounts: BTreeMap<[u8; 20], Option<Info>>,
    pub storage: BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Info {
    nonce: u64,
    balance: [u8; 32],
    code_hash: Option<[u8; 32]>,
}

impl Info {
    pub fn capture(account: &Account) -> eyre::Result<Self> {
        let info = Self {
            nonce: account.nonce,
            balance: account.balance.to_be_bytes(),
            code_hash: account.bytecode_hash.map(|h| h.0),
        };
        eyre::ensure!(info.account() == *account, "unsupported account extension");
        Ok(info)
    }

    pub fn account(&self) -> Account {
        Account {
            nonce: self.nonce,
            balance: U256::from_be_bytes(self.balance),
            bytecode_hash: self.code_hash.map(B256::from),
            ..Default::default()
        }
    }
}

impl Input {
    /// Bitmaps marking `changeset` within this input's witness. Every changed key must be in
    /// the witness with the same pre-value.
    pub fn mark(&self, changeset: &ChangeSet) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
        Ok((
            mark(&self.accounts, &changeset.accounts, "account")?,
            mark(&self.storage, &changeset.storage, "storage")?,
        ))
    }

    /// The block's historical changeset, resolved from its bitmaps over the witness.
    pub fn changeset(&self) -> eyre::Result<ChangeSet> {
        let block = &self.block;
        eyre::ensure!(
            block.changed_accounts.len() == self.accounts.len().div_ceil(8)
                && block.changed_storage.len() == self.storage.len().div_ceil(8),
            "changeset bitmap size mismatch"
        );
        Ok(ChangeSet {
            accounts: marked(&self.accounts, &block.changed_accounts),
            storage: marked(&self.storage, &block.changed_storage),
        })
    }
}

/// A transaction's full execution record, produced by capture and replay. Only its
/// [`Case`] form is stored.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Transaction {
    pub ordinal: u64,
    pub index: u64,
    pub hash: [u8; 32],
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    pub outcome: Outcome,
    pub receipt: Vec<u8>,
    pub delta: Delta,
}

impl Transaction {
    pub fn gas_used(&self) -> u64 {
        self.outcome.charged_gas
    }

    fn outputs(&self) -> eyre::Result<Outputs> {
        Ok(Outputs {
            outcome: digest(&wincode::config::serialize(&self.outcome, WINCODE)?),
            receipt: digest(&self.receipt),
            after: digest(&self.after),
        })
    }

    /// The stored form: input and state delta in full, other outputs as per-field digests.
    pub fn stored(&self) -> eyre::Result<Case> {
        Ok(Case {
            ordinal: self.ordinal,
            index: self.index,
            hash: self.hash,
            before: self.before.clone(),
            status: self.outcome.status,
            charged_gas: self.outcome.charged_gas,
            created: self.outcome.created,
            delta: self.delta.clone(),
            outputs: self.outputs()?,
        })
    }
}

/// Stored form of a [`Transaction`]: its input (`before`) and state delta in full, and every
/// other output as a separate xxh3-128 digest, so replay detects any divergence and names the
/// field. The stored deltas restore the state before any transaction of the block without
/// executing the ones before it. Status, charged gas and the created address stay readable
/// for triage.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Case {
    pub ordinal: u64,
    pub index: u64,
    pub hash: [u8; 32],
    pub before: Vec<u8>,
    pub status: u8,
    pub charged_gas: u64,
    pub created: Option<[u8; 20]>,
    pub delta: Delta,
    pub outputs: Outputs,
}

/// Per-field digests of a transaction's outputs other than its state delta.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Outputs {
    pub outcome: [u8; 16],
    pub receipt: [u8; 16],
    pub after: [u8; 16],
}

impl Case {
    /// Compares an executed transaction against this record. A mismatch names the
    /// transaction and shows a diff of the recorded and replayed sides; fields the record
    /// keeps only as digests show as digests.
    pub fn check(&self, actual: &Transaction) -> eyre::Result<()> {
        let outputs = actual.outputs()?;
        let recorded = CaseView {
            index: self.index,
            ordinal: self.ordinal,
            hash: self.hash.into(),
            before: digest(&self.before).into(),
            status: self.status,
            charged_gas: self.charged_gas,
            created: self.created.map(Address::from),
            outcome: self.outputs.outcome.into(),
            receipt: self.outputs.receipt.into(),
            delta: DeltaView::from(&self.delta),
            after: self.outputs.after.into(),
        };
        let replayed = CaseView {
            index: actual.index,
            ordinal: actual.ordinal,
            hash: actual.hash.into(),
            before: digest(&actual.before).into(),
            status: actual.outcome.status,
            charged_gas: actual.outcome.charged_gas,
            created: actual.outcome.created.map(Address::from),
            outcome: outputs.outcome.into(),
            receipt: outputs.receipt.into(),
            delta: DeltaView::from(&actual.delta),
            after: outputs.after.into(),
        };
        // Decide on the raw records; the views are for display and could hide differences.
        if actual.ordinal == self.ordinal
            && actual.index == self.index
            && actual.hash == self.hash
            && actual.before == self.before
            && actual.outcome.status == self.status
            && actual.outcome.charged_gas == self.charged_gas
            && actual.outcome.created == self.created
            && outputs == self.outputs
            && actual.delta == self.delta
        {
            return Ok(());
        }
        eyre::bail!(
            "transaction {} (index {}, ordinal {}) mismatch (< recorded, > replayed)\n{}\nreplayed: reason {}, gas {:?}, output {}",
            recorded.hash,
            self.index,
            self.ordinal,
            pretty_assertions::Comparison::new(&recorded, &replayed),
            actual.outcome.reason,
            actual.outcome.gas,
            actual
                .outcome
                .output
                .clone()
                .map(Bytes::from)
                .unwrap_or_default(),
        )
    }
}

/// [Case] fields in readable form, compared and diffed as a whole.
#[derive(Debug, PartialEq, Eq)]
struct CaseView {
    index: u64,
    ordinal: u64,
    hash: B256,
    before: B128,
    status: u8,
    charged_gas: u64,
    created: Option<Address>,
    outcome: B128,
    receipt: B128,
    delta: DeltaView,
    after: B128,
}

/// [Delta] with addresses, slots and balances in readable form.
#[derive(Debug, PartialEq, Eq)]
pub struct DeltaView(Vec<BTreeMap<Address, ChangeView>>);

#[derive(Debug, PartialEq, Eq)]
struct ChangeView {
    created: bool,
    /// None wipes the account; Some keeps it, changing only the fields that are set.
    info: Option<InfoView>,
    storage: BTreeMap<B256, B256>,
    code: Option<Bytes>,
}

#[derive(Debug, PartialEq, Eq)]
struct InfoView {
    nonce: Option<u64>,
    balance: Option<U256>,
    code_hash: Option<Option<B256>>,
}

impl From<&Delta> for DeltaView {
    fn from(delta: &Delta) -> Self {
        Self(
            delta
                .0
                .iter()
                .map(|commit| {
                    commit
                        .iter()
                        .map(|(address, change)| {
                            let view = ChangeView {
                                created: change.created,
                                info: change.info.as_ref().map(|info| InfoView {
                                    nonce: info.nonce,
                                    balance: info.balance.map(U256::from_be_bytes),
                                    code_hash: info.code_hash.map(|h| h.map(B256::from)),
                                }),
                                storage: change
                                    .storage
                                    .iter()
                                    .map(|(slot, value)| ((*slot).into(), (*value).into()))
                                    .collect(),
                                code: change.code.clone().map(Bytes::from),
                            };
                            (Address::from(*address), view)
                        })
                        .collect()
                })
                .collect(),
        )
    }
}

/// Ordered commits inside a phase, preserving wipe then recreation.
#[derive(Clone, Debug, Default, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Delta(pub Vec<BTreeMap<[u8; 20], Change>>);

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Change {
    pub info: Option<InfoChange>,
    pub created: bool,
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
    pub code: Option<Vec<u8>>,
}

/// None preserves a field; Some(zero/None) explicitly resets it.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct InfoChange {
    pub nonce: Option<u64>,
    pub balance: Option<[u8; 32]>,
    pub code_hash: Option<Option<[u8; 32]>>,
}

/// Pre- and post-execution system changes of a block.
#[derive(Debug, Default, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Phases {
    pub pre: Delta,
    pub post: Delta,
}

/// A transaction's result, excluding state changes.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Outcome {
    pub status: u8,
    pub reason: String,
    pub created: Option<[u8; 20]>,
    pub gas: [u64; 4],
    pub charged_gas: u64,
    pub output: Option<Vec<u8>>,
}

fn digest(bytes: &[u8]) -> [u8; 16] {
    xxhash_rust::xxh3::xxh3_128(bytes).to_le_bytes()
}

/// Little-endian bitmap over `witness` in key order, marking the keys in `changed`. Every changed
/// key must be in the witness with the same pre-value.
fn mark<K: Ord, V: PartialEq>(
    witness: &BTreeMap<K, V>,
    changed: &BTreeMap<K, V>,
    kind: &str,
) -> eyre::Result<Vec<u8>> {
    for (key, value) in changed {
        eyre::ensure!(
            witness.get(key) == Some(value),
            "{kind} changeset disagrees with witness"
        );
    }
    let mut bits = vec![0u8; witness.len().div_ceil(8)];
    for (i, key) in witness.keys().enumerate() {
        if changed.contains_key(key) {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(bits)
}

/// Pre-values of the `witness` entries `bits` marks (see [`mark`]).
fn marked<K: Ord + Copy, V: Clone>(witness: &BTreeMap<K, V>, bits: &[u8]) -> BTreeMap<K, V> {
    witness
        .iter()
        .enumerate()
        .filter(|(i, _)| bits[i / 8] & (1 << (i % 8)) != 0)
        .map(|(_, (key, value))| (*key, value.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(charged_gas: u64, slot_value: u8) -> Transaction {
        let change = Change {
            info: None,
            created: false,
            storage: BTreeMap::from([([1; 32], [slot_value; 32])]),
            code: None,
        };
        Transaction {
            ordinal: 7,
            index: 2,
            hash: [0xab; 32],
            before: vec![1],
            after: vec![2],
            outcome: Outcome {
                status: 0,
                reason: "Return".into(),
                created: None,
                gas: [charged_gas, 0, 0, 0],
                charged_gas,
                output: Some(vec![]),
            },
            receipt: vec![3],
            delta: Delta(vec![BTreeMap::from([([0x11; 20], change)])]),
        }
    }

    #[test]
    fn check_diffs_recorded_and_replayed() {
        let case = transaction(21_000, 1).stored().unwrap();
        assert!(case.check(&transaction(21_000, 1)).is_ok());

        let message = case.check(&transaction(21_001, 2)).unwrap_err().to_string();
        // Drop the diff's ANSI colors, which split values mid-token.
        let mut plain = String::new();
        let mut chars = message.chars();
        while let Some(c) = chars.next() {
            if c == '' {
                chars.by_ref().find(|&c| c == 'm');
            } else {
                plain.push(c);
            }
        }
        let message = plain;
        let hash = B256::from([0xab; 32]);
        assert!(
            message.starts_with(&format!(
                "transaction {hash} (index 2, ordinal 7) mismatch (< recorded, > replayed)"
            )),
            "{message}"
        );
        assert!(message.contains("<    charged_gas: 21000,"), "{message}");
        assert!(message.contains(">    charged_gas: 21001,"), "{message}");
        assert!(
            message.contains(&B256::from([2; 32]).to_string()),
            "{message}"
        );
        assert!(message.contains("< recorded, > replayed"), "{message}");

        // A wiped account (info None) and a touched one (info unchanged) must not compare equal.
        let touched = |info: Option<InfoChange>| {
            let mut tx = transaction(21_000, 1);
            for change in tx.delta.0[0].values_mut() {
                change.info = info.clone();
            }
            tx
        };
        let unchanged = InfoChange {
            nonce: None,
            balance: None,
            code_hash: None,
        };
        let case = touched(Some(unchanged)).stored().unwrap();
        assert!(case.check(&touched(None)).is_err());
        assert!(
            message.contains("replayed: reason Return, gas [21001, 0, 0, 0], output 0x"),
            "{message}"
        );
    }
}
