//! Corpus wire format: block inputs, transaction boundaries and output digests.
//!
//! Every type here is the stored representation; execution lives in other modules.

use crate::store::WINCODE;
use alloy_primitives::{B256, U256};
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

/// Pre-block values of keys a block's own execution does not read but inputs derived from it do,
/// stored apart from the corpus and merged into the block's pre-state when it is read as a fuzz
/// input. It holds only keys the block's [`Input`] does not.
#[derive(Debug, Default, SchemaRead, SchemaWrite)]
pub struct ExtraPreState {
    /// The block's hash.
    pub hash: [u8; 32],
    /// As [`Input::accounts`].
    pub accounts: BTreeMap<[u8; 20], Option<Info>>,
    /// As [`Input::storage`].
    pub storage: BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>,
    /// As [`Input::code`], with the bytecode stored under the same keys in the extra pre-state's
    /// own store.
    pub code: BTreeSet<[u8; 32]>,
    /// As [`Input::hashes`].
    pub hashes: BTreeMap<u64, [u8; 32]>,
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
    code: Code,
}

/// An account's code hash and chain-specific extension. Tags 0 and 1 encode like the
/// `Option<[u8; 32]>` code hash corpora stored before extensions, so those still decode.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
enum Code {
    #[wincode(tag = 0)]
    Empty,
    #[wincode(tag = 1)]
    Hash([u8; 32]),
    #[wincode(tag = 2)]
    Extended {
        code_hash: Option<[u8; 32]>,
        extension: Vec<u8>,
    },
}

impl Info {
    pub fn capture(account: &Account) -> Self {
        let code_hash = account.bytecode_hash.map(|h| h.0);
        let code = if account.extension.is_empty() {
            code_hash.map_or(Code::Empty, Code::Hash)
        } else {
            Code::Extended {
                code_hash,
                extension: account.extension.to_vec(),
            }
        };
        Self {
            nonce: account.nonce,
            balance: account.balance.to_be_bytes(),
            code,
        }
    }

    pub fn account(&self) -> Account {
        let (code_hash, extension) = match &self.code {
            Code::Empty => (None, Vec::new()),
            Code::Hash(hash) => (Some(*hash), Vec::new()),
            Code::Extended {
                code_hash,
                extension,
            } => (*code_hash, extension.clone()),
        };
        Account {
            nonce: self.nonce,
            balance: U256::from_be_bytes(self.balance),
            bytecode_hash: code_hash.map(B256::from),
            ..Default::default()
        }
        .with_extension(extension)
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
    /// Compares an executed transaction against this record, field by field.
    pub fn check(&self, actual: &Transaction) -> eyre::Result<()> {
        let outputs = actual.outputs()?;
        let at = self.ordinal;
        eyre::ensure!(
            actual.ordinal == self.ordinal
                && actual.index == self.index
                && actual.hash == self.hash
                && actual.before == self.before,
            "transaction context mismatch at {at}"
        );
        eyre::ensure!(
            actual.outcome.status == self.status
                && actual.outcome.charged_gas == self.charged_gas
                && actual.outcome.created == self.created
                && outputs.outcome == self.outputs.outcome,
            "transaction outcome mismatch at {at}"
        );
        eyre::ensure!(
            outputs.receipt == self.outputs.receipt,
            "transaction receipt mismatch at {at}"
        );
        eyre::ensure!(
            actual.delta == self.delta,
            "transaction delta mismatch at {at}"
        );
        eyre::ensure!(
            outputs.after == self.outputs.after,
            "transaction boundary mismatch at {at}"
        );
        Ok(())
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
    pub code: CodeChange,
}

/// Change to an account's code hash and extension. Tags 0 and 1 encode like the
/// `Option<Option<[u8; 32]>>` code hash change corpora stored before extensions, so those still
/// decode.
#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
#[wincode(tag_encoding = "u8")]
pub enum CodeChange {
    /// Code hash and extension unchanged.
    #[wincode(tag = 0)]
    Keep,
    /// Sets the code hash (None: no code); the extension is unchanged.
    #[wincode(tag = 1)]
    Hash(Option<[u8; 32]>),
    /// Sets the extension (empty: none), and the code hash as [`Self::Hash`] does when
    /// `code_hash` is Some.
    #[wincode(tag = 2)]
    Extended {
        code_hash: Option<Option<[u8; 32]>>,
        extension: Vec<u8>,
    },
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
    use wincode::config::{deserialize_exact, serialize};

    /// `Info` as corpora stored it before account extensions.
    #[derive(SchemaWrite)]
    struct LegacyInfo {
        nonce: u64,
        balance: [u8; 32],
        code_hash: Option<[u8; 32]>,
    }

    /// `InfoChange` as corpora stored it before account extensions.
    #[derive(SchemaWrite)]
    struct LegacyInfoChange {
        nonce: Option<u64>,
        balance: Option<[u8; 32]>,
        code_hash: Option<Option<[u8; 32]>>,
    }

    fn account(code_hash: Option<B256>, extension: &[u8]) -> Account {
        Account {
            nonce: 7,
            balance: U256::from(42),
            bytecode_hash: code_hash,
            ..Default::default()
        }
        .with_extension(extension.to_vec())
    }

    #[test]
    fn legacy_info_decodes() {
        for code_hash in [None, Some([0xab; 32])] {
            let legacy = LegacyInfo {
                nonce: 7,
                balance: U256::from(42).to_be_bytes(),
                code_hash,
            };
            let bytes = serialize(&legacy, WINCODE).unwrap();
            let info: Info = deserialize_exact(&bytes, WINCODE).unwrap();
            let account = account(code_hash.map(B256::from), &[]);
            assert_eq!(info.account(), account);
            assert_eq!(serialize(&Info::capture(&account), WINCODE).unwrap(), bytes);
        }
    }

    #[test]
    fn legacy_info_change_decodes() {
        for (legacy, expected) in [
            (None, CodeChange::Keep),
            (Some(None), CodeChange::Hash(None)),
            (Some(Some([0xab; 32])), CodeChange::Hash(Some([0xab; 32]))),
        ] {
            let legacy = LegacyInfoChange {
                nonce: Some(1),
                balance: None,
                code_hash: legacy,
            };
            let bytes = serialize(&legacy, WINCODE).unwrap();
            let change: InfoChange = deserialize_exact(&bytes, WINCODE).unwrap();
            assert_eq!(
                change,
                InfoChange {
                    nonce: Some(1),
                    balance: None,
                    code: expected,
                }
            );
        }
    }

    #[test]
    fn extension_round_trips() {
        for code_hash in [None, Some(B256::repeat_byte(0xab))] {
            let account = account(code_hash, &[0x82, 0xaa]);
            let bytes = serialize(&Info::capture(&account), WINCODE).unwrap();
            let info: Info = deserialize_exact(&bytes, WINCODE).unwrap();
            assert_eq!(info.account(), account);
        }
    }
}
