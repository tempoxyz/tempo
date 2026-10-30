//! Corpus wire format: block inputs, transaction boundaries and output digests.
//!
//! Every type here is the stored representation; execution lives in other modules.

use alloy_primitives::{B256, U256};
use reth_primitives_traits::Account;
use std::collections::{BTreeMap, BTreeSet};
use wincode::{SchemaRead, SchemaWrite};

/// One block's input: its canonical block, the pre-state it reads and the historical
/// changesets used to check its state changes. All values originate in the archive DB.
#[derive(Debug, SchemaRead, SchemaWrite)]
pub struct Chunk {
    pub start: u64,
    pub end: u64,
    pub parent: [u8; 32],
    pub blocks: Vec<Block>,
    pub accounts: BTreeMap<[u8; 20], Vec<(u64, Option<Info>)>>,
    #[allow(clippy::type_complexity)] // Keep the wire representation explicit.
    pub storage: BTreeMap<([u8; 20], [u8; 32]), Vec<(u64, [u8; 32])>>,
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
    /// Historical account changeset as a bitmap over the chunk's account witness (in key
    /// order): bit `i` marks the `i`-th account as changed by the block. Its pre-value is the
    /// witness value before the block, which capture checked against the archive changeset.
    pub changed_accounts: Vec<u8>,
    /// Historical storage changeset as a bitmap over the chunk's storage witness (in key
    /// order). Slots wiped by a destroyed account stay in the witness so they can be marked.
    pub changed_storage: Vec<u8>,
}

/// A block's historical changeset: pre-values of every account and slot it changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChangeSet {
    pub accounts: BTreeMap<[u8; 20], Option<Info>>,
    pub storage: BTreeMap<([u8; 20], [u8; 32]), [u8; 32]>,
}

/// Packs `len` flags, set where `changed` holds, into a little-endian bitmap.
pub fn bitmap(len: usize, mut changed: impl FnMut(usize) -> bool) -> Vec<u8> {
    let mut bits = vec![0u8; len.div_ceil(8)];
    for i in 0..len {
        if changed(i) {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    bits
}

fn bit(bits: &[u8], i: usize) -> bool {
    bits[i / 8] & (1 << (i % 8)) != 0
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

impl Chunk {
    /// Bitmaps marking `changeset` within this chunk's witness. Every changed key must be in
    /// the witness with the same pre-value.
    pub fn mark(&self, changeset: &ChangeSet) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
        for (address, info) in &changeset.accounts {
            let witness = self
                .accounts
                .get(address)
                .and_then(|v| v.first())
                .map(|(_, i)| i);
            eyre::ensure!(
                witness == Some(info),
                "account changeset disagrees with witness"
            );
        }
        for (key, value) in &changeset.storage {
            let witness = self
                .storage
                .get(key)
                .and_then(|v| v.first())
                .map(|(_, v)| v);
            eyre::ensure!(
                witness == Some(value),
                "storage changeset disagrees with witness"
            );
        }
        let accounts: Vec<bool> = self
            .accounts
            .keys()
            .map(|k| changeset.accounts.contains_key(k))
            .collect();
        let storage: Vec<bool> = self
            .storage
            .keys()
            .map(|k| changeset.storage.contains_key(k))
            .collect();
        let accounts = bitmap(accounts.len(), |i| accounts[i]);
        let storage = bitmap(storage.len(), |i| storage[i]);
        Ok((accounts, storage))
    }

    /// The block's historical changeset, resolved from its bitmaps over the witness.
    pub fn changeset(&self) -> eyre::Result<ChangeSet> {
        let block = self
            .blocks
            .first()
            .ok_or_else(|| eyre::eyre!("empty chunk"))?;
        eyre::ensure!(
            block.changed_accounts.len() == self.accounts.len().div_ceil(8)
                && block.changed_storage.len() == self.storage.len().div_ceil(8),
            "changeset bitmap size mismatch"
        );
        let mut changeset = ChangeSet::default();
        for (i, (address, versions)) in self.accounts.iter().enumerate() {
            if bit(&block.changed_accounts, i) {
                changeset.accounts.insert(*address, versions[0].1.clone());
            }
        }
        for (i, (key, versions)) in self.storage.iter().enumerate() {
            if bit(&block.changed_storage, i) {
                changeset.storage.insert(*key, versions[0].1);
            }
        }
        Ok(changeset)
    }

    pub fn validate(&self) -> eyre::Result<()> {
        eyre::ensure!(
            self.start > 0 && self.end > self.start,
            "invalid corpus range"
        );
        eyre::ensure!(
            self.blocks.len() as u64 == self.end - self.start,
            "missing/extra corpus blocks"
        );
        for versions in self.accounts.values() {
            self.validate_versions(versions)?;
        }
        for versions in self.storage.values() {
            self.validate_versions(versions)?;
        }
        Ok(())
    }

    fn validate_versions<T>(&self, versions: &[(u64, T)]) -> eyre::Result<()> {
        eyre::ensure!(
            versions.first().map(|v| v.0) == Some(self.start - 1),
            "missing initial state version"
        );
        eyre::ensure!(
            versions.windows(2).all(|v| v[0].0 < v[1].0)
                && versions.last().is_some_and(|v| v.0 < self.end),
            "invalid state version ordering"
        );
        Ok(())
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

    /// The stored form: input in full, outputs as per-field digests.
    pub fn stored(&self) -> eyre::Result<Case> {
        Ok(Case {
            ordinal: self.ordinal,
            index: self.index,
            hash: self.hash,
            before: self.before.clone(),
            status: self.outcome.status,
            charged_gas: self.outcome.charged_gas,
            created: self.outcome.created,
            outputs: Outputs {
                outcome: digest(&wincode::serialize(&self.outcome)?),
                receipt: digest(&self.receipt),
                delta: digest(&wincode::serialize(&self.delta)?),
                after: digest(&self.after),
            },
        })
    }
}

/// Stored form of a [`Transaction`]: its input (`before`) in full, and each output as a
/// separate xxh3-128 digest, so replay detects any divergence and names the field without
/// storing post values. Status, charged gas and the created address stay readable for triage.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Case {
    pub ordinal: u64,
    pub index: u64,
    pub hash: [u8; 32],
    pub before: Vec<u8>,
    pub status: u8,
    pub charged_gas: u64,
    pub created: Option<[u8; 20]>,
    pub outputs: Outputs,
}

/// Per-field digests of a transaction's outputs.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Outputs {
    pub outcome: [u8; 16],
    pub receipt: [u8; 16],
    pub delta: [u8; 16],
    pub after: [u8; 16],
}

fn digest(bytes: &[u8]) -> [u8; 16] {
    xxhash_rust::xxh3::xxh3_128(bytes).to_le_bytes()
}

impl Case {
    /// Compares an executed transaction against this record, field by field.
    pub fn check(&self, actual: &Transaction) -> eyre::Result<()> {
        let actual = actual.stored()?;
        let at = self.ordinal;
        eyre::ensure!(
            actual.ordinal == self.ordinal
                && actual.index == self.index
                && actual.hash == self.hash
                && actual.before == self.before,
            "transaction context mismatch at {at}"
        );
        eyre::ensure!(
            actual.status == self.status
                && actual.charged_gas == self.charged_gas
                && actual.created == self.created
                && actual.outputs.outcome == self.outputs.outcome,
            "transaction outcome mismatch at {at}"
        );
        eyre::ensure!(
            actual.outputs.receipt == self.outputs.receipt,
            "transaction receipt mismatch at {at}"
        );
        eyre::ensure!(
            actual.outputs.delta == self.outputs.delta,
            "transaction delta mismatch at {at}"
        );
        eyre::ensure!(
            actual.outputs.after == self.outputs.after,
            "transaction boundary mismatch at {at}"
        );
        Ok(())
    }
}

/// Ordered commits inside a phase, preserving wipe then recreation.
#[derive(Debug, Default, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Delta(pub Vec<BTreeMap<[u8; 20], Change>>);

#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Change {
    pub info: Option<InfoChange>,
    pub created: bool,
    pub storage: BTreeMap<[u8; 32], [u8; 32]>,
    pub code: Option<Vec<u8>>,
}

/// None preserves a field; Some(zero/None) explicitly resets it.
#[derive(Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
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
