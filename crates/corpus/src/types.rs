//! Corpus wire format: block inputs, transaction boundaries and output digests.
//!
//! Every type here is the stored representation; execution lives in other modules.

use crate::store::WINCODE;
use alloy_primitives::{Address, B256, U256};
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
    /// Compares an executed transaction against this record, field by field. A mismatch names
    /// the transaction and lists every field that differs, with the recorded and replayed values
    /// where the record keeps them in full.
    pub fn check(&self, actual: &Transaction) -> eyre::Result<()> {
        let outputs = actual.outputs()?;
        let mut kinds = Vec::new();
        let mut lines = Vec::new();

        if actual.ordinal != self.ordinal || actual.index != self.index || actual.hash != self.hash
        {
            kinds.push("context");
            lines.push(format!(
                "context: recorded index {} ordinal {} hash {}, replayed index {} ordinal {} hash {}",
                self.index,
                self.ordinal,
                B256::from(self.hash),
                actual.index,
                actual.ordinal,
                B256::from(actual.hash),
            ));
        }
        if actual.before != self.before {
            kinds.push("boundary before");
            lines.push("boundary before: executor state before the transaction differs".into());
        }

        let mut outcome = Vec::new();
        if actual.outcome.status != self.status {
            outcome.push(format!(
                "status: recorded {}, replayed {}",
                status_name(self.status),
                status_name(actual.outcome.status)
            ));
        }
        if actual.outcome.charged_gas != self.charged_gas {
            outcome.push(format!(
                "charged gas: recorded {}, replayed {} ({:+})",
                self.charged_gas,
                actual.outcome.charged_gas,
                i128::from(actual.outcome.charged_gas) - i128::from(self.charged_gas)
            ));
        }
        if actual.outcome.created != self.created {
            outcome.push(format!(
                "created: recorded {:?}, replayed {:?}",
                self.created.map(Address::from),
                actual.outcome.created.map(Address::from)
            ));
        }
        if outputs.outcome != self.outputs.outcome {
            if outcome.is_empty() {
                outcome.push(
                    "status, charged gas and created address match; the stop reason, gas \
                     breakdown or output differs (recorded as a digest only)"
                        .into(),
                );
            }
            let o = &actual.outcome;
            outcome.push(format!(
                "replayed: reason {}, gas [spent {}, refunded {}, floor {}, state {}], output {}",
                o.reason,
                o.gas[0],
                o.gas[1],
                o.gas[2],
                o.gas[3],
                o.output.as_deref().map_or_else(
                    || "none".to_string(),
                    |bytes| match bytes.get(..64) {
                        Some(head) if bytes.len() > 64 => format!(
                            "0x{}… ({} bytes)",
                            alloy_primitives::hex::encode(head),
                            bytes.len()
                        ),
                        _ => format!("0x{}", alloy_primitives::hex::encode(bytes)),
                    },
                ),
            ));
        }
        if !outcome.is_empty() {
            kinds.push("outcome");
            lines.extend(outcome.into_iter().map(|line| format!("outcome {line}")));
        }

        if outputs.receipt != self.outputs.receipt {
            kinds.push("receipt");
            lines.push("receipt: differs (recorded as a digest only)".into());
        }
        if actual.delta != self.delta {
            kinds.push("delta");
            lines.extend(
                self.delta
                    .diff(&actual.delta)
                    .into_iter()
                    .map(|l| format!("delta {l}")),
            );
        }
        if outputs.after != self.outputs.after {
            kinds.push("boundary after");
            lines.push("boundary after: executor state after the transaction differs".into());
        }

        if kinds.is_empty() {
            return Ok(());
        }
        let mut message = format!(
            "transaction {} (index {}, ordinal {}) {} mismatch",
            B256::from(self.hash),
            self.index,
            self.ordinal,
            kinds.join(", ")
        );
        for line in lines {
            message.push_str("\n  ");
            message.push_str(&line);
        }
        Err(eyre::eyre!(message))
    }
}

fn status_name(status: u8) -> &'static str {
    match status {
        0 => "success",
        _ => "failure",
    }
}

/// Ordered commits inside a phase, preserving wipe then recreation.
#[derive(Clone, Debug, Default, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct Delta(pub Vec<BTreeMap<[u8; 20], Change>>);

impl Delta {
    /// Most lines a diff returns before summarizing the rest.
    const DIFF_LINES: usize = 32;

    /// Human-readable differences from self (recorded) to other (replayed): per commit,
    /// each account added, missing or changed, down to its info fields, storage slots and code.
    pub fn diff(&self, other: &Self) -> Vec<String> {
        let mut lines = Vec::new();
        if self.0.len() != other.0.len() {
            lines.push(format!(
                "commits: recorded {}, replayed {}",
                self.0.len(),
                other.0.len()
            ));
        }
        let empty = BTreeMap::new();
        for commit in 0..self.0.len().max(other.0.len()) {
            let recorded = self.0.get(commit).unwrap_or(&empty);
            let replayed = other.0.get(commit).unwrap_or(&empty);
            let addresses: BTreeSet<_> = recorded.keys().chain(replayed.keys()).collect();
            for address in addresses {
                let at = format!("commit {commit} {}", Address::from(*address));
                match (recorded.get(address), replayed.get(address)) {
                    (Some(_), None) => lines.push(format!("{at}: recorded change, none replayed")),
                    (None, Some(_)) => lines.push(format!("{at}: replayed change, none recorded")),
                    (Some(a), Some(b)) if a != b => {
                        if a.created != b.created {
                            lines.push(format!(
                                "{at} created: recorded {}, replayed {}",
                                a.created, b.created
                            ));
                        }
                        match (&a.info, &b.info) {
                            (Some(x), Some(y)) => {
                                if x.nonce != y.nonce {
                                    lines.push(format!(
                                        "{at} nonce: recorded {:?}, replayed {:?}",
                                        x.nonce, y.nonce
                                    ));
                                }
                                if x.balance != y.balance {
                                    let balance = |v: Option<[u8; 32]>| v.map(U256::from_be_bytes);
                                    lines.push(format!(
                                        "{at} balance: recorded {:?}, replayed {:?}",
                                        balance(x.balance),
                                        balance(y.balance)
                                    ));
                                }
                                if x.code_hash != y.code_hash {
                                    let hash =
                                        |v: Option<Option<[u8; 32]>>| v.map(|h| h.map(B256::from));
                                    lines.push(format!(
                                        "{at} code hash: recorded {:?}, replayed {:?}",
                                        hash(x.code_hash),
                                        hash(y.code_hash)
                                    ));
                                }
                            }
                            (x, y) if x != y => lines.push(format!(
                                "{at} account info: recorded {}, replayed {}",
                                if x.is_some() { "changed" } else { "unchanged" },
                                if y.is_some() { "changed" } else { "unchanged" },
                            )),
                            _ => {}
                        }
                        let slots: BTreeSet<_> = a.storage.keys().chain(b.storage.keys()).collect();
                        for slot in slots {
                            let (x, y) = (a.storage.get(slot), b.storage.get(slot));
                            if x != y {
                                let value = |v: Option<&[u8; 32]>| v.map(|v| B256::from(*v));
                                lines.push(format!(
                                    "{at} slot {}: recorded {:?}, replayed {:?}",
                                    B256::from(*slot),
                                    value(x),
                                    value(y)
                                ));
                            }
                        }
                        if a.code != b.code {
                            let code = |c: &Option<Vec<u8>>| {
                                c.as_ref().map_or_else(
                                    || "unchanged".to_string(),
                                    |c| format!("{} bytes", c.len()),
                                )
                            };
                            lines.push(format!(
                                "{at} code: recorded {}, replayed {}",
                                code(&a.code),
                                code(&b.code)
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
        if lines.len() > Self::DIFF_LINES {
            let rest = lines.len() - Self::DIFF_LINES;
            lines.truncate(Self::DIFF_LINES);
            lines.push(format!("… {rest} more differences"));
        }
        lines
    }
}

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
    fn check_reports_transaction_and_differing_fields() {
        let case = transaction(21_000, 1).stored().unwrap();
        assert!(case.check(&transaction(21_000, 1)).is_ok());

        let message = case.check(&transaction(21_001, 2)).unwrap_err().to_string();
        let hash = B256::from([0xab; 32]);
        assert!(
            message.starts_with(&format!(
                "transaction {hash} (index 2, ordinal 7) outcome, delta mismatch"
            )),
            "{message}"
        );
        assert!(
            message.contains("charged gas: recorded 21000, replayed 21001 (+1)"),
            "{message}"
        );
        assert!(message.contains("reason Return"), "{message}");
        let address = Address::from([0x11; 20]);
        let slot = B256::from([1; 32]);
        assert!(
            message.contains(&format!(
                "delta commit 0 {address} slot {slot}: recorded Some({}), replayed Some({})",
                B256::from([1; 32]),
                B256::from([2; 32])
            )),
            "{message}"
        );
    }

    #[test]
    fn check_reports_context_status_receipt_and_boundaries() {
        let case = transaction(21_000, 1).stored().unwrap();
        let mut actual = transaction(21_000, 1);
        actual.index = 3;
        actual.before = vec![9];
        actual.outcome.status = 1;
        actual.receipt = vec![4];
        actual.after = vec![5];
        let message = case.check(&actual).unwrap_err().to_string();
        assert!(
            message.contains("context, boundary before, outcome, receipt, boundary after mismatch"),
            "{message}"
        );
        assert!(message.contains("recorded index 2 ordinal 7"), "{message}");
        assert!(message.contains("replayed index 3 ordinal 7"), "{message}");
        assert!(
            message.contains("outcome status: recorded success, replayed failure"),
            "{message}"
        );
        assert!(message.contains("receipt: differs"), "{message}");
        assert!(
            message.contains("boundary before: executor state"),
            "{message}"
        );
        assert!(
            message.contains("boundary after: executor state"),
            "{message}"
        );
    }

    #[test]
    fn delta_diff_reports_commits_and_added_or_missing_accounts() {
        let change = || Change {
            info: None,
            created: false,
            storage: BTreeMap::new(),
            code: None,
        };
        let recorded = Delta(vec![BTreeMap::from([([1; 20], change())])]);
        let replayed = Delta(vec![BTreeMap::from([([2; 20], change())]), BTreeMap::new()]);
        assert_eq!(
            recorded.diff(&replayed),
            [
                "commits: recorded 1, replayed 2".to_string(),
                format!(
                    "commit 0 {}: recorded change, none replayed",
                    Address::from([1; 20])
                ),
                format!(
                    "commit 0 {}: replayed change, none recorded",
                    Address::from([2; 20])
                ),
            ]
        );
        assert!(recorded.diff(&recorded).is_empty());
    }

    #[test]
    fn delta_diff_truncates_long_reports() {
        let change = |value: u8| Change {
            info: None,
            created: false,
            storage: (0..40u8).map(|slot| ([slot; 32], [value; 32])).collect(),
            code: None,
        };
        let recorded = Delta(vec![BTreeMap::from([([1; 20], change(1))])]);
        let replayed = Delta(vec![BTreeMap::from([([1; 20], change(2))])]);
        let lines = recorded.diff(&replayed);
        assert_eq!(lines.len(), Delta::DIFF_LINES + 1);
        assert_eq!(lines.last().unwrap(), "… 8 more differences");
    }
}
