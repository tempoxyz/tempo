//! Append-only workload ledger shared by every test command in the workload container.
//!
//! Commands can be killed at any point, so each record is one JSON line appended under an
//! exclusive file lock and synced before return. Signed intents precede broadcast; obligations
//! precede terminal outcomes. Only an incomplete last line is recoverable.

use crate::intents::{Intent, Outcome, pending};
use alloy::{
    primitives::{Address, B256, keccak256},
    rpc::types::TransactionReceipt,
    signers::local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
};
use eyre::{OptionExt as _, WrapErr as _};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead as _, BufReader, Seek as _, Write as _},
    path::{Path, PathBuf},
};

/// Mnemonic of the public dev accounts funded in the L1 genesis. Never holds real funds.
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// First index of workload-created accounts, above every funder index.
const FIRST_WORKLOAD_INDEX: u32 = 1_000;

/// One durable workload fact, intent, or terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// Externally tagged: serde buffers an internally tagged enum before picking the variant, and
// that buffer rejects the u128 amounts, which would drop every deposit, withdrawal and transfer.
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Record {
    /// A reserved identifier; gaps are permitted when a command dies before using it.
    Sequence { id: u64 },
    /// A signed payment, synced before its first broadcast.
    Intent(Intent),
    /// A mined result, synced only after its confirmed obligation.
    IntentOutcome { tx: B256, outcome: Outcome },
    /// A leadership request recorded before it is issued.
    HandoffRequest(crate::handoff::Request),
    /// A receipt or event tying a leadership update to its request.
    HandoffUpdate(crate::handoff::Update),
    /// A new account was derived at this mnemonic index. Written before the account is used.
    Account { index: u32 },
    /// An L1 deposit succeeded; the zone must credit `net_amount` to `to` or bounce it back.
    Deposit {
        l1_tx: B256,
        /// The portal's deposit queue hash after this deposit, which the zone inbox emits as
        /// `depositHash` when it credits or bounces it.
        queue_hash: B256,
        sender: Address,
        to: Address,
        net_amount: u128,
    },
    /// A zone withdrawal request succeeded; the portal must pay `amount` to `to` on L1.
    Withdrawal {
        zone_tx: B256,
        zone_block: u64,
        sender: Address,
        to: Address,
        amount: u128,
    },
    /// A zone TIP-20 transfer succeeded.
    Transfer {
        zone_tx: B256,
        zone_block: u64,
        from: Address,
        to: Address,
        amount: u128,
    },
}

/// The workload ledger and per-account leases under one state directory.
#[derive(Debug, Clone)]
pub(super) struct Ledger {
    dir: PathBuf,
}

impl Ledger {
    /// Opens the ledger in `dir`, creating the directory on first use.
    pub(super) fn open(dir: &Path) -> eyre::Result<Self> {
        std::fs::create_dir_all(dir.join("locks"))
            .wrap_err_with(|| format!("failed creating {}", dir.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Excludes process-outage episodes from handoffs and recovery. Shared holders may race
    /// handoffs as before; exclusive holders wait boundedly, never skip the requested check.
    pub(super) async fn episode_lock(&self, exclusive: bool) -> eyre::Result<File> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join("locks/episode"))
            .wrap_err("failed opening outage episode lock")?;
        super::recovery::recover_until(
            tokio::time::Instant::now() + std::time::Duration::from_secs(300),
            async || match if exclusive {
                file.try_lock()
            } else {
                file.try_lock_shared()
            } {
                Ok(()) => Ok(Some(())),
                Err(std::fs::TryLockError::WouldBlock) => Ok(None),
                Err(std::fs::TryLockError::Error(error)) => {
                    Err(error).wrap_err("failed locking outage episode")
                }
            },
        )
        .await?;
        Ok(file)
    }

    /// Returns every complete record in append order.
    pub(super) fn records(&self) -> eyre::Result<Vec<Record>> {
        let file = self.locked_file()?;
        read_records(&file)
    }

    /// Appends and syncs `record`; duplicate effects are idempotent, conflicts are errors.
    pub(super) fn append(&self, record: &Record) -> eyre::Result<()> {
        let mut file = self.locked_file()?;
        let mut records = read_records(&file)?;
        if let Some(hash) = record.effect_hash()
            && let Some(prior) = records
                .iter()
                .find(|prior| prior.effect_hash() == Some(hash))
        {
            eyre::ensure!(prior == record, "conflicting confirmed effect for {hash}");
            return Ok(());
        }
        records.push(record.clone());
        pending(&records)?;
        append_synced(&mut file, record)
    }

    /// Appends an exact record once under the journal lock; false means it already exists.
    pub(super) fn append_once(&self, record: &Record) -> eyre::Result<bool> {
        let mut file = self.locked_file()?;
        let mut records = read_records(&file)?;
        if records.contains(record) {
            return Ok(false);
        }
        if let Some(hash) = record.effect_hash() {
            eyre::ensure!(
                !records
                    .iter()
                    .any(|prior| prior.effect_hash() == Some(hash)),
                "conflicting confirmed effect for {hash}"
            );
        }
        records.push(record.clone());
        pending(&records)?;
        append_synced(&mut file, record)?;
        Ok(true)
    }

    /// Reserves and syncs a unique journal identifier before returning it.
    pub(super) fn next_id(&self) -> eyre::Result<u64> {
        let mut file = self.locked_file()?;
        let id = read_records(&file)?
            .iter()
            .filter_map(|record| match record {
                Record::Sequence { id } => Some(*id),
                _ => None,
            })
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_eyre("ledger identifier overflow")?;
        append_synced(&mut file, &Record::Sequence { id })?;
        Ok(id)
    }

    /// Resolves a mined intent under the journal lock. Cancellation after the obligation's
    /// sync leaves it unresolved, so the next pass completes without duplicating its effect.
    pub(super) fn resolve_intent(
        &self,
        intent: &Intent,
        receipt: &TransactionReceipt,
    ) -> eyre::Result<()> {
        let obligation = intent.obligation(receipt)?;
        let block = receipt.block_number.ok_or_eyre("receipt has no block")?;
        let block_hash = receipt.block_hash.ok_or_eyre("receipt has no block hash")?;
        let outcome = if receipt.status() {
            Outcome::Confirmed { block, block_hash }
        } else {
            Outcome::Reverted { block, block_hash }
        };
        let mut file = self.locked_file()?;
        let records = read_records(&file)?;
        pending(&records)?;
        eyre::ensure!(
            records
                .iter()
                .any(|record| matches!(record, Record::Intent(prior) if prior == intent)),
            "cannot resolve an unjournaled intent"
        );
        if let Some(prior) = records.iter().find_map(|record| match record {
            Record::IntentOutcome { tx, outcome } if *tx == intent.tx => Some(outcome),
            _ => None,
        }) {
            eyre::ensure!(
                prior == &outcome,
                "conflicting mined outcome for {}",
                intent.tx
            );
            return Ok(());
        }
        if !receipt.status() {
            eyre::ensure!(
                !records
                    .iter()
                    .any(|record| record.effect_hash() == Some(intent.tx)),
                "reverted receipt conflicts with confirmed obligation"
            );
        }
        if let Some(obligation) = obligation {
            if let Some(prior) = records
                .iter()
                .find(|record| record.effect_hash() == Some(intent.tx))
            {
                eyre::ensure!(prior == &obligation, "conflicting confirmed obligation");
            } else {
                append_synced(&mut file, &obligation)?;
            }
        }
        append_synced(
            &mut file,
            &Record::IntentOutcome {
                tx: intent.tx,
                outcome,
            },
        )
    }

    /// Derives a fresh workload account and records it before returning it.
    pub(super) fn new_account(&self) -> eyre::Result<Account> {
        let mut file = self.locked_file()?;
        let count = read_records(&file)?
            .iter()
            .filter(|record| matches!(record, Record::Account { .. }))
            .count();
        let index = FIRST_WORKLOAD_INDEX
            .checked_add(u32::try_from(count)?)
            .ok_or_else(|| eyre::eyre!("workload account index overflow"))?;
        append_synced(&mut file, &Record::Account { index })?;
        Account::workload(index)
    }

    /// Every workload account recorded so far.
    pub(super) fn accounts(&self) -> eyre::Result<Vec<Account>> {
        self.records()?
            .into_iter()
            .filter_map(|record| match record {
                Record::Account { index } => Some(Account::workload(index)),
                _ => None,
            })
            .collect()
    }

    /// Takes the exclusive lease on `account` without blocking, so only one command sends from
    /// it at a time. Returns `None` when another command holds it or an intent is unresolved. The lease ends when the
    /// returned guard drops or the holder dies.
    pub(super) fn try_lease(&self, account: &Account) -> eyre::Result<Option<Lease>> {
        let path = self.dir.join("locks").join(format!("{}", account.index));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .wrap_err_with(|| format!("failed opening {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {
                // A killed holder releases its OS lease, but not its unresolved nonce.
                if pending(&self.records()?)?
                    .iter()
                    .any(|intent| intent.sender == account.address())
                {
                    return Ok(None);
                }
                Ok(Some(Lease { _file: file }))
            }
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => {
                Err(error).wrap_err_with(|| format!("failed locking {}", path.display()))
            }
        }
    }

    fn locked_file(&self) -> eyre::Result<File> {
        let path = self.dir.join("ledger.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .wrap_err_with(|| format!("failed opening {}", path.display()))?;
        file.lock()
            .wrap_err_with(|| format!("failed locking {}", path.display()))?;
        // Never turn a torn append into a malformed complete record. Validate every
        // complete line before truncating only the unterminated tail.
        let mut reader = BufReader::new(&file);
        let mut line = Vec::new();
        let mut complete = 0u64;
        loop {
            line.clear();
            if reader.read_until(b'\n', &mut line)? == 0 {
                break;
            }
            if !line.ends_with(b"\n") {
                break;
            }
            serde_json::from_slice::<Record>(&line)
                .wrap_err_with(|| format!("malformed complete ledger record at byte {complete}"))?;
            complete = complete
                .checked_add(u64::try_from(line.len())?)
                .ok_or_eyre("ledger size overflow")?;
        }
        drop(reader);
        if file.metadata()?.len() != complete {
            file.set_len(complete)
                .wrap_err("failed recovering incomplete ledger tail")?;
        }
        // A killed writer may have completed its newline but not its sync. Fence those
        // complete records too before any caller can replay an intent or reuse its nonce.
        file.sync_data()
            .wrap_err("failed syncing recovered ledger")?;
        File::open(&self.dir)?
            .sync_all()
            .wrap_err("failed syncing ledger directory")?;
        file.rewind()?;
        Ok(file)
    }
}

/// An exclusive lease on one account; see [`Ledger::try_lease`].
#[derive(Debug)]
pub(super) struct Lease {
    _file: File,
}

/// An account that signs on both L1 and the zone: a genesis dev account or a workload account.
#[derive(Debug, Clone)]
pub(super) struct Account {
    /// BIP-44 index under [`TEST_MNEMONIC`] for a dev account, or the workload account index.
    pub(super) index: u32,
    /// Signer for the account's key.
    pub(super) signer: PrivateKeySigner,
}

impl Account {
    /// Derives workload account `index` from a hash of it. Commands rebuild every recorded
    /// account on each run, and BIP-39 derivation (2048 PBKDF2 rounds each) would make that
    /// slow once runs reach tens of thousands of accounts.
    pub(super) fn workload(index: u32) -> eyre::Result<Self> {
        let mut preimage = b"tempo-zone-antithesis-workload".to_vec();
        preimage.extend_from_slice(&index.to_be_bytes());
        let signer = PrivateKeySigner::from_bytes(&keccak256(preimage))
            .wrap_err_with(|| format!("failed deriving workload account {index}"))?;
        Ok(Self { index, signer })
    }

    /// Derives genesis dev account `index` from [`TEST_MNEMONIC`].
    pub(super) fn at(index: u32) -> eyre::Result<Self> {
        let signer = MnemonicBuilder::<English>::default()
            .phrase(TEST_MNEMONIC)
            .index(index)?
            .build()
            .wrap_err_with(|| format!("failed deriving account {index}"))?;
        Ok(Self { index, signer })
    }

    /// The account's address.
    pub(super) fn address(&self) -> Address {
        self.signer.address()
    }
}

impl Record {
    /// Hash identifying a confirmed payment effect, not an intent or outcome.
    pub(crate) fn effect_hash(&self) -> Option<B256> {
        match self {
            Self::Deposit { l1_tx, .. } => Some(*l1_tx),
            Self::Transfer { zone_tx, .. } | Self::Withdrawal { zone_tx, .. } => Some(*zone_tx),
            _ => None,
        }
    }
}

fn append_synced(file: &mut File, record: &Record) -> eyre::Result<()> {
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)
        .wrap_err("failed appending ledger record")?;
    file.sync_data().wrap_err("failed syncing ledger record")
}

fn read_records(file: &File) -> eyre::Result<Vec<Record>> {
    BufReader::new(file)
        .lines()
        .enumerate()
        .map(|(index, line)| {
            let line = line.wrap_err("failed reading ledger")?;
            serde_json::from_str(&line)
                .wrap_err_with(|| format!("malformed complete ledger record on line {}", index + 1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::intents::{Chain, Effect};
    use alloy::{
        consensus::{Receipt, ReceiptEnvelope, ReceiptWithBloom},
        primitives::{Bloom, Bytes},
    };

    fn intent() -> Intent {
        let raw = Bytes::from_static(b"signed test envelope");
        Intent {
            tx: keccak256(&raw),
            raw,
            chain: Chain::Zone,
            chain_id: 123,
            sender: Account::workload(FIRST_WORKLOAD_INDEX).unwrap().address(),
            nonce: 0,
            node: 0,
            effect: Effect::Transfer {
                to: Address::repeat_byte(2),
                amount: 3,
            },
        }
    }

    fn receipt(intent: &Intent, success: bool) -> TransactionReceipt {
        TransactionReceipt {
            inner: ReceiptEnvelope::Legacy(ReceiptWithBloom::new(
                Receipt {
                    status: success.into(),
                    cumulative_gas_used: 1,
                    logs: vec![],
                },
                Bloom::ZERO,
            )),
            transaction_hash: intent.tx,
            transaction_index: Some(0),
            block_hash: Some(B256::repeat_byte(4)),
            block_number: Some(1),
            gas_used: 1,
            effective_gas_price: 1,
            blob_gas_used: None,
            blob_gas_price: None,
            from: intent.sender,
            to: Some(Address::repeat_byte(2)),
            contract_address: None,
        }
    }

    #[test]
    fn malformed_complete_lines_are_not_discarded_or_repaired() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let bytes = b"{not json}\n{torn";
        std::fs::write(dir.path().join("ledger.jsonl"), bytes).unwrap();
        assert!(
            ledger
                .records()
                .unwrap_err()
                .to_string()
                .contains("malformed complete ledger record")
        );
        assert!(
            ledger
                .append(&Record::Account { index: 1 })
                .unwrap_err()
                .to_string()
                .contains("malformed complete ledger record")
        );
        assert_eq!(
            std::fs::read(dir.path().join("ledger.jsonl")).unwrap(),
            bytes
        );
    }

    #[test]
    fn every_incomplete_prefix_is_recovered_without_losing_prior_records() {
        let record = Record::Account {
            index: FIRST_WORKLOAD_INDEX + 1,
        };
        let mut encoded = serde_json::to_vec(&record).unwrap();
        encoded.push(b'\n');
        for length in 0..encoded.len() {
            let dir = tempfile::tempdir().unwrap();
            let ledger = Ledger::open(dir.path()).unwrap();
            let first = Record::Account {
                index: FIRST_WORKLOAD_INDEX,
            };
            ledger.append(&first).unwrap();
            OpenOptions::new()
                .append(true)
                .open(dir.path().join("ledger.jsonl"))
                .unwrap()
                .write_all(&encoded[..length])
                .unwrap();
            assert_eq!(ledger.records().unwrap(), vec![first]);
            ledger.append(&record).unwrap();
            assert_eq!(ledger.records().unwrap().len(), 2);
        }
    }

    #[test]
    fn crash_after_obligation_and_duplicate_reconciliation_are_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let intent = intent();
        let receipt = receipt(&intent, true);
        ledger.append(&Record::Intent(intent.clone())).unwrap();
        ledger
            .append(&intent.obligation(&receipt).unwrap().unwrap())
            .unwrap();
        // Simulate death after the obligation fsync but during the outcome append.
        OpenOptions::new()
            .append(true)
            .open(dir.path().join("ledger.jsonl"))
            .unwrap()
            .write_all(b"{\"intent_outcome\":")
            .unwrap();
        let reopened = Ledger::open(dir.path()).unwrap();
        assert_eq!(
            pending(&reopened.records().unwrap()).unwrap(),
            vec![intent.clone()]
        );
        reopened.resolve_intent(&intent, &receipt).unwrap();
        reopened.resolve_intent(&intent, &receipt).unwrap();
        let records = reopened.records().unwrap();
        assert_eq!(records.len(), 3);
        assert!(matches!(records[1], Record::Transfer { .. }));
        assert!(matches!(
            records[2],
            Record::IntentOutcome {
                outcome: Outcome::Confirmed { .. },
                ..
            }
        ));
        assert!(pending(&records).unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancellation_keeps_exact_bytes_and_blocks_sender_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let account = ledger.new_account().unwrap();
        let intent = intent();
        let lease = ledger.try_lease(&account).unwrap().unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_millis(1), async {
            ledger.append(&Record::Intent(intent.clone())).unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        assert!(result.is_err());
        drop(lease);
        let reopened = Ledger::open(dir.path()).unwrap();
        assert_eq!(
            pending(&reopened.records().unwrap()).unwrap(),
            vec![intent.clone()]
        );
        assert!(reopened.try_lease(&account).unwrap().is_none());
        reopened
            .resolve_intent(&intent, &receipt(&intent, false))
            .unwrap();
        assert!(reopened.try_lease(&account).unwrap().is_some());
        assert_eq!(
            reopened
                .records()
                .unwrap()
                .iter()
                .filter(|r| r.effect_hash().is_some())
                .count(),
            0
        );
    }

    #[test]
    fn terminal_success_requires_obligation_and_nonce_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let intent = intent();
        ledger.append(&Record::Intent(intent.clone())).unwrap();
        let error = ledger
            .append(&Record::IntentOutcome {
                tx: intent.tx,
                outcome: Outcome::Confirmed {
                    block: 1,
                    block_hash: B256::repeat_byte(4),
                },
            })
            .unwrap_err();
        assert_eq!(error.to_string(), "confirmed outcome precedes obligation");
        let mut replacement = intent.clone();
        replacement.raw = Bytes::from_static(b"different signature");
        replacement.tx = keccak256(&replacement.raw);
        assert_eq!(
            ledger
                .append(&Record::Intent(replacement))
                .unwrap_err()
                .to_string(),
            "replacement intent at an already journaled nonce"
        );
        ledger
            .resolve_intent(&intent, &receipt(&intent, false))
            .unwrap();
        assert!(
            ledger
                .resolve_intent(&intent, &receipt(&intent, true))
                .unwrap_err()
                .to_string()
                .contains("conflicting mined outcome")
        );
    }

    #[test]
    fn identifiers_are_reserved_and_append_once_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        assert_eq!(ledger.next_id().unwrap(), 1);
        assert_eq!(Ledger::open(dir.path()).unwrap().next_id().unwrap(), 2);
        let record = Record::Account {
            index: FIRST_WORKLOAD_INDEX,
        };
        assert!(ledger.append_once(&record).unwrap());
        assert!(!ledger.append_once(&record).unwrap());
        assert_eq!(ledger.records().unwrap().len(), 3);
    }

    #[test]
    fn accounts_get_consecutive_indices_and_torn_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        assert_eq!(ledger.new_account().unwrap().index, FIRST_WORKLOAD_INDEX);
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("ledger.jsonl"))
            .unwrap()
            .write_all(b"{\"accou")
            .unwrap();
        assert_eq!(
            ledger.new_account().unwrap().index,
            FIRST_WORKLOAD_INDEX + 1
        );
        assert_eq!(ledger.accounts().unwrap().len(), 2);
    }

    #[test]
    fn every_record_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let records = [
            Record::Account {
                index: FIRST_WORKLOAD_INDEX,
            },
            Record::Deposit {
                l1_tx: B256::repeat_byte(1),
                queue_hash: B256::repeat_byte(2),
                sender: Address::repeat_byte(3),
                to: Address::repeat_byte(4),
                net_amount: u128::MAX,
            },
            Record::Withdrawal {
                zone_tx: B256::repeat_byte(5),
                zone_block: 6,
                sender: Address::repeat_byte(7),
                to: Address::repeat_byte(8),
                amount: u128::MAX,
            },
            Record::Transfer {
                zone_tx: B256::repeat_byte(9),
                zone_block: 10,
                from: Address::repeat_byte(11),
                to: Address::repeat_byte(12),
                amount: u128::MAX,
            },
        ];
        for record in &records {
            ledger.append(record).unwrap();
        }
        assert_eq!(ledger.records().unwrap(), records);
    }

    #[test]
    fn lease_is_exclusive_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        let account = Account::workload(FIRST_WORKLOAD_INDEX).unwrap();
        let lease = ledger.try_lease(&account).unwrap();
        assert!(lease.is_some());
        assert!(ledger.try_lease(&account).unwrap().is_none());
        drop(lease);
        assert!(ledger.try_lease(&account).unwrap().is_some());
    }
}
