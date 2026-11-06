//! Append-only workload ledger shared by every test command in the workload container.
//!
//! Commands can be killed at any point, so each record is one JSON line appended under an
//! exclusive file lock and only after the effect it describes is confirmed on chain. A torn last
//! line from a killed writer is skipped on read.

use alloy::{
    primitives::{Address, B256, keccak256},
    signers::local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English},
};
use eyre::WrapErr as _;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

/// Mnemonic of the public dev accounts funded in the L1 genesis. Never holds real funds.
const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

/// First index of workload-created accounts, above every funder index.
const FIRST_WORKLOAD_INDEX: u32 = 1_000;

/// One confirmed workload fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(super) enum Record {
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

    /// Returns every complete record in append order.
    pub(super) fn records(&self) -> eyre::Result<Vec<Record>> {
        let file = self.locked_file()?;
        read_records(&file)
    }

    /// Appends `record`.
    pub(super) fn append(&self, record: &Record) -> eyre::Result<()> {
        let mut file = self.locked_file()?;
        let mut line = serde_json::to_vec(record)?;
        line.push(b'\n');
        file.write_all(&line)
            .wrap_err("failed appending ledger record")
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
        let mut line = serde_json::to_vec(&Record::Account { index })?;
        line.push(b'\n');
        file.write_all(&line)
            .wrap_err("failed appending account record")?;
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
    /// it at a time. Returns `None` when another command holds it. The lease ends when the
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
            Ok(()) => Ok(Some(Lease { _file: file })),
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
        // A writer killed mid-append leaves a line without its newline. End it, so the next
        // record starts its own line instead of merging into the torn one.
        if file.metadata()?.len() > 0 {
            let mut last = [0];
            file.seek(SeekFrom::End(-1))?;
            file.read_exact(&mut last)?;
            if last != *b"\n" {
                file.write_all(b"\n")?;
            }
            file.rewind()?;
        }
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

fn read_records(file: &File) -> eyre::Result<Vec<Record>> {
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line.wrap_err("failed reading ledger")?;
        // A writer killed mid-append leaves a torn last line; that record was never confirmed.
        if let Ok(record) = serde_json::from_str(&line) {
            records.push(record);
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_get_consecutive_indices_and_torn_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::open(dir.path()).unwrap();
        assert_eq!(ledger.new_account().unwrap().index, FIRST_WORKLOAD_INDEX);
        std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("ledger.jsonl"))
            .unwrap()
            .write_all(b"{\"kind\":\"acc")
            .unwrap();
        assert_eq!(
            ledger.new_account().unwrap().index,
            FIRST_WORKLOAD_INDEX + 1
        );
        assert_eq!(ledger.accounts().unwrap().len(), 2);
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
