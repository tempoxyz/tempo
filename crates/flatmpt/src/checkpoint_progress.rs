//! Planned, quiescent restart points for large canonical checkpoint imports.
use crate::FlatMpt;
use alloy_primitives::B256;
use std::{fs, io::Write, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointProgress {
    pub checkpoint_root: B256,
    pub flat_root: B256,
    pub last_account: B256,
    pub accounts: u64,
    pub slots: u64,
}

pub fn read(path: &str) -> anyhow::Result<Option<CheckpointProgress>> {
    let bytes = match fs::read(format!("{path}.progress")) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        value["version"].as_u64() == Some(1),
        "unknown checkpoint progress version"
    );
    let hash = |key: &str| -> anyhow::Result<B256> {
        Ok(value[key]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing {key}"))?
            .parse()?)
    };
    let count = |key: &str| -> anyhow::Result<u64> {
        value[key]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("missing {key}"))
    };
    Ok(Some(CheckpointProgress {
        checkpoint_root: hash("checkpoint_root")?,
        flat_root: hash("flat_root")?,
        last_account: hash("last_account")?,
        accounts: count("accounts")?,
        slots: count("slots")?,
    }))
}

pub fn open(
    path: &str,
    expected_root: B256,
    progress: &CheckpointProgress,
) -> anyhow::Result<FlatMpt> {
    anyhow::ensure!(
        progress.checkpoint_root == expected_root,
        "import progress belongs to a different canonical checkpoint"
    );
    let db = FlatMpt::open(path).map_err(|e| anyhow::anyhow!("open import checkpoint: {e:#}"))?;
    anyhow::ensure!(
        db.root() == progress.flat_root.0,
        "import progress root does not match persisted flat state"
    );
    Ok(db)
}

/// Persist both state and cursor, then return to a caller that exits immediately.
/// This is a planned restart point, not a promise of recovery after arbitrary
/// later in-place writes. Never continue mutating this instance after saving.
pub fn save(path: &str, db: &mut FlatMpt, progress: &CheckpointProgress) -> anyhow::Result<()> {
    anyhow::ensure!(db.root() == progress.flat_root.0, "incorrect progress root");
    db.persist()
        .map_err(|e| anyhow::anyhow!("persist import checkpoint: {e:#}"))?;
    let temporary = format!("{path}.progress.tmp");
    let mut file = fs::File::create(&temporary)?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({
            "version": 1,
            "checkpoint_root": progress.checkpoint_root.to_string(),
            "flat_root": progress.flat_root.to_string(),
            "last_account": progress.last_account.to_string(),
            "accounts": progress.accounts,
            "slots": progress.slots,
        }),
    )?;
    file.flush()?;
    file.sync_all()?;
    fs::rename(&temporary, format!("{path}.progress"))?;
    fs::File::open(Path::new(path).parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AccountSeed;
    use alloy_primitives::U256;

    fn seed() -> AccountSeed {
        AccountSeed {
            nonce: 1,
            balance: U256::from(7),
            code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
            slots: vec![],
        }
    }

    #[test]
    fn saved_segment_reopens_and_matches_uninterrupted_build() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.flat");
        let path = path.to_str().unwrap();
        let first = B256::repeat_byte(1);
        let second = B256::repeat_byte(2);
        let expected = B256::repeat_byte(9);
        let mut db = FlatMpt::create_ram_build(path, Default::default()).unwrap();
        db.insert_batch_accounts(vec![(first.0, seed())]).unwrap();
        let progress = CheckpointProgress {
            checkpoint_root: expected,
            flat_root: B256::from(db.root()),
            last_account: first,
            accounts: 1,
            slots: 0,
        };
        save(path, &mut db, &progress).unwrap();
        drop(db);
        assert_eq!(read(path).unwrap(), Some(progress.clone()));
        assert!(open(path, B256::ZERO, &progress).is_err());
        let mut corrupted = progress.clone();
        corrupted.flat_root = B256::ZERO;
        assert!(open(path, expected, &corrupted).is_err());
        let mut resumed = open(path, expected, &progress).unwrap();
        resumed
            .insert_batch_accounts(vec![(second.0, seed())])
            .unwrap();
        let mut uninterrupted =
            FlatMpt::create_ram_build(dir.path().join("full.flat"), Default::default()).unwrap();
        uninterrupted
            .insert_batch_accounts(vec![(first.0, seed()), (second.0, seed())])
            .unwrap();
        assert_eq!(resumed.root(), uninterrupted.root());
    }

    #[test]
    fn missing_progress_is_fresh_but_invalid_progress_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.flat");
        let path = path.to_str().unwrap();
        assert!(read(path).unwrap().is_none());
        fs::write(format!("{path}.progress"), b"{}").unwrap();
        assert!(read(path).is_err());
    }
}
