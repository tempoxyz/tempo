use crate::{input::Operation, model::Model};
use eyre::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    ops::RangeInclusive,
    path::{Path, PathBuf},
};

/// Durable operations for one round, shared by restart and persistence verification replay.
pub(crate) struct RoundJournal {
    blocks: BTreeMap<u64, JournalBlock>,
    file: File,
    directory: PathBuf,
}

impl RoundJournal {
    /// Load complete records, accepting an interrupted final append but not conflicting blocks.
    pub(crate) fn open(directory: &Path, total_blocks: u64) -> Result<Self> {
        let path = directory.join("blocks.jsonl");
        let mut blocks = BTreeMap::<u64, JournalBlock>::new();
        if path.exists() {
            for line in
                fs::read(&path)?.split(|byte| *byte == b'\n').filter(|line| !line.is_empty())
            {
                let block: JournalBlock = match serde_json::from_slice(line) {
                    Ok(block) => block,
                    // Each append starts on a new line, isolating a SIGKILL-truncated record.
                    Err(error) if error.is_eof() => continue,
                    Err(error) => return Err(error.into()),
                };
                ensure!((1..=total_blocks).contains(&block.number), "journal block out of range");
                if let Some(previous) = blocks.get(&block.number) {
                    ensure!(previous == &block, "conflicting journal block {}", block.number);
                } else {
                    blocks.insert(block.number, block);
                }
            }
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { blocks, file, directory: directory.to_path_buf() })
    }

    /// A block recorded before a restart, which must be produced again exactly.
    pub(crate) fn recorded(&self, number: u64) -> Option<Vec<Operation>> {
        self.blocks.get(&number).map(|block| block.operations.clone())
    }

    /// Durably append a block's operations before the caller executes them.
    pub(crate) fn record(&mut self, number: u64, operations: &[Operation]) -> Result<()> {
        ensure!(!self.blocks.contains_key(&number), "journal block {number} already recorded");
        let block = JournalBlock { number, operations: operations.to_vec() };
        let record = serde_json::to_vec(&block)?;
        self.file.write_all(b"\n")?;
        self.file.write_all(&record)?;
        self.file.write_all(b"\n")?;
        self.file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        self.blocks.insert(number, block);
        Ok(())
    }

    /// Apply only model updates for a contiguous inclusive range; missing records are errors.
    pub(crate) fn replay(&self, numbers: RangeInclusive<u64>, state: &mut Model) -> Result<()> {
        for number in numbers {
            let block = self
                .blocks
                .get(&number)
                .ok_or_else(|| eyre::eyre!("missing journal block {number}"))?;
            for operation in &block.operations {
                if let Operation::UpdateBatch { updates } = operation {
                    for update in updates {
                        update.apply_to_model(state);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JournalBlock {
    number: u64,
    operations: Vec<Operation>,
}
