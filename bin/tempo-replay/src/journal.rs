use crate::{config::Config, model::*};
use anyhow::{Context, Result, ensure};
use rocksdb::{DB, Direction, IteratorMode, Options, WriteBatch, WriteOptions};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

pub type SharedJournal = Arc<Mutex<Journal>>;
pub fn lock(j: &SharedJournal) -> Result<MutexGuard<'_, Journal>> {
    j.lock()
        .map_err(|_| anyhow::anyhow!("journal writer panicked"))
}
pub struct Journal {
    db: DB,
    pub state: RunState,
    path: PathBuf,
    max_bytes: u64,
    min_free: u64,
    _lock: Option<File>,
    secondary: Option<PathBuf>,
}
fn opts() -> Options {
    let mut o = Options::default();
    o.create_if_missing(true);
    o.set_max_open_files(128);
    o.set_write_buffer_size(32 * 1024 * 1024);
    o.set_max_write_buffer_number(2);
    o.set_compression_type(rocksdb::DBCompressionType::Lz4);
    o
}
impl Journal {
    /// A replay start names the first post-snapshot block, independently of an
    /// earlier capture-only journal boundary. Repeated starts never reset cursors.
    pub fn open_replay(c: &Config, from: Option<u64>, to: Option<u64>) -> Result<Self> {
        let (checkpoint, _) = c.replay()?;
        let first = checkpoint
            .source_height
            .checked_add(1)
            .context("fork height overflow")?;
        ensure!(
            from.is_none_or(|height| height == first),
            "--from-block must be {first}: the configured shadow snapshot contains source state through {}; starting elsewhere would skip or duplicate state transitions",
            checkpoint.source_height
        );
        ensure!(
            to.is_none_or(|height| height >= first),
            "--to-block must be at or after the first mirrored block {first}"
        );
        let journal = Self::open(c, None)?;
        ensure!(
            journal.state.first_height <= first,
            "journal starts after the required replay height {first}"
        );
        ensure!(
            journal
                .state
                .replay_boundary
                .is_none_or(|height| height == checkpoint.source_height),
            "journal belongs to a different shadow checkpoint"
        );
        Ok(journal)
    }
    pub fn open(c: &Config, from: Option<u64>) -> Result<Self> {
        std::fs::create_dir_all(&c.journal.path)?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(c.journal.path.join("RUN_LOCK"))?;
        file.try_lock()
            .context("another tempo-replay owns this journal")?;
        let db = DB::open(&opts(), c.journal.path.join("db"))?;
        let state = match db.get(b"meta/state")? {
            Some(bytes) => {
                let s: RunState = serde_json::from_slice(&bytes)?;
                ensure!(
                    s.schema_version == 2
                        && s.run_id == c.run.id
                        && s.chain_id == c.run.chain_id
                        && s.source_identity == c.source.rpc_http,
                    "journal run/source identity mismatch"
                );
                ensure!(
                    from.is_none_or(|h| h == s.first_height),
                    "cannot change journal start height"
                );
                s
            }
            None => RunState {
                schema_version: 2,
                run_id: c.run.id.clone(),
                chain_id: c.run.chain_id,
                source_identity: c.source.rpc_http.clone(),
                first_height: from.unwrap_or_else(|| {
                    c.checkpoint
                        .as_ref()
                        .map_or(0, |p| p.source_height.saturating_add(1))
                }),
                replay_boundary: None,
                binding: None,
                phase: Phase::CaptureOnly,
                incident: None,
                cursors: Cursors::default(),
                counts: Counts::default(),
                last_release_height: None,
                lag_ms: 0,
                slip_ms: 0,
                target_tip_seconds: 0,
                capture_error: None,
            },
        };
        let mut j = Self {
            db,
            state,
            path: c.journal.path.clone(),
            max_bytes: c.journal.max_bytes,
            min_free: c.journal.min_free_bytes,
            _lock: Some(file),
            secondary: None,
        };
        j.check_disk()?;
        j.save_state()?;
        Ok(j)
    }
    pub fn read(path: &Path) -> Result<Self> {
        static N: AtomicU64 = AtomicU64::new(0);
        let secondary = std::env::temp_dir().join(format!(
            "tempo-replay-read-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&secondary)?;
        let mut o = opts();
        o.create_if_missing(false);
        o.set_max_open_files(-1);
        let db = match DB::open_as_secondary(&o, path.join("db"), secondary.clone()) {
            Ok(db) => db,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&secondary);
                return Err(e.into());
            }
        };
        db.try_catch_up_with_primary()?;
        let state =
            serde_json::from_slice(&db.get(b"meta/state")?.context("journal metadata missing")?)?;
        Ok(Self {
            db,
            state,
            path: path.into(),
            max_bytes: u64::MAX,
            min_free: 0,
            _lock: None,
            secondary: Some(secondary),
        })
    }
    fn write(&self, batch: WriteBatch) -> Result<()> {
        ensure!(self.secondary.is_none(), "read-only journal");
        let mut o = WriteOptions::default();
        o.set_sync(true);
        self.db.write_opt(batch, &o)?;
        Ok(())
    }
    pub fn get<T: DeserializeOwned>(&self, key: impl AsRef<[u8]>) -> Result<Option<T>> {
        self.db
            .get(key)?
            .map(|b| serde_json::from_slice(&b).map_err(Into::into))
            .transpose()
    }
    pub fn put<T: Serialize>(&self, key: impl AsRef<[u8]>, value: &T) -> Result<()> {
        let mut b = WriteBatch::default();
        b.put(key, serde_json::to_vec(value)?);
        self.write(b)
    }
    pub fn save_state(&mut self) -> Result<()> {
        self.put(b"meta/state", &self.state)
    }
    pub fn check_disk(&self) -> Result<()> {
        ensure!(
            fs4::available_space(&self.path)? >= self.min_free,
            "journal disk low-watermark reached"
        );
        let mut size = 0u64;
        for e in std::fs::read_dir(self.path.join("db"))? {
            size = size.saturating_add(e?.metadata()?.len());
        }
        ensure!(size < self.max_bytes, "journal maximum disk size reached");
        Ok(())
    }
    pub fn stage(&self, b: &CapturedBlock) -> Result<()> {
        self.check_disk()?;
        ensure!(
            self.state
                .cursors
                .captured_through
                .as_ref()
                .is_none_or(|p| b.point.height > p.height),
            "cannot overwrite canonical block"
        );
        self.put(format!("b/{:020}", b.point.height), b)
    }
    pub fn block(&self, height: u64) -> Result<Option<CapturedBlock>> {
        self.get(format!("b/{height:020}"))
    }
    pub fn publish(&mut self, through: &Point, start: u64) -> Result<()> {
        // A durable verified-range marker permits bounded per-block publication after
        // the entire range has linked to both canonical history and a finality anchor.
        self.put("meta/verified_range", &(start, through))?;
        for h in start..=through.height {
            let mut block = self.block(h)?.context("verified staged block missing")?;
            block.committed_ms = now_ms();
            let mut batch = WriteBatch::default();
            batch.put(format!("b/{h:020}"), serde_json::to_vec(&block)?);
            for i in 0..block.transactions.len() {
                let o = Occurrence::new(&block, i);
                batch.put(o.key(), serde_json::to_vec(&o)?);
                batch.put(
                    format!("h/{}/{h:020}/{i:010}", o.tx.hash),
                    o.key().as_bytes(),
                );
                if self
                    .state
                    .replay_boundary
                    .is_none_or(|boundary| h > boundary)
                {
                    add_counts(&mut self.state.counts, &o, true);
                }
            }
            self.state.cursors.captured_through = Some(block.point);
            self.state.capture_error = None;
            batch.put(b"meta/state", serde_json::to_vec(&self.state)?);
            self.write(batch)?;
        }
        Ok(())
    }
    pub fn publish_target(&mut self, block: &CapturedBlock) -> Result<()> {
        let mut batch = WriteBatch::default();
        for (index, tx) in block
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| tx.class != Class::System)
        {
            batch.put(
                format!("inclusion/{}", tx.hash),
                serde_json::to_vec(&Inclusion {
                    point: block.point.clone(),
                    index,
                })?,
            );
            if let Some(lane) = tx.lane() {
                batch.put(
                    format!("consumed/{lane}/{}", tx.nonce),
                    serde_json::to_vec(&tx.hash)?,
                );
            }
        }
        batch.put(
            format!("target/canonical/{:020}", block.point.height),
            serde_json::to_vec(&block.point)?,
        );
        self.state.cursors.shadow_observed_through = Some(block.point.clone());
        self.state.target_tip_seconds = block.timestamp_ms / 1000;
        batch.put(b"meta/state", serde_json::to_vec(&self.state)?);
        self.write(batch)
    }
    pub fn occurrences(&self, height: u64) -> Result<Vec<Occurrence>> {
        self.scan(&format!("o/{height:020}/"))
    }
    pub fn scan<T: DeserializeOwned>(&self, prefix: &str) -> Result<Vec<T>> {
        let mut out = vec![];
        for entry in self
            .db
            .iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward))
        {
            let (key, value) = entry?;
            if !key.starts_with(prefix.as_bytes()) {
                break;
            }
            out.push(serde_json::from_slice(&value)?);
        }
        Ok(out)
    }
    pub fn inspect(&self, hash: &str) -> Result<Vec<Occurrence>> {
        let hash: alloy_primitives::B256 = hash.parse().context("invalid transaction hash")?;
        let prefix = format!("h/{hash}/");
        let mut out = vec![];
        for entry in self
            .db
            .iterator(IteratorMode::From(prefix.as_bytes(), Direction::Forward))
        {
            let (k, v) = entry?;
            if !k.starts_with(prefix.as_bytes()) {
                break;
            }
            if let Some(o) = self.get(v)? {
                out.push(o);
            }
        }
        Ok(out)
    }
    pub fn update(&mut self, o: &Occurrence) -> Result<()> {
        self.update_many(std::slice::from_ref(o))
    }
    pub fn update_many(&mut self, occurrences: &[Occurrence]) -> Result<()> {
        let batch = self.update_batch(occurrences)?;
        self.write(batch)
    }
    pub fn update_and_put<T: Serialize>(
        &mut self,
        occurrence: &Occurrence,
        key: &str,
        value: &T,
    ) -> Result<()> {
        let mut batch = self.update_batch(std::slice::from_ref(occurrence))?;
        batch.put(key, serde_json::to_vec(value)?);
        self.write(batch)
    }
    fn update_batch(&mut self, occurrences: &[Occurrence]) -> Result<WriteBatch> {
        let mut batch = WriteBatch::default();
        for o in occurrences {
            let old: Occurrence = self.get(o.key())?.context("occurrence missing")?;
            ensure!(
                old.source == o.source && old.tx.hash == o.tx.hash && old.tx.raw == o.tx.raw,
                "immutable occurrence changed"
            );
            add_counts(&mut self.state.counts, &old, false);
            add_counts(&mut self.state.counts, o, true);
            batch.put(o.key(), serde_json::to_vec(o)?);
        }
        batch.put(b"meta/state", serde_json::to_vec(&self.state)?);
        Ok(batch)
    }
    pub fn bind(&mut self, boundary: u64, binding: &str) -> Result<()> {
        if let Some(b) = &self.state.binding {
            ensure!(
                b == binding && self.state.replay_boundary == Some(boundary),
                "run/deployment binding changed; use a new journal"
            );
            return Ok(());
        }
        ensure!(
            self.state.first_height <= boundary.saturating_add(1),
            "journal begins after fork backlog"
        );
        self.state.binding = Some(binding.into());
        self.state.replay_boundary = Some(boundary);
        self.state.counts = Counts::default();
        if let Some(tip) = &self.state.cursors.captured_through {
            for h in boundary.saturating_add(1).max(self.state.first_height)..=tip.height {
                for o in self.occurrences(h)? {
                    add_counts(&mut self.state.counts, &o, true);
                }
            }
        }
        self.state.cursors.dispatch_accounted_through = Some(boundary);
        self.state.cursors.accounted_through = Some(boundary);
        self.state.cursors.included_through = Some(boundary);
        self.save_state()
    }
    pub fn refresh_cursors(&mut self) -> Result<()> {
        let Some(end) = self
            .state
            .cursors
            .captured_through
            .as_ref()
            .map(|p| p.height)
        else {
            return Ok(());
        };
        let Some(boundary) = self.state.replay_boundary else {
            return Ok(());
        };
        let mut cursors = [
            self.state
                .cursors
                .dispatch_accounted_through
                .unwrap_or(boundary),
            self.state.cursors.accounted_through.unwrap_or(boundary),
            self.state.cursors.included_through.unwrap_or(boundary),
        ];
        for (kind, cursor) in cursors.iter_mut().enumerate() {
            while *cursor < end {
                let entries = self.occurrences(*cursor + 1)?;
                if !entries.iter().all(|o| match kind {
                    0 => o.dispatch_accounted(),
                    1 => o.state.terminal(),
                    _ => o.tx.class == Class::System || o.state == State::Finalized,
                }) {
                    break;
                }
                *cursor += 1;
            }
        }
        if self.state.cursors.dispatch_accounted_through == Some(cursors[0])
            && self.state.cursors.accounted_through == Some(cursors[1])
            && self.state.cursors.included_through == Some(cursors[2])
        {
            return Ok(());
        }
        self.state.cursors.dispatch_accounted_through = Some(cursors[0]);
        self.state.cursors.accounted_through = Some(cursors[1]);
        self.state.cursors.included_through = Some(cursors[2]);
        self.save_state()
    }
    pub fn incident(&mut self, detail: &str) -> Result<()> {
        self.state.phase = Phase::PausedIncident;
        self.state.incident = Some(detail.into());
        self.save_state()
    }
    pub fn flush(&self) -> Result<()> {
        self.db.flush_wal(true)?;
        self.db.flush()?;
        Ok(())
    }
}
impl Drop for Journal {
    fn drop(&mut self) {
        if let Some(path) = &self.secondary {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
fn add_counts(c: &mut Counts, o: &Occurrence, add: bool) {
    fn change(n: &mut u64, by: u64, add: bool) {
        *n = if add {
            n.saturating_add(by)
        } else {
            n.saturating_sub(by)
        };
    }
    let user = o.tx.class != Class::System;
    change(&mut c.user_occurrences, u64::from(user), add);
    change(&mut c.system_occurrences, u64::from(!user), add);
    change(
        &mut c.subblock_occurrences,
        u64::from(o.tx.class == Class::Subblock),
        add,
    );
    change(&mut c.offered, u64::from(user && o.attempts > 0), add);
    change(
        &mut c.finalized,
        u64::from(user && o.state == State::Finalized),
        add,
    );
    change(
        &mut c.gaps,
        u64::from(user && matches!(o.state, State::Gap { .. })),
        add,
    );
    change(&mut c.attempts, u64::from(o.attempts), add);
    change(
        &mut c.receipt_mismatches,
        u64::from(o.receipt_mismatch == Some(true)),
        add,
    );
    change(
        &mut c.reserved_count,
        u64::from(o.state.holds_credit()),
        add,
    );
    change(
        &mut c.reserved_bytes,
        if o.state.holds_credit() {
            o.tx.raw_len()
        } else {
            0
        },
        add,
    );
}
