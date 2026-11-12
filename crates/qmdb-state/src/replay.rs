//! Replays a [`crate::record`]ing against a copy of the store it started from.
//!
//! The calls run on the store as they did on the node: each recorded thread on a thread of its
//! own, every call at its recorded time after the replay starts ([`Mode::Timed`]), or all of them in
//! order on one thread ([`Mode::Serial`]). A call that needs a block the replay has not built yet,
//! such as finalizing it or building its child, waits for it, so a slower replay still runs every
//! call. Every build's root is checked against the recorded one.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Condvar, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;

use crate::{
    QmdbBatch, StageId, Store,
    record::{Call, Event, Header},
};

/// How a replay schedules the recorded calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Every recorded thread on its own thread, each call at its recorded time.
    Timed,
    /// Every call in the order it started, on one thread, without waiting between them.
    Serial,
    /// Like [`Self::Serial`] without the stages and prefetches, so builds read what they need
    /// themselves.
    FinishOnly,
}

/// How to replay.
#[derive(Clone, Debug)]
pub struct Options {
    /// How the calls are scheduled.
    pub mode: Mode,
    /// Whether to replay the recorded state reads, the execution's reads of the applied state.
    pub reads: bool,
    /// [`Mode::Timed`] runs each call at its recorded time divided by this.
    pub speed: f64,
    /// Longest a call waits for the block or stage it needs before running without it.
    pub wait_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Timed,
            reads: true,
            speed: 1.0,
            wait_timeout: Duration::from_secs(10),
        }
    }
}

/// Kind of a replayed call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// [`Store::build_unregistered`], the payload builder's finish.
    BuildUnregistered,
    /// [`Store::build_staged`], the engine's validation of a block.
    Build,
    /// [`Store::finalize`], persisting blocks.
    Finalize,
    /// [`Store::register`].
    Register,
    /// [`Store::stage`].
    Stage,
    /// [`Store::prefetch`].
    Prefetch,
    /// [`Store::open_stage`].
    OpenStage,
    /// [`Store::get_accounts`] and [`Store::get_slots`].
    Read,
    /// [`Store::set_base`] and [`Store::rewind_to`].
    Other,
}

impl Kind {
    /// Short name of the kind.
    pub const fn name(self) -> &'static str {
        match self {
            Self::BuildUnregistered => "build_unregistered",
            Self::Build => "build",
            Self::Finalize => "finalize",
            Self::Register => "register",
            Self::Stage => "stage",
            Self::Prefetch => "prefetch",
            Self::OpenStage => "open_stage",
            Self::Read => "read",
            Self::Other => "other",
        }
    }

    /// Kind of a recorded call.
    pub const fn of(call: &Call) -> Self {
        match call {
            Call::BuildUnregistered { .. } => Self::BuildUnregistered,
            Call::Build { .. } => Self::Build,
            Call::Finalize { .. } => Self::Finalize,
            Call::Register { .. } => Self::Register,
            Call::Stage { .. } => Self::Stage,
            Call::Prefetch { .. } => Self::Prefetch,
            Call::OpenStage { .. } => Self::OpenStage,
            Call::ReadAccounts { .. } | Call::ReadSlots { .. } => Self::Read,
            Call::SetBase { .. } | Call::RewindTo { .. } => Self::Other,
        }
    }
}

/// One replayed call and how long it took, recorded and replayed.
#[derive(Clone, Debug)]
pub struct Timing {
    /// Kind of the call.
    pub kind: Kind,
    /// Block of a build, `None` for other calls.
    pub number: Option<u64>,
    /// Writes of a build, keys of a stage, prefetch or read.
    pub size: usize,
    /// Recorded duration.
    pub recorded: Duration,
    /// Replayed duration.
    pub replayed: Duration,
}

/// What a replay did.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Every replayed call, in the order they returned.
    pub timings: Vec<Timing>,
    /// Builds whose root differed from the recorded one: block, recorded and replayed root.
    pub mismatches: Vec<(u64, B256, B256)>,
    /// Calls that failed or waited past [`Options::wait_timeout`], where the recording did not.
    pub problems: Vec<String>,
    /// Wall-clock time of the replay.
    pub wall: Duration,
}

/// Returns why `store` is not the store `header` recorded from, if it is not.
pub fn check_start(store: &Store, header: &Header) -> Result<(), String> {
    let status = store
        .status()
        .map_err(|err| format!("reading the store failed: {err}"))?;
    if status.root != header.root || status.applied != header.applied {
        return Err(format!(
            "the store is at block {:?} with root {}, the recording starts at block {:?} with root {}",
            status.applied, status.root, header.applied, header.root
        ));
    }
    if let Some(base) = header.base
        && status.base != Some(base)
    {
        store
            .set_base(base)
            .map_err(|err| format!("binding the recorded base {base} failed: {err}"))?;
    }
    Ok(())
}

/// Replays `events` on `store`, which [`check_start`] accepted for their recording's `header`.
pub fn replay(store: &Store, header: &Header, events: Vec<Event>, options: &Options) -> Outcome {
    let mut events: Vec<Event> = events
        .into_iter()
        .filter(|event| match Kind::of(&event.call) {
            Kind::Read => options.reads && options.mode != Mode::FinishOnly,
            Kind::Stage | Kind::Prefetch | Kind::OpenStage => options.mode != Mode::FinishOnly,
            _ => true,
        })
        .collect();
    events.sort_by_key(|event| event.start_ns);
    let shared = Shared {
        state: Mutex::new(State {
            known: header.base.into_iter().collect(),
            ..Default::default()
        }),
        changed: Condvar::new(),
        outcome: Mutex::new(Outcome::default()),
        wait_timeout: options.wait_timeout,
    };
    let started = Instant::now();
    match options.mode {
        Mode::Timed => {
            let mut lanes = BTreeMap::<u32, Vec<Event>>::new();
            for event in events {
                lanes.entry(event.lane).or_default().push(event);
            }
            std::thread::scope(|scope| {
                for (lane, events) in lanes {
                    let shared = &shared;
                    std::thread::Builder::new()
                        .name(format!("replay-{lane}"))
                        .spawn_scoped(scope, move || {
                            for event in events {
                                let at = Duration::from_secs_f64(
                                    event.start_ns as f64 / 1e9 / options.speed,
                                );
                                if let Some(wait) = at.checked_sub(started.elapsed()) {
                                    std::thread::sleep(wait);
                                }
                                shared.run(store, event);
                            }
                        })
                        .expect("spawning a thread only fails when the OS is out of resources");
                }
            });
        }
        Mode::Serial | Mode::FinishOnly => {
            for event in events {
                shared.run(store, event);
            }
        }
    }
    let mut outcome = shared.outcome.into_inner().expect("never poisoned");
    outcome.wall = started.elapsed();
    outcome
}

/// Percentiles of a set of durations, in milliseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Percentiles {
    /// Number of durations.
    pub count: usize,
    /// Mean.
    pub mean: f64,
    /// Median.
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
    /// 99th percentile.
    pub p99: f64,
    /// Maximum.
    pub max: f64,
}

impl Percentiles {
    /// Percentiles of `durations`, nearest-rank.
    pub fn of(durations: impl IntoIterator<Item = Duration>) -> Self {
        let mut ms: Vec<f64> = durations
            .into_iter()
            .map(|duration| duration.as_secs_f64() * 1e3)
            .collect();
        if ms.is_empty() {
            return Self::default();
        }
        ms.sort_by(f64::total_cmp);
        let rank = |p: f64| ms[((p * ms.len() as f64).ceil() as usize).clamp(1, ms.len()) - 1];
        Self {
            count: ms.len(),
            mean: ms.iter().sum::<f64>() / ms.len() as f64,
            p50: rank(0.5),
            p90: rank(0.9),
            p99: rank(0.99),
            max: ms[ms.len() - 1],
        }
    }
}

#[derive(Default)]
struct State {
    /// Blocks that later calls can name: the base, built and registered blocks.
    known: HashSet<B256>,
    /// Unregistered batches by root, until registered.
    batches: HashMap<B256, QmdbBatch>,
    /// Replayed stages by recorded stage ID.
    stages: HashMap<u64, StageId>,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    outcome: Mutex<Outcome>,
    wait_timeout: Duration,
}

impl Shared {
    /// Waits until `ready` returns `Some`, or the timeout passes.
    fn wait<T>(&self, mut ready: impl FnMut(&mut State) -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + self.wait_timeout;
        let mut state = self.state.lock().expect("never poisoned");
        loop {
            if let Some(value) = ready(&mut state) {
                return Some(value);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            state = self
                .changed
                .wait_timeout(state, left)
                .expect("never poisoned")
                .0;
        }
    }

    fn update(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.state.lock().expect("never poisoned"));
        self.changed.notify_all();
    }

    fn problem(&self, problem: String) {
        self.outcome
            .lock()
            .expect("never poisoned")
            .problems
            .push(problem);
    }

    fn wait_known(&self, hash: B256, what: &str) {
        if self
            .wait(|state| state.known.contains(&hash).then_some(()))
            .is_none()
        {
            self.problem(format!("{what}: block {hash} never became known"));
        }
    }

    fn stage(&self, stage: u64) -> Option<StageId> {
        let found = self.wait(|state| state.stages.get(&stage).copied());
        if found.is_none() {
            self.problem(format!("stage {stage} was never opened"));
        }
        found
    }

    fn check_root(&self, number: u64, recorded: Option<B256>, replayed: Result<B256, String>) {
        match (recorded, replayed) {
            (Some(recorded), Ok(replayed)) if recorded != replayed => {
                self.outcome
                    .lock()
                    .expect("never poisoned")
                    .mismatches
                    .push((number, recorded, replayed));
            }
            (Some(_), Err(err)) => self.problem(format!("building block {number} failed: {err}")),
            _ => {}
        }
    }

    /// Runs one recorded call and records its timing.
    fn run(&self, store: &Store, event: Event) {
        let kind = Kind::of(&event.call);
        let recorded = Duration::from_nanos(event.end_ns.saturating_sub(event.start_ns));
        let (number, size) = match &event.call {
            Call::Build { block, writes, .. } => (Some(block.number), writes.len()),
            Call::BuildUnregistered { number, writes, .. } => (Some(*number), writes.len()),
            Call::Stage {
                accounts, slots, ..
            }
            | Call::Prefetch { accounts, slots } => (None, accounts.len() + slots.len()),
            Call::ReadAccounts { keys } | Call::ReadSlots { keys } => (None, keys.len()),
            _ => (None, 0),
        };
        // Waits for what the call needs before starting its clock.
        let mut started = Instant::now();
        match event.call {
            Call::SetBase { hash } => {
                if let Err(err) = store.set_base(hash) {
                    self.problem(format!("set_base {hash} failed: {err}"));
                }
                self.update(|state| {
                    state.known.insert(hash);
                });
            }
            Call::RewindTo { number } => {
                if let Err(err) = store.rewind_to(number) {
                    self.problem(format!("rewind_to {number} failed: {err}"));
                }
            }
            Call::OpenStage {
                stage,
                parent_hash,
                builder,
            } => {
                self.wait_known(parent_hash, "open_stage");
                started = Instant::now();
                match store.open_stage(parent_hash, builder) {
                    Ok(id) => self.update(|state| {
                        state.stages.insert(stage, id);
                    }),
                    Err(err) => self.problem(format!("open_stage failed: {err}")),
                }
            }
            Call::Stage {
                stage,
                accounts,
                slots,
            } => {
                let Some(stage) = self.stage(stage) else {
                    return;
                };
                started = Instant::now();
                if let Err(err) = store.stage(stage, accounts, slots) {
                    self.problem(format!("stage failed: {err}"));
                }
            }
            Call::Prefetch { accounts, slots } => {
                if let Err(err) = store.prefetch(accounts, slots) {
                    self.problem(format!("prefetch failed: {err}"));
                }
            }
            Call::Build {
                block,
                writes,
                stage,
                root,
            } => {
                self.wait_known(block.parent_hash, "build");
                let stage = stage.and_then(|stage| {
                    self.state
                        .lock()
                        .expect("never poisoned")
                        .stages
                        .get(&stage)
                        .copied()
                });
                started = Instant::now();
                let result = store.build_staged(block, writes, stage);
                let elapsed = started.elapsed();
                if result.is_ok() {
                    self.update(|state| {
                        state.known.insert(block.hash);
                    });
                }
                self.check_root(
                    block.number,
                    root,
                    result
                        .map(|batch| batch.root())
                        .map_err(|err| err.to_string()),
                );
                return self.time(kind, number, size, recorded, elapsed);
            }
            Call::BuildUnregistered {
                number: block,
                parent_hash,
                writes,
                root,
            } => {
                self.wait_known(parent_hash, "build_unregistered");
                started = Instant::now();
                let result = store.build_unregistered(block, parent_hash, writes);
                let elapsed = started.elapsed();
                let replayed = result
                    .as_ref()
                    .map(QmdbBatch::root)
                    .map_err(|err| err.to_string());
                if let Ok(batch) = result {
                    self.update(|state| {
                        // Registered under the recorded root, which a mismatch is reported for.
                        state
                            .batches
                            .insert(root.unwrap_or_else(|| batch.root()), batch);
                    });
                }
                self.check_root(block, root, replayed);
                return self.time(kind, number, size, recorded, elapsed);
            }
            Call::Register { hash, root } => {
                let Some(batch) = self.wait(|state| state.batches.get(&root).cloned()) else {
                    self.problem(format!("register {hash}: no batch with root {root}"));
                    return;
                };
                started = Instant::now();
                match store.register(hash, batch) {
                    Ok(()) => self.update(|state| {
                        state.known.insert(hash);
                    }),
                    Err(err) => self.problem(format!("register {hash} failed: {err}")),
                }
            }
            Call::Finalize { hash } => {
                self.wait_known(hash, "finalize");
                started = Instant::now();
                if let Err(err) = store.finalize(hash) {
                    self.problem(format!("finalize {hash} failed: {err}"));
                }
            }
            Call::ReadAccounts { keys } => {
                if let Err(err) = store.get_accounts(keys) {
                    self.problem(format!("reading accounts failed: {err}"));
                }
            }
            Call::ReadSlots { keys } => {
                if let Err(err) = store.get_slots(keys) {
                    self.problem(format!("reading slots failed: {err}"));
                }
            }
        }
        self.time(kind, number, size, recorded, started.elapsed());
    }

    fn time(
        &self,
        kind: Kind,
        number: Option<u64>,
        size: usize,
        recorded: Duration,
        replayed: Duration,
    ) {
        self.outcome
            .lock()
            .expect("never poisoned")
            .timings
            .push(Timing {
                kind,
                number,
                size,
                recorded,
                replayed,
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BlockRef, Config,
        layout::{self, Key, Write, Writes},
        record::{self, RecordOptions},
    };
    use alloy_primitives::U256;
    use std::num::NonZeroUsize;

    fn config(directory: &std::path::Path) -> Config {
        Config {
            directory: directory.to_path_buf(),
            threads: NonZeroUsize::new(2).unwrap(),
            page_cache_pages: NonZeroUsize::new(64).unwrap(),
            max_pending: NonZeroUsize::new(16).unwrap(),
        }
    }

    fn slots(writes: &[(u8, Option<u64>)]) -> Writes {
        Writes {
            accounts: Vec::new(),
            slots: writes
                .iter()
                .map(|&(key, value)| Write {
                    key: Key::new([key; 32]),
                    value: value.map(|value| layout::slot_value(U256::from(value))),
                })
                .collect(),
        }
    }

    /// Records a node-like run, then replays it in every mode on the recorded snapshot.
    #[test]
    fn replays_a_recording_with_matching_roots() {
        let dir = tempfile::tempdir().unwrap();
        let (live, snapshot, path) = (
            dir.path().join("live"),
            dir.path().join("snapshot"),
            dir.path().join("calls.rec"),
        );
        {
            let store = Store::open(config(&live)).unwrap();
            store
                .import_chunk(
                    slots(&[(1, Some(1)), (3, Some(3)), (5, Some(5))]),
                    Some((0, B256::ZERO)),
                )
                .unwrap();
        }
        let record = RecordOptions {
            path: path.clone(),
            reads: true,
            snapshot: Some(snapshot.clone()),
        };
        let mut roots = Vec::new();
        {
            let store = Store::open_recording(config(&live), Some(record)).unwrap();
            let mut parent = B256::ZERO;
            for number in 1..=4u64 {
                let key = u8::try_from(number).unwrap();
                let stage = store.open_stage(parent, true).unwrap();
                store
                    .stage(
                        stage,
                        Vec::new(),
                        vec![Key::new([key; 32]), Key::new([key + 1; 32])],
                    )
                    .unwrap();
                store.get_slots(vec![Key::new([1; 32])]).unwrap();
                let writes = slots(&[
                    (key, None),
                    (key + 1, Some(u64::from(key) * 10)),
                    (9, Some(number)),
                ]);
                let batch = store.build_unregistered(number, parent, writes).unwrap();
                let hash = B256::repeat_byte(key);
                roots.push(batch.root());
                store.register(hash, batch).unwrap();
                // Validation rebuilds the block under its hash, as the engine does.
                store
                    .build(
                        BlockRef {
                            number,
                            hash,
                            parent_hash: parent,
                        },
                        slots(&[
                            (key, None),
                            (key + 1, Some(u64::from(key) * 10)),
                            (9, Some(number)),
                        ]),
                    )
                    .unwrap();
                if number % 2 == 0 {
                    store.finalize(hash).unwrap();
                }
                parent = hash;
            }
        }
        let (header, events) = record::read(&path).unwrap();
        assert_eq!(header.applied, Some(0));
        assert_eq!(header.base, Some(B256::ZERO));
        assert!(
            events
                .iter()
                .any(|event| matches!(event.call, Call::ReadSlots { .. }))
        );
        let recorded_roots: Vec<B256> = events
            .iter()
            .filter_map(|event| match &event.call {
                Call::BuildUnregistered { root, .. } => *root,
                _ => None,
            })
            .collect();
        assert_eq!(recorded_roots, roots);

        for mode in [Mode::Timed, Mode::Serial, Mode::FinishOnly] {
            let work = dir.path().join(format!("work-{mode:?}"));
            record::copy_dir(&snapshot, &work).unwrap();
            let store = Store::open_recording(config(&work), None).unwrap();
            check_start(&store, &header).unwrap();
            let outcome = replay(
                &store,
                &header,
                events.clone(),
                &Options {
                    mode,
                    ..Default::default()
                },
            );
            assert!(
                outcome.problems.is_empty(),
                "{mode:?}: {:?}",
                outcome.problems
            );
            assert!(
                outcome.mismatches.is_empty(),
                "{mode:?}: {:?}",
                outcome.mismatches
            );
            let finishes = outcome
                .timings
                .iter()
                .filter(|timing| timing.kind == Kind::BuildUnregistered)
                .count();
            assert_eq!(finishes, 4);
            assert_eq!(store.status().unwrap().applied, Some(4));
        }
    }
}
