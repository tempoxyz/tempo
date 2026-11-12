//! Opt-in recording of a [`Store`](crate::Store)'s calls, for replaying them offline.
//!
//! A store opened with [`RecordOptions`] (or, from [`Store::open`](crate::Store::open), with the
//! [`RECORD_ENV`] environment variable set) writes every call that changes or reads its state to a
//! file: what was asked, by which thread, when it started and returned, and the root a build
//! returned. [`crate::replay`] runs the same calls against a copy of the store as it was when
//! recording began, so a change to the finish path can be measured without a node.
//!
//! Recording costs a copy of each block's writes on the caller's thread; encoding and writing run
//! on a thread of their own.

use std::{
    cell::Cell,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write as _},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Instant,
};

use alloy_primitives::B256;
use commonware_utils::sequence::FixedBytes;
use tracing::{error, info};

use crate::{
    BlockRef,
    layout::{ACCOUNT_LEN, Key, SLOT_LEN, Write, Writes},
};

/// File to record the store's calls to, read by [`RecordOptions::from_env`].
pub const RECORD_ENV: &str = "TEMPO_QMDB_RECORD";
/// Set to `1` to also record state reads, the execution's reads of the applied state.
pub const RECORD_READS_ENV: &str = "TEMPO_QMDB_RECORD_READS";
/// Directory to copy the store into before opening it, the snapshot a replay starts from.
pub const RECORD_SNAPSHOT_ENV: &str = "TEMPO_QMDB_RECORD_SNAPSHOT";

const MAGIC: &[u8; 8] = b"QMDBREC1";

/// What to record and where.
#[derive(Clone, Debug)]
pub struct RecordOptions {
    /// File the calls are written to, replaced if it exists.
    pub path: PathBuf,
    /// Whether to record state reads too.
    pub reads: bool,
    /// Directory the store is copied into before it opens, replaced if it exists.
    pub snapshot: Option<PathBuf>,
}

impl RecordOptions {
    /// Returns the options [`RECORD_ENV`], [`RECORD_READS_ENV`] and [`RECORD_SNAPSHOT_ENV`] set,
    /// or `None` when [`RECORD_ENV`] is unset.
    pub fn from_env() -> Option<Self> {
        let path = std::env::var_os(RECORD_ENV).filter(|path| !path.is_empty())?;
        Some(Self {
            path: path.into(),
            reads: std::env::var(RECORD_READS_ENV).is_ok_and(|value| value == "1"),
            snapshot: std::env::var_os(RECORD_SNAPSHOT_ENV)
                .filter(|path| !path.is_empty())
                .map(Into::into),
        })
    }
}

/// The store a recording starts from, and how it was configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Last applied block when recording began.
    pub applied: Option<u64>,
    /// Hash bound to the applied block when recording began.
    pub base: Option<B256>,
    /// Root of the applied state when recording began.
    pub root: B256,
    /// [`Config::threads`](crate::Config::threads) of the recorded store.
    pub threads: u64,
    /// [`Config::page_cache_pages`](crate::Config::page_cache_pages) of the recorded store.
    pub page_cache_pages: u64,
    /// [`Config::max_pending`](crate::Config::max_pending) of the recorded store.
    pub max_pending: u64,
}

/// One recorded call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    /// The calling thread, numbered in the order threads first called a recording store.
    pub lane: u32,
    /// When the call started, in nanoseconds since the store opened.
    pub start_ns: u64,
    /// When the call returned, in nanoseconds since the store opened.
    pub end_ns: u64,
    /// The call.
    pub call: Call,
}

/// A recorded [`Store`](crate::Store) call. Stage IDs are the recorded store's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// [`Store::set_base`](crate::Store::set_base).
    SetBase {
        /// Hash bound.
        hash: B256,
    },
    /// [`Store::rewind_to`](crate::Store::rewind_to).
    RewindTo {
        /// Block rewound to.
        number: u64,
    },
    /// [`Store::open_stage`](crate::Store::open_stage).
    OpenStage {
        /// The stage opened.
        stage: u64,
        /// Parent block of the stage.
        parent_hash: B256,
        /// Whether it is the payload builder's stage.
        builder: bool,
    },
    /// [`Store::stage`](crate::Store::stage).
    Stage {
        /// The stage read into.
        stage: u64,
        /// Account keys read.
        accounts: Vec<Key>,
        /// Slot keys read.
        slots: Vec<Key>,
    },
    /// [`Store::prefetch`](crate::Store::prefetch).
    Prefetch {
        /// Account keys read.
        accounts: Vec<Key>,
        /// Slot keys read.
        slots: Vec<Key>,
    },
    /// [`Store::build_staged`](crate::Store::build_staged), or a detached build.
    Build {
        /// The block built.
        block: BlockRef,
        /// Its writes.
        writes: Writes,
        /// The stage passed.
        stage: Option<u64>,
        /// Root built, `None` when the build failed.
        root: Option<B256>,
    },
    /// [`Store::build_unregistered`](crate::Store::build_unregistered).
    BuildUnregistered {
        /// Number of the block built.
        number: u64,
        /// Its parent.
        parent_hash: B256,
        /// Its writes.
        writes: Writes,
        /// Root built, `None` when the build failed.
        root: Option<B256>,
    },
    /// [`Store::register`](crate::Store::register).
    Register {
        /// Hash registered.
        hash: B256,
        /// Root of the registered batch.
        root: B256,
    },
    /// [`Store::finalize`](crate::Store::finalize).
    Finalize {
        /// Block finalized.
        hash: B256,
    },
    /// [`Store::get_accounts`](crate::Store::get_accounts).
    ReadAccounts {
        /// Keys read.
        keys: Vec<Key>,
    },
    /// [`Store::get_slots`](crate::Store::get_slots).
    ReadSlots {
        /// Keys read.
        keys: Vec<Key>,
    },
}

/// Writes a store's calls to a file from a thread of its own.
pub(crate) struct Recorder {
    origin: Instant,
    reads: bool,
    events: Option<mpsc::Sender<Event>>,
    writer: Option<JoinHandle<()>>,
}

impl Recorder {
    /// Creates the file and writes its header.
    pub(crate) fn create(
        options: &RecordOptions,
        origin: Instant,
        header: &Header,
    ) -> io::Result<Self> {
        let mut out = BufWriter::with_capacity(8 << 20, File::create(&options.path)?);
        out.write_all(MAGIC)?;
        encode_header(&mut out, header)?;
        let (events, received) = mpsc::channel::<Event>();
        let path = options.path.clone();
        let writer = std::thread::Builder::new()
            .name("qmdb-record".into())
            .spawn(move || {
                let mut count = 0u64;
                let written = received
                    .iter()
                    .try_for_each(|event| {
                        count += 1;
                        encode_event(&mut out, &event)
                    })
                    .and_then(|()| out.flush());
                match written {
                    Ok(()) => {
                        info!(target: "qmdb", path = %path.display(), count, "QMDB recording closed");
                    }
                    Err(err) => {
                        error!(target: "qmdb", %err, path = %path.display(), "writing the QMDB recording failed");
                    }
                }
            })?;
        info!(target: "qmdb", path = %options.path.display(), reads = options.reads, "recording QMDB calls");
        Ok(Self {
            origin,
            reads: options.reads,
            events: Some(events),
            writer: Some(writer),
        })
    }

    /// Whether state reads are recorded.
    pub(crate) const fn reads(&self) -> bool {
        self.reads
    }

    /// Records a call the current thread started at `start` and that returns now.
    pub(crate) fn record(&self, start: Instant, call: Call) {
        let event = Event {
            lane: lane(),
            start_ns: nanos(start.saturating_duration_since(self.origin)),
            end_ns: nanos(self.origin.elapsed()),
            call,
        };
        if let Some(events) = &self.events {
            // Only fails once the writer stopped on an error it already logged.
            let _ = events.send(event);
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        drop(self.events.take());
        if let Some(writer) = self.writer.take()
            && writer.join().is_err()
        {
            error!(target: "qmdb", "QMDB recording thread panicked");
        }
    }
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorder")
            .field("reads", &self.reads)
            .finish_non_exhaustive()
    }
}

/// Copies the store in `directory` into `snapshot`, replacing what it held.
pub(crate) fn copy_snapshot(directory: &Path, snapshot: &Path) -> io::Result<()> {
    if snapshot.exists() {
        std::fs::remove_dir_all(snapshot)?;
    }
    if !directory.exists() {
        return std::fs::create_dir_all(snapshot);
    }
    copy_dir(directory, snapshot)
}

/// Copies directory `from` into a new directory `to`, with reflinks where the file system has
/// them.
pub fn copy_dir(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg("--reflink=auto")
        .arg(from)
        .arg(to)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "copying {} to {} failed: {status}",
            from.display(),
            to.display()
        )))
    }
}

/// Reads a recording: its header and its events, in the order they returned.
pub fn read(path: &Path) -> io::Result<(Header, Vec<Event>)> {
    let mut input = BufReader::with_capacity(8 << 20, File::open(path)?);
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a QMDB recording",
        ));
    }
    let header = decode_header(&mut input)?;
    let mut events = Vec::new();
    loop {
        let mut tag = [0u8; 1];
        if input.read(&mut tag)? == 0 {
            break;
        }
        match decode_event(&mut input, tag[0]) {
            Ok(event) => events.push(event),
            // A node killed mid-write leaves its last event truncated.
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
    }
    Ok((header, events))
}

thread_local! {
    static LANE: Cell<Option<u32>> = const { Cell::new(None) };
}

fn lane() -> u32 {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    LANE.with(|lane| {
        lane.get().unwrap_or_else(|| {
            let next = NEXT.fetch_add(1, Ordering::Relaxed);
            lane.set(Some(next));
            next
        })
    })
}

fn nanos(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

const SET_BASE: u8 = 1;
const REWIND_TO: u8 = 2;
const OPEN_STAGE: u8 = 3;
const STAGE: u8 = 4;
const PREFETCH: u8 = 5;
const BUILD: u8 = 6;
const BUILD_UNREGISTERED: u8 = 7;
const REGISTER: u8 = 8;
const FINALIZE: u8 = 9;
const READ_ACCOUNTS: u8 = 10;
const READ_SLOTS: u8 = 11;

fn encode_header(out: &mut impl io::Write, header: &Header) -> io::Result<()> {
    put_opt_u64(out, header.applied)?;
    put_opt_b256(out, header.base)?;
    out.write_all(header.root.as_slice())?;
    put_u64(out, header.threads)?;
    put_u64(out, header.page_cache_pages)?;
    put_u64(out, header.max_pending)
}

fn decode_header(input: &mut impl Read) -> io::Result<Header> {
    Ok(Header {
        applied: get_opt_u64(input)?,
        base: get_opt_b256(input)?,
        root: get_b256(input)?,
        threads: get_u64(input)?,
        page_cache_pages: get_u64(input)?,
        max_pending: get_u64(input)?,
    })
}

fn encode_event(out: &mut impl io::Write, event: &Event) -> io::Result<()> {
    let tag = match &event.call {
        Call::SetBase { .. } => SET_BASE,
        Call::RewindTo { .. } => REWIND_TO,
        Call::OpenStage { .. } => OPEN_STAGE,
        Call::Stage { .. } => STAGE,
        Call::Prefetch { .. } => PREFETCH,
        Call::Build { .. } => BUILD,
        Call::BuildUnregistered { .. } => BUILD_UNREGISTERED,
        Call::Register { .. } => REGISTER,
        Call::Finalize { .. } => FINALIZE,
        Call::ReadAccounts { .. } => READ_ACCOUNTS,
        Call::ReadSlots { .. } => READ_SLOTS,
    };
    out.write_all(&[tag])?;
    out.write_all(&event.lane.to_le_bytes())?;
    put_u64(out, event.start_ns)?;
    put_u64(out, event.end_ns)?;
    match &event.call {
        Call::SetBase { hash } | Call::Finalize { hash } => out.write_all(hash.as_slice()),
        Call::RewindTo { number } => put_u64(out, *number),
        Call::OpenStage {
            stage,
            parent_hash,
            builder,
        } => {
            put_u64(out, *stage)?;
            out.write_all(parent_hash.as_slice())?;
            out.write_all(&[u8::from(*builder)])
        }
        Call::Stage {
            stage,
            accounts,
            slots,
        } => {
            put_u64(out, *stage)?;
            put_keys(out, accounts)?;
            put_keys(out, slots)
        }
        Call::Prefetch { accounts, slots } => {
            put_keys(out, accounts)?;
            put_keys(out, slots)
        }
        Call::Build {
            block,
            writes,
            stage,
            root,
        } => {
            put_u64(out, block.number)?;
            out.write_all(block.hash.as_slice())?;
            out.write_all(block.parent_hash.as_slice())?;
            put_writes(out, writes)?;
            put_opt_u64(out, *stage)?;
            put_opt_b256(out, *root)
        }
        Call::BuildUnregistered {
            number,
            parent_hash,
            writes,
            root,
        } => {
            put_u64(out, *number)?;
            out.write_all(parent_hash.as_slice())?;
            put_writes(out, writes)?;
            put_opt_b256(out, *root)
        }
        Call::Register { hash, root } => {
            out.write_all(hash.as_slice())?;
            out.write_all(root.as_slice())
        }
        Call::ReadAccounts { keys } | Call::ReadSlots { keys } => put_keys(out, keys),
    }
}

fn decode_event(input: &mut impl Read, tag: u8) -> io::Result<Event> {
    let mut lane = [0u8; 4];
    input.read_exact(&mut lane)?;
    let lane = u32::from_le_bytes(lane);
    let start_ns = get_u64(input)?;
    let end_ns = get_u64(input)?;
    let call = match tag {
        SET_BASE => Call::SetBase {
            hash: get_b256(input)?,
        },
        FINALIZE => Call::Finalize {
            hash: get_b256(input)?,
        },
        REWIND_TO => Call::RewindTo {
            number: get_u64(input)?,
        },
        OPEN_STAGE => Call::OpenStage {
            stage: get_u64(input)?,
            parent_hash: get_b256(input)?,
            builder: get_u8(input)? != 0,
        },
        STAGE => Call::Stage {
            stage: get_u64(input)?,
            accounts: get_keys(input)?,
            slots: get_keys(input)?,
        },
        PREFETCH => Call::Prefetch {
            accounts: get_keys(input)?,
            slots: get_keys(input)?,
        },
        BUILD => Call::Build {
            block: BlockRef {
                number: get_u64(input)?,
                hash: get_b256(input)?,
                parent_hash: get_b256(input)?,
            },
            writes: get_writes(input)?,
            stage: get_opt_u64(input)?,
            root: get_opt_b256(input)?,
        },
        BUILD_UNREGISTERED => Call::BuildUnregistered {
            number: get_u64(input)?,
            parent_hash: get_b256(input)?,
            writes: get_writes(input)?,
            root: get_opt_b256(input)?,
        },
        REGISTER => Call::Register {
            hash: get_b256(input)?,
            root: get_b256(input)?,
        },
        READ_ACCOUNTS => Call::ReadAccounts {
            keys: get_keys(input)?,
        },
        READ_SLOTS => Call::ReadSlots {
            keys: get_keys(input)?,
        },
        tag => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown event tag {tag}"),
            ));
        }
    };
    Ok(Event {
        lane,
        start_ns,
        end_ns,
        call,
    })
}

fn put_u64(out: &mut impl io::Write, value: u64) -> io::Result<()> {
    out.write_all(&value.to_le_bytes())
}

fn put_opt_u64(out: &mut impl io::Write, value: Option<u64>) -> io::Result<()> {
    match value {
        Some(value) => {
            out.write_all(&[1])?;
            put_u64(out, value)
        }
        None => out.write_all(&[0]),
    }
}

fn put_opt_b256(out: &mut impl io::Write, value: Option<B256>) -> io::Result<()> {
    match value {
        Some(value) => {
            out.write_all(&[1])?;
            out.write_all(value.as_slice())
        }
        None => out.write_all(&[0]),
    }
}

fn put_len(out: &mut impl io::Write, len: usize) -> io::Result<()> {
    let len = u32::try_from(len).map_err(|_| io::Error::other("too many keys in one call"))?;
    out.write_all(&len.to_le_bytes())
}

fn put_keys(out: &mut impl io::Write, keys: &[Key]) -> io::Result<()> {
    put_len(out, keys.len())?;
    keys.iter().try_for_each(|key| out.write_all(key.as_ref()))
}

fn put_values<const N: usize>(
    out: &mut impl io::Write,
    writes: &[Write<FixedBytes<N>>],
) -> io::Result<()> {
    put_len(out, writes.len())?;
    writes.iter().try_for_each(|write| {
        out.write_all(write.key.as_ref())?;
        match &write.value {
            Some(value) => {
                out.write_all(&[1])?;
                out.write_all(value.as_ref())
            }
            None => out.write_all(&[0]),
        }
    })
}

fn put_writes(out: &mut impl io::Write, writes: &Writes) -> io::Result<()> {
    put_values::<ACCOUNT_LEN>(out, &writes.accounts)?;
    put_values::<SLOT_LEN>(out, &writes.slots)
}

fn get_u8(input: &mut impl Read) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    input.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn get_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    input.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn get_b256(input: &mut impl Read) -> io::Result<B256> {
    let mut bytes = [0u8; 32];
    input.read_exact(&mut bytes)?;
    Ok(B256::new(bytes))
}

fn get_opt_u64(input: &mut impl Read) -> io::Result<Option<u64>> {
    Ok(match get_u8(input)? {
        0 => None,
        _ => Some(get_u64(input)?),
    })
}

fn get_opt_b256(input: &mut impl Read) -> io::Result<Option<B256>> {
    Ok(match get_u8(input)? {
        0 => None,
        _ => Some(get_b256(input)?),
    })
}

fn get_len(input: &mut impl Read) -> io::Result<usize> {
    let mut bytes = [0u8; 4];
    input.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}

fn get_fixed<const N: usize>(input: &mut impl Read) -> io::Result<FixedBytes<N>> {
    let mut bytes = [0u8; N];
    input.read_exact(&mut bytes)?;
    Ok(FixedBytes::new(bytes))
}

fn get_keys(input: &mut impl Read) -> io::Result<Vec<Key>> {
    let len = get_len(input)?;
    (0..len).map(|_| get_fixed::<32>(input)).collect()
}

fn get_values<const N: usize>(input: &mut impl Read) -> io::Result<Vec<Write<FixedBytes<N>>>> {
    let len = get_len(input)?;
    (0..len)
        .map(|_| {
            let key = get_fixed::<32>(input)?;
            let value = match get_u8(input)? {
                0 => None,
                _ => Some(get_fixed::<N>(input)?),
            };
            Ok(Write { key, value })
        })
        .collect()
}

fn get_writes(input: &mut impl Read) -> io::Result<Writes> {
    Ok(Writes {
        accounts: get_values::<ACCOUNT_LEN>(input)?,
        slots: get_values::<SLOT_LEN>(input)?,
    })
}
