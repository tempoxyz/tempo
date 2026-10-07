//! Measurement-branch instrumentation: counters and sparse fenced TSC samples, never clock syscalls.
use std::{
    cell::RefCell,
    sync::atomic::{AtomicU8, Ordering},
};
static ACTIVE: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy)]
pub enum Area {
    Other,
    FeePre,
    FeePost,
    Nonce,
    Transfer,
    Execution,
    Commit,
    Calls,
    Prepare,
    TxEnv,
    EnvValidation,
    Intrinsic,
    FeeResolve,
    NonceApply,
    Settlement,
    CachedEnv,
}
#[derive(Clone, Copy)]
pub enum Op {
    Phase,
    LoadJournal,
    StoreJournal,
    LoadTotal,
    StoreTotal,
    ProviderAccount,
    ProviderStorage,
    ProviderCode,
    AccountAccess,
    SlotLoad,
    SlotStore,
}
const AREAS: [&str; 16] = [
    "other",
    "fee_pre",
    "fee_post",
    "nonce",
    "transfer",
    "execution",
    "commit",
    "calls",
    "prepare",
    "tx_env",
    "env_validation",
    "intrinsic",
    "fee_resolve",
    "nonce_apply",
    "settlement",
    "cached_env",
];
const OPS: [&str; 11] = [
    "phase",
    "load_journal",
    "store_journal",
    "load_total",
    "store_total",
    "provider_account",
    "provider_storage",
    "provider_code",
    "account_access",
    "slot_load",
    "slot_store",
];
#[derive(Clone, Copy, Default)]
struct Cell {
    calls: u64,
    samples: u64,
    ticks: u64,
    dropped: u64,
}
struct Stats {
    mode: u8,
    sample_offset: u64,
    area: Area,
    cells: [[Cell; 11]; 16],
}
thread_local! { static STATS: RefCell<Stats> = const { RefCell::new(Stats { mode: 0, sample_offset: 0, area: Area::Other, cells: [[Cell { calls: 0, samples: 0, ticks: 0, dropped: 0 }; 11]; 16] }) }; }
#[derive(Clone, Copy)]
struct Stamp {
    ticks: u64,
    cpu: u32,
}
impl Stamp {
    #[inline]
    fn read() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let mut cpu = 0;
            let ticks = unsafe {
                core::arch::x86_64::_mm_lfence();
                let ticks = core::arch::x86_64::__rdtscp(&mut cpu);
                core::arch::x86_64::_mm_lfence();
                ticks
            };
            Self { ticks, cpu }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Self { ticks: 0, cpu: 0 }
        }
    }
}
pub struct Guard {
    area: usize,
    op: usize,
    start: Option<Stamp>,
    restore: Option<Area>,
}
impl Drop for Guard {
    #[inline]
    fn drop(&mut self) {
        let end = self.start.map(|_| Stamp::read());
        if self.start.is_some() || self.restore.is_some() {
            STATS.with(|s| {
                let mut s = s.borrow_mut();
                if let (Some(start), Some(end)) = (self.start, end) {
                    let cell = &mut s.cells[self.area][self.op];
                    if start.cpu == end.cpu && end.ticks >= start.ticks {
                        cell.samples += 1;
                        cell.ticks += end.ticks - start.ticks;
                    } else {
                        cell.dropped += 1;
                    }
                }
                if let Some(old) = self.restore {
                    s.area = old;
                }
            });
        }
    }
}
#[inline]
pub fn operation(op: Op) -> Guard {
    guard(op, None)
}
#[inline]
pub fn area(area: Area) -> Guard {
    guard(Op::Phase, Some(area))
}
#[inline]
fn guard(op: Op, area: Option<Area>) -> Guard {
    if !cfg!(feature = "execution-measure") || ACTIVE.load(Ordering::Relaxed) == 0 {
        return Guard {
            area: 0,
            op: 0,
            start: None,
            restore: None,
        };
    }
    if ACTIVE.load(Ordering::Relaxed) == 3 && !matches!(op, Op::Phase) {
        return Guard {
            area: 0,
            op: 0,
            start: None,
            restore: None,
        };
    }
    STATS.with(|s| {
        let mut s = s.borrow_mut();
        let restore = (s.mode != 0)
            .then(|| {
                area.map(|a| {
                    let old = s.area;
                    s.area = a;
                    old
                })
            })
            .flatten();
        let a = s.area as usize;
        let mode = s.mode;
        let sample_offset = s.sample_offset;
        let cell = &mut s.cells[a][op as usize];
        let sample = if mode == 0 {
            false
        } else {
            cell.calls += 1;
            // Independent streams prevent parent/child timers from selecting the same calls.
            let salt = (a * OPS.len() + op as usize + 1) as u64;
            let mut n = cell
                .calls
                .wrapping_add(sample_offset)
                .wrapping_add(salt.wrapping_mul(0xd6e8feb86659fd93))
                .wrapping_mul(0x9e3779b97f4a7c15);
            n = (n ^ (n >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            (mode == 2 || mode == 3)
                && cfg!(target_arch = "x86_64")
                && ((n ^ (n >> 27))
                    & if mode == 3 {
                        63
                    } else if matches!(op, Op::Phase) {
                        15
                    } else {
                        1023
                    })
                    == 0
        };
        Guard {
            area: a,
            op: op as usize,
            start: sample.then(Stamp::read),
            restore,
        }
    })
}
pub fn reset(mode: u8) {
    ACTIVE.store(mode, Ordering::Relaxed);
    STATS.with(|s| {
        *s.borrow_mut() = Stats {
            mode,
            sample_offset: 0,
            area: Area::Other,
            cells: [[Cell::default(); 11]; 16],
        }
    });
}
pub fn dump() {
    let mut overhead = u64::MAX;
    if cfg!(target_arch = "x86_64") {
        for _ in 0..4096 {
            let a = Stamp::read();
            let b = Stamp::read();
            if a.cpu == b.cpu {
                overhead = overhead.min(b.ticks - a.ticks);
            }
        }
    } else {
        overhead = 0;
    }
    println!("MEASURE timer_pair_ticks={overhead}");
    STATS.with(|s| {
        let s = s.borrow();
        for (a, row) in s.cells.iter().enumerate() {
            for (o, c) in row.iter().enumerate() {
                if c.calls != 0 {
                    println!(
                        "MEASURE area={} op={} calls={} samples={} ticks={} dropped={}",
                        AREAS[a], OPS[o], c.calls, c.samples, c.ticks, c.dropped
                    );
                }
            }
        }
    });
}

/// Process-level batch timestamp; never called per transaction.
pub fn timestamp() -> u64 {
    Stamp::read().ticks
}

/// Initializes counters once per real block; environment parsing never occurs per transaction.
#[allow(clippy::disallowed_methods)] // Measurement clock, once per block, outside consensus logic.
pub fn begin_node_block(number: u64) {
    if !cfg!(feature = "execution-measure") {
        return;
    }
    static MODE: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    let mode = *MODE.get_or_init(|| {
        std::env::var("NODE_MEASURE_MODE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    });
    if mode != 0 {
        reset(mode);
        NODE_SEQUENCE.with(|sequence| {
            let next = sequence.get().wrapping_add(1);
            sequence.set(next);
            STATS.with(|stats| {
                stats.borrow_mut().sample_offset = next.wrapping_mul(0x9e3779b97f4a7c15)
            });
        });
        NODE_STARTED.with(|started| {
            *started.borrow_mut() = Some((number, std::time::Instant::now(), Stamp::read()))
        });
    }
}
/// Writes one aggregate record after block execution, with no per-transaction log writes.
pub fn report_node_block(backend: &str, gas: u64, accepted: usize) {
    if !cfg!(feature = "execution-measure") || std::env::var_os("NODE_MEASURE_MODE").is_none() {
        return;
    }
    use std::fmt::Write;
    let end = Stamp::read();
    let (number, nanos, ticks) = NODE_STARTED.with(|started| {
        started
            .borrow_mut()
            .take()
            .map_or((0, 0, 0), |(number, wall, start)| {
                (
                    number,
                    wall.elapsed().as_nanos(),
                    end.ticks.saturating_sub(start.ticks),
                )
            })
    });
    static TIMER_PAIR: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let timer_pair = TIMER_PAIR.get_or_init(|| {
        (0..4096)
            .filter_map(|_| {
                let a = Stamp::read();
                let b = Stamp::read();
                (a.cpu == b.cpu).then_some(b.ticks.saturating_sub(a.ticks))
            })
            .min()
            .unwrap_or(0)
    });
    let mut row = format!(
        "NODE_MEASURE backend={backend} number={number} timer_pair_ticks={timer_pair} gas={gas} accepted={accepted} nanos={nanos} ticks={ticks}"
    );
    STATS.with(|stats| {
        let stats = stats.borrow();
        for (a, cells) in stats.cells.iter().enumerate() {
            for (o, c) in cells.iter().enumerate() {
                if c.calls != 0 {
                    write!(
                        &mut row,
                        " {}.{}={},{},{},{}",
                        AREAS[a], OPS[o], c.calls, c.samples, c.ticks, c.dropped
                    )
                    .unwrap();
                }
            }
        }
    });
    eprintln!("{row}");
}

thread_local! { static NODE_SEQUENCE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
thread_local! { static NODE_STARTED: RefCell<Option<(u64, std::time::Instant, Stamp)>> = const { RefCell::new(None) }; }
