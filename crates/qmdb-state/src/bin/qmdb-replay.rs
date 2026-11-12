//! Replays a QMDB recording offline and reports how long building and persisting batches took.
//!
//! Record on a node by starting it with `TEMPO_QMDB_RECORD=<file>` and
//! `TEMPO_QMDB_RECORD_SNAPSHOT=<dir>` (and `TEMPO_QMDB_RECORD_READS=1` to include the execution's
//! state reads), then replay with:
//!
//! ```text
//! qmdb-replay --recording <file> --snapshot <dir> [--mode timed|serial|finish-only]
//! ```
//!
//! Each run copies the snapshot to `--work` (reflinked where the file system can), opens it with
//! the recorded store's configuration unless overridden, replays every call, checks every root and
//! prints the finish (`build_unregistered`), validation (`build`) and persistence (`finalize`)
//! timings, recorded against replayed. `--info` only summarizes the recording.

use std::{
    num::NonZeroUsize,
    path::PathBuf,
    process::ExitCode,
    time::{Duration, Instant},
};

use tempo_qmdb_state::{
    Config, Store,
    record::{self, Call, RECORD_ENV},
    replay::{self, Kind, Mode, Options, Percentiles, Timing},
};

const USAGE: &str = "usage: qmdb-replay --recording <file> [--snapshot <dir>] [--work <dir>]
    [--mode timed|serial|finish-only] [--no-reads] [--speed <x>] [--warmup <blocks>]
    [--threads <n>] [--page-cache-pages <n>] [--max-pending <n>] [--csv <file>] [--info]
    [--in-place]

  --snapshot          store copied before the recording began (TEMPO_QMDB_RECORD_SNAPSHOT)
  --work              where the snapshot is copied to and replayed (default <snapshot>.replay)
  --in-place          replay on --snapshot itself, consuming it
  --mode              timed (default): recorded threads at recorded times; serial: one thread,
                      no waits; finish-only: serial without stages and prefetches
  --no-reads          skip the recorded state reads
  --speed             timed mode runs calls at recorded time / speed (default 1)
  --warmup            leading blocks left out of the statistics (default 5)
  --csv               write every call's recorded and replayed duration
  --info              only summarize the recording";

struct Args {
    recording: PathBuf,
    snapshot: Option<PathBuf>,
    work: Option<PathBuf>,
    in_place: bool,
    options: Options,
    warmup: u64,
    threads: Option<usize>,
    page_cache_pages: Option<usize>,
    max_pending: Option<usize>,
    csv: Option<PathBuf>,
    info: bool,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        recording: PathBuf::new(),
        snapshot: None,
        work: None,
        in_place: false,
        options: Options::default(),
        warmup: 5,
        threads: None,
        page_cache_pages: None,
        max_pending: None,
        csv: None,
        info: false,
    };
    let mut recording = None;
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--recording" => recording = Some(PathBuf::from(value()?)),
            "--snapshot" => parsed.snapshot = Some(value()?.into()),
            "--work" => parsed.work = Some(value()?.into()),
            "--in-place" => parsed.in_place = true,
            "--mode" => {
                parsed.options.mode = match value()?.as_str() {
                    "timed" => Mode::Timed,
                    "serial" => Mode::Serial,
                    "finish-only" => Mode::FinishOnly,
                    other => return Err(format!("unknown mode {other}")),
                }
            }
            "--no-reads" => parsed.options.reads = false,
            "--speed" => parsed.options.speed = number(&value()?)?,
            "--warmup" => parsed.warmup = number(&value()?)?,
            "--threads" => parsed.threads = Some(number(&value()?)?),
            "--page-cache-pages" => parsed.page_cache_pages = Some(number(&value()?)?),
            "--max-pending" => parsed.max_pending = Some(number(&value()?)?),
            "--csv" => parsed.csv = Some(value()?.into()),
            "--info" => parsed.info = true,
            "--help" | "-h" => return Err(String::new()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    parsed.recording = recording.ok_or("--recording is required")?;
    if !parsed.info && parsed.snapshot.is_none() {
        return Err("--snapshot is required to replay".into());
    }
    Ok(parsed)
}

fn number<T: std::str::FromStr>(value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("{value} is not a number"))
}

fn nonzero(value: u64, name: &str) -> Result<NonZeroUsize, String> {
    usize::try_from(value)
        .ok()
        .and_then(NonZeroUsize::new)
        .ok_or_else(|| format!("{name} must be positive"))
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(err) => {
            if !err.is_empty() {
                eprintln!("error: {err}");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Returns whether every root matched and every call ran.
fn run(args: Args) -> Result<bool, String> {
    if std::env::var_os(RECORD_ENV).is_some_and(|path| !path.is_empty()) {
        return Err(format!(
            "unset {RECORD_ENV}: the replay would record itself"
        ));
    }
    let loaded = Instant::now();
    let (header, events) = record::read(&args.recording)
        .map_err(|err| format!("reading {} failed: {err}", args.recording.display()))?;
    summarize_recording(&header, &events, args.warmup, loaded.elapsed());
    if args.info {
        return Ok(true);
    }

    let snapshot = args.snapshot.expect("checked by parse");
    let directory = if args.in_place {
        snapshot
    } else {
        let work = args
            .work
            .unwrap_or_else(|| snapshot.with_extension("replay"));
        if work.exists() {
            std::fs::remove_dir_all(&work)
                .map_err(|err| format!("removing {} failed: {err}", work.display()))?;
        }
        let copied = Instant::now();
        record::copy_dir(&snapshot, &work).map_err(|err| err.to_string())?;
        println!(
            "copied the snapshot to {} in {:.1?}",
            work.display(),
            copied.elapsed()
        );
        work
    };
    let config = Config {
        directory,
        threads: nonzero(
            args.threads
                .map_or(header.threads, |threads| threads as u64),
            "threads",
        )?,
        page_cache_pages: nonzero(
            args.page_cache_pages
                .map_or(header.page_cache_pages, |pages| pages as u64),
            "page cache pages",
        )?,
        max_pending: nonzero(
            args.max_pending
                .map_or(header.max_pending, |pending| pending as u64),
            "max pending",
        )?,
    };
    println!(
        "opening the store: threads {}, page cache pages {}, max pending {}",
        config.threads, config.page_cache_pages, config.max_pending
    );
    let opened = Instant::now();
    let store = Store::open_recording(config, None)
        .map_err(|err| format!("opening the store failed: {err}"))?;
    println!("opened in {:.1?}", opened.elapsed());
    replay::check_start(&store, &header)?;

    println!(
        "replaying {} calls, mode {:?}, reads {}, speed {}",
        events.len(),
        args.options.mode,
        args.options.reads,
        args.options.speed
    );
    let outcome = replay::replay(&store, &header, events, &args.options);
    drop(store);

    let first = outcome
        .timings
        .iter()
        .filter_map(|timing| timing.number)
        .min();
    let counted = |timing: &&Timing| match (timing.number, first) {
        (Some(number), Some(first)) => number >= first + args.warmup,
        _ => true,
    };
    println!(
        "\nreplayed in {:.1?}; ms, after {} warmup blocks:",
        outcome.wall, args.warmup
    );
    println!(
        "{:<20} {:>6}  {:>34}  {:>34}",
        "call", "count", "recorded mean/p50/p90/p99/max", "replayed mean/p50/p90/p99/max"
    );
    for kind in [
        Kind::BuildUnregistered,
        Kind::Build,
        Kind::Finalize,
        Kind::Stage,
        Kind::Prefetch,
        Kind::Read,
    ] {
        let timings: Vec<&Timing> = outcome
            .timings
            .iter()
            .filter(|timing| timing.kind == kind)
            .filter(counted)
            .collect();
        if timings.is_empty() {
            continue;
        }
        let recorded = Percentiles::of(timings.iter().map(|timing| timing.recorded));
        let replayed = Percentiles::of(timings.iter().map(|timing| timing.replayed));
        println!(
            "{:<20} {:>6}  {:>34}  {:>34}",
            kind.name(),
            timings.len(),
            row(&recorded),
            row(&replayed)
        );
    }

    if let Some(path) = &args.csv {
        let mut csv = String::from("kind,number,size,recorded_ms,replayed_ms\n");
        for timing in &outcome.timings {
            csv.push_str(&format!(
                "{},{},{},{:.3},{:.3}\n",
                timing.kind.name(),
                timing
                    .number
                    .map(|number| number.to_string())
                    .unwrap_or_default(),
                timing.size,
                ms(timing.recorded),
                ms(timing.replayed)
            ));
        }
        std::fs::write(path, csv)
            .map_err(|err| format!("writing {} failed: {err}", path.display()))?;
        println!("wrote {}", path.display());
    }

    for (number, recorded, replayed) in &outcome.mismatches {
        eprintln!("ROOT MISMATCH at block {number}: recorded {recorded}, replayed {replayed}");
    }
    for problem in outcome.problems.iter().take(20) {
        eprintln!("problem: {problem}");
    }
    if outcome.problems.len() > 20 {
        eprintln!("... and {} more problems", outcome.problems.len() - 20);
    }
    Ok(outcome.mismatches.is_empty() && outcome.problems.is_empty())
}

fn summarize_recording(
    header: &record::Header,
    events: &[record::Event],
    warmup: u64,
    loaded: Duration,
) {
    let lanes: std::collections::HashSet<u32> = events.iter().map(|event| event.lane).collect();
    let numbers: Vec<u64> = events
        .iter()
        .filter_map(|event| match &event.call {
            Call::BuildUnregistered { number, .. }
            | Call::Build {
                block: tempo_qmdb_state::BlockRef { number, .. },
                ..
            } => Some(*number),
            _ => None,
        })
        .collect();
    let span = events.iter().map(|event| event.end_ns).max().unwrap_or(0);
    println!(
        "recording: starts at block {:?} (root {}), {} calls on {} threads over {:.1?}, blocks {:?}..={:?}, read in {loaded:.1?}",
        header.applied,
        header.root,
        events.len(),
        lanes.len(),
        Duration::from_nanos(span),
        numbers.iter().min(),
        numbers.iter().max(),
    );
    let first = numbers.iter().min().copied().unwrap_or(0);
    let finishes: Vec<(Duration, usize)> = events
        .iter()
        .filter_map(|event| match &event.call {
            Call::BuildUnregistered { number, writes, .. } if *number >= first + warmup => Some((
                Duration::from_nanos(event.end_ns.saturating_sub(event.start_ns)),
                writes.len(),
            )),
            _ => None,
        })
        .collect();
    let finish = Percentiles::of(finishes.iter().map(|(duration, _)| *duration));
    let writes = finishes.iter().map(|(_, writes)| *writes).sum::<usize>() / finishes.len().max(1);
    println!(
        "recorded finish (build_unregistered) after {warmup} warmup blocks: {} blocks, mean {} writes, ms {}",
        finish.count,
        writes,
        row(&finish)
    );
}

fn row(p: &Percentiles) -> String {
    format!(
        "{:.1}/{:.1}/{:.1}/{:.1}/{:.1}",
        p.mean, p.p50, p.p90, p.p99, p.max
    )
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}
