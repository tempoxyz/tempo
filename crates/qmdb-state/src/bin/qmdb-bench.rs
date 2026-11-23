//! Synthetic benchmark of a QMDB [`Store`]: import, reopening (index rebuild), building blocks,
//! finalizing them to disk, and reading the applied state.
//!
//! ```text
//! qmdb-bench --dir <dir> [--slots 100000000] [--accounts 10000000] [--blocks 200]
//!     [--updates 9000] [--creates 7000] [--deletes 7000] [--account-writes 2000]
//!     [--persist-every 3] [--prefetch] [--reads 2000] [--read-batch 1000] [--read-threads 8]
//!     [--skip-import] [--json <file>]
//! ```
//!
//! The defaults mirror a heavy `public-mix` block on the e2e bench: about 23k slot mutations of
//! which 7k create and 7k delete keys, finalized three blocks at a time. Keys are spread uniformly
//! over the key space like hashed keys. `--skip-import` reuses a store an earlier run imported,
//! which then holds that run's blocks too.

use std::{
    collections::HashSet,
    num::NonZeroUsize,
    path::PathBuf,
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use alloy_primitives::{B256, U256};
use commonware_utils::sequence::FixedBytes;
use tempo_qmdb_state::{
    BlockRef, Config, Store,
    import::CHUNK_KEYS,
    layout::{self, ACCOUNT_LEN, AccountValue, Key, Write, Writes},
    replay::Percentiles,
};

struct Args {
    dir: PathBuf,
    slots: u64,
    accounts: u64,
    blocks: u64,
    warmup: u64,
    updates: usize,
    creates: usize,
    deletes: usize,
    account_writes: usize,
    persist_every: u64,
    prefetch: bool,
    reads: usize,
    read_batch: usize,
    read_threads: usize,
    threads: Option<usize>,
    page_cache_pages: usize,
    skip_import: bool,
    json: Option<PathBuf>,
}

fn parse() -> Result<Args, String> {
    let mut args = Args {
        dir: PathBuf::new(),
        slots: 100_000_000,
        accounts: 10_000_000,
        blocks: 200,
        warmup: 10,
        updates: 9_000,
        creates: 7_000,
        deletes: 7_000,
        account_writes: 2_000,
        persist_every: 3,
        prefetch: false,
        reads: 2_000,
        read_batch: 1_000,
        read_threads: 8,
        threads: None,
        page_cache_pages: 1 << 16,
        skip_import: false,
        json: None,
    };
    let mut dir = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value"));
        macro_rules! num {
            () => {
                value()?
                    .replace('_', "")
                    .parse()
                    .map_err(|_| format!("{arg} needs a number"))?
            };
        }
        match arg.as_str() {
            "--dir" => dir = Some(PathBuf::from(value()?)),
            "--slots" => args.slots = num!(),
            "--accounts" => args.accounts = num!(),
            "--blocks" => args.blocks = num!(),
            "--warmup" => args.warmup = num!(),
            "--updates" => args.updates = num!(),
            "--creates" => args.creates = num!(),
            "--deletes" => args.deletes = num!(),
            "--account-writes" => args.account_writes = num!(),
            "--persist-every" => args.persist_every = num!(),
            "--prefetch" => args.prefetch = true,
            "--reads" => args.reads = num!(),
            "--read-batch" => args.read_batch = num!(),
            "--read-threads" => args.read_threads = num!(),
            "--threads" => args.threads = Some(num!()),
            "--page-cache-pages" => args.page_cache_pages = num!(),
            "--skip-import" => args.skip_import = true,
            "--json" => args.json = Some(value()?.into()),
            other => return Err(format!("unknown argument {other}")),
        }
    }
    args.dir = dir.ok_or("--dir is required")?;
    if args.persist_every == 0 || args.slots == 0 || args.accounts == 0 {
        return Err("--persist-every, --slots and --accounts must be positive".into());
    }
    Ok(args)
}

fn main() -> ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// splitmix64.
fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(1);
        mix(self.0)
    }

    fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next()) * u128::from(n)) >> 64) as u64
    }

    fn key(&mut self) -> Key {
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            chunk.copy_from_slice(&self.next().to_be_bytes());
        }
        Key::new(bytes)
    }
}

/// The `i`th of `n` imported keys of a database tagged `tag`: ascending in `i` and spread evenly
/// over the key space.
fn base_key(tag: u64, i: u64, n: u64) -> Key {
    let mut bytes = [0u8; 32];
    let hi = ((u128::from(i) << 64) / u128::from(n)) as u64;
    bytes[..8].copy_from_slice(&hi.to_be_bytes());
    for (j, chunk) in bytes[8..].chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&mix(i ^ (tag << 60) ^ ((j as u64) << 56)).to_be_bytes());
    }
    Key::new(bytes)
}

fn slot_value(seed: u64) -> layout::SlotValue {
    layout::slot_value(U256::from(seed | 1))
}

fn account_value(seed: u64) -> AccountValue {
    let mut bytes = [0u8; ACCOUNT_LEN];
    for (j, chunk) in bytes.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&mix(seed ^ j as u64).to_be_bytes()[..chunk.len()]);
    }
    FixedBytes::new(bytes)
}

fn block_hash(number: u64) -> B256 {
    B256::left_padding_from(&mix(number ^ 0xb10c).to_be_bytes())
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1e3
}

fn row(p: &Percentiles) -> String {
    format!(
        "n={:<5} mean {:>8.1}  p50 {:>8.1}  p90 {:>8.1}  p99 {:>8.1}  max {:>8.1} ms",
        p.count, p.mean, p.p50, p.p90, p.p99, p.max
    )
}

fn json_p(p: &Percentiles) -> String {
    format!(
        "{{\"count\":{},\"mean\":{:.3},\"p50\":{:.3},\"p90\":{:.3},\"p99\":{:.3},\"max\":{:.3}}}",
        p.count, p.mean, p.p50, p.p90, p.p99, p.max
    )
}

fn du(path: &std::path::Path) -> u64 {
    fn walk(path: &std::path::Path) -> u64 {
        std::fs::read_dir(path).map_or(0, |entries| {
            entries
                .flatten()
                .map(|entry| match entry.metadata() {
                    Ok(meta) if meta.is_dir() => walk(&entry.path()),
                    Ok(meta) => meta.len(),
                    Err(_) => 0,
                })
                .sum()
        })
    }
    walk(path)
}

fn rss_mib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|line| line.starts_with("VmRSS:"))
                .and_then(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map_or(0, |kib| kib / 1024)
}

fn run(args: &Args) -> Result<(), String> {
    let config =
        Config {
            directory: args.dir.clone(),
            threads: NonZeroUsize::new(args.threads.unwrap_or_else(|| {
                std::thread::available_parallelism().map_or(1, NonZeroUsize::get)
            }))
            .ok_or("threads must be positive")?,
            page_cache_pages: NonZeroUsize::new(args.page_cache_pages)
                .ok_or("page cache pages must be positive")?,
            max_pending: NonZeroUsize::new(1024).expect("non-zero"),
        };
    let err = |what: &str| {
        let what = what.to_owned();
        move |err: tempo_qmdb_state::Error| format!("{what} failed: {err}")
    };
    let mut json = Vec::<String>::new();
    println!(
        "qmdb-bench: {} slots, {} accounts, {} threads, page cache {} pages, dir {}",
        args.slots,
        args.accounts,
        config.threads,
        config.page_cache_pages,
        args.dir.display()
    );

    // Import.
    if !args.skip_import {
        if args.dir.exists() {
            std::fs::remove_dir_all(&args.dir).map_err(|e| e.to_string())?;
        }
        let store = Store::open(config.clone()).map_err(err("opening"))?;
        let started = Instant::now();
        let chunk = CHUNK_KEYS as u64;
        let (mut next_slot, mut next_account) = (0u64, 0u64);
        while next_slot < args.slots || next_account < args.accounts {
            let slots_end = (next_slot + chunk).min(args.slots);
            let accounts_end = (next_account + chunk).min(args.accounts);
            let writes = Writes {
                accounts: (next_account..accounts_end)
                    .map(|i| Write {
                        key: base_key(1, i, args.accounts),
                        value: Some(account_value(i)),
                    })
                    .collect(),
                slots: (next_slot..slots_end)
                    .map(|i| Write {
                        key: base_key(2, i, args.slots),
                        value: Some(slot_value(i)),
                    })
                    .collect(),
            };
            (next_slot, next_account) = (slots_end, accounts_end);
            let end = (next_slot >= args.slots && next_account >= args.accounts)
                .then(|| (0, block_hash(0)));
            store.import_chunk(writes, end).map_err(err("importing"))?;
            if next_slot % (chunk * 16) == 0 || end.is_some() {
                let secs = started.elapsed().as_secs_f64();
                println!(
                    "  imported {next_slot} slots, {next_account} accounts in {secs:.0}s ({:.0}k keys/s)",
                    (next_slot + next_account) as f64 / secs / 1e3
                );
            }
        }
        let secs = started.elapsed().as_secs_f64();
        drop(store);
        println!(
            "import: {:.1}s, {:.0}k keys/s, {:.2} GiB on disk",
            secs,
            (args.slots + args.accounts) as f64 / secs / 1e3,
            du(&args.dir) as f64 / (1u64 << 30) as f64
        );
        json.push(format!("\"import_s\":{secs:.2}"));
    }

    // Reopen: rebuilds the in-memory indexes from the logs.
    let rss_before = rss_mib();
    let opened = Instant::now();
    let store = Store::open(config).map_err(err("reopening"))?;
    let open_s = opened.elapsed().as_secs_f64();
    let status = store.status().map_err(err("status"))?;
    let index_mib = rss_mib().saturating_sub(rss_before);
    println!(
        "reopen (index rebuild): {open_s:.1}s, RSS +{index_mib} MiB, applied block {:?}, {:.2} GiB on disk",
        status.applied,
        du(&args.dir) as f64 / (1u64 << 30) as f64
    );
    json.push(format!(
        "\"reopen_s\":{open_s:.2},\"index_rss_mib\":{index_mib}"
    ));
    let first = status.applied.unwrap_or(0) + 1;
    let base = status.base.unwrap_or_else(|| block_hash(first - 1));
    if status.base.is_none() {
        store.set_base(base).map_err(err("set_base"))?;
    }

    // Cold-ish reads straight after reopening, before blocks warm the cache.
    let reads_cold = read_bench(&store, args, 0xc01d)?;

    // Blocks.
    let mut rng = Rng(0x5eed ^ first);
    let mut deleted = HashSet::<u64>::new();
    let (mut prefetches, mut builds, mut finalizes, mut totals) = (vec![], vec![], vec![], vec![]);
    let mut parent = base;
    let blocks_started = Instant::now();
    for number in first..first + args.blocks {
        let mut used = HashSet::new();
        let mut pick = |rng: &mut Rng| loop {
            let i = rng.below(args.slots);
            if !deleted.contains(&i) && used.insert(i) {
                return i;
            }
        };
        let mut slots = Vec::with_capacity(args.updates + args.creates + args.deletes);
        for _ in 0..args.updates {
            let i = pick(&mut rng);
            slots.push(Write {
                key: base_key(2, i, args.slots),
                value: Some(slot_value(rng.next())),
            });
        }
        let mut doomed = Vec::with_capacity(args.deletes);
        for _ in 0..args.deletes {
            let i = pick(&mut rng);
            doomed.push(i);
            slots.push(Write {
                key: base_key(2, i, args.slots),
                value: None,
            });
        }
        for _ in 0..args.creates {
            slots.push(Write {
                key: rng.key(),
                value: Some(slot_value(rng.next())),
            });
        }
        deleted.extend(doomed);
        let mut seen = HashSet::new();
        let mut accounts: Vec<_> = (0..args.account_writes)
            .filter_map(|_| {
                let i = rng.below(args.accounts);
                seen.insert(i).then(|| Write {
                    key: base_key(1, i, args.accounts),
                    value: Some(account_value(rng.next())),
                })
            })
            .collect();
        slots.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        accounts.sort_unstable_by(|a, b| a.key.cmp(&b.key));

        let block_started = Instant::now();
        if args.prefetch {
            let started = Instant::now();
            store
                .prefetch(
                    accounts.iter().map(|w| w.key.clone()).collect(),
                    slots.iter().map(|w| w.key.clone()).collect(),
                )
                .map_err(err("prefetch"))?;
            prefetches.push((number, started.elapsed()));
        }
        let hash = block_hash(number);
        let started = Instant::now();
        store
            .build(
                BlockRef {
                    number,
                    hash,
                    parent_hash: parent,
                },
                Writes { accounts, slots },
            )
            .map_err(err("build"))?;
        builds.push((number, started.elapsed()));
        totals.push((number, block_started.elapsed()));
        if (number - first + 1) % args.persist_every == 0 {
            let started = Instant::now();
            store.finalize(hash).map_err(err("finalize"))?;
            finalizes.push((number, started.elapsed()));
        }
        parent = hash;
        if (number - first + 1) % 50 == 0 {
            println!(
                "  block {number}: build {:.1} ms",
                ms(builds.last().expect("built").1)
            );
        }
    }
    let wall = blocks_started.elapsed();
    let warm = |v: &[(u64, Duration)]| {
        Percentiles::of(
            v.iter()
                .filter(|(n, _)| *n >= first + args.warmup)
                .map(|(_, d)| *d),
        )
    };
    let (prefetch, build, finalize, total) = (
        warm(&prefetches),
        warm(&builds),
        warm(&finalizes),
        warm(&totals),
    );
    let writes = args.updates + args.creates + args.deletes + args.account_writes;
    println!(
        "\nblocks: {} of ~{writes} writes ({} updates, {} creates, {} deletes, {} accounts), finalize every {}, {:.1}s wall, after {} warmup blocks:",
        args.blocks,
        args.updates,
        args.creates,
        args.deletes,
        args.account_writes,
        args.persist_every,
        wall.as_secs_f64(),
        args.warmup
    );
    if args.prefetch {
        println!("  prefetch       {}", row(&prefetch));
    }
    println!("  build          {}", row(&build));
    if args.prefetch {
        println!("  prefetch+build {}", row(&total));
    }
    println!("  finalize x{}    {}", args.persist_every, row(&finalize));
    println!(
        "  finalize per block mean {:.1} ms; build throughput {:.0}k writes/s at p50",
        finalize.mean / args.persist_every as f64,
        writes as f64 / build.p50.max(1e-9)
    );
    json.push(format!(
        "\"blocks\":{},\"writes_per_block\":{writes},\"prefetch\":{},\"build\":{},\"prefetch_build\":{},\"finalize\":{}",
        args.blocks, json_p(&prefetch), json_p(&build), json_p(&total), json_p(&finalize)
    ));

    let reads_warm = read_bench(&store, args, 0x3a12)?;
    json.push(format!(
        "\"reads_cold\":{reads_cold},\"reads_warm\":{reads_warm}"
    ));
    drop(store);

    if let Some(path) = &args.json {
        std::fs::write(path, format!("{{{}}}\n", json.join(","))).map_err(|e| e.to_string())?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// Random batched reads of imported slots, on one thread and then on `--read-threads`. Returns
/// their results as JSON.
fn read_bench(store: &Store, args: &Args, seed: u64) -> Result<String, String> {
    if args.reads == 0 {
        return Ok("null".into());
    }
    let batch = |rng: &mut Rng| -> Vec<Key> {
        (0..args.read_batch)
            .map(|_| base_key(2, rng.below(args.slots), args.slots))
            .collect()
    };
    let label = if seed == 0xc01d {
        "after reopen"
    } else {
        "after blocks"
    };
    let mut out = Vec::new();
    for threads in [1, args.read_threads.max(1)] {
        let per_thread = (args.reads / threads).max(1);
        let latencies = std::sync::Mutex::new(Vec::with_capacity(args.reads));
        let found = AtomicU64::new(0);
        let started = Instant::now();
        std::thread::scope(|scope| {
            for t in 0..threads {
                let (latencies, found) = (&latencies, &found);
                scope.spawn(move || {
                    let mut rng = Rng(seed ^ ((t as u64 + 1) << 40) ^ (threads as u64) << 20);
                    let mut local = Vec::with_capacity(per_thread);
                    for _ in 0..per_thread {
                        let keys = batch(&mut rng);
                        let started = Instant::now();
                        if let Ok(values) = store.get_slots(keys) {
                            found.fetch_add(
                                values.iter().filter(|v| v.is_some()).count() as u64,
                                Ordering::Relaxed,
                            );
                        }
                        local.push(started.elapsed());
                    }
                    latencies.lock().expect("never poisoned").extend(local);
                });
            }
        });
        let secs = started.elapsed().as_secs_f64();
        let latencies = latencies.into_inner().expect("never poisoned");
        let keys = (latencies.len() * args.read_batch) as f64;
        let p = Percentiles::of(latencies);
        println!(
            "reads {label}, {threads} thread(s), batches of {}: {:.0}k keys/s ({:.1} us/key), batch {}, {} found",
            args.read_batch,
            keys / secs / 1e3,
            secs * 1e6 * threads as f64 / keys,
            row(&p),
            found.load(Ordering::Relaxed)
        );
        out.push(format!(
            "{{\"threads\":{threads},\"keys_per_s\":{:.0},\"batch\":{}}}",
            keys / secs,
            json_p(&p)
        ));
    }
    Ok(format!("[{}]", out.join(",")))
}
