//! Bounded in-process checkpoint reads feeding native execution workers.

use crate::{
    execute::{decode_block, execute_block, standalone_all},
    store::{self, Catalog, MAX_RECORD_BYTES, Record, Store},
    types::{Chunk, Transaction},
    view::View,
};
use alloy_primitives::B256;
use bytes::Bytes;
use crossbeam_channel::{RecvTimeoutError, Sender, TrySendError};
use parking_lot::Mutex;
use reth_cli_util::cancellation::CancellationToken;
use reth_primitives_traits::RecoveredBlock;
use slatedb::DbReader;
use std::{
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_primitives::Block;
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};
use tracing::info;

/// Serialized bytes reserved across in-flight scans, queued and executing records.
/// Each scan reserves its whole batch (at most 8 MiB) before opening, so this fits
/// ~16 maximum-size batches or two maximum-size records. Not an RSS cap: decoded
/// state, SlateDB scan/cache buffers and SDK allocations are excluded.
const REPLAY_BUDGET: usize = 2 * MAX_RECORD_BYTES;

struct Ready {
    record: Record,
    bytes: Bytes,
    cases: Vec<Bytes>,
    space: Arc<Notify>,
    // Acquired before fetching, held through decoding and execution. The Bytes
    // value moves between tasks without a framing copy or an input mutex.
    _reservation: OwnedSemaphorePermit,
}

/// Replays a published corpus range with `workers` execution threads. With `standalone`,
/// only transactions with ordinals in that range are replayed, each independently.
#[allow(clippy::too_many_arguments)]
pub fn run(
    store: Store,
    catalog: Catalog,
    mut range: Range<u64>,
    config: TempoEvmConfig,
    consensus: TempoConsensus,
    workers: usize,
    standalone: Option<(u64, u64)>,
    cancellation: CancellationToken,
) -> eyre::Result<()> {
    eyre::ensure!(workers > 0, "num-tasks must be positive");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::env::var("RETH_CORPUS_IO_THREADS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or_else(|| (workers * 3 / 4).max(4)),
        )
        .enable_all()
        .build()?;
    let reader = Arc::new(runtime.block_on(store.reader(&catalog))?);
    if let Some((from, to)) = standalone {
        range = runtime.block_on(transaction_range(&reader, &catalog, from, to))?;
    }
    let replay_budget = std::env::var("RETH_CORPUS_BUDGET_MIB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(REPLAY_BUDGET, |mib| mib << 20);
    let budget = Arc::new(Semaphore::new(replay_budget));
    let (sender, receiver) = crossbeam_channel::bounded::<Ready>(
        std::env::var("RETH_CORPUS_QUEUE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(64),
    );
    let started = Instant::now();
    // Save the triggering error before cancelling peers. Join order must not
    // replace missing/corrupt state with a secondary cancellation error.
    let failure = Mutex::new(None);
    // Shared counters for periodic progress, as the database path logs every 10 s.
    let done_blocks = AtomicU64::new(0);
    let done_transactions = AtomicU64::new(0);
    let done_gas = AtomicU64::new(0);
    let finished = AtomicBool::new(false);
    let total_blocks = if standalone.is_some() {
        0
    } else {
        range.end - range.start
    };
    let result = std::thread::scope(|scope| -> eyre::Result<()> {
        scope.spawn(|| {
            let mut last = (Instant::now(), 0u64);
            'report: loop {
                for _ in 0..100 {
                    if finished.load(Ordering::Relaxed) {
                        break 'report;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                let blocks = done_blocks.load(Ordering::Relaxed);
                let gas = done_gas.load(Ordering::Relaxed);
                let interval = last.0.elapsed().as_secs_f64();
                let throughput = (gas - last.1) as f64 / interval / 1e9;
                last = (Instant::now(), gas);
                let progress = if total_blocks == 0 {
                    0.0
                } else {
                    100.0 * blocks as f64 / total_blocks as f64
                };
                info!(
                    blocks,
                    transactions = done_transactions.load(Ordering::Relaxed),
                    progress = format!("{progress:.2}%"),
                    throughput = format!("{throughput:.2}Ggas/second"),
                    elapsed = format!("{:.0}s", started.elapsed().as_secs_f64()),
                    "Corpus replay progress"
                );
            }
        });
        let producer = scope.spawn(|| {
            match runtime.block_on(feed_catalog(
                &reader,
                &catalog,
                range.clone(),
                standalone,
                sender,
                budget.clone(),
                &cancellation,
            )) {
                Ok(totals) => totals,
                Err(error) => {
                    failure.lock().get_or_insert(error);
                    cancellation.cancel();
                    budget.close();
                    (0, 0, 0)
                }
            }
        });
        let mut threads = Vec::new();
        for _ in 0..workers {
            let receiver = receiver.clone();
            let config = &config;
            let consensus = &consensus;
            let cancellation = &cancellation;
            let budget = &budget;
            let failure = &failure;
            let (runtime, reader) = (&runtime, &*reader);
            let (done_blocks, done_transactions, done_gas) =
                (&done_blocks, &done_transactions, &done_gas);
            threads.push(scope.spawn(move || {
                let result = (|| -> eyre::Result<(u64, u64, u64)> {
                    let mut completed = (0, 0, 0);
                    let mut receive_wait = Duration::ZERO;
                    loop {
                        eyre::ensure!(!cancellation.is_cancelled(), "corpus worker cancelled");
                        let waiting = Instant::now();
                        let received = receiver.recv_timeout(Duration::from_millis(100));
                        receive_wait += waiting.elapsed();
                        let ready = match received {
                            Ok(ready) => ready,
                            Err(RecvTimeoutError::Timeout) => continue,
                            Err(RecvTimeoutError::Disconnected) => break,
                        };
                        ready.space.notify_one();
                        let chunk = store::decode(&ready.bytes, &ready.record)?;
                        runtime.block_on(store::resolve_code(reader, &chunk))?;
                        let (block, actual) =
                            verify(config, consensus, &chunk, &ready.cases, &ready.record)?;
                        let (transactions, gas) = if let Some((from, to)) = standalone {
                            let (mut transactions, mut gas) = (0, 0);
                            let phases = chunk.phases.as_ref().expect("verified");
                            standalone_all(
                                config,
                                &block,
                                View::new(chunk.clone()),
                                phases,
                                &actual,
                                |index, replayed| {
                                    let expected = &actual[index];
                                    if expected.ordinal >= from && expected.ordinal < to {
                                        eyre::ensure!(
                                            replayed == expected,
                                            "standalone transaction {} differs",
                                            expected.ordinal
                                        );
                                        gas += expected.gas_used();
                                        transactions += 1;
                                    }
                                    Ok(())
                                },
                            )?;
                            (transactions, gas)
                        } else {
                            (ready.record.transactions, ready.record.gas)
                        };
                        completed.0 += 1;
                        completed.1 += transactions;
                        completed.2 += gas;
                        done_blocks.fetch_add(1, Ordering::Relaxed);
                        done_transactions.fetch_add(transactions, Ordering::Relaxed);
                        done_gas.fetch_add(gas, Ordering::Relaxed);
                        // Drop decoded state, serialized Bytes, and its permit
                        // together, before receiving more work.
                    }
                    tracing::debug!(target: "reth::corpus::feed", receive_us = receive_wait.as_micros() as u64, records = completed.0, "Worker receive intervals (summed overlap)");
                    Ok(completed)
                })();
                match result {
                    Ok(items) => items,
                    Err(error) => {
                        failure.lock().get_or_insert(error);
                        cancellation.cancel();
                        budget.close();
                        (0, 0, 0)
                    }
                }
            }));
        }
        drop(receiver);
        let mut completed = (0, 0, 0);
        for worker in threads {
            match worker.join() {
                Ok(items) => {
                    completed.0 += items.0;
                    completed.1 += items.1;
                    completed.2 += items.2;
                }
                Err(_) => {
                    failure
                        .lock()
                        .get_or_insert_with(|| eyre::eyre!("corpus worker panicked"));
                    cancellation.cancel();
                    budget.close();
                }
            }
        }
        let wanted = producer
            .join()
            .map_err(|_| eyre::eyre!("corpus reader panicked"));
        finished.store(true, Ordering::Relaxed);
        let wanted = wanted?;
        if let Some(error) = failure.lock().take() {
            return Err(error);
        }
        // The metadata cursor rejects gaps/duplicates before each single send;
        // MPMC receive transfers each record to exactly one worker. Counts close
        // the coverage check without retaining a history-sized completion set.
        eyre::ensure!(
            completed.0 == wanted.0
                && completed.1 == wanted.1
                && (standalone.is_some() || completed.2 == wanted.2),
            "missing/duplicate completed corpus records"
        );
        let transactions = completed.1;
        let gas = completed.2;
        let blocks = if standalone.is_some() {
            0
        } else {
            range.end - range.start
        };
        info!(
            blocks,
            transactions,
            gas,
            records = completed.0,
            workers,
            standalone = standalone.is_some(),
            seconds = started.elapsed().as_secs_f64(),
            serialized_budget = REPLAY_BUDGET,
            "Corpus replay verified"
        );
        Ok(())
    });
    let closed = runtime.block_on(reader.close());
    result?;
    closed?;
    Ok(())
}

/// Fetching owns serialized reservations until ownership moves to a worker.
async fn feed_pages(
    reader: &Arc<DbReader>,
    mut pages: mpsc::Receiver<Vec<Record>>,
    tasks: &mut JoinSet<eyre::Result<()>>,
    sender: Sender<Ready>,
    budget: Arc<Semaphore>,
    cancellation: &CancellationToken,
) -> eyre::Result<()> {
    let space = Arc::new(Notify::new());
    let mut records = Vec::<Record>::new().into_iter().peekable();
    let mut closed = false;
    // Reserve whole read batches before opening scans, then transfer exact byte
    // permits to individual ready records. No task acquires a second reservation
    // while retaining its first, including when a record fills the entire budget.
    let batch_limit = budget.available_permits().min(8 * 1024 * 1024);
    loop {
        eyre::ensure!(!cancellation.is_cancelled(), "corpus replay cancelled");
        while tasks.len()
            < std::env::var("RETH_CORPUS_FETCH_TASKS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(64)
        {
            let Some(record) = records.next() else { break };
            let (mut end, mut bytes) = (record.end, record.bytes);
            let mut batch = vec![record];
            // Batches never span pages, so an unfiltered page under the byte limit is one
            // scan task; read parallelism comes from pages in flight under the byte budget.
            while let Some(next) =
                records.next_if(|next| next.start == end && bytes + next.bytes <= batch_limit)
            {
                (end, bytes) = (next.end, bytes + next.bytes);
                batch.push(next);
            }
            let sender = sender.clone();
            let reader = reader.clone();
            let budget = budget.clone();
            let space = space.clone();
            tasks.spawn(async move {
                let waiting = Instant::now();
                let mut reservation = budget.acquire_many_owned(bytes as u32).await?;
                let budget_wait = waiting.elapsed();
                let mut queue_wait = Duration::ZERO;
                let mut payloads = store::PayloadScan::open(&reader, &batch).await?;
                for record in batch {
                    let (block, cases) = payloads.next(&record).await?;
                    let permit = reservation.split(record.bytes).expect("batch sum reserved");
                    let mut ready = Ready {
                        record,
                        bytes: block,
                        cases,
                        space: space.clone(),
                        _reservation: permit,
                    };
                    loop {
                        // Register before checking capacity so a receive between
                        // try_send and await cannot leave this producer asleep.
                        let notified = space.notified();
                        tokio::pin!(notified);
                        notified.as_mut().enable();
                        match sender.try_send(ready) {
                            Ok(()) => break,
                            Err(TrySendError::Full(item)) => ready = item,
                            Err(TrySendError::Disconnected(_)) => {
                                eyre::bail!("execution workers disconnected")
                            }
                        }
                        let waiting = Instant::now();
                        notified.await;
                        queue_wait += waiting.elapsed();
                    }
                }
                payloads.finish().await?;
                tracing::debug!(
                    target: "reth::corpus::feed",
                    budget_us = budget_wait.as_micros() as u64,
                    queue_us = queue_wait.as_micros() as u64,
                    bytes,
                    "Producer waits (overlap across tasks)"
                );
                Ok(())
            });
        }
        if closed && records.peek().is_none() && tasks.is_empty() {
            return Ok(());
        }
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                result.expect("nonempty reader tasks")??;
            }
            page = pages.recv(), if !closed && records.peek().is_none() && tasks.len() < 64 => {
                match page {
                    Some(page) => records = page.into_iter().peekable(),
                    None => closed = true,
                }
            }
            // The token is a polled flag; re-check it while every arm is blocked.
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
}

/// Locate independent cases without walking all preceding block metadata.
async fn transaction_range(
    reader: &DbReader,
    catalog: &Catalog,
    from: u64,
    to: u64,
) -> eyre::Result<Range<u64>> {
    let mut bounds = Vec::new();
    for ordinal in [from, to - 1] {
        let (mut low, mut high) = (catalog.context.start, catalog.context.end);
        while low < high {
            let mid = low + (high - low) / 2;
            let record = store::metadata(reader, mid).await?;
            let end = record
                .first_tx
                .checked_add(record.transactions)
                .ok_or_else(|| eyre::eyre!("ordinal overflow"))?;
            if end <= ordinal {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        eyre::ensure!(low < catalog.context.end, "missing transaction metadata");
        let record = store::metadata(reader, low).await?;
        eyre::ensure!(
            record.first_tx <= ordinal && ordinal < record.first_tx + record.transactions,
            "transaction ordinal metadata gap"
        );
        bounds.push(low);
    }
    Ok(bounds[0]..bounds[1] + 1)
}

async fn feed_catalog(
    reader: &Arc<DbReader>,
    catalog: &Catalog,
    range: Range<u64>,
    standalone: Option<(u64, u64)>,
    sender: Sender<Ready>,
    budget: Arc<Semaphore>,
    cancellation: &CancellationToken,
) -> eyre::Result<(u64, u64, u64)> {
    // One pool spans the entire range, so a slow payload batch cannot stall
    // unrelated reads at a metadata page boundary.
    let mut tasks = JoinSet::new();
    let (pages, receiver) = mpsc::channel(1);
    let result = tokio::try_join!(
        read_catalog(reader, catalog, range, standalone, pages, cancellation),
        feed_pages(reader, receiver, &mut tasks, sender, budget, cancellation),
    );
    // The sibling future is dropped on error. Abort and join its payload tasks
    // before the caller closes the pinned reader, preserving the original error.
    tasks.shutdown().await;
    result.map(|(totals, ())| totals)
}

async fn read_catalog(
    reader: &Arc<DbReader>,
    catalog: &Catalog,
    range: Range<u64>,
    standalone: Option<(u64, u64)>,
    pages: mpsc::Sender<Vec<Record>>,
    cancellation: &CancellationToken,
) -> eyre::Result<(u64, u64, u64)> {
    let cursor = if range.start == catalog.context.start {
        store::Cursor::initial(&catalog.context)?
    } else {
        let previous = store::metadata(reader, range.start - 1).await?;
        let mut cursor = store::Cursor {
            next: previous.start,
            tx: previous.first_tx,
            parent: previous.parent,
        };
        cursor.advance(&previous)?;
        cursor
    };
    let initial_tx = cursor.tx;
    let mut totals = (0, 0, 0);
    let mut metadata = store::MetadataPages::open(reader, cursor, range.end).await?;
    while metadata.cursor.next < range.end {
        // Reserve before reading: only one queued/in-progress metadata page,
        // in addition to the current page and descriptors owned by bounded tasks.
        let slot = pages.reserve().await?;
        eyre::ensure!(!cancellation.is_cancelled(), "metadata read cancelled");
        let mut page = metadata.next_page().await?;
        if let Some((from, to)) = standalone {
            page.retain(|r| {
                r.transactions > 0 && r.first_tx < to && r.first_tx + r.transactions > from
            });
        }
        for record in &page {
            totals.0 += 1;
            totals.1 += standalone.map_or(record.transactions, |(from, to)| {
                to.min(record.first_tx + record.transactions) - from.max(record.first_tx)
            });
            totals.2 += record.gas;
        }
        // An empty filtered page is not EOF; standalone replay can skip pages.
        slot.send(page);
    }
    let cursor = metadata.cursor;
    if range.end == catalog.context.end {
        eyre::ensure!(cursor == catalog.cursor, "final metadata boundary mismatch");
    } else {
        let next = store::metadata(reader, range.end).await?;
        eyre::ensure!(
            cursor.parent == next.parent && cursor.tx == next.first_tx,
            "metadata boundary mismatch"
        );
    }
    eyre::ensure!(
        totals.1 == standalone.map_or(cursor.tx - initial_tx, |(from, to)| to - from),
        "metadata transaction coverage mismatch"
    );
    eyre::ensure!(
        standalone.is_some() || totals.0 == range.end - range.start,
        "metadata block coverage mismatch"
    );
    Ok(totals)
}

/// Verifies one published block: executes it from its record alone and checks every
/// transaction against its stored digests, consensus rules and the historical changesets.
pub fn verify(
    config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    chunk: &Arc<Chunk>,
    cases: &[Bytes],
    record: &Record,
) -> eyre::Result<(RecoveredBlock<Block>, Vec<Transaction>)> {
    eyre::ensure!(
        cases.len() == record.cases.len(),
        "transaction count mismatch"
    );
    let expected = cases
        .iter()
        .enumerate()
        .map(|(i, b)| store::decode_case(b, &record.cases[i], record.first_tx + i as u64))
        .collect::<eyre::Result<Vec<_>>>()?;
    let block = decode_block(&chunk.blocks[0], chunk.start, B256::from(chunk.parent))?;
    let phases = chunk
        .phases
        .as_ref()
        .ok_or_else(|| eyre::eyre!("missing phase expectations"))?;
    let executed = execute_block(
        config,
        consensus,
        View::new(chunk.clone()),
        &block,
        record.first_tx,
        Some((&expected, phases)),
    )?;
    crate::execute::verify_changesets(&executed.bundle, &chunk.changeset()?, chunk.start)?;
    eyre::ensure!(
        executed.transactions.len() as u64 == record.transactions && executed.gas == record.gas,
        "transaction/gas totals mismatch"
    );
    Ok((block, executed.transactions))
}
