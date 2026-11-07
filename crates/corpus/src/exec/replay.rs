//! Bounded in-process checkpoint reads feeding native execution workers.

use crate::{
    exec::{
        block::{decode_block, execute_block, standalone_cases, verify_changesets},
        db::View,
    },
    store::{self, Catalog, MAX_RECORD_BYTES, Record, Store},
    types::{Case, Input, Phases},
};
use alloy_primitives::B256;
use bytes::Bytes;
use crossbeam_channel::{RecvTimeoutError, Sender, TrySendError};
use eyre::OptionExt;
use futures::{StreamExt, TryStreamExt};
use parking_lot::Mutex;
use reth_chainspec::EthChainSpec;
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
/// Unselected blocks a payload batch reads through to the next selected one: opening a scan
/// costs far more than reading a run of small skipped blocks.
const MAX_SKIPPED_RUN: usize = 1024;
/// Block-list metadata spans read concurrently: each opens its own scan.
const METADATA_SPANS: usize = 16;

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
/// only transactions with ordinals in that range are replayed, each independently. With `blocks`
/// (sorted), only those blocks of the range are replayed.
#[allow(clippy::too_many_arguments)]
pub fn run(
    store: Store,
    mut catalog: Catalog,
    mut range: Range<u64>,
    config: TempoEvmConfig,
    consensus: TempoConsensus,
    workers: usize,
    standalone: Option<(u64, u64)>,
    blocks: Option<&[u64]>,
    cancellation: CancellationToken,
) -> eyre::Result<()> {
    eyre::ensure!(workers > 0, "num-tasks must be positive");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(env_usize("TEMPO_CORPUS_IO_THREADS").unwrap_or((workers * 3 / 4).max(4)))
        .enable_all()
        .build()?;
    // Read the published snapshot through a lease of our own: a fill extending the corpus
    // retires the published checkpoint with a fixed grace lifetime a long replay can outlast.
    // A replay that fails before releasing it leaves it to expire.
    let lease = store.lease_published(&runtime, &mut catalog, {
        let cancellation = cancellation.clone();
        // Stop reading before the lease may expire.
        move || cancellation.cancel()
    })?;
    let reader = Arc::new(runtime.block_on(store.reader(&catalog))?);
    let tip_timestamp = runtime.block_on(store::tip_timestamp(&reader, &catalog.cursor))?;
    eyre::ensure!(
        store::forks_agree(
            &catalog.context.forks,
            &config.chain_spec().display_hardforks().to_string(),
            tip_timestamp,
        ),
        "corpus fork schedule mismatch"
    );
    if let Some((from, to)) = standalone {
        range = runtime.block_on(transaction_range(&reader, &catalog, from, to))?;
    }
    let budget = Arc::new(Semaphore::new(
        env_usize("TEMPO_CORPUS_BUDGET_MIB").map_or(REPLAY_BUDGET, |mib| mib << 20),
    ));
    let (sender, receiver) =
        crossbeam_channel::bounded::<Ready>(env_usize("TEMPO_CORPUS_QUEUE").unwrap_or(64));
    let started = Instant::now();
    // Save the triggering error before cancelling peers. Join order must not
    // replace missing/corrupt state with a secondary cancellation error.
    let failure = Mutex::new(None);
    let fail = |error: eyre::Report| {
        failure.lock().get_or_insert(error);
        cancellation.cancel();
        budget.close();
    };
    // Shared counters for periodic progress, as the database path logs every 10 s.
    // Once every worker has joined they are also the completed totals.
    let done_blocks = AtomicU64::new(0);
    let done_transactions = AtomicU64::new(0);
    let done_gas = AtomicU64::new(0);
    let finished = AtomicBool::new(false);
    let total_blocks = match (standalone, blocks) {
        (Some(_), _) => 0,
        (None, Some(blocks)) => blocks.len() as u64,
        (None, None) => range.end - range.start,
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
            runtime
                .block_on(feed_catalog(
                    &reader,
                    &catalog,
                    range.clone(),
                    standalone,
                    blocks,
                    sender,
                    budget.clone(),
                    &cancellation,
                ))
                .unwrap_or_else(|error| {
                    fail(error);
                    (0, 0, 0)
                })
        });
        let (config, consensus, cancellation, runtime, reader) =
            (&config, &consensus, &cancellation, &runtime, &*reader);
        let (done_blocks, done_transactions, done_gas) =
            (&done_blocks, &done_transactions, &done_gas);
        let mut threads = Vec::new();
        for _ in 0..workers {
            let receiver = receiver.clone();
            threads.push(scope.spawn(move || {
                let result = (|| -> eyre::Result<()> {
                    let mut records = 0u64;
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
                        let input = store::decode(&ready.bytes, &ready.record)?;
                        runtime.block_on(store::resolve_code(reader, &input))?;
                        let (transactions, gas) = if let Some((from, to)) = standalone {
                            // The stored deltas restore each transaction's prestate, so the
                            // block itself is not executed.
                            let (cases, block, phases) =
                                decode_record(&input, &ready.cases, &ready.record)?;
                            let (mut transactions, mut gas) = (0, 0);
                            standalone_cases(
                                config,
                                &block,
                                View::new(input.clone()),
                                phases,
                                &cases,
                                |case| {
                                    let selected = case.ordinal >= from && case.ordinal < to;
                                    if selected {
                                        gas += case.charged_gas;
                                        transactions += 1;
                                    }
                                    selected
                                },
                            )?;
                            (transactions, gas)
                        } else {
                            verify(config, consensus, &input, &ready.cases, &ready.record)?;
                            (ready.record.transactions, ready.record.gas)
                        };
                        records += 1;
                        done_blocks.fetch_add(1, Ordering::Relaxed);
                        done_transactions.fetch_add(transactions, Ordering::Relaxed);
                        done_gas.fetch_add(gas, Ordering::Relaxed);
                        // Drop decoded state, serialized Bytes, and its permit
                        // together, before receiving more work.
                    }
                    tracing::debug!(target: "tempo::corpus::feed", receive_us = receive_wait.as_micros() as u64, records, "Worker receive intervals (summed overlap)");
                    Ok(())
                })();
                if let Err(error) = result {
                    fail(error);
                }
            }));
        }
        drop(receiver);
        for worker in threads {
            if worker.join().is_err() {
                fail(eyre::eyre!("corpus worker panicked"));
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
        let completed = (
            done_blocks.load(Ordering::Relaxed),
            done_transactions.load(Ordering::Relaxed),
            done_gas.load(Ordering::Relaxed),
        );
        // The metadata cursor rejects gaps/duplicates before each single send;
        // MPMC receive transfers each record to exactly one worker. Counts close
        // the coverage check without retaining a history-sized completion set.
        eyre::ensure!(
            completed.0 == wanted.0
                && completed.1 == wanted.1
                && (standalone.is_some() || completed.2 == wanted.2),
            "missing/duplicate completed corpus records"
        );
        info!(
            blocks = total_blocks,
            transactions = completed.1,
            gas = completed.2,
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
    let expiring = lease.expiring();
    let released = lease.release(&runtime, &store);
    let finished = result.and(closed.map_err(eyre::Report::from));
    // A failed renewal cancels the replay; report why rather than the cancellation.
    if expiring {
        released.and(finished)
    } else {
        finished.and(released)
    }
}

/// Fetching owns serialized reservations until ownership moves to a worker.
async fn feed_pages(
    reader: &Arc<DbReader>,
    mut pages: mpsc::Receiver<Vec<(Record, bool)>>,
    tasks: &mut JoinSet<eyre::Result<()>>,
    sender: Sender<Ready>,
    budget: Arc<Semaphore>,
    cancellation: &CancellationToken,
) -> eyre::Result<()> {
    let space = Arc::new(Notify::new());
    // Each record with whether to replay it; unselected ones are read only to keep scans
    // contiguous.
    let mut records = Vec::<(Record, bool)>::new().into_iter().peekable();
    let mut closed = false;
    let fetch_tasks = env_usize("TEMPO_CORPUS_FETCH_TASKS").unwrap_or(64);
    // Reserve whole read batches before opening scans, then transfer exact byte
    // permits to individual ready records. No task acquires a second reservation
    // while retaining its first, including when a record fills the entire budget.
    let total = budget.available_permits();
    let batch_limit = total.min(8 * 1024 * 1024);
    loop {
        eyre::ensure!(!cancellation.is_cancelled(), "corpus replay cancelled");
        while tasks.len() < fetch_tasks {
            while records.next_if(|(_, selected)| !selected).is_some() {}
            let Some(first) = records.next() else { break };
            let (mut end, mut bytes, mut skipped) = (first.0.number + 1, first.0.bytes, 0);
            let (mut batch, mut kept) = (vec![first], (1, bytes));
            // Batches never span pages, so an unfiltered page under the byte limit is one
            // scan task; read parallelism comes from pages in flight under the byte budget.
            while let Some(next) = records.next_if(|(next, selected)| {
                next.number == end
                    && bytes + next.bytes <= batch_limit
                    && (*selected || skipped < MAX_SKIPPED_RUN)
            }) {
                (end, bytes) = (next.0.number + 1, bytes + next.0.bytes);
                skipped = if next.1 { 0 } else { skipped + 1 };
                batch.push(next);
                if batch.last().is_some_and(|(_, selected)| *selected) {
                    kept = (batch.len(), bytes);
                }
            }
            // Never read the unselected tail.
            batch.truncate(kept.0);
            bytes = kept.1;
            // A batch over the limit is a single record; one over the whole budget would wait
            // for permits that never exist.
            eyre::ensure!(
                bytes <= total,
                "corpus record of {bytes} bytes exceeds the {total}-byte replay budget (TEMPO_CORPUS_BUDGET_MIB)"
            );
            let permits = u32::try_from(bytes)?;
            let sender = sender.clone();
            let reader = reader.clone();
            let budget = budget.clone();
            let space = space.clone();
            tasks.spawn(async move {
                let waiting = Instant::now();
                let mut reservation = budget.acquire_many_owned(permits).await?;
                let budget_wait = waiting.elapsed();
                let mut queue_wait = Duration::ZERO;
                let mut payloads =
                    store::PayloadScan::open(&reader, &batch[0].0, &batch[batch.len() - 1].0)
                        .await?;
                for (record, selected) in batch {
                    let (block, cases) = payloads.next(&record).await?;
                    let permit = reservation.split(record.bytes).expect("batch sum reserved");
                    if !selected {
                        continue;
                    }
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
                    target: "tempo::corpus::feed",
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
    let mut bounds = [0; 2];
    for (bound, ordinal) in bounds.iter_mut().zip([from, to - 1]) {
        let (mut low, mut high) = (catalog.context.start, catalog.cursor.next);
        // Metadata of the final `high`: the first block whose ordinals end after `ordinal`.
        let mut found = None;
        while low < high {
            let mid = low + (high - low) / 2;
            let record = store::metadata(reader, mid).await?;
            let end = record
                .first_tx
                .checked_add(record.transactions)
                .ok_or_eyre("ordinal overflow")?;
            if end <= ordinal {
                low = mid + 1;
            } else {
                high = mid;
                found = Some(record);
            }
        }
        let record = found.ok_or_eyre("missing transaction metadata")?;
        eyre::ensure!(
            record.first_tx <= ordinal,
            "transaction ordinal metadata gap"
        );
        *bound = low;
    }
    Ok(bounds[0]..bounds[1] + 1)
}

#[expect(clippy::too_many_arguments, reason = "the replay pipeline settings")]
async fn feed_catalog(
    reader: &Arc<DbReader>,
    catalog: &Catalog,
    range: Range<u64>,
    standalone: Option<(u64, u64)>,
    blocks: Option<&[u64]>,
    sender: Sender<Ready>,
    budget: Arc<Semaphore>,
    cancellation: &CancellationToken,
) -> eyre::Result<(u64, u64, u64)> {
    // One pool spans the entire range, so a slow payload batch cannot stall
    // unrelated reads at a metadata page boundary.
    let mut tasks = JoinSet::new();
    let (pages, receiver) = mpsc::channel(1);
    let result = tokio::try_join!(
        read_catalog(
            reader,
            catalog,
            range,
            standalone,
            blocks,
            pages,
            cancellation
        ),
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
    blocks: Option<&[u64]>,
    pages: mpsc::Sender<Vec<(Record, bool)>>,
    cancellation: &CancellationToken,
) -> eyre::Result<(u64, u64, u64)> {
    // A block list reads only the metadata around its blocks: each block carries its own
    // witness and expectations, so the stretches between them need no coverage check.
    let spans = blocks.map_or_else(|| vec![range.clone()], spans);
    let totals = futures::stream::iter(spans)
        .map(|span| {
            read_span(
                reader,
                catalog,
                span,
                standalone,
                blocks,
                &pages,
                cancellation,
            )
        })
        .buffer_unordered(METADATA_SPANS)
        .try_fold((0, 0, 0), |a, b| async move {
            Ok((a.0 + b.0, a.1 + b.1, a.2 + b.2))
        })
        .await?;
    eyre::ensure!(
        standalone.is_some()
            || totals.0 == blocks.map_or(range.end - range.start, |blocks| blocks.len() as u64),
        "metadata block coverage mismatch"
    );
    Ok(totals)
}

/// The block ranges whose metadata a replay of the sorted `blocks` reads: runs of them with
/// gaps of at most `MAX_SKIPPED_RUN` blocks.
fn spans(blocks: &[u64]) -> Vec<Range<u64>> {
    let mut spans = Vec::<Range<u64>>::new();
    for &block in blocks {
        match spans.last_mut() {
            Some(span) if block - span.end <= MAX_SKIPPED_RUN as u64 => span.end = block + 1,
            _ => spans.push(block..block + 1),
        }
    }
    spans
}

/// Sends the metadata of `span` in pages, each record marked with whether to replay it, and
/// checks it covers the span exactly. Returns the selected blocks, transactions and gas.
async fn read_span(
    reader: &DbReader,
    catalog: &Catalog,
    span: Range<u64>,
    standalone: Option<(u64, u64)>,
    blocks: Option<&[u64]>,
    pages: &mpsc::Sender<Vec<(Record, bool)>>,
    cancellation: &CancellationToken,
) -> eyre::Result<(u64, u64, u64)> {
    let cursor = store::cursor_at(reader, &catalog.context, span.start).await?;
    let initial_tx = cursor.tx;
    let (mut totals, mut covered) = ((0, 0, 0), 0);
    let mut metadata = store::MetadataPages::open(reader, cursor, span.end).await?;
    while metadata.cursor.next < span.end {
        // Reserve before reading: at most one queued metadata page per span in flight,
        // in addition to the current page and descriptors owned by bounded tasks.
        let slot = pages.reserve().await?;
        eyre::ensure!(!cancellation.is_cancelled(), "metadata read cancelled");
        let mut page = metadata.next_page().await?;
        // Coverage of the skipped blocks is still checked as their metadata is read.
        covered += page.iter().map(|r| r.transactions).sum::<u64>();
        if let Some((from, to)) = standalone {
            page.retain(|r| {
                r.transactions > 0 && r.first_tx < to && r.first_tx + r.transactions > from
            });
        }
        let page: Vec<_> = page
            .into_iter()
            .map(|r| {
                let selected = blocks.is_none_or(|blocks| blocks.binary_search(&r.number).is_ok());
                (r, selected)
            })
            .collect();
        for (record, _) in page.iter().filter(|(_, selected)| *selected) {
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
    if span.end == catalog.cursor.next {
        eyre::ensure!(cursor == catalog.cursor, "final metadata boundary mismatch");
    } else {
        let next = store::metadata(reader, span.end).await?;
        eyre::ensure!(
            cursor.parent == next.parent && cursor.tx == next.first_tx,
            "metadata boundary mismatch"
        );
    }
    eyre::ensure!(
        covered == cursor.tx - initial_tx
            && (blocks.is_some() || totals.1 == standalone.map_or(covered, |(from, to)| to - from)),
        "metadata transaction coverage mismatch"
    );
    Ok(totals)
}

/// Parses a `usize` tuning override from the environment; unset or invalid means `None`.
fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

/// Decodes a published block, its checked transaction records and its phase expectations.
fn decode_record<'a>(
    input: &'a Input,
    cases: &[Bytes],
    record: &Record,
) -> eyre::Result<(Vec<Case>, RecoveredBlock<Block>, &'a Phases)> {
    eyre::ensure!(
        cases.len() == record.cases.len(),
        "transaction count mismatch"
    );
    let cases = cases
        .iter()
        .zip(&record.cases)
        .enumerate()
        .map(|(i, (bytes, expected))| {
            store::decode_case(bytes, expected, record.first_tx + i as u64)
        })
        .collect::<eyre::Result<_>>()?;
    let block = decode_block(&input.block, input.number, B256::from(input.parent))?;
    let phases = input
        .phases
        .as_ref()
        .ok_or_eyre("missing phase expectations")?;
    Ok((cases, block, phases))
}

/// Verifies one published block: executes it from its record alone and checks every
/// transaction against its stored record, consensus rules and the historical changesets.
pub fn verify(
    config: &TempoEvmConfig,
    consensus: &TempoConsensus,
    input: &Arc<Input>,
    cases: &[Bytes],
    record: &Record,
) -> eyre::Result<()> {
    let (expected, block, phases) = decode_record(input, cases, record)?;
    let executed = execute_block(
        config,
        consensus,
        View::new(input.clone()),
        &block,
        record.first_tx,
        Some((&expected, phases)),
    )?;
    verify_changesets(&executed.bundle, &input.changeset()?, input.number)?;
    eyre::ensure!(
        executed.transactions.len() as u64 == record.transactions && executed.gas == record.gas,
        "transaction/gas totals mismatch"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_merge_blocks_across_short_gaps() {
        let far = 2 + MAX_SKIPPED_RUN as u64;
        assert_eq!(spans(&[]), []);
        assert_eq!(
            spans(&[1, 2, far, far + 1 + MAX_SKIPPED_RUN as u64 + 1]),
            [
                1..far + 1,
                far + MAX_SKIPPED_RUN as u64 + 2..far + MAX_SKIPPED_RUN as u64 + 3
            ]
        );
    }
}
