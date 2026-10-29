use std::path::PathBuf;

use flux::{
    spine::{DCacheRead, SpineAdapter},
    tile::Tile,
};
use flux_disk::{DiskEvent, DiskIo, FileToken, OpenOptions};
use rustc_hash::FxHashMap;
use tempo_flux_primitives::{Block, Finalized, Persisted};

use crate::{now_ns, spine::NodeSpine};

/// Appends finalized blocks to a log with io_uring, and reports throughput
/// and ingress-to-durable latency.
pub struct StorageTile {
    path: PathBuf,
    disk: DiskIo,
    file: Option<FileToken>,
    bodies: FxHashMap<u64, (Block, Vec<u8>)>,
    waiting: Vec<Finalized>,
    unsynced: Vec<(u64, u32, u64)>,
    stop_after_ns: Option<u64>,
    start_ns: u64,
    last_report_ns: u64,
    txs_since_report: u64,
    latencies_us: Vec<u64>,
    pub total_txs: u64,
    pub height: u64,
}

impl StorageTile {
    pub fn new(path: PathBuf, stop_after_secs: Option<u64>) -> Self {
        Self {
            path,
            disk: DiskIo::default(),
            file: None,
            bodies: FxHashMap::default(),
            waiting: Vec::new(),
            unsynced: Vec::new(),
            stop_after_ns: stop_after_secs.map(|s| s * 1_000_000_000),
            start_ns: 0,
            last_report_ns: 0,
            txs_since_report: 0,
            latencies_us: Vec::new(),
            total_txs: 0,
            height: 0,
        }
    }

    fn report(&mut self, now: u64) {
        let elapsed = (now - self.last_report_ns) as f64 / 1e9;
        self.latencies_us.sort_unstable();
        let pct = |p: f64| {
            if self.latencies_us.is_empty() {
                0.0
            } else {
                let i = ((self.latencies_us.len() as f64 - 1.0) * p) as usize;
                self.latencies_us[i] as f64 / 1000.0
            }
        };
        tracing::info!(
            height = self.height,
            tps = format!("{:.0}", self.txs_since_report as f64 / elapsed),
            p50_ms = format!("{:.2}", pct(0.5)),
            p99_ms = format!("{:.2}", pct(0.99)),
            max_ms = format!("{:.2}", pct(1.0)),
            "persisted"
        );
        self.latencies_us.clear();
        self.txs_since_report = 0;
        self.last_report_ns = now;
    }
}

impl Tile<NodeSpine> for StorageTile {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<NodeSpine>) -> bool {
        let opts = OpenOptions::new().write(true).create(true).truncate(true);
        self.file = Some(self.disk.open(&self.path, opts).expect("open block log"));
        self.start_ns = now_ns();
        self.last_report_ns = self.start_ns;
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let bodies = &mut self.bodies;
        adapter.consume_with_dcache::<Block, Vec<u8>, _, _>(
            |_, payload| payload.to_vec(),
            |res, _| match res {
                DCacheRead::Ok((b, payload)) => {
                    bodies.insert(b.height, (b, payload));
                }
                DCacheRead::NoRef(b) => {
                    bodies.insert(b.height, (b, Vec::new()));
                }
                _ => tracing::error!("storage lost a block body"),
            },
        );

        let file = self.file.expect("opened in try_init");
        let mut finalized = std::mem::take(&mut self.waiting);
        adapter.consume(|f: Finalized, _| finalized.push(f));
        let mut wrote = false;
        for f in finalized {
            // The body can still be unread in its queue; retry next loop.
            let Some((block, payload)) = self.bodies.remove(&f.height) else {
                self.waiting.push(f);
                continue;
            };
            self.disk.write_with(file, |buf| {
                buf.extend_from_slice(&block.height.to_le_bytes());
                buf.extend_from_slice(&block.hash);
                buf.extend_from_slice(&f.state_root);
                buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                buf.extend_from_slice(&payload);
            });
            self.unsynced
                .push((f.height, f.tx_count, f.oldest_ingress_ns));
            wrote = true;
        }
        if wrote {
            let _ = self.disk.sync_data(file);
        }

        let mut synced = false;
        self.disk.poll_with(|ev| match ev {
            DiskEvent::Synced { .. } => synced = true,
            DiskEvent::Failed { op, error, .. } => panic!("block log {op:?}: {error}"),
            _ => {}
        });
        if synced {
            let now = now_ns();
            for (height, tx_count, oldest) in self.unsynced.drain(..) {
                if oldest != 0 {
                    self.latencies_us.push((now - oldest) / 1000);
                }
                self.txs_since_report += u64::from(tx_count);
                self.total_txs += u64::from(tx_count);
                self.height = height;
                adapter.produce(Persisted { height });
            }
        }

        let now = now_ns();
        if now - self.last_report_ns >= 1_000_000_000 {
            self.report(now);
        }
        if self.stop_after_ns.is_some_and(|d| now - self.start_ns >= d) {
            tracing::info!(height = self.height, total_txs = self.total_txs, "stopping");
            adapter.request_stop_scope();
        }
    }
}
