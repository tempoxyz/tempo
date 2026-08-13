//! Replay TEMPO_FLATMPT_DUMP_OPS block dumps against a flat store copy and
//! report the first block whose engine root diverges from the recorded
//! sparse commitment.
//!
//!   cargo run --release -p tempo-flatmpt --example replay_ops -- <flat> <ops-dir> [start]

use alloy_primitives::B256;
use mpt_flat_poc::{FlatMpt, Key, StateOp};
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let flat = std::env::args().nth(1).expect("flat path");
    let dir = std::env::args().nth(2).expect("ops dir");
    let start: u64 = std::env::args()
        .nth(3)
        .map(|s| s.parse().unwrap())
        .unwrap_or(1);

    let mut db = FlatMpt::open(&flat).map_err(|e| anyhow::anyhow!("{e:#}"))?;
    eprintln!("opened {flat}, root {}", hex::encode(db.root()));

    // Apply the genesis alloc on top of the dump-only golden, as the node's
    // anchor does, so block 1's parent state matches.
    if let Ok(genesis_path) = std::env::var("REPLAY_GENESIS") {
        let genesis: alloy_genesis::Genesis =
            serde_json::from_str(&std::fs::read_to_string(&genesis_path)?)?;
        let ops = tempo_flatmpt::genesis_to_ops(&genesis);
        let n = ops.len();
        let (root, _) = db.apply_block(ops).map_err(|e| anyhow::anyhow!("{e:#}"))?;
        eprintln!(
            "genesis alloc applied ({n} ops), root {}",
            hex::encode(root)
        );
    }

    let mut files: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ops-"))
        })
        .collect();
    files.sort();

    for path in files {
        let bytes = std::fs::read(&path)?;
        let (parent_number, parent_root, ops, expected): (u64, B256, Vec<(Key, StateOp)>, B256) =
            bincode::deserialize(&bytes)?;
        let block = parent_number + 1;
        if block < start {
            continue;
        }
        if db.root() != parent_root.0 {
            eprintln!(
                "block {block}: PARENT MISMATCH live={} expected_parent={parent_root}",
                hex::encode(db.root())
            );
        }
        let t = Instant::now();
        let n = ops.len();
        let ops_copy = ops.clone();
        let (root, _inv) = db.apply_block(ops).map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let ms = t.elapsed().as_millis();
        // REPLAY_GC=1: run the follower's per-block gc pass (the live node
        // does; evacuation is the divergence suspect).
        if std::env::var("REPLAY_GC").as_deref() == Ok("1") {
            let t_gc = Instant::now();
            let evac = db.gc_step().map_err(|e| anyhow::anyhow!("gc: {e:#}"))?;
            // REPLAY_GC_STATS=1: per-block reclamation telemetry — is growth
            // contained when gc runs with no snapshot pins at all?
            if std::env::var("REPLAY_GC_STATS").as_deref() == Ok("1") {
                let sz = std::fs::metadata(&flat).map(|m| m.len()).unwrap_or(0);
                eprintln!(
                    "block {block}: gc evac={evac} gc_ms={} file_gb={:.2} util={:.3}",
                    t_gc.elapsed().as_millis(),
                    sz as f64 / 1e9,
                    db.utilization(),
                );
            }
            // REPLAY_AUDIT_FROM=N: full forensic audit after each gc pass
            // from block N on — the first unclean audit names the corrupting
            // pass and the exact record.
            if let Ok(from) = std::env::var("REPLAY_AUDIT_FROM")
                && block >= from.parse::<u64>().unwrap_or(u64::MAX)
            {
                let t_a = Instant::now();
                let audit = db.audit_hashes().map_err(|e| anyhow::anyhow!("{e:#}"))?;
                // Legacy golden records carry storage-relative prefixes;
                // bad_prefixes is expected on pre-composite files. Hash
                // consistency is the corruption oracle.
                let hash_clean = audit.bad_disk_roots == 0
                    && audit.bad_mem_roots == 0
                    && audit.stale_cells == 0
                    && audit.bad_record_nrefs == 0
                    && audit.bad_record_storage_roots == 0;
                eprintln!(
                    "block {block}: audit hash_clean={hash_clean} ({}s) {:?}",
                    t_a.elapsed().as_secs(),
                    if hash_clean { None } else { Some(&audit) }
                );
                if !hash_clean {
                    anyhow::bail!("audit hash-unclean after gc of block {block}");
                }
            }
        }
        let ok = root == expected.0;
        eprintln!(
            "block {block}: n_ops={n} apply_ms={ms} root={} {}",
            hex::encode(root),
            if ok { "ok" } else { "DIVERGED" }
        );
        if !ok {
            eprintln!("expected sparse root: {expected}");
            // Which side is right? If every op's value reads back exactly,
            // the flat state IS parent+ops and the flat root is the true
            // root — the recorded sparse root was computed incorrectly.
            let (mut checked, mut bad) = (0u64, 0u64);
            for (key, op) in &ops_copy {
                match op {
                    StateOp::SetStorage { slot, value } => {
                        let got = db
                            .get_storage(key, slot)
                            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                        checked += 1;
                        if got.as_deref() != Some(value.as_slice()) {
                            bad += 1;
                            if bad <= 5 {
                                eprintln!(
                                    "OP MISMATCH: key={} slot={} want={} got={:?}",
                                    hex::encode(&key[..8]),
                                    hex::encode(&slot[..8]),
                                    hex::encode(value),
                                    got.map(hex::encode)
                                );
                            }
                        }
                    }
                    StateOp::DeleteStorage { slot } => {
                        let got = db
                            .get_storage(key, slot)
                            .map_err(|e| anyhow::anyhow!("{e:#}"))?;
                        checked += 1;
                        if got.is_some() {
                            bad += 1;
                        }
                    }
                    _ => {}
                }
            }
            eprintln!("op read-back: {checked} checked, {bad} mismatched");
            anyhow::bail!("diverged at block {block}");
        }
    }
    eprintln!("replay complete, no divergence");
    Ok(())
}
