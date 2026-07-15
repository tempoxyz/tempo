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
    let start: u64 =
        std::env::args().nth(3).map(|s| s.parse().unwrap()).unwrap_or(1);

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
        eprintln!("genesis alloc applied ({n} ops), root {}", hex::encode(root));
    }

    let mut files: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("ops-")))
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
        let (root, _inv) = db.apply_block(ops).map_err(|e| anyhow::anyhow!("{e:#}"))?;
        let ms = t.elapsed().as_millis();
        let ok = root == expected.0;
        eprintln!(
            "block {block}: n_ops={n} apply_ms={ms} root={} {}",
            hex::encode(root),
            if ok { "ok" } else { "DIVERGED" }
        );
        if !ok {
            eprintln!("expected sparse root: {expected}");
            anyhow::bail!("diverged at block {block}");
        }
    }
    eprintln!("replay complete, no divergence");
    Ok(())
}
