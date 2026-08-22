//! Offline divergence replay: reopen a flat file at its persisted checkpoint,
//! apply TEMPO_FLATMPT_DUMP_OPS dumps in block order, and print the flat root
//! after each block next to the root the sparse commitment claimed at capture
//! time. Sibling candidates at one height are applied and rolled back via the
//! inverse diffs, so every disputed root gets an independent flat verdict.
//!
//!   cargo run -p tempo-flatmpt --release --example replay_dumps -- \
//!       <flat-path> <dump-dir>
//!
//! Appends land beyond the checkpoint's allocator high-water and are never
//! persisted, so the on-disk checkpoint remains valid afterwards.

use mpt_flat_poc::{FlatMpt, Key, StateOp};

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

type Dump = (u64, alloy_primitives::B256, Vec<(Key, StateOp)>, alloy_primitives::B256);

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let flat = args.next().expect("usage: replay_dumps <flat-path> <dump-dir>");
    let dir = args.next().expect("usage: replay_dumps <flat-path> <dump-dir>");

    let mut db = FlatMpt::open(&flat)?;
    println!("opened {flat} at root {}", hex32(&db.root()));

    let mut files: Vec<_> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("ops-") && n.ends_with(".bin"))
        })
        .collect();
    files.sort();

    // One entry per (block, expected_root): the per-pid duplicates are
    // bit-identical in parent and ops (verified by the capture run).
    let mut seen: std::collections::HashSet<(u64, [u8; 32])> = Default::default();
    let mut by_block: std::collections::BTreeMap<u64, Vec<Dump>> = Default::default();
    for f in &files {
        let d: Dump = bincode::deserialize(&std::fs::read(f)?)?;
        let block = d.0 + 1;
        if seen.insert((block, d.3.0)) {
            by_block.entry(block).or_default().push(d);
        }
    }

    for (block, cands) in by_block {
        let multi = cands.len() > 1;
        for (parent_number, parent_root, ops, expected) in cands {
            // Block 1's dumped parent is the genesis HEADER root; in bloat
            // mode that is the pre-dump alloc root, aliased to the flat's
            // post-dump state (same escape unwind_to applies).
            let genesis_alias = block == 1;
            if db.root() != parent_root.0 && !genesis_alias {
                println!(
                    "block {block}: SKIP candidate exp={} (flat at {}, dump parent {})",
                    hex32(&expected.0),
                    hex32(&db.root()),
                    hex32(&parent_root.0)
                );
                continue;
            }
            let (root, inverse) = db.apply_block(ops.clone())?;
            let verdict = if root == expected.0 { "MATCH" } else { "*** DIVERGES ***" };
            println!(
                "block {block} (parent {parent_number}): flat={} sparse-claimed={} {}",
                hex32(&root),
                hex32(&expected.0),
                verdict
            );
            if multi {
                // Roll back so the sibling candidate applies from the same parent.
                db.apply_block(inverse)?;
                println!("  rolled back to {}", hex32(&db.root()));
            }
        }
    }
    Ok(())
}
