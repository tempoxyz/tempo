//! Build a dump-only golden flat checkpoint from a TEMPOSB state-bloat file.
//!
//! Two-phase to respect RAM-build's insert-once design (spilled subtrees must
//! not be revisited — re-seeding the same account across batches re-promotes
//! its mega-subtree and OOMs): (1) split the dump into one raw slot file per
//! account, (2) seed each account exactly once with its full sorted slot set,
//! letting the engine spill between accounts.
//!
//!   MPT_RAM_BUILD_GIB=26 cargo run --release -p tempo-flatmpt \
//!       --example build_golden -- <dump.bin> <out.flat>

use alloy_primitives::{keccak256, U256};
use mpt_flat_poc::{AccountSeed, Config, FlatMpt, Key};
use std::collections::HashMap;
use std::io::{Read as _, Write as _};

fn main() -> anyhow::Result<()> {
    let dump = std::env::args().nth(1).expect("dump path");
    let out = std::env::args().nth(2).expect("output flat path");
    for suffix in ["", ".meta", ".meta.prev"] {
        let _ = std::fs::remove_file(format!("{out}{suffix}"));
    }
    let t0 = std::time::Instant::now();

    // Phase 1: split into per-account files of raw (hashed_slot, value) pairs.
    let mut f = std::io::BufReader::with_capacity(128 << 20, std::fs::File::open(&dump)?);
    let mut header = [0u8; 40];
    let mut writers: HashMap<Key, std::io::BufWriter<std::fs::File>> = HashMap::new();
    let mut total: u64 = 0;
    loop {
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        anyhow::ensure!(&header[0..8] == b"TEMPOSB\0", "bad magic");
        let key: Key = keccak256(&header[12..32]).0;
        let pair_count = u64::from_be_bytes(header[32..40].try_into().unwrap());
        let w = writers.entry(key).or_insert_with(|| {
            std::io::BufWriter::with_capacity(
                32 << 20,
                std::fs::File::create(format!("{out}.split.{}", mpt_flat_poc::hex(key))).unwrap(),
            )
        });
        let mut pair = [0u8; 64];
        for _ in 0..pair_count {
            f.read_exact(&mut pair)?;
            let value = U256::from_be_slice(&pair[32..64]);
            if value == U256::ZERO {
                continue;
            }
            w.write_all(&keccak256(&pair[0..32]).0)?;
            w.write_all(&pair[32..64])?;
            total += 1;
        }
    }
    let keys: Vec<Key> = writers.keys().copied().collect();
    for (_, mut w) in writers {
        w.flush()?;
    }
    eprintln!("split {} pairs into {} accounts in {:.0}s", total, keys.len(), t0.elapsed().as_secs_f64());

    // Phase 2: seed each account once with its full sorted slot set.
    let mut db = FlatMpt::create_ram_build(&out, Config::default())?;
    for key in keys {
        let split_path = format!("{}.split.{}", out, mpt_flat_poc::hex(key));
        let data = std::fs::read(&split_path)?;
        let mut slots: Vec<(Key, Vec<u8>)> = data
            .chunks_exact(64)
            .map(|c| {
                let mut k = [0u8; 32];
                k.copy_from_slice(&c[0..32]);
                (k, mpt_flat_poc::eth::storage_value_rlp(U256::from_be_slice(&c[32..64])))
            })
            .collect();
        drop(data);
        slots.sort_by(|a, b| a.0.cmp(&b.0));
        let n = slots.len();
        let t = std::time::Instant::now();
        db.insert_batch_accounts(vec![(key, AccountSeed {
            nonce: 0,
            balance: U256::ZERO,
            code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
            slots,
        })])?;
        eprintln!(
            "seeded account {} ({} slots) in {:.0}s (cum {:.0}s, footprint {:.1} GiB)",
            mpt_flat_poc::hex(key), n, t.elapsed().as_secs_f64(), t0.elapsed().as_secs_f64(),
            mpt_flat_poc::process_footprint_bytes() as f64 / (1u64 << 30) as f64,
        );
        let _ = std::fs::remove_file(&split_path);
    }
    db.persist()?;
    println!("golden built: {total} slots, root {}, {:.0}s", mpt_flat_poc::hex(db.root()), t0.elapsed().as_secs_f64());
    Ok(())
}
