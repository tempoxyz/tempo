//! Build a dump-only golden flat checkpoint from a TEMPOSB state-bloat file,
//! streaming in bounded batches (merge semantics: repeated seeds add slots).
//! Accounts get default fields — the per-leg genesis overlay sets the real
//! ones (and wins slot collisions).
//!
//!   MPT_RAM_BUILD_GIB=30 cargo run --release -p tempo-flatmpt \
//!       --example build_golden -- <dump.bin> <out.flat>

use alloy_primitives::{keccak256, U256};
use mpt_flat_poc::{AccountSeed, Config, FlatMpt, Key};
use std::collections::HashMap;
use std::io::Read as _;

const FLUSH_PAIRS: usize = 48_000_000;

fn main() -> anyhow::Result<()> {
    let dump = std::env::args().nth(1).expect("dump path");
    let out = std::env::args().nth(2).expect("output flat path");
    for suffix in ["", ".meta", ".meta.prev"] {
        let _ = std::fs::remove_file(format!("{out}{suffix}"));
    }
    let mut db = FlatMpt::create_ram_build(&out, Config::default())?;
    let mut f = std::io::BufReader::with_capacity(128 << 20, std::fs::File::open(&dump)?);
    let mut header = [0u8; 40];
    let mut acc: HashMap<Key, Vec<(Key, Vec<u8>)>> = HashMap::new();
    let mut pending: usize = 0;
    let mut total: u64 = 0;
    let t0 = std::time::Instant::now();

    let mut flush = |acc: &mut HashMap<Key, Vec<(Key, Vec<u8>)>>, db: &mut FlatMpt, total: u64| -> anyhow::Result<()> {
        let mut batch: Vec<(Key, AccountSeed)> = acc
            .drain()
            .map(|(key, mut slots)| {
                slots.sort_by(|a, b| a.0.cmp(&b.0));
                (key, AccountSeed {
                    nonce: 0,
                    balance: U256::ZERO,
                    code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
                    slots,
                })
            })
            .collect();
        batch.sort_by(|a, b| a.0.cmp(&b.0));
        let t = std::time::Instant::now();
        db.insert_batch_accounts(batch)?;
        eprintln!("flushed at {total} pairs in {:.0}s (cum {:.0}s)", t.elapsed().as_secs_f64(), t0.elapsed().as_secs_f64());
        Ok(())
    };

    loop {
        match f.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        anyhow::ensure!(&header[0..8] == b"TEMPOSB\0", "bad magic");
        let key: Key = keccak256(&header[12..32]).0;
        let pair_count = u64::from_be_bytes(header[32..40].try_into().unwrap());
        let slots = acc.entry(key).or_default();
        let mut pair = [0u8; 64];
        for _ in 0..pair_count {
            f.read_exact(&mut pair)?;
            let value = U256::from_be_slice(&pair[32..64]);
            if value == U256::ZERO {
                continue;
            }
            slots.push((keccak256(&pair[0..32]).0, mpt_flat_poc::eth::storage_value_rlp(value)));
            pending += 1;
            total += 1;
        }
        if pending >= FLUSH_PAIRS {
            flush(&mut acc, &mut db, total)?;
            pending = 0;
        }
    }
    flush(&mut acc, &mut db, total)?;
    db.persist()?;
    println!("golden built: {total} slots, root {}, {:.0}s", mpt_flat_poc::hex(db.root()), t0.elapsed().as_secs_f64());
    Ok(())
}
