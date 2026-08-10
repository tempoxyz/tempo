//! Build a dump-only golden flat checkpoint from a TEMPOSB state-bloat file.
//!
//! Memory-safe at 1B slots (two prior attempts OOM'd a 62 GB box):
//! - Phase 1 splits the dump into one raw (hashed_slot, value) file per
//!   account; skipped if split files from a previous attempt exist.
//! - Phase 2 loads each account's rows as fixed-width 64-byte entries (one
//!   flat allocation — 250M individual `Vec<u8>` values cost ~14 GB of heap
//!   overhead alone), sorts, and seeds in sorted disjoint 25M-slot ranges so
//!   each storage subtree region is written once and the per-range conversion
//!   buffer stays ~2 GB. RAM-build spills between inserts.
//!
//!   MPT_RAM_BUILD_GIB=24 cargo run --release -p tempo-flatmpt \
//!       --example build_golden -- <dump.bin> <out.flat>

use alloy_primitives::{U256, keccak256};
use mpt_flat_poc::{AccountSeed, Config, FlatMpt, Key};
use std::{
    collections::HashMap,
    io::{Read as _, Write as _},
    time::Instant,
};

const RANGE: usize = 25_000_000;

fn main() -> anyhow::Result<()> {
    let dump = std::env::args().nth(1).expect("dump path");
    let out = std::env::args().nth(2).expect("output flat path");
    let t0 = Instant::now();

    let keys = match existing_split_keys(&out)? {
        Some(keys) => {
            eprintln!("reusing {} existing split files", keys.len());
            keys
        }
        None => split_dump(&dump, &out, t0)?,
    };
    seed(&out, keys, t0)
}

/// Keys of split files left by a previous attempt, if any.
fn existing_split_keys(out: &str) -> anyhow::Result<Option<Vec<Key>>> {
    let path = std::path::Path::new(out);
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let prefix = format!("{}.split.", path.file_name().unwrap().to_str().unwrap());
    let mut keys = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name().into_string().unwrap_or_default();
        if let Some(hex_part) = name.strip_prefix(&prefix) {
            anyhow::ensure!(hex_part.len() == 64, "bad split file name {name}");
            let mut k = [0u8; 32];
            for i in 0..32 {
                k[i] = u8::from_str_radix(&hex_part[i * 2..i * 2 + 2], 16)?;
            }
            keys.push(k);
        }
    }
    Ok(if keys.is_empty() { None } else { Some(keys) })
}

/// Split the TEMPOSB dump into one raw 64-byte-row file per account.
fn split_dump(dump: &str, out: &str, t0: Instant) -> anyhow::Result<Vec<Key>> {
    let mut f = std::io::BufReader::with_capacity(128 << 20, std::fs::File::open(dump)?);
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
            if U256::from_be_slice(&pair[32..64]) == U256::ZERO {
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
    eprintln!(
        "split {} pairs into {} accounts in {:.0}s",
        total,
        keys.len(),
        t0.elapsed().as_secs_f64()
    );
    Ok(keys)
}

/// Seed each account from its split file in sorted disjoint ranges.
fn seed(out: &str, keys: Vec<Key>, t0: Instant) -> anyhow::Result<()> {
    for suffix in ["", ".meta", ".meta.prev"] {
        let _ = std::fs::remove_file(format!("{out}{suffix}"));
    }
    let mut db = FlatMpt::create_ram_build(out, Config::default())?;
    let mut total: u64 = 0;
    for key in keys {
        let split_path = format!("{}.split.{}", out, mpt_flat_poc::hex(key));
        // Stream the file into the row vector — reading it whole first doubles
        // the peak (16 GB file + 16 GB rows) and OOM'd on top of trie residue.
        let mut rows: Vec<[u8; 64]> = {
            let len = std::fs::metadata(&split_path)?.len();
            anyhow::ensure!(len % 64 == 0, "truncated split file");
            let mut r =
                std::io::BufReader::with_capacity(64 << 20, std::fs::File::open(&split_path)?);
            let mut rows = Vec::with_capacity((len / 64) as usize);
            let mut row = [0u8; 64];
            for _ in 0..len / 64 {
                r.read_exact(&mut row)?;
                rows.push(row);
            }
            rows
        };
        rows.sort_unstable_by(|a, b| a[0..32].cmp(&b[0..32]));
        let n = rows.len();
        total += n as u64;
        let t = Instant::now();
        for range in rows.chunks(RANGE) {
            let slots: Vec<(Key, Vec<u8>)> = range
                .iter()
                .map(|row| {
                    let mut k = [0u8; 32];
                    k.copy_from_slice(&row[0..32]);
                    (
                        k,
                        mpt_flat_poc::eth::storage_value_rlp(U256::from_be_slice(&row[32..64])),
                    )
                })
                .collect();
            db.insert_batch_accounts(vec![(
                key,
                AccountSeed {
                    nonce: 0,
                    balance: U256::ZERO,
                    code_hash: mpt_flat_poc::eth::EMPTY_CODE_HASH.0,
                    slots,
                },
            )])?;
            eprintln!(
                "  range done, footprint {:.1} GiB",
                mpt_flat_poc::process_footprint_bytes() as f64 / (1u64 << 30) as f64,
            );
        }
        drop(rows);
        eprintln!(
            "seeded account {} ({} slots) in {:.0}s (cum {:.0}s)",
            mpt_flat_poc::hex(key),
            n,
            t.elapsed().as_secs_f64(),
            t0.elapsed().as_secs_f64(),
        );
        let _ = std::fs::remove_file(&split_path);
    }
    db.persist()?;
    println!(
        "golden built: {total} slots, root {}, {:.0}s",
        mpt_flat_poc::hex(db.root()),
        t0.elapsed().as_secs_f64()
    );
    Ok(())
}
