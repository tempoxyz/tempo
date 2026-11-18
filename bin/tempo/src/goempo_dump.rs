//! tempo goempo-dump <datadir> <out> [chain]: exports the latest state of a
//! reth datadir with raw (unhashed) keys, for goempo to import.
//!
//! Storage v2 datadirs keep only hashed state, so raw addresses and slots are
//! recovered from the genesis alloc and every account and storage changeset
//! (changesets keep plain keys). Every hashed entry must resolve, or the dump
//! fails.
//!
//! Format (big-endian): "GOEMPOD1", block u64, block hash 32, state root 32,
//! then records: 'C' code_hash 32, len u32, code; 'A' address 20, nonce u64,
//! balance 32, code_hash 32, slots u32, then slots x (slot 32, value 32);
//! and finally 'E', accounts u64, slots u64, codes u64.

use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

use alloy_primitives::{Address, B256, U256, keccak256};
use eyre::{Context as _, ensure};
use reth_chainspec::EthChainSpec as _;
use reth_cli_runner::CliRunner;
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    tables,
    transaction::DbTx,
};
use reth_primitives_traits::Account;
use reth_provider::providers::ReadOnlyConfig;
use reth_storage_api::{
    BlockNumReader, ChangeSetReader, DBProvider, HeaderProvider, StorageChangeSetReader,
    StorageSettingsCache,
};
use tempo_chainspec::spec::chain_value_parser;
use tempo_node::node::TempoNode;

const RANGE: u64 = 250_000;
const EMPTY_CODE: B256 =
    alloy_primitives::b256!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

pub(crate) fn run(args: &[String]) -> eyre::Result<()> {
    ensure!(args.len() >= 2, "usage: tempo goempo-dump <datadir> <out> [chain]");
    let datadir = PathBuf::from(&args[0]);
    let out = PathBuf::from(&args[1]);
    let chain = args.get(2).map(String::as_str).unwrap_or("mainnet");
    let spec = chain_value_parser(chain)?;
    let runner = CliRunner::try_default_runtime().wrap_err("runtime")?;
    let factory = TempoNode::provider_factory_builder()
        .open_read_only(Arc::clone(&spec), ReadOnlyConfig::from_datadir(&datadir), runner.runtime())
        .wrap_err("open datadir")?;
    let provider = factory.provider()?;
    let hashed = provider.cached_storage_settings().use_hashed_state();
    let best = provider.best_block_number()?;
    let header = provider.sealed_header(best)?.ok_or_else(|| eyre::eyre!("no header {best}"))?;
    let root = header.header().inner.state_root;
    eprintln!("goempo-dump: block {best} hash {} root {root} hashed_state {hashed}", header.hash());
    ensure!(hashed, "datadir keeps plain state; this dumper reads hashed state only");

    let started = Instant::now();
    let mut accounts: HashSet<Address> = HashSet::new();
    let mut slots: HashMap<Address, HashSet<B256>> = HashMap::new();
    for (addr, acc) in &spec.genesis().alloc {
        accounts.insert(*addr);
        if let Some(st) = &acc.storage {
            slots.entry(*addr).or_default().extend(st.keys().copied());
        }
    }
    let mut from = 0u64;
    let (mut acs, mut scs) = (0u64, 0u64);
    while from <= best {
        let to = (from + RANGE - 1).min(best);
        for (_, a) in provider.account_changesets_range(from..=to)? {
            accounts.insert(a.address);
            acs += 1;
        }
        for (ba, e) in provider.storage_changesets_range(from..=to)? {
            slots.entry(ba.address()).or_default().insert(e.key);
            scs += 1;
        }
        if (to + 1) % 5_000_000 < RANGE || to == best {
            eprintln!(
                "goempo-dump: changesets to {to}: {acs} account rows, {scs} storage rows, {} addresses, {:?}",
                accounts.len(),
                started.elapsed()
            );
        }
        from = to + 1;
    }
    for a in slots.keys() {
        accounts.insert(*a);
    }
    let by_hash: HashMap<B256, Address> = accounts.iter().map(|a| (keccak256(a), *a)).collect();
    eprintln!("goempo-dump: {} address preimages, {:?}", by_hash.len(), started.elapsed());

    let tx = provider.tx_ref();
    let mut w = BufWriter::with_capacity(16 << 20, File::create(&out)?);
    w.write_all(b"GOEMPOD1")?;
    w.write_all(&best.to_be_bytes())?;
    w.write_all(header.hash().as_slice())?;
    w.write_all(root.as_slice())?;

    let mut codes = 0u64;
    let mut cur = tx.cursor_read::<tables::Bytecodes>()?;
    let mut entry = cur.first()?;
    while let Some((h, code)) = entry {
        let raw = code.original_bytes();
        ensure!(keccak256(&raw) == h, "bytecode {h} does not hash to its key");
        w.write_all(b"C")?;
        w.write_all(h.as_slice())?;
        w.write_all(&(raw.len() as u32).to_be_bytes())?;
        w.write_all(&raw)?;
        codes += 1;
        entry = cur.next()?;
    }
    eprintln!("goempo-dump: {codes} codes");

    let mut acur = tx.cursor_read::<tables::HashedAccounts>()?;
    let mut scur = tx.cursor_dup_read::<tables::HashedStorages>()?;
    let (mut n_acc, mut n_slots, mut miss_acc, mut miss_slots, mut orphan) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut buf: Vec<(B256, U256)> = Vec::new();
    let mut entry = acur.first()?;
    while let Some((ha, acc)) = entry {
        entry = acur.next()?;
        let Some(addr) = by_hash.get(&ha).copied() else {
            miss_acc += 1;
            continue;
        };
        buf.clear();
        if let Some(first) = scur.seek_exact(ha)?.map(|(_, v)| v) {
            let pre: HashMap<B256, B256> = slots
                .get(&addr)
                .map(|s| s.iter().map(|k| (keccak256(k), *k)).collect())
                .unwrap_or_default();
            let mut e = Some(first);
            while let Some(se) = e {
                match pre.get(&se.key) {
                    Some(k) if !se.value.is_zero() => buf.push((*k, se.value)),
                    Some(_) => {}
                    None => miss_slots += 1,
                }
                e = scur.next_dup()?.map(|(_, v)| v);
            }
        }
        write_account(&mut w, addr, &acc, &buf)?;
        n_acc += 1;
        n_slots += buf.len() as u64;
        if n_acc % 1_000_000 == 0 {
            eprintln!("goempo-dump: {n_acc} accounts, {n_slots} slots, {:?}", started.elapsed());
        }
    }
    // Storage under a hashed address with no account row would be lost.
    let mut se = scur.first()?;
    let mut last: Option<B256> = None;
    while let Some((ha, _)) = se {
        if last != Some(ha) {
            if acur.seek_exact(ha)?.is_none() {
                orphan += 1;
            }
            last = Some(ha);
        }
        se = scur.next_no_dup()?;
    }
    w.write_all(b"E")?;
    w.write_all(&n_acc.to_be_bytes())?;
    w.write_all(&n_slots.to_be_bytes())?;
    w.write_all(&codes.to_be_bytes())?;
    w.flush()?;
    eprintln!(
        "goempo-dump: done in {:?}: {n_acc} accounts, {n_slots} slots, {codes} codes; unresolved {miss_acc} accounts, {miss_slots} slots, {orphan} storage-only addresses",
        started.elapsed()
    );
    ensure!(miss_acc == 0 && miss_slots == 0 && orphan == 0, "dump is incomplete");
    Ok(())
}

fn write_account(
    w: &mut impl Write,
    addr: Address,
    acc: &Account,
    slots: &[(B256, U256)],
) -> eyre::Result<()> {
    w.write_all(b"A")?;
    w.write_all(addr.as_slice())?;
    w.write_all(&acc.nonce.to_be_bytes())?;
    w.write_all(&acc.balance.to_be_bytes::<32>())?;
    w.write_all(acc.bytecode_hash.unwrap_or(EMPTY_CODE).as_slice())?;
    w.write_all(&(slots.len() as u32).to_be_bytes())?;
    for (k, v) in slots {
        w.write_all(k.as_slice())?;
        w.write_all(&v.to_be_bytes::<32>())?;
    }
    Ok(())
}
