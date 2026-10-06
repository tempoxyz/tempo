//! Nonce execution and incremental MDBX storage-trie persistence, versus the
//! reconstructible in-memory backend including expiry, snapshots and commitment.
//!
//! Run: cargo bench -p tempo-evm --bench expiring_nonces
//! TEMPO_NONCE_BENCH_TXS=1000 TEMPO_NONCE_BENCH_WARMUP=3000 fills the T11 ring
//! before measurement. TEMPO_NONCE_BENCH_BLOCKS controls the measured block count.
//! This isolates nonce overhead; common transaction/block persistence, fees,
//! signature verification and the account trie are deliberately outside the timer.
//! Both variants durably persist one block-number-to-root record per measured block
//! so the comparison charges both for the common header-commit fsync.

use alloy_evm::{EvmEnv, EvmFactory};
use alloy_primitives::{B256, U256, keccak256};
use reth_db::{Database, init_db, mdbx::DatabaseArguments};
use reth_db_api::{
    cursor::{DbCursorRW, DbDupCursorRO},
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_primitives_traits::StorageEntry;
use reth_trie::{Nibbles, StorageRoot, prefix_set::PrefixSetMut};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStorageRoot, DatabaseStorageTrieCursor,
    DatabaseTrieCursorFactory, PackedKeyAdapter, PackedStoragesTrie,
};
use revm::{DatabaseCommit, context::JournalTr, database::InMemoryDB};
use std::{
    collections::{BTreeMap, VecDeque},
    hint::black_box,
    time::{Duration, Instant},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::TempoEvmFactory;
use tempo_expiring_nonces::ExpiringNonceState;
use tempo_precompiles::{
    NONCE_PRECOMPILE_ADDRESS,
    nonce::NonceManager,
    storage::{StorageActions, StorageCtx},
};

type DbStorageRoot<'a, TX> = StorageRoot<
    DatabaseTrieCursorFactory<&'a TX, PackedKeyAdapter>,
    DatabaseHashedCursorFactory<&'a TX>,
>;

#[derive(Default)]
struct Measurement {
    execution: Duration,
    commitment: Duration,
    slots: usize,
    trie_nodes: usize,
}

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .map(|value| value.parse().expect("integer benchmark setting"))
        .unwrap_or(default)
}

fn main() {
    let txs = setting("TEMPO_NONCE_BENCH_TXS", 1000);
    let warmup = setting("TEMPO_NONCE_BENCH_WARMUP", 0);
    let blocks = setting("TEMPO_NONCE_BENCH_BLOCKS", 100);
    let spec = TempoHardfork::T11;
    let ids: Vec<_> = (0..(warmup + blocks) * txs)
        .map(|i| keccak256((i as u64).to_be_bytes()))
        .collect();
    let path = tempfile::tempdir().unwrap();
    let db = init_db(path.path(), DatabaseArguments::default()).unwrap();
    let address = NONCE_PRECOMPILE_ADDRESS;
    let hashed_address = keccak256(address);
    let mut env = EvmEnv::default();
    env.cfg_env = env.cfg_env.with_spec_and_mainnet_gas_params(spec);
    let mut evm = TempoEvmFactory::default().create_evm(InMemoryDB::default(), env);
    let mut legacy = Measurement::default();
    let mut warmup_changes = BTreeMap::new();
    for block in 0..warmup + blocks {
        let now = 1000 + block as u64;
        let start = Instant::now();
        let ctx = evm.ctx_mut();
        ctx.block.timestamp = U256::from(now);
        StorageCtx::enter_evm_without_tip1060_accounting(
            &mut ctx.journaled_state,
            &ctx.block,
            &ctx.cfg,
            &ctx.tx,
            StorageActions::disabled(),
            || {
                let mut manager = NonceManager::new();
                for id in &ids[block * txs..(block + 1) * txs] {
                    manager
                        .check_and_mark_expiring_nonce(*id, now + 300)
                        .unwrap();
                }
            },
        );
        let state = ctx.journaled_state.finalize();
        let mut changes: Vec<_> = state
            .get(&address)
            .unwrap()
            .changed_storage_slots()
            .map(|(key, slot)| (B256::from(key.to_be_bytes::<32>()), slot.present_value))
            .collect();
        changes.sort_unstable_by_key(|(key, _)| *key);
        ctx.journaled_state.database.commit(state);
        let execution = start.elapsed();
        // Warmup is untimed. Batch its database commits to avoid thousands of
        // fsyncs while materializing exactly the same final ring and trie.
        if block < warmup {
            warmup_changes.extend(changes);
            if (block + 1) % 100 != 0 && block + 1 < warmup {
                continue;
            }
            changes = std::mem::take(&mut warmup_changes).into_iter().collect();
        }
        let start = Instant::now();
        let tx = db.tx_mut().unwrap();
        let mut prefixes = PrefixSetMut::default();
        {
            let mut plain = tx.cursor_dup_write::<tables::PlainStorageState>().unwrap();
            let mut hashed = tx.cursor_dup_write::<tables::HashedStorages>().unwrap();
            for (key, value) in &changes {
                if plain
                    .seek_by_key_subkey(address, *key)
                    .unwrap()
                    .is_some_and(|entry| entry.key == *key)
                {
                    plain.delete_current().unwrap();
                }
                if !value.is_zero() {
                    plain
                        .upsert(
                            address,
                            &StorageEntry {
                                key: *key,
                                value: *value,
                            },
                        )
                        .unwrap();
                }
                let key = keccak256(key);
                prefixes.insert(Nibbles::unpack(key));
                if hashed
                    .seek_by_key_subkey(hashed_address, key)
                    .unwrap()
                    .is_some_and(|entry| entry.key == key)
                {
                    hashed.delete_current().unwrap();
                }
                if !value.is_zero() {
                    hashed
                        .upsert(hashed_address, &StorageEntry { key, value: *value })
                        .unwrap();
                }
            }
        }
        let (root, _, updates) = DbStorageRoot::from_tx_hashed(&tx, hashed_address)
            .with_prefix_set(prefixes.freeze())
            .root_with_updates()
            .unwrap();
        tx.put::<tables::CanonicalHeaders>(block as u64, root)
            .unwrap();
        black_box(root);
        let written = DatabaseStorageTrieCursor::<_, PackedKeyAdapter>::new(
            tx.cursor_dup_write::<PackedStoragesTrie>().unwrap(),
            hashed_address,
        )
        .write_storage_trie_updates_sorted(&updates.into_sorted())
        .unwrap();
        tx.commit().unwrap();
        if block >= warmup {
            legacy.execution += execution;
            legacy.commitment += start.elapsed();
            legacy.slots += changes.len();
            legacy.trie_nodes += written;
        }
    }
    let memory_path = tempfile::tempdir().unwrap();
    let memory_db = init_db(memory_path.path(), DatabaseArguments::default()).unwrap();
    let mut memory = Measurement::default();
    let mut state = ExpiringNonceState::default();
    let mut snapshots = VecDeque::new();
    for block in 0..warmup + blocks {
        let now = 1000 + block as u64;
        let start = Instant::now();
        let mut next = state.clone();
        next.advance(now).unwrap();
        for id in &ids[block * txs..(block + 1) * txs] {
            // Executor admission, the EVM handler, and commit each validate.
            next.check(*id, now + 300, 300, 3_000_000).unwrap();
            next.check(*id, now + 300, 300, 3_000_000).unwrap();
            next.insert(*id, now + 300, 300, 3_000_000).unwrap();
        }
        let execution = start.elapsed();
        let start = Instant::now();
        // Validation, cache insertion, assembly, and the assembled-block cache.
        for _ in 0..4 {
            black_box(next.root());
        }
        snapshots.push_back(state);
        if snapshots.len() > 16 {
            snapshots.pop_front();
        }
        state = next;
        if block >= warmup || block + 1 == warmup {
            let tx = memory_db.tx_mut().unwrap();
            tx.put::<tables::CanonicalHeaders>(block as u64, state.root())
                .unwrap();
            tx.commit().unwrap();
        }
        if block >= warmup {
            memory.execution += execution;
            memory.commitment += start.elapsed();
        }
    }
    let count = blocks * txs;
    println!(
        "{{\"txs_per_block\":{txs},\"warmup_blocks\":{warmup},\"measured_blocks\":{blocks},\"measured_transactions\":{count},\"live_ids\":{},\"legacy\":{{\"execution_ms\":{},\"trie_and_durable_commit_ms\":{},\"storage_slots\":{},\"trie_nodes\":{}}},\"memory\":{{\"execution_ms\":{},\"commitment_and_durable_header_ms\":{},\"storage_slots\":0,\"trie_nodes\":0}},\"nonce_overhead_speedup\":{}}}",
        state.len(),
        legacy.execution.as_secs_f64() * 1000.0,
        legacy.commitment.as_secs_f64() * 1000.0,
        legacy.slots,
        legacy.trie_nodes,
        memory.execution.as_secs_f64() * 1000.0,
        memory.commitment.as_secs_f64() * 1000.0,
        (legacy.execution + legacy.commitment).as_secs_f64()
            / (memory.execution + memory.commitment).as_secs_f64()
    );
}
