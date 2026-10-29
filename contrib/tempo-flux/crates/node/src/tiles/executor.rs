use alloy_consensus::transaction::{Recovered, TxHashRef};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Bytes, U256};
use evm2::evm::{AccountInfo, Cache};
use flux::{
    spine::{DCacheRead, SpineAdapter},
    tile::Tile,
};
use reth_evm::{BlockExecutor, BlockExecutorFactory, BundleState};
use reth_evm_ethereum::EthBlockExecutionCtx;
use rustc_hash::FxHashMap;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoBlockExecutionCtx, TempoEvmConfig, TempoTxEnv};
use tempo_flux_primitives::{Block, StateDiff, body, diff};
use tempo_precompiles::{PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS};
use tempo_primitives::TempoTxEnvelope;

use crate::{
    spine::NodeSpine,
    tempo::{self, StateView},
};

/// Contracts whose slots shards may write concurrently. Writes from different
/// shards merge by summing deltas, which matches a serial order only while the
/// values are used as balances that no transaction's control flow depends on.
const ADDITIVE: [Address; 2] = [PATH_USD_ADDRESS, TIP_FEE_MANAGER_ADDRESS];

type Acc = (u64, U256, B256);

/// A block's state changes, merged across shards.
#[derive(Default, PartialEq, Eq)]
struct Changes {
    accounts: FxHashMap<Address, Option<Acc>>,
    storage: FxHashMap<Address, FxHashMap<U256, U256>>,
}

struct ShardOut {
    bundle: BundleState,
    gas: u64,
    reverted: u64,
}

/// Executes blocks with Tempo's block executor (evm2, Tempo precompiles, fee
/// AMM, lanes, system calls). With `shards > 1` a block's transactions are
/// split by sender across pinned worker threads that all read the pre-block
/// state; their bundles are merged, and the block re-runs sequentially if they
/// conflict outside [`ADDITIVE`].
pub struct ExecutorTile {
    state: Cache,
    hardfork: TempoHardfork,
    config: TempoEvmConfig,
    shards: usize,
    first_core: Option<usize>,
    verify: bool,
    diff: Vec<u8>,
    pub reverted: u64,
    pub fallbacks: u64,
    head: (u64, [u8; 32]),
}

fn shard_of(sender: &[u8; 20], shards: usize) -> usize {
    (u64::from_le_bytes(sender[..8].try_into().unwrap()) % shards as u64) as usize
}

fn run_shard(
    config: &TempoEvmConfig,
    hardfork: TempoHardfork,
    state: &Cache,
    block: &Block,
    payload: &[u8],
    shard: Option<(usize, usize)>,
) -> Result<ShardOut, String> {
    let env = tempo::env(hardfork, block.height, block.timestamp_ms / 1000);
    let evm = config.evm_with_database(StateView(state), env);
    let ctx = TempoBlockExecutionCtx {
        inner: EthBlockExecutionCtx {
            parent_hash: B256::from(block.parent),
            parent_beacon_block_root: Some(B256::ZERO),
            ommers: &[],
            withdrawals: None,
            extra_data: Bytes::new(),
            tx_count_hint: Some(block.tx_count as usize),
            slot_number: None,
        },
        general_gas_limit: tempo::BLOCK_GAS_LIMIT,
        shared_gas_limit: 0,
        consensus_context: None,
    };
    let mut executor = config.create_executor(evm, ctx);
    executor
        .apply_pre_execution_changes()
        .map_err(|e| format!("pre-execution: {e}"))?;
    let (mut gas, mut reverted) = (0u64, 0u64);
    for (sender, mut raw) in body::iter(payload) {
        if shard.is_some_and(|(k, n)| shard_of(&sender, n) != k) {
            continue;
        }
        let tx = TempoTxEnvelope::decode_2718(&mut raw).map_err(|e| e.to_string())?;
        let tx = tempo::recovered(tx, Address::from(sender));
        let env = Recovered::new_unchecked(TempoTxEnv::from(tx.clone()), tx.signer());
        let out = executor
            .execute_transaction_without_commit((env, &tx))
            .map_err(|e| format!("tx {}: {e}", tx.tx_hash()))?;
        reverted += u64::from(!out.result().status);
        gas += executor
            .commit_transaction(out)
            .map_err(|e| e.to_string())?
            .tx_gas_used();
    }
    let output = executor.finish().map_err(|e| format!("finish: {e}"))?;
    Ok(ShardOut {
        bundle: output.state,
        gas,
        reverted,
    })
}

fn acc(info: &Option<AccountInfo>) -> Option<Acc> {
    info.as_ref().map(|i| (i.nonce, i.balance, i.code_hash))
}

/// Merges shard bundles. `baseline` is the same block with no transactions:
/// every shard repeats its system-call writes, so each shard's effect is its
/// change relative to the baseline. Returns `None` when two shards change
/// the same account, or the same slot outside [`ADDITIVE`].
fn merge(bundles: &[BundleState], baseline: &BundleState) -> Option<Changes> {
    let mut out = Changes::default();
    let mut accounts: FxHashMap<Address, (Option<Acc>, Option<Acc>, Vec<Option<Acc>>)> =
        FxHashMap::default();
    for b in std::iter::once(baseline).chain(bundles) {
        for (addr, a) in &b.state {
            accounts.entry(*addr).or_insert_with(|| {
                let orig = acc(&a.original_info);
                let base = baseline.state.get(addr).map_or(orig, |x| acc(&x.info));
                (orig, base, Vec::new())
            });
        }
    }
    for b in bundles {
        for (addr, a) in &b.state {
            accounts
                .get_mut(addr)
                .expect("collected above")
                .2
                .push(acc(&a.info));
        }
    }
    for (addr, (orig, base, writes)) in accounts {
        let mut changed = writes.into_iter().filter(|w| *w != base);
        let value = match (changed.next(), changed.next()) {
            (None, _) => base,
            (Some(w), None) => w,
            (Some(_), Some(_)) => return None,
        };
        if value != orig {
            out.accounts.insert(addr, value);
        }
    }

    // slot -> (original, baseline, per-shard writes)
    let mut slots: FxHashMap<(Address, U256), (U256, U256, Vec<U256>)> = FxHashMap::default();
    for b in std::iter::once(baseline).chain(bundles) {
        for (addr, a) in &b.state {
            for (key, s) in &a.storage {
                slots.entry((*addr, *key)).or_insert_with(|| {
                    let orig = s.previous_or_original_value;
                    let base = baseline
                        .state
                        .get(addr)
                        .and_then(|x| x.storage.get(key))
                        .map_or(orig, |x| x.present_value);
                    (orig, base, Vec::new())
                });
            }
        }
    }
    for b in bundles {
        for (addr, a) in &b.state {
            for (key, s) in &a.storage {
                slots
                    .get_mut(&(*addr, *key))
                    .expect("collected above")
                    .2
                    .push(s.present_value);
            }
        }
    }
    for ((addr, key), (orig, base, writes)) in slots {
        let value = if ADDITIVE.contains(&addr) {
            writes
                .iter()
                .fold(base, |v, w| v.wrapping_add(w.wrapping_sub(base)))
        } else {
            let mut changed = writes.into_iter().filter(|w| *w != base);
            match (changed.next(), changed.next()) {
                (None, _) => base,
                (Some(w), None) => w,
                (Some(_), Some(_)) => return None,
            }
        };
        if value != orig {
            out.storage.entry(addr).or_default().insert(key, value);
        }
    }
    Some(out)
}

impl ExecutorTile {
    pub fn new(
        state: Cache,
        hardfork: TempoHardfork,
        shards: usize,
        first_core: Option<usize>,
        verify: bool,
    ) -> Self {
        Self {
            state,
            hardfork,
            config: tempo::config(),
            shards: shards.max(1),
            first_core,
            verify,
            diff: Vec::new(),
            reverted: 0,
            fallbacks: 0,
            head: (0, [0; 32]),
        }
    }

    fn sequential(&self, block: &Block, payload: &[u8]) -> Result<(Changes, u64, u64), String> {
        let out = run_shard(
            &self.config,
            self.hardfork,
            &self.state,
            block,
            payload,
            None,
        )?;
        let baseline = BundleState::default();
        let changes = merge(std::slice::from_ref(&out.bundle), &baseline)
            .expect("one bundle never conflicts");
        Ok((changes, out.gas, out.reverted))
    }

    fn parallel(
        &self,
        block: &Block,
        payload: &[u8],
    ) -> Result<Option<(Changes, u64, u64)>, String> {
        let n = self.shards;
        // Shard `n` matches no sender: it runs only the block's system calls.
        let results: Vec<Result<ShardOut, String>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..=n)
                .map(|k| {
                    let (config, state, hardfork) =
                        (self.config.clone(), &self.state, self.hardfork);
                    let core = self.first_core.map(|c| c + k % n);
                    s.spawn(move || {
                        if let Some(id) = core {
                            core_affinity::set_for_current(core_affinity::CoreId { id });
                        }
                        run_shard(&config, hardfork, state, block, payload, Some((k, n)))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("shard panicked"))
                .collect()
        });
        let mut bundles = Vec::with_capacity(n);
        let (mut gas, mut reverted) = (0, 0);
        for r in results {
            let r = r?;
            gas += r.gas;
            reverted += r.reverted;
            bundles.push(r.bundle);
        }
        let baseline = bundles.pop().expect("baseline shard");
        Ok(merge(&bundles, &baseline).map(|c| (c, gas, reverted)))
    }

    fn execute(&mut self, block: &Block, payload: &[u8]) -> StateDiff {
        let mut out = StateDiff {
            height: block.height,
            hash: block.hash,
            ..Default::default()
        };
        self.diff.clear();
        if (block.height, block.parent) != (self.head.0 + 1, self.head.1) {
            tracing::warn!(
                block.height,
                head = self.head.0,
                "block does not extend the executed head"
            );
            return out;
        }
        let result = if self.shards > 1 {
            match self.parallel(block, payload) {
                Ok(Some(r)) => Ok(r),
                Ok(None) => {
                    self.fallbacks += 1;
                    tracing::warn!(block.height, "shards conflicted, re-running sequentially");
                    self.sequential(block, payload)
                }
                Err(e) => Err(e),
            }
        } else {
            self.sequential(block, payload)
        };
        let (changes, gas, reverted) = match result {
            Ok(r) => r,
            Err(err) => {
                tracing::warn!(block.height, err, "block failed execution");
                return out;
            }
        };
        if self.verify && self.shards > 1 {
            let (seq, seq_gas, _) = self
                .sequential(block, payload)
                .expect("sequential run failed");
            assert!(
                seq == changes && seq_gas == gas,
                "parallel state diverged at {}",
                block.height
            );
        }
        out.gas_used = gas;
        self.reverted += reverted;
        (out.accounts, out.slots) = apply(&mut self.state, &changes, &mut self.diff);
        out.valid = true;
        self.head = (block.height, block.hash);
        out
    }
}

/// Writes a block's changes into the state and encodes them as a diff.
fn apply(state: &mut Cache, changes: &Changes, buf: &mut Vec<u8>) -> (u32, u32) {
    let mut accounts = 0;
    for (addr, a) in &changes.accounts {
        match a {
            None => {
                state.accounts.insert(*addr, None);
                state.storage.remove(addr);
                diff::push_account(buf, addr.0.0, 0, [0; 32], [0; 32], true);
            }
            Some((nonce, balance, code_hash)) => {
                diff::push_account(
                    buf,
                    addr.0.0,
                    *nonce,
                    balance.to_be_bytes::<32>(),
                    code_hash.0,
                    false,
                );
                let mut info = AccountInfo::default();
                info.nonce = *nonce;
                info.balance = *balance;
                info.code_hash = *code_hash;
                state.accounts.insert(*addr, Some(info));
            }
        }
        accounts += 1;
    }
    let mut slots = 0;
    for (addr, st) in &changes.storage {
        let cache = state.storage.entry(*addr).or_default();
        for (key, value) in st {
            if value.is_zero() {
                cache.slots.remove(key);
            } else {
                cache.slots.insert(*key, *value);
            }
            diff::push_slot(
                buf,
                addr.0.0,
                key.to_be_bytes::<32>(),
                value.to_be_bytes::<32>(),
            );
            slots += 1;
        }
    }
    (accounts, slots)
}

/// Encodes a genesis state as a diff so the merkle tile can load it.
pub fn genesis_diff(state: &Cache) -> (StateDiff, Vec<u8>) {
    let mut buf = Vec::new();
    let mut d = StateDiff {
        valid: true,
        ..Default::default()
    };
    for (addr, info) in &state.accounts {
        if let Some(info) = info {
            diff::push_account(
                &mut buf,
                addr.0.0,
                info.nonce,
                info.balance.to_be_bytes::<32>(),
                info.code_hash.0,
                false,
            );
            d.accounts += 1;
        }
    }
    for (addr, st) in &state.storage {
        for (k, v) in &st.slots {
            diff::push_slot(
                &mut buf,
                addr.0.0,
                k.to_be_bytes::<32>(),
                v.to_be_bytes::<32>(),
            );
            d.slots += 1;
        }
    }
    (d, buf)
}

impl Tile<NodeSpine> for ExecutorTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<NodeSpine>) {
        let mut blocks = Vec::new();
        let mut lost = Vec::new();
        adapter.consume_with_dcache::<Block, Vec<u8>, _, _>(
            |_, payload| payload.to_vec(),
            |res, _| match res {
                DCacheRead::Ok((b, payload)) => blocks.push((b, payload)),
                DCacheRead::NoRef(b) => blocks.push((b, Vec::new())),
                DCacheRead::Lost(b) => lost.push(b),
                DCacheRead::SpedPast => tracing::error!("executor lapped on blocks"),
            },
        );
        // State is untouched, so consensus can treat a lost body as a rejected
        // block and the builder requeues its transactions.
        for b in lost {
            tracing::error!(b.height, "block body lost, rejecting it");
            let out = StateDiff {
                height: b.height,
                hash: b.hash,
                ..Default::default()
            };
            adapter
                .produce_with_dcache(out, None::<(usize, fn(&mut [u8]))>)
                .expect("no payload");
        }
        for (block, payload) in blocks {
            let start = crate::now_ns();
            let out = self.execute(&block, &payload);
            tracing::info!(
                block.height,
                txs = block.tx_count,
                gas = out.gas_used,
                valid = out.valid,
                reverted = self.reverted,
                fallbacks = self.fallbacks,
                exec_ms = format!("{:.2}", (crate::now_ns() - start) as f64 / 1e6),
                "executed"
            );
            let diff = &self.diff;
            let payload = (!diff.is_empty())
                .then_some((diff.len(), |buf: &mut [u8]| buf.copy_from_slice(diff)));
            adapter
                .produce_with_dcache(out, payload)
                .expect("state diff fits the dcache");
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{U256, map::U256Map};
    use reth_evm::BundleState;

    use super::{ADDITIVE, merge};

    fn slot_bundle(addr: alloy_primitives::Address, key: u64, orig: u64, now: u64) -> BundleState {
        let mut storage = U256Map::default();
        storage.insert(U256::from(key), (U256::from(orig), U256::from(now)));
        BundleState::builder(0..=0)
            .state_address(addr)
            .state_storage(addr, storage)
            .build()
    }

    #[test]
    fn equal_additive_deltas_from_two_shards_both_count() {
        let token = ADDITIVE[0];
        let a = slot_bundle(token, 7, 10, 11);
        let b = slot_bundle(token, 7, 10, 11);
        let merged = merge(&[a, b], &BundleState::default()).unwrap();
        assert_eq!(merged.storage[&token][&U256::from(7)], U256::from(12));
    }

    #[test]
    fn system_call_writes_count_once() {
        let token = ADDITIVE[0];
        let base = slot_bundle(token, 7, 10, 15);
        let a = slot_bundle(token, 7, 10, 16);
        let b = slot_bundle(token, 7, 10, 15);
        let merged = merge(&[a, b], &base).unwrap();
        assert_eq!(merged.storage[&token][&U256::from(7)], U256::from(16));
    }
}
