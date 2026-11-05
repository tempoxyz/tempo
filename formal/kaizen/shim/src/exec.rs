//! Execution oracle: re-executes a block with Tempo's EVM against the parent state, read through
//! `eth_getProof` from an untrusted RPC and checked against the parent's state root, and
//! recomputes the post-state root over the same proof nodes.

use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
};

use alloy_consensus::BlockHeader as _;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY, TrieAccount};
use eyre::{OptionExt as _, WrapErr as _, bail, eyre};
use rayon::prelude::*;
use reth_consensus::FullConsensus as _;
use reth_evm::{ConfigureEvm as _, Executor as _, database::StateProviderDatabase};
use reth_primitives_traits::{Account, Bytecode, SealedBlock};
use reth_storage_api::{
    EvmStateProvider,
    errors::provider::{ProviderError, ProviderResult},
};
use serde::Deserialize;
use tempo_chainspec::spec::MODERATO;
use tempo_evm::{TempoEvmConfig, consensus::TempoConsensus};
use tempo_primitives::{Block, BlockBody, TempoHeader};

use crate::mpt::{self, Store, Trie};

/// Blocking JSON-RPC client for state proofs.
#[derive(Clone)]
pub(crate) struct ProofRpc {
    client: reqwest::blocking::Client,
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProofResponse {
    account_proof: Vec<Bytes>,
    storage_proof: Vec<StorageProof>,
}

#[derive(Deserialize)]
struct StorageProof {
    proof: Vec<Bytes>,
}

impl ProofRpc {
    pub(crate) fn new(url: String) -> eyre::Result<Self> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            url,
        })
    }

    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> eyre::Result<T> {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
                .to_string();
        let mut attempt = 0u64;
        loop {
            attempt += 1;
            let res = (|| -> eyre::Result<T> {
                let resp = self
                    .client
                    .post(&self.url)
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .send()?;
                let status = resp.status();
                let mut v: serde_json::Value = serde_json::from_slice(&resp.bytes()?)
                    .wrap_err_with(|| format!("HTTP {status}"))?;
                if let Some(err) = v.get("error") {
                    bail!("{method}: {err}");
                }
                Ok(serde_json::from_value(v["result"].take())?)
            })();
            match res {
                Ok(v) => return Ok(v),
                Err(e) if attempt < 40 => {
                    std::thread::sleep(std::time::Duration::from_millis((200 * attempt).min(5000)));
                    if attempt > 3 {
                        eprintln!("retrying {method}: {e:#}");
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn proof(&self, address: Address, slots: &[B256], block: u64) -> eyre::Result<ProofResponse> {
        self.call(
            "eth_getProof",
            serde_json::json!([address, slots, format!("{block:#x}")]),
        )
    }

    fn code(&self, address: Address, block: u64) -> eyre::Result<Bytes> {
        self.call(
            "eth_getCode",
            serde_json::json!([address, format!("{block:#x}")]),
        )
    }
}

/// State at the parent block, read lazily and verified against its state root.
struct ProofState {
    rpc: ProofRpc,
    parent_number: u64,
    block_number: u64,
    pre_root: B256,
    inner: Mutex<Inner>,
    block_hashes: Arc<Mutex<BTreeMap<u64, B256>>>,
}

#[derive(Default)]
struct Inner {
    store: Store,
    accounts: HashMap<Address, Option<TrieAccount>>,
    storage: HashMap<(Address, B256), U256>,
    code_owner: HashMap<B256, Address>,
    codes: HashMap<B256, Bytecode>,
}

fn rpc_err(e: impl std::fmt::Display) -> ProviderError {
    ProviderError::other(std::io::Error::other(e.to_string()))
}

/// Accounts and slots recent blocks touched, prefetched in parallel before each execution.
static HOT: std::sync::LazyLock<Mutex<HashMap<Address, std::collections::BTreeSet<B256>>>> =
    std::sync::LazyLock::new(Default::default);

impl ProofState {
    /// Fetches proofs for the hot keys concurrently, one eth_getProof per account, and verifies
    /// them into the caches exactly as lazy reads would.
    fn prefetch(&self) {
        let hot: Vec<(Address, Vec<B256>)> = HOT
            .lock()
            .unwrap()
            .iter()
            .map(|(a, s)| (*a, s.iter().copied().collect()))
            .collect();
        hot.par_iter().for_each(|(address, slots)| {
            for chunk in slots
                .chunks(128)
                .map(<[B256]>::to_vec)
                .chain(slots.is_empty().then(Vec::new))
            {
                let Ok(proof) = self.rpc.proof(*address, &chunk, self.parent_number) else {
                    return;
                };
                let mut inner = self.inner.lock().unwrap();
                inner
                    .store
                    .add(proof.account_proof.iter().map(|b| b.as_ref()));
                for sp in &proof.storage_proof {
                    inner.store.add(sp.proof.iter().map(|b| b.as_ref()));
                }
            }
        });
        // Resolve from the store; anything a proof did not cover falls back to a lazy fetch.
        for (address, slots) in &hot {
            if self.account_from_store(*address).is_none() {
                continue;
            }
            for slot in slots {
                self.slot_from_store(*address, *slot);
            }
        }
    }

    fn account_from_store(&self, address: Address) -> Option<()> {
        let mut inner = self.inner.lock().unwrap();
        let leaf = Trie::new(self.pre_root)
            .get(&inner.store, &keccak256(address))
            .ok()?;
        let account: Option<TrieAccount> = match leaf {
            Some(v) => Some(alloy_rlp::Decodable::decode(&mut v.as_slice()).ok()?),
            None => None,
        };
        if let Some(a) = &account {
            inner.code_owner.insert(a.code_hash, address);
        }
        inner.accounts.insert(address, account);
        Some(())
    }

    fn slot_from_store(&self, address: Address, slot: B256) -> Option<()> {
        let mut inner = self.inner.lock().unwrap();
        let root = inner
            .accounts
            .get(&address)?
            .as_ref()
            .map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
        let leaf = Trie::new(root).get(&inner.store, &keccak256(slot)).ok()?;
        let value = match leaf {
            Some(v) => <U256 as alloy_rlp::Decodable>::decode(&mut v.as_slice()).ok()?,
            None => U256::ZERO,
        };
        inner.storage.insert((address, slot), value);
        Some(())
    }

    /// Replaces the hot set with the keys this execution read.
    fn record_hot(&self) {
        let inner = self.inner.lock().unwrap();
        let mut hot: HashMap<Address, std::collections::BTreeSet<B256>> = HashMap::new();
        for a in inner.accounts.keys() {
            hot.entry(*a).or_default();
        }
        for (a, s) in inner.storage.keys() {
            hot.entry(*a).or_default().insert(*s);
        }
        let mut global = HOT.lock().unwrap();
        // Keep keys from the previous block too, so alternating traffic stays warm.
        for (a, s) in hot {
            global.entry(a).or_default().extend(s);
        }
        if global.values().map(|s| s.len() + 1).sum::<usize>() > 4000 {
            global.clear();
        }
    }

    fn account(&self, address: Address) -> eyre::Result<Option<TrieAccount>> {
        if let Some(a) = self.inner.lock().unwrap().accounts.get(&address) {
            return Ok(a.clone());
        }
        let proof = self.rpc.proof(address, &[], self.parent_number)?;
        let mut inner = self.inner.lock().unwrap();
        inner
            .store
            .add(proof.account_proof.iter().map(|b| b.as_ref()));
        let leaf = Trie::new(self.pre_root)
            .get(&inner.store, &keccak256(address))
            .map_err(|e| eyre!("account proof for {address} does not verify against the parent state root: {e:?}"))?;
        let account = leaf
            .map(|v| alloy_rlp::Decodable::decode(&mut v.as_slice()))
            .transpose()
            .map_err(|e| eyre!("bad account leaf for {address}: {e}"))?;
        if let Some(a) = &account {
            let a: &TrieAccount = a;
            inner.code_owner.insert(a.code_hash, address);
        }
        inner.accounts.insert(address, account.clone());
        Ok(account)
    }

    fn slot(&self, address: Address, slot: B256) -> eyre::Result<U256> {
        if let Some(v) = self.inner.lock().unwrap().storage.get(&(address, slot)) {
            return Ok(*v);
        }
        let Some(account) = self.account(address)? else {
            return Ok(U256::ZERO);
        };
        if account.storage_root == EMPTY_ROOT_HASH {
            return Ok(U256::ZERO);
        }
        let proof = self.rpc.proof(address, &[slot], self.parent_number)?;
        let mut inner = self.inner.lock().unwrap();
        inner
            .store
            .add(proof.account_proof.iter().map(|b| b.as_ref()));
        for sp in &proof.storage_proof {
            inner.store.add(sp.proof.iter().map(|b| b.as_ref()));
        }
        let leaf = Trie::new(account.storage_root)
            .get(&inner.store, &keccak256(slot))
            .map_err(|e| eyre!("storage proof for {address}/{slot} does not verify: {e:?}"))?;
        let value = leaf
            .map(|v| <U256 as alloy_rlp::Decodable>::decode(&mut v.as_slice()))
            .transpose()
            .map_err(|e| eyre!("bad storage leaf: {e}"))?
            .unwrap_or_default();
        inner.storage.insert((address, slot), value);
        Ok(value)
    }

    fn code(&self, hash: B256) -> eyre::Result<Bytecode> {
        if hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        if let Some(c) = self.inner.lock().unwrap().codes.get(&hash) {
            return Ok(c.clone());
        }
        let owner = *self
            .inner
            .lock()
            .unwrap()
            .code_owner
            .get(&hash)
            .ok_or_eyre("code hash of an unloaded account")?;
        let raw = self.rpc.code(owner, self.parent_number)?;
        if keccak256(&raw) != hash {
            bail!("eth_getCode for {owner} does not match its code hash");
        }
        let code = Bytecode::new_raw(raw);
        self.inner.lock().unwrap().codes.insert(hash, code.clone());
        Ok(code)
    }

    /// Fetches post-state proofs of every key the block deletes. Each passes through the node its
    /// deleted leaf's sibling merged into, whose suffixes include the sibling's pre-state node.
    fn reveal_from_post_state(&self, bundle: &reth_evm::BundleState) -> eyre::Result<()> {
        let mut nodes: Vec<Bytes> = Vec::new();
        for (address, account) in &bundle.state {
            let deleted: Vec<B256> = account
                .storage
                .iter()
                .filter(|(_, v)| v.present_value.is_zero())
                .map(|(k, _)| B256::from(*k))
                .collect();
            if account.info.is_none() || !deleted.is_empty() {
                for chunk in deleted
                    .chunks(64)
                    .map(<[B256]>::to_vec)
                    .chain(deleted.is_empty().then(Vec::new))
                {
                    let p = self.rpc.proof(*address, &chunk, self.block_number)?;
                    nodes.extend(p.account_proof);
                    nodes.extend(p.storage_proof.into_iter().flat_map(|s| s.proof));
                }
            }
        }
        let mut inner = self.inner.lock().unwrap();
        for n in &nodes {
            inner.store.add([n.as_ref()]);
            inner.store.add_suffixes(n);
        }
        Ok(())
    }

    /// Fetches a proof whose path covers `path` in the given trie, by searching for a key whose
    /// hash starts with that prefix, so a deletion can see the sibling it collapses into.
    fn reveal(&self, owner: Option<Address>, path: &[u8]) -> eyre::Result<()> {
        if path.len() > 6 {
            bail!(
                "trie node at depth {} is not revealed by any proof",
                path.len()
            );
        }
        let matches = |h: &B256| {
            path.iter()
                .enumerate()
                .all(|(i, n)| (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 }) & 0xf) == *n)
        };
        let found = (0u64..1 << 34)
            .into_par_iter()
            .find_any(|i| {
                let h = match owner {
                    Some(_) => keccak256(B256::from(U256::from(*i))),
                    None => keccak256(Address::left_padding_from(&i.to_be_bytes())),
                };
                matches(&h)
            })
            .ok_or_eyre("no key found for prefix")?;
        let proof = match owner {
            Some(address) => self.rpc.proof(
                address,
                &[B256::from(U256::from(found))],
                self.parent_number,
            )?,
            None => self.rpc.proof(
                Address::left_padding_from(&found.to_be_bytes()),
                &[],
                self.parent_number,
            )?,
        };
        let mut inner = self.inner.lock().unwrap();
        inner
            .store
            .add(proof.account_proof.iter().map(|b| b.as_ref()));
        for sp in &proof.storage_proof {
            inner.store.add(sp.proof.iter().map(|b| b.as_ref()));
        }
        Ok(())
    }
}

impl EvmStateProvider for ProofState {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        Ok(self.account(*address).map_err(rpc_err)?.map(|a| Account {
            nonce: a.nonce,
            balance: a.balance,
            bytecode_hash: Some(a.code_hash),
            extension: a.extension,
        }))
    }

    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        match self.block_hashes.lock().unwrap().get(&number) {
            Some(h) => Ok(Some(*h)),
            // BLOCKHASH can reach the 256 previous blocks: answering zero for one we don't know
            // would execute the block differently, so fail instead.
            None if number < self.block_number && number + 256 >= self.block_number => {
                Err(rpc_err(format!("block hash {number} unknown")))
            }
            None => Ok(None),
        }
    }

    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        Ok(Some(self.code(*code_hash).map_err(rpc_err)?))
    }

    fn storage(&self, account: Address, key: B256) -> ProviderResult<Option<U256>> {
        Ok(Some(self.slot(account, key).map_err(rpc_err)?))
    }
}

pub(crate) struct Outcome {
    pub(crate) post_root: B256,
    pub(crate) accounts: usize,
    pub(crate) slots: usize,
    pub(crate) reveals: usize,
}

/// Executes `block` on the state with root `pre_root` (the parent block's) and returns the
/// recomputed post-state root. Also checks gas used, receipts root and logs bloom against the
/// header with Tempo's own post-execution validation.
pub(crate) fn execute(
    rpc: &ProofRpc,
    header: &TempoHeader,
    body: &BlockBody,
    pre_root: B256,
    block_hashes: Arc<Mutex<BTreeMap<u64, B256>>>,
) -> eyre::Result<Outcome> {
    let state = Arc::new(ProofState {
        rpc: rpc.clone(),
        parent_number: header.number() - 1,
        block_number: header.number(),
        pre_root,
        inner: Mutex::new(Inner::default()),
        block_hashes,
    });
    let block = SealedBlock::seal_slow(Block {
        header: header.clone(),
        body: body.clone(),
    })
    .try_recover()
    .map_err(|e| eyre!("sender recovery failed: {e}"))?;
    let config = TempoEvmConfig::new(MODERATO.clone());
    let output = config
        .executor(StateProviderDatabase::new(ArcState(state.clone())))
        .execute(&block)
        .map_err(|e| eyre!("execution failed: {e}"))?;
    TempoConsensus::new(MODERATO.clone())
        .validate_block_post_execution(&block, &output.result, None, None)
        .map_err(|e| eyre!("post-execution check failed: {e}"))?;

    let mut reveals = 0;
    loop {
        match post_root(&state, &output.state) {
            Ok(root) => {
                if root != header.state_root() && std::env::var_os("KAIZEN_DIAGNOSE").is_some() {
                    diagnose(&state, &output.state, header.state_root());
                }
                state.record_hot();
                let inner = state.inner.lock().unwrap();
                return Ok(Outcome {
                    post_root: root,
                    accounts: inner.accounts.len(),
                    slots: inner.storage.len(),
                    reveals,
                });
            }
            Err((owner, mpt::Error::Missing(path))) => {
                reveals += 1;
                if reveals > 64 {
                    bail!("too many unrevealed trie nodes");
                }
                if reveals == 1 {
                    state.reveal_from_post_state(&output.state)?;
                } else {
                    state.reveal(owner, &path)?;
                }
            }
            Err((_, e)) => bail!("trie error: {e:?}"),
        }
    }
}

type RootErr = (Option<Address>, mpt::Error);

fn post_root(state: &ProofState, bundle: &reth_evm::BundleState) -> Result<B256, RootErr> {
    let inner = state.inner.lock().unwrap();
    let store = &inner.store;
    let mut accounts = Trie::new(state.pre_root);
    let mut changed: Vec<_> = bundle.state.iter().collect();
    changed.sort_by_key(|(a, _)| **a);
    for (address, account) in changed {
        let pre = inner.accounts.get(address).cloned().flatten();
        let key = keccak256(address);
        let Some(info) = &account.info else {
            accounts.remove(store, &key).map_err(|e| (None, e))?;
            continue;
        };
        let pre_storage_root = if account.status.was_destroyed() {
            EMPTY_ROOT_HASH
        } else {
            pre.as_ref().map_or(EMPTY_ROOT_HASH, |a| a.storage_root)
        };
        let mut storage = Trie::new(pre_storage_root);
        let mut slots: Vec<_> = account.storage.iter().collect();
        slots.sort_by_key(|(k, _)| **k);
        for (slot, value) in slots {
            let skey = keccak256(B256::from(*slot));
            let r = if value.present_value.is_zero() {
                storage.remove(store, &skey)
            } else {
                storage.insert(store, &skey, alloy_rlp::encode(value.present_value))
            };
            r.map_err(|e| (Some(*address), e))?;
        }
        let leaf = TrieAccount {
            nonce: info.nonce,
            balance: info.balance,
            storage_root: storage.root(),
            code_hash: info.code_hash,
            extension: alloy_trie::AccountExtension::copy_from_slice(info.extension.as_ref()),
        };
        accounts
            .insert(store, &key, alloy_rlp::encode(&leaf))
            .map_err(|e| (None, e))?;
    }
    Ok(accounts.root())
}

/// `EvmStateProvider` through an Arc, so the executor can own the database while we keep the proofs.
struct ArcState(Arc<ProofState>);

impl EvmStateProvider for ArcState {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        self.0.basic_account(address)
    }
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        self.0.block_hash(number)
    }
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        self.0.bytecode_by_hash(code_hash)
    }
    fn storage(&self, account: Address, key: B256) -> ProviderResult<Option<U256>> {
        self.0.storage(account, key)
    }
}

/// Compares every changed account and slot with post-state proofs, to find where a recomputed
/// root diverges from the header's.
fn diagnose(state: &ProofState, bundle: &reth_evm::BundleState, post_root: B256) {
    for (address, account) in &bundle.state {
        let slots: Vec<B256> = account.storage.keys().map(|k| B256::from(*k)).collect();
        let Ok(p) = state.rpc.proof(*address, &slots, state.block_number) else {
            continue;
        };
        let mut store = Store::default();
        store.add(p.account_proof.iter().map(|b| b.as_ref()));
        for sp in &p.storage_proof {
            store.add(sp.proof.iter().map(|b| b.as_ref()));
        }
        let want: Option<TrieAccount> = Trie::new(post_root)
            .get(&store, &keccak256(address))
            .ok()
            .flatten()
            .and_then(|v| alloy_rlp::Decodable::decode(&mut v.as_slice()).ok());
        let got = account.info.as_ref();
        let (wn, wb, wc, ws) = want
            .as_ref()
            .map_or((0, U256::ZERO, KECCAK_EMPTY, EMPTY_ROOT_HASH), |a| {
                (a.nonce, a.balance, a.code_hash, a.storage_root)
            });
        let (gn, gb, gc) = got.map_or((0, U256::ZERO, KECCAK_EMPTY), |i| {
            (i.nonce, i.balance, i.code_hash)
        });
        if want.is_none() != got.is_none() || wn != gn || wb != gb || wc != gc {
            eprintln!(
                "DIAG {address}: want {:?} got exists={} nonce {gn} balance {gb} code {gc} status {:?}",
                want.as_ref().map(|a| (
                    a.nonce,
                    a.balance,
                    a.code_hash,
                    a.extension.as_ref().len()
                )),
                got.is_some(),
                account.status
            );
        }
        if let (Some(w), Some(i)) = (&want, got) {
            if w.extension.as_ref() != i.extension.as_ref() {
                eprintln!(
                    "DIAG {address}: extension differs: want {} got {}",
                    alloy_primitives::hex::encode(w.extension.as_ref()),
                    alloy_primitives::hex::encode(i.extension.as_ref())
                );
            }
        }
        for (slot, v) in &account.storage {
            let key = B256::from(*slot);
            let w = Trie::new(ws)
                .get(&store, &keccak256(key))
                .ok()
                .flatten()
                .and_then(|v| <U256 as alloy_rlp::Decodable>::decode(&mut v.as_slice()).ok())
                .unwrap_or_default();
            if w != v.present_value {
                eprintln!(
                    "DIAG {address} slot {key}: want {w} got {}",
                    v.present_value
                );
            }
        }
        let _ = ws;
    }
    eprintln!("DIAG done ({} accounts)", bundle.state.len());
}
