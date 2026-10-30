//! Database views over captured corpus state for execution without the archive DB.

use crate::{
    code,
    types::{Change, Chunk, Delta, Info, InfoChange},
};
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Database},
    interpreter::Word,
};
use parking_lot::{Mutex, RwLock};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    sync::{Arc, LazyLock},
};

/// A value the corpus did not capture; replay never falls back to a default.
#[derive(Debug)]
pub struct Missing(pub String);

impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Missing {}

/// Analyzed bytecode by hash, built once from the verified shared code.
static ANALYZED: LazyLock<RwLock<HashMap<B256, Bytecode>>> = LazyLock::new(Default::default);

fn analyzed(hash: B256) -> Result<Bytecode, Missing> {
    if let Some(code) = ANALYZED.read().get(&hash) {
        return Ok(code.clone());
    }
    let bytes =
        code::code_bytes(&hash.0).ok_or_else(|| Missing(format!("unresolved code {hash}")))?;
    let code = Bytecode::new_raw_checked(bytes).map_err(|err| Missing(err.to_string()))?;
    ANALYZED.write().insert(hash, code.clone());
    Ok(code)
}

fn account_info(nonce: u64, balance: U256, code_hash: B256) -> AccountInfo {
    AccountInfo {
        nonce,
        balance,
        code_hash,
        ..Default::default()
    }
}

fn from_info(info: &Info) -> AccountInfo {
    let account = info.account();
    account_info(
        account.nonce,
        account.balance,
        account.bytecode_hash.unwrap_or(KECCAK256_EMPTY),
    )
}

fn version<T>(versions: &[(u64, T)], at: u64) -> Result<&T, Missing> {
    versions
        .get(versions.partition_point(|(n, _)| *n <= at).wrapping_sub(1))
        .map(|(_, value)| value)
        .ok_or_else(|| Missing(format!("missing state version at {at}")))
}

/// Changes applied on top of a chunk's pre-state, such as earlier transactions' deltas.
#[derive(Clone, Debug, Default)]
pub struct Overlay {
    accounts: HashMap<Address, Option<AccountInfo>>,
    storage: HashMap<(Address, U256), U256>,
    wiped: HashSet<Address>,
    code: HashSet<B256>,
}

/// The canonical state at a block boundary covered by a chunk, plus applied deltas.
#[derive(Clone, Debug)]
pub struct View {
    pub chunk: Arc<Chunk>,
    pub at: u64,
    pub overlay: Overlay,
}

impl View {
    /// The state before the chunk's first block.
    pub fn new(chunk: Arc<Chunk>) -> Self {
        let at = chunk.start - 1;
        Self {
            chunk,
            at,
            overlay: Overlay::default(),
        }
    }

    fn account(&self, address: &Address) -> Result<Option<AccountInfo>, Missing> {
        if let Some(account) = self.overlay.accounts.get(address) {
            return Ok(account.clone());
        }
        let versions = self
            .chunk
            .accounts
            .get(&address.into_array())
            .ok_or_else(|| Missing(format!("uncaptured account {address}")))?;
        Ok(version(versions, self.at)?.as_ref().map(from_info))
    }

    fn storage(&self, address: &Address, key: &U256) -> Result<U256, Missing> {
        if let Some(value) = self.overlay.storage.get(&(*address, *key)) {
            return Ok(*value);
        }
        if self.overlay.wiped.contains(address) {
            return Ok(U256::ZERO);
        }
        let versions = self
            .chunk
            .storage
            .get(&(address.into_array(), key.to_be_bytes()))
            .ok_or_else(|| Missing(format!("uncaptured storage {address} {key}")))?;
        Ok(U256::from_be_bytes(*version(versions, self.at)?))
    }

    fn wipe(&mut self, address: Address) {
        self.overlay.wiped.insert(address);
        self.overlay.storage.retain(|(a, _), _| *a != address);
    }

    /// Applies committed changes in order, as the executor committed them.
    pub fn apply(&mut self, delta: &Delta) -> eyre::Result<()> {
        for commit in &delta.0 {
            for (address, change) in commit {
                let address = Address::from(*address);
                let Some(info) = &change.info else {
                    self.overlay.accounts.insert(address, None);
                    self.wipe(address);
                    continue;
                };
                let mut account = if change.created {
                    AccountInfo::default()
                } else {
                    self.account(&address)?.unwrap_or_default()
                };
                if let Some(nonce) = info.nonce {
                    account.nonce = nonce;
                }
                if let Some(balance) = info.balance {
                    account.balance = U256::from_be_bytes(balance);
                }
                if let Some(hash) = info.code_hash {
                    account.code_hash = hash.map(B256::from).unwrap_or(KECCAK256_EMPTY);
                }
                if let Some(bytes) = &change.code {
                    code::insert_code(&account.code_hash.0, bytes)?;
                    self.overlay.code.insert(account.code_hash);
                }
                if change.created {
                    self.wipe(address);
                }
                for (key, value) in &change.storage {
                    self.overlay.storage.insert(
                        (address, U256::from_be_bytes(*key)),
                        U256::from_be_bytes(*value),
                    );
                }
                self.overlay.accounts.insert(address, Some(account));
            }
        }
        Ok(())
    }
}

impl Database for View {
    type Error = Missing;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Missing> {
        self.account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Missing> {
        if *code_hash == KECCAK256_EMPTY {
            return Ok(Bytecode::default());
        }
        if !self.chunk.code.contains(&code_hash.0) && !self.overlay.code.contains(code_hash) {
            return Err(Missing(format!("uncaptured code {code_hash}")));
        }
        analyzed(*code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Missing> {
        self.storage(address, key)
    }

    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Missing> {
        let number = number.saturating_to::<u64>();
        self.chunk
            .hashes
            .get(&number)
            .copied()
            .map(B256::from)
            .ok_or_else(|| Missing(format!("uncaptured block hash {number}")))
    }
}

/// State keys a block reads, recorded beneath the executor during capture.
#[derive(Debug, Default)]
pub struct Keys {
    pub accounts: BTreeSet<Address>,
    pub storage: BTreeSet<(Address, U256)>,
    pub code: BTreeSet<B256>,
    pub hashes: BTreeSet<u64>,
}

/// Records every key the executor requests from the archive database.
#[derive(Debug)]
pub struct Recording<D> {
    pub inner: D,
    pub keys: Arc<Mutex<Keys>>,
}

impl<D: Database> Database for Recording<D> {
    type Error = D::Error;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.keys.lock().accounts.insert(*address);
        self.inner.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.keys.lock().code.insert(*code_hash);
        self.inner.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Self::Error> {
        self.keys.lock().storage.insert((*address, *key));
        self.inner.get_storage(address, key)
    }

    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Self::Error> {
        self.keys
            .lock()
            .hashes
            .insert(number.saturating_to::<u64>());
        self.inner.get_block_hash(number)
    }
}

/// Converts one committed account update into its stored change. `code` returns the
/// bytecode of a changed, non-empty code hash.
pub fn change_from_update(
    update: &reth_execution_types::AccountUpdate,
    mut code: impl FnMut(B256) -> eyre::Result<Bytes>,
) -> eyre::Result<Change> {
    let created = update.created || update.wiped;
    let deleted = match &update.current {
        None => true,
        Some(current) => !created && current.is_empty(),
    };
    if deleted {
        return Ok(Change {
            info: None,
            created: false,
            storage: BTreeMap::new(),
            code: None,
        });
    }
    let current = update.current.as_ref().expect("not deleted");
    let base = if created {
        AccountInfo::default()
    } else {
        update.original.clone().unwrap_or_default()
    };
    let hash = |h: B256| (h != KECCAK256_EMPTY).then_some(h.0);
    let code_changed = current.code_hash != base.code_hash;
    Ok(Change {
        info: Some(InfoChange {
            nonce: (current.nonce != base.nonce).then_some(current.nonce),
            balance: (current.balance != base.balance).then_some(current.balance.to_be_bytes()),
            code_hash: code_changed.then_some(hash(current.code_hash)),
        }),
        created,
        storage: update
            .storage
            .iter()
            .map(|(key, slot)| (key.to_be_bytes(), slot.present_value.to_be_bytes()))
            .collect(),
        code: if code_changed && current.code_hash != KECCAK256_EMPTY {
            Some(code(current.code_hash)?.to_vec())
        } else {
            None
        },
    })
}
