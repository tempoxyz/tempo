//! Database views over captured corpus state for execution without the archive DB.

use crate::{
    code,
    types::{Change, CodeChange, Delta, InfoChange, Input},
};
use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Database},
    interpreter::Word,
};
use parking_lot::Mutex;
use schnellru::{ByLength, LruMap};
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

/// Most analyzed contracts kept at once. A miss only re-analyzes the verified shared code.
const MAX_ANALYZED: u32 = 16 * 1024;

/// Analyzed bytecode by hash, built from the verified shared code.
static ANALYZED: LazyLock<Mutex<LruMap<B256, Bytecode, ByLength>>> =
    LazyLock::new(|| Mutex::new(LruMap::new(ByLength::new(MAX_ANALYZED))));

fn analyzed(hash: B256) -> Result<Bytecode, Missing> {
    if let Some(code) = ANALYZED.lock().get(&hash) {
        return Ok(code.clone());
    }
    let bytes =
        code::code_bytes(&hash.0).ok_or_else(|| Missing(format!("unresolved code {hash}")))?;
    let code = Bytecode::new_raw_checked(bytes).map_err(|err| Missing(err.to_string()))?;
    ANALYZED.lock().insert(hash, code.clone());
    Ok(code)
}

/// Changes applied on top of an input's pre-state, such as earlier transactions' deltas.
#[derive(Clone, Debug, Default)]
pub struct Overlay {
    accounts: HashMap<Address, Option<AccountInfo>>,
    storage: HashMap<(Address, U256), U256>,
    wiped: HashSet<Address>,
    code: HashSet<B256>,
}

/// The canonical state before an input's block, plus applied deltas. Executors read it by
/// reference, so several can execute on one view without copying it.
#[derive(Debug)]
pub struct View<'p> {
    pub input: Arc<Input>,
    /// The view this one's changes are layered on, if any.
    parent: Option<&'p Self>,
    pub overlay: Overlay,
}

impl View<'_> {
    /// The state before the input's block.
    pub fn new(input: Arc<Input>) -> Self {
        Self {
            input,
            parent: None,
            overlay: Overlay::default(),
        }
    }

    /// An empty layer over this view: deltas applied to it leave this view unchanged.
    pub fn child(&self) -> View<'_> {
        View {
            input: self.input.clone(),
            parent: Some(self),
            overlay: Overlay::default(),
        }
    }

    pub(crate) fn account(&self, address: &Address) -> Result<Option<AccountInfo>, Missing> {
        if let Some(account) = self.overlay.accounts.get(address) {
            return Ok(account.clone());
        }
        if let Some(parent) = self.parent {
            return parent.account(address);
        }
        Ok(self
            .input
            .accounts
            .get(&address.into_array())
            .ok_or_else(|| Missing(format!("uncaptured account {address}")))?
            .as_ref()
            .map(|info| info.account().into()))
    }

    pub(crate) fn storage(&self, address: &Address, key: &U256) -> Result<U256, Missing> {
        if let Some(value) = self.overlay.storage.get(&(*address, *key)) {
            return Ok(*value);
        }
        if self.overlay.wiped.contains(address) {
            return Ok(U256::ZERO);
        }
        if let Some(parent) = self.parent {
            return parent.storage(address, key);
        }
        self.input
            .storage
            .get(&(address.into_array(), key.to_be_bytes()))
            .map(|value| U256::from_be_bytes(*value))
            .ok_or_else(|| Missing(format!("uncaptured storage {address} {key}")))
    }

    fn has_code(&self, code_hash: &B256) -> bool {
        self.overlay.code.contains(code_hash)
            || self
                .parent
                .map_or(self.input.code.contains(&code_hash.0), |parent| {
                    parent.has_code(code_hash)
                })
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
                account.nonce = info.nonce.unwrap_or(account.nonce);
                account.balance = info.balance.map_or(account.balance, U256::from_be_bytes);
                let (code_hash, extension) = match &info.code {
                    CodeChange::Keep => (None, None),
                    CodeChange::Hash(hash) => (Some(*hash), None),
                    CodeChange::Extended {
                        code_hash,
                        extension,
                    } => (*code_hash, Some(extension)),
                };
                account.code_hash = code_hash.map_or(account.code_hash, |hash| {
                    hash.map_or(KECCAK256_EMPTY, B256::from)
                });
                if let Some(extension) = extension {
                    account.extension = extension.clone().into();
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

impl Database for &View<'_> {
    type Error = Missing;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Missing> {
        self.account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Missing> {
        if *code_hash == KECCAK256_EMPTY {
            return Ok(Bytecode::default());
        }
        if !self.has_code(code_hash) {
            return Err(Missing(format!("uncaptured code {code_hash}")));
        }
        analyzed(*code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Missing> {
        self.storage(address, key)
    }

    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Missing> {
        let number = number.saturating_to::<u64>();
        self.input
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
pub struct Recording<'a, D> {
    pub inner: D,
    pub keys: &'a mut Keys,
}

impl<D: Database> Database for Recording<'_, D> {
    type Error = D::Error;

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.keys.accounts.insert(*address);
        self.inner.get_account(address)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        self.keys.code.insert(*code_hash);
        self.inner.get_code_by_hash(code_hash)
    }

    fn get_storage(&mut self, address: &Address, key: &Word) -> Result<Word, Self::Error> {
        self.keys.storage.insert((*address, *key));
        self.inner.get_storage(address, key)
    }

    fn get_block_hash(&mut self, number: &Word) -> Result<B256, Self::Error> {
        self.keys.hashes.insert(number.saturating_to::<u64>());
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
    let Some(current) = update
        .current
        .as_ref()
        .filter(|current| created || !current.is_empty())
    else {
        return Ok(Change {
            info: None,
            created: false,
            storage: BTreeMap::new(),
            code: None,
        });
    };
    let empty = AccountInfo::default();
    let base = update
        .original
        .as_ref()
        .filter(|_| !created)
        .unwrap_or(&empty);
    let code_changed = current.code_hash != base.code_hash;
    let has_code = current.code_hash != KECCAK256_EMPTY;
    let code_hash = code_changed.then_some(has_code.then_some(current.code_hash.0));
    let code_change = if current.extension != base.extension {
        CodeChange::Extended {
            code_hash,
            extension: current.extension.to_vec(),
        }
    } else {
        code_hash.map_or(CodeChange::Keep, CodeChange::Hash)
    };
    Ok(Change {
        info: Some(InfoChange {
            nonce: (current.nonce != base.nonce).then_some(current.nonce),
            balance: (current.balance != base.balance).then_some(current.balance.to_be_bytes()),
            code: code_change,
        }),
        created,
        storage: update
            .storage
            .iter()
            .map(|(key, slot)| (key.to_be_bytes(), slot.present_value.to_be_bytes()))
            .collect(),
        code: (code_changed && has_code)
            .then(|| code(current.code_hash).map(|bytes| bytes.to_vec()))
            .transpose()?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::types::{Block, Info};
    use reth_primitives_traits::Account;

    /// An input whose pre-state holds `accounts` (`None` for one known not to exist) and `storage`.
    pub(crate) fn input(
        accounts: &[(Address, Option<Account>)],
        storage: &[(Address, U256, U256)],
    ) -> Arc<Input> {
        Arc::new(Input {
            number: 1,
            parent: [0; 32],
            block: Block {
                hash: [0; 32],
                rlp: Vec::new(),
                senders: Vec::new(),
                changed_accounts: Vec::new(),
                changed_storage: Vec::new(),
            },
            accounts: accounts
                .iter()
                .map(|(address, account)| {
                    (address.into_array(), account.as_ref().map(Info::capture))
                })
                .collect(),
            storage: storage
                .iter()
                .map(|(address, key, value)| {
                    (
                        (address.into_array(), key.to_be_bytes()),
                        value.to_be_bytes(),
                    )
                })
                .collect(),
            code: BTreeSet::new(),
            hashes: BTreeMap::new(),
            phases: None,
        })
    }

    /// One commit changing `address`.
    pub(crate) fn commit(address: Address, change: Change) -> Delta {
        Delta(vec![[(address.into_array(), change)].into()])
    }

    pub(crate) fn change(info: InfoChange, storage: &[(U256, U256)]) -> Change {
        Change {
            info: Some(info),
            created: false,
            storage: storage
                .iter()
                .map(|(key, value)| (key.to_be_bytes(), value.to_be_bytes()))
                .collect(),
            code: None,
        }
    }

    #[test]
    fn a_child_layers_deltas_over_its_parent() {
        let address = Address::repeat_byte(1);
        let account = Account {
            nonce: 1,
            balance: U256::from(10),
            ..Default::default()
        };
        let (slot, other_slot) = (U256::ZERO, U256::ONE);
        let parent = View::new(input(
            &[(address, Some(account))],
            &[(address, slot, U256::from(5))],
        ));
        let mut child = parent.child();
        let balance = InfoChange {
            nonce: None,
            balance: Some(U256::from(7).to_be_bytes()),
            code: CodeChange::Hash(Some([2; 32])),
        };
        child
            .apply(&commit(address, change(balance, &[(slot, U256::from(9))])))
            .unwrap();
        // A canonical change keeps the fields it does not set, such as a candidate's code.
        let nonce = InfoChange {
            nonce: Some(2),
            balance: None,
            code: CodeChange::Keep,
        };
        child.apply(&commit(address, change(nonce, &[]))).unwrap();

        let changed = child.account(&address).unwrap().unwrap();
        assert_eq!(
            (changed.nonce, changed.balance, changed.code_hash),
            (2, U256::from(7), B256::repeat_byte(2))
        );
        assert_eq!(child.storage(&address, &slot).unwrap(), U256::from(9));
        let unchanged = parent.account(&address).unwrap().unwrap();
        assert_eq!((unchanged.nonce, unchanged.balance), (1, U256::from(10)));
        assert_eq!(parent.storage(&address, &slot).unwrap(), U256::from(5));
        // Reads the child has no value for go through to what the parent captured.
        assert_eq!(
            child
                .storage(&address, &other_slot)
                .unwrap_err()
                .to_string(),
            format!("uncaptured storage {address} {other_slot}")
        );

        // Creating the account in a child hides the parent's storage from the child only.
        let mut created = parent.child();
        let mut recreate = change(
            InfoChange {
                nonce: Some(1),
                balance: None,
                code: CodeChange::Keep,
            },
            &[],
        );
        recreate.created = true;
        created.apply(&commit(address, recreate)).unwrap();
        assert_eq!(created.storage(&address, &slot).unwrap(), U256::ZERO);
        assert_eq!(created.storage(&address, &other_slot).unwrap(), U256::ZERO);
        assert_eq!(parent.storage(&address, &slot).unwrap(), U256::from(5));
    }
}
