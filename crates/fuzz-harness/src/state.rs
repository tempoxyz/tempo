//! The pre-state blocks execute on, and how the state they leave is reported.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    fmt,
    sync::LazyLock,
};

use alloy_primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, map::B256Map};
use evm2::{
    bytecode::Bytecode,
    evm::{AccountInfo, Cache, Database, EmptyDB},
};
use reth_execution_types::StateUpdate;
use reth_trie_common::{
    TrieAccount,
    bundle_state::{PlainAccount, StorageSlot},
    root::{state_root_unhashed, storage_root_unhashed},
};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, ErrorClass, PreState, StateChanges, StateInput, StorageChangeOutput,
};

/// The state blocks execute on: what the pre-state and the blocks before left in `cache`, over
/// `pre`, which answers what the cache does not hold.
///
/// An EVM reads it through [`Db::reader`]. Execution steps are committed to the cache between
/// reads, with [`Db::commit`].
pub(crate) struct Db {
    pub(crate) cache: RefCell<Cache>,
    pub(crate) pre: PreStateDb,
}

impl Db {
    /// A database that records what it loads in the cache, as an executing EVM reads it.
    pub(crate) fn reader(&self) -> Reader<'_> {
        Reader {
            db: self,
            record: true,
        }
    }

    /// A database for view calls, which leaves the cache as it is.
    pub(crate) fn view(&self) -> Reader<'_> {
        Reader {
            db: self,
            record: false,
        }
    }

    /// Writes the net changes of an execution step to the cache. `code` finds the bytecode of an
    /// account the step gave new code.
    pub(crate) fn commit(&self, net: &Net, code: impl Fn(&B256) -> Option<Bytecode>) {
        let mut cache = self.cache.borrow_mut();
        for (address, change) in &net.0 {
            let info = change.current.clone().map(|mut info| {
                info.code = None;
                info
            });
            if let Some(info) = &info
                && info.code_hash != KECCAK256_EMPTY
                && !cache.contracts.contains_key(&info.code_hash)
                && let Some(code) = code(&info.code_hash)
            {
                cache.contracts.insert(info.code_hash, code);
            }
            cache.accounts.insert(*address, info);
            let storage = cache.storage.entry(*address).or_default();
            // An account that did not exist has no slots, whatever the pre-state lists for it.
            if change.storage_cleared || change.original.is_none() {
                storage.wipe();
            }
            storage.slots.extend(
                change
                    .storage
                    .iter()
                    .map(|(slot, value)| (*slot, value.present_value)),
            );
        }
    }
}

/// What execution reads when the seeded state does not hold a key. For a genesis pre-state that is
/// empty state. For an exact pre-state it is an error, also recorded so the input is known to be
/// incomplete even when the error was swallowed on its way up.
#[derive(Debug)]
pub(crate) struct PreStateDb {
    exact: bool,
    missed: Cell<bool>,
}

impl PreStateDb {
    /// Whether a read missed an exact pre-state.
    pub(crate) fn missed(&self) -> bool {
        self.missed.get()
    }

    /// Sets the miss flag, e.g. back to a value saved before reads that are not part of execution.
    pub(crate) fn restore_missed(&self, missed: bool) {
        self.missed.set(missed);
    }

    fn miss(&self, missing: MissingPreState) -> Result<(), MissingPreState> {
        if !self.exact {
            return Ok(());
        }
        self.missed.set(true);
        Err(missing)
    }

    fn account(&self, address: &Address) -> Result<Option<AccountInfo>, MissingPreState> {
        self.miss(MissingPreState::Account(*address))?;
        Ok(None)
    }

    fn code(&self, hash: &B256) -> Result<Bytecode, MissingPreState> {
        self.miss(MissingPreState::Code(*hash))?;
        Ok(Bytecode::default())
    }

    fn storage(&self, address: &Address, slot: &U256) -> Result<U256, MissingPreState> {
        self.miss(MissingPreState::Storage(*address, *slot))?;
        Ok(U256::ZERO)
    }

    fn block_hash(&self, number: &U256) -> Result<B256, MissingPreState> {
        self.miss(MissingPreState::BlockHash(number.saturating_to()))?;
        let Ok(hash) = EmptyDB::default().get_block_hash(number);
        Ok(hash)
    }
}

/// A read of a key an exact pre-state does not hold.
#[derive(Debug)]
pub(crate) enum MissingPreState {
    Account(Address),
    Storage(Address, U256),
    Code(B256),
    BlockHash(u64),
}

impl fmt::Display for MissingPreState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the exact pre-state does not hold ")?;
        match self {
            Self::Account(address) => write!(f, "account {address}"),
            Self::Storage(address, slot) => write!(f, "slot {slot} of {address}"),
            Self::Code(hash) => write!(f, "code {hash}"),
            Self::BlockHash(number) => write!(f, "the hash of block {number}"),
        }
    }
}

impl core::error::Error for MissingPreState {}

/// Reads [`Db`]: its cache first, then the pre-state, as a cache over a database does. A genesis
/// pre-state answers misses the way an empty database does, which fuzz inputs rely on.
pub(crate) struct Reader<'a> {
    db: &'a Db,
    record: bool,
}

impl Database for Reader<'_> {
    type Error = MissingPreState;

    fn is_fatal(_error: &Self::Error) -> bool {
        false
    }

    fn get_account(&mut self, address: &Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.db.cache.borrow().accounts.get(address) {
            return Ok(account.clone());
        }
        let account = self.db.pre.account(address)?;
        if self.record {
            let mut cache = self.db.cache.borrow_mut();
            cache.accounts.insert(*address, account.clone());
        }
        Ok(account)
    }

    fn get_code_by_hash(&mut self, code_hash: &B256) -> Result<Bytecode, Self::Error> {
        if let Some(code) = self.db.cache.borrow().contracts.get(code_hash) {
            return Ok(code.clone());
        }
        let code = self.db.pre.code(code_hash)?;
        if self.record {
            let mut cache = self.db.cache.borrow_mut();
            cache.contracts.insert(*code_hash, code.clone());
        }
        Ok(code)
    }

    fn get_storage(&mut self, address: &Address, key: &U256) -> Result<U256, Self::Error> {
        {
            let cache = self.db.cache.borrow();
            if let Some(storage) = cache.storage.get(address) {
                if let Some(value) = storage.slots.get(key) {
                    return Ok(*value);
                }
                if storage.wiped {
                    return Ok(U256::ZERO);
                }
            }
            if cache.accounts.get(address).is_some_and(Option::is_none) {
                return Ok(U256::ZERO);
            }
        }
        let value = self.db.pre.storage(address, key)?;
        if self.record {
            let mut cache = self.db.cache.borrow_mut();
            cache
                .storage
                .entry(*address)
                .or_default()
                .slots
                .insert(*key, value);
        }
        Ok(value)
    }

    fn get_block_hash(&mut self, number: &U256) -> Result<B256, Self::Error> {
        if let Some(hash) = self.db.cache.borrow().block_hashes.get(number) {
            return Ok(*hash);
        }
        let hash = self.db.pre.block_hash(number)?;
        if self.record {
            let mut cache = self.db.cache.borrow_mut();
            cache.block_hashes.insert(*number, hash);
        }
        Ok(hash)
    }
}

/// The dev genesis allocation, seeded once per process: seeding analyses and hashes every genesis
/// contract, which costs more than executing a transfer.
static GENESIS: LazyLock<Cache> = LazyLock::new(|| {
    let mut cache = Cache::default();
    for (address, account) in &tempo_chainspec::spec::DEV.inner.genesis.alloc {
        let account = AccountInput {
            balance: account.balance,
            nonce: account.nonce.unwrap_or_default(),
            code: account.code.clone().unwrap_or_default(),
            storage: account
                .storage
                .iter()
                .flatten()
                .map(|(slot, value)| ((*slot).into(), (*value).into()))
                .collect(),
        };
        insert(&mut cache, *address, &account).expect("the dev genesis code is well-formed");
    }
    cache
});

/// `pre_state` as a database. A genesis pre-state's account at a genesis address replaces it whole,
/// but must keep the genesis code: a protocol contract's code marks it deployed. `InvalidInput` if it
/// does not, or if an account's code starts with the EIP-7702 prefix `0xef01` but is not a valid
/// delegation.
pub(crate) fn seed(pre_state: &PreState) -> Result<Db, ErrorClass> {
    let (state, mut cache, exact) = match pre_state {
        PreState::Genesis(state) => {
            let keeps_code = |(address, account): (&Address, &AccountInput)| {
                GENESIS
                    .accounts
                    .get(address)
                    .and_then(Option::as_ref)
                    .is_none_or(|genesis| {
                        account.code == Contracts(&[&GENESIS.contracts]).code(genesis)
                    })
            };
            if !state.accounts.iter().all(keeps_code) {
                return Err(ErrorClass::InvalidInput);
            }
            (state, GENESIS.clone(), false)
        }
        PreState::Exact { state, .. } => (state, Cache::default(), true),
    };
    for (address, account) in &state.accounts {
        insert(&mut cache, *address, account)?;
    }
    if let PreState::Exact { block_hashes, .. } = pre_state {
        cache
            .block_hashes
            .extend(block_hashes.iter().map(|(n, h)| (U256::from(*n), *h)));
    }
    Ok(Db {
        cache: RefCell::new(cache),
        pre: PreStateDb {
            exact,
            missed: Cell::new(false),
        },
    })
}

/// Whether `account` holds nothing: an extractor lists the slots a block read even for an account
/// that does not exist, all of them zero.
fn is_empty(account: &AccountInput) -> bool {
    account.balance.is_zero()
        && account.nonce == 0
        && account.code.is_empty()
        && account.storage.values().all(U256::is_zero)
}

/// Replaces the account at `address` with `account`, its code and the slots the pre-state holds for
/// it, or records that it does not exist if it holds nothing. Other slots are read from the
/// database. `InvalidInput` if its code is a malformed EIP-7702 delegation.
fn insert(cache: &mut Cache, address: Address, account: &AccountInput) -> Result<(), ErrorClass> {
    cache.storage.remove(&address);
    if is_empty(account) {
        cache.accounts.insert(address, None);
        return Ok(());
    }
    let code =
        Bytecode::new_raw_checked(account.code.clone()).map_err(|_| ErrorClass::InvalidInput)?;
    let mut info = AccountInfo::default()
        .with_balance(account.balance)
        .with_nonce(account.nonce)
        .with_code(code.clone());
    info.code = None;
    if info.code_hash != KECCAK256_EMPTY {
        cache.contracts.insert(info.code_hash, code);
    }
    cache.accounts.insert(address, Some(info));
    cache
        .storage
        .entry(address)
        .or_default()
        .slots
        .extend(account.storage.iter().map(|(slot, value)| (*slot, *value)));
    Ok(())
}

/// The net changes execution made to one account over a span of steps.
#[derive(Default)]
pub(crate) struct AccountNet {
    /// The account before the first change, `None` if it did not exist.
    original: Option<AccountInfo>,
    /// The account after the last change, `None` if it does not exist.
    current: Option<AccountInfo>,
    /// Whether all of its storage was cleared first.
    storage_cleared: bool,
    /// The slots written after the clear, with their values before the first write.
    storage: BTreeMap<U256, StorageSlot>,
}

/// The net changes of a span of execution steps, by address.
#[derive(Default)]
pub(crate) struct Net(BTreeMap<Address, AccountNet>);

impl Net {
    /// The net changes of `updates`, applied in order.
    pub(crate) fn of<'a>(updates: impl IntoIterator<Item = &'a StateUpdate>) -> Self {
        let mut net = Self::default();
        for update in updates {
            net.apply(update);
        }
        net
    }

    /// Applies a later update on top of the changes so far.
    pub(crate) fn apply(&mut self, update: &StateUpdate) {
        for account in &update.accounts {
            let net = self.0.entry(account.address).or_insert_with(|| AccountNet {
                original: account.original.clone(),
                current: account.original.clone(),
                ..Default::default()
            });
            net.current = account.current.clone();
            // A clear starts a new storage lifetime.
            if account.wiped {
                net.storage_cleared = true;
                net.storage.clear();
            }
            for (slot, value) in &account.storage {
                net.storage
                    .entry(*slot)
                    .and_modify(|slot| slot.present_value = value.present_value())
                    .or_insert_with(|| {
                        StorageSlot::new_changed(value.original_value(), value.present_value())
                    });
            }
        }
    }

    /// Whether the span changed the account at `address`.
    pub(crate) fn contains(&self, address: &Address) -> bool {
        self.0.contains_key(address)
    }
}

/// The state `pre` holds with `net` applied: what blocks that applied left.
pub(crate) fn after(pre: &Cache, net: &Net) -> BTreeMap<Address, PlainAccount> {
    let mut accounts: BTreeMap<_, _> = pre
        .accounts
        .iter()
        .filter_map(|(address, account)| {
            let storage = pre
                .storage
                .get(address)
                .map(|storage| storage.slots.clone())
                .unwrap_or_default();
            Some((
                *address,
                PlainAccount {
                    info: account.clone()?,
                    storage,
                },
            ))
        })
        .collect();
    for (address, change) in &net.0 {
        let Some(info) = &change.current else {
            accounts.remove(address);
            continue;
        };
        let after = accounts.entry(*address).or_default();
        after.info = info.clone();
        // A destroyed account keeps none of its earlier slots.
        if change.storage_cleared {
            after.storage.clear();
        }
        after.storage.extend(
            change
                .storage
                .iter()
                .map(|(slot, value)| (*slot, value.present_value)),
        );
    }
    for account in accounts.values_mut() {
        account.storage.retain(|_, value| !value.is_zero());
    }
    accounts
}

/// `accounts`, as an outcome reports them. Code comes from `contracts`, by hash.
pub(crate) fn encode(
    accounts: &BTreeMap<Address, PlainAccount>,
    contracts: &Contracts<'_>,
) -> StateInput {
    let accounts = accounts
        .iter()
        .map(|(address, account)| {
            let account = AccountInput {
                balance: account.info.balance,
                nonce: account.info.nonce,
                code: contracts.code(&account.info),
                storage: account.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            };
            (*address, account)
        })
        .collect();
    StateInput { accounts }
}

/// Where the code of an account is found, by its hash: the first of several maps that holds it.
pub(crate) struct Contracts<'a>(pub(crate) &'a [&'a B256Map<Bytecode>]);

impl Contracts<'_> {
    fn code(&self, info: &AccountInfo) -> Bytes {
        info.code
            .as_ref()
            .or_else(|| self.0.iter().find_map(|map| map.get(&info.code_hash)))
            .map(Bytecode::original_bytes)
            .unwrap_or_default()
    }
}

/// The state root of `accounts`, which must be the whole state.
pub(crate) fn state_root(accounts: &BTreeMap<Address, PlainAccount>) -> B256 {
    state_root_unhashed(accounts.iter().map(|(address, account)| {
        let storage = account
            .storage
            .iter()
            .map(|(slot, value)| (B256::from(*slot), *value));
        let trie_account = TrieAccount {
            nonce: account.info.nonce,
            balance: account.info.balance,
            storage_root: storage_root_unhashed(storage),
            code_hash: account.info.code_hash,
            extension: Default::default(),
        };
        (*address, trie_account)
    }))
}

/// `net` as an outcome reports it, by address and then slot.
pub(crate) fn changes(net: &Net, contracts: &Contracts<'_>) -> StateChanges {
    let mut out = StateChanges::default();
    let empty = AccountInfo::default();
    for (address, change) in &net.0 {
        let (before, after) = (
            change.original.as_ref().unwrap_or(&empty),
            change.current.as_ref().unwrap_or(&empty),
        );
        let diff = AccountDiff {
            address: *address,
            exists: (change.original.is_some() != change.current.is_some())
                .then_some(change.current.is_some()),
            balance: (before.balance != after.balance).then_some(after.balance),
            nonce: (before.nonce != after.nonce).then_some(after.nonce),
            code: (before.code_hash != after.code_hash).then(|| contracts.code(after)),
            storage_cleared: change.storage_cleared,
        };
        if diff.exists.is_some()
            || diff.balance.is_some()
            || diff.nonce.is_some()
            || diff.code.is_some()
            || diff.storage_cleared
        {
            out.accounts.push(diff);
        }
        out.storage.extend(
            change
                .storage
                .iter()
                .filter(|(_, slot)| slot.is_changed())
                .map(|(slot, value)| StorageChangeOutput {
                    address: *address,
                    slot: *slot,
                    before: value.previous_or_original_value,
                    after: value.present_value,
                }),
        );
    }
    out
}
