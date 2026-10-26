//! The pre-state blocks execute on, and how the state they leave is reported.

use std::{cell::Cell, collections::BTreeMap, fmt, sync::LazyLock};

use alloy_primitives::{Address, B256, Bytes, U256, map::B256Map};
use reth_trie_common::{
    TrieAccount,
    root::{state_root_unhashed, storage_root_unhashed},
};
use revm::{
    DatabaseRef,
    bytecode::Bytecode,
    database::{
        BundleState, CacheState, DBErrorMarker, EmptyDB, PlainAccount, State,
        StorageWithOriginalValues, TransitionState,
    },
    database_interface::WrapDatabaseRef,
    state::AccountInfo,
};
use tempo_fuzz_types::{
    AccountDiff, AccountInput, ErrorClass, PreState, StateChanges, StateInput, StorageChangeOutput,
};

/// The state blocks execute on, as the node executes blocks: revm's `State` with bundle updates,
/// over the seeded pre-state.
pub(crate) type Db = State<WrapDatabaseRef<PreStateDb>>;

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

impl DBErrorMarker for MissingPreState {}

/// Answers misses on a genesis pre-state the way revm's `EmptyDB` does, which fuzz inputs rely on.
impl DatabaseRef for PreStateDb {
    type Error = MissingPreState;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.miss(MissingPreState::Account(address))?;
        let Ok(info) = EmptyDB::new().basic_ref(address);
        Ok(info)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.miss(MissingPreState::Code(code_hash))?;
        let Ok(code) = EmptyDB::new().code_by_hash_ref(code_hash);
        Ok(code)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.miss(MissingPreState::Storage(address, slot))?;
        let Ok(value) = EmptyDB::new().storage_ref(address, slot);
        Ok(value)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.miss(MissingPreState::BlockHash(number))?;
        let Ok(hash) = EmptyDB::new().block_hash_ref(number);
        Ok(hash)
    }
}

/// The dev genesis allocation, seeded once per process: seeding analyses and hashes every genesis
/// contract, which costs more than executing a transfer.
static GENESIS: LazyLock<CacheState> = LazyLock::new(|| {
    let mut cache = CacheState::new();
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

/// `pre_state` as a database. `InvalidInput` if a genesis pre-state overrides a genesis account, or
/// if an account's code starts with the EIP-7702 prefix `0xef01` but is not a valid delegation.
pub(crate) fn seed(pre_state: &PreState) -> Result<Db, ErrorClass> {
    let (state, mut cache, exact) = match pre_state {
        PreState::Genesis(state) => {
            if state
                .accounts
                .keys()
                .any(|address| GENESIS.accounts.contains_key(address))
            {
                return Err(ErrorClass::InvalidInput);
            }
            (state, GENESIS.clone(), false)
        }
        PreState::Exact { state, .. } => (state, CacheState::new(), true),
    };
    for (address, account) in &state.accounts {
        insert(&mut cache, *address, account)?;
    }
    let mut db = State::builder()
        .with_database(WrapDatabaseRef(PreStateDb {
            exact,
            missed: Cell::new(false),
        }))
        .with_cached_prestate(cache)
        .with_bundle_update()
        .build();
    if let PreState::Exact { block_hashes, .. } = pre_state {
        db.block_hashes
            .extend(block_hashes.iter().map(|(n, h)| (*n, *h)));
    }
    Ok(db)
}

/// Whether `account` holds nothing: an extractor lists the slots a block read even for an account
/// that does not exist, all of them zero.
fn is_empty(account: &AccountInput) -> bool {
    account.balance.is_zero()
        && account.nonce == 0
        && account.code.is_empty()
        && account.storage.values().all(U256::is_zero)
}

/// Inserts `account`, its code and the slots the pre-state holds for it, or records that it does not
/// exist if it holds nothing. Other slots are read from the database below. `InvalidInput` if its
/// code is a malformed EIP-7702 delegation.
fn insert(
    cache: &mut CacheState,
    address: Address,
    account: &AccountInput,
) -> Result<(), ErrorClass> {
    if is_empty(account) {
        cache.insert_not_existing(address);
        return Ok(());
    }
    let code =
        Bytecode::new_raw_checked(account.code.clone()).map_err(|_| ErrorClass::InvalidInput)?;
    let info = AccountInfo::from_balance(account.balance)
        .with_nonce(account.nonce)
        .with_code(code);
    if let Some(code) = &info.code {
        cache.contracts.insert(info.code_hash, code.clone());
    }
    let storage = account.storage.iter().map(|(slot, value)| (*slot, *value));
    cache.insert_account_with_storage(address, info, storage.collect());
    Ok(())
}

/// The net changes recorded since the last call: the state transitions of one execution step.
pub(crate) fn drain(db: &mut Db) -> TransitionState {
    db.transition_state
        .as_mut()
        .expect("the state records bundle updates")
        .take()
}

/// The state `pre` holds with `bundle` applied: what blocks that applied left.
pub(crate) fn after(pre: &CacheState, bundle: &BundleState) -> BTreeMap<Address, PlainAccount> {
    let mut accounts: BTreeMap<_, _> = pre
        .accounts
        .iter()
        .filter_map(|(address, account)| Some((*address, account.account.clone()?)))
        .collect();
    for (address, account) in &bundle.state {
        let Some(info) = &account.info else {
            accounts.remove(address);
            continue;
        };
        let after = accounts.entry(*address).or_default();
        after.info = info.clone();
        // A destroyed account keeps none of its earlier slots.
        if account.status.was_destroyed() {
            after.storage.clear();
        }
        after.storage.extend(
            account
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

/// `accounts`, as an outcome reports them. Code comes from the accounts or, by hash, from
/// `contracts`.
pub(crate) fn encode(
    accounts: &BTreeMap<Address, PlainAccount>,
    contracts: &B256Map<Bytecode>,
) -> StateInput {
    let accounts = accounts
        .iter()
        .map(|(address, account)| {
            let account = AccountInput {
                balance: account.info.balance,
                nonce: account.info.nonce,
                code: code(&account.info, contracts),
                storage: account.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            };
            (*address, account)
        })
        .collect();
    StateInput { accounts }
}

fn code(info: &AccountInfo, contracts: &B256Map<Bytecode>) -> Bytes {
    info.code
        .as_ref()
        .or_else(|| contracts.get(&info.code_hash))
        .map(Bytecode::original_bytes)
        .unwrap_or_default()
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
        };
        (*address, trie_account)
    }))
}

/// One account's net change, as both transitions and bundles record it.
struct Change<'a> {
    before: Option<&'a AccountInfo>,
    after: Option<&'a AccountInfo>,
    storage_cleared: bool,
    storage: &'a StorageWithOriginalValues,
}

/// `changes` as an outcome reports them, by address and then slot.
fn state_changes<'a>(
    changes: impl Iterator<Item = (Address, Change<'a>)>,
    contracts: &B256Map<Bytecode>,
) -> StateChanges {
    let changes: BTreeMap<_, _> = changes.collect();
    let mut out = StateChanges::default();
    let empty = AccountInfo::default();
    for (address, change) in changes {
        let (before, after) = (
            change.before.unwrap_or(&empty),
            change.after.unwrap_or(&empty),
        );
        let diff = AccountDiff {
            address,
            exists: (change.before.is_some() != change.after.is_some())
                .then_some(change.after.is_some()),
            balance: (before.balance != after.balance).then_some(after.balance),
            nonce: (before.nonce != after.nonce).then_some(after.nonce),
            code: (before.code_hash != after.code_hash).then(|| code(after, contracts)),
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
        let slots: BTreeMap<_, _> = change
            .storage
            .iter()
            .filter(|(_, slot)| slot.is_changed())
            .collect();
        out.storage
            .extend(slots.into_iter().map(|(slot, value)| StorageChangeOutput {
                address,
                slot: *slot,
                before: value.previous_or_original_value,
                after: value.present_value,
            }));
    }
    out
}

/// The changes `transitions` record.
pub(crate) fn transition_changes(
    transitions: &TransitionState,
    contracts: &B256Map<Bytecode>,
) -> StateChanges {
    let changes = transitions.transitions.iter().map(|(address, account)| {
        let change = Change {
            before: account.previous_info.as_ref(),
            after: account.info.as_ref(),
            storage_cleared: account.storage_was_destroyed,
            storage: &account.storage,
        };
        (*address, change)
    });
    state_changes(changes, contracts)
}

/// The changes `bundle` records.
pub(crate) fn bundle_changes(bundle: &BundleState, contracts: &B256Map<Bytecode>) -> StateChanges {
    let changes = bundle.state.iter().map(|(address, account)| {
        let change = Change {
            before: account.original_info.as_ref(),
            after: account.info.as_ref(),
            storage_cleared: account.status.was_destroyed(),
            storage: &account.storage,
        };
        (*address, change)
    });
    state_changes(changes, contracts)
}
