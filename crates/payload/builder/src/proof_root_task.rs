//! Background TIP-1082 proof-root computation for payload building.

use alloy_consensus::constants::EMPTY_ROOT_HASH;
use alloy_primitives::{
    Address, B256, keccak256,
    map::{AddressMap, B256Map},
};
use reth_evm::{OnStateHook, block::BlockExecutionError};
use reth_primitives_traits::Account;
use reth_revm::state::EvmState;
use reth_storage_api::{StateProvider, StateProviderBox, errors::provider::ProviderResult};
use reth_tasks::TaskExecutor;
use reth_trie_common::{HashedPostState, HashedStorage, root::state_root_unhashed};
use std::sync::Arc;
use tokio::sync::oneshot;

/// Proof root state for a payload.
#[derive(Debug)]
pub(crate) enum ProofRootTaskHandle {
    /// Proof roots are inactive for this payload timestamp.
    Inactive,
    /// Proof root is known without spawning a task.
    Ready(B256),
    /// Proof root is being computed in the background.
    Running(ProofRootTask),
}

impl ProofRootTaskHandle {
    pub(crate) const fn inactive() -> Self {
        Self::Inactive
    }

    pub(crate) const fn ready(root: B256) -> Self {
        Self::Ready(root)
    }

    pub(crate) fn spawn(
        executor: &TaskExecutor,
        state_provider: StateProviderBox,
        provable_accounts: Arc<[Address]>,
    ) -> Self {
        Self::Running(ProofRootTask::spawn(
            executor,
            state_provider,
            proof_root_targets(provable_accounts),
        ))
    }

    pub(crate) fn state_hook(&self) -> Option<ProofRootHook> {
        match self {
            Self::Running(task) => Some(task.state_hook()),
            Self::Inactive | Self::Ready(_) => None,
        }
    }

    pub(crate) fn wait(self) -> Result<Option<B256>, BlockExecutionError> {
        match self {
            Self::Inactive => Ok(None),
            Self::Ready(root) => Ok(Some(root)),
            Self::Running(task) => task.wait().map(Some),
        }
    }
}

/// Composite state hook used by the builder.
///
/// The proof hook observes the update by reference and then forwards the original owned update to
/// the downstream sparse-trie hook, if one is installed.
pub(crate) struct BuilderStateHook {
    proof_root_hook: Option<ProofRootHook>,
    downstream_hook: Option<Box<dyn OnStateHook>>,
}

impl BuilderStateHook {
    pub(crate) fn new(
        proof_root_hook: Option<ProofRootHook>,
        downstream_hook: Option<Box<dyn OnStateHook>>,
    ) -> Option<Self> {
        if proof_root_hook.is_none() && downstream_hook.is_none() {
            None
        } else {
            Some(Self {
                proof_root_hook,
                downstream_hook,
            })
        }
    }
}

impl OnStateHook for BuilderStateHook {
    fn on_state(&mut self, state: EvmState) {
        if let Some(proof_root_hook) = &self.proof_root_hook {
            proof_root_hook.on_state_ref(&state);
        }

        if let Some(downstream_hook) = &mut self.downstream_hook {
            downstream_hook.on_state(state);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProofRootTask {
    update_tx: crossbeam_channel::Sender<ProofRootMessage>,
    result_rx: oneshot::Receiver<ProviderResult<B256>>,
    targets: Arc<[ProofRootTarget]>,
}

impl ProofRootTask {
    fn spawn(
        executor: &TaskExecutor,
        state_provider: StateProviderBox,
        targets: Arc<[ProofRootTarget]>,
    ) -> Self {
        let (update_tx, update_rx) = crossbeam_channel::unbounded();
        let (result_tx, result_rx) = oneshot::channel();
        let task_targets = Arc::clone(&targets);

        executor.spawn_blocking_named("builder-proof-root-task", move || {
            let result = run_proof_root_task(&*state_provider, &task_targets, update_rx);
            let _ = result_tx.send(result);
        });

        Self {
            update_tx,
            result_rx,
            targets,
        }
    }

    fn state_hook(&self) -> ProofRootHook {
        ProofRootHook {
            update_tx: self.update_tx.clone(),
            targets: Arc::clone(&self.targets),
        }
    }

    fn wait(self) -> Result<B256, BlockExecutionError> {
        self.result_rx
            .blocking_recv()
            .map_err(|_| BlockExecutionError::msg("proof root task dropped"))?
            .map_err(BlockExecutionError::other)
    }
}

#[derive(Debug)]
pub(crate) struct ProofRootHook {
    update_tx: crossbeam_channel::Sender<ProofRootMessage>,
    targets: Arc<[ProofRootTarget]>,
}

impl ProofRootHook {
    fn on_state_ref(&self, state: &EvmState) {
        let hashed_state = proof_hashed_state_from_evm_state_update(state, &self.targets);
        if !hashed_state.is_empty() {
            let _ = self.update_tx.send(ProofRootMessage::Update(hashed_state));
        }
    }
}

impl Drop for ProofRootHook {
    fn drop(&mut self) {
        let _ = self.update_tx.send(ProofRootMessage::Finish);
    }
}

#[derive(Debug)]
enum ProofRootMessage {
    Update(HashedPostState),
    Finish,
}

#[derive(Debug, Clone, Copy)]
struct ProofRootTarget {
    address: Address,
    hashed_address: B256,
}

fn proof_root_targets(provable_accounts: Arc<[Address]>) -> Arc<[ProofRootTarget]> {
    provable_accounts
        .iter()
        .map(|address| ProofRootTarget {
            address: *address,
            hashed_address: keccak256(address),
        })
        .collect()
}

#[derive(Debug, Clone)]
struct ProofAccountState {
    account: Option<Account>,
    storage: HashedStorage,
    storage_root: B256,
}

fn run_proof_root_task(
    state_provider: &dyn StateProvider,
    targets: &[ProofRootTarget],
    update_rx: crossbeam_channel::Receiver<ProofRootMessage>,
) -> ProviderResult<B256> {
    let mut accounts = preload_proof_accounts(state_provider, targets)?;
    let mut current_root = proof_root_from_loaded_accounts(targets, &accounts);
    let mut dirty_accounts = AddressMap::default();

    loop {
        let mut finished = match update_rx.recv() {
            Ok(ProofRootMessage::Update(update)) => {
                apply_proof_update(targets, &mut accounts, &mut dirty_accounts, &update);
                false
            }
            Ok(ProofRootMessage::Finish) | Err(_) => true,
        };

        while !finished {
            match update_rx.try_recv() {
                Ok(ProofRootMessage::Update(update)) => {
                    apply_proof_update(targets, &mut accounts, &mut dirty_accounts, &update);
                }
                Ok(ProofRootMessage::Finish)
                | Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    finished = true;
                }
                Err(crossbeam_channel::TryRecvError::Empty) => break,
            }
        }

        if !dirty_accounts.is_empty() {
            recompute_dirty_storage_roots(state_provider, &mut accounts, &dirty_accounts)?;
            dirty_accounts.clear();
            current_root = proof_root_from_loaded_accounts(targets, &accounts);
        }

        if finished {
            return Ok(current_root);
        }
    }
}

fn preload_proof_accounts(
    state_provider: &dyn StateProvider,
    targets: &[ProofRootTarget],
) -> ProviderResult<AddressMap<ProofAccountState>> {
    let mut accounts = AddressMap::default();
    accounts.reserve(targets.len());

    for target in targets {
        let account = state_provider.basic_account(&target.address)?;
        let storage_root = if account.is_some() {
            state_provider.storage_root(target.address, HashedStorage::default())?
        } else {
            EMPTY_ROOT_HASH
        };

        accounts.insert(
            target.address,
            ProofAccountState {
                account,
                storage: HashedStorage::default(),
                storage_root,
            },
        );
    }

    Ok(accounts)
}

fn apply_proof_update(
    targets: &[ProofRootTarget],
    accounts: &mut AddressMap<ProofAccountState>,
    dirty_accounts: &mut AddressMap<()>,
    hashed_state: &HashedPostState,
) {
    for target in targets {
        let account_update = hashed_state.accounts.get(&target.hashed_address);
        let storage_update = hashed_state.storages.get(&target.hashed_address);
        if account_update.is_none() && storage_update.is_none() {
            continue;
        }

        let account_state = accounts
            .get_mut(&target.address)
            .expect("proof account preloaded");

        if let Some(account) = account_update {
            account_state.account = *account;
        }
        if let Some(storage) = storage_update {
            account_state.storage.extend(storage);
        }

        dirty_accounts.insert(target.address, ());
    }
}

fn recompute_dirty_storage_roots(
    state_provider: &dyn StateProvider,
    accounts: &mut AddressMap<ProofAccountState>,
    dirty_accounts: &AddressMap<()>,
) -> ProviderResult<()> {
    for address in dirty_accounts.keys().copied() {
        let account_state = accounts
            .get_mut(&address)
            .expect("dirty proof account preloaded");
        account_state.storage_root = if account_state.account.is_some() {
            state_provider.storage_root(address, account_state.storage.clone())?
        } else {
            EMPTY_ROOT_HASH
        };
    }

    Ok(())
}

fn proof_root_from_loaded_accounts(
    targets: &[ProofRootTarget],
    accounts: &AddressMap<ProofAccountState>,
) -> B256 {
    state_root_unhashed(targets.iter().filter_map(|target| {
        let account_state = accounts.get(&target.address)?;
        let account = account_state.account?;
        if account.is_empty() && account_state.storage_root == EMPTY_ROOT_HASH {
            None
        } else {
            Some((
                target.address,
                account.into_trie_account(account_state.storage_root),
            ))
        }
    }))
}

fn proof_hashed_state_from_evm_state_update(
    state: &EvmState,
    targets: &[ProofRootTarget],
) -> HashedPostState {
    let mut hashed_state = HashedPostState::with_capacity(targets.len().min(state.len()));

    for target in targets {
        let Some(account) = state.get(&target.address) else {
            continue;
        };
        if !account.is_touched() {
            continue;
        }

        let destroyed = account.is_selfdestructed();
        if account.info != account.original_info() {
            let info = if destroyed {
                None
            } else {
                Some(Account::from(account.info.clone()))
            };
            hashed_state.accounts.insert(target.hashed_address, info);
        }

        let mut changed_storage = B256Map::default();
        if !destroyed {
            changed_storage.extend(
                account
                    .storage
                    .iter()
                    .filter(|(_, value)| value.is_changed())
                    .map(|(slot, value)| (keccak256(B256::from(*slot)), value.present_value)),
            );
        }

        if destroyed {
            hashed_state
                .storages
                .insert(target.hashed_address, HashedStorage::new(true));
        } else if !changed_storage.is_empty() {
            hashed_state.storages.insert(
                target.hashed_address,
                HashedStorage::from_iter(false, changed_storage),
            );
        }
    }

    hashed_state
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;
    use reth_revm::state::{Account as RevmAccount, AccountInfo, EvmStorageSlot};

    fn target(address: Address) -> ProofRootTarget {
        ProofRootTarget {
            address,
            hashed_address: keccak256(address),
        }
    }

    fn account(nonce: u64) -> AccountInfo {
        AccountInfo {
            nonce,
            balance: U256::from(nonce + 1),
            code_hash: Default::default(),
            account_id: None,
            code: None,
        }
    }

    #[test]
    fn hashes_only_whitelisted_evm_updates() {
        let whitelisted = Address::repeat_byte(0x11);
        let other = Address::repeat_byte(0x22);
        let mut state = EvmState::default();
        state.insert(
            whitelisted,
            RevmAccount::from(account(1))
                .with_info(account(2))
                .with_touched_mark(),
        );
        state.insert(
            other,
            RevmAccount::from(account(1))
                .with_info(account(3))
                .with_touched_mark(),
        );

        let hashed = proof_hashed_state_from_evm_state_update(&state, &[target(whitelisted)]);

        assert!(hashed.accounts.contains_key(&keccak256(whitelisted)));
        assert!(!hashed.accounts.contains_key(&keccak256(other)));
    }

    #[test]
    fn hashes_whitelisted_storage_updates() {
        let address = Address::repeat_byte(0x11);
        let slot = U256::from(1);
        let value = U256::from(7);
        let mut state = EvmState::default();
        state.insert(
            address,
            RevmAccount::from(account(1))
                .with_storage(
                    [(
                        slot,
                        EvmStorageSlot::new_changed(U256::ZERO, value, Default::default()),
                    )]
                    .into_iter(),
                )
                .with_touched_mark(),
        );

        let hashed = proof_hashed_state_from_evm_state_update(&state, &[target(address)]);

        let storage = hashed.storages.get(&keccak256(address)).unwrap();
        assert_eq!(
            storage.storage.get(&keccak256(B256::from(slot))).copied(),
            Some(value)
        );
    }

    #[test]
    fn hashes_selfdestruct_as_account_and_storage_deletion() {
        let address = Address::repeat_byte(0x11);
        let mut state = EvmState::default();
        state.insert(
            address,
            RevmAccount::from(account(1))
                .with_info(AccountInfo::default())
                .with_selfdestruct_mark()
                .with_touched_mark(),
        );

        let hashed = proof_hashed_state_from_evm_state_update(&state, &[target(address)]);
        let hashed_address = keccak256(address);

        assert_eq!(hashed.accounts.get(&hashed_address), Some(&None));
        assert!(
            hashed
                .storages
                .get(&hashed_address)
                .is_some_and(|storage| storage.wiped)
        );
    }

    #[test]
    fn applies_hashed_updates_in_order() {
        let address = Address::repeat_byte(0x11);
        let target = target(address);
        let hashed_address = target.hashed_address;
        let slot = keccak256(B256::from(U256::from(1)));
        let mut accounts = AddressMap::from_iter([(
            address,
            ProofAccountState {
                account: Some(Account {
                    nonce: 1,
                    balance: U256::from(2),
                    bytecode_hash: None,
                }),
                storage: HashedStorage::default(),
                storage_root: EMPTY_ROOT_HASH,
            },
        )]);
        let mut dirty = AddressMap::default();
        let destroy_update = HashedPostState::default()
            .with_accounts([(hashed_address, None)])
            .with_storages([(hashed_address, HashedStorage::new(true))]);
        let recreate_update = HashedPostState::default()
            .with_accounts([(
                hashed_address,
                Some(Account {
                    nonce: 2,
                    balance: U256::from(3),
                    bytecode_hash: None,
                }),
            )])
            .with_storages([(
                hashed_address,
                HashedStorage::from_iter(false, [(slot, U256::from(4))]),
            )]);

        apply_proof_update(&[target], &mut accounts, &mut dirty, &destroy_update);
        apply_proof_update(&[target], &mut accounts, &mut dirty, &recreate_update);

        let account = accounts.get(&address).unwrap();
        assert_eq!(account.account.unwrap().nonce, 2);
        assert!(account.storage.wiped);
        assert_eq!(account.storage.storage.get(&slot), Some(&U256::from(4)));
        assert!(dirty.contains_key(&address));
    }
}
