use alloy_consensus::{BlockHeader as _, constants::KECCAK_EMPTY};
use alloy_eip7928::{AccountChanges, bal::DecodedBal};
use alloy_primitives::{
    Address, B256, BlockNumber, Bytes, StorageKey, StorageValue, U256, keccak256,
};
use reth_errors::{ProviderError, ProviderResult};
use reth_primitives_traits::{Account, Bytecode, SealedHeader};
use reth_revm::db::BundleState;
use reth_storage_api::{
    AccountReader, BlockHashReader, BytecodeReader, HashedPostStateProvider, StateProofProvider,
    StateProvider, StateProviderBox, StateRootProvider, StorageRootProvider,
};
use reth_trie_common::{
    AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage, MultiProof,
    MultiProofTargets, StorageMultiProof, StorageProof, TrieInput, updates::TrieUpdates,
};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tempo_primitives::TempoHeader;
use tracing::debug;

/// State provider that exposes a speculative parent block's BAL post-state over its canonical parent.
pub(crate) struct BalOverlayStateProvider {
    inner: StateProviderBox,
    parent_header: Arc<SealedHeader<TempoHeader>>,
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<StorageKey, StorageValue>>,
    bytecodes: HashMap<B256, Bytecode>,
    hashed_post_state: HashedPostState,
}

struct DecodedBalOverlay {
    accounts: HashMap<Address, Account>,
    storage: HashMap<Address, HashMap<StorageKey, StorageValue>>,
    bytecodes: HashMap<B256, Bytecode>,
    hashed_post_state: HashedPostState,
}

/// Builds the hashed post-state represented by a block access list.
pub fn block_access_list_hashed_post_state(
    inner: &dyn StateProvider,
    raw_bal: &Bytes,
) -> ProviderResult<HashedPostState> {
    Ok(decode_block_access_list_overlay(inner, raw_bal)?.hashed_post_state)
}

impl BalOverlayStateProvider {
    pub(crate) fn new(
        inner: StateProviderBox,
        parent_header: Arc<SealedHeader<TempoHeader>>,
        raw_bal: Bytes,
    ) -> ProviderResult<Self> {
        let decode_start = Instant::now();
        let DecodedBalOverlay {
            accounts,
            storage,
            bytecodes,
            hashed_post_state,
        } = decode_block_access_list_overlay(inner.as_ref(), &raw_bal)?;

        debug!(
            target: "payload_builder",
            parent_hash = %parent_header.hash(),
            parent_number = parent_header.number(),
            accounts = accounts.len(),
            storage_accounts = storage.len(),
            bytecodes = bytecodes.len(),
            elapsed = ?decode_start.elapsed(),
            "constructed BAL overlay state provider"
        );

        Ok(Self {
            inner,
            parent_header,
            accounts,
            storage,
            bytecodes,
            hashed_post_state,
        })
    }
}

impl BalOverlayStateProvider {
    fn merge_hashed_state(&self, child_state: HashedPostState) -> HashedPostState {
        let mut state = self.hashed_post_state.clone();
        state.extend(child_state);
        state
    }

    fn prepend_overlay(&self, input: &mut TrieInput) {
        input.prepend_self(TrieInput::from_state(self.hashed_post_state.clone()));
    }

    fn merged_storage(&self, address: Address, child_storage: HashedStorage) -> HashedStorage {
        let mut storage = self
            .hashed_post_state
            .storages
            .get(&keccak256(address))
            .cloned()
            .unwrap_or_default();
        storage.extend(&child_storage);
        storage
    }
}

impl BlockHashReader for BalOverlayStateProvider {
    fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
        if number == self.parent_header.number() {
            return Ok(Some(self.parent_header.hash()));
        }

        self.inner.block_hash(number)
    }

    fn canonical_hashes_range(
        &self,
        start: BlockNumber,
        end: BlockNumber,
    ) -> ProviderResult<Vec<B256>> {
        let mut hashes = self.inner.canonical_hashes_range(start, end)?;
        if (start..end).contains(&self.parent_header.number()) {
            hashes.push(self.parent_header.hash());
        }
        Ok(hashes)
    }
}

impl AccountReader for BalOverlayStateProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        if let Some(account) = self.accounts.get(address) {
            return Ok(Some(*account));
        }

        self.inner.basic_account(address)
    }
}

impl BytecodeReader for BalOverlayStateProvider {
    fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        if *code_hash == KECCAK_EMPTY {
            return Ok(None);
        }
        if let Some(bytecode) = self.bytecodes.get(code_hash) {
            return Ok(Some(bytecode.clone()));
        }

        self.inner.bytecode_by_hash(code_hash)
    }
}

impl StateProvider for BalOverlayStateProvider {
    fn storage(
        &self,
        account: Address,
        storage_key: StorageKey,
    ) -> ProviderResult<Option<StorageValue>> {
        if let Some(value) = self
            .storage
            .get(&account)
            .and_then(|slots| slots.get(&storage_key))
        {
            return Ok(Some(*value));
        }

        self.inner.storage(account, storage_key)
    }
}

impl HashedPostStateProvider for BalOverlayStateProvider {
    fn hashed_post_state(&self, bundle_state: &BundleState) -> HashedPostState {
        self.inner.hashed_post_state(bundle_state)
    }
}

impl StateRootProvider for BalOverlayStateProvider {
    fn state_root(&self, hashed_state: HashedPostState) -> ProviderResult<B256> {
        self.inner.state_root(self.merge_hashed_state(hashed_state))
    }

    fn state_root_from_nodes(&self, mut input: TrieInput) -> ProviderResult<B256> {
        self.prepend_overlay(&mut input);
        self.inner.state_root_from_nodes(input)
    }

    fn state_root_with_updates(
        &self,
        hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.inner
            .state_root_with_updates(self.merge_hashed_state(hashed_state))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        mut input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        self.prepend_overlay(&mut input);
        self.inner.state_root_from_nodes_with_updates(input)
    }
}

impl StorageRootProvider for BalOverlayStateProvider {
    fn storage_root(&self, address: Address, storage: HashedStorage) -> ProviderResult<B256> {
        self.inner
            .storage_root(address, self.merged_storage(address, storage))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        self.inner
            .storage_proof(address, slot, self.merged_storage(address, storage))
    }

    fn storage_multiproof(
        &self,
        address: Address,
        slots: &[B256],
        storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        self.inner
            .storage_multiproof(address, slots, self.merged_storage(address, storage))
    }
}

impl StateProofProvider for BalOverlayStateProvider {
    fn proof(
        &self,
        mut input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        self.prepend_overlay(&mut input);
        self.inner.proof(input, address, slots)
    }

    fn multiproof(
        &self,
        mut input: TrieInput,
        targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        self.prepend_overlay(&mut input);
        self.inner.multiproof(input, targets)
    }

    fn witness(
        &self,
        mut input: TrieInput,
        target: HashedPostState,
        mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        self.prepend_overlay(&mut input);
        self.inner.witness(input, target, mode)
    }
}

fn decode_block_access_list_overlay(
    inner: &dyn StateProvider,
    raw_bal: &Bytes,
) -> ProviderResult<DecodedBalOverlay> {
    let decoded = DecodedBal::from_rlp_bytes(raw_bal.clone()).map_err(ProviderError::Rlp)?;
    let bal = decoded.as_bal();

    let mut accounts = HashMap::with_capacity(bal.account_count());
    let mut storage = HashMap::with_capacity(bal.account_count());
    let mut bytecodes = HashMap::new();
    let mut hashed_post_state = HashedPostState::with_capacity(bal.account_count());

    for account_changes in bal {
        apply_account_changes(
            inner,
            account_changes,
            &mut accounts,
            &mut storage,
            &mut bytecodes,
            &mut hashed_post_state,
        )?;
    }

    Ok(DecodedBalOverlay {
        accounts,
        storage,
        bytecodes,
        hashed_post_state,
    })
}

fn apply_account_changes(
    inner: &dyn StateProvider,
    account_changes: &AccountChanges,
    accounts: &mut HashMap<Address, Account>,
    storage: &mut HashMap<Address, HashMap<StorageKey, StorageValue>>,
    bytecodes: &mut HashMap<B256, Bytecode>,
    hashed_post_state: &mut HashedPostState,
) -> ProviderResult<()> {
    let address = account_changes.address;
    let hashed_address = keccak256(address);

    if !account_changes.storage_changes.is_empty() {
        let plain_storage = storage.entry(address).or_default();
        let hashed_storage = hashed_post_state
            .storages
            .entry(hashed_address)
            .or_insert_with(|| HashedStorage::new(false));

        for slot_changes in &account_changes.storage_changes {
            let Some(last_change) = slot_changes.changes.last() else {
                continue;
            };
            let storage_key = storage_key_from_bal_slot(slot_changes.slot);
            plain_storage.insert(storage_key, last_change.new_value);

            let hashed_slot = keccak256(slot_changes.slot.to_be_bytes::<32>());
            hashed_storage
                .storage
                .insert(hashed_slot, last_change.new_value);
        }
    }

    let balance = account_changes
        .balance_changes
        .last()
        .map(|change| change.post_balance);
    let nonce = account_changes
        .nonce_changes
        .last()
        .map(|change| change.new_nonce);
    let code_hash = account_changes.code_changes.last().map(|code_change| {
        if code_change.new_code.is_empty() {
            KECCAK_EMPTY
        } else {
            let code_hash = keccak256(&code_change.new_code);
            bytecodes.insert(code_hash, Bytecode::new_raw(code_change.new_code.clone()));
            code_hash
        }
    });

    if balance.is_none()
        && nonce.is_none()
        && code_hash.is_none()
        && account_changes.storage_changes.is_empty()
    {
        return Ok(());
    }

    let existing_account = inner.basic_account(&address)?;
    let account = Account {
        balance: balance.unwrap_or_else(|| {
            existing_account
                .as_ref()
                .map(|account| account.balance)
                .unwrap_or(U256::ZERO)
        }),
        nonce: nonce.unwrap_or_else(|| {
            existing_account
                .as_ref()
                .map(|account| account.nonce)
                .unwrap_or(0)
        }),
        bytecode_hash: code_hash.or_else(|| {
            existing_account
                .as_ref()
                .and_then(|account| account.bytecode_hash)
                .or(Some(KECCAK_EMPTY))
        }),
    };

    accounts.insert(address, account);
    hashed_post_state
        .accounts
        .insert(hashed_address, Some(account));
    Ok(())
}

fn storage_key_from_bal_slot(slot: U256) -> StorageKey {
    B256::from(slot.to_be_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eip7928::{
        AccountChanges, BalanceChange, BlockAccessIndex, CodeChange, NonceChange, SlotChanges,
        StorageChange, bal::Bal,
    };
    use reth_storage_api::{
        AccountReader, BytecodeReader, HashedPostStateProvider, StateProofProvider, StateProvider,
        StateRootProvider, StorageRootProvider,
    };

    #[derive(Default)]
    struct MockStateProvider {
        accounts: HashMap<Address, Account>,
        storage: HashMap<(Address, StorageKey), StorageValue>,
        bytecodes: HashMap<B256, Bytecode>,
        block_hashes: HashMap<BlockNumber, B256>,
    }

    impl BlockHashReader for MockStateProvider {
        fn block_hash(&self, number: BlockNumber) -> ProviderResult<Option<B256>> {
            Ok(self.block_hashes.get(&number).copied())
        }

        fn canonical_hashes_range(
            &self,
            start: BlockNumber,
            end: BlockNumber,
        ) -> ProviderResult<Vec<B256>> {
            Ok((start..end)
                .filter_map(|number| self.block_hashes.get(&number).copied())
                .collect())
        }
    }

    impl AccountReader for MockStateProvider {
        fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
            Ok(self.accounts.get(address).copied())
        }
    }

    impl BytecodeReader for MockStateProvider {
        fn bytecode_by_hash(&self, code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
            Ok(self.bytecodes.get(code_hash).cloned())
        }
    }

    impl StateProvider for MockStateProvider {
        fn storage(
            &self,
            account: Address,
            storage_key: StorageKey,
        ) -> ProviderResult<Option<StorageValue>> {
            Ok(self.storage.get(&(account, storage_key)).copied())
        }
    }

    impl HashedPostStateProvider for MockStateProvider {
        fn hashed_post_state(&self, _bundle_state: &BundleState) -> HashedPostState {
            HashedPostState::default()
        }
    }

    impl StateRootProvider for MockStateProvider {
        fn state_root(&self, _hashed_state: HashedPostState) -> ProviderResult<B256> {
            Ok(B256::ZERO)
        }

        fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
            Ok(B256::ZERO)
        }

        fn state_root_with_updates(
            &self,
            _hashed_state: HashedPostState,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            Ok((B256::ZERO, TrieUpdates::default()))
        }

        fn state_root_from_nodes_with_updates(
            &self,
            _input: TrieInput,
        ) -> ProviderResult<(B256, TrieUpdates)> {
            Ok((B256::ZERO, TrieUpdates::default()))
        }
    }

    impl StorageRootProvider for MockStateProvider {
        fn storage_root(&self, _address: Address, _storage: HashedStorage) -> ProviderResult<B256> {
            Ok(B256::ZERO)
        }

        fn storage_proof(
            &self,
            _address: Address,
            _slot: B256,
            _storage: HashedStorage,
        ) -> ProviderResult<StorageProof> {
            Err(ProviderError::UnsupportedProvider)
        }

        fn storage_multiproof(
            &self,
            _address: Address,
            _slots: &[B256],
            _storage: HashedStorage,
        ) -> ProviderResult<StorageMultiProof> {
            Err(ProviderError::UnsupportedProvider)
        }
    }

    impl StateProofProvider for MockStateProvider {
        fn proof(
            &self,
            _input: TrieInput,
            _address: Address,
            _slots: &[B256],
        ) -> ProviderResult<AccountProof> {
            Err(ProviderError::UnsupportedProvider)
        }

        fn multiproof(
            &self,
            _input: TrieInput,
            _targets: MultiProofTargets,
        ) -> ProviderResult<MultiProof> {
            Err(ProviderError::UnsupportedProvider)
        }

        fn witness(
            &self,
            _input: TrieInput,
            _target: HashedPostState,
            _mode: ExecutionWitnessMode,
        ) -> ProviderResult<Vec<Bytes>> {
            Err(ProviderError::UnsupportedProvider)
        }
    }

    #[test]
    fn bal_overlay_reads_post_state_before_inner_provider() {
        let address = Address::from([0x11; 20]);
        let storage_slot = U256::from(7);
        let storage_key = storage_key_from_bal_slot(storage_slot);
        let code = Bytes::from_static(&[0x60, 0x01]);
        let code_hash = keccak256(&code);

        let mut inner = MockStateProvider::default();
        inner.accounts.insert(
            address,
            Account {
                balance: U256::from(1),
                nonce: 1,
                bytecode_hash: None,
            },
        );
        inner.storage.insert((address, storage_key), U256::from(1));

        let bal = Bal::new(vec![
            AccountChanges::new(address)
                .with_storage_change(SlotChanges::new(
                    storage_slot,
                    vec![StorageChange::new(
                        BlockAccessIndex::new(1),
                        U256::from(0xbeefu64),
                    )],
                ))
                .with_balance_change(BalanceChange::new(BlockAccessIndex::new(1), U256::from(2)))
                .with_nonce_change(NonceChange::new(BlockAccessIndex::new(1), 3))
                .with_code_change(CodeChange::new(BlockAccessIndex::new(1), code.clone())),
        ]);
        let raw_bal = Bytes::from(alloy_rlp::encode(bal));

        let parent_header = Arc::new(SealedHeader::new_unhashed(TempoHeader {
            inner: alloy_consensus::Header {
                number: 10,
                ..Default::default()
            },
            ..Default::default()
        }));
        let overlay =
            BalOverlayStateProvider::new(Box::new(inner), parent_header.clone(), raw_bal).unwrap();

        assert_eq!(
            overlay.basic_account(&address).unwrap(),
            Some(Account {
                balance: U256::from(2),
                nonce: 3,
                bytecode_hash: Some(code_hash),
            })
        );
        assert_eq!(
            overlay.storage(address, storage_key).unwrap(),
            Some(U256::from(0xbeefu64))
        );
        assert_eq!(
            overlay.bytecode_by_hash(&code_hash).unwrap(),
            Some(Bytecode::new_raw(code))
        );
        assert_eq!(overlay.block_hash(10).unwrap(), Some(parent_header.hash()));
    }
}
