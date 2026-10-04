use super::*;
use reth_evm::parent_reads::{ParentReadBatch, ValidateParentReads};
use reth_revm::{
    Database as _, State,
    db::{AccountStatus, BundleAccount, BundleState, states::StorageSlot},
    state::{Account, EvmState, bal::Bal},
};
use revm::database::EmptyDB;

type Witness = (usize, Address, U256, U256);
type ValidationError = <State<Provider> as reth_revm::Database>::Error;
type Candidate = SpeculativeResult<ValidationError>;

#[derive(Debug, thiserror::Error)]
#[error("provider unavailable")]
struct Unavailable;
impl DBErrorMarker for Unavailable {}

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Offer(usize),
    Basic(Address),
    Storage(U256),
    Witness(usize),
    Fallback(U256),
    Clear,
}
#[derive(Debug, Default)]
struct Provider {
    inner: CacheDB<EmptyDB>,
    events: Vec<Event>,
    offered: Option<Witness>,
    fail_basic: bool,
    fail_slot: Option<U256>,
}
impl reth_revm::Database for Provider {
    type Error = Unavailable;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.events.push(Event::Basic(address));
        if self.fail_basic {
            return Err(Unavailable);
        }
        Ok(self.inner.basic(address).unwrap())
    }
    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.events.push(Event::Storage(slot));
        if let Some((index, key_address, key_slot, value)) = self.offered.take()
            && (address, slot) == (key_address, key_slot)
        {
            self.events.push(Event::Witness(index));
            return Ok(value);
        }
        self.events.push(Event::Fallback(slot));
        if self.fail_slot == Some(slot) {
            return Err(Unavailable);
        }
        Ok(self.inner.storage(address, slot).unwrap())
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        Ok(self.inner.code_by_hash(hash).unwrap())
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self.inner.block_hash(number).unwrap())
    }
}
fn hooks<'db>() -> ValidateParentReads<&'db mut State<Provider>> {
    ValidateParentReads {
        offer: |state, batch, index, address, slot, expected| {
            state.database.events.push(Event::Offer(index));
            // Only test transport: sealed provider identities are tested in Engine-tree.
            state.database.offered = batch
                .opaque
                .downcast_ref::<Vec<Witness>>()
                .and_then(|reads| {
                    reads
                        .iter()
                        .find(|&&entry| entry == (index, address, slot, expected))
                })
                .copied();
        },
        clear: |state| {
            state.database.events.push(Event::Clear);
            state.database.offered = None;
        },
    }
}
fn batch(reads: &[(ReadKey, ReadValue)]) -> ParentReadBatch {
    let values: Vec<Witness> = reads
        .iter()
        .enumerate()
        .filter_map(|(index, (key, value))| match (key, value) {
            (ReadKey::Storage(address, slot), ReadValue::Storage(value)) => {
                Some((index, *address, *slot, *value))
            }
            _ => None,
        })
        .collect();
    let estimated_bytes = std::mem::size_of::<Vec<Witness>>()
        + values.capacity() * std::mem::size_of::<Witness>()
        + 64;
    ParentReadBatch {
        opaque: Arc::new(values),
        estimated_bytes,
    }
}
fn candidate(reads: Vec<(ReadKey, ReadValue)>) -> Candidate {
    let (parent, env, tx, _, _) = tests::native_increment_tests::fixture();
    let mut candidate = PrewarmingExecutor::new(parent, env)
        .execute(tx.clone(), None)
        .unwrap()
        .into_candidate(&tx)
        .unwrap();
    candidate.parent_reads = Some(batch(&reads));
    candidate.reads = reads;
    candidate.fee_updates.clear();
    candidate.native_increment = None;
    candidate
}
fn validate(
    candidate: &mut Candidate,
    mut state: &mut State<Provider>,
) -> Result<bool, ValidationError> {
    candidate.validate_state_with_parent_reads(&mut state, Some(hooks()))
}
fn fixture() -> (State<Provider>, Address) {
    let address = Address::with_last_byte(221);
    let mut provider = Provider::default();
    provider.inner.insert_account_info(
        address,
        AccountInfo {
            nonce: 1,
            ..Default::default()
        },
    );
    provider
        .inner
        .insert_account_storage(address, U256::ONE, U256::from(7))
        .unwrap();
    provider
        .inner
        .insert_account_storage(address, U256::from(2), U256::from(11))
        .unwrap();
    (State::builder().with_database(provider).build(), address)
}
fn storage(address: Address, slot: u64, value: u64) -> (ReadKey, ReadValue) {
    (
        ReadKey::Storage(address, U256::from(slot)),
        ReadValue::Storage(U256::from(value)),
    )
}

#[test]
fn offers_materialize_cold_reads_but_never_override_current_cache() {
    let (mut state, address) = fixture();
    let mut result = candidate(vec![storage(address, 1, 7), storage(address, 1, 7)]);
    assert!(validate(&mut result, &mut state).unwrap());
    assert_eq!(
        state.database.events,
        vec![
            Event::Offer(0),
            Event::Basic(address),
            Event::Storage(U256::ONE),
            Event::Witness(0),
            Event::Clear
        ]
    );
    let slot = state
        .cache
        .accounts
        .get_mut(&address)
        .unwrap()
        .account
        .as_mut()
        .unwrap()
        .storage
        .get_mut(&U256::ONE)
        .unwrap();
    assert_eq!(*slot, U256::from(7));
    *slot = U256::from(99);
    state.database.events.clear();
    assert!(!validate(&mut result, &mut state).unwrap());
    assert!(state.database.events.is_empty());
    assert!(state.database.offered.is_none());
}

#[test]
fn account_lifecycle_keeps_known_zero_authoritative_and_materialized() {
    for lifecycle in ["created", "destroyed", "absent"] {
        let (mut state, address) = fixture();
        if lifecycle == "absent" {
            state.database.inner = CacheDB::default();
        }
        state.basic(address).unwrap();
        if lifecycle != "absent" {
            let mut account = Account::default();
            account.mark_touch();
            if lifecycle == "created" {
                account.mark_created();
                account.info.nonce = 1;
            } else {
                account.mark_selfdestruct();
            }
            state.commit(EvmState::from_iter([(address, account)]));
        }
        state.database.events.clear();
        // The parent offered seven, but the current account has no such storage.
        assert!(!validate(&mut candidate(vec![storage(address, 1, 7)]), &mut state).unwrap());
        assert!(!state.database.events.iter().any(|event| matches!(
            event,
            Event::Storage(_) | Event::Witness(_) | Event::Fallback(_)
        )));
        assert!(state.database.offered.is_none());
        if lifecycle == "created" {
            assert_eq!(state.database.events, vec![Event::Offer(0), Event::Clear]);
            let cached = state.cache.accounts.get_mut(&address).unwrap();
            assert_eq!(
                cached.account.as_ref().unwrap().storage[&U256::ONE],
                U256::ZERO
            );
            // A later direct status mutation must still observe that inserted zero.
            cached.status = AccountStatus::Loaded;
        }
        state.database.events.clear();
        assert!(validate(&mut candidate(vec![storage(address, 1, 0)]), &mut state).unwrap());
        assert!(state.database.events.is_empty());
    }
}

#[test]
fn errors_clear_offers_and_first_conflict_precedes_later_provider_failure() {
    for scenario in [
        "account_error",
        "storage_error",
        "first_conflict",
        "foreign_batch",
    ] {
        let (mut state, address) = fixture();
        state.database.fail_basic = scenario == "account_error";
        state.database.fail_slot = match scenario {
            "storage_error" => Some(U256::ONE),
            "first_conflict" => Some(U256::from(2)),
            _ => None,
        };
        let mut result = candidate(vec![
            storage(address, 1, if scenario == "first_conflict" { 8 } else { 7 }),
            storage(address, 2, 11),
        ]);
        // Unrecognized batches must preserve ordinary provider reads and errors.
        result.parent_reads = Some(ParentReadBatch {
            opaque: Arc::new(()),
            estimated_bytes: 0,
        });
        let actual = validate(&mut result, &mut state);
        assert!(state.database.offered.is_none());
        match scenario {
            "account_error" => {
                assert!(actual.is_err());
                assert_eq!(
                    state.database.events,
                    vec![Event::Offer(0), Event::Basic(address), Event::Clear]
                );
                assert!(!state.cache.accounts.contains_key(&address));
            }
            "storage_error" => {
                assert!(actual.is_err());
                assert_eq!(
                    state.database.events,
                    vec![
                        Event::Offer(0),
                        Event::Basic(address),
                        Event::Storage(U256::ONE),
                        Event::Fallback(U256::ONE),
                        Event::Clear
                    ]
                );
                assert!(
                    !state.cache.accounts[&address]
                        .account
                        .as_ref()
                        .unwrap()
                        .storage
                        .contains_key(&U256::ONE)
                );
            }
            "first_conflict" => {
                assert!(!actual.unwrap());
                assert_eq!(
                    state.database.events,
                    vec![
                        Event::Offer(0),
                        Event::Basic(address),
                        Event::Storage(U256::ONE),
                        Event::Fallback(U256::ONE),
                        Event::Clear
                    ]
                );
                assert_eq!(
                    state.cache.accounts[&address]
                        .account
                        .as_ref()
                        .unwrap()
                        .storage[&U256::ONE],
                    U256::from(7)
                );
            }
            _ => {
                assert!(actual.unwrap());
                assert_eq!(
                    state.database.events,
                    vec![
                        Event::Offer(0),
                        Event::Basic(address),
                        Event::Storage(U256::ONE),
                        Event::Fallback(U256::ONE),
                        Event::Clear,
                        Event::Offer(1),
                        Event::Storage(U256::from(2)),
                        Event::Fallback(U256::from(2)),
                        Event::Clear
                    ]
                );
            }
        }
    }
}

#[test]
fn bal_and_preloaded_bundle_receive_no_offers() {
    let (mut state, address) = fixture();
    let mut result = candidate(vec![storage(address, 1, 7)]);
    state.set_bal(Some(Arc::new(Bal::new())));
    state.bump_bal_index();
    assert!(validate(&mut result, &mut state).is_err());
    assert!(
        !state
            .database
            .events
            .iter()
            .any(|event| matches!(event, Event::Offer(_) | Event::Clear))
    );
    state.set_bal(None);
    state.database.events.clear();
    assert!(validate(&mut result, &mut state).unwrap());
    assert!(state.database.events.contains(&Event::Witness(0)));

    let (state, address) = fixture();
    let info = AccountInfo {
        nonce: 1,
        ..Default::default()
    };
    let mut bundle = BundleState::default();
    bundle.state.insert(
        address,
        BundleAccount::new(
            Some(info.clone()),
            Some(info),
            HashMap::from_iter([(
                U256::ONE,
                StorageSlot::new_changed(U256::ZERO, U256::from(77)),
            )]),
            AccountStatus::Loaded,
        ),
    );
    let mut state = State::builder()
        .with_database(state.database)
        .with_bundle_prestate(bundle)
        .build();
    assert!(!validate(&mut candidate(vec![storage(address, 1, 7)]), &mut state).unwrap());
    assert!(state.database.events.is_empty());
    assert_eq!(
        state.cache.accounts[&address]
            .account
            .as_ref()
            .unwrap()
            .storage[&U256::ONE],
        U256::from(77)
    );
}

#[test]
fn fee_and_native_rebase_restarts_keep_absolute_offer_indices() {
    for native in [false, true] {
        let (parent, env, tx, token, slot) = tests::native_increment_tests::fixture();
        let mut result: Candidate = PrewarmingExecutor::new(parent.clone(), env)
            .execute(tx.clone(), Some(0))
            .unwrap()
            .into_candidate(&tx)
            .unwrap();
        let (address, slot, changed) = if native {
            assert!(result.native_increment.is_some());
            (token, slot, U256::from(20))
        } else {
            let update = result.fee_updates.first().unwrap();
            let old = result
                .reads
                .iter()
                .find_map(|(key, value)| match (key, value) {
                    (ReadKey::Storage(address, slot), ReadValue::Storage(value))
                        if (*address, *slot) == (update.address, update.slot) =>
                    {
                        Some(*value)
                    }
                    _ => None,
                })
                .unwrap();
            let changed = old.checked_add(U256::ONE).unwrap();
            assert!(update.apply(changed).is_some());
            (update.address, update.slot, changed)
        };
        let last_index = result.reads.len();
        assert!(
            !result
                .reads
                .iter()
                .any(|(key, _)| *key == ReadKey::Storage(token, U256::MAX))
        );
        result.reads.push((
            ReadKey::Storage(token, U256::MAX),
            ReadValue::Storage(U256::ZERO),
        ));
        result.parent_reads = Some(batch(&result.reads));
        let mut state = State::builder()
            .with_database(Provider {
                inner: parent,
                ..Default::default()
            })
            .build();
        state.basic(address).unwrap();
        state
            .cache
            .accounts
            .get_mut(&address)
            .unwrap()
            .account
            .as_mut()
            .unwrap()
            .storage
            .insert(slot, changed);
        state.database.events.clear();
        assert!(validate(&mut result, &mut state).unwrap());
        assert_eq!(result.native_rebased, native);
        assert_eq!(result.fees_rebased, !native);
        assert!(state.database.events.contains(&Event::Offer(last_index)));
        assert!(state.database.events.contains(&Event::Witness(last_index)));
        assert_eq!(state.database.events.last(), Some(&Event::Clear));
        assert!(state.database.offered.is_none());
    }
}
