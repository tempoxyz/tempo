use super::*;
use alloy_primitives::{Bytes, TxKind};
use revm::{
    Database as _,
    context::TxEnv,
    database::{CacheDB, EmptyDB, State},
    state::bal::Bal,
};

fn candidate<E: DBErrorMarker>(reads: Vec<(ReadKey, ReadValue)>) -> SpeculativeResult<E> {
    let (_, env) = crate::test_utils::test_evm_with_basefee(EmptyDB::default(), 0).finish();
    let tx = TempoTxEnv {
        inner: TxEnv {
            caller: Address::with_last_byte(201),
            kind: TxKind::Call(Address::with_last_byte(202)),
            gas_limit: 1_000_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut worker = PrewarmingExecutor::new(EmptyDB::default(), env);
    let mut candidate = worker
        .execute(tx.clone(), None)
        .unwrap()
        .into_candidate(&tx)
        .unwrap();
    candidate.reads = reads;
    candidate
}

fn fixture() -> (CacheDB<EmptyDB>, Address, B256, Vec<ReadKey>) {
    let address = Address::with_last_byte(211);
    let code = Bytecode::new_raw(Bytes::from_static(&[0x60, 0, 0]));
    let info = AccountInfo {
        nonce: 1,
        ..Default::default()
    }
    .with_code(code);
    let hash = info.code_hash;
    let mut db = CacheDB::<EmptyDB>::default();
    db.insert_account_info(address, info);
    db.insert_account_storage(address, U256::ONE, U256::from(7))
        .unwrap();
    (
        db,
        address,
        hash,
        vec![
            ReadKey::Account(address),
            ReadKey::Storage(address, U256::ONE),
            ReadKey::Storage(address, U256::from(2)),
            ReadKey::Code(hash),
            ReadKey::BlockHash(1),
        ],
    )
}

fn compare(
    canonical: &mut State<CacheDB<EmptyDB>>,
    cached: &mut State<CacheDB<EmptyDB>>,
    reads: &[(ReadKey, ReadValue)],
) -> Result<bool, String> {
    let mut normal = candidate(reads.to_vec());
    let mut fast = candidate(reads.to_vec());
    let expected = normal
        .validate(canonical)
        .map_err(|error| format!("{error:?}"));
    let actual = fast
        .validate_state(cached)
        .map_err(|error| format!("{error:?}"));
    assert_eq!(actual, expected);
    assert_eq!(
        format!("{:?}", fast.conflict),
        format!("{:?}", normal.conflict)
    );
    assert_eq!(fast.result.unwrap(), normal.result.unwrap());
    assert_eq!(fast.fees_rebased, normal.fees_rebased);
    actual
}

#[test]
fn canonical_cache_validation_tracks_cold_reads_and_direct_mutations() {
    let (parent, address, hash, keys) = fixture();
    let mut oracle = State::builder().with_database(parent.clone()).build();
    let reads = keys
        .into_iter()
        .map(|key| (key, read(&mut oracle, key).unwrap()))
        .collect::<Vec<_>>();
    for changed in ["none", "account", "storage", "code", "block_hash"] {
        let mut canonical = State::builder().with_database(parent.clone()).build();
        let mut cached = State::builder().with_database(parent.clone()).build();
        assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
        for db in [&mut canonical, &mut cached] {
            match changed {
                "account" => {
                    db.cache
                        .accounts
                        .get_mut(&address)
                        .unwrap()
                        .account
                        .as_mut()
                        .unwrap()
                        .info
                        .balance = U256::ONE
                }
                "storage" => {
                    db.cache
                        .accounts
                        .get_mut(&address)
                        .unwrap()
                        .account
                        .as_mut()
                        .unwrap()
                        .storage
                        .insert(U256::ONE, U256::from(9));
                }
                "code" => {
                    db.cache
                        .contracts
                        .insert(hash, Bytecode::new_raw(Bytes::from_static(&[0])));
                }
                "block_hash" => {
                    db.block_hashes.insert(1, B256::repeat_byte(3));
                }
                _ => {}
            }
        }
        assert_eq!(
            compare(&mut canonical, &mut cached, &reads),
            Ok(changed == "none"),
            "{changed}"
        );
    }
}

#[test]
fn canonical_cache_validation_honors_absence_and_cleared_storage() {
    let (parent, address, _, _) = fixture();
    for created in [false, true] {
        let mut canonical = State::builder().with_database(parent.clone()).build();
        let mut cached = State::builder().with_database(parent.clone()).build();
        for db in [&mut canonical, &mut cached] {
            db.basic(address).unwrap();
            let mut account = reth_revm::state::Account::default();
            account.mark_touch();
            if created {
                account.mark_created();
                account.info.nonce = 1;
            } else {
                account.mark_selfdestruct();
            }
            db.commit(reth_revm::state::EvmState::from_iter([(address, account)]));
        }
        // Slot 1 was nonzero in the parent and has never been loaded into State.
        // A cleared account must produce zero without consulting that old value.
        let account = read(&mut canonical, ReadKey::Account(address)).unwrap();
        let reads = vec![
            (ReadKey::Account(address), account),
            (
                ReadKey::Storage(address, U256::ONE),
                ReadValue::Storage(U256::ZERO),
            ),
        ];
        assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
        let stale = [(
            ReadKey::Storage(address, U256::ONE),
            ReadValue::Storage(U256::from(7)),
        )];
        assert_eq!(compare(&mut canonical, &mut cached, &stale), Ok(false));
    }
}

#[test]
fn canonical_cache_validation_preserves_known_zero_materialization() {
    let (parent, address, _, _) = fixture();
    let mut canonical = State::builder().with_database(parent.clone()).build();
    let mut cached = State::builder().with_database(parent).build();
    for db in [&mut canonical, &mut cached] {
        db.basic(address).unwrap();
        let mut account = reth_revm::state::Account::default();
        account.mark_touch();
        account.mark_created();
        account.info.nonce = 1;
        db.commit(reth_revm::state::EvmState::from_iter([(address, account)]));
    }
    let reads = [(
        ReadKey::Storage(address, U256::ONE),
        ReadValue::Storage(U256::ZERO),
    )];
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
    // Canonical validation materializes the known zero. A later public status
    // change must not expose the old nonzero parent value on only one path.
    for db in [&mut canonical, &mut cached] {
        db.cache.accounts.get_mut(&address).unwrap().status = reth_revm::db::AccountStatus::Loaded;
    }
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
}

#[test]
fn canonical_cache_validation_rechecks_bal_presence_each_time() {
    let (parent, address, _, _) = fixture();
    let mut canonical = State::builder().with_database(parent.clone()).build();
    let mut cached = State::builder().with_database(parent).build();
    let key = ReadKey::Account(address);
    let reads = [(key, read(&mut canonical, key).unwrap())];
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
    for db in [&mut canonical, &mut cached] {
        db.set_bal(Some(Arc::new(Bal::new())));
        db.bump_bal_index();
    }
    // Warm entries cannot hide BAL's missing-account error.
    assert!(compare(&mut canonical, &mut cached, &reads).is_err());
    for db in [&mut canonical, &mut cached] {
        db.set_bal(None);
    }
    assert_eq!(compare(&mut canonical, &mut cached, &reads), Ok(true));
}

#[derive(Debug, thiserror::Error)]
#[error("provider unavailable")]
struct Unavailable;
impl DBErrorMarker for Unavailable {}

#[derive(Debug)]
struct FailingProvider;
impl revm::Database for FailingProvider {
    type Error = Unavailable;
    fn basic(&mut self, _: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Err(Unavailable)
    }
    fn storage(&mut self, _: Address, _: U256) -> Result<U256, Self::Error> {
        Err(Unavailable)
    }
    fn code_by_hash(&mut self, _: B256) -> Result<Bytecode, Self::Error> {
        Err(Unavailable)
    }
    fn block_hash(&mut self, _: u64) -> Result<B256, Self::Error> {
        Err(Unavailable)
    }
}

#[test]
fn canonical_cache_validation_preserves_cold_provider_errors() {
    let address = Address::with_last_byte(212);
    for reads in [
        vec![(ReadKey::Account(address), ReadValue::Account(None))],
        vec![(
            ReadKey::Storage(address, U256::ONE),
            ReadValue::Storage(U256::ZERO),
        )],
        vec![(
            ReadKey::Code(B256::repeat_byte(4)),
            ReadValue::Code(Bytecode::default()),
        )],
        vec![(ReadKey::BlockHash(1), ReadValue::BlockHash(B256::ZERO))],
    ] {
        let mut normal = candidate(reads.clone());
        let mut fast = candidate(reads);
        let mut canonical = State::builder().with_database(FailingProvider).build();
        let mut cached = State::builder().with_database(FailingProvider).build();
        // Keep storage cold while ensuring its account itself is warm.
        for db in [&mut canonical, &mut cached] {
            db.insert_account(
                address,
                AccountInfo {
                    nonce: 1,
                    ..Default::default()
                },
            );
        }
        // The account case must still exercise a missing provider account.
        normal
            .reads
            .iter_mut()
            .chain(fast.reads.iter_mut())
            .for_each(|(key, _)| {
                if let ReadKey::Account(value) = key {
                    *value = Address::with_last_byte(213);
                }
            });
        let expected = normal.validate(&mut canonical).unwrap_err();
        let actual = fast.validate_state(&mut cached).unwrap_err();
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }
}
