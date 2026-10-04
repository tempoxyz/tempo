use super::*;
use crate::parallel::parent_reads::capture_with_parent_reads;
use revm::{
    Database as _,
    database::{CacheDB, EmptyDB},
};

type Witness = (usize, Address, U256, U256);

#[derive(Debug, PartialEq, Eq)]
struct Unavailable;
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("parent storage unavailable")
    }
}
impl std::error::Error for Unavailable {}
impl DBErrorMarker for Unavailable {}

#[derive(Debug, Default)]
struct CaptureDb {
    inner: CacheDB<EmptyDB>,
    calls: Vec<ReadKey>,
    active: Option<Vec<Witness>>,
    begins: usize,
    finishes: usize,
    discards: usize,
    storage_hooks: usize,
    fail_storage: bool,
    panic_storage: bool,
}

impl CaptureDb {
    fn hooks() -> CaptureParentReads<Self> {
        CaptureParentReads {
            begin: |db| {
                db.begins += 1;
                db.active = Some(Vec::new());
            },
            storage: |db, index, address, slot| {
                db.storage_hooks += 1;
                let value = db.storage(address, slot)?;
                db.active
                    .as_mut()
                    .unwrap()
                    .push((index, address, slot, value));
                Ok(value)
            },
            finish: |db| {
                db.finishes += 1;
                let reads = db.active.take().unwrap();
                let estimated_bytes = std::mem::size_of::<Vec<Witness>>()
                    + reads.capacity() * std::mem::size_of::<Witness>()
                    + 64;
                Some(ParentReadBatch {
                    opaque: Arc::new(reads),
                    estimated_bytes,
                })
            },
            discard: |db| {
                db.discards += 1;
                db.active = None;
            },
        }
    }
}

impl reth_revm::Database for CaptureDb {
    type Error = Unavailable;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.calls.push(ReadKey::Account(address));
        Ok(self.inner.basic(address).unwrap())
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.calls.push(ReadKey::Storage(address, slot));
        assert!(!self.panic_storage, "injected provider unwind");
        if self.fail_storage {
            return Err(Unavailable);
        }
        Ok(self.inner.storage(address, slot).unwrap())
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.calls.push(ReadKey::Code(hash));
        Ok(self.inner.code_by_hash(hash).unwrap())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.calls.push(ReadKey::BlockHash(number));
        Ok(self.inner.block_hash(number).unwrap())
    }
}

#[test]
fn only_provider_fallback_storage_records_absolute_read_indices() {
    let address = Address::with_last_byte(7);
    let prefix = PrewarmingState::default();
    prefix.0.write().unwrap().accounts.insert(
        address,
        PrefixAccount {
            storage: HashMap::from_iter([(U256::from(7), U256::from(99))]),
            ..Default::default()
        },
    );
    let mut recorder = ReadRecorder {
        db: CaptureDb::default(),
        reads: Vec::new(),
        predicted_nonce_ptr: Some(U256::from(23)),
        prefix: Some(prefix),
        parent_reads: Some(CaptureDb::hooks()),
    };
    (CaptureDb::hooks().begin)(&mut recorder.db);
    recorder.basic(Address::ZERO).unwrap();
    assert_eq!(
        recorder.storage(address, U256::from(7)).unwrap(),
        U256::from(99)
    );
    assert_eq!(
        recorder.read(nonce_ptr_key()).unwrap(),
        ReadValue::Storage(U256::from(23))
    );
    recorder.block_hash(5).unwrap();
    recorder.storage(address, U256::from(8)).unwrap();
    recorder.storage(address, U256::from(8)).unwrap();
    recorder.db.fail_storage = true;
    assert_eq!(recorder.storage(address, U256::from(9)), Err(Unavailable));
    assert_eq!(recorder.reads.len(), 6);
    recorder.db.fail_storage = false;
    recorder.storage(address, U256::from(9)).unwrap();
    assert_eq!(
        recorder.db.calls,
        vec![
            ReadKey::Account(Address::ZERO),
            ReadKey::BlockHash(5),
            ReadKey::Storage(address, U256::from(8)),
            ReadKey::Storage(address, U256::from(8)),
            ReadKey::Storage(address, U256::from(9)),
            ReadKey::Storage(address, U256::from(9)),
        ]
    );
    assert_eq!(recorder.db.storage_hooks, 4);
    assert_eq!(
        recorder.db.active.as_ref().unwrap(),
        &vec![
            (4, address, U256::from(8), U256::ZERO),
            (5, address, U256::from(8), U256::ZERO),
            (6, address, U256::from(9), U256::ZERO),
        ]
    );
}

#[test]
fn successful_capture_preserves_execution_and_seals_one_fresh_batch() {
    let (parent, env, tx, _, _) = crate::parallel::tests::native_increment_tests::fixture();
    let mut plain = CaptureDb {
        inner: parent.clone(),
        ..Default::default()
    };
    let expected = PrewarmingExecutor::new(&mut plain, env.clone())
        .execute(tx.clone(), Some(0))
        .unwrap();
    assert!(expected.parent_reads.is_none());
    let mut captured = CaptureDb {
        inner: parent,
        ..Default::default()
    };
    let mut first_batch = None;
    for iteration in 0..2 {
        captured.calls.clear();
        // begin must erase abandoned provenance before every execution.
        captured.active = Some(vec![(usize::MAX, Address::ZERO, U256::ZERO, U256::ZERO)]);
        let candidate = capture_with_parent_reads(
            &mut captured,
            env.clone(),
            PrewarmingState::default(),
            tx.clone(),
            Some(0),
            CaptureDb::hooks(),
        )
        .unwrap();
        assert_eq!(candidate.result, expected.result);
        assert_eq!(candidate.reads, expected.reads);
        assert_eq!(candidate.validator_fee, expected.validator_fee);
        assert_eq!(captured.calls, plain.calls);
        assert_eq!(captured.begins, iteration + 1);
        assert_eq!(captured.finishes, iteration + 1);
        assert_eq!(captured.discards, 0);
        assert!(captured.active.is_none());
        let batch = candidate.parent_reads.as_ref().unwrap();
        let reads = batch.opaque.downcast_ref::<Vec<Witness>>().unwrap();
        assert!(!reads.is_empty());
        for &(index, address, slot, value) in reads {
            assert_eq!(
                candidate.reads[index],
                (ReadKey::Storage(address, slot), ReadValue::Storage(value))
            );
            assert_ne!(
                ReadKey::Storage(address, slot),
                nonce_ptr_key(),
                "prediction preload is not a candidate read"
            );
        }
        let opaque = batch.opaque.clone();
        if let Some(first) = &first_batch {
            assert!(!Arc::ptr_eq(first, &opaque));
        } else {
            first_batch = Some(opaque.clone());
        }
        let result = candidate.into_candidate::<Unavailable>(&tx).unwrap();
        assert!(Arc::ptr_eq(&opaque, &result.parent_reads.unwrap().opaque));
    }
}

#[test]
fn failed_or_unwound_captures_discard_without_sealing() {
    for (unwind, offset) in [
        (false, Some(0)),
        (true, Some(0)),
        (false, None),
        (true, None),
    ] {
        let (parent, env, tx, _, _) = crate::parallel::tests::native_increment_tests::fixture();
        let mut plain = CaptureDb {
            inner: parent.clone(),
            fail_storage: !unwind,
            panic_storage: unwind,
            ..Default::default()
        };
        let expected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PrewarmingExecutor::new(&mut plain, env.clone()).execute(tx.clone(), offset)
        }));
        let mut db = CaptureDb {
            inner: parent,
            fail_storage: !unwind,
            panic_storage: unwind,
            ..Default::default()
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capture_with_parent_reads(
                &mut db,
                env.clone(),
                PrewarmingState::default(),
                tx.clone(),
                offset,
                CaptureDb::hooks(),
            )
        }));
        if unwind {
            assert!(expected.is_err());
            assert!(outcome.is_err());
        } else {
            // Preload errors remain Database errors; failures from a native
            // precompile retain the ordinary executor's error conversion.
            assert_eq!(
                outcome.unwrap().unwrap_err(),
                expected.unwrap().unwrap_err()
            );
        }
        assert_eq!(db.calls, plain.calls);
        assert_eq!((db.begins, db.finishes, db.discards), (1, 0, 1));
        assert!(db.active.is_none());
        if offset.is_some() {
            assert_eq!(db.calls, vec![nonce_ptr_key()]);
            assert_eq!(
                db.storage_hooks, 0,
                "prediction preload delegates ordinary Database::storage"
            );
        } else {
            assert_eq!(db.storage_hooks, 1);
            assert!(matches!(db.calls.last(), Some(ReadKey::Storage(..))));
        }

        db.fail_storage = false;
        db.panic_storage = false;
        let mut invalid = tx;
        invalid.inner.gas_limit = 0;
        assert!(
            capture_with_parent_reads(
                &mut db,
                env,
                PrewarmingState::default(),
                invalid,
                None,
                CaptureDb::hooks(),
            )
            .is_err()
        );
        assert_eq!((db.begins, db.finishes, db.discards), (2, 0, 2));
        assert!(db.active.is_none());
    }
}
