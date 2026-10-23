use std::path::Path;

use alloy_primitives::{Address, B256, U256};
use reth_codecs::{Compress as _, Decompress as _};
use reth_db::{
    Database as _, DatabaseEnv, DatabaseEnvKind, DatabaseError, RawKey, RawTable, RawValue,
    mdbx::{DatabaseArguments, init_db_for},
    transaction::{DbTx as _, DbTxMut as _},
};

use crate::accounting::{AccountKey, BalanceChange, Effect, LiabilityKind, State, TokenState};

use super::{
    BlockRef, CandidateTransition, Checkpoint, Finding, Identity, Metadata, PersistenceError,
    SCHEMA_VERSION, Status, Store,
    schema::{
        AccountValue, Accounts, Meta, MetaKey, MetaValue, Tables, TokenValue, TokenValueV1, Tokens,
    },
};

fn block(number: u64, byte: u8) -> BlockRef {
    BlockRef {
        number,
        hash: B256::repeat_byte(byte),
    }
}

fn identity() -> Identity {
    Identity {
        l1_chain_id: 1,
        zone_chain_id: 2,
        zone_id: 3,
        portal: Address::repeat_byte(4),
        creation: block(5, 5),
    }
}

#[test]
fn checkpoint_accounting_anchor_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let checkpoint = Checkpoint {
        identity: identity(),
        zone: block(0, 10),
        tempo: block(100, 20),
        state: Default::default(),
    };
    let (store, snapshot) = Store::open_or_create(&path, &checkpoint).unwrap();
    let candidate = CandidateTransition::derive(
        snapshot,
        block(1, 11),
        checkpoint.zone,
        checkpoint.tempo,
        &[],
    )
    .unwrap();
    let one = store.apply(candidate).unwrap();
    drop(store);
    let (store, reopened) = Store::open(&path, identity()).unwrap();
    assert_eq!(reopened, one);
    assert_eq!(reopened.metadata.imported_tempo, checkpoint.tempo);
    assert_eq!(reopened.metadata.status, Status::Verifying);

    let candidate =
        CandidateTransition::derive(reopened, block(2, 12), block(1, 11), block(110, 30), &[])
            .unwrap();
    let full = store.apply(candidate).unwrap();
    assert_eq!(full.metadata.imported_tempo, block(110, 30));
    assert_eq!(full.metadata.verified_zone, block(2, 12));
}

#[test]
fn rows_survive_restart_and_clear_on_reset() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let genesis = block(0, 10);
    let tempo = block(20, 20);
    let token = Address::repeat_byte(30);
    let mut state = State::default();
    state.apply(&[Effect::EnableToken(token)]).unwrap();
    let checkpoint = Checkpoint {
        identity: identity(),
        zone: genesis,
        tempo,
        state,
    };
    let initial = Store::create_atomic(&path, &checkpoint).unwrap();
    assert_eq!(Store::inspect_identity(&path).unwrap(), identity());
    let (store, reopened) = Store::open(&path, identity()).unwrap();
    assert_eq!(reopened, initial);
    assert_eq!(reopened.state.token(token), Some(TokenState::default()));

    let account = AccountKey::new(token, Address::repeat_byte(31));
    let candidate = CandidateTransition::derive(
        reopened,
        block(1, 11),
        genesis,
        block(21, 21),
        &[
            Effect::Account {
                key: account,
                change: BalanceChange::Credit(U256::from(100)),
            },
            Effect::Liability {
                token,
                kind: LiabilityKind::TempoRefund,
                change: BalanceChange::Credit(U256::from(5)),
            },
            Effect::Liability {
                token,
                kind: LiabilityKind::ZoneRefund,
                change: BalanceChange::Credit(U256::from(7)),
            },
        ],
    )
    .unwrap();
    let one = store.apply(candidate).unwrap();
    drop(store);

    let (store, loaded) = Store::open(&path, identity()).unwrap();
    assert_eq!(loaded, one);
    assert_eq!(loaded.state.account(account), Some(U256::from(100)));
    let token_state = loaded.state.token(token).unwrap();
    assert_eq!(token_state.pending_tempo_refunds, U256::from(5));
    assert_eq!(token_state.pending_zone_refunds, U256::from(7));

    let reset = store.reset(&checkpoint).unwrap();
    assert_eq!(reset.metadata.verified_zone, genesis);
    assert_eq!(reset.state.account(account), None);
    assert_eq!(reset.state.token(token), Some(TokenState::default()));
}

#[test]
fn inspect_identity_validates_schema() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let checkpoint = Checkpoint {
        identity: identity(),
        zone: block(0, 10),
        tempo: block(20, 20),
        state: Default::default(),
    };
    Store::create_atomic(&path, &checkpoint).unwrap();
    let (store, _) = Store::open(&path, identity()).unwrap();
    let tx = store.db.tx_mut().unwrap();
    tx.put::<Meta>(MetaKey::Version, MetaValue::Version(SCHEMA_VERSION + 1))
        .unwrap();
    tx.commit().unwrap();
    drop(store);

    assert!(matches!(
        Store::inspect_identity(&path),
        Err(PersistenceError::Schema { .. })
    ));
}

/// Hand-write a v1 database: v1 version row, v2-compatible metadata, and raw v1 token rows.
fn write_v1_database(
    path: &Path,
    metadata: &Metadata,
    accounts: &[(AccountKey, U256)],
    tokens: &[(Address, Vec<u8>)],
) {
    let db = init_db_for::<_, Tables>(path, DatabaseArguments::default()).unwrap();
    let tx = db.tx_mut().unwrap();
    tx.put::<Meta>(MetaKey::Version, MetaValue::Version(1))
        .unwrap();
    tx.put::<Meta>(
        MetaKey::Metadata,
        MetaValue::Metadata(Box::new(metadata.clone())),
    )
    .unwrap();
    for (key, value) in accounts {
        tx.put::<Accounts>(*key, AccountValue(*value)).unwrap();
    }
    for (token, value) in tokens {
        tx.put::<RawTable<Tokens>>(RawKey::new(*token), RawValue::from_vec(value.clone()))
            .unwrap();
    }
    tx.commit().unwrap();
}

fn read_version(path: &Path) -> Option<MetaValue> {
    let db = DatabaseEnv::open(path, DatabaseEnvKind::RO, DatabaseArguments::default()).unwrap();
    db.tx().unwrap().get::<Meta>(MetaKey::Version).unwrap()
}

#[test]
fn v1_database_migrates_in_place() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let funded = Address::repeat_byte(6);
    let empty = Address::repeat_byte(7);
    let account = AccountKey::new(funded, Address::repeat_byte(8));
    let v1 = TokenValueV1 {
        account_total: U256::from(100),
        pending_deposits: U256::from(1),
        pending_withdrawals: U256::from(2),
        pending_tempo_refunds: U256::from(3),
        pending_zone_refunds: U256::from(4),
    };
    let empty_v1 = TokenValueV1 {
        account_total: U256::ZERO,
        pending_deposits: U256::ZERO,
        pending_withdrawals: U256::ZERO,
        pending_tempo_refunds: U256::ZERO,
        pending_zone_refunds: U256::ZERO,
    };
    // A diverged v1 checker must keep its finding across the upgrade.
    let finding = Finding {
        zone: block(2, 12),
        summary: "balance mismatch".into(),
    };
    let metadata = Metadata {
        identity: identity(),
        verified_zone: block(1, 11),
        imported_tempo: block(21, 21),
        observed_zone: block(3, 13),
        status: Status::Diverged { finding },
    };
    assert!(TokenValue::decompress(&v1.compress()).is_err());
    write_v1_database(
        &path,
        &metadata,
        &[(account, U256::from(100))],
        &[(funded, v1.compress()), (empty, empty_v1.compress())],
    );

    assert_eq!(Store::inspect_identity(&path).unwrap(), identity());
    assert_eq!(read_version(&path), Some(MetaValue::Version(1)));

    let (store, migrated) = Store::open(&path, identity()).unwrap();
    drop(store);
    assert_eq!(migrated.metadata, metadata);
    assert_eq!(migrated.state.account(account), Some(U256::from(100)));
    assert_eq!(
        migrated.state.token(funded),
        Some(TokenState {
            account_total: U256::from(100),
            pending_deposits: U256::from(1),
            pending_withdrawals: U256::from(2),
            pending_tempo_refunds: U256::from(3),
            pending_forced_exit_fees: U256::ZERO,
            pending_zone_refunds: U256::from(4),
        })
    );
    assert_eq!(migrated.state.token(empty), Some(TokenState::default()));
    assert_eq!(
        read_version(&path),
        Some(MetaValue::Version(SCHEMA_VERSION))
    );
    assert_eq!(Store::inspect_identity(&path).unwrap(), identity());

    let (_, reopened) = Store::open(&path, identity()).unwrap();
    assert_eq!(reopened, migrated);
}

#[test]
fn v1_migration_failure_leaves_database_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let metadata = Metadata {
        identity: identity(),
        verified_zone: block(0, 10),
        imported_tempo: block(20, 20),
        observed_zone: block(0, 10),
        status: Status::Verifying,
    };
    // A v2-shaped row has trailing bytes under the v1 decoder.
    let malformed = TokenValue(TokenState::default()).compress();
    write_v1_database(
        &path,
        &metadata,
        &[],
        &[(Address::repeat_byte(6), malformed)],
    );

    assert!(matches!(
        Store::open(&path, identity()),
        Err(PersistenceError::Database(DatabaseError::Decode))
    ));
    assert_eq!(read_version(&path), Some(MetaValue::Version(1)));
}

#[test]
fn finding_survives_restart_and_clears_on_reset() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let genesis = block(0, 10);
    let checkpoint = Checkpoint {
        identity: identity(),
        zone: genesis,
        tempo: block(20, 20),
        state: Default::default(),
    };
    Store::create_atomic(&path, &checkpoint).unwrap();
    let (store, snapshot) = Store::open(&path, identity()).unwrap();
    let failed = block(1, 11);
    let finding = Finding {
        zone: failed,
        summary: "balance mismatch".into(),
    };
    let diverged = store.record_finding(&snapshot, finding.clone()).unwrap();

    assert_eq!(diverged.metadata.verified_zone, genesis);
    assert_eq!(
        diverged.metadata.status,
        Status::Diverged {
            finding: finding.clone(),
        }
    );

    drop(store);
    let (store, reopened) = Store::open(&path, identity()).unwrap();
    assert_eq!(reopened, diverged);

    let observed = block(2, 12);
    let extended = store.observe(&reopened, observed).unwrap();
    assert_eq!(extended.metadata.verified_zone, genesis);
    assert_eq!(extended.metadata.observed_zone, observed);
    assert_eq!(extended.metadata.status, Status::Diverged { finding });

    let recovered = store.reset(&checkpoint).unwrap();
    assert_eq!(recovered.metadata.observed_zone, genesis);
    assert_eq!(recovered.metadata.status, Status::Verifying);
}

#[test]
fn apply_rejects_stale_candidate_parent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("checker");
    let genesis = block(0, 10);
    Store::create_atomic(
        &path,
        &Checkpoint {
            identity: identity(),
            zone: genesis,
            tempo: block(20, 20),
            state: Default::default(),
        },
    )
    .unwrap();
    let (store, snapshot) = Store::open(&path, identity()).unwrap();
    let stale =
        CandidateTransition::derive(snapshot.clone(), block(1, 11), genesis, block(21, 21), &[])
            .unwrap();
    let current =
        CandidateTransition::derive(snapshot, block(1, 12), genesis, block(21, 21), &[]).unwrap();
    store.apply(current).unwrap();

    assert!(matches!(
        store.apply(stale),
        Err(PersistenceError::StaleSnapshot)
    ));
}
