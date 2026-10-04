#![cfg(feature = "client")]

use alloy_primitives::B256;
use tempo_light::checkpoint::{Error, Store};
mod common;
use common::checkpoint;

#[test]
fn exclusive_writer_and_verified_restart() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = checkpoint();
    let store = Store::open(directory.path()).unwrap();
    assert!(matches!(Store::open(directory.path()), Err(Error::Locked)));
    assert!(store.load(&checkpoint.network).unwrap().is_none());
    store.save(&checkpoint).unwrap();
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    let restored = store.load(&checkpoint.network).unwrap().unwrap();
    assert_eq!(restored.head, checkpoint.head);
    assert_eq!(
        restored.restore().unwrap().snapshot().unwrap().evidence(),
        &checkpoint.head
    );
    let mut other = checkpoint.network.clone();
    other.chain_id += 1;
    assert!(matches!(store.load(&other), Err(Error::NetworkMismatch)));
    other.chain_id = checkpoint.network.chain_id;
    other.unsupported_layout_from = Some(100);
    assert!(matches!(store.load(&other), Err(Error::NetworkMismatch)));
}

#[test]
fn interrupted_temporary_publication_keeps_committed_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = checkpoint();
    let store = Store::open(directory.path()).unwrap();
    store.save(&checkpoint).unwrap();
    std::fs::write(
        directory.path().join("checkpoint.tmp"),
        b"interrupted partial write",
    )
    .unwrap();
    drop(store);
    let store = Store::open(directory.path()).unwrap();
    assert_eq!(
        store.load(&checkpoint.network).unwrap().unwrap().head,
        checkpoint.head
    );
    store.save(&checkpoint).unwrap();
    assert!(!directory.path().join("checkpoint.tmp").exists());
}

#[test]
fn corrupt_unknown_format_and_unauthenticated_head_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = checkpoint();
    let store = Store::open(directory.path()).unwrap();
    store.save(&checkpoint).unwrap();
    let path = directory.path().join("checkpoint.json");
    std::fs::write(&path, b"{\"partial").unwrap();
    assert!(matches!(
        store.load(&checkpoint.network),
        Err(Error::Invalid)
    ));
    let mut changed = checkpoint.clone();
    changed.version = 2;
    store.save(&changed).unwrap(); // Even a checksummed future format is not accepted.
    assert!(matches!(
        store.load(&checkpoint.network),
        Err(Error::Invalid)
    ));
    changed = checkpoint.clone();
    changed.head.header.inner.state_root = B256::ZERO;
    store.save(&changed).unwrap();
    assert!(matches!(
        store.load(&checkpoint.network),
        Err(Error::Invalid)
    ));
    changed = checkpoint.clone();
    changed.identity.from_epoch += 1;
    assert!(matches!(changed.restore(), Err(Error::Invalid)));
    store.save(&checkpoint).unwrap();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    envelope["checksum"] = serde_json::json!(B256::ZERO);
    std::fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
    assert!(matches!(
        store.load(&checkpoint.network),
        Err(Error::Invalid)
    ));
}

#[test]
fn publication_failure_is_explicit_and_keeps_prior_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let checkpoint = checkpoint();
    let store = Store::open(directory.path()).unwrap();
    store.save(&checkpoint).unwrap();
    std::fs::create_dir(directory.path().join("checkpoint.tmp")).unwrap();
    assert!(matches!(store.save(&checkpoint), Err(Error::Io)));
    assert_eq!(
        store.load(&checkpoint.network).unwrap().unwrap().head,
        checkpoint.head
    );
}
