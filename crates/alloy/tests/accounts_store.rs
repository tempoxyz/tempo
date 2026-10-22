//! Tempo Accounts store persistence of configurable account key authorizations.

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256};
use alloy_signer_local::PrivateKeySigner;
use tempo_alloy::accounts::{TempoAccountsError, TempoAccountsStore};
use tempo_primitives::{
    SignatureType,
    transaction::{
        CallScope, ConfigurableAccountConfig, ConfigurableAccountOwner,
        ConfigurableAccountSignature, KeyAuthorization, PrimitiveSignature, SignedKeyAuthorization,
    },
};

fn unique_test_directory() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tempo-alloy-accounts-store-{}-{unique}",
        std::process::id()
    ))
}

fn configurable_authorization(
    account: Address,
    signer: &PrivateKeySigner,
) -> SignedKeyAuthorization {
    let config = ConfigurableAccountConfig {
        salt: B256::ZERO,
        version: 1,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: Address::repeat_byte(1),
            weight: 1,
        }],
    };
    KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address()).into_signed(
        ConfigurableAccountSignature::try_new(account, config, vec![PrimitiveSignature::default()])
            .unwrap(),
    )
}

#[test_case::test_case(false, false; "parent_signed")]
#[test_case::test_case(true, false; "scoped_parent_signed")]
#[test_case::test_case(false, true; "admin_signed")]
fn configurable_account_authorization_round_trips(scoped: bool, admin: bool) {
    let account = Address::repeat_byte(2);
    let signer = PrivateKeySigner::random();
    let signing_account = if admin {
        Address::repeat_byte(3)
    } else {
        account
    };
    let mut authorization = configurable_authorization(signing_account, &signer);
    if admin {
        authorization.authorization.account = Some(account);
    }
    if scoped {
        authorization.authorization.allowed_calls = Some(vec![CallScope {
            target: Address::repeat_byte(4),
            selector_rules: Vec::new(),
        }]);
    }
    let directory = unique_test_directory();
    let path = directory.join("store.json");

    TempoAccountsStore::at(path.clone())
        .upsert_secp256k1_access_key(account, &signer, &authorization)
        .unwrap();
    let access_keys = TempoAccountsStore::open(&path)
        .unwrap()
        .access_keys()
        .unwrap();
    fs::remove_dir_all(directory).unwrap();

    let [access_key] = access_keys.as_slice() else {
        panic!("expected one stored access key, got {}", access_keys.len())
    };
    let decoded = access_key.key_authorization().unwrap();
    assert_eq!(decoded, &authorization);
    assert_eq!(decoded.signature_hash(), authorization.signature_hash());
}

#[test]
fn configurable_account_authorization_for_another_account_is_rejected() {
    let account = Address::repeat_byte(2);
    let other = Address::repeat_byte(3);
    let signer = PrivateKeySigner::random();
    let authorization = configurable_authorization(other, &signer);
    let directory = unique_test_directory();
    let path = directory.join("store.json");
    let store = TempoAccountsStore::at(path.clone());

    assert!(matches!(
        store.upsert_secp256k1_access_key(account, &signer, &authorization),
        Err(TempoAccountsError::InvalidAuthorization(_))
    ));

    store
        .upsert_secp256k1_access_key(other, &signer, &authorization)
        .unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["tempo-cli.store"]["state"]["accessKeys"][0]["access"] = serde_json::json!(account);
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let result = TempoAccountsStore::open(&path).unwrap().access_keys();
    fs::remove_dir_all(directory).unwrap();

    let Err(TempoAccountsError::InvalidAccessKey { address, .. }) = result else {
        panic!("expected the stored authorization to be rejected")
    };
    assert_eq!(address, signer.address());
}
