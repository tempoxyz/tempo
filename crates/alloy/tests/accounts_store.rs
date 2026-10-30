//! Tempo Accounts store persistence of configurable account key authorizations.

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy_network::{NetworkWallet, TransactionBuilder};
use alloy_primitives::{Address, B256};
use alloy_provider::{ProviderBuilder, fillers::TxFiller, mock::Asserter};
use alloy_signer_local::PrivateKeySigner;
use tempo_alloy::{
    TempoNetwork,
    accounts::{TempoAccessKey, TempoAccountsError, TempoAccountsStore, TempoAccountsWallet},
    fillers::TempoGasFiller,
    rpc::TempoTransactionRequest,
};
use tempo_primitives::{
    SignatureType, TempoTransaction,
    transaction::{
        CallScope, ConfigurableAccountConfig, ConfigurableAccountOwner,
        ConfigurableAccountSignature, KeyAuthorization, PrimitiveSignature, SignedKeyAuthorization,
        TempoTypedTransaction,
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

#[test_case::test_case(false; "parent_signed")]
#[test_case::test_case(true; "scoped_parent_signed")]
fn configurable_account_authorization_round_trips(scoped: bool) {
    let account = Address::repeat_byte(2);
    let signer = PrivateKeySigner::random();
    let mut authorization = configurable_authorization(account, &signer);
    if scoped {
        authorization.authorization.allowed_calls = Some(vec![CallScope {
            target: Address::repeat_byte(4),
            selector_rules: Vec::new(),
        }]);
    }
    let directory = unique_test_directory();
    let path = directory.join("store.json");

    TempoAccountsStore::at(&path)
        .upsert_secp256k1_access_key(account, &signer, &authorization)
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let access_keys = TempoAccountsStore::open(&path)
        .unwrap()
        .access_keys()
        .unwrap();
    fs::remove_dir_all(directory).unwrap();

    // Stored like every other authorization signature: an object tagged by `type`.
    let signature = authorization.signature.as_configurable_account().unwrap();
    assert_eq!(
        stored["tempo-cli.store"]["state"]["accessKeys"][0]["keyAuthorization"]["signature"],
        serde_json::json!({ "type": "configurableAccount", "signature": signature }),
    );

    let [access_key] = access_keys.as_slice() else {
        panic!("expected one stored access key, got {}", access_keys.len())
    };
    let decoded = access_key.key_authorization().unwrap();
    assert_eq!(decoded, &authorization);
}

#[tokio::test]
async fn configurable_account_authorization_for_another_account_is_rejected() {
    let account = Address::repeat_byte(2);
    let other = Address::repeat_byte(3);
    let signer = PrivateKeySigner::random();
    let authorization = configurable_authorization(other, &signer);
    let directory = unique_test_directory();
    let path = directory.join("store.json");
    let store = TempoAccountsStore::at(&path);

    // Naming the account does not let another configurable account sign its grant, and a
    // configurable account's grant cannot name another account.
    let mut named = authorization.clone();
    named.authorization.account = Some(account);
    for (expected, authorization) in [
        (account, &authorization),
        (account, &named),
        (other, &named),
    ] {
        assert!(matches!(
            store.upsert_secp256k1_access_key(expected, &signer, authorization),
            Err(TempoAccountsError::InvalidAuthorization(_))
        ));
    }
    assert!(
        TempoAccessKey::from_secp256k1(account, 4217, signer.clone())
            .with_key_authorization(named)
            .sign_transaction_from(
                account,
                TempoTypedTransaction::AA(TempoTransaction {
                    chain_id: 4217,
                    ..Default::default()
                }),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("account does not match the selected key")
    );
    // Gas filling rejects the grant before estimating, as the chain would.
    assert!(
        TempoGasFiller::default()
            .prepare(
                &ProviderBuilder::new_with_network::<TempoNetwork>()
                    .connect_mocked_client(Asserter::new()),
                &TempoTransactionRequest {
                    key_authorization: Some(authorization.clone()),
                    ..TempoTransactionRequest::default()
                        .with_from(account)
                        .with_chain_id(4217)
                },
            )
            .await
            .unwrap_err()
            .to_string()
            .contains(&format!(
                "Tempo key authorization account is {other}, expected {account}"
            ))
    );

    store
        .upsert_secp256k1_access_key(other, &signer, &authorization)
        .unwrap();
    let stored: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    // Neither the stored owner nor the grant's explicit account may differ from the signing
    // configurable account, even when they agree with each other.
    for fields in [
        &["access"][..],
        &["keyAuthorization/account"],
        &["access", "keyAuthorization/account"],
    ] {
        let mut value = stored.clone();
        for field in fields {
            *field.split('/').fold(
                &mut value["tempo-cli.store"]["state"]["accessKeys"][0],
                |value, field| &mut value[field],
            ) = serde_json::json!(account);
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let Err(TempoAccountsError::InvalidAccessKey { address, .. }) =
            TempoAccountsStore::open(&path).unwrap().access_keys()
        else {
            panic!("expected the stored authorization with a different {fields:?} to be rejected")
        };
        assert_eq!(address, signer.address());
        assert!(matches!(
            TempoAccountsWallet::from_store(&path).unwrap().access_key(
                account,
                4217,
                signer.address()
            ),
            Err(TempoAccountsError::MissingAccessKey { .. })
        ));
    }

    // A stored configurable signature that does not decode drops only its own key.
    let mut value = stored;
    value["tempo-cli.store"]["state"]["accessKeys"][0]["keyAuthorization"]["signature"]["signature"] =
        serde_json::json!("0xc0");
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let usable = PrivateKeySigner::random();
    store
        .upsert_secp256k1_access_key(other, &usable, &configurable_authorization(other, &usable))
        .unwrap();
    let wallet = TempoAccountsWallet::from_store(&path).unwrap();
    assert!(matches!(
        wallet.access_key(other, 4217, signer.address()),
        Err(TempoAccountsError::MissingAccessKey { .. })
    ));
    wallet.access_key(other, 4217, usable.address()).unwrap();
    fs::remove_dir_all(directory).unwrap();
}
