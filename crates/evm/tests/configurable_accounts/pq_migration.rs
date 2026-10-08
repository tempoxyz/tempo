//! Verify native ML-DSA owner receipts through the production migration handler.

use super::{
    migration::{fixture, root_signed, upgrade},
    *,
};
use alloy_evm::FromRecoveredTx;
use alloy_primitives::Bytes;
use ml_dsa::{Keypair as _, MlDsa65, Seed, SigningKey};
use revm::context::result::EVMError;
use std::{fs, str::FromStr};
use tempo_contracts::precompiles::{ACCOUNT_KEYCHAIN_ADDRESS, IAccountKeychain, authorizeKeyCall};
use tempo_precompiles::key_publisher::{IKeyPublisher, KeyPublisher};
use tempo_primitives::transaction::{
    KeychainSignature, SignatureType, ZkSignature, tt_signature::Mldsa65Signature,
};
use tempo_revm::{TempoInvalidTransaction, TempoTxEnv, native_multisig::NativeMultisigError};

/// Runs against the real receipt generated from oidc-demo/scripts/pq-fixture.ts.
#[test]
#[ignore = "requires PQ_TEST_WITNESS, PQ_TEST_RECEIPT and PQ_TEST_IMAGE from native proving"]
fn migration_runtime_real_pq_owner_retires_secp_root_and_rejects_bad_proof() {
    let witness: tempo_pq_oidc::Witness =
        serde_json::from_slice(&fs::read(std::env::var("PQ_TEST_WITNESS").unwrap()).unwrap())
            .unwrap();
    let statement = tempo_pq_oidc::evaluate(&witness).unwrap();
    let proof = Bytes::from(fs::read(std::env::var("PQ_TEST_RECEIPT").unwrap()).unwrap());
    let image = B256::from_str(&std::env::var("PQ_TEST_IMAGE").unwrap()).unwrap();
    tempo_zk::set_genesis_keys([(0x80, image.as_slice())]).unwrap();
    let device = SigningKey::<MlDsa65>::from_seed(&Seed::from([8; 32]));
    let public_key = device.verifying_key().encode().to_vec();
    assert_eq!(
        tempo_pq_oidc::access_key_id(&public_key).unwrap(),
        statement.access_key_id
    );

    let mut f = fixture();
    f.evm.ctx_mut().block.timestamp = U256::from(1500);
    f.evm.ctx_mut().block.gas_limit = 500_000_000;
    f.evm.ctx_mut().cfg.tx_gas_limit_cap = Some(200_000_000);
    let publisher_id = StorageCtx::enter_ctx(f.evm.ctx_mut(), StorageActions::disabled(), || {
        let mut publisher = KeyPublisher::new();
        publisher.initialize()?;
        publisher.create_publisher(
            f.owner.address(),
            IKeyPublisher::createPublisherCall {
                salt: B256::ZERO,
                owner: f.owner.address(),
                initialKeys: vec![IKeyPublisher::IssuerKeys {
                    issuer: B256::from(statement.issuer),
                    keyHashes: vec![B256::from(statement.key_hash)],
                }],
            },
        )
    })
    .unwrap();
    let state = f.evm.ctx_mut().journaled_state.finalize();
    f.evm.db_mut().commit(state);

    let mut credential = ZkSignature::new(
        0x80,
        publisher_id,
        B256::from(statement.issuer),
        B256::from(statement.key_hash),
        B256::from(statement.address_seed),
        statement.issued_at,
        statement.valid_until,
        proof,
        PrimitiveSignature::default(),
    );
    let owner = credential.address().unwrap();
    f.config.owners = vec![MultisigOwner { owner, weight: 1 }];
    let migrated = root_signed(&f, 3, 1_000_000, vec![upgrade(&f)]);
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&migrated, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.state[&f.account].info.balance, U256::from(42));
    f.evm.db_mut().commit(output.state);
    assert_eq!(f.commitment(), f.config.commitment().unwrap());

    let retired = root_signed(&f, 4, 1_000_000, vec![f.getter()]);
    assert_eq!(
        f.evm
            .transact(TempoTxEnv::from_recovered_tx(&retired, f.account))
            .unwrap_err(),
        EVMError::Transaction(TempoInvalidTransaction::NativeMultisig(
            NativeMultisigError::RootKeyRetired { account: f.account }
        ))
    );

    let tx = TempoTransaction {
        chain_id: 1,
        nonce: 4,
        gas_limit: 200_000_000,
        calls: vec![Call {
            to: ACCOUNT_KEYCHAIN_ADDRESS.into(),
            value: U256::ZERO,
            input: authorizeKeyCall {
                keyId: Address::from(statement.access_key_id),
                signatureType: IAccountKeychain::SignatureType::Mldsa65,
                config: IAccountKeychain::KeyRestrictions {
                    expiry: statement.valid_until,
                    enforceLimits: false,
                    limits: vec![],
                    allowAnyCalls: true,
                    allowedCalls: vec![],
                },
            }
            .abi_encode()
            .into(),
        }],
        ..Default::default()
    };
    let digest = multisig_digest(tx.signature_hash(), f.account, f.config.version);
    let signature = device
        .expanded_key()
        .sign_deterministic(credential.signing_hash(&digest).as_slice(), b"")
        .unwrap();
    credential.access_key_signature = PrimitiveSignature::Mldsa65(Mldsa65Signature {
        public_key: public_key.into(),
        signature: signature.encode().to_vec().into(),
    });
    assert_eq!(
        credential.access_key_signature.signature_type(),
        SignatureType::Mldsa65
    );
    let account = f.account;
    let config = f.config.clone();
    let wrap = |credential: ZkSignature| {
        TempoSignature::Multisig(
            MultisigSignature::try_new_with_owners(
                account,
                config.clone(),
                vec![credential.into()],
            )
            .unwrap(),
        )
    };
    let signed = tx.clone().into_signed(wrap(credential.clone()));
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.state[&f.account].info.nonce, 5);
    assert_eq!(output.state[&f.account].info.balance, U256::from(42));
    let granted_state = output.state;
    // Leave the successful state uncommitted so the negative proof uses the same nonce/digest.
    credential.proof = Bytes::from_static(b"{}");
    let signature = device
        .expanded_key()
        .sign_deterministic(credential.signing_hash(&digest).as_slice(), b"")
        .unwrap();
    if let PrimitiveSignature::Mldsa65(key) = &mut credential.access_key_signature {
        key.signature = signature.encode().to_vec().into();
    }
    let bad = tx.into_signed(wrap(credential));
    assert_eq!(
        f.evm
            .transact(TempoTxEnv::from_recovered_tx(&bad, f.account))
            .unwrap_err(),
        EVMError::Transaction(TempoInvalidTransaction::ZkSignature(
            tempo_revm::zk::ZkSignatureError::Invalid
        ))
    );

    f.evm.db_mut().commit(granted_state);
    let tx = TempoTransaction {
        chain_id: 1,
        nonce: 5,
        gas_limit: 1_000_000,
        calls: vec![f.getter()],
        ..Default::default()
    };
    let digest = KeychainSignature::signing_hash(tx.signature_hash(), f.account);
    let signature = device
        .expanded_key()
        .sign_deterministic(digest.as_slice(), b"")
        .unwrap();
    let key = PrimitiveSignature::Mldsa65(Mldsa65Signature {
        public_key: device.verifying_key().encode().to_vec().into(),
        signature: signature.encode().to_vec().into(),
    });
    let signed = tx.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        f.account, key,
    )));
    let output = f
        .evm
        .transact(TempoTxEnv::from_recovered_tx(&signed, f.account))
        .unwrap();
    assert!(output.result.is_success(), "{:?}", output.result);
    assert_eq!(output.state[&f.account].info.nonce, 6);
    assert_eq!(output.state[&f.account].info.balance, U256::from(42));
}
