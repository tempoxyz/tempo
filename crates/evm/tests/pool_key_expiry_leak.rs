use alloy_consensus::{Signed, TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use evm2::evm::{DbStats, DynDatabase, InMemoryDB};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{
    TempoBlockEnv, TempoEvmExt, TempoEvmTypes, TempoPoolValidationEvm, TempoTxEnv, build_tempo_evm,
};
use tempo_precompiles::{PATH_USD_ADDRESS, TempoPrecompiles};
use tempo_primitives::{
    AASigned, SignatureType, TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{Call, KeyAuthorization, PrimitiveSignature},
};

#[test]
fn rejected_pool_transaction_does_not_leak_key_expiry() {
    const BLOCK_TIMESTAMP: u64 = 10;

    let root = PrivateKeySigner::from_bytes(&B256::with_last_byte(1)).unwrap();
    let key = PrivateKeySigner::from_bytes(&B256::with_last_byte(2)).unwrap();
    let authorization = KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, key.address())
        .with_expiry(BLOCK_TIMESTAMP);
    let authorization_signature = root
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();

    let ext = TempoEvmExt::default();
    let precompiles = TempoPrecompiles::<TempoEvmTypes>::new(
        TempoHardfork::T10,
        ext.actions.clone(),
        ext.non_creditable_slots.clone(),
    );
    let mut evm = build_tempo_evm(
        TempoHardfork::T10,
        1,
        TempoBlockEnv {
            timestamp: U256::from(BLOCK_TIMESTAMP),
            ..Default::default()
        },
        DbStats::new(InMemoryDB::default()),
        precompiles,
        ext,
    );
    evm.configure_for_pool();

    let transaction = TempoTransaction {
        chain_id: 1,
        fee_token: Some(PATH_USD_ADDRESS),
        gas_limit: 1_000_000,
        calls: vec![Call {
            to: TxKind::Call(Address::repeat_byte(0x44)),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        key_authorization: Some(
            authorization.into_signed(PrimitiveSignature::Secp256k1(authorization_signature)),
        ),
        ..Default::default()
    };
    let signature = root.sign_hash_sync(&transaction.signature_hash()).unwrap();
    let rejected = TempoTxEnvelope::AA(AASigned::new_unhashed(
        transaction,
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(signature)),
    ));
    let rejected: TempoTxEnv = Recovered::new_unchecked(rejected, root.address()).into();
    assert!(
        evm.validate_pool_transaction(rejected).0.is_err(),
        "the first transaction must be rejected"
    );

    assert_eq!(evm.ext().resolved_fee_token, None);
    assert_eq!(evm.ext().key_expiry, None);

    let valid = TxLegacy {
        chain_id: Some(1),
        gas_limit: 1_000_000,
        to: TxKind::Call(Address::repeat_byte(0x55)),
        ..Default::default()
    };
    let valid = TempoTxEnvelope::Legacy(Signed::new_unhashed(valid, Signature::test_signature()));
    let valid: TempoTxEnv = Recovered::new_unchecked(valid, root.address()).into();
    let (result, valid) = evm.validate_pool_transaction(valid);
    let context = result.expect("the second non-AA transaction must be valid");
    assert_eq!(context.key_expiry, None);
    assert_eq!(evm.ext().resolved_fee_token, None);
    assert_eq!(evm.ext().key_expiry, None);
    assert_eq!(
        evm.overlay_db_mut()
            .get_account(&root.address())
            .unwrap()
            .unwrap_or_default()
            .nonce,
        0,
        "pool validation must discard nonce writes",
    );

    let reads = evm.database_as::<DbStats<InMemoryDB>>().unwrap().counts();
    let (result, _) = evm.validate_pool_transaction(valid);
    assert_eq!(result.unwrap().key_expiry, None);
    assert_eq!(
        evm.database_as::<DbStats<InMemoryDB>>().unwrap().counts(),
        reads,
        "reusing the EVM must retain loaded reads without leaking transaction writes",
    );
}
