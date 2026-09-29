use alloy_evm::EvmEnv;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use revm::{
    context::{CfgEnv, TxEnv},
    database::EmptyDB,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_evm::{TempoBlockEnv, TempoPoolValidationEvm, evm::TempoEvm};
use tempo_precompiles::PATH_USD_ADDRESS;
use tempo_primitives::{
    SignatureType, TempoSignature,
    transaction::{Call, KeyAuthorization, PrimitiveSignature},
};
use tempo_revm::{TempoBatchCallEnv, TempoTxEnv, gas_params::tempo_gas_params_with_amsterdam};

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

    let mut env = EvmEnv::new(
        CfgEnv::new_with_spec_and_gas_params(
            TempoHardfork::T10,
            tempo_gas_params_with_amsterdam(TempoHardfork::T10, false),
        ),
        TempoBlockEnv::default(),
    );
    env.cfg_env.chain_id = 1;
    env.block_env.inner.timestamp = U256::from(BLOCK_TIMESTAMP);
    env.block_env.inner.basefee = 0;
    let mut evm = TempoEvm::new(EmptyDB::default(), env);
    evm.configure_for_pool();

    let rejected = TempoTxEnv {
        inner: TxEnv {
            caller: root.address(),
            gas_limit: 1_000_000,
            gas_price: 0,
            kind: TxKind::Call(Address::repeat_byte(0x44)),
            ..Default::default()
        },
        fee_token: Some(PATH_USD_ADDRESS),
        tempo_tx_env: Some(Box::new(TempoBatchCallEnv {
            signature: TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
                root.sign_hash_sync(&B256::ZERO).unwrap(),
            )),
            aa_calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x44)),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            key_authorization: Some(
                authorization.into_signed(PrimitiveSignature::Secp256k1(authorization_signature)),
            ),
            signature_hash: B256::ZERO,
            ..Default::default()
        })),
        ..Default::default()
    };

    let (result, _) = evm.validate_pool_transaction(rejected);
    assert!(result.is_err(), "the first transaction must be rejected");

    let valid_non_aa_transaction = TempoTxEnv {
        inner: TxEnv {
            caller: root.address(),
            gas_limit: 1_000_000,
            gas_price: 0,
            kind: TxKind::Call(Address::repeat_byte(0x55)),
            ..Default::default()
        },
        fee_token: Some(PATH_USD_ADDRESS),
        ..Default::default()
    };

    let (result, _) = evm.validate_pool_transaction(valid_non_aa_transaction);
    let context = result.expect("the second non-AA transaction must be valid");
    assert_eq!(context.key_expiry, None);
}
