use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_primitives::{
    TempoTransaction,
    transaction::{Call, KeychainSignature, PrimitiveSignature, TempoSignature},
};

fn tx(nonce: u64) -> TempoTransaction {
    TempoTransaction {
        chain_id: 1,
        gas_limit: 21_000,
        nonce,
        calls: vec![Call {
            to: TxKind::Call(Address::repeat_byte(0x42)),
            value: U256::ZERO,
            input: Bytes::new(),
        }],
        ..Default::default()
    }
}

// A keychain signature reused on another transaction reports the same access key as a freshly
// decoded copy of it, whatever it recovered before.
#[test]
fn reused_keychain_signature_recovers_for_the_new_digest() {
    let parent = Address::repeat_byte(0xaa);
    let access_key = PrivateKeySigner::random();
    let first = tx(0);
    let approval = access_key
        .sign_hash_sync(&KeychainSignature::signing_hash(
            first.signature_hash(),
            parent,
        ))
        .unwrap();
    let first = first.into_signed(TempoSignature::Keychain(KeychainSignature::new(
        parent,
        PrimitiveSignature::Secp256k1(approval),
    )));
    let first_keychain = first.signature().as_keychain().unwrap();
    assert_eq!(
        first_keychain.key_id(&first.signature_hash()).unwrap(),
        access_key.address()
    );

    let second = tx(1).into_signed(first.signature().clone());
    let fresh = TempoSignature::from_bytes(&second.signature().to_bytes()).unwrap();
    let fresh_key_id = fresh
        .as_keychain()
        .unwrap()
        .key_id(&second.signature_hash())
        .ok();
    let reused_key_id = second
        .signature()
        .as_keychain()
        .unwrap()
        .key_id(&second.signature_hash())
        .ok();
    assert_ne!(fresh_key_id, Some(access_key.address()));
    assert_eq!(reused_key_id, fresh_key_id);
    assert_eq!(
        first_keychain.key_id(&second.signature_hash()).ok(),
        fresh_key_id
    );
}
