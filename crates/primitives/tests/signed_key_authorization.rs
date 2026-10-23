//! `SignedKeyAuthorization::new` is public API of published `tempo-primitives`.

use alloy_primitives::Address;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use tempo_primitives::transaction::{
    KeyAuthorization, PrimitiveSignature, SignatureType, SignedKeyAuthorization,
};

#[test]
fn new_signs_key_authorization_from_outside_the_crate() {
    let signer = PrivateKeySigner::random();
    let authorization =
        KeyAuthorization::unrestricted(1, SignatureType::Secp256k1, Address::repeat_byte(0x11));
    let signature = PrimitiveSignature::Secp256k1(
        signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap(),
    );

    let signed = SignedKeyAuthorization::new(authorization.clone(), signature);

    assert_eq!(signed.authorization, authorization);
    assert_eq!(signed.recover_signer().unwrap(), signer.address());
}
