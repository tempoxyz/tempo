use commonware_cryptography::{
    Signer as _,
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519::PrivateKey,
};
use commonware_utils::NZU32;
use crypto_common::rand_core::CryptoRngCore;
use rand::SeedableRng as _;

use crate::{SigningKey, SigningShare};

use super::EncryptionKey;

fn key(rng: &mut impl CryptoRngCore) -> EncryptionKey {
    EncryptionKey::random(rng)
}

#[test]
fn encryption_key_hex_roundtrip() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let key = key(&mut rng);
    assert_eq!(
        key.to_hex(),
        EncryptionKey::from_hex(key.to_hex().as_bytes())
            .unwrap()
            .to_hex(),
    );
}

#[test]
fn encryption_key_file_roundtrip() {
    let tmpfile = tempfile::NamedTempFile::new().unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let key = key(&mut rng);
    key.write_to_file(&tmpfile).unwrap();
    assert_eq!(
        key.to_hex(),
        EncryptionKey::read_from_file(&tmpfile).unwrap().to_hex(),
    );
}

#[test]
fn signing_key_roundtrip() {
    let signing_key: SigningKey = PrivateKey::from_seed(42).into();
    assert_eq!(
        signing_key,
        SigningKey::try_from_hex(&signing_key.to_string()).unwrap(),
    );
}

#[test]
fn signing_share_roundtrip() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let (_, mut shares) = dkg::deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(1));
    let share = shares.remove(0);
    let signing_share: SigningShare = share.into();

    let key = key(&mut rng);

    assert_eq!(
        signing_share,
        SigningShare::try_from_hex(signing_share.to_hex(&key, &mut rng).as_bytes(), &key).unwrap(),
    );
}

#[test]
fn zeroize_feature_is_activated() {
    fn implements_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    implements_zeroize_on_drop::<super::ChaCha20Poly1305>();
}
