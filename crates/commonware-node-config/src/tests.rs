use commonware_cryptography::{
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519::PrivateKey,
    Signer as _,
};
use commonware_utils::{N3f1, NZU32};
use rand_08::SeedableRng as _;

use crate::{SigningKey, SigningShare};

const SIGNING_KEY: &str = "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
const SIGNING_SHARE: &str = "0x00594108e8326f1a4f1dcfd0a473141bb95c54c9a591983922158f1f082c671e31";

#[test]
fn signing_key_snapshot() {
    SigningKey::try_from_hex(SIGNING_KEY).unwrap();
}

#[test]
fn signing_key_roundtrip() {
    let signing_key: SigningKey = PrivateKey::from_seed(42).into();
    assert_eq!(
        signing_key.public_key(),
        SigningKey::try_from_hex(&signing_key.to_string())
            .unwrap()
            .public_key(),
    );
}

#[test]
fn signing_share_snapshot() {
    SigningShare::try_from_hex(SIGNING_SHARE).unwrap();
}

#[test]
fn signing_share_roundtrip() {
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(42);

    let (_, mut shares) =
        dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(1));
    let share = shares.remove(0);
    let signing_share: SigningShare = share.into();
    assert_eq!(
        signing_share,
        SigningShare::try_from_hex(&signing_share.to_string()).unwrap(),
    );
}

// --- Encrypted key roundtrip tests ---

#[test]
fn signing_key_encrypted_roundtrip() {
    let dir = std::env::temp_dir().join("tempo_test_enc_key");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.key.enc");

    let original: SigningKey = PrivateKey::from_seed(99).into();
    let passphrase = b"integration-test-passphrase";

    original.write_encrypted(&path, passphrase).unwrap();

    // The file on disk must not contain the hex key in cleartext.
    let raw = std::fs::read(&path).unwrap();
    assert!(crate::encrypted::is_encrypted(&raw));

    // Decrypt and verify the public key matches.
    let recovered = SigningKey::read_maybe_encrypted(&path, Some(passphrase)).unwrap();
    assert_eq!(original.public_key(), recovered.public_key());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signing_key_plaintext_still_works_with_passphrase() {
    let dir = std::env::temp_dir().join("tempo_test_plain_key");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.key");

    let original: SigningKey = PrivateKey::from_seed(7).into();
    let mut file = std::fs::File::create(&path).unwrap();
    original.to_writer(&mut file).unwrap();

    // Plaintext files are read transparently even when a passphrase is supplied.
    let recovered = SigningKey::read_maybe_encrypted(&path, Some(b"unused")).unwrap();
    assert_eq!(original.public_key(), recovered.public_key());

    // Also works without any passphrase at all.
    let recovered_no_pass = SigningKey::read_maybe_encrypted(&path, None).unwrap();
    assert_eq!(original.public_key(), recovered_no_pass.public_key());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn signing_share_encrypted_roundtrip() {
    let dir = std::env::temp_dir().join("tempo_test_enc_share");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("test.share.enc");

    let mut rng = rand_08::rngs::StdRng::seed_from_u64(42);
    let (_, mut shares) =
        dkg::deal_anonymous::<MinSig, N3f1>(&mut rng, Default::default(), NZU32!(1));
    let original: SigningShare = shares.remove(0).into();
    let passphrase = b"share-passphrase";

    original.write_encrypted(&path, passphrase).unwrap();

    let recovered = SigningShare::read_maybe_encrypted(&path, Some(passphrase)).unwrap();
    assert_eq!(original, recovered);

    let _ = std::fs::remove_dir_all(&dir);
}
