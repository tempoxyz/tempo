use std::io::Write as _;

use commonware_codec::Encode as _;
use commonware_cryptography::{
    Signer as _,
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519::PrivateKey,
};
use commonware_utils::{N3f1, NZU32};
use rand_08::SeedableRng as _;
use secrecy::ExposeSecret as _;

use crate::{
    MAX_SIGNING_KEY_PASSPHRASE_BYTES, SigningKey, SigningKeyPassphrase, SigningShare, read_secret,
    read_secret_inner,
};

const SIGNING_KEY: &str = "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
const SIGNING_SHARE: &str = "0x00594108e8326f1a4f1dcfd0a473141bb95c54c9a591983922158f1f082c671e31";

fn write_tempfile(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}
fn encrypt_with_passphrase(plaintext: &[u8], passphrase: &str) -> Vec<u8> {
    use std::io::Write as _;

    let mut ciphertext = Vec::new();
    let mut writer = age::Encryptor::with_user_passphrase(secrecy::SecretString::from(passphrase))
        .wrap_output(&mut ciphertext)
        .unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    ciphertext
}

fn raw_private_key_bytes() -> Vec<u8> {
    SigningKey::try_from_hex(SIGNING_KEY)
        .unwrap()
        .into_inner()
        .encode()
        .to_vec()
}

fn passphrase(value: &str) -> SigningKeyPassphrase {
    secrecy::SecretString::from(value.to_owned())
}

#[test]
fn signing_key_passphrase_reader_trims_trailing_newlines() {
    let passphrase = read_secret_inner("hunter2\r\n".as_bytes()).unwrap();
    assert_eq!(passphrase.expose_secret(), "hunter2");
}

#[test]
fn signing_key_passphrase_reader_allows_missing_trailing_newline() {
    let passphrase = read_secret_inner("hunter2".as_bytes()).unwrap();
    assert_eq!(passphrase.expose_secret(), "hunter2");
}

#[test]
fn signing_key_passphrase_reader_rejects_over_limit_passphrases() {
    let passphrase = "x".repeat(MAX_SIGNING_KEY_PASSPHRASE_BYTES as usize + 1);
    let err = read_secret_inner(passphrase.as_bytes()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn signing_key_passphrase_reader_accepts_regular_files() {
    let file = write_tempfile("hunter2\n");
    let (passphrase, is_fifo) = read_secret(file.path()).unwrap();
    assert_eq!(passphrase.expose_secret(), "hunter2");
    assert!(!is_fifo);
}

#[test]
fn signing_key_snapshot() {
    SigningKey::try_from_hex(SIGNING_KEY).unwrap();
}

#[test]
fn signing_key_read_unencrypted_from_file_trims_whitespace() {
    let file = write_tempfile(&format!("{SIGNING_KEY}\n"));
    SigningKey::read_from_file_unencrypted(file.path()).unwrap();
    let file = write_tempfile(&format!("  {SIGNING_KEY}\r\n"));
    SigningKey::read_from_file_unencrypted(file.path()).unwrap();
}

#[test]
fn signing_key_read_encrypted_roundtrip() {
    let ciphertext =
        encrypt_with_passphrase(&raw_private_key_bytes(), "correct horse battery staple");

    let key = SigningKey::read_encrypted(
        ciphertext.as_slice(),
        passphrase("correct horse battery staple"),
    )
    .expect("decryption with the correct passphrase should succeed");

    let expected = SigningKey::try_from_hex(SIGNING_KEY).unwrap();
    assert_eq!(key.public_key(), expected.public_key());
}

#[test]
fn signing_key_read_encrypted_wrong_passphrase_fails() {
    let ciphertext = encrypt_with_passphrase(&raw_private_key_bytes(), "right");
    SigningKey::read_encrypted(ciphertext.as_slice(), passphrase("wrong"))
        .expect_err("decryption with the wrong passphrase must fail");
}

#[test]
fn signing_key_read_encrypted_from_file_roundtrip() {
    let ciphertext = encrypt_with_passphrase(&raw_private_key_bytes(), "hunter2");
    let mut file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut file, &ciphertext).unwrap();

    let key = SigningKey::read_from_file_encrypted(file.path(), passphrase("hunter2")).unwrap();
    let expected = SigningKey::try_from_hex(SIGNING_KEY).unwrap();
    assert_eq!(key.public_key(), expected.public_key());
}

#[test]
fn signing_key_random_generates_distinct_keys() {
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(7);
    let a = SigningKey::random(&mut rng);
    let b = SigningKey::random(&mut rng);
    assert_ne!(a.public_key(), b.public_key());
}

#[test]
fn signing_key_write_to_file_encrypted_roundtrip() {
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(99);
    let original = SigningKey::random(&mut rng);

    let file = tempfile::NamedTempFile::new().unwrap();
    original
        .write_to_file_encrypted(file.path(), passphrase("hunter2"))
        .expect("encrypted write must succeed");

    let loaded = SigningKey::read_from_file_encrypted(file.path(), passphrase("hunter2"))
        .expect("encrypted read with the correct passphrase must succeed");

    assert_eq!(loaded.public_key(), original.public_key());
}

#[test]
fn signing_key_write_encrypted_wrong_passphrase_fails() {
    let mut rng = rand_08::rngs::StdRng::seed_from_u64(1234);
    let key = SigningKey::random(&mut rng);

    let mut buf = Vec::new();
    key.write_encrypted(&mut buf, passphrase("right")).unwrap();

    SigningKey::read_encrypted(buf.as_slice(), passphrase("wrong"))
        .expect_err("wrong passphrase must fail to decrypt");
}

#[test]
fn signing_key_roundtrip() {
    let signing_key: SigningKey = PrivateKey::from_seed(42).into();
    let mut buf = Vec::new();
    signing_key.to_writer_unencrypted(&mut buf).unwrap();
    let hex = std::str::from_utf8(&buf).unwrap();
    assert_eq!(
        signing_key.public_key(),
        SigningKey::try_from_hex(hex).unwrap().public_key(),
    );
}

#[test]
fn signing_share_snapshot() {
    SigningShare::try_from_hex(SIGNING_SHARE).unwrap();
}

#[test]
fn signing_share_read_from_file_trims_whitespace() {
    let file = write_tempfile(&format!("{SIGNING_SHARE}\n"));
    SigningShare::read_from_file(file.path()).unwrap();
    let file = write_tempfile(&format!("  {SIGNING_SHARE}\r\n"));
    SigningShare::read_from_file(file.path()).unwrap();
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
