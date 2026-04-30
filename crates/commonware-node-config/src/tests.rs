use std::io::Write as _;

use commonware_cryptography::{
    Signer as _,
    bls12381::{dkg, primitives::variant::MinSig},
    ed25519::PrivateKey,
};
use commonware_utils::{N3f1, NZU32};
use rand_08::SeedableRng as _;

use crate::{SigningKey, SigningShare};

const SIGNING_KEY: &str = "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
const SIGNING_SHARE: &str = "0x00594108e8326f1a4f1dcfd0a473141bb95c54c9a591983922158f1f082c671e31";

fn write_tempfile(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

#[test]
fn signing_key_snapshot() {
    SigningKey::try_from_hex(SIGNING_KEY).unwrap();
}

#[test]
fn signing_key_read_from_file_trims_whitespace() {
    let file = write_tempfile(&format!("{SIGNING_KEY}\n"));
    SigningKey::read_from_file(file.path()).unwrap();
    let file = write_tempfile(&format!("  {SIGNING_KEY}\r\n"));
    SigningKey::read_from_file(file.path()).unwrap();
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
