use std::collections::BTreeMap;

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _,
    bls12381::{
        dkg::{Dealer, Info, Player},
        primitives::variant::MinSig,
    },
    ed25519::{PrivateKey, PublicKey},
};
use commonware_utils::{TryFromIterator as _, ordered};
use rand::SeedableRng as _;

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
        signing_key,
        SigningKey::try_from_hex(&signing_key.to_string()).unwrap(),
    );
}

#[test]
fn signing_share_snapshot() {
    SigningShare::try_from_hex(SIGNING_SHARE).unwrap();
}

#[test]
fn signing_share_roundtrip() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);

    let dealer_key = PrivateKey::from_rng(&mut rng);
    let player_key = PrivateKey::from_rng(&mut rng);

    let info = Info::<MinSig, PublicKey>::new(
        b"test",
        0,
        None,
        ordered::Set::try_from_iter([dealer_key.public_key()]).unwrap(),
        ordered::Set::try_from_iter([player_key.public_key()]).unwrap(),
    )
    .unwrap();

    let (mut dealer, pub_msg, mut priv_msgs) =
        Dealer::start(rng, info.clone(), dealer_key.clone(), None).unwrap();

    let mut player = Player::new(info.clone(), player_key.clone()).unwrap();
    let ack = player
        .dealer_message(dealer_key.public_key(), pub_msg, priv_msgs.remove(0).1)
        .unwrap();
    dealer
        .receive_player_ack(player_key.public_key(), ack)
        .unwrap();
    let signed_log = dealer.finalize();
    let (_, log) = signed_log.check(&info).unwrap();
    let logs = BTreeMap::from([(dealer_key.public_key(), log)]);
    let (_, share) = player.finalize(logs, 1).unwrap();

    let signing_share: SigningShare = share.into();
    assert_eq!(
        signing_share,
        SigningShare::try_from_hex(&signing_share.to_string()).unwrap(),
    );
}
