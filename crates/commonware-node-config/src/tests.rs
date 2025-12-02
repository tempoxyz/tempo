use std::net::SocketAddr;

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _, bls12381::primitives::variant::MinSig, ed25519::PrivateKey,
};
use commonware_utils::set::OrderedAssociated;
use rand::SeedableRng as _;

use crate::{Peers, PublicPolynomial, SigningKey, SigningShare};

const PEERS: &str = r#"{
"0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7": "127.0.0.1:8000",
"0xbaad106129bc215c1cca3760644914ed37ea91f1f1319999ce91ef2eaf51c827": "192.168.0.1:9000"
}
"#;

const SIGNING_KEY: &str = "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
const SIGNING_SHARE: &str = "0x00594108e8326f1a4f1dcfd0a473141bb95c54c9a591983922158f1f082c671e31";

#[test]
fn peers_snapshot() {
    serde_json::from_str::<Peers>(PEERS).expect("the example config should be parse-able");
}

#[test]
fn peers_roundtrip() {
    let peers: Peers = OrderedAssociated::from_iter([
        (
            PrivateKey::from_seed(0).public_key(),
            "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
        ),
        (
            PrivateKey::from_seed(1).public_key(),
            "192.168.0.1:9000".parse::<SocketAddr>().unwrap(),
        ),
        (
            PrivateKey::from_seed(2).public_key(),
            "1.1.1.1:58".parse::<SocketAddr>().unwrap(),
        ),
        (
            PrivateKey::from_seed(3).public_key(),
            "172.3.2.4:42".parse::<SocketAddr>().unwrap(),
        ),
    ])
    .into();
    assert_eq!(
        peers,
        serde_json::from_str(&serde_json::to_string(&peers).unwrap()).unwrap(),
    );
}

#[should_panic(expected = "duplicate key")]
#[test]
fn duplicate_peers_are_rejected() {
    const DUPLICATE_PEERS: &str = r#"
{
"0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7": "127.0.0.1:8000",
"0xbaad106129bc215c1cca3760644914ed37ea91f1f1319999ce91ef2eaf51c827": "192.168.0.1:9000",
"0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7": "127.0.0.1:8000",
}
"#;
    serde_json::from_str::<Peers>(DUPLICATE_PEERS).unwrap();
}

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
    let quorum = commonware_utils::quorum(1_u32);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (_, mut shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<_, MinSig>(
        &mut rng, None, 1, quorum,
    );
    let signing_share: SigningShare = shares.remove(0).into();
    assert_eq!(
        signing_share,
        SigningShare::try_from_hex(&signing_share.to_string()).unwrap(),
    );
}

#[track_caller]
fn assert_public_polynomial_roundtrip(nodes: u32) {
    let quorum = commonware_utils::quorum(nodes);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (polynomial, _) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<_, MinSig>(
        &mut rng, None, nodes, quorum,
    );
    let public_polynomial = PublicPolynomial::from(polynomial);
    assert_eq!(
        public_polynomial,
        serde_json::from_str(&serde_json::to_string(&public_polynomial).unwrap()).unwrap()
    );
}

#[test]
fn public_polynomial_roundtrips() {
    assert_public_polynomial_roundtrip(1);
    assert_public_polynomial_roundtrip(2);
    assert_public_polynomial_roundtrip(10);
    assert_public_polynomial_roundtrip(100);
    assert_public_polynomial_roundtrip(150);
}
