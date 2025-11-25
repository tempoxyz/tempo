use std::str::FromStr;

use commonware_cryptography::{
    PrivateKeyExt as _, Signer as _, bls12381::primitives::variant::MinSig, ed25519::PrivateKey,
};
use commonware_utils::set::OrderedAssociated;
use rand::SeedableRng as _;

use std::net::SocketAddr;

use crate::{PeersAndPublicPolynomial, SigningKey, SigningShare};

const PEERS_AND_PUBLIC_POLYNOMIAL: &str = r#"
public_polynomial = "0x85a21686d219ba66f65165c17cb9b8f02a827b473b54f734e8f00d5705b7ceb12537de49c1c06fdad1df74cbfb7cd7d104eb6ab9330edf7854b2180ff1594034115fa80dbc865aca54f8813f41ef0e34518f972adad793e9d9302114f941db0183a5ec4224f3df5471a3927e2d8968e2a7948322f204b228a131c5931df4eb5e903d1a1e4cf31f2fbda357191e33b0810a0e97b748b7ab8142fdb946c457b1b3d29b60469c488306381285e794a377e9d3cf049eb850507a04f8775b2dcb0788"
    
[peers]
0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7 = "127.0.0.1:8000"
0xbaad106129bc215c1cca3760644914ed37ea91f1f1319999ce91ef2eaf51c827 = "192.168.0.1:9000"
"#;

const SIGNING_KEY: &str = "0x7848b5d711bc9883996317a3f9c90269d56771005d540a19184939c9e8d0db2a";
const SIGNING_SHARE: &str = "0x00594108e8326f1a4f1dcfd0a473141bb95c54c9a591983922158f1f082c671e31";

#[test]
fn peers_and_public_polynomial_snapshot() {
    PeersAndPublicPolynomial::from_str(PEERS_AND_PUBLIC_POLYNOMIAL)
        .expect("the example config should be parse-able");
}

#[test]
fn peers_and_public_polynomial_roundtrip() {
    let peers = OrderedAssociated::from_iter([
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
    ]);
    let quorum = commonware_utils::quorum(peers.len() as u32);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (public_polynomial, _) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<
        _,
        MinSig,
    >(&mut rng, None, peers.len() as u32, quorum);
    let peers_and_public_polynomial = PeersAndPublicPolynomial {
        public_polynomial,
        peers,
    };

    assert_eq!(
        peers_and_public_polynomial,
        PeersAndPublicPolynomial::from_str(&peers_and_public_polynomial.to_string().unwrap())
            .unwrap(),
    );
}

#[should_panic(expected = "duplicate key")]
#[test]
fn duplicate_peers_are_rejected() {
    const DUPLICATE_PEERS: &str = r#"
public_polynomial = "0x85a21686d219ba66f65165c17cb9b8f02a827b473b54f734e8f00d5705b7ceb12537de49c1c06fdad1df74cbfb7cd7d104eb6ab9330edf7854b2180ff1594034115fa80dbc865aca54f8813f41ef0e34518f972adad793e9d9302114f941db0183a5ec4224f3df5471a3927e2d8968e2a7948322f204b228a131c5931df4eb5e903d1a1e4cf31f2fbda357191e33b0810a0e97b748b7ab8142fdb946c457b1b3d29b60469c488306381285e794a377e9d3cf049eb850507a04f8775b2dcb0788"
    
[peers]
0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7 = "127.0.0.1:8000"
0xbaad106129bc215c1cca3760644914ed37ea91f1f1319999ce91ef2eaf51c827 = "192.168.0.1:9000"
0x945fadcd1ea3bac97c86c2acbc539fce43219552d24aaa3188c3afc1df4d50a7 = "127.0.0.1:8000"
"#;
    PeersAndPublicPolynomial::from_str(DUPLICATE_PEERS).unwrap();
}

#[test]
fn signing_key_snapshot() {
    SigningKey::from_str(SIGNING_KEY).unwrap();
}

#[test]
fn signing_key_roundtrip() {
    let signing_key: SigningKey = PrivateKey::from_seed(42).into();
    assert_eq!(
        signing_key,
        SigningKey::from_str(&signing_key.to_string()).unwrap(),
    );
}

#[test]
fn signing_share_snapshot() {
    SigningShare::from_str(SIGNING_SHARE).unwrap();
}

#[test]
fn signing_share_roundtrip() {
    let quorum = commonware_utils::quorum(1_u32);
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let (_, mut shares) = commonware_cryptography::bls12381::dkg::ops::generate_shares::<_, MinSig>(
        &mut rng, None, 1, quorum,
    );
    let signing_share: SigningShare = shares.remove(0).into();
    println!("{signing_share}");
    assert_eq!(
        signing_share,
        SigningShare::from_str(&signing_share.to_string()).unwrap(),
    );
}
