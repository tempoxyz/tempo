use super::*;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal_anonymous, primitives::sharing::Mode,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32};
use rand::{SeedableRng, rngs::StdRng};

struct Network {
    sharing: Sharing<MinSig>,
    shares: Vec<Share>,
}

impl Network {
    fn new(rng: &mut StdRng) -> Self {
        let (sharing, shares) =
            deal_anonymous::<MinSig, N3f1>(rng, Mode::NonZeroCounter, NZU32!(4));
        Self { sharing, shares }
    }

    fn identity(&self) -> NetworkIdentity {
        *self.sharing.public()
    }

    /// Keys for `identities` recovered from the first quorum of validators.
    fn keys(&self, identities: &[B256]) -> Vec<DecryptionKey> {
        let quorum: Vec<_> = self.shares[..self.sharing.required() as usize]
            .iter()
            .map(|share| key_shares(share, identities, &Sequential))
            .collect();
        recover_keys(&self.sharing, &quorum, &Sequential).unwrap()
    }
}

fn envelope(nonce: u64) -> Envelope {
    Envelope {
        chain_id: 4217,
        sender: Address::repeat_byte(0x11),
        nonce_key: U256::from(7),
        nonce,
        gas_limit: 100_000,
    }
}

#[test]
fn recovered_key_opens_body() {
    let mut rng = StdRng::seed_from_u64(1);
    let network = Network::new(&mut rng);
    let body = b"transfer 100 USDC to 0xabc".to_vec();
    let (encrypted, id) =
        EncryptedBody::encrypt(&mut rng, network.identity(), &envelope(0), &body).unwrap();

    let keys = network.keys(&[id]);

    verify_keys(&mut rng, &network.identity(), &[id], &keys, &Sequential).unwrap();
    assert_eq!(encrypted.decrypt(&keys[0]).unwrap(), body);
}

#[test]
fn key_for_another_envelope_does_not_open_body() {
    let mut rng = StdRng::seed_from_u64(2);
    let network = Network::new(&mut rng);
    let (encrypted, _) =
        EncryptedBody::encrypt(&mut rng, network.identity(), &envelope(0), b"secret").unwrap();
    let copied_into = envelope(1).identity(keccak256(&encrypted.sealed));

    let keys = network.keys(&[copied_into]);

    assert!(matches!(encrypted.decrypt(&keys[0]), Err(Error::Decrypt)));
}

#[test]
fn tampered_body_is_rejected() {
    let mut rng = StdRng::seed_from_u64(3);
    let network = Network::new(&mut rng);
    let (mut encrypted, id) =
        EncryptedBody::encrypt(&mut rng, network.identity(), &envelope(0), b"secret").unwrap();
    encrypted.sealed[0] ^= 1;

    let keys = network.keys(&[id]);

    assert!(matches!(encrypted.decrypt(&keys[0]), Err(Error::Decrypt)));
}

#[test]
fn swapped_key_shares_are_rejected() {
    let mut rng = StdRng::seed_from_u64(4);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1), B256::repeat_byte(2)];
    let signer = &network.shares[0];
    let mut shares = key_shares(signer, &ids, &Sequential);
    verify_key_shares(
        &mut rng,
        &network.sharing,
        signer.index,
        &ids,
        &shares,
        &Sequential,
    )
    .unwrap();

    shares.swap(0, 1);

    assert!(matches!(
        verify_key_shares(
            &mut rng,
            &network.sharing,
            signer.index,
            &ids,
            &shares,
            &Sequential
        ),
        Err(Error::Threshold(_))
    ));
}

#[test]
fn swapped_keys_are_rejected() {
    let mut rng = StdRng::seed_from_u64(5);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1), B256::repeat_byte(2)];
    let mut keys = network.keys(&ids);

    keys.swap(0, 1);

    assert!(matches!(
        verify_keys(&mut rng, &network.identity(), &ids, &keys, &Sequential),
        Err(Error::Threshold(_))
    ));
}

#[test]
fn missing_keys_are_rejected() {
    let mut rng = StdRng::seed_from_u64(6);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1), B256::repeat_byte(2)];
    let keys = network.keys(&ids[..1]);

    assert!(matches!(
        verify_keys(&mut rng, &network.identity(), &ids, &keys, &Sequential),
        Err(Error::LengthMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn ragged_share_sets_are_rejected() {
    let mut rng = StdRng::seed_from_u64(7);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1), B256::repeat_byte(2)];
    let mut quorum: Vec<_> = network.shares[..network.sharing.required() as usize]
        .iter()
        .map(|share| key_shares(share, &ids, &Sequential))
        .collect();
    quorum[1].pop();

    assert!(matches!(
        recover_keys(&network.sharing, &quorum, &Sequential),
        Err(Error::LengthMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn substituted_key_ciphertext_does_not_open_body() {
    let mut rng = StdRng::seed_from_u64(8);
    let network = Network::new(&mut rng);
    let (mut encrypted, id) =
        EncryptedBody::encrypt(&mut rng, network.identity(), &envelope(0), b"secret").unwrap();
    encrypted.key = tle::encrypt::<_, MinSig>(
        &mut rng,
        network.identity(),
        (NAMESPACE, id.as_slice()),
        &tle::Block::new([7; 32]),
    )
    .unwrap();

    let keys = network.keys(&[id]);

    assert!(matches!(encrypted.decrypt(&keys[0]), Err(Error::Decrypt)));
}
