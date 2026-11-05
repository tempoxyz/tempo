use super::*;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::deal_anonymous, primitives::sharing::Mode,
};
use commonware_parallel::Sequential;
use commonware_utils::{N3f1, NZU32, Participant};
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

#[test]
fn missing_key_shares_are_rejected() {
    let mut rng = StdRng::seed_from_u64(9);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1), B256::repeat_byte(2)];
    let signer = &network.shares[0];
    let shares = key_shares(signer, &ids[..1], &Sequential);

    assert!(matches!(
        verify_key_shares(
            &mut rng,
            &network.sharing,
            signer.index,
            &ids,
            &shares,
            &Sequential
        ),
        Err(Error::LengthMismatch {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn recovery_below_quorum_is_rejected() {
    let mut rng = StdRng::seed_from_u64(10);
    let network = Network::new(&mut rng);
    let ids = [B256::repeat_byte(1)];
    let too_few: Vec<_> = network.shares[..network.sharing.required() as usize - 1]
        .iter()
        .map(|share| key_shares(share, &ids, &Sequential))
        .collect();

    assert!(matches!(
        recover_keys(&network.sharing, &too_few, &Sequential),
        Err(Error::Threshold(
            commonware_cryptography::bls12381::primitives::Error::NotEnoughPartialSignatures(3, 2)
        ))
    ));
}

mod fast_path {
    use super::*;
    use crate::fast;
    use commonware_codec::Encode;
    use commonware_parallel::Sequential;

    fn block(
        network: &Network,
        rng: &mut StdRng,
        count: u64,
    ) -> (Vec<(B256, EncryptedBody)>, Vec<Vec<u8>>) {
        let plaintexts: Vec<_> = (0..count)
            .map(|i| format!("body {i}").into_bytes())
            .collect();
        let bodies = plaintexts
            .iter()
            .enumerate()
            .map(|(i, body)| {
                let (encrypted, id) =
                    EncryptedBody::encrypt(rng, network.identity(), &envelope(i as u64), body)
                        .unwrap();
                (id, encrypted)
            })
            .collect();
        (bodies, plaintexts)
    }

    fn quorum(
        network: &Network,
        prepared: &[fast::Prepared],
    ) -> Vec<(Participant, Vec<fast::Key>)> {
        network.shares[..network.sharing.required() as usize]
            .iter()
            .map(|share| (share.index, fast::sign(share, prepared, &Sequential)))
            .collect()
    }

    #[test]
    fn matches_reference_and_opens_every_body() {
        let mut rng = StdRng::seed_from_u64(20);
        let network = Network::new(&mut rng);
        let (bodies, plaintexts) = block(&network, &mut rng, 6);
        let ids: Vec<_> = bodies.iter().map(|(id, _)| *id).collect();
        let prepared = fast::prepare(&bodies, &Sequential).unwrap();
        let quorum = quorum(&network, &prepared);

        let reference_shares = key_shares(&network.shares[0], &ids, &Sequential);
        let reference_bytes: Vec<u8> = reference_shares
            .iter()
            .flat_map(|share| share.value.encode())
            .collect();
        assert_eq!(fast::encode_compressed(&quorum[0].1), reference_bytes);

        let keys = fast::recover(&quorum, &Sequential).unwrap();
        let reference_keys: Vec<u8> = network
            .keys(&ids)
            .iter()
            .flat_map(|key| key.encode())
            .collect();
        assert_eq!(fast::encode_compressed(&keys), reference_keys);

        let point = fast::network_point(&network.identity()).unwrap();
        fast::verify_keys(&mut rng, &point, &prepared, &keys, &Sequential).unwrap();
        let sigmas = fast::decrypt_sigmas(&prepared, &keys, &Sequential).unwrap();
        let body_keys = fast::verify_openings(&mut rng, &prepared, &sigmas, &Sequential).unwrap();
        let opened: Vec<_> = fast::open_bodies(&bodies, &body_keys, &Sequential)
            .into_iter()
            .map(Option::unwrap)
            .collect();
        assert_eq!(opened, plaintexts);
    }

    #[test]
    fn shares_round_trip_both_encodings() {
        let mut rng = StdRng::seed_from_u64(21);
        let network = Network::new(&mut rng);
        let (bodies, _) = block(&network, &mut rng, 3);
        let prepared = fast::prepare(&bodies, &Sequential).unwrap();
        let shares = fast::sign(&network.shares[0], &prepared, &Sequential);

        let compressed =
            fast::decode(&fast::encode_compressed(&shares), true, &Sequential).unwrap();
        let uncompressed =
            fast::decode(&fast::encode_uncompressed(&shares), false, &Sequential).unwrap();

        assert_eq!(
            fast::encode_compressed(&compressed),
            fast::encode_compressed(&shares)
        );
        assert_eq!(
            fast::encode_compressed(&uncompressed),
            fast::encode_compressed(&shares)
        );
    }

    #[test]
    fn swapped_keys_fail_batch_verification() {
        let mut rng = StdRng::seed_from_u64(22);
        let network = Network::new(&mut rng);
        let (bodies, _) = block(&network, &mut rng, 3);
        let prepared = fast::prepare(&bodies, &Sequential).unwrap();
        let mut keys = fast::recover(&quorum(&network, &prepared), &Sequential).unwrap();
        keys.swap(0, 1);
        let point = fast::network_point(&network.identity()).unwrap();

        assert!(matches!(
            fast::verify_keys(&mut rng, &point, &prepared, &keys, &Sequential),
            Err(Error::InvalidKey)
        ));
    }

    #[test]
    fn malformed_ciphertext_is_the_only_one_not_opened() {
        let mut rng = StdRng::seed_from_u64(23);
        let network = Network::new(&mut rng);
        let (mut bodies, _) = block(&network, &mut rng, 4);
        let mut v: [u8; 32] = bodies[2].1.key.v.as_ref().try_into().unwrap();
        v[0] ^= 1;
        bodies[2].1.key.v = tle::Block::new(v);
        let prepared = fast::prepare(&bodies, &Sequential).unwrap();
        let keys = fast::recover(&quorum(&network, &prepared), &Sequential).unwrap();

        let sigmas = fast::decrypt_sigmas(&prepared, &keys, &Sequential).unwrap();

        let body_keys = fast::verify_openings(&mut rng, &prepared, &sigmas, &Sequential).unwrap();
        let opened: Vec<_> = body_keys.iter().map(Option::is_some).collect();
        assert_eq!(opened, [true, true, false, true]);
    }

    #[test]
    fn ragged_quorum_is_rejected() {
        let mut rng = StdRng::seed_from_u64(24);
        let network = Network::new(&mut rng);
        let (bodies, _) = block(&network, &mut rng, 2);
        let prepared = fast::prepare(&bodies, &Sequential).unwrap();
        let mut quorum = quorum(&network, &prepared);
        quorum[1].1.pop();

        assert!(matches!(
            fast::recover(&quorum, &Sequential),
            Err(Error::LengthMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }
}

#[test]
fn wrong_sigma_does_not_open() {
    use crate::fast;
    use commonware_parallel::Sequential;

    let mut rng = StdRng::seed_from_u64(25);
    let network = Network::new(&mut rng);
    let bodies: Vec<_> = (0..3)
        .map(|i| {
            let (body, id) =
                EncryptedBody::encrypt(&mut rng, network.identity(), &envelope(i), b"secret")
                    .unwrap();
            (id, body)
        })
        .collect();
    let prepared = fast::prepare(&bodies, &Sequential).unwrap();
    let quorum: Vec<_> = network.shares[..network.sharing.required() as usize]
        .iter()
        .map(|share| (share.index, fast::sign(share, &prepared, &Sequential)))
        .collect();
    let keys = fast::recover(&quorum, &Sequential).unwrap();
    let mut sigmas = fast::decrypt_sigmas(&prepared, &keys, &Sequential).unwrap();
    sigmas[1][0] ^= 1;

    let body_keys = fast::verify_openings(&mut rng, &prepared, &sigmas, &Sequential).unwrap();

    let opened: Vec<_> = body_keys.iter().map(Option::is_some).collect();
    assert_eq!(opened, [true, false, true]);
}
