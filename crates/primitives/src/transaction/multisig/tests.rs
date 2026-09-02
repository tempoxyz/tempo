use super::*;
use crate::transaction::{
    KeychainSignature, PrimitiveSignature, TempoSignature, derive_p256_address,
    tt_authorization::tests::{generate_secp256k1_keypair, sign_hash},
    tt_signature::{P256SignatureWithPreHash, WebAuthnSignature, normalize_p256_s},
};
use alloy_rlp::{Decodable, Encodable};
use p256::{
    ecdsa::{SigningKey as P256SigningKey, signature::hazmat::PrehashSigner},
    elliptic_curve::rand_core::OsRng,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

fn sorted_secp_config(owners: &[(Address, u8)], threshold: u8) -> MultisigConfig {
    let mut owners = owners
        .iter()
        .map(|(owner, weight)| MultisigOwner {
            owner: *owner,
            weight: *weight,
        })
        .collect::<Vec<_>>();
    owners.sort_by_key(|owner| owner.owner);
    MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold,
        owners,
    }
}

fn indexed_owner(index: u16) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18..].copy_from_slice(&index.to_be_bytes());
    Address::from(bytes)
}

fn valid_owner_signature_bytes() -> Bytes {
    valid_owner_signature().to_bytes()
}

fn valid_owner_signature() -> TempoSignature {
    TempoSignature::Primitive(PrimitiveSignature::Secp256k1(
        alloy_primitives::Signature::test_signature(),
    ))
}

fn initial_multisig_signature() -> MultisigSignature {
    let config = sorted_secp_config(&[(indexed_owner(2), 1)], 1);
    MultisigSignature::try_new(
        config.derive_account().unwrap(),
        config,
        vec![TempoSignature::Primitive(PrimitiveSignature::default())],
    )
    .unwrap()
}

fn current_config(owner: Address) -> MultisigConfig {
    MultisigConfig {
        salt: B256::ZERO,
        version: 1,
        threshold: 1,
        owners: vec![MultisigOwner { owner, weight: 1 }],
    }
}

fn generate_p256_keypair() -> (P256SigningKey, B256, B256, Address) {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let encoded_point = verifying_key.to_encoded_point(false);
    let pub_key_x = B256::from_slice(encoded_point.x().unwrap().as_ref());
    let pub_key_y = B256::from_slice(encoded_point.y().unwrap().as_ref());
    let owner = derive_p256_address(&pub_key_x, &pub_key_y);
    (signing_key, pub_key_x, pub_key_y, owner)
}

fn sign_p256_owner_approval_with_prehash(
    signing_key: &P256SigningKey,
    digest: B256,
    pub_key_x: B256,
    pub_key_y: B256,
) -> Bytes {
    let prehashed = B256::from_slice(Sha256::digest(digest).as_ref());
    let signature: p256::ecdsa::Signature = signing_key.sign_prehash(prehashed.as_slice()).unwrap();
    let sig_bytes = signature.to_bytes();
    PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::from_slice(&sig_bytes[..32]),
        s: normalize_p256_s(&sig_bytes[32..64]).expect("p256 crate produces valid s"),
        pub_key_x,
        pub_key_y,
        pre_hash: true,
    })
    .to_bytes()
}

fn encoded_multisig(
    account: Address,
    config: &MultisigConfig,
    signatures: Vec<Vec<u8>>,
) -> Vec<u8> {
    let signatures = signatures.into_iter().map(Bytes::from).collect::<Vec<_>>();
    let payload_length = account.length() + config.length() + signatures.length();
    let mut encoded = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    account.encode(&mut encoded);
    config.encode(&mut encoded);
    signatures.encode(&mut encoded);
    encoded
}

/// Builds `levels` of nested current-configuration multisig signatures, where the innermost
/// approval is primitive and each outer level has a single nested multisig owner.
fn nested_multisig_encoding(levels: usize) -> Vec<u8> {
    let mut current = encoded_multisig(
        indexed_owner(100),
        &current_config(indexed_owner(200)),
        vec![valid_owner_signature_bytes().to_vec()],
    );
    for level in 1..levels {
        let mut owner_approval = vec![SIGNATURE_TYPE_MULTISIG];
        owner_approval.extend_from_slice(&current);
        current = encoded_multisig(
            indexed_owner(100 + level as u16),
            &current_config(indexed_owner(200 + level as u16)),
            vec![owner_approval],
        );
    }
    current
}

fn assert_multisig_decode_rejected(encoded: &[u8]) {
    let mut input = encoded;
    assert!(MultisigSignature::decode(&mut input).is_err());

    let tempo_encoded = [SIGNATURE_TYPE_MULTISIG]
        .into_iter()
        .chain(encoded.iter().copied())
        .collect::<Vec<_>>();
    assert!(TempoSignature::from_bytes(&tempo_encoded).is_err());
}

#[cfg(feature = "serde")]
fn malformed_multisig_encodings() -> [Vec<u8>; 2] {
    [
        encoded_multisig(
            indexed_owner(1),
            &current_config(indexed_owner(2)),
            vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
        ),
        nested_multisig_encoding(4_096),
    ]
}

#[test]
fn account_derivation_is_stable_and_validates_owner_order() {
    let owner_a = Address::from([0x11; 20]);
    let owner_b = Address::from([0x22; 20]);
    let config = sorted_secp_config(&[(owner_b, 2), (owner_a, 1)], 2);

    config.validate().expect("config is valid");
    assert_eq!(
        config.derive_account().unwrap(),
        config.derive_account().unwrap()
    );

    let unsorted = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 1,
        owners: vec![
            MultisigOwner {
                owner: owner_b,
                weight: 1,
            },
            MultisigOwner {
                owner: owner_a,
                weight: 1,
            },
        ],
    };
    assert!(unsorted.validate().is_err());
}

#[test]
fn account_derivation_includes_salt() {
    let owner = Address::from([0x11; 20]);
    let zero_salt = sorted_secp_config(&[(owner, 1)], 1);
    let mut nonzero_salt = zero_salt.clone();
    nonzero_salt.salt = B256::repeat_byte(0x42);

    assert_ne!(
        zero_salt.derive_account().unwrap(),
        nonzero_salt.derive_account().unwrap()
    );
    zero_salt.validate().expect("zero salt is valid");
}

#[test]
fn recovery_factory_matches_singleton_create2_vector() {
    let factory = MULTISIG_RECOVERY_SINGLETON_FACTORY
        .create2(B256::ZERO, MULTISIG_RECOVERY_FACTORY_INIT_CODE_HASH);
    assert_eq!(factory, MULTISIG_RECOVERY_FACTORY);
}

#[test]
fn multisig_domains_match_spec_vectors() {
    let mut config = sorted_secp_config(&[(Address::repeat_byte(0x11), 1)], 1);
    let account_salt = config.account_salt().unwrap();
    let account = config.derive_account().unwrap();

    assert_eq!(
        account_salt,
        alloy_primitives::b256!("7162e370e58784e6b33d61878820d1497eeaf4f68e00b2cfc00a2f3b1dbb00da")
    );
    assert_eq!(
        account,
        alloy_primitives::address!("91847576f406d0842ad7c1a0c97c22a122e64278")
    );
    assert_eq!(multisig_account_address(account_salt), account);
    assert_eq!(
        multisig_digest(B256::repeat_byte(0x42), account, 0),
        alloy_primitives::b256!("7a62ef46efdf76a6a0ab6c38c5fdeda2169d6a0de3643bb9912a4fbce881a870")
    );

    assert_eq!(
        config.commitment().unwrap(),
        alloy_primitives::b256!("a9e7d1e2ad25e227a4de5f38f3bba31d854ffc8efec46aaa8649097a516bb4ee")
    );
    config.version = 1;
    assert_eq!(
        config.commitment().unwrap(),
        alloy_primitives::b256!("6237ca5930f2265d4fb70a0305dd6ceea4df227053b4a62c304489ede946a2f8")
    );
    assert_eq!(
        multisig_digest(B256::repeat_byte(0x42), account, 1),
        alloy_primitives::b256!("cceb022fd342beddcf6583e680c18a34936212276a680f026e52728b5ebb722b")
    );
}

#[test]
fn config_accepts_max_owners() {
    let owners = (1..=MAX_MULTISIG_OWNERS as u16)
        .map(|index| (indexed_owner(index), 1))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, MAX_MULTISIG_SIGNATURES as u8);

    assert_eq!(config.validate(), Ok(MAX_MULTISIG_OWNERS as u8));
    assert!(config.derive_account().is_ok());
}

#[test]
fn config_rejects_more_than_max_owners() {
    let owners = (1..=MAX_MULTISIG_OWNERS as u16 + 1)
        .map(|index| (indexed_owner(index), 1))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, 1);

    assert_eq!(config.validate(), Err(MultisigConfigError::TooManyOwners));
}

#[test]
fn config_total_weight_is_capped_at_u8_max() {
    let owner_a = Address::from([0x11; 20]);
    let owner_b = Address::from([0x22; 20]);
    let config = sorted_secp_config(&[(owner_a, 128), (owner_b, 128)], 1);

    assert_eq!(
        config.validate(),
        Err(MultisigConfigError::TotalWeightExceedsMax)
    );
}

#[test]
fn config_accepts_threshold_above_signature_cap() {
    let owner = Address::from([0x11; 20]);
    let threshold = MAX_MULTISIG_THRESHOLD;
    let config = sorted_secp_config(&[(owner, threshold)], threshold);

    assert_eq!(config.validate(), Ok(threshold));
}

#[test]
fn config_rejects_threshold_requiring_too_many_approvals() {
    let owners = (1..=MAX_MULTISIG_SIGNATURES as u16 + 1)
        .map(|index| (indexed_owner(index), 1))
        .collect::<Vec<_>>();
    let config = sorted_secp_config(&owners, owners.len() as u8);

    assert_eq!(
        config.validate(),
        Err(MultisigConfigError::ThresholdExceedsWeight)
    );
}

#[test]
fn config_rejects_own_account_as_owner() {
    let account = indexed_owner(1);
    let config = sorted_secp_config(&[(account, 1)], 1);

    assert_eq!(
        config.validate_for_account(account),
        Err(MultisigConfigError::AccountIsOwner)
    );

    let config = sorted_secp_config(&[(account, 0)], 1);
    assert_eq!(
        config.validate_for_account(account),
        Err(MultisigConfigError::AccountIsOwner)
    );
}

#[test]
fn multisig_shape_rejects_keychain_owner_approval() {
    let account = indexed_owner(1);
    let approval = TempoSignature::Keychain(KeychainSignature::new(
        indexed_owner(2),
        PrimitiveSignature::default(),
    ));

    assert_eq!(
        MultisigSignature::try_new(account, current_config(indexed_owner(2)), vec![approval],),
        Err(MultisigSignatureError::KeychainOwnerSignature)
    );
}

#[test]
fn multisig_shape_allows_nested_initial_approval() {
    let nested = initial_multisig_signature();
    let account = indexed_owner(1);
    assert!(
        MultisigSignature::try_new(
            account,
            current_config(nested.account()),
            vec![TempoSignature::Multisig(nested)],
        )
        .is_ok()
    );
}

#[test]
fn multisig_shape_rejects_programmatic_excess_nesting() {
    let leaf = MultisigSignature::try_new(
        indexed_owner(3),
        current_config(indexed_owner(4)),
        vec![TempoSignature::Primitive(PrimitiveSignature::default())],
    )
    .unwrap();
    let middle = MultisigSignature::try_new(
        indexed_owner(2),
        current_config(indexed_owner(3)),
        vec![TempoSignature::Multisig(leaf)],
    )
    .unwrap();

    assert_eq!(
        MultisigSignature::try_new(
            indexed_owner(1),
            current_config(indexed_owner(2)),
            vec![TempoSignature::Multisig(middle)],
        ),
        Err(MultisigSignatureError::NestingDepthExceeded)
    );
}

#[test]
fn shared_quorum_helpers_verify_order_and_threshold() {
    let owner_a = indexed_owner(1);
    let owner_b = indexed_owner(2);
    let owner_c = indexed_owner(3);
    let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 3), (owner_c, 2)], 4);

    // Reproduce the weight-accounting the native multisig verifier performs: look up each
    // recovered owner's configured weight and feed it to the shared accumulator in order.
    let ordered_weights = |owners: &[Address]| -> Result<(), MultisigQuorumError> {
        let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
        for &owner in owners {
            let weight = config
                .owner_weight(owner)
                .ok_or(MultisigQuorumError::SignerNotOwner)?;
            accumulator.record_owner(owner, weight)?;
        }
        accumulator.finish()
    };

    assert_eq!(ordered_weights(&[owner_a, owner_b]), Ok(()));
    assert_eq!(
        ordered_weights(&[owner_b]),
        Err(MultisigQuorumError::WeightBelowThreshold)
    );
    assert_eq!(
        ordered_weights(&[owner_b, owner_a]),
        Err(MultisigQuorumError::SignersNotAscending)
    );
    assert_eq!(
        ordered_weights(&[indexed_owner(4)]),
        Err(MultisigQuorumError::SignerNotOwner)
    );

    assert_eq!(
        MultisigWeightAccumulator::new(0).err(),
        Some(MultisigQuorumError::ZeroThreshold)
    );
}

#[test]
fn owner_signature_cannot_replay_across_accounts_with_same_owners() {
    let (signer, owner) = generate_secp256k1_keypair();
    let mut config_a = sorted_secp_config(&[(owner, 1)], 1);
    config_a.salt = B256::repeat_byte(0x11);
    let mut config_b = sorted_secp_config(&[(owner, 1)], 1);
    config_b.salt = B256::repeat_byte(0x22);

    let account_a = config_a.derive_account().unwrap();
    let account_b = config_b.derive_account().unwrap();
    assert_ne!(account_a, account_b);

    let inner_digest = B256::repeat_byte(0x42);
    let digest_a = multisig_digest(inner_digest, account_a, 0);
    let digest_b = multisig_digest(inner_digest, account_b, 0);
    assert_ne!(digest_a, digest_b, "digest is domain-separated by account");

    // An owner approval recovers the owner only against the account it was signed for; replaying
    // it against another account's digest recovers a different address that is not an owner.
    let signature = sign_hash(&signer, &digest_a);
    assert_eq!(signature.recover_signer(&digest_a).unwrap(), owner);
    assert_ne!(signature.recover_signer(&digest_b).unwrap(), owner);
}

#[test]
fn owner_signature_cannot_replay_across_config_versions() {
    let (signer, owner) = generate_secp256k1_keypair();
    let config = sorted_secp_config(&[(owner, 1)], 1);
    let account = config.derive_account().unwrap();
    let inner_digest = B256::repeat_byte(0x42);
    let initial_digest = multisig_digest(inner_digest, account, 0);
    let rotated_digest = multisig_digest(inner_digest, account, 1);

    assert_ne!(initial_digest, rotated_digest);
    let signature = sign_hash(&signer, &initial_digest);
    assert_eq!(signature.recover_signer(&initial_digest).unwrap(), owner);
    assert_ne!(signature.recover_signer(&rotated_digest).unwrap(), owner);
}

#[test]
fn verifies_weighted_owner_signatures_in_sorted_order() {
    let (signer_a, owner_a) = generate_secp256k1_keypair();
    let (signer_b, owner_b) = generate_secp256k1_keypair();
    let config = sorted_secp_config(&[(owner_a, 1), (owner_b, 1)], 2);
    let account = config.derive_account().unwrap();
    let digest = multisig_digest(B256::repeat_byte(0x42), account, 0);

    let mut signed = [
        (owner_a, sign_hash(&signer_a, &digest)),
        (owner_b, sign_hash(&signer_b, &digest)),
    ];
    signed.sort_by_key(|(owner, _)| *owner);

    // Feed the recovered owners through the shared accumulator, as the verifier does.
    let quorum_weight = |approvals: &[&TempoSignature]| -> Result<(), MultisigQuorumError> {
        let mut accumulator = MultisigWeightAccumulator::new(config.threshold)?;
        for approval in approvals {
            let owner = approval.recover_signer(&digest).unwrap();
            let weight = config
                .owner_weight(owner)
                .ok_or(MultisigQuorumError::SignerNotOwner)?;
            accumulator.record_owner(owner, weight)?;
        }
        accumulator.finish()
    };

    let both = [&signed[0].1, &signed[1].1];
    assert_eq!(quorum_weight(&both), Ok(()));

    // A single owner falls short of the threshold of 2.
    assert!(quorum_weight(&[&signed[0].1]).is_err());
}

#[test]
fn noncanonical_p256_owner_prehash_flag_canonicalizes() {
    // A P256 owner approval carrying a noncanonical pre_hash flag byte decodes to the same
    // signature and re-encodes with the canonical flag, so it cannot malleate the transaction
    // hash even though the raw wire byte differs. This structural canonicalization replaces the
    // (STF-breaking) strict-flag rejection that was previously attempted at decode time.
    let (signer, pub_key_x, pub_key_y, owner) = generate_p256_keypair();
    let config = sorted_secp_config(&[(owner, 1)], 1);
    let account = config.derive_account().unwrap();
    let digest = multisig_digest(B256::repeat_byte(0x42), account, 0);

    let canonical_signature =
        sign_p256_owner_approval_with_prehash(&signer, digest, pub_key_x, pub_key_y);
    assert_eq!(
        canonical_signature[canonical_signature.len() - 1],
        1,
        "test setup should use canonical pre_hash=true encoding"
    );

    let mut noncanonical_signature = canonical_signature.to_vec();
    let flag_index = noncanonical_signature.len() - 1;
    noncanonical_signature[flag_index] = 2;

    let decoded = TempoSignature::from_bytes(&noncanonical_signature)
        .expect("noncanonical pre_hash flag decodes leniently");
    assert_eq!(
        decoded.to_bytes(),
        canonical_signature,
        "noncanonical owner approval re-encodes to the canonical signature bytes"
    );
}

#[test]
fn multisig_signature_encodes_complete_config() {
    let config = current_config(indexed_owner(2));
    let account = Address::repeat_byte(0x11);
    let signatures = [valid_owner_signature_bytes()];
    let signature =
        MultisigSignature::try_new(account, config.clone(), vec![valid_owner_signature()]).unwrap();

    let mut encoded = Vec::new();
    signature.encode(&mut encoded);
    assert_eq!(
        encoded,
        encoded_multisig(
            account,
            &config,
            signatures
                .iter()
                .map(|signature| signature.to_vec())
                .collect(),
        )
    );

    let mut input = encoded.as_slice();
    let decoded = MultisigSignature::decode(&mut input).unwrap();
    assert!(input.is_empty());
    assert_eq!(decoded, signature);
}

#[test]
fn multisig_signature_rejects_initial_account_mismatch() {
    let owner = Address::from([0x11; 20]);
    let config = sorted_secp_config(&[(owner, 1)], 1);
    let expected_account = config.derive_account().unwrap();
    let wrong_account = Address::repeat_byte(0x99);

    let signature =
        MultisigSignature::try_new(wrong_account, config, vec![valid_owner_signature()]);

    let error = signature.unwrap_err();
    assert_eq!(
        error,
        MultisigSignatureError::InitialAccountMismatch {
            expected: expected_account,
            actual: wrong_account,
        }
    );
    assert_eq!(
        error.to_string(),
        format!(
            "initial multisig account mismatch: expected {expected_account}, actual {wrong_account}"
        )
    );
}

#[test]
fn tempo_signature_decode_bounds_multisig_nesting() {
    // Nesting up to MAX_MULTISIG_NESTING_DEPTH decodes structurally.
    let mut ok = vec![SIGNATURE_TYPE_MULTISIG];
    ok.extend(nested_multisig_encoding(MAX_MULTISIG_NESTING_DEPTH));
    assert!(
        TempoSignature::from_bytes(&ok).is_ok(),
        "nesting within the depth bound must decode"
    );

    // One level deeper exceeds the bound and is rejected at decode time.
    let mut too_deep = vec![SIGNATURE_TYPE_MULTISIG];
    too_deep.extend(nested_multisig_encoding(MAX_MULTISIG_NESTING_DEPTH + 1));
    assert!(
        TempoSignature::from_bytes(&too_deep).is_err(),
        "nesting past the depth bound must be rejected"
    );

    // A pathologically deep payload is rejected quickly instead of recursing into a stack
    // overflow during decoding.
    let mut pathological = vec![SIGNATURE_TYPE_MULTISIG];
    pathological.extend(nested_multisig_encoding(4096));
    assert!(TempoSignature::from_bytes(&pathological).is_err());
}

#[test]
fn multisig_signature_decode_rejects_invalid_config() {
    let invalid_config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: 0,
        owners: Vec::new(),
    };
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &invalid_config,
        vec![valid_owner_signature_bytes().to_vec()],
    );

    assert_multisig_decode_rejected(&encoded);
}

#[test]
fn multisig_config_decode_bounds_owner_count() {
    let config = MultisigConfig {
        salt: B256::ZERO,
        version: 0,
        threshold: MAX_MULTISIG_THRESHOLD,
        owners: (1..=MAX_MULTISIG_OWNERS as u16 + 1)
            .map(|index| MultisigOwner {
                owner: Address::from_word(B256::from(alloy_primitives::U256::from(index))),
                weight: 1,
            })
            .collect(),
    };
    let mut encoded = Vec::new();
    config.encode(&mut encoded);

    let mut input = encoded.as_slice();
    assert!(matches!(
        MultisigConfig::decode(&mut input),
        Err(alloy_rlp::Error::Custom("too many multisig owners"))
    ));
}

#[test]
fn multisig_signature_decode_bounds_approval_count() {
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &current_config(indexed_owner(2)),
        vec![valid_owner_signature_bytes().to_vec(); MAX_MULTISIG_SIGNATURES + 1],
    );

    let mut input = encoded.as_slice();
    assert!(matches!(
        MultisigSignature::decode(&mut input),
        Err(alloy_rlp::Error::Custom("too many multisig signatures"))
    ));
}

#[test]
fn multisig_signature_shape_rejects_oversized_owner_signature() {
    let signature = MultisigSignature::try_new(
        Address::repeat_byte(0x11),
        current_config(indexed_owner(2)),
        vec![TempoSignature::Primitive(PrimitiveSignature::WebAuthn(
            WebAuthnSignature {
                webauthn_data: Bytes::from(vec![0; MAX_WEBAUTHN_SIGNATURE_LENGTH + 1]),
                r: B256::ZERO,
                s: B256::ZERO,
                pub_key_x: B256::ZERO,
                pub_key_y: B256::ZERO,
            },
        ))],
    );

    assert_eq!(
        signature,
        Err(MultisigSignatureError::OwnerSignatureTooLarge)
    );
}

#[test]
fn multisig_signature_shape_allows_nested_signature_above_primitive_byte_cap() {
    let primitive = PrimitiveSignature::WebAuthn(WebAuthnSignature {
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
        webauthn_data: Bytes::from(vec![0; MAX_WEBAUTHN_SIGNATURE_LENGTH - 128]),
    });
    let nested = TempoSignature::Multisig(
        MultisigSignature::try_new(
            Address::repeat_byte(0x22),
            current_config(indexed_owner(3)),
            vec![
                TempoSignature::Primitive(primitive.clone()),
                TempoSignature::Primitive(primitive),
            ],
        )
        .unwrap(),
    );
    assert!(nested.encoded_length() > MAX_MULTISIG_OWNER_SIGNATURE_BYTES);

    let signature = MultisigSignature::try_new(
        Address::repeat_byte(0x11),
        current_config(Address::repeat_byte(0x22)),
        vec![nested],
    );

    assert!(signature.is_ok());
}

#[test]
fn multisig_signature_decode_rejects_oversized_owner_signature() {
    let encoded = encoded_multisig(
        Address::repeat_byte(0x11),
        &current_config(indexed_owner(2)),
        vec![vec![0xaa; MAX_MULTISIG_OWNER_SIGNATURE_BYTES + 1]],
    );
    assert_multisig_decode_rejected(&encoded);
}

#[test]
fn multisig_signature_roundtrips_complete_encoding() {
    let (signer, owner) = generate_secp256k1_keypair();
    let mut config = sorted_secp_config(&[(owner, 1)], 1);
    config.salt = B256::repeat_byte(0x33);
    let account = config.derive_account().unwrap();
    let signature_hash = B256::ZERO;
    let digest = multisig_digest(signature_hash, account, 0);
    let signatures = vec![sign_hash(&signer, &digest)];
    let signature =
        MultisigSignature::try_new(account, config.clone(), signatures.clone()).unwrap();
    let tempo_signature = TempoSignature::Multisig(signature.clone());

    let encoded = tempo_signature.to_bytes();
    assert_eq!(encoded[0], SIGNATURE_TYPE_MULTISIG);
    assert_eq!(
        &encoded[1..],
        encoded_multisig(
            account,
            &config,
            signatures
                .iter()
                .map(|signature| signature.to_bytes().to_vec())
                .collect(),
        )
    );
    let decoded = TempoSignature::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.as_multisig(), Some(&signature));
    assert_eq!(
        decoded.recover_signer(&signature_hash).unwrap(),
        signature.account()
    );
}

#[cfg(feature = "serde")]
#[test]
fn multisig_signature_serde_roundtrips_rlp_bytes() {
    let (signer, owner) = generate_secp256k1_keypair();
    let config = sorted_secp_config(&[(owner, 1)], 1);
    let account = config.derive_account().unwrap();
    let digest = multisig_digest(B256::ZERO, account, 0);
    let owner_signature = sign_hash(&signer, &digest);
    let signatures = vec![owner_signature];

    let signature = MultisigSignature::try_new(account, config, signatures).unwrap();
    let mut encoded = Vec::with_capacity(signature.length());
    signature.encode(&mut encoded);
    let json = serde_json::to_value(&signature).unwrap();
    assert_eq!(
        json,
        serde_json::to_value(Bytes::from(encoded.clone())).unwrap()
    );
    assert_eq!(
        serde_json::from_value::<MultisigSignature>(json.clone()).unwrap(),
        signature
    );
    assert_eq!(
        serde_json::from_value::<TempoSignature>(json).unwrap(),
        TempoSignature::Multisig(signature)
    );
}

#[cfg(feature = "serde")]
#[test]
fn multisig_signature_json_bytes_reject_malformed_shapes() {
    for encoded in malformed_multisig_encodings() {
        let json = serde_json::to_value(Bytes::from(encoded)).unwrap();
        assert!(serde_json::from_value::<TempoSignature>(json).is_err());
    }
}

#[cfg(feature = "serde")]
#[test]
fn multisig_signature_json_rejects_structured_form() {
    let json = serde_json::json!({
        "account": Address::repeat_byte(0x11),
        "signatures": [],
    });
    let error = serde_json::from_value::<TempoSignature>(json)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("did not match any variant") || error.contains("missing field"),
        "unexpected error: {error}"
    );
}

#[cfg(feature = "serde")]
#[test]
fn binary_multisig_deserializer_roundtrips_bytes() {
    let primitive = PrimitiveSignature::Secp256k1(alloy_primitives::Signature::test_signature());
    let signature = TempoSignature::Multisig(
        MultisigSignature::try_new(
            indexed_owner(2),
            current_config(indexed_owner(3)),
            vec![TempoSignature::Primitive(primitive)],
        )
        .unwrap(),
    );
    let signature = signature.as_multisig().unwrap();

    let mut encoded = Vec::new();
    signature.encode(&mut encoded);
    let decoded = MultisigSignature::deserialize(serde::de::value::BorrowedBytesDeserializer::<
        serde::de::value::Error,
    >::new(&encoded))
    .unwrap();

    assert_eq!(&decoded, signature);
}

#[cfg(feature = "serde")]
#[test]
fn binary_multisig_deserializer_bounds_shape_before_typed_recursion() {
    fn decode(bytes: &[u8]) -> Result<MultisigSignature, serde::de::value::Error> {
        MultisigSignature::deserialize(serde::de::value::BorrowedBytesDeserializer::new(bytes))
    }

    for encoded in malformed_multisig_encodings() {
        assert!(decode(&encoded).is_err());
    }
}

proptest! {
    #[test]
    fn proptest_multisig_signature_decode_encode_canonicalizes_accepted_raw_bytes(
        raw in prop_oneof![
            proptest::collection::vec(any::<u8>(), 0..256),
            (
                any::<Address>(),
                proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..128), 0..=MAX_MULTISIG_SIGNATURES),
            ).prop_map(|(account, signatures)| {
                encoded_multisig(account, &current_config(indexed_owner(2)), signatures)
            }),
        ],
    ) {
        let mut input = raw.as_slice();
        if let Ok(decoded) = MultisigSignature::decode(&mut input) {
            prop_assert!(input.is_empty());

            let mut reencoded = Vec::new();
            decoded.encode(&mut reencoded);

            let mut canonical_input = reencoded.as_slice();
            let canonical_decoded = MultisigSignature::decode(&mut canonical_input).unwrap();
            prop_assert!(canonical_input.is_empty());
            prop_assert_eq!(&canonical_decoded, &decoded);

            let mut canonical_reencoded = Vec::new();
            canonical_decoded.encode(&mut canonical_reencoded);
            prop_assert_eq!(canonical_reencoded, reencoded);
        }
    }
}
