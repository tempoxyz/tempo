//! Gas-metered AWS Nitro attestation verification for the Zone verifier.

use crate::storage::StorageCtx;
use tempo_nitro_attestation::NitroAttestation;
#[cfg(test)]
use tempo_nitro_attestation::{MAX_DOCUMENT_SIZE, parse_attestation};
pub(super) use tempo_zone_verifier::AWS_NITRO_ROOT_DER;
#[cfg(test)]
use tempo_zone_verifier::{BASE_GAS, SIGNATURE_GAS};

pub(super) fn verify_attestation_with_root(
    document: &[u8],
    block_timestamp: u64,
    root_der: &[u8],
) -> crate::error::Result<Option<NitroAttestation>> {
    tempo_zone_verifier::verify_attestation_with_root(document, block_timestamp, root_der, |gas| {
        StorageCtx.deduct_gas(gas)
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::storage::{StorageCtx, hashmap::HashMapStorageProvider};
    use base64::Engine;
    use minicbor::Encoder;
    use p384::ecdsa::{DerSignature, Signature, SigningKey, signature::Signer};
    use std::{
        str::FromStr,
        time::{Duration, UNIX_EPOCH},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use x509_cert::{
        Certificate,
        builder::{Builder, CertificateBuilder, Profile},
        der::{Decode, Encode},
        name::Name,
        serial_number::SerialNumber,
        spki::SubjectPublicKeyInfoOwned,
        time::{Time, Validity},
    };

    pub(in crate::zone_verifier) const BLOCK_TIMESTAMP: u64 = 1_800_000_000;
    const PRODUCTION_FIXTURE_TIME: u64 = 1_767_472_867;
    const P384_HALF_ORDER: [u8; 48] = alloy::primitives::hex!(
        "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9"
    );

    fn production_fixture() -> Vec<u8> {
        let encoded: String =
            include_str!("../../../nitro-attestation/testdata/aws_attestation_2026_01_03.b64")
                .split_whitespace()
                .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid fixture base64")
    }

    fn verify_production_document_at(document: &[u8], timestamp: u64) -> Option<NitroAttestation> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            verify_attestation_with_root(document, timestamp, AWS_NITRO_ROOT_DER).unwrap()
        })
    }

    fn replace_unique(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) {
        assert_eq!(needle.len(), replacement.len());
        let offsets = haystack
            .windows(needle.len())
            .enumerate()
            .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1, "mutation target must occur exactly once");
        haystack[offsets[0]..offsets[0] + needle.len()].copy_from_slice(replacement);
    }

    fn mutate_leaf_certificate(document: &mut [u8], mutate: impl FnOnce(&mut Vec<u8>)) {
        let original = parse_attestation(document)
            .expect("production fixture parses")
            .certificate;
        let mut modified = original.clone();
        mutate(&mut modified);
        Certificate::from_der(&modified).expect("mutation must preserve certificate DER");
        replace_unique(document, &original, &modified);
    }

    fn signing_key(byte: u8) -> SigningKey {
        SigningKey::from_slice(&[byte; 48]).unwrap()
    }

    fn validity() -> Validity {
        Validity {
            not_before: Time::try_from(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).unwrap(),
            not_after: Time::try_from(UNIX_EPOCH + Duration::from_secs(1_900_000_000)).unwrap(),
        }
    }

    fn build_certificate(
        profile: Profile,
        serial: u32,
        subject: Name,
        subject_key: &SigningKey,
        issuer_key: &SigningKey,
    ) -> Vec<u8> {
        let spki = SubjectPublicKeyInfoOwned::from_key(*subject_key.verifying_key()).unwrap();
        CertificateBuilder::new(
            profile,
            SerialNumber::from(serial),
            validity(),
            subject,
            spki,
            issuer_key,
        )
        .unwrap()
        .build::<DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
    }

    pub(in crate::zone_verifier) fn fixture(
        user_data: &[u8; 32],
    ) -> (Vec<u8>, Vec<u8>, [[u8; 48]; 3]) {
        fixture_at(user_data, BLOCK_TIMESTAMP * 1_000)
    }

    pub(in crate::zone_verifier) fn fixture_at(
        user_data: &[u8; 32],
        attestation_timestamp: u64,
    ) -> (Vec<u8>, Vec<u8>, [[u8; 48]; 3]) {
        let root_key = signing_key(1);
        let intermediate_key = signing_key(2);
        let leaf_key = signing_key(3);
        let root_name = Name::from_str("CN=Test Nitro Root,O=Tempo,C=US").unwrap();
        let intermediate_name = Name::from_str("CN=Test Nitro Intermediate,O=Tempo,C=US").unwrap();
        let leaf_name = Name::from_str("CN=Test Nitro Leaf,O=Tempo,C=US").unwrap();
        let root = build_certificate(Profile::Root, 1, root_name.clone(), &root_key, &root_key);
        let intermediate = build_certificate(
            Profile::SubCA {
                issuer: root_name,
                path_len_constraint: Some(0),
            },
            2,
            intermediate_name.clone(),
            &intermediate_key,
            &root_key,
        );
        let leaf = build_certificate(
            Profile::Leaf {
                issuer: intermediate_name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            3,
            leaf_name,
            &leaf_key,
            &intermediate_key,
        );
        let pcrs = [[0x10; 48], [0x11; 48], [0x12; 48]];

        let mut payload = Encoder::new(Vec::new());
        payload.map(9).unwrap();
        payload
            .str("module_id")
            .unwrap()
            .str("test-module")
            .unwrap();
        payload.str("digest").unwrap().str("SHA384").unwrap();
        payload
            .str("timestamp")
            .unwrap()
            .u64(attestation_timestamp)
            .unwrap();
        payload.str("pcrs").unwrap().map(3).unwrap();
        for (index, pcr) in pcrs.iter().enumerate() {
            payload.u8(index as u8).unwrap().bytes(pcr).unwrap();
        }
        payload.str("certificate").unwrap().bytes(&leaf).unwrap();
        payload.str("cabundle").unwrap().array(2).unwrap();
        payload.bytes(&root).unwrap().bytes(&intermediate).unwrap();
        payload.str("public_key").unwrap().null().unwrap();
        payload.str("user_data").unwrap().bytes(user_data).unwrap();
        payload.str("nonce").unwrap().null().unwrap();
        let payload = payload.into_writer();

        let mut protected = Encoder::new(Vec::new());
        protected.map(1).unwrap().i8(1).unwrap().i8(-35).unwrap();
        let protected = protected.into_writer();
        let mut structure = Encoder::new(Vec::new());
        structure.array(4).unwrap();
        structure.str("Signature1").unwrap();
        structure.bytes(&protected).unwrap();
        structure.bytes(&[]).unwrap();
        structure.bytes(&payload).unwrap();
        let signature: Signature = leaf_key.sign(&structure.into_writer());

        let mut cose = Encoder::new(Vec::new());
        cose.tag(minicbor::data::Tag::new(18)).unwrap();
        cose.array(4).unwrap();
        cose.bytes(&protected).unwrap();
        cose.map(0).unwrap();
        cose.bytes(&payload).unwrap();
        cose.bytes(signature.to_bytes().as_slice()).unwrap();
        (cose.into_writer(), root, pcrs)
    }

    #[test]
    fn verifies_production_attestation_and_accepts_high_s() {
        let document = production_fixture();
        let parsed = parse_attestation(&document).expect("production fixture parses");
        assert!(parsed.signature[48..] > P384_HALF_ORDER[..]);
        assert_eq!(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &parsed.certificate).as_ref(),
            alloy::primitives::hex!(
                "37dbbf810aba51d3423c84f6999b6bd0fcf008d9af094ae419134647bd41aa07"
            )
        );

        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T13);
        StorageCtx::enter(&mut storage, || {
            let verified = verify_attestation_with_root(
                &document,
                PRODUCTION_FIXTURE_TIME,
                AWS_NITRO_ROOT_DER,
            )
            .unwrap()
            .unwrap();
            assert_eq!(verified.timestamp, 1_767_472_867_402);
            assert_eq!(verified.pcrs.len(), 16);
            assert!(verified.public_key.is_empty());
            assert!(verified.nonce.is_empty());
        });
    }

    #[test]
    fn pinned_root_has_expected_sha256() {
        assert_eq!(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, AWS_NITRO_ROOT_DER).as_ref(),
            alloy::primitives::hex!(
                "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
            )
        );
    }

    #[test]
    fn production_leaf_validity_boundaries_are_inclusive() {
        let document = production_fixture();
        let parsed = parse_attestation(&document).unwrap();
        let leaf = Certificate::from_der(&parsed.certificate).unwrap();
        let not_before = leaf
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs();
        let not_after = leaf
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs();

        for timestamp in [not_before, not_after] {
            assert!(verify_production_document_at(&document, timestamp).is_some());
        }
        for timestamp in [not_before - 1, not_after + 1] {
            assert!(verify_production_document_at(&document, timestamp).is_none());
        }
    }

    #[test]
    fn rejects_wrong_curve_and_compressed_leaf_key() {
        const P384_OID_DER: [u8; 7] = alloy::primitives::hex!("06052b81040022");
        const P521_OID_DER: [u8; 7] = alloy::primitives::hex!("06052b81040023");
        const UNCOMPRESSED_KEY_HEADER: [u8; 4] = alloy::primitives::hex!("03620004");
        const COMPRESSED_KEY_HEADER: [u8; 4] = alloy::primitives::hex!("03620002");

        for (needle, replacement) in [
            (P384_OID_DER.as_slice(), P521_OID_DER.as_slice()),
            (
                UNCOMPRESSED_KEY_HEADER.as_slice(),
                COMPRESSED_KEY_HEADER.as_slice(),
            ),
        ] {
            let mut document = production_fixture();
            mutate_leaf_certificate(&mut document, |leaf| {
                replace_unique(leaf, needle, replacement);
            });
            assert!(verify_production_document_at(&document, PRODUCTION_FIXTURE_TIME).is_none());
        }
    }

    #[test]
    fn rejects_broken_issuer_and_unknown_critical_extension() {
        const CRITICAL_BASIC_CONSTRAINTS: [u8; 8] = alloy::primitives::hex!("0603551d130101ff");
        const CRITICAL_UNKNOWN_EXTENSION: [u8; 8] = alloy::primitives::hex!("0603551d7f0101ff");

        let mut broken_issuer = production_fixture();
        mutate_leaf_certificate(&mut broken_issuer, |leaf| {
            let certificate = Certificate::from_der(leaf).unwrap();
            let issuer = certificate.tbs_certificate.issuer.to_der().unwrap();
            let mut changed = issuer.clone();
            let character = changed
                .iter_mut()
                .rfind(|byte| byte.is_ascii_lowercase())
                .unwrap();
            *character = if *character == b'z' {
                b'y'
            } else {
                *character + 1
            };
            replace_unique(leaf, &issuer, &changed);
        });
        assert!(verify_production_document_at(&broken_issuer, PRODUCTION_FIXTURE_TIME).is_none());

        let mut unknown_critical = production_fixture();
        mutate_leaf_certificate(&mut unknown_critical, |leaf| {
            replace_unique(
                leaf,
                &CRITICAL_BASIC_CONSTRAINTS,
                &CRITICAL_UNKNOWN_EXTENSION,
            );
        });
        assert!(
            verify_production_document_at(&unknown_critical, PRODUCTION_FIXTURE_TIME).is_none()
        );
    }

    #[test]
    fn rejects_wrong_root_and_corrupt_signatures() {
        let mut wrong_root = production_fixture();
        let root = parse_attestation(&wrong_root).unwrap().cabundle[0].clone();
        let mut replacement = root.clone();
        *replacement.last_mut().unwrap() ^= 1;
        replace_unique(&mut wrong_root, &root, &replacement);
        assert!(verify_production_document_at(&wrong_root, PRODUCTION_FIXTURE_TIME).is_none());

        let mut corrupt_document = production_fixture();
        *corrupt_document.last_mut().unwrap() ^= 1;
        assert!(
            verify_production_document_at(&corrupt_document, PRODUCTION_FIXTURE_TIME).is_none()
        );

        let mut corrupt_leaf = production_fixture();
        mutate_leaf_certificate(&mut corrupt_leaf, |leaf| {
            *leaf.last_mut().unwrap() ^= 1;
        });
        assert!(verify_production_document_at(&corrupt_leaf, PRODUCTION_FIXTURE_TIME).is_none());
    }
}
