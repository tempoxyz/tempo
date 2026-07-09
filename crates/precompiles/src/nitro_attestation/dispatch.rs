use super::{BASE_GAS_COST, NitroAttestationVerifier};
use crate::{
    IntoPrecompileResult, Precompile, charge_input_cost, missing_selector_result,
    selector_from_calldata, unknown_selector_result,
};
use alloy::{primitives::Address, sol_types::SolCall};
use revm::precompile::{PrecompileHalt, PrecompileResult};
use tempo_contracts::precompiles::{INitroAttestationVerifier, NitroAttestationError};
use tempo_nitro_attestation::MAX_DOCUMENT_SIZE;

/// selector + offset + length + a maximally sized, word-aligned document.
const MAX_CALLDATA_LEN: usize = 4 + 32 + 32 + MAX_DOCUMENT_SIZE;

impl Precompile for NitroAttestationVerifier {
    fn call(&mut self, calldata: &[u8], _msg_sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }

        let Some(selector) = selector_from_calldata(calldata) else {
            return missing_selector_result();
        };
        if selector != INitroAttestationVerifier::verifyAttestationCall::SELECTOR {
            return unknown_selector_result(calldata);
        }

        // Charge the full parsing/hash cost before inspecting ABI or CBOR lengths. This makes
        // oversized and malformed verify calls obey the same first-stage gas rule.
        if self.storage.deduct_gas(BASE_GAS_COST).is_err() {
            return Ok(self.storage.halt_output(PrecompileHalt::OutOfGas));
        }

        if calldata.len() > MAX_CALLDATA_LEN {
            return Ok(self
                .storage
                .abi_revert(NitroAttestationError::invalid_format()));
        }

        let call = match INitroAttestationVerifier::verifyAttestationCall::abi_decode(calldata) {
            Ok(call) => call,
            Err(_) => {
                return Ok(self
                    .storage
                    .abi_revert(NitroAttestationError::invalid_format()));
            }
        };
        let result = self.verify_attestation(call.document);
        result.into_precompile_result(
            self.storage.gas_used(),
            self.storage.reservoir(),
            |attestation| {
                INitroAttestationVerifier::verifyAttestationCall::abi_encode_returns(&attestation)
                    .into()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Bytes, U256},
        sol_types::{SolCall, SolInterface},
    };
    use base64::Engine;
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{
        INitroAttestationVerifier,
        INitroAttestationVerifier::INitroAttestationVerifierCalls as NitroCalls,
        NitroAttestationError,
    };
    use tempo_nitro_attestation::parse_attestation;
    use x509_cert::{
        Certificate,
        der::{Decode, Encode},
    };

    const FIXTURE_TIME: u64 = 1_767_472_867;
    const P384_HALF_ORDER: [u8; 48] = alloy::primitives::hex!(
        "7fffffffffffffffffffffffffffffffffffffffffffffffe3b1a6c0fa1b96efac0d06d9245853bd76760cb5666294b9"
    );

    fn production_fixture() -> Vec<u8> {
        let encoded: String = include_str!("testdata/aws_attestation_2026_01_03.b64")
            .split_whitespace()
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("valid fixture base64")
    }

    fn production_storage() -> HashMapStorageProvider {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        storage.set_timestamp(U256::from(FIXTURE_TIME));
        storage
    }

    fn call_production_document_at(document: &[u8], timestamp: u64) -> PrecompileResult {
        let mut storage = production_storage();
        storage.set_timestamp(U256::from(timestamp));
        StorageCtx::enter(&mut storage, || {
            NitroAttestationVerifier::new().call(
                &INitroAttestationVerifier::verifyAttestationCall {
                    document: Bytes::copy_from_slice(document),
                }
                .abi_encode(),
                Address::ZERO,
            )
        })
    }

    fn replace_unique(haystack: &mut [u8], needle: &[u8], replacement: &[u8]) {
        assert_eq!(
            needle.len(),
            replacement.len(),
            "replacement must preserve DER length"
        );
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

    #[test]
    fn selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let mut verifier = NitroAttestationVerifier::new();
            let unsupported = check_selector_coverage(
                &mut verifier,
                NitroCalls::SELECTORS,
                "INitroAttestationVerifier",
                NitroCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
        });
        Ok(())
    }

    #[test]
    fn verifies_production_attestation_and_accepts_high_s() -> eyre::Result<()> {
        let document = production_fixture();
        let parsed = parse_attestation(&document).expect("production fixture parses");
        assert!(
            parsed.signature[48..] > P384_HALF_ORDER[..],
            "fixture must retain a high-s document signature"
        );
        let mut storage = production_storage();
        StorageCtx::enter(&mut storage, || {
            let calldata = INitroAttestationVerifier::verifyAttestationCall {
                document: document.into(),
            }
            .abi_encode();
            let output = NitroAttestationVerifier::new().call(&calldata, Address::ZERO)?;
            let result = INitroAttestationVerifier::verifyAttestationCall::abi_decode_returns(
                &output.bytes,
            )?;

            let expected_pcrs = [
                alloy::primitives::hex!(
                    "4b8d4cf2a99e05ce1b5bddaf9d21cb446eb0e606c5bebd1ebf02b473a22165f7b68b0bb0d1ac5a90f0311e493522cfab"
                ),
                alloy::primitives::hex!(
                    "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa"
                ),
                alloy::primitives::hex!(
                    "16efcc1d6952c5b9737eb2ab1751a08412835c5125818bfb55f6367cb3cdca49b13d2a5b6d771de9db1578242e328c6d"
                ),
                [0; 48],
                alloy::primitives::hex!(
                    "245617239e18ae8eb5150c2be45200db1e6b1e483d94c81d8386171eaad6cf641a1c90f1571f185426c82f77783feb37"
                ),
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
                [0; 48],
            ];
            assert_eq!(result.moduleId, "i-0368fa67e156d6d23-enc019b8596b1a9dad6");
            assert_eq!(result.timestamp, 1_767_472_867_402);
            assert_eq!(result.pcrs.len(), expected_pcrs.len());
            for (expected_index, (actual, expected)) in
                result.pcrs.iter().zip(expected_pcrs).enumerate()
            {
                assert_eq!(usize::from(actual.index), expected_index);
                assert_eq!(actual.value.as_ref(), expected);
            }
            assert!(result.publicKey.is_empty());
            assert_eq!(
                result.userData.as_ref(),
                alloy::primitives::hex!("69553adc61d6e9fcdecbe1ea49bb2b52a60238e0")
            );
            assert!(result.nonce.is_empty());
            assert_eq!(
                result.leafCertHash,
                alloy::primitives::b256!(
                    "37dbbf810aba51d3423c84f6999b6bd0fcf008d9af094ae419134647bd41aa07"
                )
            );
            Ok(())
        })
    }

    #[test]
    fn leaf_certificate_validity_boundaries_are_inclusive() -> eyre::Result<()> {
        let document = production_fixture();
        let parsed = parse_attestation(&document).expect("production fixture parses");
        let leaf = Certificate::from_der(&parsed.certificate).expect("leaf certificate parses");
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
            let output = call_production_document_at(&document, timestamp)?;
            assert!(
                output.is_success(),
                "certificate boundary {timestamp} must be inclusive"
            );
        }
        for timestamp in [not_before - 1, not_after + 1] {
            let result = call_production_document_at(&document, timestamp);
            expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
        }
        Ok(())
    }

    #[test]
    fn rejects_leaf_with_wrong_curve() {
        const P384_OID_DER: [u8; 7] = alloy::primitives::hex!("06052b81040022");
        const P521_OID_DER: [u8; 7] = alloy::primitives::hex!("06052b81040023");

        let mut document = production_fixture();
        mutate_leaf_certificate(&mut document, |leaf| {
            replace_unique(leaf, &P384_OID_DER, &P521_OID_DER);
        });
        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
    }

    #[test]
    fn rejects_leaf_with_compressed_point_marker() {
        // Keep the BIT STRING and certificate lengths unchanged while replacing SEC1's
        // uncompressed marker (04) with a compressed marker (02).
        const UNCOMPRESSED_KEY_HEADER: [u8; 4] = alloy::primitives::hex!("03620004");
        const COMPRESSED_KEY_HEADER: [u8; 4] = alloy::primitives::hex!("03620002");

        let mut document = production_fixture();
        mutate_leaf_certificate(&mut document, |leaf| {
            replace_unique(leaf, &UNCOMPRESSED_KEY_HEADER, &COMPRESSED_KEY_HEADER);
        });
        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
    }

    #[test]
    fn rejects_broken_leaf_issuer_linkage() {
        let mut document = production_fixture();
        mutate_leaf_certificate(&mut document, |leaf| {
            let certificate = Certificate::from_der(leaf).expect("leaf certificate parses");
            let issuer = certificate
                .tbs_certificate
                .issuer
                .to_der()
                .expect("issuer encodes as DER");
            let mut changed_issuer = issuer.clone();
            let character = changed_issuer
                .iter_mut()
                .rfind(|byte| byte.is_ascii_lowercase())
                .expect("issuer contains an ASCII name");
            *character = if *character == b'z' {
                b'y'
            } else {
                *character + 1
            };
            replace_unique(leaf, &issuer, &changed_issuer);
        });
        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
    }

    #[test]
    fn rejects_unknown_critical_leaf_extension() {
        const CRITICAL_BASIC_CONSTRAINTS: [u8; 8] = alloy::primitives::hex!("0603551d130101ff");
        const CRITICAL_UNKNOWN_EXTENSION: [u8; 8] = alloy::primitives::hex!("0603551d7f0101ff");

        let mut document = production_fixture();
        mutate_leaf_certificate(&mut document, |leaf| {
            replace_unique(
                leaf,
                &CRITICAL_BASIC_CONSTRAINTS,
                &CRITICAL_UNKNOWN_EXTENSION,
            );
        });
        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
    }

    #[test]
    fn rejects_wrong_root_as_invalid_certificate() {
        let mut document = production_fixture();
        let root = parse_attestation(&document)
            .expect("production fixture parses")
            .cabundle[0]
            .clone();
        let mut wrong_root = root.clone();
        *wrong_root.last_mut().expect("root certificate is nonempty") ^= 1;
        replace_unique(&mut document, &root, &wrong_root);

        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_certificate());
    }

    #[test]
    fn rejects_corrupt_document_signature() -> eyre::Result<()> {
        let mut document = production_fixture();
        let mut storage = production_storage();
        *document.last_mut().expect("nonempty fixture") ^= 1;
        StorageCtx::enter(&mut storage, || {
            let calldata = INitroAttestationVerifier::verifyAttestationCall {
                document: document.into(),
            }
            .abi_encode();
            let result = NitroAttestationVerifier::new().call(&calldata, Address::ZERO);
            expect_precompile_revert(&result, NitroAttestationError::invalid_signature());
            Ok(())
        })
    }

    #[test]
    fn rejects_corrupt_leaf_certificate_signature() {
        let mut document = production_fixture();
        mutate_leaf_certificate(&mut document, |leaf| {
            *leaf.last_mut().expect("leaf certificate is nonempty") ^= 1;
        });
        let result = call_production_document_at(&document, FIXTURE_TIME);
        expect_precompile_revert(&result, NitroAttestationError::invalid_signature());
    }

    #[test]
    fn rejects_oversized_document_before_decoding() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let calldata = INitroAttestationVerifier::verifyAttestationCall {
                document: vec![0u8; MAX_DOCUMENT_SIZE + 1].into(),
            }
            .abi_encode();
            let result = NitroAttestationVerifier::new().call(&calldata, Address::ZERO);
            expect_precompile_revert(&result, NitroAttestationError::invalid_format());
            Ok(())
        })
    }

    #[test]
    fn malformed_abi_reverts_with_invalid_format() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T9);
        StorageCtx::enter(&mut storage, || {
            let mut calldata = INitroAttestationVerifier::verifyAttestationCall::SELECTOR.to_vec();
            calldata.extend_from_slice(&[0u8; 32]); // zero offset, not a valid dynamic argument
            let result = NitroAttestationVerifier::new().call(&calldata, Address::ZERO);
            expect_precompile_revert(&result, NitroAttestationError::invalid_format());
            Ok(())
        })
    }

    #[test]
    fn selectors_match_tip() {
        assert_eq!(
            INitroAttestationVerifier::verifyAttestationCall::SELECTOR,
            [0x76, 0x9d, 0x87, 0xe7]
        );
        assert_eq!(
            NitroAttestationError::invalid_format().selector(),
            [0x25, 0x7a, 0xa2, 0x3b]
        );
        assert_eq!(
            NitroAttestationError::invalid_certificate().selector(),
            [0x1d, 0x39, 0xf9, 0x46]
        );
        assert_eq!(
            NitroAttestationError::invalid_signature().selector(),
            [0x8b, 0xaa, 0x57, 0x9f]
        );
    }
}
