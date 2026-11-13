#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha384};
use tempo_nitro_attestation::{
    P384_FIXED_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE, P384Verifier, SHA384_SIZE, Sha384Hasher,
    parse_attestation, verify_parsed,
};
use x509_parser::parse_x509_certificate;

/// Cryptography is deliberately accepted here so the target can isolate the consensus parser and
/// X.509 profile. Public-key shape and all non-cryptographic certificate rules remain enforced by
/// `verify_parsed` before an input is compared with the `x509-parser` acceptance oracle.
struct ParserOnlyBackend;

impl P384Verifier for ParserOnlyBackend {
    fn validate_public_key(&self, _public_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> bool {
        true
    }

    fn verify_der(
        &self,
        _public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        _digest: &[u8; SHA384_SIZE],
        _signature_der: &[u8],
    ) -> bool {
        true
    }

    fn verify_fixed(
        &self,
        _public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        _digest: &[u8; SHA384_SIZE],
        _signature: &[u8; P384_FIXED_SIGNATURE_SIZE],
    ) -> bool {
        true
    }
}

impl Sha384Hasher for ParserOnlyBackend {
    fn sha384(&self, input: &[u8]) -> [u8; SHA384_SIZE] {
        Sha384::digest(input).into()
    }
}

fn parse_with_x509_parser(der: &[u8]) -> bool {
    matches!(
        parse_x509_certificate(der),
        Ok((remaining, _)) if remaining.is_empty()
    )
}

fuzz_target!(|document: &[u8]| {
    let Ok(parsed) = parse_attestation(document) else {
        return;
    };

    // Exercise the independent DER parser for every structurally valid attestation, including
    // inputs whose certificate bytes are intentionally invalid.
    let leaf_accepted_by_x509_parser = parse_with_x509_parser(&parsed.certificate);
    let bundle_accepted_by_x509_parser: Vec<_> = parsed
        .cabundle
        .iter()
        .map(|certificate| parse_with_x509_parser(certificate))
        .collect();

    let root_der = parsed
        .cabundle
        .first()
        .expect("the structural parser requires a non-empty CA bundle");

    // The attestation timestamp is the best available validity-time seed and keeps the known-good
    // production corpus on the successful path. Signatures are accepted by ParserOnlyBackend so a
    // success here means Tempo accepted the complete non-cryptographic X.509 profile.
    let block_timestamp = parsed.timestamp / 1_000;
    if verify_parsed(
        parsed.clone(),
        block_timestamp,
        root_der,
        &ParserOnlyBackend,
    )
    .is_ok()
    {
        assert!(
            leaf_accepted_by_x509_parser,
            "Tempo accepted a leaf certificate rejected by x509-parser"
        );
        assert!(
            bundle_accepted_by_x509_parser
                .iter()
                .all(|accepted| *accepted),
            "Tempo accepted a CA certificate rejected by x509-parser"
        );
    }
});
