#![no_main]

use libfuzzer_sys::fuzz_target;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha384};
use std::hint::black_box;
use tempo_nitro_attestation::{
    P384_FIXED_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE, P384Verifier, SHA384_SIZE, Sha384Hasher,
    parse_attestation, verify_parsed,
};
use webpki::{EndEntityCert, anchor_from_trusted_cert};
use x509_parser::parse_x509_certificate;

/// Cryptography is deliberately accepted here so the target can isolate the consensus parser and
/// X.509 profile. Public-key shape and all non-cryptographic certificate rules remain enforced by
/// `verify_parsed` before an input is compared with the independent parser oracles.
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

#[derive(Clone, Copy)]
struct OracleResult {
    x509_parser: bool,
    rustls_webpki: bool,
}

fn parse_with_oracles(der: &[u8]) -> OracleResult {
    let x509_parser = matches!(
        parse_x509_certificate(der),
        Ok((remaining, _)) if remaining.is_empty()
    );

    let certificate = CertificateDer::from(der);
    let rustls_webpki = EndEntityCert::try_from(&certificate).is_ok();

    black_box(OracleResult {
        x509_parser,
        rustls_webpki,
    })
}

fuzz_target!(|document: &[u8]| {
    let Ok(parsed) = parse_attestation(document) else {
        return;
    };

    // Exercise both independent DER parsers for every structurally valid attestation, including
    // inputs whose certificate bytes are intentionally invalid.
    let leaf_oracles = parse_with_oracles(&parsed.certificate);
    let bundle_oracles: Vec<_> = parsed
        .cabundle
        .iter()
        .map(|certificate| parse_with_oracles(certificate))
        .collect();

    let root_der = parsed
        .cabundle
        .first()
        .expect("the structural parser requires a non-empty CA bundle");
    let root_certificate = CertificateDer::from(root_der.as_slice());
    let root_anchor_parsed = black_box(anchor_from_trusted_cert(&root_certificate).is_ok());

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
            leaf_oracles.x509_parser,
            "Tempo accepted a leaf certificate rejected by x509-parser"
        );
        assert!(
            leaf_oracles.rustls_webpki,
            "Tempo accepted a leaf certificate rejected by rustls-webpki"
        );
        assert!(
            bundle_oracles.iter().all(|result| result.x509_parser),
            "Tempo accepted a CA certificate rejected by x509-parser"
        );
        assert!(
            bundle_oracles.iter().all(|result| result.rustls_webpki),
            "Tempo accepted a CA certificate rejected by rustls-webpki"
        );
        assert!(
            root_anchor_parsed,
            "Tempo accepted a root certificate rejected by rustls-webpki"
        );
    }
});
