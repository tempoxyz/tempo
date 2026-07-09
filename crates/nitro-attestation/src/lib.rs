//! Consensus-critical AWS Nitro Enclave attestation validation.
//!
//! This crate deliberately contains no chain or EVM integration. Callers can parse first, charge
//! gas from [`ParsedAttestation::signature_count`], and only then call [`verify_parsed`].

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod cbor;
mod error;
mod x509;

use alloc::{string::String, vec::Vec};
use sha2::{Digest, Sha256};

pub use error::{CertificateError, Error, ErrorCategory, FormatError, SignatureError};

/// Maximum accepted size of the complete COSE_Sign1 document.
pub const MAX_DOCUMENT_SIZE: usize = 24_576;
/// Maximum accepted size of the signed CBOR payload.
pub const MAX_PAYLOAD_SIZE: usize = 16_384;
/// Maximum number of PCR entries.
pub const MAX_PCRS: usize = 32;
/// Maximum number of certificates in `cabundle`, including the root.
pub const MAX_CA_BUNDLE: usize = 32;
/// Maximum CBOR nesting depth.
pub const MAX_CBOR_DEPTH: usize = 16;
/// Size of an uncompressed SEC1 P-384 public key.
pub const P384_PUBLIC_KEY_SIZE: usize = 97;
/// Size of a fixed-width ES384 signature (`r || s`).
pub const P384_FIXED_SIGNATURE_SIZE: usize = 96;
/// Size of a SHA-384 digest.
pub const SHA384_SIZE: usize = 48;

/// One PCR value returned by the attestation document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pcr {
    /// PCR index in `[0, 32)`.
    pub index: u8,
    /// Signed PCR bytes (32, 48, or 64 bytes).
    pub value: Vec<u8>,
}

/// A structurally valid Nitro attestation, before X.509 or signature validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedAttestation {
    /// Exact contents of the COSE protected-header byte string.
    pub protected: Vec<u8>,
    /// Exact signed CBOR payload bytes.
    pub payload: Vec<u8>,
    /// Fixed-width COSE signature (`r || s`).
    pub signature: [u8; P384_FIXED_SIGNATURE_SIZE],
    /// Issuing Nitro hypervisor module ID.
    pub module_id: String,
    /// Document timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// PCR entries, sorted by ascending index.
    pub pcrs: Vec<Pcr>,
    /// DER-encoded leaf signing certificate.
    pub certificate: Vec<u8>,
    /// DER-encoded chain ordered root first, closest intermediate last.
    pub cabundle: Vec<Vec<u8>>,
    /// Optional enclave public key. Empty when absent or CBOR null.
    pub public_key: Vec<u8>,
    /// Optional user data. Empty when absent, CBOR null, or present with zero length.
    pub user_data: Vec<u8>,
    /// Optional nonce. Empty when absent, CBOR null, or present with zero length.
    pub nonce: Vec<u8>,
}

impl ParsedAttestation {
    /// Number of P-384 verifications required by TIP-1090.
    ///
    /// The root is pinned and is not self-verified. Every other certificate plus the COSE
    /// document is verified, giving `cabundle.len() + 1` operations.
    pub fn signature_count(&self) -> usize {
        self.cabundle.len() + 1
    }
}

/// Validated fields returned to an onchain caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NitroAttestation {
    /// Issuing Nitro hypervisor module ID.
    pub module_id: String,
    /// Document timestamp in milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// PCR entries, sorted by ascending index.
    pub pcrs: Vec<Pcr>,
    /// Optional enclave public key. Empty when absent or CBOR null.
    pub public_key: Vec<u8>,
    /// Optional user data. Empty when absent, CBOR null, or present with zero length.
    pub user_data: Vec<u8>,
    /// Optional nonce. Empty when absent, CBOR null, or present with zero length.
    pub nonce: Vec<u8>,
    /// SHA-256 of the exact DER-encoded leaf certificate.
    pub leaf_cert_hash: [u8; 32],
}

/// Backend used for P-384 public-key and signature operations.
///
/// Inputs to the verification methods are already SHA-384 digests. Backends must accept both
/// low- and high-s signatures. `verify_der` receives an ASN.1 DER ECDSA signature from an X.509
/// certificate; `verify_fixed` receives a 96-byte `r || s` COSE signature.
pub trait P384Verifier {
    /// Checks that an uncompressed SEC1 key encodes a non-infinite point on P-384.
    fn validate_public_key(&self, public_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> bool;

    /// Verifies a DER-encoded ECDSA signature against a SHA-384 digest.
    fn verify_der(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature_der: &[u8],
    ) -> bool;

    /// Verifies a fixed-width `r || s` ECDSA signature against a SHA-384 digest.
    fn verify_fixed(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature: &[u8; P384_FIXED_SIGNATURE_SIZE],
    ) -> bool;
}

/// Backend used for consensus-critical SHA-384 hashing.
pub trait Sha384Hasher {
    /// Hashes `input` and returns its 48-byte SHA-384 digest.
    fn sha384(&self, input: &[u8]) -> [u8; SHA384_SIZE];
}

/// Parses and structurally validates a COSE_Sign1 Nitro attestation document.
pub fn parse_attestation(document: &[u8]) -> Result<ParsedAttestation, Error> {
    cbor::parse_attestation(document)
}

/// Validates a parsed attestation's certificate chain and all signatures.
///
/// `block_timestamp` is in seconds since the Unix epoch. `pinned_root_der` is compared byte for
/// byte with `cabundle[0]` before any certificate signature is checked.
pub fn verify_parsed<V: P384Verifier + Sha384Hasher>(
    parsed: ParsedAttestation,
    block_timestamp: u64,
    pinned_root_der: &[u8],
    verifier: &V,
) -> Result<NitroAttestation, Error> {
    let leaf_public_key =
        x509::validate_chain(&parsed, block_timestamp, pinned_root_der, verifier)?;

    let sig_structure = cbor::encode_sig_structure(&parsed.protected, &parsed.payload)?;
    let digest = verifier.sha384(&sig_structure);
    if !verifier.verify_fixed(&leaf_public_key, &digest, &parsed.signature) {
        return Err(SignatureError::Document.into());
    }

    let leaf_cert_hash: [u8; 32] = Sha256::digest(&parsed.certificate).into();
    Ok(NitroAttestation {
        module_id: parsed.module_id,
        timestamp: parsed.timestamp,
        pcrs: parsed.pcrs,
        public_key: parsed.public_key,
        user_data: parsed.user_data,
        nonce: parsed.nonce,
        leaf_cert_hash,
    })
}

/// Parses and fully verifies a Nitro attestation in one call.
///
/// Gas-metered callers should instead use [`parse_attestation`] and [`verify_parsed`] separately,
/// charging for [`ParsedAttestation::signature_count`] before calling the latter.
pub fn verify_attestation<V: P384Verifier + Sha384Hasher>(
    document: &[u8],
    block_timestamp: u64,
    pinned_root_der: &[u8],
    verifier: &V,
) -> Result<NitroAttestation, Error> {
    verify_parsed(
        parse_attestation(document)?,
        block_timestamp,
        pinned_root_der,
        verifier,
    )
}
