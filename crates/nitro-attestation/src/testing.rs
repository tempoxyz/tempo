//! Development attestation documents that chain to [`NITRO_DEV_ROOT_DER`].
//!
//! Documents are built as `root -> intermediate -> leaf`, in the shape [`crate::parse_attestation`]
//! accepts. Every key here is public, so these documents are for tests and development tooling
//! only.

extern crate std;

use crate::NITRO_DEV_ROOT_DER;
use alloc::vec::Vec;
use core::str::FromStr;
use minicbor::{Encoder, data::Tag};
use p384::{
    ecdsa::{DerSignature, Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
use x509_cert::{
    Certificate,
    builder::{Builder, CertificateBuilder, Profile},
    der::{Decode, Encode},
    name::Name,
    serial_number::SerialNumber,
    spki::SubjectPublicKeyInfoOwned,
};

/// PKCS#8 PEM private key of [`NITRO_DEV_ROOT_DER`]. Public and test-only.
pub const DEV_ROOT_KEY_PEM: &str = include_str!("../testdata/dev_root.key.pem");

/// PCR0, PCR1 and PCR2 that development signer programs report.
pub const DEV_PCRS: [[u8; 48]; 3] = [[0x01; 48], [0x02; 48], [0x03; 48]];

/// A development Nitro attestation document, signed under [`NITRO_DEV_ROOT_DER`].
#[derive(Clone, Debug)]
pub struct DevAttestation {
    /// Document `timestamp`, in milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// PCR0, PCR1 and PCR2, in that order.
    pub pcrs: [[u8; 48]; 3],
    /// Document `user_data`.
    pub user_data: Vec<u8>,
}

impl DevAttestation {
    /// A document reporting [`DEV_PCRS`] with `user_data` at `timestamp_ms`.
    pub fn new(user_data: impl Into<Vec<u8>>, timestamp_ms: u64) -> Self {
        Self {
            timestamp_ms,
            pcrs: DEV_PCRS,
            user_data: user_data.into(),
        }
    }

    /// Encodes the tagged COSE_Sign1 document with `cabundle = [root, intermediate]`.
    ///
    /// The intermediate and leaf certificates copy the root's validity period.
    ///
    /// # Panics
    ///
    /// Panics if the embedded development root or key does not decode.
    pub fn build(&self) -> Vec<u8> {
        let root_key = SigningKey::from_pkcs8_pem(DEV_ROOT_KEY_PEM).expect("dev root key decodes");
        let root = Certificate::from_der(NITRO_DEV_ROOT_DER).expect("dev root decodes");
        let intermediate_key = SigningKey::from_slice(&[0x02; 48]).expect("valid scalar");
        let leaf_key = SigningKey::from_slice(&[0x03; 48]).expect("valid scalar");
        let intermediate_name =
            Name::from_str("CN=Tempo Dev Nitro Intermediate,OU=DEV ONLY,O=Tempo,C=US")
                .expect("valid name");

        let intermediate = certificate(
            &root,
            Profile::SubCA {
                issuer: root.tbs_certificate.subject.clone(),
                path_len_constraint: Some(0),
            },
            2,
            intermediate_name.clone(),
            &intermediate_key,
            &root_key,
        );
        let leaf = certificate(
            &root,
            Profile::Leaf {
                issuer: intermediate_name,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            3,
            Name::from_str("CN=Tempo Dev Nitro Enclave,OU=DEV ONLY,O=Tempo,C=US")
                .expect("valid name"),
            &leaf_key,
            &intermediate_key,
        );

        let mut payload = Encoder::new(Vec::new());
        payload.map(9).expect("infallible");
        payload
            .str("module_id")
            .and_then(|e| e.str("tempo-dev-enclave"))
            .expect("infallible");
        payload
            .str("digest")
            .and_then(|e| e.str("SHA384"))
            .expect("infallible");
        payload
            .str("timestamp")
            .and_then(|e| e.u64(self.timestamp_ms))
            .expect("infallible");
        payload
            .str("pcrs")
            .and_then(|e| e.map(3))
            .expect("infallible");
        for (index, pcr) in (0u8..).zip(&self.pcrs) {
            payload
                .u8(index)
                .and_then(|e| e.bytes(pcr))
                .expect("infallible");
        }
        payload
            .str("certificate")
            .and_then(|e| e.bytes(&leaf))
            .expect("infallible");
        payload
            .str("cabundle")
            .and_then(|e| e.array(2))
            .and_then(|e| e.bytes(NITRO_DEV_ROOT_DER))
            .and_then(|e| e.bytes(&intermediate))
            .expect("infallible");
        payload
            .str("public_key")
            .and_then(|e| e.null())
            .expect("infallible");
        payload
            .str("user_data")
            .and_then(|e| e.bytes(&self.user_data))
            .expect("infallible");
        payload
            .str("nonce")
            .and_then(|e| e.null())
            .expect("infallible");
        let payload = payload.into_writer();

        // Protected header `{1: -35}`: alg ES384.
        let mut protected = Encoder::new(Vec::new());
        protected
            .map(1)
            .and_then(|e| e.i8(1))
            .and_then(|e| e.i8(-35))
            .expect("infallible");
        let protected = protected.into_writer();

        let mut structure = Encoder::new(Vec::new());
        structure
            .array(4)
            .and_then(|e| e.str("Signature1"))
            .and_then(|e| e.bytes(&protected))
            .and_then(|e| e.bytes(&[]))
            .and_then(|e| e.bytes(&payload))
            .expect("infallible");
        let signature: Signature = leaf_key.sign(&structure.into_writer());

        let mut cose = Encoder::new(Vec::new());
        cose.tag(Tag::new(18))
            .and_then(|e| e.array(4))
            .and_then(|e| e.bytes(&protected))
            .and_then(|e| e.map(0))
            .and_then(|e| e.bytes(&payload))
            .and_then(|e| e.bytes(signature.to_bytes().as_slice()))
            .expect("infallible");
        cose.into_writer()
    }
}

/// Builds a DER certificate for `subject_key`, valid for the same period as `root`.
fn certificate(
    root: &Certificate,
    profile: Profile,
    serial: u32,
    subject: Name,
    subject_key: &SigningKey,
    issuer_key: &SigningKey,
) -> Vec<u8> {
    let spki =
        SubjectPublicKeyInfoOwned::from_key(*subject_key.verifying_key()).expect("valid key");
    CertificateBuilder::new(
        profile,
        SerialNumber::from(serial),
        root.tbs_certificate.validity,
        subject,
        spki,
        issuer_key,
    )
    .expect("valid certificate profile")
    .build::<DerSignature>()
    .expect("certificate signs")
    .to_der()
    .expect("certificate encodes")
}
