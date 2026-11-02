//! Development attestation documents that chain to [`NITRO_DEV_ROOT_DER`].
//!
//! Documents are built as `root -> intermediate -> leaf`, in the shape [`crate::parse_attestation`]
//! accepts. Every key here is public, so these documents are for tests and development tooling
//! only.

extern crate std;

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

/// Development-only Nitro root certificate (P-384), in DER form.
///
/// Its private key is [`DEV_ROOT_KEY_PEM`], so documents chaining to it prove nothing. A scheme
/// `0xFE` policy accepts it only if it lists `keccak256` of it as a trust anchor.
///
/// SHA-256: `eef02ddde90ed0c4cbcdfa551b60b00ddbaae3824d929ecb9102ddff3f34e666`.
pub const NITRO_DEV_ROOT_DER: &[u8; 536] = &hex_literal::hex!(
    "308202143082019aa003020102020101300a06082a8648ce3d0403033053310b3009060355040613025553310e300c060355040a0c0554656d706f3111300f060355040b0c08444556204f4e4c593121301f06035504030c1874656d706f2d6465762e6e6974726f2d656e636c61766573301e170d3236313033313232303732325a170d3438303932353232303732325a3053310b3009060355040613025553310e300c060355040a0c0554656d706f3111300f060355040b0c08444556204f4e4c593121301f06035504030c1874656d706f2d6465762e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b81040022036200041c018137da9d96ce0115068d106ba72a0f3cf3942daa1b7a0e1fb7f73f595c97eb5ceea02994fa5e5db68fc99d45c183fcbd608dbd6df89bfdd80abc6d6c1815a8133b07cf20f4558a858b1713716c04e0487ae7efff58a4c2893a4e24f1c35aa3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020186301d0603551d0e0416041449241c69d024a9a65bc43a34503a233a6b238452300a06082a8648ce3d04030303680030650230304c22bba81a5184458e513eceaef788920d49200cb827472b1b97aea383338713bd255121eab0bab260a7f21567bc02023100b280db4a2964df9dad0882f9ad7d1fcb69889bf7522da2c28f9c652133854f5772fd5599765ffeb799f7428cb50ac893"
);

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
