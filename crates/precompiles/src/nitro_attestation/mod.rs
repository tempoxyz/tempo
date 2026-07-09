//! TIP-1090 AWS Nitro Enclave attestation verifier.

pub mod dispatch;

use alloy::primitives::{B256, Bytes};
use aws_lc_rs::{
    digest::{Digest as AwsLcDigest, SHA384 as AWS_LC_SHA384, digest as aws_lc_digest},
    signature::{
        ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_FIXED, ParsedPublicKey as AwsLcParsedPublicKey,
    },
};
use tempo_contracts::precompiles::{
    INitroAttestationVerifier, NITRO_ATTESTATION_VERIFIER_ADDRESS, NitroAttestationError,
};
use tempo_nitro_attestation::{
    ErrorCategory, P384_FIXED_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE, P384Verifier, SHA384_SIZE,
    Sha384Hasher, parse_attestation, verify_parsed,
};
use tempo_precompiles_macros::contract;

use crate::error::Result;

/// Gas charged before CBOR, COSE, X.509, or hashing work begins.
pub const BASE_GAS_COST: u64 = 40_000;
/// Gas charged for each P-384 signature verification.
pub const P384_VERIFY_GAS_COST: u64 = 35_000;

/// AWS Nitro Enclaves commercial-partition root certificate (G1), in DER form.
///
/// SHA-256: `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`.
const AWS_NITRO_ROOT_G1_DER: &[u8; 533] = &alloy::primitives::hex!(
    "3082021130820196a003020102021100f93175681b90afe11d46ccb4e4e7f856300a06082a8648ce3d0403033049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c61766573301e170d3139313032383133323830355a170d3439313032383134323830355a3049310b3009060355040613025553310f300d060355040a0c06416d617a6f6e310c300a060355040b0c03415753311b301906035504030c126177732e6e6974726f2d656e636c617665733076301006072a8648ce3d020106052b8104002203620004fc0254eba608c1f36870e29ada90be46383292736e894bfff672d989444b5051e534a4b1f6dbe3c0bc581a32b7b176070ede12d69a3fea211b66e752cf7dd1dd095f6f1370f4170843d9dc100121e4cf63012809664487c9796284304dc53ff4a3423040300f0603551d130101ff040530030101ff301d0603551d0e041604149025b50dd90547e796c396fa729dcf99a9df4b96300e0603551d0f0101ff040403020186300a06082a8648ce3d0403030369003066023100a37f2f91a1c9bd5ee7b8627c1698d255038e1f0343f95b63a9628c3d39809545a11ebcbf2e3b55d8aeee71b4c3d6adf3023100a2f39b1605b27028a5dd4ba069b5016e65b4fbde8fe0061d6a53197f9cdaf5d943bc61fc2beb03cb6fee8d2302f3dff6"
);

#[contract(addr = NITRO_ATTESTATION_VERIFIER_ADDRESS)]
pub struct NitroAttestationVerifier {}

impl NitroAttestationVerifier {
    /// Parses and verifies an AWS Nitro Enclave attestation document.
    pub fn verify_attestation(
        &mut self,
        document: Bytes,
    ) -> Result<INitroAttestationVerifier::NitroAttestation> {
        let parsed = parse_attestation(&document).map_err(map_validation_error)?;

        // Parsing establishes the bounded chain length. Charge every signature before running
        // any P-384 operation, so OOG cannot leave a partially verified chain.
        let verification_gas = u64::try_from(parsed.signature_count())
            .unwrap_or(u64::MAX)
            .saturating_mul(P384_VERIFY_GAS_COST);
        self.storage.deduct_gas(verification_gas)?;

        let block_timestamp = self.storage.timestamp().saturating_to::<u64>();
        let attestation = verify_parsed(parsed, block_timestamp, AWS_NITRO_ROOT_G1_DER, &AwsLcP384)
            .map_err(map_validation_error)?;

        Ok(INitroAttestationVerifier::NitroAttestation {
            moduleId: attestation.module_id,
            timestamp: attestation.timestamp,
            pcrs: attestation
                .pcrs
                .into_iter()
                .map(|pcr| INitroAttestationVerifier::Pcr {
                    index: pcr.index,
                    value: pcr.value.into(),
                })
                .collect(),
            publicKey: attestation.public_key.into(),
            userData: attestation.user_data.into(),
            nonce: attestation.nonce.into(),
            leafCertHash: B256::from(attestation.leaf_cert_hash),
        })
    }
}

fn map_validation_error(
    error: tempo_nitro_attestation::Error,
) -> crate::error::TempoPrecompileError {
    match error.category() {
        ErrorCategory::InvalidFormat => NitroAttestationError::invalid_format().into(),
        ErrorCategory::InvalidCertificate => NitroAttestationError::invalid_certificate().into(),
        ErrorCategory::InvalidSignature => NitroAttestationError::invalid_signature().into(),
    }
}

struct AwsLcP384;

impl Sha384Hasher for AwsLcP384 {
    fn sha384(&self, input: &[u8]) -> [u8; SHA384_SIZE] {
        aws_lc_digest(&AWS_LC_SHA384, input)
            .as_ref()
            .try_into()
            .expect("SHA-384 has a fixed 48-byte output")
    }
}

impl P384Verifier for AwsLcP384 {
    fn validate_public_key(&self, public_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> bool {
        AwsLcParsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key).is_ok()
    }

    fn verify_der(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature_der: &[u8],
    ) -> bool {
        verify_digest(&ECDSA_P384_SHA384_ASN1, public_key, digest, signature_der)
    }

    fn verify_fixed(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature: &[u8; P384_FIXED_SIGNATURE_SIZE],
    ) -> bool {
        verify_digest(&ECDSA_P384_SHA384_FIXED, public_key, digest, signature)
    }
}

fn verify_digest(
    algorithm: &'static aws_lc_rs::signature::EcdsaVerificationAlgorithm,
    public_key: &[u8; P384_PUBLIC_KEY_SIZE],
    digest: &[u8; SHA384_SIZE],
    signature: &[u8],
) -> bool {
    let Ok(public_key) = AwsLcParsedPublicKey::new(algorithm, public_key) else {
        return false;
    };
    let Ok(digest) = AwsLcDigest::import_less_safe(digest, &AWS_LC_SHA384) else {
        return false;
    };
    public_key.verify_digest_sig(&digest, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::AWS_NITRO_ROOT_G1_DER;
    use aws_lc_rs::digest::{SHA256, digest};

    #[test]
    fn pinned_root_has_expected_sha256() {
        assert_eq!(
            digest(&SHA256, AWS_NITRO_ROOT_G1_DER).as_ref(),
            alloy::primitives::hex!(
                "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b"
            )
        );
    }
}
