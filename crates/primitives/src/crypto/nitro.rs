use tempo_nitro_attestation::{
    AwsLcP384, P384_FIXED_SIGNATURE_SIZE, P384_PUBLIC_KEY_SIZE, P384Verifier, SHA384_SIZE,
    Sha384Hasher,
};

/// The Nitro attestation's P-384 verifier, also accepting mocks under `mock-crypto`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NitroVerifier;

impl Sha384Hasher for NitroVerifier {
    fn sha384(&self, input: &[u8]) -> [u8; SHA384_SIZE] {
        AwsLcP384.sha384(input)
    }
}

impl P384Verifier for NitroVerifier {
    fn validate_public_key(&self, public_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> bool {
        AwsLcP384.validate_public_key(public_key)
    }

    fn verify_der(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature_der: &[u8],
    ) -> bool {
        #[cfg(feature = "mock-crypto")]
        if super::mock::verify_p384(public_key, digest, signature_der) {
            return true;
        }
        AwsLcP384.verify_der(public_key, digest, signature_der)
    }

    fn verify_fixed(
        &self,
        public_key: &[u8; P384_PUBLIC_KEY_SIZE],
        digest: &[u8; SHA384_SIZE],
        signature: &[u8; P384_FIXED_SIGNATURE_SIZE],
    ) -> bool {
        #[cfg(feature = "mock-crypto")]
        if super::mock::verify_p384(public_key, digest, signature) {
            return true;
        }
        AwsLcP384.verify_fixed(public_key, digest, signature)
    }
}
