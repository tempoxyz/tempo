pub use INitroAttestationVerifier::INitroAttestationVerifierErrors as NitroAttestationError;

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface INitroAttestationVerifier {
        struct Pcr {
            uint8 index;
            bytes value;
        }

        struct NitroAttestation {
            string moduleId;
            uint64 timestamp;
            Pcr[] pcrs;
            bytes publicKey;
            bytes userData;
            bytes nonce;
            bytes32 leafCertHash;
        }

        /// Verifies an AWS Nitro Enclave COSE_Sign1 attestation document.
        function verifyAttestation(bytes calldata document)
            external
            view
            returns (NitroAttestation memory attestation);

        error InvalidFormat();
        error InvalidCertificate();
        error InvalidSignature();
    }
}
