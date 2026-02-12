pub use IEd25519::{IEd25519Errors as Ed25519Error};

crate::sol! {
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IEd25519 {
        function verify(bytes calldata message, bytes32 signatureR, bytes32 signatureS, bytes32 publicKey) external view returns (bool valid);
        function verifyPacked(bytes calldata message, bytes calldata signature, bytes32 publicKey) external view returns (bool valid);
        function verifyBatch(bytes[] calldata messages, bytes32[] calldata signaturesR, bytes32[] calldata signaturesS, bytes32[] calldata publicKeys) external view returns (bool valid);

        error InvalidSignatureLength();
        error InvalidPublicKey();
        error ArrayLengthMismatch();
        error EmptyBatch();
    }
}

impl Ed25519Error {
    pub const fn invalid_signature_length() -> Self {
        Self::InvalidSignatureLength(IEd25519::InvalidSignatureLength {})
    }

    pub const fn invalid_public_key() -> Self {
        Self::InvalidPublicKey(IEd25519::InvalidPublicKey {})
    }

    pub const fn array_length_mismatch() -> Self {
        Self::ArrayLengthMismatch(IEd25519::ArrayLengthMismatch {})
    }

    pub const fn empty_batch() -> Self {
        Self::EmptyBatch(IEd25519::EmptyBatch {})
    }
}
