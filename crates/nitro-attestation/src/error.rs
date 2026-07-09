use core::fmt;

/// ABI-level TIP-1090 error category.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// CBOR/COSE or payload structure is invalid.
    InvalidFormat,
    /// The X.509 chain or certificate profile is invalid.
    InvalidCertificate,
    /// A certificate or document signature failed verification.
    InvalidSignature,
}

/// Structural document errors mapped to `InvalidFormat()` by the precompile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormatError {
    DocumentTooLarge,
    InvalidCbor,
    NestingTooDeep,
    InvalidCoseTag,
    InvalidCoseStructure,
    InvalidProtectedHeader,
    InvalidPayload,
    InvalidSignatureEncoding,
    MissingField(&'static str),
    DuplicateField(&'static str),
    InvalidField(&'static str),
    TooManyPcrs,
    DuplicatePcr(u8),
    TooManyCertificates,
}

/// Certificate errors mapped to `InvalidCertificate()` by the precompile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateError {
    RootMismatch,
    InvalidDer { index: usize },
    InvalidVersion { index: usize },
    InvalidSignatureAlgorithm { index: usize },
    InvalidPublicKey { index: usize },
    InvalidValidity { index: usize },
    BrokenIssuerLink { index: usize },
    DuplicateExtension { index: usize },
    UnknownCriticalExtension { index: usize },
    InvalidBasicConstraints { index: usize },
    InvalidKeyUsage { index: usize },
    InvalidPathLength { index: usize },
}

/// Signature failures mapped to `InvalidSignature()` by the precompile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature on a non-root certificate. Index zero is the root, so this is always nonzero.
    Certificate { index: usize },
    /// COSE document signature.
    Document,
}

/// Categorized TIP-1090 validation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidFormat(FormatError),
    InvalidCertificate(CertificateError),
    InvalidSignature(SignatureError),
}

impl Error {
    /// Returns the ABI-level error category.
    pub const fn category(self) -> ErrorCategory {
        match self {
            Self::InvalidFormat(_) => ErrorCategory::InvalidFormat,
            Self::InvalidCertificate(_) => ErrorCategory::InvalidCertificate,
            Self::InvalidSignature(_) => ErrorCategory::InvalidSignature,
        }
    }
}

impl From<FormatError> for Error {
    fn from(value: FormatError) -> Self {
        Self::InvalidFormat(value)
    }
}

impl From<CertificateError> for Error {
    fn from(value: CertificateError) -> Self {
        Self::InvalidCertificate(value)
    }
}

impl From<SignatureError> for Error {
    fn from(value: SignatureError) -> Self {
        Self::InvalidSignature(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat(reason) => write!(f, "invalid attestation format: {reason:?}"),
            Self::InvalidCertificate(reason) => write!(f, "invalid certificate: {reason:?}"),
            Self::InvalidSignature(reason) => write!(f, "invalid signature: {reason:?}"),
        }
    }
}
