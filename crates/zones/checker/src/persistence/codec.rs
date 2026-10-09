//! Versioned value encoding for checker MDBX tables.

use bincode::Options as _;
use reth_codecs::{Compress, Decompress, DecompressError};
use serde::{Serialize, de::DeserializeOwned};

const VERSION: u8 = 1;
const MAX_VALUE_SIZE: u64 = 16 * 1024 * 1024;

fn options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_VALUE_SIZE - 1)
}

/// Validate a dynamic value before passing it to MDBX's infallible codec interface.
pub(super) fn validate<T: Serialize>(value: &T) -> Result<(), String> {
    options()
        .serialized_size(value)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut encoded = vec![VERSION];
    options().serialize_into(&mut encoded, value).map_err(map)?;
    Ok(encoded)
}

fn decode<T: DeserializeOwned>(encoded: &[u8]) -> Result<T, CodecError> {
    let (&version, value) = encoded.split_first().ok_or(CodecError::Empty)?;
    if version != VERSION {
        return Err(CodecError::Version(version));
    }
    options().deserialize(value).map_err(map)
}

fn map(error: Box<bincode::ErrorKind>) -> CodecError {
    if matches!(*error, bincode::ErrorKind::SizeLimit) {
        CodecError::Oversize
    } else {
        CodecError::Malformed(error.to_string())
    }
}

macro_rules! values {
    ($($value:ty),+ $(,)?) => {$ (
        impl Compress for $value {
            type Compressed = Vec<u8>;

            fn compress_to_buf<B: bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
                buf.put_slice(&encode(self).expect("validated persistence value"));
            }
        }

        impl Decompress for $value {
            fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
                decode(value).map_err(|error| {
                    DecompressError::new(std::io::Error::other(error))
                })
            }
        }
    )+};
}

values!(super::schema::MetaValue, super::schema::TokenValue);

/// Invalid durable value envelope.
#[derive(Debug, thiserror::Error)]
enum CodecError {
    #[error("empty persistence value")]
    Empty,
    #[error("unsupported persistence value version {0}")]
    Version(u8),
    #[error("persistence value exceeds 16 MiB")]
    Oversize,
    #[error("malformed persistence value: {0}")]
    Malformed(String),
}
