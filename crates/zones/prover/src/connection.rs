use std::{convert::Infallible, io};

use futures::{SinkExt as _, StreamExt as _};
use minicbor::data::Type;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec, LengthDelimitedCodecError};

use crate::{ErrorCode, PROTOCOL_VERSION, VerifyResponse};

// Derive a separate value-count cap to allow for owned values, vector slack, and witness indexes.
const BYTES_PER_CBOR_VALUE: usize = 256;

/// A typed connection using the prover's length-delimited CBOR protocol.
pub struct ProverConnection<T> {
    inner: Framed<T, LengthDelimitedCodec>,
    maximum: usize,
    last_received_bytes: Option<usize>,
}

impl<IO> ProverConnection<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Limits encoded messages to `maximum` bytes and decoded messages to `maximum / 256` CBOR values.
    pub fn new(io: IO, maximum: usize) -> Self {
        Self {
            inner: LengthDelimitedCodec::builder()
                .max_frame_length(maximum)
                .new_framed(io),
            maximum,
            last_received_bytes: None,
        }
    }

    /// Returns the encoded size of the most recently received message.
    pub fn last_received_bytes(&self) -> Option<usize> {
        self.last_received_bytes
    }

    /// Serializes and sends an owned typed message, returning its encoded size.
    pub async fn send<T: Serialize + Send + 'static>(
        &mut self,
        message: T,
    ) -> Result<usize, ProverConnectionError> {
        let payload = tokio::task::spawn_blocking(move || {
            minicbor_serde::to_vec(message).map_err(ProverConnectionError::CborEncode)
        })
        .await
        .map_err(|_| ProverConnectionError::WorkerPanic)??;
        let bytes = payload.len();
        self.inner
            .send(payload.into())
            .await
            .map_err(|error| classify_io_error(error, self.maximum))?;
        Ok(bytes)
    }

    /// Receives and deserializes a typed message.
    pub async fn receive<T: DeserializeOwned + Send + 'static>(
        &mut self,
    ) -> Result<Option<T>, ProverConnectionError> {
        self.last_received_bytes = None;
        let Some(payload) = self.inner.next().await else {
            return Ok(None);
        };
        let payload = payload.map_err(|error| classify_io_error(error, self.maximum))?;
        self.last_received_bytes = Some(payload.len());
        let maximum = self.maximum;
        tokio::task::spawn_blocking(move || decode_exact(&payload, maximum))
            .await
            .map_err(|_| ProverConnectionError::WorkerPanic)?
            .map(Some)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverConnectionError {
    #[error("message exceeds the maximum of {maximum} bytes")]
    MessageTooLarge { maximum: usize },
    /// The message exceeds the value-count limit derived from the configured frame size.
    #[error("message exceeds the maximum of {maximum} CBOR values")]
    TooManyValues {
        /// Maximum permitted number of CBOR values.
        maximum: usize,
    },
    #[error("message frame is truncated")]
    TruncatedFrame,
    #[error("message CBOR encoding failed: {0}")]
    CborEncode(#[source] minicbor_serde::error::EncodeError<Infallible>),
    #[error("message CBOR is invalid: {0}")]
    CborDecode(#[source] minicbor_serde::error::DecodeError),
    #[error("message CBOR has trailing data")]
    TrailingCborData,
    #[error("connection I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("CBOR worker panicked")]
    WorkerPanic,
}

/// Decodes one schema-driven CBOR value and requires it to consume the complete frame.
fn decode_exact<T: DeserializeOwned>(
    payload: &[u8],
    max: usize,
) -> Result<T, ProverConnectionError> {
    check_value_limit(payload, max / BYTES_PER_CBOR_VALUE)?;
    let decoder = minicbor::Decoder::new(payload);
    let mut deserializer = minicbor_serde::Deserializer::from(decoder);
    let value = T::deserialize(&mut deserializer).map_err(ProverConnectionError::CborDecode)?;
    if deserializer.decoder().position() != payload.len() {
        return Err(ProverConnectionError::TrailingCborData);
    }
    Ok(value)
}

/// Checks declared lengths and counts values without allocating or hashing their contents.
fn check_value_limit(payload: &[u8], maximum: usize) -> Result<(), ProverConnectionError> {
    let exceeded = || ProverConnectionError::TooManyValues { maximum };
    let invalid = |error: minicbor::decode::Error| ProverConnectionError::CborDecode(error.into());
    let mut remaining = maximum;
    let mut decoder = minicbor::Decoder::new(payload);
    while decoder.position() < payload.len() {
        remaining = remaining.checked_sub(1).ok_or_else(exceeded)?;
        let length = match decoder.datatype().map_err(invalid)? {
            Type::Array | Type::ArrayIndef => decoder.array().map_err(invalid)?,
            Type::Map | Type::MapIndef => decoder
                .map()
                .map_err(invalid)?
                .map(|length| length.checked_mul(2).ok_or_else(exceeded))
                .transpose()?,
            Type::Bytes | Type::BytesIndef => {
                decoder.bytes().map_err(invalid)?;
                None
            }
            Type::String | Type::StringIndef => {
                decoder.str().map_err(invalid)?;
                None
            }
            Type::Tag => {
                decoder.tag().map_err(invalid)?;
                None
            }
            _ => {
                decoder.skip().map_err(invalid)?;
                None
            }
        };
        if let Some(length) = length {
            let length = usize::try_from(length).map_err(|_| exceeded())?;
            if length > remaining {
                return Err(exceeded());
            }
        }
    }
    Ok(())
}

fn classify_io_error(error: io::Error, maximum: usize) -> ProverConnectionError {
    if error
        .get_ref()
        .is_some_and(|source| source.is::<LengthDelimitedCodecError>())
    {
        ProverConnectionError::MessageTooLarge { maximum }
    } else if error.kind() == io::ErrorKind::Other
        && error.to_string() == "bytes remaining on stream"
    {
        ProverConnectionError::TruncatedFrame
    } else {
        ProverConnectionError::Io(error)
    }
}

/// Converts a request receive error into a prover protocol response.
pub fn request_error_response(error: &ProverConnectionError) -> VerifyResponse {
    let (code, message) = match error {
        ProverConnectionError::MessageTooLarge { maximum } => (
            ErrorCode::RequestTooLarge,
            format!("request payload exceeds the maximum of {maximum} bytes"),
        ),
        ProverConnectionError::TooManyValues { maximum } => (
            ErrorCode::RequestTooLarge,
            format!("request exceeds the maximum of {maximum} CBOR values"),
        ),
        ProverConnectionError::TruncatedFrame => (
            ErrorCode::TruncatedFrame,
            "request frame is truncated".into(),
        ),
        ProverConnectionError::CborDecode(error) => (
            ErrorCode::MalformedRequest,
            format!("invalid request CBOR: {error}"),
        ),
        ProverConnectionError::CborEncode(error) => (
            ErrorCode::InternalError,
            format!("CBOR encoding failed: {error}"),
        ),
        ProverConnectionError::TrailingCborData => (
            ErrorCode::MalformedRequest,
            "request CBOR has trailing data".into(),
        ),
        ProverConnectionError::Io(error) => (
            ErrorCode::InternalError,
            format!("frame I/O failed: {error}"),
        ),
        ProverConnectionError::WorkerPanic => {
            (ErrorCode::InternalError, "CBOR worker panicked".into())
        }
    };
    VerifyResponse::Error {
        version: PROTOCOL_VERSION,
        request_id: None,
        code,
        message,
    }
}

#[cfg(test)]
mod tests {
    use alloy_consensus::Header;
    use alloy_primitives::{Address, B256, Bytes};
    use reth_trie_common::EMPTY_ROOT_HASH;
    use tempo_primitives::TempoHeader;
    use tokio::io::AsyncWriteExt as _;
    use zone_spf::{
        BatchWitness, PublicInputs, TempoImport, TempoStateWitness, ZoneBlock, ZoneStateWitness,
    };

    use super::*;
    use crate::{DEFAULT_MAX_REQUEST_BYTES, VerifyRequest};

    #[test]
    fn value_limit_boundaries() {
        let mut scenarios = vec![
            (vec![0x44, 1, 2, 3, 4], 1),
            (vec![0xa1, 0x61, b'a', 0x40], 3),
            (vec![0xbf, 0x61, b'a', 0x40, 0xff], 4),
            (vec![0xc0, 0x00], 2),
        ];
        for count in 0_u32..128 {
            let entries: Vec<Bytes> = (0..count)
                .map(|entry| Bytes::from(entry.to_be_bytes().to_vec()))
                .collect();
            let definite = minicbor_serde::to_vec(&entries).unwrap();
            let mut indefinite = vec![0x9f];
            for entry in &entries {
                indefinite.extend(minicbor_serde::to_vec(entry).unwrap());
            }
            indefinite.push(0xff);
            assert_eq!(
                decode_exact::<Vec<Bytes>>(&indefinite, DEFAULT_MAX_REQUEST_BYTES).unwrap(),
                entries
            );
            scenarios.extend([
                (definite, entries.len() + 1),
                (indefinite, entries.len() + 2),
            ]);
        }
        for (payload, tokens) in scenarios {
            check_value_limit(&payload, tokens).unwrap();
            assert!(matches!(
                check_value_limit(&payload, tokens - 1),
                Err(ProverConnectionError::TooManyValues { maximum }) if maximum == tokens - 1
            ));
        }
    }

    #[test]
    fn value_limit_rejects_declared_lengths_before_decoding() {
        for (header, length) in [(0x9b, u64::MAX), (0xbb, u64::MAX), (0xbb, u64::MAX / 2)] {
            let mut payload = vec![header];
            payload.extend_from_slice(&length.to_be_bytes());
            let error =
                decode_exact::<VerifyRequest>(&payload, DEFAULT_MAX_REQUEST_BYTES).unwrap_err();
            assert!(matches!(
                error,
                ProverConnectionError::TooManyValues { maximum }
                    if maximum == DEFAULT_MAX_REQUEST_BYTES / BYTES_PER_CBOR_VALUE
            ));
            assert!(matches!(
                request_error_response(&error),
                VerifyResponse::Error {
                    code: ErrorCode::RequestTooLarge,
                    request_id: None,
                    ..
                }
            ));
        }
    }

    #[test]
    fn value_limit_is_shared_between_pools() {
        const MAXIMUM: usize = 512;
        let entries: Vec<Bytes> = (0_u32..192)
            .map(|entry| Bytes::from(entry.to_be_bytes().to_vec()))
            .collect();
        for ([zone_nodes, bytecodes, tempo_nodes], accepted) in [
            ([entries.clone(), vec![], vec![]], true),
            ([vec![], entries.clone(), vec![]], true),
            ([vec![], vec![], entries.clone()], true),
            ([entries.clone(), entries.clone(), entries], false),
        ] {
            let mut witness = empty_witness();
            witness.zone_state_witness.node_pool = zone_nodes;
            witness.zone_state_witness.bytecodes = bytecodes;
            witness.tempo_state_witness.node_pool = tempo_nodes;
            let payload = minicbor_serde::to_vec(&witness).unwrap();
            let result = check_value_limit(&payload, MAXIMUM);
            if accepted {
                result.unwrap();
            } else {
                assert!(matches!(
                    result,
                    Err(ProverConnectionError::TooManyValues { maximum: MAXIMUM })
                ));
            }
        }
    }

    #[tokio::test]
    async fn request_round_trip() {
        let maximum = 1024 * 1024;
        let (client, server) = tokio::io::duplex(maximum);
        let mut client = ProverConnection::new(client, maximum);
        let mut server = ProverConnection::new(server, maximum);
        let request = VerifyRequest {
            version: PROTOCOL_VERSION,
            request_id: "round-trip".into(),
            witness: empty_witness(),
        };
        let sent_bytes = client.send(request).await.unwrap();
        let received: VerifyRequest = server.receive().await.unwrap().unwrap();

        assert_eq!(received.version, PROTOCOL_VERSION);
        assert_eq!(received.request_id, "round-trip");
        assert_eq!(server.last_received_bytes(), Some(sent_bytes));

        let response = VerifyResponse::Error {
            version: PROTOCOL_VERSION,
            request_id: Some(received.request_id),
            code: ErrorCode::VerificationFailed,
            message: "round-trip".into(),
        };
        let sent_bytes = server.send(response).await.unwrap();
        let received: VerifyResponse = client.receive().await.unwrap().unwrap();
        assert!(matches!(
            received,
            VerifyResponse::Error {
                request_id: Some(id),
                code: ErrorCode::VerificationFailed,
                ..
            } if id == "round-trip"
        ));
        assert_eq!(client.last_received_bytes(), Some(sent_bytes));
    }

    #[test]
    fn request_cbor_rejects_unknown_and_duplicate_fields() {
        for field in ["unknown", "version"] {
            let request = VerifyRequest {
                version: PROTOCOL_VERSION,
                request_id: "strict".into(),
                witness: empty_witness(),
            };
            let mut encoded = minicbor_serde::to_vec(&request).unwrap();
            assert_eq!(
                encoded[0], 0xa3,
                "VerifyRequest must encode as a three-field map"
            );
            encoded[0] = 0xa4;
            // Deliberately omit the field value: strict schema rejection must happen at the key.
            encoded.extend(minicbor_serde::to_vec(field).unwrap());

            assert!(matches!(
                decode_exact::<VerifyRequest>(&encoded, DEFAULT_MAX_REQUEST_BYTES),
                Err(ProverConnectionError::CborDecode(_))
            ));
        }
    }

    #[test]
    fn response_rejects_deep_unknown_fields_without_traversing_them() {
        let mut encoded = vec![0xa1, 0x65];
        encoded.extend_from_slice(b"error");
        encoded.extend_from_slice(&[0xa1, 0x66]);
        encoded.extend_from_slice(b"nested");
        encoded.extend(std::iter::repeat_n(0x81, 10_000));
        encoded.push(0xf6);

        assert!(matches!(
            decode_exact::<VerifyResponse>(&encoded, DEFAULT_MAX_REQUEST_BYTES),
            Err(ProverConnectionError::CborDecode(_))
        ));
    }

    #[test]
    fn cbor_keeps_byte_payloads_binary() {
        let value = Bytes::from(vec![0xab; 1024]);
        let encoded = minicbor_serde::to_vec(&value).unwrap();
        let decoded: Bytes = decode_exact(&encoded, DEFAULT_MAX_REQUEST_BYTES).unwrap();

        assert_eq!(decoded, value);
        assert!(encoded.len() < serde_json::to_vec(&value).unwrap().len());
    }

    #[tokio::test]
    async fn rejects_oversized_truncated_and_value_heavy_frames() {
        for (frame, max, expected) in [
            (&[0, 0, 0, 10][..], 4, ErrorCode::RequestTooLarge),
            (&[0, 0, 0, 2, 1][..], 4, ErrorCode::TruncatedFrame),
            (
                &[0, 0, 0, 2, 0x81, 0x40][..],
                BYTES_PER_CBOR_VALUE,
                ErrorCode::RequestTooLarge,
            ),
        ] {
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer.write_all(frame).await.unwrap();
            writer.shutdown().await.unwrap();
            let error = ProverConnection::new(reader, max)
                .receive::<Vec<Bytes>>()
                .await
                .unwrap_err();
            assert!(matches!(
                request_error_response(&error),
                VerifyResponse::Error { code, .. } if code == expected
            ));
        }
    }

    #[tokio::test]
    async fn malformed_cbor_has_a_stable_error() {
        for payload in [
            &[0xff][..],
            &[0x01, 0x02][..],
            &[0x44, 0x01][..],
            &[0x64, b'a'][..],
            &[0x18][..],
        ] {
            let (mut writer, reader) = tokio::io::duplex(1024);
            writer
                .write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
                .await
                .unwrap();
            writer.write_all(payload).await.unwrap();
            let error = ProverConnection::new(reader, 1024)
                .receive::<u8>()
                .await
                .unwrap_err();
            let response = request_error_response(&error);
            assert!(matches!(
                response,
                VerifyResponse::Error {
                    request_id: None,
                    code: ErrorCode::MalformedRequest,
                    ..
                }
            ));
        }
    }

    fn empty_witness() -> BatchWitness {
        let tempo_header = TempoHeader {
            inner: Header {
                number: 2,
                state_root: EMPTY_ROOT_HASH,
                ..Default::default()
            },
            ..Default::default()
        };
        BatchWitness {
            public_inputs: PublicInputs {
                parent_chain_id: 42_431,
                zone_id: 1,
                tempo_block_number: 2,
                anchor_block_number: 2,
                anchor_block_hash: B256::ZERO,
                expected_withdrawal_batch_index: 3,
            },
            parent_header: TempoHeader::default(),
            zone_blocks: vec![ZoneBlock {
                number: 1,
                parent_hash: B256::ZERO,
                timestamp: 1,
                timestamp_millis_part: 2,
                beneficiary: Address::ZERO,
                tempo_import: TempoImport::CheckpointOnly {
                    headers_rlp: vec![Bytes::from_static(&[0x01, 0x02])],
                },
                finalize_withdrawal_batch_count: None,
                finalize_withdrawal_batch_encrypted_senders: vec![Bytes::from_static(&[0x03])],
                transactions: vec![Bytes::from_static(&[0x04, 0x05])],
            }],
            zone_state_witness: ZoneStateWitness {
                node_pool: vec![Bytes::from_static(&[0x06])],
                bytecodes: vec![Bytes::from_static(&[0x07])],
            },
            tempo_state_witness: TempoStateWitness {
                initial_tempo_header_rlp: Bytes::from(alloy_rlp::encode(tempo_header)),
                node_pool: vec![Bytes::from_static(&[0x08])],
            },
            tempo_ancestry_headers: vec![Bytes::from_static(&[0x09])],
        }
    }
}
