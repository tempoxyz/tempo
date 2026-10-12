use alloy_primitives::B256;

use crate::network::MAX_MESSAGE_SIZE;

const BLOCK_FRAME: u8 = 0;
const COMPLETE_FRAME: u8 = 1;
const CAPABILITIES_FRAME: u8 = 2;
const REQUEST_LEN: usize = 16;
const RESPONSE_HEADER_LEN: usize = 1 + std::mem::size_of::<u64>();

/// A block's RLP bytes and optional CBOR-encoded witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedBlock {
    pub block: Vec<u8>,
    pub witness: Option<Vec<u8>>,
}

impl EncodedBlock {
    /// Versioned prefix of the witnessed block envelope.
    pub const WITNESS_PREFIX: &[u8] = b"ZWIT\x01";

    /// Encode a witness envelope when present, otherwise preserve bare RLP.
    pub fn encode(&self) -> Vec<u8> {
        if let Some(witness) = &self.witness {
            let mut encoded =
                Vec::with_capacity(Self::WITNESS_PREFIX.len() + self.block.len() + witness.len());
            encoded.extend_from_slice(Self::WITNESS_PREFIX);
            encoded.extend_from_slice(&self.block);
            encoded.extend_from_slice(witness);
            encoded
        } else {
            self.block.clone()
        }
    }
}

/// A peer's advertised canonical tip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerTip {
    pub zone_height: u64,
    pub zone_hash: B256,
    pub tempo_block_number: u64,
    pub tempo_block_hash: B256,
}

impl PeerTip {
    pub(crate) const ENCODED_LEN: usize = 8 + 32 + 8 + 32;

    pub(crate) fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..8].copy_from_slice(&self.zone_height.to_be_bytes());
        encoded[8..40].copy_from_slice(self.zone_hash.as_slice());
        encoded[40..48].copy_from_slice(&self.tempo_block_number.to_be_bytes());
        encoded[48..].copy_from_slice(self.tempo_block_hash.as_slice());
        encoded
    }

    pub(crate) fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        if payload.len() != Self::ENCODED_LEN {
            return Err(DecodeError::InvalidCompletionLength {
                expected: Self::ENCODED_LEN,
                actual: payload.len(),
            });
        }
        Ok(Self {
            zone_height: u64::from_be_bytes(payload[..8].try_into().expect("fixed size")),
            zone_hash: B256::from_slice(&payload[8..40]),
            tempo_block_number: u64::from_be_bytes(payload[40..48].try_into().expect("fixed size")),
            tempo_block_hash: B256::from_slice(&payload[48..80]),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestFrame {
    pub request_id: u64,
    pub start: u64,
}

impl RequestFrame {
    pub(crate) fn encode(&self) -> [u8; REQUEST_LEN] {
        let mut encoded = [0; REQUEST_LEN];
        encoded[..8].copy_from_slice(&self.request_id.to_be_bytes());
        encoded[8..].copy_from_slice(&self.start.to_be_bytes());
        encoded
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != REQUEST_LEN {
            return Err(DecodeError::IncorrectRequestLength {
                expected: REQUEST_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            request_id: u64::from_be_bytes(bytes[..8].try_into().expect("fixed size")),
            start: u64::from_be_bytes(bytes[8..].try_into().expect("fixed size")),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResponseFrame {
    Block {
        request_id: u64,
        block: Vec<u8>,
    },
    Complete {
        request_id: u64,
        tip: PeerTip,
    },
    /// Unsolicited capability version on the existing response channel. Old receivers
    /// ignore this unknown frame tag without disconnecting the authenticated transport.
    Capabilities(u8),
}

impl ResponseFrame {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            Self::Capabilities(version) => Ok(vec![CAPABILITIES_FRAME, *version]),
            Self::Block { request_id, block } => {
                let frame_len = block.len().saturating_add(RESPONSE_HEADER_LEN);
                if frame_len > MAX_MESSAGE_SIZE as usize {
                    return Err(EncodeError::OversizedResponseBlock {
                        size: frame_len,
                        max: MAX_MESSAGE_SIZE as usize,
                    });
                }
                let mut encoded = Vec::with_capacity(frame_len);
                encoded.push(BLOCK_FRAME);
                encoded.extend_from_slice(&request_id.to_be_bytes());
                encoded.extend_from_slice(block);
                Ok(encoded)
            }
            Self::Complete { request_id, tip } => {
                let mut encoded = Vec::with_capacity(RESPONSE_HEADER_LEN + PeerTip::ENCODED_LEN);
                encoded.push(COMPLETE_FRAME);
                encoded.extend_from_slice(&request_id.to_be_bytes());
                encoded.extend_from_slice(&tip.encode());
                Ok(encoded)
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let Some((&tag, payload)) = bytes.split_first() else {
            return Err(DecodeError::EmptyResponse);
        };
        if tag == CAPABILITIES_FRAME {
            return match payload {
                [version] => Ok(Self::Capabilities(*version)),
                _ => Err(DecodeError::InvalidCapabilities),
            };
        }
        if !matches!(tag, BLOCK_FRAME | COMPLETE_FRAME) {
            return Err(DecodeError::UnknownResponseTag(tag));
        }
        let Some((request_id_bytes, payload)) = payload.split_at_checked(8) else {
            return Err(DecodeError::MissingRequestId);
        };
        let request_id = u64::from_be_bytes(
            request_id_bytes
                .try_into()
                .expect("split_at_checked preserves the requested length"),
        );
        match tag {
            BLOCK_FRAME => {
                let frame_len = bytes.len();
                if frame_len > MAX_MESSAGE_SIZE as usize {
                    return Err(DecodeError::OversizedResponseBlock {
                        size: frame_len,
                        max: MAX_MESSAGE_SIZE as usize,
                    });
                }
                Ok(Self::Block {
                    request_id,
                    block: payload.to_vec(),
                })
            }
            COMPLETE_FRAME => Ok(Self::Complete {
                request_id,
                tip: PeerTip::decode(payload)?,
            }),
            _ => unreachable!("response tag was checked above"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DecodeError {
    #[error("invalid capabilities announcement")]
    InvalidCapabilities,
    #[error("incorrect request length: expected {expected} bytes, got {actual}")]
    IncorrectRequestLength { expected: usize, actual: usize },
    #[error("empty response")]
    EmptyResponse,
    #[error("missing request ID")]
    MissingRequestId,
    #[error("unknown response tag {0}")]
    UnknownResponseTag(u8),
    #[error("invalid completion length: expected {expected} bytes, got {actual}")]
    InvalidCompletionLength { expected: usize, actual: usize },
    #[error("oversized response block: {size} bytes exceeds {max} bytes")]
    OversizedResponseBlock { size: usize, max: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EncodeError {
    #[error("oversized response block: {size} bytes exceeds {max} bytes")]
    OversizedResponseBlock { size: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;

    use super::{
        DecodeError, EncodeError, PeerTip, RESPONSE_HEADER_LEN, RequestFrame, ResponseFrame,
    };
    use crate::network::MAX_MESSAGE_SIZE;

    fn tip() -> PeerTip {
        PeerTip {
            zone_height: 7,
            zone_hash: B256::repeat_byte(0x11),
            tempo_block_number: 13,
            tempo_block_hash: B256::repeat_byte(0x22),
        }
    }

    #[test]
    fn golden_request_and_peer_tip_bytes() {
        assert_eq!(
            RequestFrame {
                request_id: 7,
                start: 13,
            }
            .encode(),
            [0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 13]
        );

        let encoded = tip().encode().to_vec();
        assert_eq!(&encoded[..8], &7_u64.to_be_bytes());
        assert_eq!(&encoded[8..40], &[0x11; 32]);
        assert_eq!(&encoded[40..48], &13_u64.to_be_bytes());
        assert_eq!(&encoded[48..], &[0x22; 32]);
        assert_eq!(PeerTip::decode(&encoded), Ok(tip()));
    }

    #[test]
    fn response_golden_bytes_and_round_trips() {
        let block = ResponseFrame::Block {
            request_id: 7,
            block: vec![0xaa, 0xbb],
        };
        assert_eq!(
            block.encode().unwrap(),
            vec![0, 0, 0, 0, 0, 0, 0, 0, 7, 0xaa, 0xbb]
        );
        assert_eq!(ResponseFrame::decode(&block.encode().unwrap()), Ok(block));

        let complete = ResponseFrame::Complete {
            request_id: 7,
            tip: tip(),
        };
        let encoded = complete.encode().unwrap();
        assert_eq!(encoded[0], 1);
        assert_eq!(&encoded[1..9], &7_u64.to_be_bytes());
        assert_eq!(encoded.len(), RESPONSE_HEADER_LEN + PeerTip::ENCODED_LEN);
        assert_eq!(ResponseFrame::decode(&encoded), Ok(complete));
    }

    #[test]
    fn capabilities_are_a_versioned_unsolicited_frame() {
        let announcement = ResponseFrame::Capabilities(1).encode().unwrap();
        assert_eq!(announcement, [2, 1]);
        assert_eq!(
            ResponseFrame::decode(&announcement),
            Ok(ResponseFrame::Capabilities(1))
        );
        // The old decoder accepts only tags 0/1, returning UnknownResponseTag for this
        // announcement before trying to read a request ID. Its coordinator ignores that error.
        assert!(!matches!(announcement[0], 0 | 1));
        for version in 0..=u8::MAX {
            let frame = ResponseFrame::Capabilities(version);
            assert_eq!(frame.encode().unwrap(), [2, version]);
            assert_eq!(ResponseFrame::decode(&[2, version]), Ok(frame));
        }
        for bytes in [&[2][..], &[2, 1, 0]] {
            assert_eq!(
                ResponseFrame::decode(bytes),
                Err(DecodeError::InvalidCapabilities)
            );
        }
    }

    #[test]
    fn malformed_frames_are_rejected_precisely() {
        assert!(matches!(
            RequestFrame::decode(&[]),
            Err(DecodeError::IncorrectRequestLength { .. })
        ));
        assert_eq!(ResponseFrame::decode(&[]), Err(DecodeError::EmptyResponse));
        assert_eq!(
            ResponseFrame::decode(&[0]),
            Err(DecodeError::MissingRequestId)
        );
        assert_eq!(
            ResponseFrame::decode(&[9]),
            Err(DecodeError::UnknownResponseTag(9))
        );
        assert!(matches!(
            ResponseFrame::decode(&[1, 0, 0, 0, 0, 0, 0, 0, 7]),
            Err(DecodeError::InvalidCompletionLength { .. })
        ));
        let mut overlong_completion = vec![1, 0, 0, 0, 0, 0, 0, 0, 7];
        overlong_completion.extend_from_slice(&[0; PeerTip::ENCODED_LEN + 1]);
        assert!(matches!(
            ResponseFrame::decode(&overlong_completion),
            Err(DecodeError::InvalidCompletionLength { .. })
        ));
    }

    #[test]
    fn oversized_blocks_are_rejected_on_encode_and_decode() {
        let block = vec![0; MAX_MESSAGE_SIZE as usize - RESPONSE_HEADER_LEN + 1];
        assert!(matches!(
            ResponseFrame::Block {
                request_id: 1,
                block: block.clone(),
            }
            .encode(),
            Err(EncodeError::OversizedResponseBlock { .. })
        ));
        let mut encoded = vec![0, 0, 0, 0, 0, 0, 0, 0, 1];
        encoded.extend_from_slice(&block);
        assert!(matches!(
            ResponseFrame::decode(&encoded),
            Err(DecodeError::OversizedResponseBlock { .. })
        ));
    }
}
