//! Frame format for the `tempo/1` subprotocol.
//!
//! The protocol has one message, `NewFinalization`.

use alloy_primitives::bytes::{BufMut as _, BytesMut};
use commonware_codec::{DecodeExt as _, Encode as _, Read};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{Digest, certificate::Scheme};
use reth_ethereum::network::eth_wire::{Capability, protocol::Protocol};

/// Name used during the `RLPx` handshake.
const NAME: &str = "tempo";

/// Protocol version.
///
/// Peers negotiate only the name and version. Change the version if the frame
/// layout or certificate encoding changes.
const VERSION: usize = 1;

/// Number of message IDs reserved by the protocol.
///
/// Both peers must use the same count so later `RLPx` message IDs stay aligned.
const MESSAGE_COUNT: u8 = 1;

/// Message ID of `NewFinalization`.
const NEW_FINALIZATION: u8 = 0x00;

/// Largest frame accepted from a peer.
///
/// Certificates are much smaller. This limit reduces the work an
/// unauthenticated peer can request before signature verification.
pub const MAX_FRAME_BYTES: usize = 1024;

/// Returns the capability announced during the handshake.
pub const fn capability() -> Capability {
    Capability::new_static(NAME, VERSION)
}

/// Returns the protocol announced during the handshake.
pub const fn protocol() -> Protocol {
    Protocol::new(capability(), MESSAGE_COUNT)
}

/// An error found while decoding a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The frame has no message ID.
    #[error("frame was empty")]
    Empty,
    /// The frame exceeds [`MAX_FRAME_BYTES`].
    #[error("frame of {size} bytes exceeds the frame size limit")]
    Oversized {
        /// Size of the rejected frame.
        size: usize,
    },
    /// The protocol does not define this message ID.
    #[error("unknown message id `{0:#04x}`")]
    UnknownMessage(u8),
    /// The message payload is not a finalization certificate.
    #[error("invalid finalization certificate")]
    InvalidFinalization(#[source] commonware_codec::Error),
}

/// Encodes a certificate as a `NewFinalization` frame.
pub fn encode<S: Scheme, D: Digest>(finalization: &Finalization<S, D>) -> BytesMut {
    let certificate = finalization.encode();
    let mut frame = BytesMut::with_capacity(1 + certificate.len());
    frame.put_u8(NEW_FINALIZATION);
    frame.put_slice(&certificate);
    frame
}

/// Decodes a `NewFinalization` frame.
pub fn decode<S, D>(frame: &[u8]) -> Result<Finalization<S, D>, FrameError>
where
    S: Scheme,
    D: Digest,
    S::Certificate: Read<Cfg = ()>,
{
    if frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized { size: frame.len() });
    }

    let (&id, payload) = frame.split_first().ok_or(FrameError::Empty)?;
    if id != NEW_FINALIZATION {
        return Err(FrameError::UnknownMessage(id));
    }

    Finalization::decode(payload).map_err(FrameError::InvalidFinalization)
}

#[cfg(test)]
mod tests {
    use commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme;
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, ed25519::PublicKey, sha256::Digest,
    };

    use super::*;

    type TestFinalization = Finalization<Scheme<PublicKey, MinSig>, Digest>;

    const GOLDEN_FRAME: &[u8] = &alloy_primitives::hex!(
        "000001000000000000000000000000000000000000000000000000000000000000000001893a6fba4f0630edd4f1f610258f9b3a1e1fbf9c1abefaea77a62bfd27b0dea1d448c4b4b992fa094bf96c8789b49cfa8565f0bc98152e274fd6d0e3b85955736432cdca1a52201ff244bf69a65b566ffbcf642a53a23e66b4d9bd6819dd95cc"
    );

    fn decode_frame(frame: &[u8]) -> Result<TestFinalization, FrameError> {
        decode(frame)
    }

    // Peers use the version to identify the frame layout. An incompatible
    // layout must use a new version.
    #[test]
    fn frame_layout_is_frozen() {
        assert_eq!(capability().name.as_ref(), "tempo");
        assert_eq!(capability().version, 1);
        assert_eq!(protocol(), Protocol::new(capability(), 1));

        let finalization = decode_frame(GOLDEN_FRAME).unwrap();
        assert_eq!(encode(&finalization).as_ref(), GOLDEN_FRAME);
    }

    #[test]
    fn encode_decode_round_trips() {
        let finalization = decode_frame(GOLDEN_FRAME).unwrap();
        let frame = encode(&finalization);
        assert_eq!(decode_frame(&frame).unwrap(), finalization);
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert!(matches!(
            decode_frame(&[NEW_FINALIZATION]),
            Err(FrameError::InvalidFinalization(_))
        ));
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let frame = vec![0u8; MAX_FRAME_BYTES + 1];
        assert!(matches!(
            decode_frame(&frame),
            Err(FrameError::Oversized { size }) if size == MAX_FRAME_BYTES + 1
        ));
    }

    #[test]
    fn frame_at_the_limit_is_not_oversized() {
        let frame = vec![0u8; MAX_FRAME_BYTES];
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        assert!(matches!(
            decode_frame(&frame),
            Err(FrameError::InvalidFinalization(_))
        ));
    }

    #[test]
    fn empty_frame_is_rejected() {
        assert!(matches!(decode_frame(&[]), Err(FrameError::Empty)));
    }

    #[test]
    fn unknown_message_id_is_rejected() {
        assert!(matches!(
            decode_frame(&[0x01, 0xff]),
            Err(FrameError::UnknownMessage(1))
        ));
    }
}
