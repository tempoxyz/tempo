//! Frame format for the `tempo/1` subprotocol.
//!
//! The protocol has one message, `NewFinalization`. Its payload is an opaque
//! consensus certificate. Certificate decoding needs the consensus codec, so
//! it stays in the consensus crate. This keeps the node crate independent of
//! the consensus crate.

use alloy_primitives::bytes::{BufMut as _, BytesMut};
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

/// An error found before the certificate payload is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
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
}

/// Encodes a certificate as a `NewFinalization` frame.
pub fn encode(certificate: &[u8]) -> BytesMut {
    let mut frame = BytesMut::with_capacity(1 + certificate.len());
    frame.put_u8(NEW_FINALIZATION);
    frame.put_slice(certificate);
    frame
}

/// Validates a frame and returns its certificate payload.
///
/// The returned payload borrows from the frame. A caller can inspect the
/// certificate and relay the original frame without copying it.
pub fn decode(frame: &[u8]) -> Result<&[u8], FrameError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized { size: frame.len() });
    }

    let (&id, payload) = frame.split_first().ok_or(FrameError::Empty)?;
    if id != NEW_FINALIZATION {
        return Err(FrameError::UnknownMessage(id));
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Peers use the version to identify the frame layout. An incompatible
    // layout must use a new version.
    #[test]
    fn frame_layout_is_frozen() {
        assert_eq!(capability().name.as_ref(), "tempo");
        assert_eq!(capability().version, 1);
        assert_eq!(protocol(), Protocol::new(capability(), 1));

        let frame = encode(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&frame[..], &[0x00, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn encode_decode_round_trips() {
        let certificate = [0x01, 0x02, 0x03];
        let frame = encode(&certificate);
        assert_eq!(decode(&frame).unwrap(), &certificate);
    }

    #[test]
    fn empty_payload_round_trips() {
        let frame = encode(&[]);
        assert_eq!(decode(&frame).unwrap(), &[] as &[u8]);
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let frame = encode(&vec![0u8; MAX_FRAME_BYTES]);
        assert_eq!(
            decode(&frame),
            Err(FrameError::Oversized {
                size: MAX_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn frame_at_the_limit_is_accepted() {
        let frame = encode(&vec![0u8; MAX_FRAME_BYTES - 1]);
        assert_eq!(frame.len(), MAX_FRAME_BYTES);
        assert!(decode(&frame).is_ok());
    }

    #[test]
    fn empty_frame_is_rejected() {
        assert_eq!(decode(&[]), Err(FrameError::Empty));
    }

    #[test]
    fn unknown_message_id_is_rejected() {
        assert_eq!(decode(&[0x01, 0xff]), Err(FrameError::UnknownMessage(1)));
    }
}
