//! Error types for the genesis ceremony.

use commonware_cryptography::ed25519::PublicKey;
use tempo_dkg_onchain_artifacts::PublicOutcome;
use thiserror::Error;

/// Errors that can occur during the genesis ceremony.
#[derive(Debug, Error)]
pub enum Error {
    /// Config specifies fewer than 2 participants.
    #[error("insufficient participants: expected at least 2, got {0}")]
    InsufficientParticipants(usize),
    /// Key files already exist and --force was not specified.
    #[error("key files already exist, use --force to overwrite")]
    KeysAlreadyExist,
    /// Our signing key's public key is not in the participants list.
    #[error("our public key not found in participants")]
    NotInParticipants,
    /// Received a message from a public key not in the participants list.
    #[error("unknown participant: {0:?}")]
    UnknownParticipant(Box<PublicKey>),
    /// Received an ack with an invalid signature.
    #[error("invalid ack signature from {0:?}")]
    InvalidAckSignature(Box<PublicKey>),
    /// Received a dealing with an invalid dealer signature.
    #[error("invalid dealing signature from {0:?}")]
    InvalidDealingSignature(Box<PublicKey>),
    /// Participants computed different group public keys - Loss of consensus.
    #[error(
        "outcome mismatch from {from:?} - Loss of consensus, expected {expected:?}, got {got:?}"
    )]
    OutcomeMismatch {
        from: Box<PublicKey>,
        expected: Box<PublicOutcome>,
        got: Box<PublicOutcome>,
    },
    /// Received a dealing with reveals (strict mode forbids reveals).
    #[error("strict mode: no reveals allowed, dealer {dealer:?} sent {count} reveals")]
    RevealsNotAllowed {
        dealer: Box<PublicKey>,
        count: usize,
    },
    /// Received a dealing without acks from all participants.
    #[error("strict mode: missing acks in dealing from {dealer:?}, expected {expected}, got {got}")]
    MissingAcksInDealing {
        dealer: Box<PublicKey>,
        expected: usize,
        got: usize,
    },
    /// Cannot construct dealing because we haven't received acks from all participants.
    #[error("missing acks - strict mode requires all")]
    MissingAcks,
    /// A dealing contains an ack that fails signature verification.
    #[error("invalid ack in dealing from {dealer:?}, ack by {acker:?} failed verification")]
    InvalidAckInDealing {
        dealer: Box<PublicKey>,
        acker: Box<PublicKey>,
    },
    /// One or more peers rejected our outcome.
    #[error("outcome rejected by peers: {0:?}")]
    OutcomeRejected(Box<[PublicKey]>),
}
