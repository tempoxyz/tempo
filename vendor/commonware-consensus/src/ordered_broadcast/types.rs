//! Types used in [crate::ordered_broadcast].

use super::scheme;
use crate::{
    types::{Epoch, Height},
    Heightable,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Namespace, Provider, Scheme, Subject, Verifier},
    Digest, PublicKey, Signer,
};
use commonware_parallel::Strategy;
use commonware_utils::{channel::oneshot, ordered::Set, union, N3f1};
use rand_core::CryptoRng;
use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

/// Error that may be encountered when interacting with `ordered-broadcast`.
///
/// These errors are categorized into several groups:
/// - Parser errors (missing parent, etc.)
/// - Application verification errors
/// - P2P errors
/// - Broadcast errors (certificate-related issues)
/// - Epoch errors (unknown validators or sequencers)
/// - Peer errors
/// - Signature errors
/// - Ignorable message errors (outside epoch/height bounds)
/// - Attributable faults (conflicting chunks)
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // Parser Errors
    /// The parent is missing for a non-genesis chunk
    #[error("Missing parent")]
    ParentMissing,
    /// The parent was provided for a genesis chunk (height 0)
    #[error("Parent on genesis chunk")]
    ParentOnGenesis,
    /// Verification failed because no public key was provided
    #[error("Public key required")]
    PublicKeyRequired,

    // Application Verification Errors
    /// The verification was canceled by the application
    #[error("Application verify error: {0}")]
    AppVerifyCanceled(oneshot::error::RecvError),
    /// The application tried to verify a chunk but no tip was found
    #[error("Application verified no tip")]
    AppVerifiedNoTip,
    /// The application verified a chunk but the height doesn't match the tip
    #[error("Application verified height mismatch")]
    AppVerifiedHeightMismatch,
    /// The application verified a chunk but the payload doesn't match the tip
    #[error("Application verified payload mismatch")]
    AppVerifiedPayloadMismatch,

    // Broadcast errors
    /// The chunk already has a certificate
    #[error("Already certified")]
    AlreadyCertified,
    /// I am not a sequencer in the specified epoch
    #[error("I am not a sequencer in epoch {0}")]
    IAmNotASequencer(Epoch),
    /// Nothing to rebroadcast
    #[error("Nothing to rebroadcast")]
    NothingToRebroadcast,
    /// A certificate is missing
    #[error("Missing certificate")]
    MissingCertificate,
    /// The sequencer in the context doesn't match the expected sequencer
    #[error("Invalid context sequencer")]
    ContextSequencer,
    /// The height in the context is invalid
    #[error("Invalid context height")]
    ContextHeight,

    // Epoch Errors
    /// No signing scheme is known for the specified epoch
    #[error("Unknown signing scheme at epoch {0}")]
    UnknownScheme(Epoch),
    /// The specified sequencer is not a participant in the epoch
    #[error("Epoch {0} has no sequencer {1}")]
    UnknownSequencer(Epoch, String),
    /// The specified validator is not a participant in the epoch
    #[error("Epoch {0} has no validator {1}")]
    UnknownValidator(Epoch, String),
    /// The local validator is not a signer in the scheme for the specified epoch.
    #[error("Not a signer at epoch {0}")]
    NotSigner(Epoch),

    // Peer Errors
    /// The sender's public key doesn't match the expected key
    #[error("Peer mismatch")]
    PeerMismatch,

    // Signature Errors
    /// The sequencer's signature is invalid
    #[error("Invalid sequencer signature")]
    InvalidSequencerSignature,
    /// The certificate is invalid
    #[error("Invalid certificate")]
    InvalidCertificate,
    /// The node signature is invalid
    #[error("Invalid node signature")]
    InvalidNodeSignature,
    /// The acknowledgment signature is invalid
    #[error("Invalid ack signature")]
    InvalidAckSignature,

    // Ignorable Message Errors
    /// The acknowledgment's epoch is outside the accepted bounds
    #[error("Invalid ack epoch {0} outside bounds {1} - {2}")]
    AckEpochOutsideBounds(Epoch, Epoch, Epoch),
    /// The acknowledgment's height is outside the accepted bounds
    #[error("Invalid ack height {0} outside bounds {1} - {2}")]
    AckHeightOutsideBounds(Height, Height, Height),
    /// The chunk's height is lower than the current tip height
    #[error("Chunk height {0} lower than tip height {1}")]
    ChunkHeightTooLow(Height, Height),

    // Attributable Faults
    /// The chunk conflicts with an existing chunk at the same height
    #[error("Chunk payload mismatch from sequencer {0} at height {1}")]
    ChunkMismatch(String, Height),
}

/// Interface responsible for providing the set of sequencers active at a given epoch.
pub trait SequencersProvider: Clone + Send + Sync + 'static {
    /// Public key used to identify sequencers.
    type PublicKey: PublicKey;

    /// Get the **sorted** sequencers for the given epoch.
    /// Returns `None` if the epoch is not known.
    fn sequencers(&self, epoch: Epoch) -> Option<Arc<Set<Self::PublicKey>>>;
}

/// Suffix used to identify a chunk namespace for domain separation.
/// Used when signing and verifying chunks to prevent signature reuse across different message types.
pub const CHUNK_SUFFIX: &[u8] = b"_CHUNK";

/// Suffix used to identify an acknowledgment (ack) namespace for domain separation.
/// Used when signing and verifying acks to prevent signature reuse across different message types.
pub const ACK_SUFFIX: &[u8] = b"_ACK";

/// Returns a suffixed namespace for signing a chunk.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for chunks cannot be reused for other message types.
#[inline]
fn chunk_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, CHUNK_SUFFIX)
}

/// Returns a suffixed namespace for signing an ack.
///
/// This provides domain separation for signatures, preventing cross-protocol attacks
/// by ensuring signatures for acks cannot be reused for other message types.
#[inline]
pub fn ack_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, ACK_SUFFIX)
}

/// Namespace type for chunk signing/verification.
///
/// This type encapsulates the pre-computed namespace bytes used for signing and
/// verifying chunks (nodes and proposals).
#[derive(Clone, Debug)]
pub struct ChunkNamespace(Vec<u8>);

impl Namespace for ChunkNamespace {
    fn derive(namespace: &[u8]) -> Self {
        Self(chunk_namespace(namespace))
    }
}

/// Signer for chunk operations.
///
/// The namespace is pre-computed at construction time.
#[derive(Clone)]
pub struct ChunkSigner<C: Signer> {
    signer: C,
    namespace: ChunkNamespace,
}

impl<C: Signer> ChunkSigner<C> {
    /// Creates a new ChunkSigner with the given namespace and signer.
    ///
    /// The chunk namespace is pre-computed from the base namespace.
    pub fn new(namespace: &[u8], signer: C) -> Self {
        Self {
            signer,
            namespace: ChunkNamespace::derive(namespace),
        }
    }

    /// Returns the public key of the underlying signer.
    pub fn public_key(&self) -> C::PublicKey {
        self.signer.public_key()
    }

    /// Signs a chunk and returns the signature.
    pub fn sign<P, D>(&mut self, chunk: &Chunk<P, D>) -> C::Signature
    where
        P: PublicKey,
        D: Digest,
    {
        self.signer.sign(&self.namespace.0, &chunk.encode())
    }
}

/// Verifier for chunk operations.
///
/// The namespace is pre-computed at construction time.
#[derive(Clone)]
pub struct ChunkVerifier {
    namespace: ChunkNamespace,
}

impl ChunkVerifier {
    /// Creates a new ChunkVerifier with the given namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            namespace: ChunkNamespace::derive(namespace),
        }
    }

    /// Verifies a chunk signature.
    pub fn verify<P: PublicKey, D: Digest>(
        &self,
        chunk: &Chunk<P, D>,
        signature: &P::Signature,
    ) -> bool {
        chunk
            .sequencer
            .verify(&self.namespace.0, &chunk.encode(), signature)
    }
}

/// Used as the [crate::Automaton::Context] type.
///
/// Carries the necessary context for the automaton to verify a payload, including
/// the sequencer's public key and its sequencer-specific height.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Context<P: PublicKey> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: Height,
}

impl<P: PublicKey> Heightable for Context<P> {
    fn height(&self) -> Height {
        self.height
    }
}

/// Chunk is a message generated by a sequencer that is broadcasted to all validators.
///
/// A chunk represents a unit of data in the ordered broadcast system. Each sequencer
/// maintains its own chain of chunks with monotonically increasing heights. Validators
/// acknowledge chunks with a vote, which are then aggregated into a certificate to prove
/// reliable broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Chunk<P: PublicKey, D: Digest> {
    /// Sequencer's public key.
    pub sequencer: P,

    /// Sequencer-specific sequential height. Zero-indexed.
    pub height: Height,

    /// Digest of the payload.
    pub payload: D,
}

impl<P: PublicKey, D: Digest> Chunk<P, D> {
    /// Create a new chunk with the given sequencer, height, and payload.
    ///
    /// This is the basic unit of data in the ordered broadcast system.
    pub const fn new(sequencer: P, height: Height, payload: D) -> Self {
        Self {
            sequencer,
            height,
            payload,
        }
    }
}

impl<P: PublicKey, D: Digest> Heightable for Chunk<P, D> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<P: PublicKey, D: Digest> Write for Chunk<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.sequencer.write(writer);
        self.height.write(writer);
        self.payload.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for Chunk<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let sequencer = P::read(reader)?;
        let height = Height::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Self {
            sequencer,
            height,
            payload,
        })
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Chunk<P, D> {
    fn encode_size(&self) -> usize {
        self.sequencer.encode_size() + self.height.encode_size() + self.payload.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, D: Digest> arbitrary::Arbitrary<'_> for Chunk<P, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let sequencer = P::arbitrary(u)?;
        let height = Height::arbitrary(u)?;
        let payload = D::arbitrary(u)?;
        Ok(Self {
            sequencer,
            height,
            payload,
        })
    }
}

/// Namespace type for ordered broadcast acknowledgments.
///
/// This type encapsulates the pre-computed namespace bytes used for signing and
/// verifying acks.
#[derive(Clone, Debug)]
pub struct AckNamespace(Vec<u8>);

impl Namespace for AckNamespace {
    fn derive(namespace: &[u8]) -> Self {
        Self(ack_namespace(namespace))
    }
}

/// Context for signing/verifying validator acknowledgments.
///
/// This is used as the context type for `Scheme` implementations for validators.
/// It contains the chunk being acknowledged and the epoch of the validator set.
#[derive(Debug, Clone)]
pub struct AckSubject<'a, P: PublicKey, D: Digest> {
    /// The chunk being acknowledged.
    pub chunk: &'a Chunk<P, D>,
    /// The epoch of the validator set.
    pub epoch: Epoch,
}

impl<P: PublicKey, D: Digest> Subject for AckSubject<'_, P, D> {
    type Namespace = AckNamespace;

    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        &derived.0
    }

    fn message(&self) -> Bytes {
        let mut message =
            BytesMut::with_capacity(self.chunk.encode_size() + self.epoch.encode_size());
        self.chunk.write(&mut message);
        self.epoch.write(&mut message);
        message.freeze()
    }
}

/// Parent is a message that contains information about the parent (previous height) of a Chunk.
///
/// The sequencer and height are not provided as they are implied by the sequencer and height of the
/// current chunk. The parent includes a certificate which proves that a quorum of validators have
/// seen and acknowledged the parent chunk, making it an essential part of the chain linking
/// mechanism.
#[derive(Clone, Debug)]
pub struct Parent<S: Scheme, D: Digest> {
    /// Digest of the parent chunk.
    pub digest: D,

    /// Epoch of the validator set that signed the parent.
    pub epoch: Epoch,

    /// Certificate over the parent, proving that a quorum of validators
    /// in the specified epoch have acknowledged the parent chunk.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Parent<S, D> {
    /// Create a new parent with the given digest, epoch, and signature.
    ///
    /// The parent links a chunk to its predecessor in the chain and provides
    /// the certificate that proves the predecessor was reliably broadcast.
    pub const fn new(digest: D, epoch: Epoch, certificate: S::Certificate) -> Self {
        Self {
            digest,
            epoch,
            certificate,
        }
    }
}

impl<S: Scheme, D: Digest> PartialEq for Parent<S, D>
where
    S::Certificate: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
            && self.epoch == other.epoch
            && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for Parent<S, D> where S::Certificate: Eq {}

impl<S: Scheme, D: Digest> Hash for Parent<S, D>
where
    S::Certificate: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
        self.epoch.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Parent<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.digest.write(writer);
        self.epoch.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for Parent<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let digest = D::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;
        Ok(Self {
            digest,
            epoch,
            certificate,
        })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Parent<S, D> {
    fn encode_size(&self) -> usize {
        self.digest.encode_size() + self.epoch.encode_size() + self.certificate.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Parent<S, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let digest = u.arbitrary::<D>()?;
        let epoch = u.arbitrary::<Epoch>()?;
        let certificate = u.arbitrary::<S::Certificate>()?;
        Ok(Self {
            digest,
            epoch,
            certificate,
        })
    }
}

/// Node is a message from a sequencer that contains a Chunk and a proof that the parent was correctly broadcasted.
///
/// It represents a newly-proposed tip of the chain for the given sequencer. The node includes:
/// 1. The chunk itself (sequencer, height, payload)
/// 2. The sequencer's signature over the chunk
/// 3. For non-genesis nodes (height > 0), proof that the previous chunk was acknowledged by a quorum of validators
///
/// Nodes form a linked chain from each sequencer, ensuring that new chunks can only be added
/// after their predecessors have been properly acknowledged by the validator set.
#[derive(Clone, Debug)]
pub struct Node<P: PublicKey, S: Scheme, D: Digest> {
    /// Chunk of the node.
    pub chunk: Chunk<P, D>,

    /// Signature of the sequencer over the chunk.
    pub signature: P::Signature,

    /// Information about the parent chunk (previous height)
    ///
    /// This part is not signed over, but it is used to verify that the previous chunk
    /// in the chain was correctly broadcast. It contains the certificate that proves
    /// a quorum of validators acknowledged the parent.
    ///
    /// For genesis nodes (height = 0), this is None.
    pub parent: Option<Parent<S, D>>,
}

impl<P: PublicKey, S: Scheme, D: Digest> Node<P, S, D> {
    /// Create a new node with the given chunk, signature, and parent.
    ///
    /// For genesis nodes (height = 0), parent should be None.
    /// For all other nodes, parent must be provided.
    pub const fn new(
        chunk: Chunk<P, D>,
        signature: P::Signature,
        parent: Option<Parent<S, D>>,
    ) -> Self {
        Self {
            chunk,
            signature,
            parent,
        }
    }

    /// Decode a Node from network bytes with epoch-aware certificate decoding.
    ///
    /// This method performs staged decoding:
    /// 1. Decodes the chunk and signature
    /// 2. Checks if a parent exists
    /// 3. If present, decodes parent fields including epoch
    /// 4. Fetches the appropriate scheme for that epoch from the provider
    /// 5. Decodes the certificate using the epoch-specific bounded codec config
    pub fn read_staged(
        reader: &mut impl Buf,
        provider: &impl Provider<Scope = Epoch, Scheme = S>,
    ) -> Result<Self, CodecError> {
        // Decode chunk and signature
        let chunk = Chunk::read(reader)?;
        let signature = P::Signature::read(reader)?;

        // Decode `Option<()>` to check if parent exists
        // This consumes the bool prefix and positions us correctly
        let parent = if Option::<()>::read(reader)?.is_some() {
            // The bool prefix has been consumed, now read parent fields
            let digest = D::read(reader)?;
            let epoch = Epoch::read(reader)?;

            // Get scheme for parent's epoch
            let scoped = provider.scoped(epoch).ok_or_else(|| {
                CodecError::Wrapped(
                    "consensus::ordered_broadcast::Node::read_staged",
                    Box::new(Error::UnknownScheme(epoch)),
                )
            })?;

            // Decode certificate with epoch-specific bounded config
            let certificate = S::Certificate::read_cfg(reader, &scoped.certificate_codec_config())?;

            Some(Parent {
                digest,
                epoch,
                certificate,
            })
        } else {
            None
        };

        // Validate height/parent consistency
        if chunk.height.is_zero() && parent.is_some() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node::read_staged",
                Box::new(Error::ParentOnGenesis),
            ));
        } else if !chunk.height.is_zero() && parent.is_none() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node::read_staged",
                Box::new(Error::ParentMissing),
            ));
        }

        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }

    /// Signs and creates a new Node.
    ///
    /// This is used by sequencers to create and sign new nodes for broadcast.
    /// For non-genesis nodes (height > 0), a parent with a certificate must be provided.
    pub fn sign<C>(
        signer: &mut ChunkSigner<C>,
        height: Height,
        payload: D,
        parent: Option<Parent<S, D>>,
    ) -> Self
    where
        C: Signer<PublicKey = P, Signature = P::Signature>,
    {
        let chunk = Chunk::new(signer.public_key(), height, payload);
        let signature = signer.sign(&chunk);
        Self::new(chunk, signature, parent)
    }

    /// Verifies a Node (and its parent).
    ///
    /// This ensures:
    /// 1. The sequencer's signature over the chunk is valid
    /// 2. For non-genesis nodes, the parent's certificate is valid
    ///
    /// If verification is successful, returns:
    /// - None for genesis nodes
    /// - Some(parent_chunk) for non-genesis nodes
    ///
    /// If verification fails, returns an appropriate error.
    pub fn verify<R, Pr>(
        &self,
        rng: &mut R,
        verifier: &ChunkVerifier,
        provider: &Pr,
        strategy: &impl Strategy,
    ) -> Result<Option<Chunk<P, D>>, Error>
    where
        R: CryptoRng,
        Pr: Provider<Scope = Epoch, Scheme = S>,
        S: scheme::Scheme<P, D>,
    {
        // Verify chunk signature
        if !verifier.verify(&self.chunk, &self.signature) {
            return Err(Error::InvalidSequencerSignature);
        }
        let Some(parent) = &self.parent else {
            return Ok(None);
        };

        // Verify parent (if present)
        let parent_chunk = Chunk::new(
            self.chunk.sequencer.clone(),
            self.chunk.height.previous().ok_or(Error::ParentMissing)?,
            parent.digest,
        );
        let scoped = provider
            .scoped(parent.epoch)
            .ok_or(Error::UnknownScheme(parent.epoch))?;
        let ctx = AckSubject {
            chunk: &parent_chunk,
            epoch: parent.epoch,
        };
        if !scoped.verify_certificate::<R, D, N3f1>(rng, ctx, &parent.certificate, strategy) {
            return Err(Error::InvalidCertificate);
        }
        Ok(Some(parent_chunk))
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Hash for Node<P, S, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
        self.parent.hash(state);
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> PartialEq for Node<P, S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk
            && self.signature == other.signature
            && self.parent == other.parent
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Eq for Node<P, S, D> {}

impl<P: PublicKey, S: Scheme, D: Digest> Write for Node<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
        self.parent.write(writer);
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Read for Node<P, S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = P::Signature::read(reader)?;
        let parent = <Option<Parent<S, D>>>::read_cfg(reader, cfg)?;
        if chunk.height.is_zero() && parent.is_some() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node",
                Box::new(Error::ParentOnGenesis),
            ));
        } else if !chunk.height.is_zero() && parent.is_none() {
            return Err(CodecError::Wrapped(
                "consensus::ordered_broadcast::Node",
                Box::new(Error::ParentMissing),
            ));
        }
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> EncodeSize for Node<P, S, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.signature.encode_size() + self.parent.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<C: PublicKey, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Node<C, S, D>
where
    C: for<'a> arbitrary::Arbitrary<'a>,
    C::Signature: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let chunk = Chunk::<C, D>::arbitrary(u)?;
        let signature = C::Signature::arbitrary(u)?;
        let parent = if chunk.height.is_zero() {
            None
        } else {
            Some(Parent::<S, D>::arbitrary(u)?)
        };
        Ok(Self {
            chunk,
            signature,
            parent,
        })
    }
}

/// Ack is a message sent by a validator to acknowledge the receipt of a Chunk.
///
/// When a validator receives and validates a chunk, it sends an Ack containing:
/// 1. The chunk being acknowledged
/// 2. The current epoch
/// 3. An attestation over the chunk and epoch
///
/// These attestations from validators can be aggregated to form a certificate
/// once enough validators (a quorum) have acknowledged the chunk. This certificate
/// serves as proof that the chunk was reliably broadcast.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ack<P: PublicKey, S: Scheme, D: Digest> {
    /// Chunk that is being acknowledged.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Attestation for this chunk.
    ///
    /// This is a cryptographic attestation that can be combined with other attestations
    /// to form a certificate once a quorum is reached.
    pub attestation: Attestation<S>,
}

impl<P: PublicKey, S: Scheme, D: Digest> Ack<P, S, D> {
    /// Create a new ack with the given chunk, epoch, and attestation.
    pub const fn new(chunk: Chunk<P, D>, epoch: Epoch, attestation: Attestation<S>) -> Self {
        Self {
            chunk,
            epoch,
            attestation,
        }
    }

    /// Verify the Ack.
    ///
    /// This ensures that the attestation is valid for the given chunk and epoch,
    /// using the provided scheme.
    ///
    /// Returns true if the attestation is valid, false otherwise.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<P, D>,
    {
        let ctx = AckSubject {
            chunk: &self.chunk,
            epoch: self.epoch,
        };
        scheme.verify_attestation::<_, D>(rng, ctx, &self.attestation, strategy)
    }

    /// Generate a new Ack by signing with the provided scheme.
    ///
    /// This is used by validators to create and sign new acknowledgments for chunks.
    /// Returns None if the scheme cannot sign.
    pub fn sign(scheme: &S, chunk: Chunk<P, D>, epoch: Epoch) -> Option<Self>
    where
        S: scheme::Scheme<P, D>,
    {
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestation = scheme.sign::<D>(ctx)?;
        Some(Self::new(chunk, epoch, attestation))
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Write for Ack<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.attestation.write(writer);
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Read for Ack<P, S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let attestation = Attestation::read(reader)?;
        Ok(Self {
            chunk,
            epoch,
            attestation,
        })
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> EncodeSize for Ack<P, S, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.epoch.encode_size() + self.attestation.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Ack<P, S, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let chunk = Chunk::<P, D>::arbitrary(u)?;
        let epoch = u.arbitrary::<Epoch>()?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self {
            chunk,
            epoch,
            attestation,
        })
    }
}

/// Activity is the type associated with the [crate::Reporter] trait.
///
/// This enum represents the two main types of activities that are reported:
/// 1. Tips - when a new chunk at the latest tip is verified for some sequencer
/// 2. Locks - when a certificate is formed for a chunk
///
/// The Reporter is notified of these activities so it can track the state of the system
/// and provide the appropriate information to other components.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq)]
pub enum Activity<P: PublicKey, S: Scheme, D: Digest> {
    /// A new tip for a sequencer
    ///
    /// This activity is only emitted when the application has verified some peer proposal.
    Tip(Proposal<P, D>),
    /// A certificate for a chunk, indicating it has been acknowledged by a quorum
    Lock(Lock<P, S, D>),
}

impl<P: PublicKey, S: Scheme, D: Digest> Write for Activity<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Tip(proposal) => {
                0u8.write(writer);
                proposal.write(writer);
            }
            Self::Lock(lock) => {
                1u8.write(writer);
                lock.write(writer);
            }
        }
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Read for Activity<P, S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Tip(Proposal::read(reader)?)),
            1 => Ok(Self::Lock(Lock::read_cfg(reader, cfg)?)),
            _ => Err(CodecError::Invalid(
                "consensus::ordered_broadcast::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> EncodeSize for Activity<P, S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Tip(proposal) => proposal.encode_size(),
            Self::Lock(lock) => lock.encode_size(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<C: PublicKey, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Activity<C, S, D>
where
    Proposal<C, D>: for<'a> arbitrary::Arbitrary<'a>,
    Lock<C, S, D>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let choice = u.int_in_range(0..=1)?;
        match choice {
            0 => Ok(Self::Tip(Proposal::<C, D>::arbitrary(u)?)),
            1 => Ok(Self::Lock(Lock::<C, S, D>::arbitrary(u)?)),
            _ => unreachable!(),
        }
    }
}

/// Proposal is a message that is generated by a sequencer when proposing a new chunk.
///
/// This represents a new chunk that has been created by a sequencer and is being
/// broadcast to validators for acknowledgment. It contains the chunk itself and the
/// sequencer's signature over that chunk.
#[derive(Clone, Debug)]
pub struct Proposal<P: PublicKey, D: Digest> {
    /// Chunk that is being proposed.
    pub chunk: Chunk<P, D>,

    /// Signature over the chunk.
    /// This is the sequencer's signature proving authenticity of the chunk.
    pub signature: P::Signature,
}

impl<P: PublicKey, D: Digest> Proposal<P, D> {
    /// Create a new Proposal with the given chunk and signature.
    pub const fn new(chunk: Chunk<P, D>, signature: P::Signature) -> Self {
        Self { chunk, signature }
    }

    /// Verifies the proposal's signature.
    ///
    /// Returns true if the sequencer's signature over the chunk is valid.
    pub fn verify(&self, verifier: &ChunkVerifier) -> bool {
        verifier.verify(&self.chunk, &self.signature)
    }
}

impl<P: PublicKey, D: Digest> Hash for Proposal<P, D> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.chunk.hash(state);
        self.signature.hash(state);
    }
}

impl<P: PublicKey, D: Digest> PartialEq for Proposal<P, D> {
    fn eq(&self, other: &Self) -> bool {
        self.chunk == other.chunk && self.signature == other.signature
    }
}

/// This is needed to implement `Eq` for `Proposal`.
impl<P: PublicKey, D: Digest> Eq for Proposal<P, D> {}

impl<P: PublicKey, D: Digest> Write for Proposal<P, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.signature.write(writer);
    }
}

impl<P: PublicKey, D: Digest> Read for Proposal<P, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let signature = P::Signature::read(reader)?;
        Ok(Self { chunk, signature })
    }
}

impl<P: PublicKey, D: Digest> EncodeSize for Proposal<P, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.signature.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<C: PublicKey, D: Digest> arbitrary::Arbitrary<'_> for Proposal<C, D>
where
    Chunk<C, D>: for<'a> arbitrary::Arbitrary<'a>,
    C::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let chunk = Chunk::<C, D>::arbitrary(u)?;
        let signature = C::Signature::arbitrary(u)?;
        Ok(Self { chunk, signature })
    }
}

/// Lock is a message that can be generated once `2f + 1` acks are received for a Chunk.
///
/// A Lock represents proof that a quorum of validators (at least 2f+1, where f is the
/// maximum number of faulty validators) have acknowledged a chunk. This proof is in the
/// form of a certificate that can be verified by anyone.
///
/// The Lock is essential for:
/// 1. Proving that a chunk has been reliably broadcast
/// 2. Allowing sequencers to build chains of chunks
/// 3. Preventing sequencers from creating forks in their chains
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Lock<P: PublicKey, S: Scheme, D: Digest> {
    /// Chunk that is being locked.
    pub chunk: Chunk<P, D>,

    /// Epoch of the validator set.
    pub epoch: Epoch,

    /// Recovered certificate over the chunk.
    /// This is a cryptographic proof that proves a quorum of validators
    /// have acknowledged the chunk.
    pub certificate: S::Certificate,
}

impl<P: PublicKey, S: Scheme, D: Digest> Lock<P, S, D> {
    /// Create a new Lock with the given chunk, epoch, and certificate.
    pub const fn new(chunk: Chunk<P, D>, epoch: Epoch, certificate: S::Certificate) -> Self {
        Self {
            chunk,
            epoch,
            certificate,
        }
    }

    /// Verify the Lock.
    ///
    /// This ensures that the certificate is valid for the given chunk and epoch,
    /// using the provided scheme.
    ///
    /// Returns true if the signature is valid, false otherwise.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<P, D>,
    {
        let ctx = AckSubject {
            chunk: &self.chunk,
            epoch: self.epoch,
        };
        scheme.verify_certificate::<R, D, N3f1>(rng, ctx, &self.certificate, strategy)
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Write for Lock<P, S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.chunk.write(writer);
        self.epoch.write(writer);
        self.certificate.write(writer);
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> Read for Lock<P, S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let chunk = Chunk::read(reader)?;
        let epoch = Epoch::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;
        Ok(Self {
            chunk,
            epoch,
            certificate,
        })
    }
}

impl<P: PublicKey, S: Scheme, D: Digest> EncodeSize for Lock<P, S, D> {
    fn encode_size(&self) -> usize {
        self.chunk.encode_size() + self.epoch.encode_size() + self.certificate.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<P: PublicKey, S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Lock<P, S, D>
where
    P: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            chunk: u.arbitrary()?,
            epoch: u.arbitrary()?,
            certificate: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ordered_broadcast::{
            mocks::Provider,
            scheme::{bls12381_multisig, bls12381_threshold, ed25519, secp256r1, Scheme},
        },
        types::Participant,
    };
    use commonware_codec::{DecodeExt as _, Encode, Read};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::{mocks::Fixture, ConstantProvider},
        ed25519::{PrivateKey, PublicKey},
        sha256::Digest as Sha256Digest,
        Signer,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1, TestRng};
    use std::panic::catch_unwind;

    const NAMESPACE: &[u8] = b"test";

    fn chunk_verifier() -> ChunkVerifier {
        ChunkVerifier::new(NAMESPACE)
    }

    fn chunk_signer(signer: PrivateKey) -> ChunkSigner<PrivateKey> {
        ChunkSigner::new(NAMESPACE, signer)
    }

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256Digest {
        Sha256Digest::from([v; 32]) // Simple fixed digest for testing
    }

    // Helper function to create a sample Ed25519 private key
    fn sample_scheme(v: u64) -> PrivateKey {
        PrivateKey::from_seed(v)
    }

    /// Generate a fixture using the provided generator function with a specific seed.
    fn setup_seeded<S, F>(n: u32, seed: u64, fixture: F) -> Fixture<S>
    where
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = TestRng::new(seed);
        fixture(&mut rng, NAMESPACE, n)
    }

    #[test]
    fn test_chunk_encode_decode() {
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let encoded = chunk.encode();
        let decoded = Chunk::<PublicKey, Sha256Digest>::decode(encoded).unwrap();
        assert_eq!(chunk, decoded);
    }

    // Tests migrated to use Scheme-based API
    fn parent_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            Height::zero(),
            sample_digest(1),
        );
        let epoch = Epoch::new(5);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Generate acks from quorum validators
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();

        // Assemble certificate
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create and test parent
        let parent = Parent::<S, Sha256Digest>::new(sample_digest(1), epoch, certificate);
        let encoded = parent.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Parent::<S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(parent, decoded);
    }

    #[test]
    fn test_parent_encode_decode() {
        parent_encode_decode(ed25519::fixture);
        parent_encode_decode(secp256r1::fixture);
        parent_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        parent_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        parent_encode_decode(bls12381_threshold::fixture::<MinPk, _>);
        parent_encode_decode(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let ed_scheme = sample_scheme(0);
        let public_key = ed_scheme.public_key();
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;
        let cfg = fixture.schemes[0].certificate_codec_config();

        // Test with no parent (genesis)
        let chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(1));
        let message = chunk.encode();
        let signature = ed_scheme.sign(chunk_namespace.as_ref(), &message);

        let node = Node::<PublicKey, S, Sha256Digest>::new(chunk, signature, None);
        let encoded = node.encode();
        let decoded =
            Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
        assert_eq!(decoded.chunk, node.chunk);
        assert_eq!(decoded.signature, node.signature);
        assert_eq!(decoded.parent, node.parent);

        // Test with parent - generate a proper certificate
        let parent_chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(0));
        let parent_epoch = Epoch::new(5);

        // Generate parent certificate
        let parent_ctx = AckSubject {
            chunk: &parent_chunk,
            epoch: parent_epoch,
        };
        let parent_attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(parent_ctx.clone()).unwrap())
            .collect();

        let parent_certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(parent_attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create proper parent with valid certificate
        let parent = Some(Parent::<S, Sha256Digest>::new(
            parent_chunk.payload,
            parent_epoch,
            parent_certificate,
        ));

        // Create child node
        let chunk2 = Chunk::new(public_key, Height::new(1), sample_digest(2));
        let message2 = chunk2.encode();
        let signature2 = ed_scheme.sign(chunk_namespace.as_ref(), &message2);
        let node2 = Node::<PublicKey, S, Sha256Digest>::new(chunk2, signature2, parent);

        // Test encode/decode
        let encoded2 = node2.encode();
        let decoded2 =
            Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded2.as_ref(), &cfg).unwrap();
        assert_eq!(decoded2.chunk, node2.chunk);
        assert_eq!(decoded2.signature, node2.signature);
        assert_eq!(decoded2.parent, node2.parent);
    }

    #[test]
    fn test_node_encode_decode() {
        node_encode_decode(ed25519::fixture);
        node_encode_decode(secp256r1::fixture);
        node_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        node_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        node_encode_decode(bls12381_threshold::fixture::<MinPk, _>);
        node_encode_decode(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_read_staged<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);

        // Create a provider that returns the verifier for any epoch.
        // This simulates the normal case where the scheme is available.
        let provider = ConstantProvider::new(fixture.verifier.clone());

        // Create common test data: a sequencer public key and the chunk namespace.
        let public_key = fixture.participants[0].clone();
        let chunk_namespace = chunk_namespace(NAMESPACE);

        // Genesis nodes have no parent certificate, so read_staged should succeed
        // without needing to look up a scheme for the parent's epoch.
        let genesis_chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(1));
        let genesis_message = genesis_chunk.encode();
        let genesis_signature =
            fixture.private_keys[0].sign(chunk_namespace.as_ref(), &genesis_message);

        let genesis_node =
            Node::<PublicKey, S, Sha256Digest>::new(genesis_chunk.clone(), genesis_signature, None);
        let encoded = genesis_node.encode();
        let decoded =
            Node::<PublicKey, S, Sha256Digest>::read_staged(&mut encoded.as_ref(), &provider)
                .expect("Should decode genesis node");

        assert_eq!(decoded.chunk, genesis_node.chunk);
        assert_eq!(decoded.signature, genesis_node.signature);
        assert_eq!(decoded.parent, genesis_node.parent);

        // Non-genesis nodes have a parent with a certificate. read_staged must
        // look up the scheme for the parent's epoch to decode the certificate.
        let parent_epoch = Epoch::new(5);
        let parent_ctx = AckSubject {
            chunk: &genesis_chunk,
            epoch: parent_epoch,
        };

        // Collect signatures from a quorum of validators to form the parent certificate.
        let parent_attestations: Vec<_> = fixture.schemes[..N3f1::quorum(4) as usize]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(parent_ctx.clone()).unwrap())
            .collect();
        let parent_certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(parent_attestations, &Sequential)
            .expect("Should assemble certificate");

        let parent =
            Parent::<S, Sha256Digest>::new(sample_digest(0), parent_epoch, parent_certificate);

        let chunk_height_1 = Chunk::new(public_key, Height::new(1), sample_digest(2));
        let message_height_1 = chunk_height_1.encode();
        let signature_height_1 =
            fixture.private_keys[0].sign(chunk_namespace.as_ref(), &message_height_1);

        let node_with_parent = Node::<PublicKey, S, Sha256Digest>::new(
            chunk_height_1,
            signature_height_1,
            Some(parent),
        );

        let encoded2 = node_with_parent.encode();
        let decoded2 =
            Node::<PublicKey, S, Sha256Digest>::read_staged(&mut encoded2.as_ref(), &provider)
                .expect("Should decode non-genesis node");

        assert_eq!(decoded2.chunk, node_with_parent.chunk);
        assert_eq!(decoded2.signature, node_with_parent.signature);
        assert_eq!(decoded2.parent, node_with_parent.parent);

        // When the provider doesn't have a scheme registered for the parent's epoch,
        // read_staged should return an UnknownScheme error.
        let empty_provider = Provider::<S>::new();

        let result = Node::<PublicKey, S, Sha256Digest>::read_staged(
            &mut encoded2.as_ref(),
            &empty_provider,
        );

        assert!(
            result.is_err(),
            "Should fail when scheme is missing for parent's epoch"
        );
    }

    #[test]
    fn test_node_read_staged() {
        node_read_staged(ed25519::fixture);
        node_read_staged(secp256r1::fixture);
        node_read_staged(bls12381_multisig::fixture::<MinPk, _>);
        node_read_staged(bls12381_multisig::fixture::<MinSig, _>);
        node_read_staged(bls12381_threshold::fixture::<MinPk, _>);
        node_read_staged(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn ack_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let fixture = fixture(&mut test_rng(), NAMESPACE, 4);
        let chunk = Chunk::new(
            fixture.participants[0].clone(),
            Height::new(42),
            sample_digest(1),
        );
        let epoch = Epoch::new(5);

        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestation = fixture.schemes[0]
            .sign::<Sha256Digest>(ctx)
            .expect("Should sign vote");

        let ack = Ack::<PublicKey, S, Sha256Digest> {
            chunk,
            epoch,
            attestation,
        };
        let encoded = ack.encode();
        let decoded =
            Ack::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &()).unwrap();

        assert_eq!(decoded.chunk, ack.chunk);
        assert_eq!(decoded.epoch, ack.epoch);
        assert_eq!(decoded.attestation.signer, ack.attestation.signer);
    }

    #[test]
    fn test_ack_encode_decode() {
        ack_encode_decode(ed25519::fixture);
        ack_encode_decode(secp256r1::fixture);
        ack_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        ack_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        ack_encode_decode(bls12381_threshold::fixture::<MinPk, _>);
        ack_encode_decode(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn activity_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;
        let cfg = fixture.schemes[0].certificate_codec_config();

        // Test Proposal
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk.clone(), signature.clone());
        let activity = Activity::<PublicKey, S, _>::Tip(proposal);
        let encoded = activity.encode();
        let decoded =
            Activity::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();

        match decoded {
            Activity::Tip(p) => {
                assert_eq!(p.chunk, chunk);
                assert_eq!(p.signature, signature);
            }
            _ => panic!("Decoded activity has wrong type"),
        }

        // Test Lock with proper certificate
        let epoch = Epoch::new(5);

        // Generate votes from quorum validators
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();

        // Assemble certificate
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock
        let lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk.clone(), epoch, certificate);

        // Verify lock
        assert!(lock.verify(&mut rng, &fixture.verifier, &Sequential));

        // Test activity with the lock
        let activity = Activity::<PublicKey, S, Sha256Digest>::Lock(lock.clone());
        let encoded = activity.encode();
        let decoded =
            Activity::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();

        match decoded {
            Activity::Lock(l) => {
                assert_eq!(l.chunk, chunk);
                assert_eq!(l.epoch, epoch);
                assert!(l.verify(&mut rng, &fixture.verifier, &Sequential));
            }
            _ => panic!("Decoded activity has wrong type"),
        }
    }

    #[test]
    fn test_activity_encode_decode() {
        activity_encode_decode(ed25519::fixture);
        activity_encode_decode(secp256r1::fixture);
        activity_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        activity_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        activity_encode_decode(bls12381_threshold::fixture::<MinPk, _>);
        activity_encode_decode(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test]
    fn test_proposal_encode_decode() {
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));

        // Create a properly signed proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);

        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);
        let encoded = proposal.encode();
        let decoded = Proposal::<PublicKey, Sha256Digest>::decode(encoded).unwrap();

        assert_eq!(decoded.chunk, proposal.chunk);
        assert_eq!(decoded.signature, proposal.signature);

        // Verify the decoded proposal
        let verifier = chunk_verifier();
        assert!(decoded.verify(&verifier));
    }

    fn lock_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Generate votes from quorum validators
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();

        // Assemble certificate
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock, encode and decode
        let lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk, epoch, certificate);
        let encoded = lock.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded =
            Lock::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();

        assert_eq!(decoded.chunk, lock.chunk);
        assert_eq!(decoded.epoch, lock.epoch);

        // Verify the signature in the decoded lock
        assert!(decoded.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn test_lock_encode_decode() {
        lock_encode_decode(ed25519::fixture);
        lock_encode_decode(secp256r1::fixture);
        lock_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        lock_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        lock_encode_decode(bls12381_threshold::fixture::<MinPk, _>);
        lock_encode_decode(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_sign_verify<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let mut signer = chunk_signer(scheme);
        let verifier = chunk_verifier();
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Test genesis node (no parent)
        let node: Node<PublicKey, S, Sha256Digest> =
            Node::sign(&mut signer, Height::zero(), sample_digest(1), None);
        let provider = ConstantProvider::new(fixture.verifier.clone());
        let result = node.verify(&mut rng, &verifier, &provider, &Sequential);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Test node with parent
        let parent_chunk = Chunk::new(public_key, Height::zero(), sample_digest(1));
        let parent_epoch = Epoch::new(5);

        // Create certificate for parent
        let parent_ctx = AckSubject {
            chunk: &parent_chunk,
            epoch: parent_epoch,
        };
        let parent_attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(parent_ctx.clone()).unwrap())
            .collect();
        let parent_certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(parent_attestations, &Sequential)
            .expect("Should assemble certificate");

        let parent = Some(Parent::<S, Sha256Digest>::new(
            parent_chunk.payload,
            parent_epoch,
            parent_certificate,
        ));
        let node: Node<PublicKey, S, Sha256Digest> =
            Node::sign(&mut signer, Height::new(1), sample_digest(2), parent);

        let result = node.verify(&mut rng, &verifier, &provider, &Sequential);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_node_sign_verify() {
        node_sign_verify(ed25519::fixture);
        node_sign_verify(secp256r1::fixture);
        node_sign_verify(bls12381_multisig::fixture::<MinPk, _>);
        node_sign_verify(bls12381_multisig::fixture::<MinSig, _>);
        node_sign_verify(bls12381_threshold::fixture::<MinPk, _>);
        node_sign_verify(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn ack_sign_verify<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);

        let ack = Ack::sign(&fixture.schemes[0], chunk, epoch).expect("Should sign ack");
        assert!(ack.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn test_ack_sign_verify() {
        ack_sign_verify(ed25519::fixture);
        ack_sign_verify(secp256r1::fixture);
        ack_sign_verify(bls12381_multisig::fixture::<MinPk, _>);
        ack_sign_verify(bls12381_multisig::fixture::<MinSig, _>);
        ack_sign_verify(bls12381_threshold::fixture::<MinPk, _>);
        ack_sign_verify(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn certificate_assembly<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Create quorum votes
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();

        // Assemble certificate
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock with certificate
        let lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk, epoch, certificate);

        // Verify lock
        assert!(lock.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn test_certificate_assembly() {
        certificate_assembly(ed25519::fixture);
        certificate_assembly(secp256r1::fixture);
        certificate_assembly(bls12381_multisig::fixture::<MinPk, _>);
        certificate_assembly(bls12381_multisig::fixture::<MinSig, _>);
        certificate_assembly(bls12381_threshold::fixture::<MinPk, _>);
        certificate_assembly(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn lock_verify<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Create certificate
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock
        let lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk, epoch, certificate);

        // Verify lock
        assert!(lock.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn test_lock_verify() {
        lock_verify(ed25519::fixture);
        lock_verify(secp256r1::fixture);
        lock_verify(bls12381_multisig::fixture::<MinPk, _>);
        lock_verify(bls12381_multisig::fixture::<MinSig, _>);
        lock_verify(bls12381_threshold::fixture::<MinPk, _>);
        lock_verify(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test]
    fn test_proposal_verify() {
        let scheme = sample_scheme(0);
        let chunk = Chunk::new(scheme.public_key(), Height::new(42), sample_digest(1));

        // Sign and create proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verify proposal
        let verifier = chunk_verifier();
        assert!(proposal.verify(&verifier));

        // Test that verification fails with wrong namespace
        let wrong_verifier = ChunkVerifier::new(b"wrong");
        assert!(!proposal.verify(&wrong_verifier));
    }

    fn node_verify_invalid_signature<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();

        // Create a valid chunk
        let chunk = Chunk::new(public_key, Height::zero(), sample_digest(1));

        // Create a valid signature
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);

        // Create a node with valid signature
        let node = Node::<PublicKey, S, Sha256Digest>::new(chunk.clone(), signature, None);

        // Verification should succeed
        let provider = ConstantProvider::new(fixture.verifier);
        let verifier = chunk_verifier();
        assert!(node
            .verify(&mut rng, &verifier, &provider, &Sequential)
            .is_ok());

        // Now create a node with invalid signature
        let tampered_signature = scheme.sign(chunk_namespace.as_ref(), &node.encode());
        let invalid_node = Node::<PublicKey, S, Sha256Digest>::new(chunk, tampered_signature, None);

        // Verification should fail
        assert!(matches!(
            invalid_node.verify(&mut rng, &verifier, &provider, &Sequential),
            Err(Error::InvalidSequencerSignature)
        ));
    }

    #[test]
    fn test_node_verify_invalid_signature() {
        node_verify_invalid_signature(ed25519::fixture);
        node_verify_invalid_signature(secp256r1::fixture);
        node_verify_invalid_signature(bls12381_multisig::fixture::<MinPk, _>);
        node_verify_invalid_signature(bls12381_multisig::fixture::<MinSig, _>);
        node_verify_invalid_signature(bls12381_threshold::fixture::<MinPk, _>);
        node_verify_invalid_signature(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_verify_invalid_parent_signature<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        let scheme = sample_scheme(0);
        let public_key = scheme.public_key();
        let quorum = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Create parent and child chunks
        let parent_chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(0));
        let child_chunk = Chunk::new(public_key, Height::new(1), sample_digest(1));
        let epoch = Epoch::new(5);

        // Generate a valid certificate for the parent
        let parent_ctx = AckSubject {
            chunk: &parent_chunk,
            epoch,
        };
        let parent_attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(parent_ctx.clone()).unwrap())
            .collect();
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(parent_attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create parent with valid certificate
        let parent = Parent::<S, Sha256Digest>::new(parent_chunk.payload, epoch, certificate);

        // Create child node
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = child_chunk.encode();
        let node_signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let node = Node::<PublicKey, S, Sha256Digest>::new(
            child_chunk.clone(),
            node_signature.clone(),
            Some(parent),
        );

        // Verification should succeed
        let provider = ConstantProvider::new(fixture.verifier.clone());
        let verifier = chunk_verifier();
        assert!(node
            .verify(&mut rng, &verifier, &provider, &Sequential)
            .is_ok());

        // Now create a parent with invalid certificate
        // Generate certificate with the wrong keys (sign with schemes[1..] but pretend it's from schemes[0..])
        let wrong_ctx = AckSubject {
            chunk: &parent_chunk,
            epoch: Epoch::new(99), // Different epoch to get different signatures
        };
        let wrong_attestations: Vec<_> = fixture.schemes[..quorum]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(wrong_ctx.clone()).unwrap())
            .collect();
        let wrong_certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(wrong_attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create parent with certificate signed for wrong context (wrong epoch)
        let wrong_parent =
            Parent::<S, Sha256Digest>::new(parent_chunk.payload, epoch, wrong_certificate);

        // Create child node with wrong parent
        let node = Node::<PublicKey, S, Sha256Digest>::new(
            child_chunk,
            node_signature,
            Some(wrong_parent),
        );

        // Verification should fail because the parent certificate was signed for different epoch
        assert!(matches!(
            node.verify(&mut rng, &verifier, &provider, &Sequential),
            Err(Error::InvalidCertificate)
        ));
    }

    #[test]
    fn test_node_verify_invalid_parent_signature() {
        node_verify_invalid_parent_signature(ed25519::fixture);
        node_verify_invalid_parent_signature(secp256r1::fixture);
        node_verify_invalid_parent_signature(bls12381_multisig::fixture::<MinPk, _>);
        node_verify_invalid_parent_signature(bls12381_multisig::fixture::<MinSig, _>);
        node_verify_invalid_parent_signature(bls12381_threshold::fixture::<MinPk, _>);
        node_verify_invalid_parent_signature(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn ack_verify_invalid_signature<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        // Create a chunk and ack
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);

        // Create a valid ack
        let ack =
            Ack::<PublicKey, S, Sha256Digest>::sign(&fixture.schemes[0], chunk.clone(), epoch)
                .expect("Should sign ack");

        // Verification should succeed
        assert!(ack.verify(&mut rng, &fixture.verifier, &Sequential));

        // Create an ack with tampered signature by signing with a different scheme
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let mut tampered_vote = fixture.schemes[1]
            .sign::<Sha256Digest>(ctx)
            .expect("Should sign vote");
        // Change the signer index to mismatch with the actual signature
        // The vote was signed by validator 1, but we claim it's from validator 0
        tampered_vote.signer = Participant::new(0);
        let invalid_ack = Ack::<PublicKey, S, Sha256Digest>::new(chunk, epoch, tampered_vote);

        // Verification should fail because the signer index doesn't match the signature
        assert!(!invalid_ack.verify(&mut rng, &fixture.verifier, &Sequential));
    }

    #[test]
    fn test_ack_verify_invalid_signature() {
        ack_verify_invalid_signature(ed25519::fixture);
        ack_verify_invalid_signature(secp256r1::fixture);
        ack_verify_invalid_signature(bls12381_multisig::fixture::<MinPk, _>);
        ack_verify_invalid_signature(bls12381_multisig::fixture::<MinSig, _>);
        ack_verify_invalid_signature(bls12381_threshold::fixture::<MinPk, _>);
        ack_verify_invalid_signature(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn ack_verify_wrong_validator<S, F>(f: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(4, 0, &f);
        let wrong_fixture = setup_seeded(4, 1, &f);
        // Create a chunk and ack
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);

        // Create a valid ack
        let ack = Ack::<PublicKey, S, Sha256Digest>::sign(&fixture.schemes[0], chunk, epoch)
            .expect("Should sign ack");

        // Verification should succeed with correct verifier
        assert!(ack.verify(&mut rng, &fixture.verifier, &Sequential));

        // Verification should fail with wrong verifier
        assert!(!ack.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_ack_verify_wrong_validator() {
        ack_verify_wrong_validator(ed25519::fixture);
        ack_verify_wrong_validator(secp256r1::fixture);
        ack_verify_wrong_validator(bls12381_multisig::fixture::<MinPk, _>);
        ack_verify_wrong_validator(bls12381_multisig::fixture::<MinSig, _>);
        ack_verify_wrong_validator(bls12381_threshold::fixture::<MinPk, _>);
        ack_verify_wrong_validator(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn lock_verify_invalid_signature<S, F>(f: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(4, 0, &f);
        let wrong_fixture = setup_seeded(4, 1, &f);
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(42), sample_digest(1));
        let epoch = Epoch::new(5);
        let quorum_size = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Generate certificate
        let ctx = AckSubject {
            chunk: &chunk,
            epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum_size]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock
        let lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk.clone(), epoch, certificate);

        // Verification should succeed
        assert!(lock.verify(&mut rng, &fixture.verifier, &Sequential));

        // Generate certificate with the wrong keys
        let wrong_attestations: Vec<_> = wrong_fixture.schemes[..quorum_size]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();
        let wrong_certificate = wrong_fixture.schemes[0]
            .assemble::<_, N3f1>(wrong_attestations, &Sequential)
            .expect("Should assemble certificate");

        // Create lock with wrong signature
        let wrong_lock = Lock::<PublicKey, S, Sha256Digest>::new(chunk, epoch, wrong_certificate);

        // Verification should fail with the original public key
        assert!(!wrong_lock.verify(&mut rng, &fixture.verifier, &Sequential));

        // But succeed with the matching wrong verifier
        assert!(wrong_lock.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_lock_verify_invalid_signature() {
        lock_verify_invalid_signature(ed25519::fixture);
        lock_verify_invalid_signature(secp256r1::fixture);
        lock_verify_invalid_signature(bls12381_multisig::fixture::<MinPk, _>);
        lock_verify_invalid_signature(bls12381_multisig::fixture::<MinSig, _>);
        lock_verify_invalid_signature(bls12381_threshold::fixture::<MinPk, _>);
        lock_verify_invalid_signature(bls12381_threshold::fixture::<MinSig, _>);
    }

    #[test]
    fn test_proposal_verify_wrong_namespace() {
        let scheme = sample_scheme(0);
        let chunk = Chunk::new(scheme.public_key(), Height::new(42), sample_digest(1));

        // Sign and create proposal
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verify with correct namespace - should pass
        let verifier = chunk_verifier();
        assert!(proposal.verify(&verifier));

        // Verify with wrong namespace - should fail
        let wrong_verifier = ChunkVerifier::new(b"wrong_namespace");
        assert!(!proposal.verify(&wrong_verifier));
    }

    #[test]
    fn test_proposal_verify_wrong_sequencer() {
        let scheme1 = sample_scheme(0);
        let scheme2 = sample_scheme(1); // Different key

        // Create chunk with scheme1's public key
        let chunk = Chunk::new(scheme1.public_key(), Height::new(42), sample_digest(1));

        // But sign it with scheme2 (wrong key)
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = scheme2.sign(chunk_namespace.as_ref(), &message);
        let proposal = Proposal::<PublicKey, Sha256Digest>::new(chunk, signature);

        // Verification should fail because the signature doesn't match the sequencer's public key
        let verifier = chunk_verifier();
        assert!(!proposal.verify(&verifier));
    }

    fn node_genesis_with_parent_fails<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        // Try to create a node with height 0 and a parent
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);
        let quorum_size = N3f1::quorum(fixture.schemes.len() as u32) as usize;

        // Create a parent with a dummy certificate (content doesn't matter for this test)
        let dummy_chunk = Chunk::new(public_key, Height::zero(), sample_digest(0));
        let dummy_epoch = Epoch::new(5);
        let ctx = AckSubject {
            chunk: &dummy_chunk,
            epoch: dummy_epoch,
        };
        let attestations: Vec<_> = fixture.schemes[..quorum_size]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(ctx.clone()).unwrap())
            .collect();
        let certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("Should assemble certificate");

        let parent = Parent::<S, Sha256Digest>::new(sample_digest(0), Epoch::new(5), certificate);

        // Create the genesis node with a parent - should fail to decode
        let encoded =
            Node::<PublicKey, S, Sha256Digest>::new(chunk, signature, Some(parent)).encode();

        // This should error because genesis nodes can't have parents
        let cfg = fixture.schemes[0].certificate_codec_config();
        let result = Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_genesis_with_parent_fails() {
        node_genesis_with_parent_fails(ed25519::fixture);
        node_genesis_with_parent_fails(secp256r1::fixture);
        node_genesis_with_parent_fails(bls12381_multisig::fixture::<MinPk, _>);
        node_genesis_with_parent_fails(bls12381_multisig::fixture::<MinSig, _>);
        node_genesis_with_parent_fails(bls12381_threshold::fixture::<MinPk, _>);
        node_genesis_with_parent_fails(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_non_genesis_without_parent_fails<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);
        // Try to create a non-genesis node without a parent
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(1), sample_digest(1)); // Height > 0
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Create the node without a parent - should fail to decode
        let encoded = Node::<PublicKey, S, Sha256Digest>::new(chunk, signature, None).encode();

        // This should error because non-genesis nodes must have parents
        let cfg = fixture.schemes[0].certificate_codec_config();
        let result = Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg);
        assert!(result.is_err());
    }

    #[test]
    fn test_node_non_genesis_without_parent_fails() {
        node_non_genesis_without_parent_fails(ed25519::fixture);
        node_non_genesis_without_parent_fails(secp256r1::fixture);
        node_non_genesis_without_parent_fails(bls12381_multisig::fixture::<MinPk, _>);
        node_non_genesis_without_parent_fails(bls12381_multisig::fixture::<MinSig, _>);
        node_non_genesis_without_parent_fails(bls12381_threshold::fixture::<MinPk, _>);
        node_non_genesis_without_parent_fails(bls12381_threshold::fixture::<MinSig, _>);
    }

    fn node_genesis_with_parent_panics<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);

        // Try to create a genesis node (height 0) with a parent - should panic in Node::new
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key.clone(), Height::zero(), sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Generate a valid parent certificate
        let parent_chunk = Chunk::new(public_key, Height::zero(), sample_digest(0));
        let parent_epoch = Epoch::new(5);
        let parent_ctx = AckSubject {
            chunk: &parent_chunk,
            epoch: parent_epoch,
        };
        let parent_attestations: Vec<_> = fixture.schemes[..N3f1::quorum(4) as usize]
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(parent_ctx.clone()).unwrap())
            .collect();
        let parent_certificate = fixture.schemes[0]
            .assemble::<_, N3f1>(parent_attestations, &Sequential)
            .expect("Should assemble certificate");

        let parent =
            Parent::<S, Sha256Digest>::new(sample_digest(0), parent_epoch, parent_certificate);

        // Create invalid node (genesis with parent), encode it, then decode - should panic on unwrap
        let encoded =
            Node::<PublicKey, S, Sha256Digest>::new(chunk, signature, Some(parent)).encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
    }

    #[test]
    fn test_node_genesis_with_parent_panics() {
        assert!(catch_unwind(|| node_genesis_with_parent_panics(ed25519::fixture)).is_err());
        assert!(catch_unwind(|| node_genesis_with_parent_panics(secp256r1::fixture)).is_err());
        assert!(catch_unwind(|| node_genesis_with_parent_panics(
            bls12381_multisig::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_genesis_with_parent_panics(
            bls12381_multisig::fixture::<MinSig, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_genesis_with_parent_panics(
            bls12381_threshold::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_genesis_with_parent_panics(
            bls12381_threshold::fixture::<MinSig, _>
        ))
        .is_err());
    }

    fn node_non_genesis_without_parent_panics<S, F>(fixture: F)
    where
        S: Scheme<PublicKey, Sha256Digest>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 4);

        // Try to create a non-genesis node (height > 0) without a parent - should panic on decode
        let public_key = sample_scheme(0).public_key();
        let chunk = Chunk::new(public_key, Height::new(1), sample_digest(1));
        let chunk_namespace = chunk_namespace(NAMESPACE);
        let message = chunk.encode();
        let signature = sample_scheme(0).sign(chunk_namespace.as_ref(), &message);

        // Create invalid node (non-genesis without parent), encode it, then decode - should panic on unwrap
        let encoded = Node::<PublicKey, S, Sha256Digest>::new(chunk, signature, None).encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        Node::<PublicKey, S, Sha256Digest>::read_cfg(&mut encoded.as_ref(), &cfg).unwrap();
    }

    #[test]
    fn test_node_non_genesis_without_parent_panics() {
        assert!(catch_unwind(|| node_non_genesis_without_parent_panics(ed25519::fixture)).is_err());
        assert!(
            catch_unwind(|| node_non_genesis_without_parent_panics(secp256r1::fixture)).is_err()
        );
        assert!(catch_unwind(|| node_non_genesis_without_parent_panics(
            bls12381_multisig::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_non_genesis_without_parent_panics(
            bls12381_multisig::fixture::<MinSig, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_non_genesis_without_parent_panics(
            bls12381_threshold::fixture::<MinPk, _>
        ))
        .is_err());
        assert!(catch_unwind(|| node_non_genesis_without_parent_panics(
            bls12381_threshold::fixture::<MinSig, _>
        ))
        .is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::ordered_broadcast::scheme::bls12381_threshold;
        use commonware_codec::conformance::CodecConformance;

        type Scheme = bls12381_threshold::Scheme<PublicKey, MinPk>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Chunk<PublicKey, Sha256Digest>>,
            CodecConformance<Parent<Scheme, Sha256Digest>>,
            CodecConformance<Node<PublicKey, Scheme, Sha256Digest>>,
            CodecConformance<Ack<PublicKey, Scheme, Sha256Digest>>,
            CodecConformance<Activity<PublicKey, Scheme, Sha256Digest>>,
            CodecConformance<Proposal<PublicKey, Sha256Digest>>,
            CodecConformance<Lock<PublicKey, Scheme, Sha256Digest>>,
        }
    }
}
