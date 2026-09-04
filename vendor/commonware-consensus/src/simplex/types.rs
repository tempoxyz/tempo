//! Types used in [crate::simplex].

use crate::{
    simplex::scheme::{self, CertificateVerifier},
    types::{Epoch, Participant, Round, View},
    Epochable, Viewable,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{
    certificate::{Attestation, Scheme},
    Digest, PublicKey,
};
use commonware_parallel::Strategy;
use commonware_utils::N3f1;
use rand_core::CryptoRng;
use std::{collections::HashSet, fmt::Debug, hash::Hash, iter::once};

/// Context is a collection of metadata from consensus about a given payload.
/// It provides information about the current epoch/view and the parent payload that new proposals are built on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context<D: Digest, P: PublicKey> {
    /// Current round of consensus.
    pub round: Round,
    /// Leader of the current round.
    pub leader: P,
    /// Parent the payload is built on.
    ///
    /// If there is a gap between the current view and the parent view, the participant
    /// must possess a nullification for each discarded view to safely vote on the proposed
    /// payload (any view without a nullification may eventually be finalized and skipping
    /// it would result in a fork).
    pub parent: (View, D),
}

impl<D: Digest, P: PublicKey> Epochable for Context<D, P> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest, P: PublicKey> Viewable for Context<D, P> {
    fn view(&self) -> View {
        self.round.view()
    }
}

impl<D: Digest, P: PublicKey> Write for Context<D, P> {
    fn write(&self, buf: &mut impl BufMut) {
        self.round.write(buf);
        self.leader.write(buf);
        self.parent.write(buf);
    }
}

impl<D: Digest, P: PublicKey> EncodeSize for Context<D, P> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.leader.encode_size() + self.parent.encode_size()
    }
}

impl<D: Digest, P: PublicKey> Read for Context<D, P> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let leader = P::read(reader)?;
        let parent = <(View, D)>::read_cfg(reader, &((), ()))?;

        Ok(Self {
            round,
            leader,
            parent,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest, P: PublicKey> arbitrary::Arbitrary<'_> for Context<D, P>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
    P: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            round: Round::arbitrary(u)?,
            leader: P::arbitrary(u)?,
            parent: (View::arbitrary(u)?, D::arbitrary(u)?),
        })
    }
}

/// Attributable is a trait that provides access to the signer index.
/// This is used to identify which participant signed a given message.
pub trait Attributable {
    /// Returns the index of the signer (validator) who produced this message.
    fn signer(&self) -> Participant;
}

/// A map of [Attributable] items keyed by their signer index.
///
/// The key for each item is automatically inferred from [Attributable::signer()].
/// Each signer can insert at most one item.
pub struct AttributableMap<T: Attributable> {
    data: Vec<Option<T>>,
    added: usize,
}

impl<T: Attributable> AttributableMap<T> {
    /// Creates a new [AttributableMap] with the given number of participants.
    pub fn new(participants: usize) -> Self {
        // `resize_with` avoids requiring `T: Clone` while pre-filling with `None`.
        let mut data = Vec::with_capacity(participants);
        data.resize_with(participants, || None);

        Self { data, added: 0 }
    }

    /// Clears all existing items from the [AttributableMap].
    pub fn clear(&mut self) {
        self.data.fill_with(|| None);
        self.added = 0;
    }

    /// Inserts an item into the map, using [Attributable::signer()] as the key,
    /// if it has not been added yet.
    ///
    /// Returns `true` if the item was inserted, `false` if an item from this
    /// signer already exists or if the signer index is out of bounds.
    pub fn insert(&mut self, item: T) -> bool {
        let index: usize = item.signer().into();
        if index >= self.data.len() {
            return false;
        }
        if self.data[index].is_some() {
            return false;
        }
        self.data[index] = Some(item);
        self.added += 1;
        true
    }

    /// Returns the number of items in the [AttributableMap].
    pub const fn len(&self) -> usize {
        self.added
    }

    /// Returns `true` if the [AttributableMap] is empty.
    pub const fn is_empty(&self) -> bool {
        self.added == 0
    }

    /// Returns a reference to the item associated with the given signer, if present.
    pub fn get(&self, signer: Participant) -> Option<&T> {
        self.data.get(<usize>::from(signer))?.as_ref()
    }

    /// Returns an iterator over items in the map, ordered by signer index
    /// ([Attributable::signer()]).
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter().filter_map(|o| o.as_ref())
    }
}

/// Tracks notarize/nullify/finalize votes for a view.
///
/// Each vote type is stored in its own [`AttributableMap`] so a validator can only
/// contribute one vote per phase. The tracker is reused across rounds/views to keep
/// allocations stable.
pub struct VoteTracker<S: Scheme, D: Digest> {
    /// Per-signer notarize votes keyed by validator index.
    notarizes: AttributableMap<Notarize<S, D>>,
    /// Per-signer nullify votes keyed by validator index.
    nullifies: AttributableMap<Nullify<S>>,
    /// Per-signer finalize votes keyed by validator index.
    ///
    /// Finalize votes include the proposal digest so the entire certificate can be
    /// reconstructed once the quorum threshold is hit.
    finalizes: AttributableMap<Finalize<S, D>>,
}

impl<S: Scheme, D: Digest> VoteTracker<S, D> {
    /// Creates a tracker sized for `participants` validators.
    pub fn new(participants: usize) -> Self {
        Self {
            notarizes: AttributableMap::new(participants),
            nullifies: AttributableMap::new(participants),
            finalizes: AttributableMap::new(participants),
        }
    }

    /// Inserts a notarize vote if the signer has not already voted.
    pub fn insert_notarize(&mut self, vote: Notarize<S, D>) -> bool {
        self.notarizes.insert(vote)
    }

    /// Inserts a nullify vote if the signer has not already voted.
    pub fn insert_nullify(&mut self, vote: Nullify<S>) -> bool {
        self.nullifies.insert(vote)
    }

    /// Inserts a finalize vote if the signer has not already voted.
    pub fn insert_finalize(&mut self, vote: Finalize<S, D>) -> bool {
        self.finalizes.insert(vote)
    }

    /// Returns the notarize vote for `signer`, if present.
    pub fn notarize(&self, signer: Participant) -> Option<&Notarize<S, D>> {
        self.notarizes.get(signer)
    }

    /// Returns the nullify vote for `signer`, if present.
    pub fn nullify(&self, signer: Participant) -> Option<&Nullify<S>> {
        self.nullifies.get(signer)
    }

    /// Returns the finalize vote for `signer`, if present.
    pub fn finalize(&self, signer: Participant) -> Option<&Finalize<S, D>> {
        self.finalizes.get(signer)
    }

    /// Iterates over notarize votes in signer order.
    pub fn iter_notarizes(&self) -> impl Iterator<Item = &Notarize<S, D>> {
        self.notarizes.iter()
    }

    /// Iterates over nullify votes in signer order.
    pub fn iter_nullifies(&self) -> impl Iterator<Item = &Nullify<S>> {
        self.nullifies.iter()
    }

    /// Iterates over finalize votes in signer order.
    pub fn iter_finalizes(&self) -> impl Iterator<Item = &Finalize<S, D>> {
        self.finalizes.iter()
    }

    /// Returns how many notarize votes have been recorded.
    pub fn len_notarizes(&self) -> u32 {
        u32::try_from(self.notarizes.len()).expect("too many notarize votes")
    }

    /// Returns how many nullify votes have been recorded.
    pub fn len_nullifies(&self) -> u32 {
        u32::try_from(self.nullifies.len()).expect("too many nullify votes")
    }

    /// Returns how many finalize votes have been recorded.
    pub fn len_finalizes(&self) -> u32 {
        u32::try_from(self.finalizes.len()).expect("too many finalize votes")
    }

    /// Returns `true` if the given signer has a notarize vote recorded.
    pub fn has_notarize(&self, signer: Participant) -> bool {
        self.notarizes.get(signer).is_some()
    }

    /// Returns `true` if a nullify vote has been recorded for `signer`.
    pub fn has_nullify(&self, signer: Participant) -> bool {
        self.nullifies.get(signer).is_some()
    }

    /// Returns `true` if a finalize vote has been recorded for `signer`.
    pub fn has_finalize(&self, signer: Participant) -> bool {
        self.finalizes.get(signer).is_some()
    }

    /// Clears all notarize votes but keeps the allocations for reuse.
    pub fn clear_notarizes(&mut self) {
        self.notarizes.clear();
    }

    /// Clears all finalize votes but keeps the allocations for reuse.
    pub fn clear_finalizes(&mut self) {
        self.finalizes.clear();
    }
}

/// Identifies the subject of a vote or certificate.
///
/// Implementations use the subject to derive domain-separated message bytes for both
/// individual votes and recovered certificates.
#[derive(Copy, Clone, Debug)]
pub enum Subject<'a, D: Digest> {
    /// Subject for notarize votes and certificates, carrying the proposal.
    Notarize { proposal: &'a Proposal<D> },
    /// Subject for nullify votes and certificates, scoped to a round.
    Nullify { round: Round },
    /// Subject for finalize votes and certificates, carrying the proposal.
    Finalize { proposal: &'a Proposal<D> },
}

impl<D: Digest> Viewable for Subject<'_, D> {
    fn view(&self) -> View {
        match self {
            Subject::Notarize { proposal } => proposal.view(),
            Subject::Nullify { round } => round.view(),
            Subject::Finalize { proposal } => proposal.view(),
        }
    }
}

/// Vote represents individual votes ([Notarize], [Nullify], [Finalize]).
#[derive(Clone, Debug, PartialEq)]
pub enum Vote<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
}

impl<S: Scheme, D: Digest> Write for Vote<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Nullify(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Finalize(v) => {
                2u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Vote<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Vote<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Nullify::read(reader)?;
                Ok(Self::Nullify(v))
            }
            2 => {
                let v = Finalize::read(reader)?;
                Ok(Self::Finalize(v))
            }
            _ => Err(Error::Invalid("consensus::simplex::Vote", "Invalid type")),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Vote<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Vote<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Nullify(v) => v.view(),
            Self::Finalize(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Vote<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=2)?;
        match tag {
            0 => {
                let v = Notarize::arbitrary(u)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Nullify::arbitrary(u)?;
                Ok(Self::Nullify(v))
            }
            2 => {
                let v = Finalize::arbitrary(u)?;
                Ok(Self::Finalize(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Certificate represents aggregated votes ([Notarization], [Nullification], [Finalization]).
#[derive(Clone, Debug, PartialEq)]
pub enum Certificate<S: Scheme, D: Digest> {
    /// A recovered certificate for a notarization.
    Notarization(Notarization<S, D>),
    /// A recovered certificate for a nullification.
    Nullification(Nullification<S>),
    /// A recovered certificate for a finalization.
    Finalization(Finalization<S, D>),
}

#[cfg(not(target_arch = "wasm32"))]
impl<S: Scheme, D: Digest> Certificate<S, D> {
    /// Returns the stable trace field value for this certificate's type.
    pub(crate) const fn kind(&self) -> &'static str {
        match self {
            Self::Notarization(_) => "notarization",
            Self::Nullification(_) => "nullification",
            Self::Finalization(_) => "finalization",
        }
    }
}

impl<S: Scheme, D: Digest> Write for Certificate<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarization(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Finalization(v) => {
                2u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Certificate<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarization(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Certificate<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarization::read_cfg(reader, cfg)?;
                Ok(Self::Notarization(v))
            }
            1 => {
                let v = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(v))
            }
            2 => {
                let v = Finalization::read_cfg(reader, cfg)?;
                Ok(Self::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::simplex::Certificate",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Certificate<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarization(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Certificate<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarization(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalization(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Certificate<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=2)?;
        match tag {
            0 => {
                let v = Notarization::arbitrary(u)?;
                Ok(Self::Notarization(v))
            }
            1 => {
                let v = Nullification::arbitrary(u)?;
                Ok(Self::Nullification(v))
            }
            2 => {
                let v = Finalization::arbitrary(u)?;
                Ok(Self::Finalization(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Artifact represents all consensus artifacts (votes and certificates) for storage.
#[derive(Clone, Debug, PartialEq)]
pub enum Artifact<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization.
    Notarization(Notarization<S, D>),
    /// A notarization was locally certified.
    Certification(Round, bool),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification.
    Nullification(Nullification<S>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization.
    Finalization(Finalization<S, D>),
}

impl<S: Scheme, D: Digest> Write for Artifact<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Certification(r, b) => {
                2u8.write(writer);
                r.write(writer);
                b.write(writer);
            }
            Self::Nullify(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Self::Finalize(v) => {
                5u8.write(writer);
                v.write(writer);
            }
            Self::Finalization(v) => {
                6u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Artifact<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Notarization(v) => v.encode_size(),
            Self::Certification(r, b) => r.encode_size() + b.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Artifact<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::read(reader)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Notarization::read_cfg(reader, cfg)?;
                Ok(Self::Notarization(v))
            }
            2 => {
                let r = Round::read(reader)?;
                let b = bool::read(reader)?;
                Ok(Self::Certification(r, b))
            }
            3 => {
                let v = Nullify::read(reader)?;
                Ok(Self::Nullify(v))
            }
            4 => {
                let v = Nullification::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(v))
            }
            5 => {
                let v = Finalize::read(reader)?;
                Ok(Self::Finalize(v))
            }
            6 => {
                let v = Finalization::read_cfg(reader, cfg)?;
                Ok(Self::Finalization(v))
            }
            _ => Err(Error::Invalid(
                "consensus::simplex::Artifact",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Artifact<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Notarization(v) => v.epoch(),
            Self::Certification(r, _) => r.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Artifact<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Notarization(v) => v.view(),
            Self::Certification(r, _) => r.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalize(v) => v.view(),
            Self::Finalization(v) => v.view(),
        }
    }
}

impl<S: Scheme, D: Digest> From<Vote<S, D>> for Artifact<S, D> {
    fn from(vote: Vote<S, D>) -> Self {
        match vote {
            Vote::Notarize(v) => Self::Notarize(v),
            Vote::Nullify(v) => Self::Nullify(v),
            Vote::Finalize(v) => Self::Finalize(v),
        }
    }
}

impl<S: Scheme, D: Digest> From<Certificate<S, D>> for Artifact<S, D> {
    fn from(cert: Certificate<S, D>) -> Self {
        match cert {
            Certificate::Notarization(v) => Self::Notarization(v),
            Certificate::Nullification(v) => Self::Nullification(v),
            Certificate::Finalization(v) => Self::Finalization(v),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Artifact<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=6)?;
        match tag {
            0 => {
                let v = Notarize::arbitrary(u)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Notarization::arbitrary(u)?;
                Ok(Self::Notarization(v))
            }
            2 => {
                let r = Round::arbitrary(u)?;
                let b = bool::arbitrary(u)?;
                Ok(Self::Certification(r, b))
            }
            3 => {
                let v = Nullify::arbitrary(u)?;
                Ok(Self::Nullify(v))
            }
            4 => {
                let v = Nullification::arbitrary(u)?;
                Ok(Self::Nullification(v))
            }
            5 => {
                let v = Finalize::arbitrary(u)?;
                Ok(Self::Finalize(v))
            }
            6 => {
                let v = Finalization::arbitrary(u)?;
                Ok(Self::Finalization(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Proposal represents a proposed block in the protocol.
/// It includes the view number, the parent view, and the actual payload (typically a digest of block data).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Proposal<D: Digest> {
    /// The round in which this proposal is made
    pub round: Round,
    /// The view of the parent proposal that this one builds upon
    pub parent: View,
    /// The actual payload/content of the proposal (typically a digest of the block data)
    pub payload: D,
}

impl<D: Digest> Proposal<D> {
    /// Creates a new proposal with the specified view, parent view, and payload.
    pub const fn new(round: Round, parent: View, payload: D) -> Self {
        Self {
            round,
            parent,
            payload,
        }
    }
}

impl<D: Digest> Write for Proposal<D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.parent.write(writer);
        self.payload.write(writer)
    }
}

impl<D: Digest> Read for Proposal<D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let parent = View::read(reader)?;
        let payload = D::read(reader)?;
        Ok(Self {
            round,
            parent,
            payload,
        })
    }
}

impl<D: Digest> EncodeSize for Proposal<D> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.parent.encode_size() + self.payload.encode_size()
    }
}

impl<D: Digest> Epochable for Proposal<D> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<D: Digest> Viewable for Proposal<D> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Proposal<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let parent = View::arbitrary(u)?;
        let payload = D::arbitrary(u)?;
        Ok(Self {
            round,
            parent,
            payload,
        })
    }
}

/// Validator vote that endorses a proposal for notarization.
#[derive(Clone, Debug)]
pub struct Notarize<S: Scheme, D: Digest> {
    /// Proposal being notarized.
    pub proposal: Proposal<D>,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme, D: Digest> Notarize<S, D> {
    /// Signs a notarize vote for the provided proposal.
    pub fn sign(scheme: &S, proposal: Proposal<D>) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(Subject::Notarize {
            proposal: &proposal,
        })?;

        Some(Self {
            proposal,
            attestation,
        })
    }

    /// Verifies the notarize vote against the provided signing scheme.
    ///
    /// This ensures that the notarize signature is valid for the claimed proposal.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(
            rng,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.attestation,
            strategy,
        )
    }

    /// Returns the round associated with this notarize vote.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Notarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.attestation == other.attestation
    }
}

impl<S: Scheme, D: Digest> Eq for Notarize<S, D> {}

impl<S: Scheme, D: Digest> Hash for Notarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.attestation.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Notarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Notarize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.attestation.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Notarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self {
            proposal,
            attestation,
        })
    }
}

impl<S: Scheme, D: Digest> Attributable for Notarize<S, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<S: Scheme, D: Digest> Epochable for Notarize<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Notarize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Notarize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self {
            proposal,
            attestation,
        })
    }
}

/// Batch-verifies certificates and returns a per-item result.
///
/// Uses bisection to efficiently identify invalid certificates when batch
/// verification fails.
pub fn verify_certificates<'a, R, S, D>(
    rng: &mut R,
    scheme: &S,
    certificates: &[(Subject<'a, D>, &'a S::Certificate)],
    strategy: &impl Strategy,
) -> Vec<bool>
where
    R: CryptoRng,
    S: CertificateVerifier<D>,
    D: Digest,
{
    scheme.verify_certificates_bisect::<_, D, N3f1>(rng, certificates, strategy)
}

/// Aggregated notarization certificate recovered from notarize votes.
/// When a proposal is notarized, it means at least 2f+1 validators have voted for it.
///
/// Some signing schemes (like [`super::scheme::bls12381_threshold::vrf`]) embed an additional
/// randomness seed in the certificate. For threshold signatures, the seed can be accessed
/// via [`super::scheme::bls12381_threshold::vrf::Seedable::seed`].
#[derive(Clone, Debug)]
pub struct Notarization<S: Scheme, D: Digest> {
    /// The proposal that has been notarized.
    pub proposal: Proposal<D>,
    /// The recovered certificate for the proposal.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Notarization<S, D> {
    /// Builds a notarization certificate from owned notarize votes for the same proposal,
    /// consuming the votes to avoid cloning each attestation.
    pub fn from_owned_notarizes<I>(
        scheme: &S,
        notarizes: I,
        strategy: &impl Strategy,
    ) -> Option<Self>
    where
        I: IntoIterator<Item = Notarize<S, D>>,
        I::IntoIter: Send,
    {
        let mut notarizes = notarizes.into_iter();
        let Notarize {
            proposal,
            attestation,
        } = notarizes.next()?;
        let attestations = once(attestation).chain(notarizes.map(|n| n.attestation));
        let certificate = scheme.assemble::<_, N3f1>(attestations, strategy)?;

        Some(Self {
            proposal,
            certificate,
        })
    }

    /// Builds a notarization certificate from notarize votes for the same proposal.
    pub fn from_notarizes<'a, I>(scheme: &S, notarizes: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Notarize<S, D>>,
        I::IntoIter: Send,
    {
        Self::from_owned_notarizes(scheme, notarizes.into_iter().cloned(), strategy)
    }

    /// Verifies the notarization certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed proposal.
    pub fn verify<R: CryptoRng>(
        &self,
        rng: &mut R,
        scheme: &impl CertificateVerifier<D, Certificate = S::Certificate>,
        strategy: &impl Strategy,
    ) -> bool {
        scheme.verify_certificate::<_, D, N3f1>(
            rng,
            Subject::Notarize {
                proposal: &self.proposal,
            },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with the notarized proposal.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Notarization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for Notarization<S, D> {}

impl<S: Scheme, D: Digest> Hash for Notarization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Notarization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Notarization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Notarization<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for Notarization<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Notarization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Notarization<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Validator vote for nullifying the current round, i.e. skip the current round.
/// This is typically used when the leader is unresponsive or fails to propose a valid block.
#[derive(Clone, Debug)]
pub struct Nullify<S: Scheme> {
    /// The round to be nullified (skipped).
    pub round: Round,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme> PartialEq for Nullify<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.attestation == other.attestation
    }
}

impl<S: Scheme> Eq for Nullify<S> {}

impl<S: Scheme> Hash for Nullify<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.attestation.hash(state);
    }
}

impl<S: Scheme> Nullify<S> {
    /// Signs a nullify vote for the given round.
    pub fn sign<D: Digest>(scheme: &S, round: Round) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(Subject::Nullify { round })?;

        Some(Self { round, attestation })
    }

    /// Verifies the nullify vote against the provided signing scheme.
    ///
    /// This ensures that the nullify signature is valid for the given round.
    pub fn verify<R, D: Digest>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(
            rng,
            Subject::Nullify { round: self.round },
            &self.attestation,
            strategy,
        )
    }

    /// Returns the round associated with this nullify vote.
    pub const fn round(&self) -> Round {
        self.round
    }
}

impl<S: Scheme> Write for Nullify<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Nullify<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.attestation.encode_size()
    }
}

impl<S: Scheme> Read for Nullify<S> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self { round, attestation })
    }
}

impl<S: Scheme> Attributable for Nullify<S> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<S: Scheme> Epochable for Nullify<S> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: Scheme> Viewable for Nullify<S> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Nullify<S>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self { round, attestation })
    }
}

/// Aggregated nullification certificate recovered from nullify votes.
/// When a view is nullified, the consensus moves to the next view without finalizing a block.
#[derive(Clone, Debug)]
pub struct Nullification<S: Scheme> {
    /// The round in which this nullification is made.
    pub round: Round,
    /// The recovered certificate for the nullification.
    pub certificate: S::Certificate,
}

impl<S: Scheme> Nullification<S> {
    /// Builds a nullification certificate from owned nullify votes from the same round,
    /// consuming the votes to avoid cloning each attestation.
    pub fn from_owned_nullifies<I>(
        scheme: &S,
        nullifies: I,
        strategy: &impl Strategy,
    ) -> Option<Self>
    where
        I: IntoIterator<Item = Nullify<S>>,
        I::IntoIter: Send,
    {
        let mut nullifies = nullifies.into_iter();
        let Nullify { round, attestation } = nullifies.next()?;
        let attestations = once(attestation).chain(nullifies.map(|n| n.attestation));
        let certificate = scheme.assemble::<_, N3f1>(attestations, strategy)?;

        Some(Self { round, certificate })
    }

    /// Builds a nullification certificate from nullify votes from the same round.
    pub fn from_nullifies<'a, I>(scheme: &S, nullifies: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Nullify<S>>,
        I::IntoIter: Send,
    {
        Self::from_owned_nullifies(scheme, nullifies.into_iter().cloned(), strategy)
    }

    /// Verifies the nullification certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed round.
    pub fn verify<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        scheme: &impl CertificateVerifier<D, Certificate = S::Certificate>,
        strategy: &impl Strategy,
    ) -> bool {
        scheme.verify_certificate::<_, D, N3f1>(
            rng,
            Subject::Nullify { round: self.round },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with this nullification.
    pub const fn round(&self) -> Round {
        self.round
    }
}

impl<S: Scheme> PartialEq for Nullification<S> {
    fn eq(&self, other: &Self) -> bool {
        self.round == other.round && self.certificate == other.certificate
    }
}

impl<S: Scheme> Eq for Nullification<S> {}

impl<S: Scheme> Hash for Nullification<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.round.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme> Write for Nullification<S> {
    fn write(&self, writer: &mut impl BufMut) {
        self.round.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme> EncodeSize for Nullification<S> {
    fn encode_size(&self) -> usize {
        self.round.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme> Read for Nullification<S> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let round = Round::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self { round, certificate })
    }
}

impl<S: Scheme> Epochable for Nullification<S> {
    fn epoch(&self) -> Epoch {
        self.round.epoch()
    }
}

impl<S: Scheme> Viewable for Nullification<S> {
    fn view(&self) -> View {
        self.round.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme> arbitrary::Arbitrary<'_> for Nullification<S>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let round = Round::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self { round, certificate })
    }
}

/// Validator vote to finalize a proposal.
/// This happens after a proposal has been notarized, confirming it as the canonical block
/// for this round.
#[derive(Clone, Debug)]
pub struct Finalize<S: Scheme, D: Digest> {
    /// Proposal being finalized.
    pub proposal: Proposal<D>,
    /// Scheme-specific attestation material.
    pub attestation: Attestation<S>,
}

impl<S: Scheme, D: Digest> Finalize<S, D> {
    /// Signs a finalize vote for the provided proposal.
    pub fn sign(scheme: &S, proposal: Proposal<D>) -> Option<Self>
    where
        S: scheme::Scheme<D>,
    {
        let attestation = scheme.sign::<D>(Subject::Finalize {
            proposal: &proposal,
        })?;

        Some(Self {
            proposal,
            attestation,
        })
    }

    /// Verifies the finalize vote against the provided signing scheme.
    ///
    /// This ensures that the finalize signature is valid for the claimed proposal.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        scheme.verify_attestation::<_, D>(
            rng,
            Subject::Finalize {
                proposal: &self.proposal,
            },
            &self.attestation,
            strategy,
        )
    }

    /// Returns the round associated with this finalize vote.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Finalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.attestation == other.attestation
    }
}

impl<S: Scheme, D: Digest> Eq for Finalize<S, D> {}

impl<S: Scheme, D: Digest> Hash for Finalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.attestation.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Finalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.attestation.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Finalize<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.attestation.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Finalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let attestation = Attestation::read(reader)?;

        Ok(Self {
            proposal,
            attestation,
        })
    }
}

impl<S: Scheme, D: Digest> Attributable for Finalize<S, D> {
    fn signer(&self) -> Participant {
        self.attestation.signer
    }
}

impl<S: Scheme, D: Digest> Epochable for Finalize<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Finalize<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Finalize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let attestation = Attestation::arbitrary(u)?;
        Ok(Self {
            proposal,
            attestation,
        })
    }
}

/// Aggregated finalization certificate recovered from finalize votes.
/// When a proposal is finalized, it becomes the canonical block for its view.
///
/// Some signing schemes (like [`super::scheme::bls12381_threshold::vrf`]) embed an additional
/// randomness seed in the certificate. For threshold signatures, the seed can be accessed
/// via [`super::scheme::bls12381_threshold::vrf::Seedable::seed`].
#[derive(Clone, Debug)]
pub struct Finalization<S: Scheme, D: Digest> {
    /// The proposal that has been finalized.
    pub proposal: Proposal<D>,
    /// The recovered certificate for the proposal.
    pub certificate: S::Certificate,
}

impl<S: Scheme, D: Digest> Finalization<S, D> {
    /// Builds a finalization certificate from owned finalize votes for the same proposal,
    /// consuming the votes to avoid cloning each attestation.
    pub fn from_owned_finalizes<I>(
        scheme: &S,
        finalizes: I,
        strategy: &impl Strategy,
    ) -> Option<Self>
    where
        I: IntoIterator<Item = Finalize<S, D>>,
        I::IntoIter: Send,
    {
        let mut finalizes = finalizes.into_iter();
        let Finalize {
            proposal,
            attestation,
        } = finalizes.next()?;
        let attestations = once(attestation).chain(finalizes.map(|f| f.attestation));
        let certificate = scheme.assemble::<_, N3f1>(attestations, strategy)?;

        Some(Self {
            proposal,
            certificate,
        })
    }

    /// Builds a finalization certificate from finalize votes for the same proposal.
    pub fn from_finalizes<'a, I>(scheme: &S, finalizes: I, strategy: &impl Strategy) -> Option<Self>
    where
        I: IntoIterator<Item = &'a Finalize<S, D>>,
        I::IntoIter: Send,
    {
        Self::from_owned_finalizes(scheme, finalizes.into_iter().cloned(), strategy)
    }

    /// Verifies the finalization certificate against the provided signing scheme.
    ///
    /// This ensures that the certificate is valid for the claimed proposal.
    pub fn verify<R: CryptoRng>(
        &self,
        rng: &mut R,
        scheme: &impl CertificateVerifier<D, Certificate = S::Certificate>,
        strategy: &impl Strategy,
    ) -> bool {
        scheme.verify_certificate::<_, D, N3f1>(
            rng,
            Subject::Finalize {
                proposal: &self.proposal,
            },
            &self.certificate,
            strategy,
        )
    }

    /// Returns the round associated with the finalized proposal.
    pub const fn round(&self) -> Round {
        self.proposal.round
    }
}

impl<S: Scheme, D: Digest> PartialEq for Finalization<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.proposal == other.proposal && self.certificate == other.certificate
    }
}

impl<S: Scheme, D: Digest> Eq for Finalization<S, D> {}

impl<S: Scheme, D: Digest> Hash for Finalization<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.proposal.hash(state);
        self.certificate.hash(state);
    }
}

impl<S: Scheme, D: Digest> Write for Finalization<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.proposal.write(writer);
        self.certificate.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Finalization<S, D> {
    fn encode_size(&self) -> usize {
        self.proposal.encode_size() + self.certificate.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Finalization<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let proposal = Proposal::read(reader)?;
        let certificate = S::Certificate::read_cfg(reader, cfg)?;

        Ok(Self {
            proposal,
            certificate,
        })
    }
}

impl<S: Scheme, D: Digest> Epochable for Finalization<S, D> {
    fn epoch(&self) -> Epoch {
        self.proposal.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for Finalization<S, D> {
    fn view(&self) -> View {
        self.proposal.view()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Finalization<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let proposal = Proposal::arbitrary(u)?;
        let certificate = S::Certificate::arbitrary(u)?;
        Ok(Self {
            proposal,
            certificate,
        })
    }
}

/// Backfiller is a message type for requesting and receiving missing consensus artifacts.
/// This is used to synchronize validators that have fallen behind or just joined the network.
#[derive(Clone, Debug, PartialEq)]
pub enum Backfiller<S: Scheme, D: Digest> {
    /// Request for missing notarizations and nullifications
    Request(Request),
    /// Response containing requested notarizations and nullifications
    Response(Response<S, D>),
}

impl<S: Scheme, D: Digest> Write for Backfiller<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request(request) => {
                0u8.write(writer);
                request.write(writer);
            }
            Self::Response(response) => {
                1u8.write(writer);
                response.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Backfiller<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request(v) => v.encode_size(),
            Self::Response(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Backfiller<S, D> {
    type Cfg = (usize, <S::Certificate as Read>::Cfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let (max_len, _) = cfg;
                let v = Request::read_cfg(reader, max_len)?;
                Ok(Self::Request(v))
            }
            1 => {
                let v = Response::<S, D>::read_cfg(reader, cfg)?;
                Ok(Self::Response(v))
            }
            _ => Err(Error::Invalid(
                "consensus::simplex::Backfiller",
                "Invalid type",
            )),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Backfiller<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=1)?;
        match tag {
            0 => {
                let v = Request::arbitrary(u)?;
                Ok(Self::Request(v))
            }
            1 => {
                let v = Response::<S, D>::arbitrary(u)?;
                Ok(Self::Response(v))
            }
            _ => unreachable!(),
        }
    }
}

/// Request is a message to request missing notarizations and nullifications.
/// This is used by validators who need to catch up with the consensus state.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Request {
    /// Unique identifier for this request (used to match responses)
    pub id: u64,
    /// Views for which notarizations are requested
    pub notarizations: Vec<View>,
    /// Views for which nullifications are requested
    pub nullifications: Vec<View>,
}

impl Request {
    /// Creates a new request for missing notarizations and nullifications.
    pub const fn new(id: u64, notarizations: Vec<View>, nullifications: Vec<View>) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }
}

impl Write for Request {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl EncodeSize for Request {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl Read for Request {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, max_len: &usize) -> Result<Self, Error> {
        let id = UInt::read(reader)?.into();
        let mut views = HashSet::new();
        let notarizations = Vec::<View>::read_range(reader, ..=*max_len)?;
        for view in notarizations.iter() {
            if !views.insert(view) {
                return Err(Error::Invalid(
                    "consensus::simplex::Request",
                    "Duplicate notarization",
                ));
            }
        }
        let remaining = max_len - notarizations.len();
        views.clear();
        let nullifications = Vec::<View>::read_range(reader, ..=remaining)?;
        for view in nullifications.iter() {
            if !views.insert(view) {
                return Err(Error::Invalid(
                    "consensus::simplex::Request",
                    "Duplicate nullification",
                ));
            }
        }
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Response is a message containing the requested notarizations and nullifications.
/// This is sent in response to a Request message.
#[derive(Clone, Debug, PartialEq)]
pub struct Response<S: Scheme, D: Digest> {
    /// Identifier matching the original request
    pub id: u64,
    /// Notarizations for the requested views
    pub notarizations: Vec<Notarization<S, D>>,
    /// Nullifications for the requested views
    pub nullifications: Vec<Nullification<S>>,
}

impl<S: Scheme, D: Digest> Response<S, D> {
    /// Creates a new response with the given id, notarizations, and nullifications.
    pub const fn new(
        id: u64,
        notarizations: Vec<Notarization<S, D>>,
        nullifications: Vec<Nullification<S>>,
    ) -> Self {
        Self {
            id,
            notarizations,
            nullifications,
        }
    }

    /// Verifies the certificates contained in this response against the signing scheme.
    pub fn verify<R: CryptoRng>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        S: scheme::Scheme<D>,
    {
        // Prepare to verify
        if self.notarizations.is_empty() && self.nullifications.is_empty() {
            return true;
        }

        let notarizations = self.notarizations.iter().map(|notarization| {
            let context = Subject::Notarize {
                proposal: &notarization.proposal,
            };

            (context, &notarization.certificate)
        });

        let nullifications = self.nullifications.iter().map(|nullification| {
            let context = Subject::Nullify {
                round: nullification.round,
            };

            (context, &nullification.certificate)
        });

        scheme.verify_certificates::<_, D, _, N3f1>(
            rng,
            notarizations.chain(nullifications),
            strategy,
        )
    }
}

impl<S: Scheme, D: Digest> Write for Response<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.id).write(writer);
        self.notarizations.write(writer);
        self.nullifications.write(writer);
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Response<S, D> {
    fn encode_size(&self) -> usize {
        UInt(self.id).encode_size()
            + self.notarizations.encode_size()
            + self.nullifications.encode_size()
    }
}

impl<S: Scheme, D: Digest> Read for Response<S, D> {
    type Cfg = (usize, <S::Certificate as Read>::Cfg);

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let (max_len, certificate_cfg) = cfg;
        let id = UInt::read(reader)?.into();
        let mut views = HashSet::new();
        let notarizations = Vec::<Notarization<S, D>>::read_cfg(
            reader,
            &((..=*max_len).into(), certificate_cfg.clone()),
        )?;
        for notarization in notarizations.iter() {
            if !views.insert(notarization.view()) {
                return Err(Error::Invalid(
                    "consensus::simplex::Response",
                    "Duplicate notarization",
                ));
            }
        }
        let remaining = max_len - notarizations.len();
        views.clear();
        let nullifications = Vec::<Nullification<S>>::read_cfg(
            reader,
            &((..=remaining).into(), certificate_cfg.clone()),
        )?;
        for nullification in nullifications.iter() {
            if !views.insert(nullification.view()) {
                return Err(Error::Invalid(
                    "consensus::simplex::Response",
                    "Duplicate nullification",
                ));
            }
        }
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Response<S, D>
where
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let id = u.arbitrary()?;
        let notarizations = u.arbitrary()?;
        let nullifications = u.arbitrary()?;
        Ok(Self {
            id,
            notarizations,
            nullifications,
        })
    }
}

/// Activity represents all possible activities that can occur in the consensus protocol.
/// This includes both regular consensus messages and fault evidence.
///
/// # Verification
///
/// Some activities issued by consensus are not guaranteed to be cryptographically verified (i.e. if not needed
/// to produce a minimum quorum certificate). Use [`Activity::verified`] to check if an activity may not be verified,
/// and [`Activity::verify`] to perform verification.
///
/// # Activity Filtering
///
/// For **non-attributable** schemes like [`crate::simplex::scheme::bls12381_threshold`], exposing
/// per-validator activity as fault evidence is not safe: with threshold cryptography, any `t` valid partial signatures can
/// be used to forge a partial signature for any player.
///
/// Use [`crate::simplex::scheme::reporter::AttributableReporter`] to automatically filter and
/// verify activities based on [`Scheme::is_attributable`].
#[derive(Clone, Debug)]
pub enum Activity<S: Scheme, D: Digest> {
    /// A validator's notarize vote over a proposal.
    Notarize(Notarize<S, D>),
    /// A recovered certificate for a notarization (scheme-specific).
    Notarization(Notarization<S, D>),
    /// A notarization was locally certified.
    Certification(Notarization<S, D>),
    /// A validator's nullify vote used to skip the current view.
    Nullify(Nullify<S>),
    /// A recovered certificate for a nullification (scheme-specific).
    Nullification(Nullification<S>),
    /// A validator's finalize vote over a proposal.
    Finalize(Finalize<S, D>),
    /// A recovered certificate for a finalization (scheme-specific).
    Finalization(Finalization<S, D>),
    /// Evidence of a validator sending conflicting notarizes (Byzantine behavior).
    ConflictingNotarize(ConflictingNotarize<S, D>),
    /// Evidence of a validator sending conflicting finalizes (Byzantine behavior).
    ConflictingFinalize(ConflictingFinalize<S, D>),
    /// Evidence of a validator sending both nullify and finalize for the same view (Byzantine behavior).
    NullifyFinalize(NullifyFinalize<S, D>),
}

impl<S: Scheme, D: Digest> PartialEq for Activity<S, D> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Notarize(a), Self::Notarize(b)) => a == b,
            (Self::Notarization(a), Self::Notarization(b)) => a == b,
            (Self::Certification(a), Self::Certification(b)) => a == b,
            (Self::Nullify(a), Self::Nullify(b)) => a == b,
            (Self::Nullification(a), Self::Nullification(b)) => a == b,
            (Self::Finalize(a), Self::Finalize(b)) => a == b,
            (Self::Finalization(a), Self::Finalization(b)) => a == b,
            (Self::ConflictingNotarize(a), Self::ConflictingNotarize(b)) => a == b,
            (Self::ConflictingFinalize(a), Self::ConflictingFinalize(b)) => a == b,
            (Self::NullifyFinalize(a), Self::NullifyFinalize(b)) => a == b,
            _ => false,
        }
    }
}

impl<S: Scheme, D: Digest> Eq for Activity<S, D> {}

impl<S: Scheme, D: Digest> Hash for Activity<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Notarize(v) => {
                0u8.hash(state);
                v.hash(state);
            }
            Self::Notarization(v) => {
                1u8.hash(state);
                v.hash(state);
            }
            Self::Certification(v) => {
                2u8.hash(state);
                v.hash(state);
            }
            Self::Nullify(v) => {
                3u8.hash(state);
                v.hash(state);
            }
            Self::Nullification(v) => {
                4u8.hash(state);
                v.hash(state);
            }
            Self::Finalize(v) => {
                5u8.hash(state);
                v.hash(state);
            }
            Self::Finalization(v) => {
                6u8.hash(state);
                v.hash(state);
            }
            Self::ConflictingNotarize(v) => {
                7u8.hash(state);
                v.hash(state);
            }
            Self::ConflictingFinalize(v) => {
                8u8.hash(state);
                v.hash(state);
            }
            Self::NullifyFinalize(v) => {
                9u8.hash(state);
                v.hash(state);
            }
        }
    }
}

impl<S: Scheme, D: Digest> Activity<S, D> {
    /// Indicates whether the activity is guaranteed to have been verified by consensus.
    pub const fn verified(&self) -> bool {
        match self {
            Self::Notarize(_) => false,
            Self::Notarization(_) => true,
            Self::Certification(_) => false,
            Self::Nullify(_) => false,
            Self::Nullification(_) => true,
            Self::Finalize(_) => false,
            Self::Finalization(_) => true,
            Self::ConflictingNotarize(_) => false,
            Self::ConflictingFinalize(_) => false,
            Self::NullifyFinalize(_) => false,
        }
    }

    /// Verifies the validity of this activity against the signing scheme.
    ///
    /// This method **always** performs verification regardless of whether the activity has been
    /// previously verified. Callers can use [`Activity::verified`] to check if verification is
    /// necessary before calling this method.
    pub fn verify<R: CryptoRng>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        S: scheme::Scheme<D>,
    {
        match self {
            Self::Notarize(n) => n.verify(rng, scheme, strategy),
            Self::Notarization(n) => n.verify(rng, scheme, strategy),
            Self::Certification(n) => n.verify(rng, scheme, strategy),
            Self::Nullify(n) => n.verify(rng, scheme, strategy),
            Self::Nullification(n) => n.verify(rng, scheme, strategy),
            Self::Finalize(f) => f.verify(rng, scheme, strategy),
            Self::Finalization(f) => f.verify(rng, scheme, strategy),
            Self::ConflictingNotarize(c) => c.verify(rng, scheme, strategy),
            Self::ConflictingFinalize(c) => c.verify(rng, scheme, strategy),
            Self::NullifyFinalize(c) => c.verify(rng, scheme, strategy),
        }
    }
}

impl<S: Scheme, D: Digest> Write for Activity<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Notarize(v) => {
                0u8.write(writer);
                v.write(writer);
            }
            Self::Notarization(v) => {
                1u8.write(writer);
                v.write(writer);
            }
            Self::Certification(v) => {
                2u8.write(writer);
                v.write(writer);
            }
            Self::Nullify(v) => {
                3u8.write(writer);
                v.write(writer);
            }
            Self::Nullification(v) => {
                4u8.write(writer);
                v.write(writer);
            }
            Self::Finalize(v) => {
                5u8.write(writer);
                v.write(writer);
            }
            Self::Finalization(v) => {
                6u8.write(writer);
                v.write(writer);
            }
            Self::ConflictingNotarize(v) => {
                7u8.write(writer);
                v.write(writer);
            }
            Self::ConflictingFinalize(v) => {
                8u8.write(writer);
                v.write(writer);
            }
            Self::NullifyFinalize(v) => {
                9u8.write(writer);
                v.write(writer);
            }
        }
    }
}

impl<S: Scheme, D: Digest> EncodeSize for Activity<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Notarize(v) => v.encode_size(),
            Self::Notarization(v) => v.encode_size(),
            Self::Certification(v) => v.encode_size(),
            Self::Nullify(v) => v.encode_size(),
            Self::Nullification(v) => v.encode_size(),
            Self::Finalize(v) => v.encode_size(),
            Self::Finalization(v) => v.encode_size(),
            Self::ConflictingNotarize(v) => v.encode_size(),
            Self::ConflictingFinalize(v) => v.encode_size(),
            Self::NullifyFinalize(v) => v.encode_size(),
        }
    }
}

impl<S: Scheme, D: Digest> Read for Activity<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let tag = <u8>::read(reader)?;
        match tag {
            0 => {
                let v = Notarize::<S, D>::read(reader)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Notarization::<S, D>::read_cfg(reader, cfg)?;
                Ok(Self::Notarization(v))
            }
            2 => {
                let v = Notarization::<S, D>::read_cfg(reader, cfg)?;
                Ok(Self::Certification(v))
            }
            3 => {
                let v = Nullify::<S>::read(reader)?;
                Ok(Self::Nullify(v))
            }
            4 => {
                let v = Nullification::<S>::read_cfg(reader, cfg)?;
                Ok(Self::Nullification(v))
            }
            5 => {
                let v = Finalize::<S, D>::read(reader)?;
                Ok(Self::Finalize(v))
            }
            6 => {
                let v = Finalization::<S, D>::read_cfg(reader, cfg)?;
                Ok(Self::Finalization(v))
            }
            7 => {
                let v = ConflictingNotarize::<S, D>::read(reader)?;
                Ok(Self::ConflictingNotarize(v))
            }
            8 => {
                let v = ConflictingFinalize::<S, D>::read(reader)?;
                Ok(Self::ConflictingFinalize(v))
            }
            9 => {
                let v = NullifyFinalize::<S, D>::read(reader)?;
                Ok(Self::NullifyFinalize(v))
            }
            _ => Err(Error::Invalid(
                "consensus::simplex::Activity",
                "Invalid type",
            )),
        }
    }
}

impl<S: Scheme, D: Digest> Epochable for Activity<S, D> {
    fn epoch(&self) -> Epoch {
        match self {
            Self::Notarize(v) => v.epoch(),
            Self::Notarization(v) => v.epoch(),
            Self::Certification(v) => v.epoch(),
            Self::Nullify(v) => v.epoch(),
            Self::Nullification(v) => v.epoch(),
            Self::Finalize(v) => v.epoch(),
            Self::Finalization(v) => v.epoch(),
            Self::ConflictingNotarize(v) => v.epoch(),
            Self::ConflictingFinalize(v) => v.epoch(),
            Self::NullifyFinalize(v) => v.epoch(),
        }
    }
}

impl<S: Scheme, D: Digest> Viewable for Activity<S, D> {
    fn view(&self) -> View {
        match self {
            Self::Notarize(v) => v.view(),
            Self::Notarization(v) => v.view(),
            Self::Certification(v) => v.view(),
            Self::Nullify(v) => v.view(),
            Self::Nullification(v) => v.view(),
            Self::Finalize(v) => v.view(),
            Self::Finalization(v) => v.view(),
            Self::ConflictingNotarize(v) => v.view(),
            Self::ConflictingFinalize(v) => v.view(),
            Self::NullifyFinalize(v) => v.view(),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for Activity<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = u.int_in_range(0..=9)?;
        match tag {
            0 => {
                let v = Notarize::<S, D>::arbitrary(u)?;
                Ok(Self::Notarize(v))
            }
            1 => {
                let v = Notarization::<S, D>::arbitrary(u)?;
                Ok(Self::Notarization(v))
            }
            2 => {
                let v = Notarization::<S, D>::arbitrary(u)?;
                Ok(Self::Certification(v))
            }
            3 => {
                let v = Nullify::<S>::arbitrary(u)?;
                Ok(Self::Nullify(v))
            }
            4 => {
                let v = Nullification::<S>::arbitrary(u)?;
                Ok(Self::Nullification(v))
            }
            5 => {
                let v = Finalize::<S, D>::arbitrary(u)?;
                Ok(Self::Finalize(v))
            }
            6 => {
                let v = Finalization::<S, D>::arbitrary(u)?;
                Ok(Self::Finalization(v))
            }
            7 => {
                let v = ConflictingNotarize::<S, D>::arbitrary(u)?;
                Ok(Self::ConflictingNotarize(v))
            }
            8 => {
                let v = ConflictingFinalize::<S, D>::arbitrary(u)?;
                Ok(Self::ConflictingFinalize(v))
            }
            9 => {
                let v = NullifyFinalize::<S, D>::arbitrary(u)?;
                Ok(Self::NullifyFinalize(v))
            }
            _ => unreachable!(),
        }
    }
}

/// ConflictingNotarize represents evidence of a Byzantine validator sending conflicting notarizes.
/// This is used to prove that a validator has equivocated (voted for different proposals in the same view).
#[derive(Clone, Debug)]
pub struct ConflictingNotarize<S: Scheme, D: Digest> {
    /// The first conflicting notarize
    notarize_1: Notarize<S, D>,
    /// The second conflicting notarize
    notarize_2: Notarize<S, D>,
}

impl<S: Scheme, D: Digest> PartialEq for ConflictingNotarize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.notarize_1 == other.notarize_1 && self.notarize_2 == other.notarize_2
    }
}

impl<S: Scheme, D: Digest> Eq for ConflictingNotarize<S, D> {}

impl<S: Scheme, D: Digest> Hash for ConflictingNotarize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.notarize_1.hash(state);
        self.notarize_2.hash(state);
    }
}

impl<S: Scheme, D: Digest> ConflictingNotarize<S, D> {
    /// Creates a new conflicting notarize evidence from two conflicting notarizes.
    ///
    /// # Panics
    ///
    /// Panics if the two notarizes do not have the same round and signer, or if they
    /// have identical proposals (which would not constitute conflicting evidence).
    pub fn new(notarize_1: Notarize<S, D>, notarize_2: Notarize<S, D>) -> Self {
        assert_eq!(notarize_1.round(), notarize_2.round());
        assert_eq!(notarize_1.signer(), notarize_2.signer());
        assert_ne!(
            notarize_1.proposal, notarize_2.proposal,
            "proposals must differ to constitute conflicting evidence"
        );

        Self {
            notarize_1,
            notarize_2,
        }
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        self.notarize_1.verify(rng, scheme, strategy)
            && self.notarize_2.verify(rng, scheme, strategy)
    }
}

impl<S: Scheme, D: Digest> Attributable for ConflictingNotarize<S, D> {
    fn signer(&self) -> Participant {
        self.notarize_1.signer()
    }
}

impl<S: Scheme, D: Digest> Epochable for ConflictingNotarize<S, D> {
    fn epoch(&self) -> Epoch {
        self.notarize_1.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for ConflictingNotarize<S, D> {
    fn view(&self) -> View {
        self.notarize_1.view()
    }
}

impl<S: Scheme, D: Digest> Write for ConflictingNotarize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.notarize_1.write(writer);
        self.notarize_2.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for ConflictingNotarize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let notarize_1 = Notarize::read(reader)?;
        let notarize_2 = Notarize::read(reader)?;

        if notarize_1.signer() != notarize_2.signer()
            || notarize_1.round() != notarize_2.round()
            || notarize_1.proposal == notarize_2.proposal
        {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingNotarize",
                "invalid conflicting notarize",
            ));
        }

        Ok(Self {
            notarize_1,
            notarize_2,
        })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for ConflictingNotarize<S, D> {
    fn encode_size(&self) -> usize {
        self.notarize_1.encode_size() + self.notarize_2.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for ConflictingNotarize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let notarize_1 = Notarize::arbitrary(u)?;
        let notarize_2 = Notarize::arbitrary(u)?;
        Ok(Self {
            notarize_1,
            notarize_2,
        })
    }
}

/// ConflictingFinalize represents evidence of a Byzantine validator sending conflicting finalizes.
/// Similar to ConflictingNotarize, but for finalizes.
#[derive(Clone, Debug)]
pub struct ConflictingFinalize<S: Scheme, D: Digest> {
    /// The second conflicting finalize
    finalize_1: Finalize<S, D>,
    /// The second conflicting finalize
    finalize_2: Finalize<S, D>,
}

impl<S: Scheme, D: Digest> PartialEq for ConflictingFinalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.finalize_1 == other.finalize_1 && self.finalize_2 == other.finalize_2
    }
}

impl<S: Scheme, D: Digest> Eq for ConflictingFinalize<S, D> {}

impl<S: Scheme, D: Digest> Hash for ConflictingFinalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.finalize_1.hash(state);
        self.finalize_2.hash(state);
    }
}

impl<S: Scheme, D: Digest> ConflictingFinalize<S, D> {
    /// Creates a new conflicting finalize evidence from two conflicting finalizes.
    ///
    /// # Panics
    ///
    /// Panics if the two finalizes do not have the same round and signer, or if they
    /// have identical proposals (which would not constitute conflicting evidence).
    pub fn new(finalize_1: Finalize<S, D>, finalize_2: Finalize<S, D>) -> Self {
        assert_eq!(finalize_1.round(), finalize_2.round());
        assert_eq!(finalize_1.signer(), finalize_2.signer());
        assert_ne!(
            finalize_1.proposal, finalize_2.proposal,
            "proposals must differ to constitute conflicting evidence"
        );

        Self {
            finalize_1,
            finalize_2,
        }
    }

    /// Verifies that both conflicting signatures are valid, proving Byzantine behavior.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        self.finalize_1.verify(rng, scheme, strategy)
            && self.finalize_2.verify(rng, scheme, strategy)
    }
}

impl<S: Scheme, D: Digest> Attributable for ConflictingFinalize<S, D> {
    fn signer(&self) -> Participant {
        self.finalize_1.signer()
    }
}

impl<S: Scheme, D: Digest> Epochable for ConflictingFinalize<S, D> {
    fn epoch(&self) -> Epoch {
        self.finalize_1.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for ConflictingFinalize<S, D> {
    fn view(&self) -> View {
        self.finalize_1.view()
    }
}

impl<S: Scheme, D: Digest> Write for ConflictingFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.finalize_1.write(writer);
        self.finalize_2.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for ConflictingFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let finalize_1 = Finalize::read(reader)?;
        let finalize_2 = Finalize::read(reader)?;

        if finalize_1.signer() != finalize_2.signer()
            || finalize_1.round() != finalize_2.round()
            || finalize_1.proposal == finalize_2.proposal
        {
            return Err(Error::Invalid(
                "consensus::simplex::ConflictingFinalize",
                "invalid conflicting finalize",
            ));
        }

        Ok(Self {
            finalize_1,
            finalize_2,
        })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for ConflictingFinalize<S, D> {
    fn encode_size(&self) -> usize {
        self.finalize_1.encode_size() + self.finalize_2.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for ConflictingFinalize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let finalize_1 = Finalize::arbitrary(u)?;
        let finalize_2 = Finalize::arbitrary(u)?;
        Ok(Self {
            finalize_1,
            finalize_2,
        })
    }
}

/// NullifyFinalize represents evidence of a Byzantine validator sending both a nullify and finalize
/// for the same view, which is contradictory behavior (a validator should either try to skip a view OR
/// finalize a proposal, not both).
#[derive(Clone, Debug)]
pub struct NullifyFinalize<S: Scheme, D: Digest> {
    /// The conflicting nullify
    nullify: Nullify<S>,
    /// The conflicting finalize
    finalize: Finalize<S, D>,
}

impl<S: Scheme, D: Digest> PartialEq for NullifyFinalize<S, D> {
    fn eq(&self, other: &Self) -> bool {
        self.nullify == other.nullify && self.finalize == other.finalize
    }
}

impl<S: Scheme, D: Digest> Eq for NullifyFinalize<S, D> {}

impl<S: Scheme, D: Digest> Hash for NullifyFinalize<S, D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nullify.hash(state);
        self.finalize.hash(state);
    }
}

impl<S: Scheme, D: Digest> NullifyFinalize<S, D> {
    /// Creates a new nullify-finalize evidence from a nullify and a finalize.
    pub fn new(nullify: Nullify<S>, finalize: Finalize<S, D>) -> Self {
        assert_eq!(nullify.round, finalize.round());
        assert_eq!(nullify.signer(), finalize.signer());

        Self { nullify, finalize }
    }

    /// Verifies that both the nullify and finalize signatures are valid, proving Byzantine behavior.
    pub fn verify<R>(&self, rng: &mut R, scheme: &S, strategy: &impl Strategy) -> bool
    where
        R: CryptoRng,
        S: scheme::Scheme<D>,
    {
        self.nullify.verify(rng, scheme, strategy) && self.finalize.verify(rng, scheme, strategy)
    }
}

impl<S: Scheme, D: Digest> Attributable for NullifyFinalize<S, D> {
    fn signer(&self) -> Participant {
        self.nullify.signer()
    }
}

impl<S: Scheme, D: Digest> Epochable for NullifyFinalize<S, D> {
    fn epoch(&self) -> Epoch {
        self.nullify.epoch()
    }
}

impl<S: Scheme, D: Digest> Viewable for NullifyFinalize<S, D> {
    fn view(&self) -> View {
        self.nullify.view()
    }
}

impl<S: Scheme, D: Digest> Write for NullifyFinalize<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        self.nullify.write(writer);
        self.finalize.write(writer);
    }
}

impl<S: Scheme, D: Digest> Read for NullifyFinalize<S, D> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let nullify = Nullify::read(reader)?;
        let finalize = Finalize::read(reader)?;

        if nullify.signer() != finalize.signer() || nullify.round != finalize.round() {
            return Err(Error::Invalid(
                "consensus::simplex::NullifyFinalize",
                "mismatched signatures",
            ));
        }

        Ok(Self { nullify, finalize })
    }
}

impl<S: Scheme, D: Digest> EncodeSize for NullifyFinalize<S, D> {
    fn encode_size(&self) -> usize {
        self.nullify.encode_size() + self.finalize.encode_size()
    }
}

#[cfg(feature = "arbitrary")]
impl<S: Scheme, D: Digest> arbitrary::Arbitrary<'_> for NullifyFinalize<S, D>
where
    S::Signature: for<'a> arbitrary::Arbitrary<'a>,
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let nullify = Nullify::arbitrary(u)?;
        let finalize = Finalize::arbitrary(u)?;
        Ok(Self { nullify, finalize })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        quorum,
        scheme::{
            bls12381_multisig,
            bls12381_threshold::{
                standard as bls12381_threshold_std, vrf as bls12381_threshold_vrf,
            },
            ed25519, secp256r1, Scheme,
        },
    };
    use bytes::Bytes;
    use commonware_codec::{Decode, DecodeExt, Encode};
    use commonware_cryptography::{
        bls12381::primitives::variant::{MinPk, MinSig},
        certificate::mocks::Fixture,
        sha256::Digest as Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, Faults, N3f1, TestRng};

    const NAMESPACE: &[u8] = b"test";

    // Helper function to create a sample digest
    fn sample_digest(v: u8) -> Sha256 {
        Sha256::from([v; 32]) // Simple fixed digest for testing
    }

    /// Generate a fixture using the provided generator function with a specific seed.
    fn setup_seeded<S, F>(n: u32, seed: u64, fixture: F) -> Fixture<S>
    where
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        setup_seeded_ns(n, seed, NAMESPACE, fixture)
    }

    /// Generate a fixture using the provided generator function with a specific seed and namespace.
    fn setup_seeded_ns<S, F>(n: u32, seed: u64, namespace: &[u8], fixture: F) -> Fixture<S>
    where
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = TestRng::new(seed);
        fixture(&mut rng, namespace, n)
    }

    #[test]
    fn test_proposal_encode_decode() {
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let encoded = proposal.encode();
        let decoded = Proposal::<Sha256>::decode(encoded).unwrap();
        assert_eq!(proposal, decoded);
    }

    fn notarize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        let encoded = notarize.encode();
        let decoded = Notarize::decode(encoded).unwrap();

        assert_eq!(notarize, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarize_encode_decode() {
        notarize_encode_decode(ed25519::fixture);
        notarize_encode_decode(secp256r1::fixture);
        notarize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();
        let encoded = notarization.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Notarization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(notarization, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarization_encode_decode() {
        notarization_encode_decode(ed25519::fixture);
        notarization_encode_decode(secp256r1::fixture);
        notarization_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        notarization_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let nullify = Nullify::sign::<Sha256>(&fixture.schemes[0], round).unwrap();
        let encoded = nullify.encode();
        let decoded = Nullify::decode(encoded).unwrap();
        assert_eq!(nullify, decoded);
        assert!(decoded.verify::<_, Sha256>(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullify_encode_decode() {
        nullify_encode_decode(ed25519::fixture);
        nullify_encode_decode(secp256r1::fixture);
        nullify_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullify_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullification_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(333), View::new(10));
        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_nullifies(&fixture.schemes[0], &nullifies, &Sequential).unwrap();
        let encoded = nullification.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Nullification::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(nullification, decoded);
        assert!(decoded.verify::<_, Sha256>(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullification_encode_decode() {
        nullification_encode_decode(ed25519::fixture);
        nullification_encode_decode(secp256r1::fixture);
        nullification_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullification_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullification_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullification_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let encoded = finalize.encode();
        let decoded = Finalize::decode(encoded).unwrap();
        assert_eq!(finalize, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_finalize_encode_decode() {
        finalize_encode_decode(ed25519::fixture);
        finalize_encode_decode(secp256r1::fixture);
        finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalization_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&fixture.schemes[0], &finalizes, &Sequential).unwrap();
        let encoded = finalization.encode();
        let cfg = fixture.schemes[0].certificate_codec_config();
        let decoded = Finalization::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(finalization, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_finalization_encode_decode() {
        finalization_encode_decode(ed25519::fixture);
        finalization_encode_decode(secp256r1::fixture);
        finalization_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        finalization_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalization_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        finalization_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn backfiller_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let cfg = fixture.schemes[0].certificate_codec_config();
        let request = Request::new(
            1,
            vec![View::new(10), View::new(11)],
            vec![View::new(12), View::new(13)],
        );
        let encoded_request = Backfiller::<S, Sha256>::Request(request.clone()).encode();
        let decoded_request =
            Backfiller::<S, Sha256>::decode_cfg(encoded_request, &(usize::MAX, cfg.clone()))
                .unwrap();
        assert!(matches!(decoded_request, Backfiller::Request(r) if r == request));

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();

        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_nullifies(&fixture.schemes[0], &nullifies, &Sequential).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let encoded_response = Backfiller::<S, Sha256>::Response(response.clone()).encode();
        let decoded_response =
            Backfiller::<S, Sha256>::decode_cfg(encoded_response, &(usize::MAX, cfg)).unwrap();
        assert!(matches!(decoded_response, Backfiller::Response(r) if r.id == response.id));
    }

    #[test]
    fn test_backfiller_encode_decode() {
        backfiller_encode_decode(ed25519::fixture);
        backfiller_encode_decode(secp256r1::fixture);
        backfiller_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        backfiller_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        backfiller_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        backfiller_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    #[test]
    fn test_request_encode_decode() {
        let request = Request::new(
            1,
            vec![View::new(10), View::new(11)],
            vec![View::new(12), View::new(13)],
        );
        let encoded = request.encode();
        let decoded = Request::decode_cfg(encoded, &usize::MAX).unwrap();
        assert_eq!(request, decoded);
    }

    fn response_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));

        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential).unwrap();

        let nullifies: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256>(scheme, round).unwrap())
            .collect();
        let nullification =
            Nullification::from_nullifies(&fixture.schemes[0], &nullifies, &Sequential).unwrap();

        let response = Response::<S, Sha256>::new(1, vec![notarization], vec![nullification]);
        let cfg = fixture.schemes[0].certificate_codec_config();
        let mut decoded =
            Response::<S, Sha256>::decode_cfg(response.encode(), &(usize::MAX, cfg)).unwrap();
        assert_eq!(response.id, decoded.id);
        assert_eq!(response.notarizations.len(), decoded.notarizations.len());
        assert_eq!(response.nullifications.len(), decoded.nullifications.len());

        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));

        decoded.nullifications[0].round = Round::new(
            decoded.nullifications[0].round.epoch(),
            decoded.nullifications[0].round.view().next(),
        );
        assert!(!decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_response_encode_decode() {
        response_encode_decode(ed25519::fixture);
        response_encode_decode(secp256r1::fixture);
        response_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        response_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        response_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        response_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        response_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        response_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_notarize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal1 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let proposal2 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(2),
        );
        let notarize1 = Notarize::sign(&fixture.schemes[0], proposal1).unwrap();
        let notarize2 = Notarize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflicting = ConflictingNotarize::new(notarize1, notarize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingNotarize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_conflicting_notarize_encode_decode() {
        conflicting_notarize_encode_decode(ed25519::fixture);
        conflicting_notarize_encode_decode(secp256r1::fixture);
        conflicting_notarize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_notarize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let proposal1 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let proposal2 = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(2),
        );
        let finalize1 = Finalize::sign(&fixture.schemes[0], proposal1).unwrap();
        let finalize2 = Finalize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflicting = ConflictingFinalize::new(finalize1, finalize2);

        let encoded = conflicting.encode();
        let decoded = ConflictingFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflicting, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_conflicting_finalize_encode_decode() {
        conflicting_finalize_encode_decode(ed25519::fixture);
        conflicting_finalize_encode_decode(secp256r1::fixture);
        conflicting_finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_finalize_encode_decode<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let nullify = Nullify::sign::<Sha256>(&fixture.schemes[0], round).unwrap();
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let conflict = NullifyFinalize::new(nullify, finalize);

        let encoded = conflict.encode();
        let decoded = NullifyFinalize::<S, Sha256>::decode(encoded).unwrap();

        assert_eq!(conflict, decoded);
        assert!(decoded.verify(&mut rng, &fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_nullify_finalize_encode_decode() {
        nullify_finalize_encode_decode(ed25519::fixture);
        nullify_finalize_encode_decode(secp256r1::fixture);
        nullify_finalize_encode_decode(bls12381_multisig::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_multisig::fixture::<MinSig, _>);
        nullify_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_finalize_encode_decode(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_finalize_encode_decode(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarize_verify_wrong_namespace<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Create two fixtures with different namespaces
        let mut rng = test_rng();
        let fixture = setup_seeded_ns(5, 0, NAMESPACE, &f);
        let wrong_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(1));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        assert!(notarize.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarize.verify(&mut rng, &wrong_fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarize_verify_wrong_namespace() {
        notarize_verify_wrong_namespace(ed25519::fixture);
        notarize_verify_wrong_namespace(secp256r1::fixture);
        notarize_verify_wrong_namespace(bls12381_multisig::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_multisig::fixture::<MinSig, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarize_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(2));
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        assert!(notarize.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarize.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_notarize_verify_wrong_scheme() {
        notarize_verify_wrong_scheme(ed25519::fixture);
        notarize_verify_wrong_scheme(secp256r1::fixture);
        notarize_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        notarize_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(3));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization =
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential)
                .expect("quorum notarization");
        assert!(notarization.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!notarization.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_notarization_verify_wrong_scheme() {
        notarization_verify_wrong_scheme(ed25519::fixture);
        notarization_verify_wrong_scheme(secp256r1::fixture);
        notarization_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_verify_wrong_namespace<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        // Create two fixtures with different namespaces
        let fixture = setup_seeded_ns(5, 0, NAMESPACE, &f);
        let wrong_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let mut rng = test_rng();
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(4));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let notarization =
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential)
                .expect("quorum notarization");
        assert!(notarization.verify(&mut rng, &fixture.schemes[0], &Sequential));

        assert!(!notarization.verify(&mut rng, &wrong_fixture.schemes[0], &Sequential));
    }

    #[test]
    fn test_notarization_verify_wrong_namespace() {
        notarization_verify_wrong_namespace(ed25519::fixture);
        notarization_verify_wrong_namespace(secp256r1::fixture);
        notarization_verify_wrong_namespace(bls12381_multisig::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_multisig::fixture::<MinSig, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_verify_wrong_namespace(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn notarization_recover_insufficient_signatures<S, F>(fixture: F)
    where
        S: Scheme<Sha256>,
        F: FnOnce(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = fixture(&mut rng, NAMESPACE, 5);
        let quorum_size = quorum(fixture.schemes.len() as u32) as usize;
        assert!(quorum_size > 1, "test requires quorum larger than one");
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(5));
        let notarizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum_size - 1)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        assert!(
            Notarization::from_notarizes(&fixture.schemes[0], &notarizes, &Sequential).is_none(),
            "insufficient votes should not form a notarization"
        );
    }

    #[test]
    fn test_notarization_recover_insufficient_signatures() {
        notarization_recover_insufficient_signatures(ed25519::fixture);
        notarization_recover_insufficient_signatures(secp256r1::fixture);
        notarization_recover_insufficient_signatures(bls12381_multisig::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_multisig::fixture::<MinSig, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_vrf::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_vrf::fixture::<MinSig, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_std::fixture::<MinPk, _>);
        notarization_recover_insufficient_signatures(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn conflicting_notarize_detection<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_ns_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let wrong_scheme_fixture = setup_seeded(5, 1, &f);

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal1 = Proposal::new(round, View::new(5), sample_digest(6));
        let proposal2 = Proposal::new(round, View::new(5), sample_digest(7));

        let notarize1 = Notarize::sign(&fixture.schemes[0], proposal1).unwrap();
        let notarize2 = Notarize::sign(&fixture.schemes[0], proposal2).unwrap();
        let conflict = ConflictingNotarize::new(notarize1, notarize2);

        assert!(conflict.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_ns_fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_scheme_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_conflicting_notarize_detection() {
        conflicting_notarize_detection(ed25519::fixture);
        conflicting_notarize_detection(secp256r1::fixture);
        conflicting_notarize_detection(bls12381_multisig::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_multisig::fixture::<MinSig, _>);
        conflicting_notarize_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        conflicting_notarize_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        conflicting_notarize_detection(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn nullify_finalize_detection<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_ns_fixture = setup_seeded_ns(5, 0, b"wrong_namespace", &f);
        let wrong_scheme_fixture = setup_seeded(5, 1, &f);

        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(8));

        let nullify = Nullify::sign::<Sha256>(&fixture.schemes[0], round).unwrap();
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let conflict = NullifyFinalize::new(nullify, finalize);

        assert!(conflict.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_ns_fixture.schemes[0], &Sequential));
        assert!(!conflict.verify(&mut rng, &wrong_scheme_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_nullify_finalize_detection() {
        nullify_finalize_detection(ed25519::fixture);
        nullify_finalize_detection(secp256r1::fixture);
        nullify_finalize_detection(bls12381_multisig::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_multisig::fixture::<MinSig, _>);
        nullify_finalize_detection(bls12381_threshold_vrf::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_threshold_vrf::fixture::<MinSig, _>);
        nullify_finalize_detection(bls12381_threshold_std::fixture::<MinPk, _>);
        nullify_finalize_detection(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    fn finalization_verify_wrong_scheme<S, F>(f: F)
    where
        S: Scheme<Sha256>,
        F: Fn(&mut TestRng, &[u8], u32) -> Fixture<S>,
    {
        let mut rng = test_rng();
        let fixture = setup_seeded(5, 0, &f);
        let wrong_fixture = setup_seeded(5, 1, &f);
        let round = Round::new(Epoch::new(0), View::new(10));
        let proposal = Proposal::new(round, View::new(5), sample_digest(9));
        let quorum = N3f1::quorum(fixture.schemes.len()) as usize;
        let finalizes: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        let finalization =
            Finalization::from_finalizes(&fixture.schemes[0], &finalizes, &Sequential)
                .expect("quorum finalization");
        assert!(finalization.verify(&mut rng, &fixture.schemes[0], &Sequential));
        assert!(!finalization.verify(&mut rng, &wrong_fixture.verifier, &Sequential));
    }

    #[test]
    fn test_finalization_wrong_scheme() {
        finalization_verify_wrong_scheme(ed25519::fixture);
        finalization_verify_wrong_scheme(secp256r1::fixture);
        finalization_verify_wrong_scheme(bls12381_multisig::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_multisig::fixture::<MinSig, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_vrf::fixture::<MinSig, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinPk, _>);
        finalization_verify_wrong_scheme(bls12381_threshold_std::fixture::<MinSig, _>);
    }

    struct MockAttributable(Participant);

    impl Attributable for MockAttributable {
        fn signer(&self) -> Participant {
            self.0
        }
    }

    #[test]
    fn test_attributable_map() {
        let mut map = AttributableMap::new(5);
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());

        // Test get on empty map
        for i in 0..5 {
            assert!(map.get(Participant::new(i)).is_none());
        }

        assert!(map.insert(MockAttributable(Participant::new(3))));
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test get on existing item
        assert!(
            matches!(map.get(Participant::new(3)), Some(a) if a.signer() == Participant::new(3))
        );

        assert!(map.insert(MockAttributable(Participant::new(1))));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(1)));
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test get on both items
        assert!(
            matches!(map.get(Participant::new(1)), Some(a) if a.signer() == Participant::new(1))
        );
        assert!(
            matches!(map.get(Participant::new(3)), Some(a) if a.signer() == Participant::new(3))
        );

        // Test get on non-existing items
        assert!(map.get(Participant::new(0)).is_none());
        assert!(map.get(Participant::new(2)).is_none());
        assert!(map.get(Participant::new(4)).is_none());

        assert!(!map.insert(MockAttributable(Participant::new(3))));
        assert_eq!(map.len(), 2);
        assert!(!map.is_empty());
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(1)));
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(3)));
        assert!(iter.next().is_none());
        drop(iter);

        // Test out-of-bounds signer indices
        assert!(!map.insert(MockAttributable(Participant::new(5))));
        assert!(!map.insert(MockAttributable(Participant::new(100))));
        assert_eq!(map.len(), 2);

        // Test clear
        map.clear();
        assert_eq!(map.len(), 0);
        assert!(map.is_empty());
        assert!(map.iter().next().is_none());

        // Verify can insert after clear
        assert!(map.insert(MockAttributable(Participant::new(2))));
        assert_eq!(map.len(), 1);
        let mut iter = map.iter();
        assert!(matches!(iter.next(), Some(a) if a.signer() == Participant::new(2)));
        assert!(iter.next().is_none());
    }

    #[test]
    #[should_panic(expected = "proposals must differ")]
    fn issue_2944_regression_conflicting_notarize_new() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();
        let _ = ConflictingNotarize::new(notarize.clone(), notarize);
    }

    #[test]
    fn issue_2944_regression_conflicting_notarize_decode() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let notarize = Notarize::sign(&fixture.schemes[0], proposal).unwrap();

        // Manually encode two identical notarizes
        let mut buf = Vec::new();
        notarize.write(&mut buf);
        notarize.write(&mut buf);

        // Decoding should fail
        let result = ConflictingNotarize::<ed25519::Scheme, Sha256>::decode(Bytes::from(buf));
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "proposals must differ")]
    fn issue_2944_regression_conflicting_finalize_new() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();
        let _ = ConflictingFinalize::new(finalize.clone(), finalize);
    }

    #[test]
    fn issue_2944_regression_conflicting_finalize_decode() {
        let mut rng = test_rng();
        let fixture = ed25519::fixture(&mut rng, NAMESPACE, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(10)),
            View::new(5),
            sample_digest(1),
        );
        let finalize = Finalize::sign(&fixture.schemes[0], proposal).unwrap();

        // Manually encode two identical finalizes
        let mut buf = Vec::new();
        finalize.write(&mut buf);
        finalize.write(&mut buf);

        // Decoding should fail
        let result = ConflictingFinalize::<ed25519::Scheme, Sha256>::decode(Bytes::from(buf));
        assert!(result.is_err());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::simplex::scheme::bls12381_threshold::vrf as bls12381_threshold_vrf;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::{ed25519::PublicKey, sha256::Digest as Sha256Digest};

        type Scheme = bls12381_threshold_vrf::Scheme<PublicKey, MinSig>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Vote<Scheme, Sha256Digest>>,
            CodecConformance<Certificate<Scheme, Sha256Digest>>,
            CodecConformance<Artifact<Scheme, Sha256Digest>>,
            CodecConformance<Proposal<Sha256Digest>>,
            CodecConformance<Notarize<Scheme, Sha256Digest>>,
            CodecConformance<Notarization<Scheme, Sha256Digest>>,
            CodecConformance<Nullify<Scheme>>,
            CodecConformance<Nullification<Scheme>>,
            CodecConformance<Finalize<Scheme, Sha256Digest>>,
            CodecConformance<Finalization<Scheme, Sha256Digest>>,
            CodecConformance<Backfiller<Scheme, Sha256Digest>>,
            CodecConformance<Request>,
            CodecConformance<Response<Scheme, Sha256Digest>>,
            CodecConformance<Activity<Scheme, Sha256Digest>>,
            CodecConformance<ConflictingNotarize<Scheme, Sha256Digest>>,
            CodecConformance<ConflictingFinalize<Scheme, Sha256Digest>>,
            CodecConformance<NullifyFinalize<Scheme, Sha256Digest>>,
            CodecConformance<Context<Sha256Digest, PublicKey>>
        }
    }
}
