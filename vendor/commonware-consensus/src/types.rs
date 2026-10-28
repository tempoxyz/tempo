//! Consensus types shared across the crate.
//!
//! This module defines the core types used throughout the consensus implementation:
//!
//! - [`Epoch`]: Represents a distinct segment of a contiguous sequence of views. When the validator
//!   set changes, the epoch increments. Epochs provide reconfiguration boundaries for the consensus
//!   protocol.
//!
//! - [`Height`]: Represents a sequential position in a chain or sequence.
//!
//! - [`View`]: A monotonically increasing counter within a single epoch, representing individual
//!   consensus rounds. Views advance as the protocol progresses through proposals and votes.
//!
//! - [`Round`]: Combines an epoch and view into a single identifier for a consensus round.
//!   Provides ordering across epoch boundaries.
//!
//! - [`Delta`]: A generic type representing offsets or durations for consensus types. Provides
//!   type safety to prevent mixing epoch, height, and view deltas. Type aliases [`EpochDelta`],
//!   [`HeightDelta`], and [`ViewDelta`] are provided for convenience.
//!
//! - [`TermLength`]: The number of consecutive views in which a leader remains stable (a "term").
//!
//! - [`Epocher`]: Mechanism for determining epoch boundaries.
//!
//! - [`coding::Commitment`]: A unique identifier combining a block digest, coding digest, context
//!   hash, and encoded coding configuration. Used as the certificate payload for erasure-coded blocks.
//!
//! # Arithmetic Safety
//!
//! Arithmetic operations avoid silent errors. Only `next()`, `View::term_end()`, and
//! `View::next_term_start()` panic on overflow. All other operations either saturate or
//! return `Option`.
//!
//! # Type Conversions
//!
//! Explicit type constructors (`Epoch::new()`, `View::new()`) are required to create instances
//! from raw integers. Implicit conversions via, e.g. `From<u64>` are intentionally not provided
//! to prevent accidental type misuse.

use crate::{Epochable, Viewable};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
#[cfg(not(target_arch = "wasm32"))]
use commonware_runtime::telemetry::traces::TracedExt;
use commonware_utils::sequence::U64;
use core::{
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    num::{NonZeroU32, NonZeroU64},
    ops::RangeInclusive,
};

/// Represents a distinct segment of a contiguous sequence of views.
///
/// An epoch increments when the validator set changes, providing a reconfiguration boundary.
/// All consensus operations within an epoch use the same validator set.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Epoch(u64);

impl Epoch {
    /// Returns epoch zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new epoch from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is epoch zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next epoch.
    ///
    /// # Panics
    ///
    /// Panics if the epoch would overflow u64::MAX. In practice, this is extremely unlikely
    /// to occur during normal operation.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("epoch overflow"))
    }

    /// Returns the previous epoch, or `None` if this is epoch zero.
    ///
    /// Unlike `Epoch::next()`, this returns an Option since reaching epoch zero
    /// is common, whereas overflowing u64::MAX is not expected in normal
    /// operation.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Adds a delta to this epoch, saturating at u64::MAX.
    pub const fn saturating_add(self, delta: EpochDelta) -> Self {
        Self(self.0.saturating_add(delta.0))
    }

    /// Subtracts a delta from this epoch, returning `None` if it would underflow.
    pub fn checked_sub(self, delta: EpochDelta) -> Option<Self> {
        self.0.checked_sub(delta.0).map(Self)
    }

    /// Subtracts a delta from this epoch, saturating at zero.
    pub const fn saturating_sub(self, delta: EpochDelta) -> Self {
        Self(self.0.saturating_sub(delta.0))
    }
}

impl Display for Epoch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Read for Epoch {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value: u64 = UInt::read(buf)?.into();
        Ok(Self(value))
    }
}

impl Write for Epoch {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl EncodeSize for Epoch {
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl From<Epoch> for U64 {
    fn from(epoch: Epoch) -> Self {
        Self::from(epoch.get())
    }
}

/// Represents a sequential position in a chain or sequence.
///
/// Height is a monotonically increasing counter. Height zero is the genesis block.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Height(u64);

impl Height {
    /// Returns height zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new height from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is height zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next height.
    ///
    /// # Panics
    ///
    /// Panics if the height would overflow u64::MAX. In practice, this is extremely unlikely
    /// to occur during normal operation.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("height overflow"))
    }

    /// Returns the previous height, or `None` if this is height zero.
    ///
    /// Unlike `Height::next()`, this returns an Option since reaching height zero
    /// is common, whereas overflowing u64::MAX is not expected in normal
    /// operation.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Adds a height delta, saturating at u64::MAX.
    pub const fn saturating_add(self, delta: HeightDelta) -> Self {
        Self(self.0.saturating_add(delta.0))
    }

    /// Subtracts a height delta, saturating at zero.
    pub const fn saturating_sub(self, delta: HeightDelta) -> Self {
        Self(self.0.saturating_sub(delta.0))
    }

    /// Returns the delta from `other` to `self`, or `None` if `other > self`.
    pub fn delta_from(self, other: Self) -> Option<HeightDelta> {
        self.0.checked_sub(other.0).map(HeightDelta::new)
    }

    /// Returns an iterator over the range [start, end).
    ///
    /// If start >= end, returns an empty range.
    pub const fn range(start: Self, end: Self) -> HeightRange {
        HeightRange {
            inner: start.get()..end.get(),
        }
    }
}

impl Display for Height {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Read for Height {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value: u64 = UInt::read(buf)?.into();
        Ok(Self(value))
    }
}

impl Write for Height {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl EncodeSize for Height {
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl From<Height> for U64 {
    fn from(height: Height) -> Self {
        Self::from(height.get())
    }
}

/// A monotonically increasing counter within a single epoch.
///
/// Views represent individual consensus rounds within an epoch. Each view corresponds to
/// one attempt to reach consensus on a proposal.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct View(u64);

impl View {
    /// Returns view zero.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Creates a new view from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this is view zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Returns the next view.
    ///
    /// # Panics
    ///
    /// Panics if the view would overflow u64::MAX. In practice, this is extremely unlikely
    /// to occur during normal operation.
    pub const fn next(self) -> Self {
        Self(self.0.checked_add(1).expect("view overflow"))
    }

    /// Returns the previous view, or `None` if this is view zero.
    ///
    /// Unlike `View::next()`, this returns an Option since reaching view zero
    /// is common, whereas overflowing u64::MAX is not expected in normal
    /// operation.
    pub fn previous(self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }

    /// Adds a view delta, saturating at u64::MAX.
    pub const fn saturating_add(self, delta: ViewDelta) -> Self {
        Self(self.0.saturating_add(delta.0))
    }

    /// Subtracts a view delta, saturating at zero.
    pub const fn saturating_sub(self, delta: ViewDelta) -> Self {
        Self(self.0.saturating_sub(delta.0))
    }

    /// Returns an iterator over the range [start, end).
    ///
    /// If start >= end, returns an empty range.
    pub const fn range(start: Self, end: Self) -> ViewRange {
        ViewRange {
            inner: start.get()..end.get(),
        }
    }

    /// Returns the first view of the term containing this view.
    ///
    /// Terms group consecutive views so that the same leader serves for
    /// `term_length` views. View 0 (genesis) is its own term. For views >= 1,
    /// term boundaries are: [1, term_length], [term_length+1, 2*term_length], ...
    ///
    /// When `term_length` is 1, every view is its own term (no grouping).
    pub const fn term_start(self, term_length: TermLength) -> Self {
        let term_length = term_length.get();
        let Self(view) = self;
        if view == 0 {
            return self;
        }
        // Cannot overflow: base is at most view - 1.
        let base = (view - 1) / term_length * term_length;
        Self(base).next()
    }

    /// Returns whether this view is the first view of its term.
    pub const fn is_term_start(self, term_length: TermLength) -> bool {
        let start = self.term_start(term_length);
        self.get() == start.get()
    }

    /// Returns whether this view shares a term with `other`.
    pub const fn same_term(self, other: Self, term_length: TermLength) -> bool {
        let start = self.term_start(term_length);
        let other_start = other.term_start(term_length);
        start.get() == other_start.get()
    }

    /// Returns the last view of the term containing this view.
    ///
    /// See [`term_start`](View::term_start) for term boundary semantics.
    ///
    /// When `term_length` is 1, returns `self`.
    pub const fn term_end(self, term_length: TermLength) -> Self {
        if self.0 == 0 {
            return self;
        }
        let end = self
            .term_start(term_length)
            .get()
            .checked_add(term_length.get() - 1)
            .expect("view term_end overflow");
        Self(end)
    }

    /// Returns the first view of the term that follows this view's term.
    ///
    /// When `term_length` is 1, returns `self.next()`.
    pub const fn next_term_start(self, term_length: TermLength) -> Self {
        self.term_end(term_length).next()
    }

    /// Returns the index of the term containing this view.
    ///
    /// View 0 (genesis) is its own term with index 0; terms of later views
    /// are numbered from 1. When `term_length` is 1, the index equals the
    /// view.
    pub const fn term_index(self, term_length: TermLength) -> u64 {
        self.get().div_ceil(term_length.get())
    }

    /// Returns whether a nullification at this view covers `view`.
    ///
    /// A nullification covers the view it was created for and the rest of that
    /// view's term.
    pub const fn covers(self, view: Self, term_length: TermLength) -> bool {
        self.get() <= view.get() && self.same_term(view, term_length)
    }

    /// Returns the range of views whose nullifications cover this view.
    ///
    /// The inverse of [`covers`](Self::covers): a nullification covers the
    /// rest of its term, so this view is covered by a nullification at any
    /// view in `[term_start, self]`.
    pub const fn covering_range(self, term_length: TermLength) -> RangeInclusive<Self> {
        self.term_start(term_length)..=self
    }

    /// Returns whether `pending` is an acceptable view relative to this view
    /// when future views are bounded.
    ///
    /// Views at or below this view are always acceptable (callers enforce any
    /// lower bound separately). Beyond that, only the next view and the first
    /// view of the next term are acceptable: the only views this view can
    /// directly advance into (a nullification of the current view skips to
    /// the latter). When `term_length` is 1 the two views are the same.
    ///
    /// This bound exists to limit memory committed to unverified messages
    /// (like votes) from future views. It should not be applied to
    /// self-certifying artifacts (like certificates), which may arrive from
    /// arbitrarily far ahead and let a lagging participant fast-forward.
    pub const fn admits(self, pending: Self, term_length: TermLength) -> bool {
        if pending.get() <= self.get() || pending.get() == self.next().get() {
            return true;
        }
        // Equivalent to `pending == self.next_term_start(term_length)`, but
        // stated as a property of `pending` so it stays total: computing the
        // next term start can overflow near `u64::MAX`, where the correct
        // answer is simply that no representable view starts the next term.
        // Cannot underflow: pending is above self, so it is at least 1.
        pending.is_term_start(term_length) && self.same_term(Self(pending.get() - 1), term_length)
    }
}

impl Display for View {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TracedExt for Epoch {
    fn traced(self) -> i64 {
        self.0.traced()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TracedExt for Height {
    fn traced(self) -> i64 {
        self.0.traced()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl TracedExt for View {
    fn traced(self) -> i64 {
        self.0.traced()
    }
}

impl Read for View {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        let value: u64 = UInt::read(buf)?.into();
        Ok(Self(value))
    }
}

impl Write for View {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.0).write(buf);
    }
}

impl EncodeSize for View {
    fn encode_size(&self) -> usize {
        UInt(self.0).encode_size()
    }
}

impl From<View> for U64 {
    fn from(view: View) -> Self {
        Self::from(view.get())
    }
}

/// A generic type representing offsets or durations for consensus types.
///
/// [`Delta<T>`] is semantically distinct from point-in-time types like [`Epoch`] or [`View`] -
/// it represents a duration or distance rather than a specific moment.
///
/// For convenience, type aliases [`EpochDelta`] and [`ViewDelta`] are provided and should
/// be preferred in most code.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Delta<T>(u64, PhantomData<T>);

impl<T> Delta<T> {
    /// Returns a delta of zero.
    pub const fn zero() -> Self {
        Self(0, PhantomData)
    }

    /// Creates a new delta from a u64 value.
    pub const fn new(value: u64) -> Self {
        Self(value, PhantomData)
    }

    /// Returns the underlying u64 value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns true if this delta is zero.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl<T> Display for Delta<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type alias for epoch offsets and durations.
///
/// [`EpochDelta`] represents a distance between epochs or a duration measured in epochs.
/// It is used for epoch arithmetic operations and defining epoch bounds for data retention.
pub type EpochDelta = Delta<Epoch>;

/// Type alias for height offsets and durations.
///
/// [`HeightDelta`] represents a distance between heights or a duration measured in heights.
/// It is used for height arithmetic operations and defining height bounds for data retention.
pub type HeightDelta = Delta<Height>;

/// Type alias for view offsets and durations.
///
/// [`ViewDelta`] represents a distance between views or a duration measured in views.
/// It is commonly used for timeouts, activity tracking windows, and view arithmetic.
pub type ViewDelta = Delta<View>;

/// Number of consecutive views in which a leader remains stable (a "term").
///
/// When the term length is 1, every view is its own term and each view has an
/// independently elected leader. When greater than 1, views are grouped into
/// terms and the same leader serves for every view in the term.
///
/// Unlike [`ViewDelta`], which represents an offset added to or subtracted from
/// a view, a term length is a period that partitions the view space. It is
/// always non-zero.
///
/// # Consensus-Critical
///
/// The term length is consensus-critical configuration (like the namespace or
/// participant set): it is local, is not carried by any vote or certificate,
/// and nothing in the protocol detects a mismatch. All participants must
/// configure the same value. Term boundaries determine which views a
/// nullification covers, leader election, and when finalize votes are
/// withheld, so mismatched participants silently disagree on view transitions
/// and vote safety without producing any fault evidence. Only change the term
/// length when all participants change it together (e.g., at an epoch
/// boundary).
///
/// Longer terms also widen the window of unverified votes a participant may
/// buffer while finalization stalls: votes are accepted for any view between
/// the highest finalized view and the current view, and the current view
/// advances by up to a full term per nullification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TermLength(u32);

impl TermLength {
    /// The maximum term length. Lengths are stored as a `u32`, bounding term
    /// arithmetic (like [`View::next_term_start`]) away from `u64` overflow
    /// for any realistic view.
    pub const MAX: Self = Self(u32::MAX);

    /// A term length of one view (every view has an independently elected leader).
    pub const ONE: Self = Self(1);

    /// Creates a new term length.
    pub const fn new(length: NonZeroU32) -> Self {
        Self(length.get())
    }

    /// Returns the number of views per term.
    pub const fn get(self) -> u64 {
        self.0 as u64
    }
}

impl Default for TermLength {
    fn default() -> Self {
        Self::ONE
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for TermLength {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self(u.int_in_range(1..=u32::MAX)?))
    }
}

impl Display for TermLength {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A unique identifier combining epoch and view for a consensus round.
///
/// Round provides a total ordering across epoch boundaries, where rounds are
/// ordered first by epoch, then by view within that epoch.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Round {
    epoch: Epoch,
    view: View,
}

impl Round {
    /// Creates a new round from an epoch and view.
    pub const fn new(epoch: Epoch, view: View) -> Self {
        Self { epoch, view }
    }

    /// Returns round zero, i.e. epoch zero and view zero.
    pub const fn zero() -> Self {
        Self::new(Epoch::zero(), View::zero())
    }

    /// Returns the epoch of this round.
    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    /// Returns the view of this round.
    pub const fn view(self) -> View {
        self.view
    }
}

impl Epochable for Round {
    fn epoch(&self) -> Epoch {
        self.epoch
    }
}

impl Viewable for Round {
    fn view(&self) -> View {
        self.view
    }
}

impl From<(Epoch, View)> for Round {
    fn from((epoch, view): (Epoch, View)) -> Self {
        Self { epoch, view }
    }
}

impl From<Round> for (Epoch, View) {
    fn from(round: Round) -> Self {
        (round.epoch, round.view)
    }
}

/// Represents the relative position within an epoch.
///
/// Epochs are divided into two halves with a distinct midpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochPhase {
    /// First half of the epoch (0 <= relative < length/2).
    Early,
    /// Exactly at the midpoint (relative == length/2).
    Midpoint,
    /// Second half of the epoch (length/2 < relative < length).
    Late,
}

/// Information about an epoch relative to a specific height.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochInfo {
    epoch: Epoch,
    height: Height,
    first: Height,
    last: Height,
}

impl EpochInfo {
    /// Creates a new [`EpochInfo`].
    pub const fn new(epoch: Epoch, height: Height, first: Height, last: Height) -> Self {
        Self {
            epoch,
            height,
            first,
            last,
        }
    }

    /// Returns the epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the queried height.
    pub const fn height(&self) -> Height {
        self.height
    }

    /// Returns the first block height in this epoch.
    pub const fn first(&self) -> Height {
        self.first
    }

    /// Returns the last block height in this epoch.
    pub const fn last(&self) -> Height {
        self.last
    }

    /// Returns the length of this epoch.
    pub const fn length(&self) -> HeightDelta {
        HeightDelta::new(self.last.get() - self.first.get() + 1)
    }

    /// Returns the relative position of the queried height within this epoch.
    pub const fn relative(&self) -> Height {
        Height::new(self.height.get() - self.first.get())
    }

    /// Returns the phase of the queried height within this epoch.
    pub const fn phase(&self) -> EpochPhase {
        let relative = self.relative().get();
        let midpoint = self.length().get() / 2;

        if relative < midpoint {
            EpochPhase::Early
        } else if relative == midpoint {
            EpochPhase::Midpoint
        } else {
            EpochPhase::Late
        }
    }
}

/// Mechanism for determining epoch boundaries.
///
/// Genesis is not produced by any epoch, so every epoch must contain at least one
/// height above [`Height::zero`].
pub trait Epocher: Clone + Send + Sync + 'static {
    /// Returns the information about an epoch containing the given block height.
    ///
    /// Returns `None` if the height is not supported.
    fn containing(&self, height: Height) -> Option<EpochInfo>;

    /// Returns the first block height in the given epoch.
    ///
    /// Returns `None` if the epoch is not supported.
    fn first(&self, epoch: Epoch) -> Option<Height>;

    /// Returns the last block height in the given epoch.
    ///
    /// Returns `None` if the epoch is not supported.
    fn last(&self, epoch: Epoch) -> Option<Height>;
}

/// Implementation of [`Epocher`] for fixed epoch lengths.
///
/// Epoch `e` spans heights `e * length..(e + 1) * length`, so epoch zero includes
/// genesis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEpocher(u64);

impl FixedEpocher {
    /// Creates a new fixed epoch strategy.
    ///
    /// # Panics
    ///
    /// Panics if `length` is one, since epoch zero would contain only genesis.
    ///
    /// # Example
    /// ```rust
    /// # use commonware_consensus::types::FixedEpocher;
    /// # use commonware_utils::NZU64;
    /// let strategy = FixedEpocher::new(NZU64!(60_480));
    /// ```
    pub const fn new(length: NonZeroU64) -> Self {
        assert!(length.get() > 1, "epoch length must exceed one");
        Self(length.get())
    }

    /// Computes the first and last block height for an epoch, returning `None` if
    /// either would overflow.
    fn bounds(&self, epoch: Epoch) -> Option<(Height, Height)> {
        let first = epoch.get().checked_mul(self.0)?;
        let last = first.checked_add(self.0 - 1)?;
        Some((Height::new(first), Height::new(last)))
    }

    /// Returns the midpoint block height in the given epoch.
    ///
    /// Returns `None` if the epoch is not supported.
    pub fn midpoint(&self, epoch: Epoch) -> Option<Height> {
        let (first, _) = self.bounds(epoch)?;
        first.get().checked_add(self.0 / 2).map(Height::new)
    }
}

impl Epocher for FixedEpocher {
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        let epoch = Epoch::new(height.get() / self.0);
        let (first, last) = self.bounds(epoch)?;
        Some(EpochInfo::new(epoch, height, first, last))
    }

    fn first(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(first, _)| first)
    }

    fn last(&self, epoch: Epoch) -> Option<Height> {
        self.bounds(epoch).map(|(_, last)| last)
    }
}

impl Read for Round {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _cfg: &Self::Cfg) -> Result<Self, Error> {
        Ok(Self {
            epoch: Epoch::read(buf)?,
            view: View::read(buf)?,
        })
    }
}

impl Write for Round {
    fn write(&self, buf: &mut impl BufMut) {
        self.epoch.write(buf);
        self.view.write(buf);
    }
}

impl EncodeSize for Round {
    fn encode_size(&self) -> usize {
        self.epoch.encode_size() + self.view.encode_size()
    }
}

impl Display for Round {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "({}, {})", self.epoch, self.view)
    }
}

/// An iterator over a range of views.
///
/// Created by [`View::range`]. Iterates from start (inclusive) to end (exclusive).
pub struct ViewRange {
    inner: std::ops::Range<u64>,
}

impl Iterator for ViewRange {
    type Item = View;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(View::new)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for ViewRange {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(View::new)
    }
}

impl ExactSizeIterator for ViewRange {
    fn len(&self) -> usize {
        self.size_hint().0
    }
}

/// An iterator over a range of heights.
///
/// Created by [`Height::range`]. Iterates from start (inclusive) to end (exclusive).
pub struct HeightRange {
    inner: std::ops::Range<u64>,
}

impl Iterator for HeightRange {
    type Item = Height;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(Height::new)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl DoubleEndedIterator for HeightRange {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner.next_back().map(Height::new)
    }
}

impl ExactSizeIterator for HeightRange {
    fn len(&self) -> usize {
        self.size_hint().0
    }
}

/// Re-export [Participant] from commonware_utils for convenience.
pub use commonware_utils::Participant;

commonware_macros::stability_scope!(ALPHA {
    pub mod coding {
        //! Types and utilities for working with [`Commitment`]s.

        use commonware_codec::{Encode, FixedArray, FixedSize, Read, ReadExt, Write};
        use commonware_coding::{Config as CodingConfig, Scheme};
        use commonware_cryptography::{Digest, Digestible, Hasher};
        use commonware_math::algebra::Random;
        use commonware_utils::{Array, NZU16, Span};
        use core::{
            cmp::Ordering,
            hash::{Hash, Hasher as StdHasher},
            marker::PhantomData,
            num::NonZeroU16,
            ops::Deref,
        };
        use rand_core::CryptoRng;

        /// The fixed wire width reserved for each digest field in a [`Commitment`].
        ///
        /// A concrete width keeps the representation independent of `B`, `C`, and `H`.
        /// Stable Rust cannot use their associated sizes in the backing array length.
        pub const COMMITMENT_DIGEST_SIZE: usize = 32;

        /// The encoded size of a [`Commitment`].
        pub const COMMITMENT_SIZE: usize = 3 * COMMITMENT_DIGEST_SIZE + CodingConfig::SIZE;

        /// A [`Digest`] containing a coding commitment, encoded [`CodingConfig`], and context hash.
        ///
        /// ```text
        /// 0                   32                  64                  96            100
        /// +-------------------+-------------------+-------------------+---------------+
        /// | block digest      | coding root       | context digest    | coding config |
        /// +-------------------+-------------------+-------------------+---------------+
        /// ```
        ///
        /// Each digest occupies [`COMMITMENT_DIGEST_SIZE`] bytes. Any unused bytes at the end of
        /// a digest field are zero.
        ///
        /// Each field is parsed as its declared type on deserialization, so the accessors on a
        /// successfully decoded [`Commitment`] never fail.
        #[derive(FixedArray)]
        #[fixed_array(bytes([u8; COMMITMENT_SIZE]))]
        pub struct Commitment<B, C, H>([u8; COMMITMENT_SIZE], PhantomData<(B, C, H)>);

        impl<B, C, H> Clone for Commitment<B, C, H> {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<B, C, H> Copy for Commitment<B, C, H> {}

        impl<B, C, H> PartialEq for Commitment<B, C, H> {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }

        impl<B, C, H> Eq for Commitment<B, C, H> {}

        impl<B, C, H> PartialOrd for Commitment<B, C, H> {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl<B, C, H> Ord for Commitment<B, C, H> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl<B, C, H> Hash for Commitment<B, C, H> {
            fn hash<S: StdHasher>(&self, state: &mut S) {
                self.0.hash(state);
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Commitment<B, C, H> {
            const BLOCK_OFFSET: usize = 0;
            const ROOT_OFFSET: usize = Self::BLOCK_OFFSET + COMMITMENT_DIGEST_SIZE;
            const CONTEXT_OFFSET: usize = Self::ROOT_OFFSET + COMMITMENT_DIGEST_SIZE;
            const CONFIG_OFFSET: usize = Self::CONTEXT_OFFSET + COMMITMENT_DIGEST_SIZE;

            /// Returns the block [`Digest`] from this [`Commitment`].
            pub fn block(&self) -> B::Digest {
                self.field(Self::BLOCK_OFFSET)
            }

            /// Returns the coding root [`Digest`] from this [`Commitment`].
            pub fn root(&self) -> C::Commitment {
                self.field(Self::ROOT_OFFSET)
            }

            /// Returns the context [`Digest`] from this [`Commitment`].
            pub fn context(&self) -> H::Digest {
                self.field(Self::CONTEXT_OFFSET)
            }

            /// Extracts the [`CodingConfig`] from this [`Commitment`].
            pub fn config(&self) -> CodingConfig {
                self.field(Self::CONFIG_OFFSET)
            }

            fn field<T: ReadExt + FixedSize>(&self, offset: usize) -> T {
                T::read(&mut &self.0[offset..offset + T::SIZE])
                    .expect("fields are validated on decode and typed construction")
            }

            /// Validates a typed digest field and its canonical zero padding.
            fn validate_field<T: ReadExt + FixedSize>(
                bytes: &[u8],
                offset: usize,
                reason: &'static str,
            ) -> Result<(), commonware_codec::Error> {
                let field_end = offset + T::SIZE;
                let padding_end = offset + COMMITMENT_DIGEST_SIZE;
                T::read(&mut &bytes[offset..field_end])
                    .map_err(|_| commonware_codec::Error::Invalid("Commitment", reason))?;
                if bytes[field_end..padding_end].iter().any(|byte| *byte != 0) {
                    return Err(commonware_codec::Error::Invalid(
                        "Commitment",
                        "non-zero digest padding",
                    ));
                }
                Ok(())
            }

            /// Ensures each typed digest fits its fixed-width wire field.
            const fn assert_layout() {
                assert!(
                    B::Digest::SIZE <= COMMITMENT_DIGEST_SIZE,
                    "block digest exceeds commitment field size"
                );
                assert!(
                    C::Commitment::SIZE <= COMMITMENT_DIGEST_SIZE,
                    "coding root exceeds commitment field size"
                );
                assert!(
                    H::Digest::SIZE <= COMMITMENT_DIGEST_SIZE,
                    "context digest exceeds commitment field size"
                );
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Random for Commitment<B, C, H> {
            fn random(mut rng: impl CryptoRng) -> Self {
                let one = NZU16!(1);
                let shards = rng.next_u32();
                let config = CodingConfig {
                    minimum_shards: NonZeroU16::new(shards as u16).unwrap_or(one),
                    extra_shards: NonZeroU16::new((shards >> 16) as u16).unwrap_or(one),
                };
                Self::from((
                    B::Digest::random(&mut rng),
                    C::Commitment::random(&mut rng),
                    H::Digest::random(&mut rng),
                    config,
                ))
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Digest for Commitment<B, C, H> {
            /// The all-zero sentinel. Its config bytes are not a valid
            /// [`CodingConfig`], so accessors must not be called on it.
            const EMPTY: Self = {
                Self::assert_layout();
                Self([0u8; COMMITMENT_SIZE], PhantomData)
            };
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Write for Commitment<B, C, H> {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                buf.put_slice(self.as_ref());
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> FixedSize for Commitment<B, C, H> {
            const SIZE: usize = COMMITMENT_SIZE;
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Read for Commitment<B, C, H> {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl bytes::Buf,
                _cfg: &Self::Cfg,
            ) -> Result<Self, commonware_codec::Error> {
                const { Self::assert_layout() };
                let arr = <[u8; COMMITMENT_SIZE]>::read(buf)?;

                Self::validate_field::<B::Digest>(
                    &arr,
                    Self::BLOCK_OFFSET,
                    "invalid block digest",
                )?;
                Self::validate_field::<C::Commitment>(
                    &arr,
                    Self::ROOT_OFFSET,
                    "invalid coding root",
                )?;
                Self::validate_field::<H::Digest>(
                    &arr,
                    Self::CONTEXT_OFFSET,
                    "invalid context digest",
                )?;
                let mut cursor = &arr[Self::CONFIG_OFFSET..];
                CodingConfig::read(&mut cursor).map_err(|_| {
                    commonware_codec::Error::Invalid("Commitment", "invalid embedded CodingConfig")
                })?;

                Ok(Self(arr, PhantomData))
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> AsRef<[u8]> for Commitment<B, C, H> {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Deref for Commitment<B, C, H> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                self.as_ref()
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> core::fmt::Display for Commitment<B, C, H> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> core::fmt::Debug for Commitment<B, C, H> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Default for Commitment<B, C, H> {
            fn default() -> Self {
                Self::EMPTY
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher>
            From<(B::Digest, C::Commitment, H::Digest, CodingConfig)> for Commitment<B, C, H>
        {
            fn from(
                (block, root, context, config): (B::Digest, C::Commitment, H::Digest, CodingConfig),
            ) -> Self {
                const { Self::assert_layout() };

                let mut buf = [0u8; COMMITMENT_SIZE];
                buf[Self::BLOCK_OFFSET..Self::BLOCK_OFFSET + B::Digest::SIZE]
                    .copy_from_slice(&block);
                buf[Self::ROOT_OFFSET..Self::ROOT_OFFSET + C::Commitment::SIZE]
                    .copy_from_slice(&root);
                buf[Self::CONTEXT_OFFSET..Self::CONTEXT_OFFSET + H::Digest::SIZE]
                    .copy_from_slice(&context);
                buf[Self::CONFIG_OFFSET..].copy_from_slice(&config.encode());
                Self(buf, PhantomData)
            }
        }

        impl<B: Digestible, C: Scheme, H: Hasher> Span for Commitment<B, C, H> {}

        impl<B: Digestible, C: Scheme, H: Hasher> Array for Commitment<B, C, H> {}

        #[cfg(feature = "arbitrary")]
        impl<B, C, H> arbitrary::Arbitrary<'_> for Commitment<B, C, H>
        where
            B: Digestible,
            B::Digest: for<'a> arbitrary::Arbitrary<'a>,
            C: Scheme,
            C::Commitment: for<'a> arbitrary::Arbitrary<'a>,
            H: Hasher,
            H::Digest: for<'a> arbitrary::Arbitrary<'a>,
        {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                Ok(Self::from((
                    B::Digest::arbitrary(u)?,
                    C::Commitment::arbitrary(u)?,
                    H::Digest::arbitrary(u)?,
                    CodingConfig::arbitrary(u)?,
                )))
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::coding::{COMMITMENT_SIZE, Commitment};
    use commonware_codec::{DecodeExt, Encode, EncodeSize, FixedSize};
    use commonware_coding::{Config as CodingConfig, ReedSolomon};
    use commonware_cryptography::{Digest as DigestTrait, Digestible, Hasher};
    use commonware_math::algebra::Random;
    use commonware_utils::{Array, NZU16, NZU64, Span, test_rng};
    use std::{marker::PhantomData, ops::Deref};

    #[derive(Clone)]
    struct TestBlock<D>(PhantomData<D>);

    impl<D: DigestTrait> Digestible for TestBlock<D> {
        type Digest = D;

        fn digest(&self) -> Self::Digest {
            unreachable!("test block is only used to bind commitment digest types")
        }
    }

    #[derive(Clone)]
    struct TestHasher<D>(PhantomData<D>);

    impl<D> Default for TestHasher<D> {
        fn default() -> Self {
            Self(PhantomData)
        }
    }

    impl<D: DigestTrait> Hasher for TestHasher<D> {
        type Digest = D;

        fn hash(_parts: &[&[u8]]) -> Self::Digest {
            D::EMPTY
        }

        fn hash_pair(_left: &[&[u8]], _right: &[&[u8]]) -> (Self::Digest, Self::Digest) {
            (D::EMPTY, D::EMPTY)
        }

        fn update(&mut self, _message: &[u8]) -> &mut Self {
            self
        }

        fn finalize(self) -> (Self, Self::Digest) {
            (self, D::EMPTY)
        }
    }

    #[test]
    fn test_epoch_constructors() {
        assert_eq!(Epoch::zero().get(), 0);
        assert_eq!(Epoch::new(42).get(), 42);
        assert_eq!(Epoch::default().get(), 0);
    }

    #[test]
    fn test_epoch_is_zero() {
        assert!(Epoch::zero().is_zero());
        assert!(Epoch::new(0).is_zero());
        assert!(!Epoch::new(1).is_zero());
        assert!(!Epoch::new(100).is_zero());
    }

    #[test]
    fn test_epoch_next() {
        assert_eq!(Epoch::zero().next().get(), 1);
        assert_eq!(Epoch::new(5).next().get(), 6);
        assert_eq!(Epoch::new(999).next().get(), 1000);
    }

    #[test]
    #[should_panic(expected = "epoch overflow")]
    fn test_epoch_next_overflow() {
        Epoch::new(u64::MAX).next();
    }

    #[test]
    fn test_epoch_previous() {
        assert_eq!(Epoch::zero().previous(), None);
        assert_eq!(Epoch::new(1).previous(), Some(Epoch::zero()));
        assert_eq!(Epoch::new(5).previous(), Some(Epoch::new(4)));
        assert_eq!(Epoch::new(1000).previous(), Some(Epoch::new(999)));
    }

    #[test]
    fn test_epoch_saturating_add() {
        assert_eq!(Epoch::zero().saturating_add(EpochDelta::new(5)).get(), 5);
        assert_eq!(Epoch::new(10).saturating_add(EpochDelta::new(20)).get(), 30);
        assert_eq!(
            Epoch::new(u64::MAX)
                .saturating_add(EpochDelta::new(1))
                .get(),
            u64::MAX
        );
        assert_eq!(
            Epoch::new(u64::MAX - 5)
                .saturating_add(EpochDelta::new(10))
                .get(),
            u64::MAX
        );
    }

    #[test]
    fn test_epoch_checked_sub() {
        assert_eq!(
            Epoch::new(10).checked_sub(EpochDelta::new(5)),
            Some(Epoch::new(5))
        );
        assert_eq!(
            Epoch::new(5).checked_sub(EpochDelta::new(5)),
            Some(Epoch::zero())
        );
        assert_eq!(Epoch::new(5).checked_sub(EpochDelta::new(10)), None);
        assert_eq!(Epoch::zero().checked_sub(EpochDelta::new(1)), None);
    }

    #[test]
    fn test_epoch_saturating_sub() {
        assert_eq!(Epoch::new(10).saturating_sub(EpochDelta::new(5)).get(), 5);
        assert_eq!(Epoch::new(5).saturating_sub(EpochDelta::new(5)).get(), 0);
        assert_eq!(Epoch::new(5).saturating_sub(EpochDelta::new(10)).get(), 0);
        assert_eq!(Epoch::zero().saturating_sub(EpochDelta::new(100)).get(), 0);
    }

    #[test]
    fn test_epoch_display() {
        assert_eq!(format!("{}", Epoch::zero()), "0");
        assert_eq!(format!("{}", Epoch::new(42)), "42");
        assert_eq!(format!("{}", Epoch::new(1000)), "1000");
    }

    #[test]
    fn test_epoch_ordering() {
        assert!(Epoch::zero() < Epoch::new(1));
        assert!(Epoch::new(5) < Epoch::new(10));
        assert!(Epoch::new(10) > Epoch::new(5));
        assert_eq!(Epoch::new(42), Epoch::new(42));
    }

    #[test]
    fn test_epoch_encode_decode() {
        let cases = vec![0u64, 1, 127, 128, 255, 256, u64::MAX];
        for value in cases {
            let epoch = Epoch::new(value);
            let encoded = epoch.encode();
            assert_eq!(encoded.len(), epoch.encode_size());
            let decoded = Epoch::decode(encoded).unwrap();
            assert_eq!(epoch, decoded);
        }
    }

    #[test]
    fn test_height_constructors() {
        assert_eq!(Height::zero().get(), 0);
        assert_eq!(Height::new(42).get(), 42);
        assert_eq!(Height::new(100).get(), 100);
        assert_eq!(Height::default().get(), 0);
    }

    #[test]
    fn test_height_is_zero() {
        assert!(Height::zero().is_zero());
        assert!(Height::new(0).is_zero());
        assert!(!Height::new(1).is_zero());
        assert!(!Height::new(100).is_zero());
    }

    #[test]
    fn test_height_next() {
        assert_eq!(Height::zero().next().get(), 1);
        assert_eq!(Height::new(5).next().get(), 6);
        assert_eq!(Height::new(999).next().get(), 1000);
    }

    #[test]
    #[should_panic(expected = "height overflow")]
    fn test_height_next_overflow() {
        Height::new(u64::MAX).next();
    }

    #[test]
    fn test_height_previous() {
        assert_eq!(Height::zero().previous(), None);
        assert_eq!(Height::new(1).previous(), Some(Height::zero()));
        assert_eq!(Height::new(5).previous(), Some(Height::new(4)));
        assert_eq!(Height::new(1000).previous(), Some(Height::new(999)));
    }

    #[test]
    fn test_height_saturating_add() {
        let delta5 = HeightDelta::new(5);
        let delta100 = HeightDelta::new(100);
        assert_eq!(Height::zero().saturating_add(delta5).get(), 5);
        assert_eq!(Height::new(10).saturating_add(delta100).get(), 110);
        assert_eq!(
            Height::new(u64::MAX)
                .saturating_add(HeightDelta::new(1))
                .get(),
            u64::MAX
        );
    }

    #[test]
    fn test_height_saturating_sub() {
        let delta5 = HeightDelta::new(5);
        let delta100 = HeightDelta::new(100);
        assert_eq!(Height::new(10).saturating_sub(delta5).get(), 5);
        assert_eq!(Height::new(5).saturating_sub(delta5).get(), 0);
        assert_eq!(Height::new(5).saturating_sub(delta100).get(), 0);
        assert_eq!(Height::zero().saturating_sub(delta100).get(), 0);
    }

    #[test]
    fn test_height_display() {
        assert_eq!(format!("{}", Height::zero()), "0");
        assert_eq!(format!("{}", Height::new(42)), "42");
        assert_eq!(format!("{}", Height::new(1000)), "1000");
    }

    #[test]
    fn test_height_ordering() {
        assert!(Height::zero() < Height::new(1));
        assert!(Height::new(5) < Height::new(10));
        assert!(Height::new(10) > Height::new(5));
        assert_eq!(Height::new(42), Height::new(42));
    }

    #[test]
    fn test_height_encode_decode() {
        let cases = vec![0u64, 1, 127, 128, 255, 256, u64::MAX];
        for value in cases {
            let height = Height::new(value);
            let encoded = height.encode();
            assert_eq!(encoded.len(), height.encode_size());
            let decoded = Height::decode(encoded).unwrap();
            assert_eq!(height, decoded);
        }
    }

    #[test]
    fn test_height_delta_from() {
        assert_eq!(
            Height::new(10).delta_from(Height::new(3)),
            Some(HeightDelta::new(7))
        );
        assert_eq!(
            Height::new(5).delta_from(Height::new(5)),
            Some(HeightDelta::zero())
        );
        assert_eq!(Height::new(3).delta_from(Height::new(10)), None);
        assert_eq!(Height::zero().delta_from(Height::new(1)), None);
    }

    #[test]
    fn height_range_iterates() {
        let collected: Vec<_> = Height::range(Height::new(3), Height::new(6))
            .map(Height::get)
            .collect();
        assert_eq!(collected, vec![3, 4, 5]);
    }

    #[test]
    fn height_range_empty() {
        let collected: Vec<_> = Height::range(Height::new(5), Height::new(5)).collect();
        assert_eq!(collected, vec![]);

        let collected: Vec<_> = Height::range(Height::new(10), Height::new(5)).collect();
        assert_eq!(collected, vec![]);
    }

    #[test]
    fn height_range_single() {
        let collected: Vec<_> = Height::range(Height::new(5), Height::new(6))
            .map(Height::get)
            .collect();
        assert_eq!(collected, vec![5]);
    }

    #[test]
    fn height_range_size_hint() {
        let range = Height::range(Height::new(3), Height::new(10));
        assert_eq!(range.size_hint(), (7, Some(7)));
        assert_eq!(range.len(), 7);

        let empty = Height::range(Height::new(5), Height::new(5));
        assert_eq!(empty.size_hint(), (0, Some(0)));
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn height_range_rev() {
        let collected: Vec<_> = Height::range(Height::new(3), Height::new(7))
            .rev()
            .map(Height::get)
            .collect();
        assert_eq!(collected, vec![6, 5, 4, 3]);
    }

    #[test]
    fn height_range_double_ended() {
        let mut range = Height::range(Height::new(5), Height::new(10));
        assert_eq!(range.next(), Some(Height::new(5)));
        assert_eq!(range.next_back(), Some(Height::new(9)));
        assert_eq!(range.next(), Some(Height::new(6)));
        assert_eq!(range.next_back(), Some(Height::new(8)));
        assert_eq!(range.len(), 1);
        assert_eq!(range.next(), Some(Height::new(7)));
        assert_eq!(range.next(), None);
        assert_eq!(range.next_back(), None);
    }

    #[test]
    fn test_view_constructors() {
        assert_eq!(View::zero().get(), 0);
        assert_eq!(View::new(42).get(), 42);
        assert_eq!(View::new(100).get(), 100);
        assert_eq!(View::default().get(), 0);
    }

    #[test]
    fn test_view_is_zero() {
        assert!(View::zero().is_zero());
        assert!(View::new(0).is_zero());
        assert!(!View::new(1).is_zero());
        assert!(!View::new(100).is_zero());
    }

    #[test]
    fn test_view_next() {
        assert_eq!(View::zero().next().get(), 1);
        assert_eq!(View::new(5).next().get(), 6);
        assert_eq!(View::new(999).next().get(), 1000);
    }

    #[test]
    #[should_panic(expected = "view overflow")]
    fn test_view_next_overflow() {
        View::new(u64::MAX).next();
    }

    #[test]
    fn test_view_previous() {
        assert_eq!(View::zero().previous(), None);
        assert_eq!(View::new(1).previous(), Some(View::zero()));
        assert_eq!(View::new(5).previous(), Some(View::new(4)));
        assert_eq!(View::new(1000).previous(), Some(View::new(999)));
    }

    #[test]
    fn test_view_saturating_add() {
        let delta5 = ViewDelta::new(5);
        let delta100 = ViewDelta::new(100);
        assert_eq!(View::zero().saturating_add(delta5).get(), 5);
        assert_eq!(View::new(10).saturating_add(delta100).get(), 110);
        assert_eq!(
            View::new(u64::MAX).saturating_add(ViewDelta::new(1)).get(),
            u64::MAX
        );
    }

    #[test]
    fn test_view_saturating_sub() {
        let delta5 = ViewDelta::new(5);
        let delta100 = ViewDelta::new(100);
        assert_eq!(View::new(10).saturating_sub(delta5).get(), 5);
        assert_eq!(View::new(5).saturating_sub(delta5).get(), 0);
        assert_eq!(View::new(5).saturating_sub(delta100).get(), 0);
        assert_eq!(View::zero().saturating_sub(delta100).get(), 0);
    }

    #[test]
    fn test_view_display() {
        assert_eq!(format!("{}", View::zero()), "0");
        assert_eq!(format!("{}", View::new(42)), "42");
        assert_eq!(format!("{}", View::new(1000)), "1000");
    }

    #[test]
    fn test_view_ordering() {
        assert!(View::zero() < View::new(1));
        assert!(View::new(5) < View::new(10));
        assert!(View::new(10) > View::new(5));
        assert_eq!(View::new(42), View::new(42));
    }

    #[test]
    fn test_view_encode_decode() {
        let cases = vec![0u64, 1, 127, 128, 255, 256, u64::MAX];
        for value in cases {
            let view = View::new(value);
            let encoded = view.encode();
            assert_eq!(encoded.len(), view.encode_size());
            let decoded = View::decode(encoded).unwrap();
            assert_eq!(view, decoded);
        }
    }

    #[test]
    fn test_view_term_start() {
        let cases = [
            (0, 5, 0),
            (1, 1, 1),
            (5, 1, 5),
            (6, 1, 6),
            (7, 1, 7),
            (1, 5, 1),
            (5, 5, 1),
            (6, 5, 6),
            (10, 5, 6),
            (11, 5, 11),
            (12, 3, 10),
        ];
        for (view, term_length, expected) in cases {
            assert_eq!(
                View::new(view).term_start(TermLength::new(commonware_utils::NZU32!(term_length))),
                View::new(expected),
                "view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_term_end() {
        let cases = [
            (0, 5, 0),
            (1, 1, 1),
            (5, 1, 5),
            (1, 5, 5),
            (5, 5, 5),
            (6, 5, 10),
            (10, 5, 10),
            (11, 5, 15),
            (12, 3, 12),
        ];
        for (view, term_length, expected) in cases {
            assert_eq!(
                View::new(view).term_end(TermLength::new(commonware_utils::NZU32!(term_length))),
                View::new(expected),
                "view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_is_term_start() {
        let cases = [
            (0, 1, true),
            (1, 1, true),
            (5, 1, true),
            (1, 5, true),
            (5, 5, false),
            (6, 5, true),
            (10, 5, false),
            (11, 5, true),
        ];
        for (view, term_length, expected) in cases {
            assert_eq!(
                View::new(view)
                    .is_term_start(TermLength::new(commonware_utils::NZU32!(term_length))),
                expected,
                "view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_same_term() {
        let cases = [
            (0, 0, 1, true),
            (0, 0, 5, true),
            (0, 1, 5, false),
            (0, 5, 5, false),
            (1, 1, 1, true),
            (1, 2, 5, true),
            (1, 5, 5, true),
            (5, 6, 5, false),
            (6, 10, 5, true),
            (10, 11, 5, false),
            (11, 15, 5, true),
        ];
        for (a, b, term_length, expected) in cases {
            assert_eq!(
                View::new(a).same_term(
                    View::new(b),
                    TermLength::new(commonware_utils::NZU32!(term_length))
                ),
                expected,
                "a={a}, b={b}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_next_term_start() {
        let cases = [
            (0, 1, 1),
            (5, 1, 6),
            (1, 5, 6),
            (5, 5, 6),
            (6, 5, 11),
            (10, 5, 11),
            (11, 5, 16),
            (12, 3, 13),
        ];
        for (view, term_length, expected) in cases {
            assert_eq!(
                View::new(view)
                    .next_term_start(TermLength::new(commonware_utils::NZU32!(term_length))),
                View::new(expected),
                "view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_term_index() {
        let cases = [
            (0, 1, 0),
            (1, 1, 1),
            (5, 1, 5),
            (0, 5, 0),
            (1, 5, 1),
            (5, 5, 1),
            (6, 5, 2),
            (10, 5, 2),
            (11, 5, 3),
        ];
        for (view, term_length, expected) in cases {
            assert_eq!(
                View::new(view).term_index(TermLength::new(commonware_utils::NZU32!(term_length))),
                expected,
                "view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_covers() {
        let cases = [
            (0, 0, 5, true),
            (0, 3, 5, false),
            (1, 0, 5, false),
            (1, 1, 1, true),
            (1, 2, 1, false),
            (2, 1, 1, false),
            (6, 6, 5, true),
            (6, 8, 5, true),
            (6, 10, 5, true),
            (6, 11, 5, false),
            (8, 6, 5, false),
            (6, 5, 5, false),
        ];
        for (nullified, view, term_length, expected) in cases {
            assert_eq!(
                View::new(nullified).covers(
                    View::new(view),
                    TermLength::new(commonware_utils::NZU32!(term_length))
                ),
                expected,
                "nullified={nullified}, view={view}, term_length={term_length}"
            );
        }
    }

    #[test]
    fn test_view_admits() {
        let cases = [
            (0, 0, 5, true),
            (0, 1, 5, true),
            (0, 2, 5, false),
            (0, 5, 5, false),
            (5, 4, 1, true),
            (5, 5, 1, true),
            (5, 6, 1, true),
            (5, 7, 1, false),
            (6, 7, 5, true),
            (6, 11, 5, true),
            (6, 8, 5, false),
            (6, 12, 5, false),
            (10, 11, 5, true),
            (10, 12, 5, false),
        ];
        for (current, pending, term_length, expected) in cases {
            assert_eq!(
                View::new(current).admits(
                    View::new(pending),
                    TermLength::new(commonware_utils::NZU32!(term_length))
                ),
                expected,
                "current={current}, pending={pending}, term_length={term_length}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "view term_end overflow")]
    fn test_view_term_end_overflow_panics() {
        let _ = View::new(u64::MAX).term_end(TermLength::new(commonware_utils::NZU32!(2)));
    }

    #[test]
    #[should_panic(expected = "view overflow")]
    fn test_view_next_term_start_overflow_panics() {
        let _ = View::new(u64::MAX).next_term_start(TermLength::ONE);
    }

    #[test]
    fn test_view_admits_near_max_does_not_panic() {
        let term_length = TermLength::new(commonware_utils::NZU32!(5));
        // The next term start overflows, so only lower views and the
        // successor are admitted.
        let current = View::new(u64::MAX - 2);
        assert!(current.admits(View::new(0), term_length));
        assert!(current.admits(View::new(u64::MAX - 1), term_length));
        assert!(!current.admits(View::new(u64::MAX), term_length));
    }

    #[test]
    fn test_view_delta_constructors() {
        assert_eq!(ViewDelta::zero().get(), 0);
        assert_eq!(ViewDelta::new(42).get(), 42);
        assert_eq!(ViewDelta::new(100).get(), 100);
        assert_eq!(ViewDelta::default().get(), 0);
    }

    #[test]
    fn test_view_delta_is_zero() {
        assert!(ViewDelta::zero().is_zero());
        assert!(ViewDelta::new(0).is_zero());
        assert!(!ViewDelta::new(1).is_zero());
        assert!(!ViewDelta::new(100).is_zero());
    }

    #[test]
    fn test_view_delta_display() {
        assert_eq!(format!("{}", ViewDelta::zero()), "0");
        assert_eq!(format!("{}", ViewDelta::new(42)), "42");
        assert_eq!(format!("{}", ViewDelta::new(1000)), "1000");
    }

    #[test]
    fn test_view_delta_ordering() {
        assert!(ViewDelta::zero() < ViewDelta::new(1));
        assert!(ViewDelta::new(5) < ViewDelta::new(10));
        assert!(ViewDelta::new(10) > ViewDelta::new(5));
        assert_eq!(ViewDelta::new(42), ViewDelta::new(42));
    }

    #[test]
    fn test_round_cmp() {
        assert!(Round::new(Epoch::new(1), View::new(2)) < Round::new(Epoch::new(1), View::new(3)));
        assert!(Round::new(Epoch::new(1), View::new(2)) < Round::new(Epoch::new(2), View::new(1)));
    }

    #[test]
    fn test_round_encode_decode_roundtrip() {
        let r: Round = (Epoch::new(42), View::new(1_000_000)).into();
        let encoded = r.encode();
        assert_eq!(encoded.len(), r.encode_size());
        let decoded = Round::decode(encoded).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn test_round_conversions() {
        let r: Round = (Epoch::new(5), View::new(6)).into();
        assert_eq!(r.epoch(), Epoch::new(5));
        assert_eq!(r.view(), View::new(6));
        let tuple: (Epoch, View) = r.into();
        assert_eq!(tuple, (Epoch::new(5), View::new(6)));
    }

    #[test]
    fn test_round_new() {
        let r = Round::new(Epoch::new(10), View::new(20));
        assert_eq!(r.epoch(), Epoch::new(10));
        assert_eq!(r.view(), View::new(20));

        let r2 = Round::new(Epoch::new(5), View::new(15));
        assert_eq!(r2.epoch(), Epoch::new(5));
        assert_eq!(r2.view(), View::new(15));
    }

    #[test]
    fn test_round_display() {
        let r = Round::new(Epoch::new(5), View::new(100));
        assert_eq!(format!("{r}"), "(5, 100)");
    }

    #[test]
    fn view_range_iterates() {
        let collected: Vec<_> = View::range(View::new(3), View::new(6))
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![3, 4, 5]);
    }

    #[test]
    fn view_range_empty() {
        let collected: Vec<_> = View::range(View::new(5), View::new(5)).collect();
        assert_eq!(collected, vec![]);

        let collected: Vec<_> = View::range(View::new(10), View::new(5)).collect();
        assert_eq!(collected, vec![]);
    }

    #[test]
    fn view_range_single() {
        let collected: Vec<_> = View::range(View::new(5), View::new(6))
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![5]);
    }

    #[test]
    fn view_range_size_hint() {
        let range = View::range(View::new(3), View::new(10));
        assert_eq!(range.size_hint(), (7, Some(7)));
        assert_eq!(range.len(), 7);

        let empty = View::range(View::new(5), View::new(5));
        assert_eq!(empty.size_hint(), (0, Some(0)));
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn view_range_collect() {
        let views: Vec<View> = View::range(View::new(0), View::new(3)).collect();
        assert_eq!(views, vec![View::zero(), View::new(1), View::new(2)]);
    }

    #[test]
    fn view_range_iterator_next() {
        let mut range = View::range(View::new(5), View::new(8));
        assert_eq!(range.next(), Some(View::new(5)));
        assert_eq!(range.next(), Some(View::new(6)));
        assert_eq!(range.next(), Some(View::new(7)));
        assert_eq!(range.next(), None);
        assert_eq!(range.next(), None); // Multiple None
    }

    #[test]
    fn view_range_exact_size_iterator() {
        let range = View::range(View::new(10), View::new(15));
        assert_eq!(range.len(), 5);
        assert_eq!(range.size_hint(), (5, Some(5)));

        let mut range = View::range(View::new(10), View::new(15));
        assert_eq!(range.len(), 5);
        range.next();
        assert_eq!(range.len(), 4);
        range.next();
        assert_eq!(range.len(), 3);
    }

    #[test]
    fn view_range_rev() {
        // Use .rev() to iterate in descending order
        let collected: Vec<_> = View::range(View::new(3), View::new(7))
            .rev()
            .map(View::get)
            .collect();
        assert_eq!(collected, vec![6, 5, 4, 3]);
    }

    #[test]
    fn view_range_double_ended() {
        // Mixed next() and next_back() calls
        let mut range = View::range(View::new(5), View::new(10));
        assert_eq!(range.next(), Some(View::new(5)));
        assert_eq!(range.next_back(), Some(View::new(9)));
        assert_eq!(range.next(), Some(View::new(6)));
        assert_eq!(range.next_back(), Some(View::new(8)));
        assert_eq!(range.len(), 1);
        assert_eq!(range.next(), Some(View::new(7)));
        assert_eq!(range.next(), None);
        assert_eq!(range.next_back(), None);
    }

    #[test]
    fn test_fixed_epoch_strategy() {
        let epocher = FixedEpocher::new(NZU64!(100));

        // Test containing returns correct EpochInfo
        let bounds = epocher.containing(Height::zero()).unwrap();
        assert_eq!(bounds.epoch(), Epoch::new(0));
        assert_eq!(bounds.first(), Height::zero());
        assert_eq!(bounds.last(), Height::new(99));
        assert_eq!(bounds.length(), HeightDelta::new(100));

        let bounds = epocher.containing(Height::new(99)).unwrap();
        assert_eq!(bounds.epoch(), Epoch::new(0));

        let bounds = epocher.containing(Height::new(100)).unwrap();
        assert_eq!(bounds.epoch(), Epoch::new(1));
        assert_eq!(bounds.first(), Height::new(100));
        assert_eq!(bounds.last(), Height::new(199));

        // Test first/last return correct boundaries
        assert_eq!(epocher.first(Epoch::new(0)), Some(Height::zero()));
        assert_eq!(epocher.last(Epoch::new(0)), Some(Height::new(99)));
        assert_eq!(epocher.first(Epoch::new(1)), Some(Height::new(100)));
        assert_eq!(epocher.last(Epoch::new(1)), Some(Height::new(199)));
        assert_eq!(epocher.first(Epoch::new(5)), Some(Height::new(500)));
        assert_eq!(epocher.last(Epoch::new(5)), Some(Height::new(599)));
    }

    #[test]
    fn test_epoch_bounds_relative() {
        let epocher = FixedEpocher::new(NZU64!(100));

        // Epoch 0: heights 0-99
        assert_eq!(
            epocher.containing(Height::zero()).unwrap().relative(),
            Height::zero()
        );
        assert_eq!(
            epocher.containing(Height::new(50)).unwrap().relative(),
            Height::new(50)
        );
        assert_eq!(
            epocher.containing(Height::new(99)).unwrap().relative(),
            Height::new(99)
        );

        // Epoch 1: heights 100-199
        assert_eq!(
            epocher.containing(Height::new(100)).unwrap().relative(),
            Height::zero()
        );
        assert_eq!(
            epocher.containing(Height::new(150)).unwrap().relative(),
            Height::new(50)
        );
        assert_eq!(
            epocher.containing(Height::new(199)).unwrap().relative(),
            Height::new(99)
        );

        // Epoch 5: heights 500-599
        assert_eq!(
            epocher.containing(Height::new(500)).unwrap().relative(),
            Height::zero()
        );
        assert_eq!(
            epocher.containing(Height::new(567)).unwrap().relative(),
            Height::new(67)
        );
        assert_eq!(
            epocher.containing(Height::new(599)).unwrap().relative(),
            Height::new(99)
        );
    }

    #[test]
    fn test_epoch_bounds_phase() {
        // Test with epoch length of 30 (midpoint = 15)
        let epocher = FixedEpocher::new(NZU64!(30));

        // Early phase: relative 0-14
        assert_eq!(
            epocher.containing(Height::zero()).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(14)).unwrap().phase(),
            EpochPhase::Early
        );

        // Midpoint: relative 15
        assert_eq!(
            epocher.containing(Height::new(15)).unwrap().phase(),
            EpochPhase::Midpoint
        );

        // Late phase: relative 16-29
        assert_eq!(
            epocher.containing(Height::new(16)).unwrap().phase(),
            EpochPhase::Late
        );
        assert_eq!(
            epocher.containing(Height::new(29)).unwrap().phase(),
            EpochPhase::Late
        );

        // Second epoch starts at height 30
        assert_eq!(
            epocher.containing(Height::new(30)).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(44)).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(45)).unwrap().phase(),
            EpochPhase::Midpoint
        );
        assert_eq!(
            epocher.containing(Height::new(46)).unwrap().phase(),
            EpochPhase::Late
        );

        // Test with epoch length 10 (midpoint = 5)
        let epocher = FixedEpocher::new(NZU64!(10));
        assert_eq!(
            epocher.containing(Height::zero()).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(4)).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(5)).unwrap().phase(),
            EpochPhase::Midpoint
        );
        assert_eq!(
            epocher.containing(Height::new(6)).unwrap().phase(),
            EpochPhase::Late
        );
        assert_eq!(
            epocher.containing(Height::new(9)).unwrap().phase(),
            EpochPhase::Late
        );

        // Test with odd epoch length 11 (midpoint = 5 via integer division)
        let epocher = FixedEpocher::new(NZU64!(11));
        assert_eq!(
            epocher.containing(Height::zero()).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(4)).unwrap().phase(),
            EpochPhase::Early
        );
        assert_eq!(
            epocher.containing(Height::new(5)).unwrap().phase(),
            EpochPhase::Midpoint
        );
        assert_eq!(
            epocher.containing(Height::new(6)).unwrap().phase(),
            EpochPhase::Late
        );
        assert_eq!(
            epocher.containing(Height::new(10)).unwrap().phase(),
            EpochPhase::Late
        );
    }

    #[test]
    #[should_panic(expected = "epoch length must exceed one")]
    fn test_fixed_epocher_rejects_length_one() {
        let _ = FixedEpocher::new(NZU64!(1));
    }

    #[test]
    fn test_fixed_epocher_overflow() {
        // Test that containing() returns None when last() would overflow
        let epocher = FixedEpocher::new(NZU64!(100));

        // For epoch length 100:
        // - last valid epoch = (u64::MAX - 100 + 1) / 100 = 184467440737095515
        // - last valid first = 184467440737095515 * 100 = 18446744073709551500
        // - last valid last = 18446744073709551500 + 99 = 18446744073709551599
        // Heights 18446744073709551500 to 18446744073709551599 are in the last valid epoch
        // Height 18446744073709551600 onwards would be in an invalid epoch

        // This height is in the last valid epoch
        let last_valid_first = Height::new(18446744073709551500u64);
        let last_valid_last = Height::new(18446744073709551599u64);

        let result = epocher.containing(last_valid_first);
        assert!(result.is_some());
        let bounds = result.unwrap();
        assert_eq!(bounds.first(), last_valid_first);
        assert_eq!(bounds.last(), last_valid_last);

        let result = epocher.containing(last_valid_last);
        assert!(result.is_some());
        assert_eq!(result.unwrap().last(), last_valid_last);

        // This height would be in an epoch where last() overflows
        let overflow_height = last_valid_last.next();
        assert!(epocher.containing(overflow_height).is_none());

        // u64::MAX is also in the overflow range
        assert!(epocher.containing(Height::new(u64::MAX)).is_none());

        // Test the boundary more precisely with epoch length 2
        let epocher = FixedEpocher::new(NZU64!(2));

        // u64::MAX - 1 is even, so epoch starts at u64::MAX - 1, last = u64::MAX
        let result = epocher.containing(Height::new(u64::MAX - 1));
        assert!(result.is_some());
        assert_eq!(result.unwrap().last(), Height::new(u64::MAX));

        // u64::MAX is odd, epoch would start at u64::MAX - 1
        // first = u64::MAX - 1, last = first + 2 - 1 = u64::MAX (OK)
        let result = epocher.containing(Height::new(u64::MAX));
        assert!(result.is_some());
        assert_eq!(result.unwrap().last(), Height::new(u64::MAX));

        // Test with the smallest epoch length (the final epoch ends exactly at u64::MAX)
        let epocher = FixedEpocher::new(NZU64!(2));
        let result = epocher.containing(Height::new(u64::MAX));
        assert!(result.is_some());
        assert_eq!(result.unwrap().last(), Height::new(u64::MAX));

        // Test case where first overflows (covered by existing checked_mul)
        let epocher = FixedEpocher::new(NZU64!(u64::MAX));
        assert!(epocher.containing(Height::new(u64::MAX)).is_none());

        // Test consistency: first(), last(), and containing() should agree on valid epochs
        let epocher = FixedEpocher::new(NZU64!(100));
        let last_valid_epoch = Epoch::new(184467440737095515);
        let first_invalid_epoch = Epoch::new(184467440737095516);

        // For last valid epoch, all methods should return Some
        assert!(epocher.first(last_valid_epoch).is_some());
        assert!(epocher.last(last_valid_epoch).is_some());
        let first = epocher.first(last_valid_epoch).unwrap();
        assert!(epocher.containing(first).is_some());
        assert_eq!(
            epocher.containing(first).unwrap().last(),
            epocher.last(last_valid_epoch).unwrap()
        );

        // For first invalid epoch, all methods should return None
        assert!(epocher.first(first_invalid_epoch).is_none());
        assert!(epocher.last(first_invalid_epoch).is_none());
        assert!(epocher.containing(last_valid_last.next()).is_none());
    }

    #[test]
    fn test_coding_commitment_fallible_digest() {
        #[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        struct Digest([u8; Self::SIZE]);

        impl Random for Digest {
            fn random(mut rng: impl rand_core::CryptoRng) -> Self {
                let mut buf = [0u8; Self::SIZE];
                rng.fill_bytes(&mut buf);
                Self(buf)
            }
        }

        impl commonware_cryptography::Digest for Digest {
            const EMPTY: Self = Self([0u8; Self::SIZE]);
        }

        impl Write for Digest {
            fn write(&self, buf: &mut impl BufMut) {
                buf.put_slice(&self.0);
            }
        }

        impl FixedSize for Digest {
            const SIZE: usize = 32;
        }

        impl Read for Digest {
            type Cfg = ();

            fn read_cfg(
                _: &mut impl bytes::Buf,
                _: &Self::Cfg,
            ) -> Result<Self, commonware_codec::Error> {
                Err(commonware_codec::Error::Invalid(
                    "Digest",
                    "read not implemented",
                ))
            }
        }

        impl AsRef<[u8]> for Digest {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for Digest {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl core::fmt::Display for Digest {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl core::fmt::Debug for Digest {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "Digest({})", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl Span for Digest {}
        impl Array for Digest {}

        let digest = Digest::random(test_rng());
        let config = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        type Sha256Digest = commonware_cryptography::sha256::Digest;
        type InvalidBlockCommitment =
            Commitment<TestBlock<Digest>, ReedSolomon<TestHasher<Digest>>, TestHasher<Digest>>;
        let commitment = InvalidBlockCommitment::from((digest, digest, digest, config));
        assert!(InvalidBlockCommitment::decode(commitment.encode()).is_err());

        type InvalidRootCommitment = Commitment<
            TestBlock<Sha256Digest>,
            ReedSolomon<TestHasher<Digest>>,
            TestHasher<Sha256Digest>,
        >;
        let commitment =
            InvalidRootCommitment::from((Sha256Digest::EMPTY, digest, Sha256Digest::EMPTY, config));
        assert!(InvalidRootCommitment::decode(commitment.encode()).is_err());

        type InvalidContextCommitment = Commitment<
            TestBlock<Sha256Digest>,
            ReedSolomon<TestHasher<Sha256Digest>>,
            TestHasher<Digest>,
        >;
        let commitment = InvalidContextCommitment::from((
            Sha256Digest::EMPTY,
            Sha256Digest::EMPTY,
            digest,
            config,
        ));
        assert!(InvalidContextCommitment::decode(commitment.encode()).is_err());
    }

    #[test]
    fn test_coding_commitment_supports_short_digest_types() {
        type CrcCommitment = Commitment<
            TestBlock<commonware_cryptography::crc32::Digest>,
            ReedSolomon<commonware_cryptography::Crc32>,
            commonware_cryptography::Crc32,
        >;

        let block = commonware_cryptography::crc32::Digest::from(1);
        let root = commonware_cryptography::crc32::Digest::from(2);
        let context = commonware_cryptography::crc32::Digest::from(3);
        let config = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        let commitment = CrcCommitment::from((block, root, context, config));

        assert_eq!(CrcCommitment::SIZE, COMMITMENT_SIZE);
        assert_eq!(commitment.encode().len(), COMMITMENT_SIZE);

        let decoded = CrcCommitment::decode(commitment.encode()).unwrap();
        assert_eq!(decoded.block(), block);
        assert_eq!(decoded.root(), root);
        assert_eq!(decoded.context(), context);
        assert_eq!(decoded.config(), config);
    }

    #[test]
    fn test_coding_commitment_rejects_non_zero_digest_padding() {
        type CrcCommitment = Commitment<
            TestBlock<commonware_cryptography::crc32::Digest>,
            ReedSolomon<commonware_cryptography::Crc32>,
            commonware_cryptography::Crc32,
        >;

        let config = CodingConfig {
            minimum_shards: NZU16!(1),
            extra_shards: NZU16!(1),
        };
        let commitment = CrcCommitment::from((
            commonware_cryptography::crc32::Digest::from(1),
            commonware_cryptography::crc32::Digest::from(2),
            commonware_cryptography::crc32::Digest::from(3),
            config,
        ));
        let encoded = commitment.encode();
        for offset in [
            commonware_cryptography::crc32::Digest::SIZE,
            32 + commonware_cryptography::crc32::Digest::SIZE,
            64 + commonware_cryptography::crc32::Digest::SIZE,
        ] {
            let mut malformed = encoded.to_vec();
            malformed[offset] = 1;
            assert!(CrcCommitment::decode(malformed.as_ref()).is_err());
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::{coding::Commitment, *};
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};

        type TestCommitment = Commitment<TestBlock<Sha256Digest>, ReedSolomon<Sha256>, Sha256>;

        commonware_conformance::conformance_tests! {
            CodecConformance<Epoch>,
            CodecConformance<Height>,
            CodecConformance<View>,
            CodecConformance<Round>,
            CodecConformance<TestCommitment>,
        }
    }
}
