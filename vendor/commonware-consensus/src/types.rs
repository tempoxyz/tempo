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
//! - [`Epocher`]: Mechanism for determining epoch boundaries.
//!
//! - [`coding::Commitment`]: A unique identifier combining a block digest, coding digest, context
//!   hash, and encoded coding configuration. Used as the certificate payload for erasure-coded blocks.
//!
//! # Arithmetic Safety
//!
//! Arithmetic operations avoid silent errors. Only `next()` panics on overflow. All other
//! operations either saturate or return `Option`.
//!
//! # Type Conversions
//!
//! Explicit type constructors (`Epoch::new()`, `View::new()`) are required to create instances
//! from raw integers. Implicit conversions via, e.g. `From<u64>` are intentionally not provided
//! to prevent accidental type misuse.

use crate::{Epochable, Viewable};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, Write};
#[cfg(not(target_arch = "wasm32"))]
use commonware_runtime::telemetry::traces::TracedExt;
use commonware_utils::sequence::U64;
use core::{
    fmt::{self, Display, Formatter},
    marker::PhantomData,
    num::NonZeroU64,
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
/// Height is a monotonically increasing counter.
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedEpocher(u64);

impl FixedEpocher {
    /// Creates a new fixed epoch strategy.
    ///
    /// # Example
    /// ```rust
    /// # use commonware_consensus::types::FixedEpocher;
    /// # use commonware_utils::NZU64;
    /// let strategy = FixedEpocher::new(NZU64!(60_480));
    /// ```
    pub const fn new(length: NonZeroU64) -> Self {
        Self(length.get())
    }

    /// Computes the first and last block height for an epoch, returning `None` if
    /// either would overflow.
    fn bounds(&self, epoch: Epoch) -> Option<(Height, Height)> {
        let first = epoch.get().checked_mul(self.0)?;
        let last = first.checked_add(self.0 - 1)?;
        Some((Height::new(first), Height::new(last)))
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
        use commonware_coding::Config as CodingConfig;
        use commonware_cryptography::Digest;
        use commonware_math::algebra::Random;
        use commonware_utils::{Array, Span, NZU16};
        use core::{
            num::NonZeroU16,
            ops::{Deref, Range},
        };
        use rand_core::CryptoRng;

        /// A [`Digest`] containing a coding commitment, encoded [`CodingConfig`], and context hash.
        ///
        /// Commitment wire layout (byte ranges are start..end):
        /// - block digest:   0..32
        /// - coding root:    32..64
        /// - context digest: 64..96
        /// - coding config:  96..100
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, FixedArray)]
        pub struct Commitment([u8; Self::SIZE]);

        impl Commitment {
            const DIGEST_SIZE: usize = 32;
            const BLOCK_DIGEST_OFFSET: usize = 0;
            const CODING_ROOT_OFFSET: usize = Self::BLOCK_DIGEST_OFFSET + Self::DIGEST_SIZE;
            const CONTEXT_DIGEST_OFFSET: usize = Self::CODING_ROOT_OFFSET + Self::DIGEST_SIZE;
            const CONFIG_OFFSET: usize = Self::CONTEXT_DIGEST_OFFSET + Self::DIGEST_SIZE;

            /// Extracts the [`CodingConfig`] from this [`Commitment`].
            pub fn config(&self) -> CodingConfig {
                let mut buf = &self.0[Self::CONFIG_OFFSET..];
                CodingConfig::read(&mut buf).expect("Commitment always contains a valid config")
            }

            /// Returns the block [`Digest`] from this [`Commitment`].
            ///
            /// ## Panics
            ///
            /// Panics if the [`Digest`]'s [`FixedSize::SIZE`] is > 32 bytes.
            pub fn block<D: Digest>(&self) -> D {
                self.take(Self::BLOCK_DIGEST_OFFSET..Self::BLOCK_DIGEST_OFFSET + D::SIZE)
            }

            /// Returns the coding root [`Digest`] from this [`Commitment`].
            ///
            /// ## Panics
            ///
            /// Panics if the [`Digest`]'s [`FixedSize::SIZE`] is > 32 bytes.
            pub fn root<D: Digest>(&self) -> D {
                self.take(Self::CODING_ROOT_OFFSET..Self::CODING_ROOT_OFFSET + D::SIZE)
            }

            /// Returns the context [`Digest`] from this [`Commitment`].
            ///
            /// ## Panics
            ///
            /// Panics if the [`Digest`]'s [`FixedSize::SIZE`] is > 32 bytes.
            pub fn context<D: Digest>(&self) -> D {
                self.take(Self::CONTEXT_DIGEST_OFFSET..Self::CONTEXT_DIGEST_OFFSET + D::SIZE)
            }

            /// Extracts the [`Digest`] from this [`Commitment`].
            ///
            /// ## Panics
            ///
            /// Panics if the [`Digest`]'s [`FixedSize::SIZE`] is > 32 bytes.
            fn take<D: Digest>(&self, range: Range<usize>) -> D {
                const {
                    assert!(
                        D::SIZE <= 32,
                        "Cannot extract Digest with size > 32 from Commitment"
                    );
                }

                D::read(&mut self.0[range].as_ref())
                    .expect("Commitment always contains a valid digest")
            }
        }

        impl Random for Commitment {
            fn random(mut rng: impl CryptoRng) -> Self {
                let mut buf = [0u8; Self::SIZE];
                rng.fill_bytes(&mut buf[..Self::CONFIG_OFFSET]);

                let one = NZU16!(1);
                let shards = rng.next_u32();
                let config = CodingConfig {
                    minimum_shards: NonZeroU16::new(shards as u16).unwrap_or(one),
                    extra_shards: NonZeroU16::new((shards >> 16) as u16).unwrap_or(one),
                };
                let mut cfg_buf = &mut buf[Self::CONFIG_OFFSET..];
                config.write(&mut cfg_buf);

                Self(buf)
            }
        }

        impl Digest for Commitment {
            const EMPTY: Self = Self([0u8; Self::SIZE]);
        }

        impl Write for Commitment {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                buf.put_slice(&self.0);
            }
        }

        impl FixedSize for Commitment {
            const SIZE: usize = Self::CONFIG_OFFSET + CodingConfig::SIZE;
        }

        impl Read for Commitment {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl bytes::Buf,
                _cfg: &Self::Cfg,
            ) -> Result<Self, commonware_codec::Error> {
                if buf.remaining() < Self::SIZE {
                    return Err(commonware_codec::Error::EndOfBuffer);
                }
                let mut arr = [0u8; Self::SIZE];
                buf.copy_to_slice(&mut arr);

                // Validate the embedded CodingConfig so that `config()` can
                // never panic on a successfully-deserialized Commitment.
                let mut cfg_buf = &arr[Self::CONFIG_OFFSET..];
                CodingConfig::read(&mut cfg_buf).map_err(|_| {
                    commonware_codec::Error::Invalid("Commitment", "invalid embedded CodingConfig")
                })?;

                Ok(Self(arr))
            }
        }

        impl AsRef<[u8]> for Commitment {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Deref for Commitment {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl core::fmt::Display for Commitment {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl core::fmt::Debug for Commitment {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", commonware_formatting::Hex(self.as_ref()))
            }
        }

        impl Default for Commitment {
            fn default() -> Self {
                Self([0u8; Self::SIZE])
            }
        }

        impl<D1: Digest, D2: Digest, D3: Digest> From<(D1, D2, D3, CodingConfig)> for Commitment {
            fn from(
                (digest, commitment, context_digest, config): (D1, D2, D3, CodingConfig),
            ) -> Self {
                const {
                    assert!(
                        D1::SIZE <= Self::DIGEST_SIZE,
                        "Cannot create Commitment from Digest with size > Self::DIGEST_SIZE"
                    );
                    assert!(
                        D2::SIZE <= Self::DIGEST_SIZE,
                        "Cannot create Commitment from Digest with size > Self::DIGEST_SIZE"
                    );
                    assert!(
                        D3::SIZE <= Self::DIGEST_SIZE,
                        "Cannot create Commitment from Digest with size > Self::DIGEST_SIZE"
                    );
                }

                let mut buf = [0u8; Self::SIZE];
                buf[..D1::SIZE].copy_from_slice(&digest);
                buf[Self::CODING_ROOT_OFFSET..Self::CODING_ROOT_OFFSET + D2::SIZE]
                    .copy_from_slice(&commitment);
                buf[Self::CONTEXT_DIGEST_OFFSET..Self::CONTEXT_DIGEST_OFFSET + D3::SIZE]
                    .copy_from_slice(&context_digest);
                buf[Self::CONFIG_OFFSET..].copy_from_slice(&config.encode());
                Self(buf)
            }
        }

        impl Span for Commitment {}

        impl Array for Commitment {}

        #[cfg(feature = "arbitrary")]
        impl arbitrary::Arbitrary<'_> for Commitment {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                let config = CodingConfig::arbitrary(u)?;
                let mut buf = [0u8; Self::SIZE];
                buf[..96].copy_from_slice(u.bytes(96)?);
                buf[96..].copy_from_slice(&config.encode());
                Ok(Self(buf))
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::coding::Commitment;
    use commonware_codec::{DecodeExt, Encode, EncodeSize, FixedSize};
    use commonware_coding::Config as CodingConfig;
    use commonware_math::algebra::Random;
    use commonware_utils::{test_rng, Array, Span, NZU16, NZU64};
    use std::ops::Deref;

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

        // Test with epoch length 1 (every height is its own epoch)
        let epocher = FixedEpocher::new(NZU64!(1));
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
        let commitment = Commitment::from((
            digest,
            digest,
            digest,
            CodingConfig {
                minimum_shards: NZU16!(1),
                extra_shards: NZU16!(1),
            },
        ));

        // Decoding the commitment should succeed.
        let encoded = commitment.encode();
        let decoded = Commitment::decode(encoded).unwrap();

        // Pulling out the digest should panic.
        let result = std::panic::catch_unwind(|| decoded.block::<Digest>());
        assert!(result.is_err());
        let result = std::panic::catch_unwind(|| decoded.root::<Digest>());
        assert!(result.is_err());
        let result = std::panic::catch_unwind(|| decoded.context::<Digest>());
        assert!(result.is_err());
        let result = std::panic::catch_unwind(|| decoded.config());
        assert!(result.is_ok());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::{coding::Commitment, *};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Epoch>,
            CodecConformance<Height>,
            CodecConformance<View>,
            CodecConformance<Round>,
            CodecConformance<Commitment>,
        }
    }
}
