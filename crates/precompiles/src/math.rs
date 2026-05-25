//! Checked arithmetic helpers for Tempo precompile code.

use alloy::primitives::Uint;

use crate::error::{Result, TempoPrecompileError};

/// Checked arithmetic helpers that convert arithmetic failure into a Tempo precompile error.
///
/// This trait is implemented for all Alloy unsigned integer types (`Uint<BITS, LIMBS>`),
/// including aliases like `U256`, and for Rust primitive unsigned integers. It preserves the
/// checked arithmetic semantics of `checked_add`, `checked_sub`, `checked_mul`, and `checked_div`,
/// but returns the crate's [`Result`] so callers can use `?` directly.
pub trait CheckedMath<Rhs = Self>: Sized {
    /// Adds `rhs`, returning [`TempoPrecompileError::under_overflow`] on overflow.
    fn try_add(self, rhs: Rhs) -> Result<Self>;

    /// Subtracts `rhs`, returning [`TempoPrecompileError::under_overflow`] on underflow.
    fn try_sub(self, rhs: Rhs) -> Result<Self>;

    /// Multiplies by `rhs`, returning [`TempoPrecompileError::under_overflow`] on overflow.
    fn try_mul(self, rhs: Rhs) -> Result<Self>;

    /// Divides by `rhs`, returning [`TempoPrecompileError::under_overflow`] on division by zero.
    fn try_div(self, rhs: Rhs) -> Result<Self>;
}

impl<const BITS: usize, const LIMBS: usize> CheckedMath for Uint<BITS, LIMBS> {
    #[inline]
    fn try_add(self, rhs: Self) -> Result<Self> {
        self.checked_add(rhs)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    #[inline]
    fn try_sub(self, rhs: Self) -> Result<Self> {
        self.checked_sub(rhs)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    #[inline]
    fn try_mul(self, rhs: Self) -> Result<Self> {
        self.checked_mul(rhs)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }

    #[inline]
    fn try_div(self, rhs: Self) -> Result<Self> {
        self.checked_div(rhs)
            .ok_or_else(TempoPrecompileError::under_overflow)
    }
}

macro_rules! impl_checked_math_for_unsigned_primitives {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl CheckedMath for $ty {
                #[inline]
                fn try_add(self, rhs: Self) -> Result<Self> {
                    self.checked_add(rhs).ok_or_else(TempoPrecompileError::under_overflow)
                }

                #[inline]
                fn try_sub(self, rhs: Self) -> Result<Self> {
                    self.checked_sub(rhs).ok_or_else(TempoPrecompileError::under_overflow)
                }

                #[inline]
                fn try_mul(self, rhs: Self) -> Result<Self> {
                    self.checked_mul(rhs).ok_or_else(TempoPrecompileError::under_overflow)
                }

                #[inline]
                fn try_div(self, rhs: Self) -> Result<Self> {
                    self.checked_div(rhs).ok_or_else(TempoPrecompileError::under_overflow)
                }
            }
        )+
    };
}

impl_checked_math_for_unsigned_primitives!(u8, u16, u32, u64, u128);
