//! Checked arithmetic helpers for Tempo precompiles.

use crate::error::{Result, TempoPrecompileError};
use alloy::primitives::Uint;

/// Checked arithmetic helpers that convert arithmetic failure into a Tempo precompile error.
///
/// Implemented for all Alloy and Rust primitive unsigned integer types.
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
