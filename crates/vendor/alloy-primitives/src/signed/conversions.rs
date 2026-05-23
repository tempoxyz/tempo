use super::{BigIntConversionError, ParseSignedError, Sign, Signed, utils::twos_complement};
use alloc::string::String;
use core::str::FromStr;
use ruint::{FromUintError, ToUintError, Uint, UintTryFrom, UintTryTo};

impl<const BITS: usize, const LIMBS: usize> TryFrom<Uint<BITS, LIMBS>> for Signed<BITS, LIMBS> {
    type Error = BigIntConversionError;

    #[inline]
    fn try_from(from: Uint<BITS, LIMBS>) -> Result<Self, Self::Error> {
        let value = Self(from);
        match value.sign() {
            Sign::Positive => Ok(value),
            Sign::Negative => Err(BigIntConversionError),
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<Signed<BITS, LIMBS>> for Uint<BITS, LIMBS> {
    type Error = BigIntConversionError;

    #[inline]
    fn try_from(value: Signed<BITS, LIMBS>) -> Result<Self, Self::Error> {
        match value.sign() {
            Sign::Positive => Ok(value.0),
            Sign::Negative => Err(BigIntConversionError),
        }
    }
}

/// Conversion from `Signed` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_SRC: usize, const LIMBS_SRC: usize>
    UintTryFrom<Signed<BITS_SRC, LIMBS_SRC>> for Signed<BITS, LIMBS>
{
    #[inline]
    fn uint_try_from(value: Signed<BITS_SRC, LIMBS_SRC>) -> Result<Self, ToUintError<Self>> {
        let (sign, abs) = value.into_sign_and_abs();
        let resized = Self::from_raw(Uint::<BITS, LIMBS>::uint_try_from(abs).map_err(signed_err)?);
        if resized.is_negative() {
            return Err(ToUintError::ValueNegative(BITS, resized));
        }
        Ok(match sign {
            Sign::Negative => {
                resized.checked_neg().ok_or(ToUintError::ValueTooLarge(BITS, resized))?
            }
            Sign::Positive => resized,
        })
    }
}

/// Conversion to `Signed` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_TARGET: usize, const LIMBS_TARGET: usize>
    UintTryTo<Signed<BITS_TARGET, LIMBS_TARGET>> for Signed<BITS, LIMBS>
{
    #[inline]
    fn uint_try_to(
        &self,
    ) -> Result<Signed<BITS_TARGET, LIMBS_TARGET>, FromUintError<Signed<BITS_TARGET, LIMBS_TARGET>>>
    {
        let (sign, abs) = self.into_sign_and_abs();
        let resized = Signed::<BITS_TARGET, LIMBS_TARGET>::from_raw(
            Uint::uint_try_to(&abs).map_err(|e| match e {
                FromUintError::Overflow(b, t, v) => {
                    FromUintError::Overflow(b, Signed(t), Signed(v))
                }
            })?,
        );
        if resized.is_negative() {
            return Err(FromUintError::Overflow(BITS_TARGET, resized, Signed::MAX));
        }
        Ok(match sign {
            Sign::Negative => resized.checked_neg().ok_or(FromUintError::Overflow(
                BITS_TARGET,
                resized,
                Signed::MAX,
            ))?,
            Sign::Positive => resized,
        })
    }
}

/// Conversion from positive `Signed` to `Uint` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_SRC: usize, const LIMBS_SRC: usize>
    UintTryFrom<Signed<BITS_SRC, LIMBS_SRC>> for Uint<BITS, LIMBS>
{
    #[inline]
    fn uint_try_from(value: Signed<BITS_SRC, LIMBS_SRC>) -> Result<Self, ToUintError<Self>> {
        if value.is_negative() {
            return Err(ToUintError::ValueNegative(BITS, Self::uint_try_from(value.into_raw())?));
        }
        Self::uint_try_from(value.into_raw())
    }
}

/// Conversion to `Uint` from positive `Signed` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_TARGET: usize, const LIMBS_TARGET: usize>
    UintTryTo<Uint<BITS_TARGET, LIMBS_TARGET>> for Signed<BITS, LIMBS>
{
    #[inline]
    fn uint_try_to(
        &self,
    ) -> Result<Uint<BITS_TARGET, LIMBS_TARGET>, FromUintError<Uint<BITS_TARGET, LIMBS_TARGET>>>
    {
        if self.is_negative() {
            return Err(FromUintError::Overflow(BITS_TARGET, Uint::ZERO, Uint::MAX));
        }
        Uint::uint_try_to(&self.into_raw())
    }
}

/// Conversion from `Uint` to positive `Signed` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_SRC: usize, const LIMBS_SRC: usize>
    UintTryFrom<Uint<BITS_SRC, LIMBS_SRC>> for Signed<BITS, LIMBS>
{
    #[inline]
    fn uint_try_from(value: Uint<BITS_SRC, LIMBS_SRC>) -> Result<Self, ToUintError<Self>> {
        let resized =
            Self::from_raw(Uint::<BITS, LIMBS>::uint_try_from(value).map_err(signed_err)?);
        if resized.is_negative() {
            return Err(ToUintError::ValueNegative(BITS, resized));
        }
        Ok(resized)
    }
}

/// Conversion to positive `Signed` from `Uint` of different `BITS` or `LIMBS` length.
impl<const BITS: usize, const LIMBS: usize, const BITS_TARGET: usize, const LIMBS_TARGET: usize>
    UintTryTo<Signed<BITS_TARGET, LIMBS_TARGET>> for Uint<BITS, LIMBS>
{
    #[inline]
    fn uint_try_to(
        &self,
    ) -> Result<Signed<BITS_TARGET, LIMBS_TARGET>, FromUintError<Signed<BITS_TARGET, LIMBS_TARGET>>>
    {
        let resized = Signed::<BITS_TARGET, LIMBS_TARGET>::from_raw(
            Self::uint_try_to(self).map_err(|e| match e {
                FromUintError::Overflow(b, t, v) => {
                    FromUintError::Overflow(b, Signed(t), Signed(v))
                }
            })?,
        );
        if resized.is_negative() {
            return Err(FromUintError::Overflow(BITS_TARGET, resized, Signed::MAX));
        }
        Ok(resized)
    }
}

fn signed_err<const BITS: usize, const LIMBS: usize>(
    err: ToUintError<Uint<BITS, LIMBS>>,
) -> ToUintError<Signed<BITS, LIMBS>> {
    match err {
        ToUintError::ValueTooLarge(b, t) => ToUintError::ValueTooLarge(b, Signed(t)),
        ToUintError::ValueNegative(b, t) => ToUintError::ValueNegative(b, Signed(t)),
        ToUintError::NotANumber(b) => ToUintError::NotANumber(b),
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<&str> for Signed<BITS, LIMBS> {
    type Error = ParseSignedError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<&String> for Signed<BITS, LIMBS> {
    type Error = ParseSignedError;

    #[inline]
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<String> for Signed<BITS, LIMBS> {
    type Error = ParseSignedError;

    #[inline]
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl<const BITS: usize, const LIMBS: usize> FromStr for Signed<BITS, LIMBS> {
    type Err = ParseSignedError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (sign, s) = match s.as_bytes().first() {
            Some(b'+') => (Sign::Positive, &s[1..]),
            Some(b'-') => (Sign::Negative, &s[1..]),
            _ => (Sign::Positive, s),
        };
        let abs = Uint::<BITS, LIMBS>::from_str(s)?;
        Self::checked_from_sign_and_abs(sign, abs).ok_or(ParseSignedError::IntegerOverflow)
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<Signed<BITS, LIMBS>> for i128 {
    type Error = BigIntConversionError;

    fn try_from(value: Signed<BITS, LIMBS>) -> Result<Self, Self::Error> {
        if value.bits() > 128 {
            return Err(BigIntConversionError);
        }

        if value.is_positive() {
            Ok(u128::try_from(value.0).unwrap() as Self)
        } else {
            let u = twos_complement(value.0);
            let u = u128::try_from(u).unwrap() as Self;
            Ok((!u).wrapping_add(1))
        }
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<i128> for Signed<BITS, LIMBS> {
    type Error = BigIntConversionError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        let u = value as u128;
        if value >= 0 {
            return Self::try_from(u);
        }

        // This is a bit messy :(
        let tc = (!u).wrapping_add(1);
        let stc = Uint::<128, 2>::saturating_from(tc);
        let (num, overflow) = Uint::<BITS, LIMBS>::overflowing_from_limbs_slice(stc.as_limbs());
        if overflow {
            return Err(BigIntConversionError);
        }
        Ok(Self(twos_complement(num)))
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<Signed<BITS, LIMBS>> for u128 {
    type Error = BigIntConversionError;

    fn try_from(value: Signed<BITS, LIMBS>) -> Result<Self, Self::Error> {
        if value.is_negative() {
            return Err(BigIntConversionError);
        }

        let saturated = Uint::<BITS, LIMBS>::saturating_from(Self::MAX);

        // if the value is greater than the saturated value, return an error
        if value > Signed(saturated) {
            return Err(BigIntConversionError);
        }

        value.into_raw().try_into().map_err(|_| BigIntConversionError)
    }
}

impl<const BITS: usize, const LIMBS: usize> TryFrom<u128> for Signed<BITS, LIMBS> {
    type Error = BigIntConversionError;

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        let saturated = Uint::<BITS, LIMBS>::saturating_from(value);

        if value != saturated.to::<u128>() {
            return Err(BigIntConversionError);
        }

        Self::try_from(saturated)
    }
}

// conversions
macro_rules! impl_conversions {
    ($(
        $u:ty [$actual_low_u:ident -> $low_u:ident, $as_u:ident],
        $i:ty [$actual_low_i:ident -> $low_i:ident, $as_i:ident];
    )+) => {
        // low_*, as_*
        impl<const BITS: usize, const LIMBS: usize> Signed<BITS, LIMBS> {
            $(
                impl_conversions!(@impl_fns $u, $actual_low_u $low_u $as_u);
                impl_conversions!(@impl_fns $i, $actual_low_i $low_i $as_i);
            )+
        }

        // From<$>, TryFrom
        $(
            impl<const BITS: usize, const LIMBS: usize> TryFrom<$u> for Signed<BITS, LIMBS> {
                type Error = BigIntConversionError;

                #[inline]
                fn try_from(value: $u) -> Result<Self, Self::Error> {
                    let u = Uint::<BITS, LIMBS>::try_from(value).map_err(|_| BigIntConversionError)?;
                    Signed::checked_from_sign_and_abs(Sign::Positive, u).ok_or(BigIntConversionError)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> TryFrom<$i> for Signed<BITS, LIMBS> {
                type Error = BigIntConversionError;

                #[inline]
                fn try_from(value: $i) -> Result<Self, Self::Error> {
                    let uint: $u = value as $u;

                    if value.is_positive() {
                        return Self::try_from(uint);
                    }

                    let abs = (!uint).wrapping_add(1);
                    let tc = twos_complement(Uint::<BITS, LIMBS>::from(abs));
                    Ok(Self(tc))
                }
            }

            impl<const BITS: usize, const LIMBS: usize> TryFrom<Signed<BITS, LIMBS>> for $u {
                type Error = BigIntConversionError;

                #[inline]
                fn try_from(value: Signed<BITS, LIMBS>) -> Result<$u, Self::Error> {
                    u128::try_from(value)?.try_into().map_err(|_| BigIntConversionError)
                }
            }

            impl<const BITS: usize, const LIMBS: usize> TryFrom<Signed<BITS, LIMBS>> for $i {
                type Error = BigIntConversionError;

                #[inline]
                fn try_from(value: Signed<BITS, LIMBS>) -> Result<$i, Self::Error> {
                    i128::try_from(value)?.try_into().map_err(|_| BigIntConversionError)
                }
            }
        )+
    };

    (@impl_fns $t:ty, $actual_low:ident $low:ident $as:ident) => {
        /// Low word.
        #[inline]
        pub const fn $low(&self) -> $t {
            if BITS == 0 {
                return 0
            }

            self.0.as_limbs()[0] as $t
        }

        #[doc = concat!("Conversion to ", stringify!($t) ," with overflow checking.")]
        ///
        /// # Panics
        ///
        #[doc = concat!("Panics if the number is outside the ", stringify!($t), " valid range.")]
        #[inline]
        #[track_caller]
        pub fn $as(&self) -> $t {
            <$t as TryFrom<Self>>::try_from(*self).unwrap()
        }
    };
}

impl_conversions! {
    u8   [low_u64  -> low_u8,    as_u8],    i8   [low_u64  -> low_i8,    as_i8];
    u16  [low_u64  -> low_u16,   as_u16],   i16  [low_u64  -> low_i16,   as_i16];
    u32  [low_u64  -> low_u32,   as_u32],   i32  [low_u64  -> low_i32,   as_i32];
    u64  [low_u64  -> low_u64,   as_u64],   i64  [low_u64  -> low_i64,   as_i64];
    usize[low_u64  -> low_usize, as_usize], isize[low_u64  -> low_isize, as_isize];
}
