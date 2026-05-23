use crate::FixedBytes;
use alloc::vec::Vec;
use core::slice;

/// Extension trait for flattening a slice of `FixedBytes` to a byte slice.
///
/// This mirrors the standard library's `as_flattened` and `as_flattened_mut` methods for
/// `&[[T; N]]`.
pub trait FixedBytesSliceExt {
    /// Takes a `&[FixedBytes<N>]` and flattens it to a `&[u8]`.
    ///
    /// # Panics
    ///
    /// This panics if the length of the resulting slice would overflow a `usize`.
    ///
    /// This is only possible when `N == 0`, which tends to be irrelevant in practice.
    ///
    /// # Examples
    ///
    /// ```
    /// use alloy_primitives::{FixedBytes, FixedBytesSliceExt};
    ///
    /// let arr = [FixedBytes::<4>::new([1, 2, 3, 4]), FixedBytes::new([5, 6, 7, 8])];
    /// assert_eq!(arr.as_flattened(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    /// ```
    fn as_flattened(&self) -> &[u8];

    /// Takes a `&mut [FixedBytes<N>]` and flattens it to a `&mut [u8]`.
    ///
    /// # Panics
    ///
    /// This panics if the length of the resulting slice would overflow a `usize`.
    ///
    /// This is only possible when `N == 0`, which tends to be irrelevant in practice.
    ///
    /// # Examples
    ///
    /// ```
    /// use alloy_primitives::{FixedBytes, FixedBytesSliceExt};
    ///
    /// fn add_one(slice: &mut [u8]) {
    ///     for b in slice {
    ///         *b = b.wrapping_add(1);
    ///     }
    /// }
    ///
    /// let mut arr = [FixedBytes::<4>::new([1, 2, 3, 4]), FixedBytes::new([5, 6, 7, 8])];
    /// add_one(arr.as_flattened_mut());
    /// assert_eq!(arr[0].as_slice(), &[2, 3, 4, 5]);
    /// ```
    fn as_flattened_mut(&mut self) -> &mut [u8];
}

impl<const N: usize> FixedBytesSliceExt for [FixedBytes<N>] {
    #[inline]
    fn as_flattened(&self) -> &[u8] {
        // SAFETY: `self.len() * N` cannot overflow because `self` is
        // already in the address space.
        let len = unsafe { self.len().unchecked_mul(N) };
        // SAFETY: `FixedBytes<N>` is `repr(transparent)` over `[u8; N]`.
        unsafe { slice::from_raw_parts(self.as_ptr().cast(), len) }
    }

    #[inline]
    fn as_flattened_mut(&mut self) -> &mut [u8] {
        // SAFETY: `self.len() * N` cannot overflow because `self` is
        // already in the address space.
        let len = unsafe { self.len().unchecked_mul(N) };
        // SAFETY: `FixedBytes<N>` is `repr(transparent)` over `[u8; N]`.
        unsafe { slice::from_raw_parts_mut(self.as_mut_ptr().cast(), len) }
    }
}

/// Extension trait for flattening a `Vec` of `FixedBytes` to a `Vec<u8>`.
///
/// This mirrors the standard library's `into_flattened` method for `Vec<[T; N]>`.
pub trait FixedBytesVecExt {
    /// Takes a `Vec<FixedBytes<N>>` and flattens it into a `Vec<u8>`.
    ///
    /// # Panics
    ///
    /// This panics if the length of the resulting vector would overflow a `usize`.
    ///
    /// This is only possible when `N == 0`, which tends to be irrelevant in practice.
    ///
    /// # Examples
    ///
    /// ```
    /// use alloy_primitives::{FixedBytes, FixedBytesVecExt};
    ///
    /// let mut vec = vec![
    ///     FixedBytes::<4>::new([1, 2, 3, 4]),
    ///     FixedBytes::new([5, 6, 7, 8]),
    ///     FixedBytes::new([9, 10, 11, 12]),
    /// ];
    /// assert_eq!(vec.pop(), Some(FixedBytes::new([9, 10, 11, 12])));
    ///
    /// let mut flattened = vec.into_flattened();
    /// assert_eq!(flattened.pop(), Some(8));
    /// ```
    fn into_flattened(self) -> Vec<u8>;
}

impl<const N: usize> FixedBytesVecExt for Vec<FixedBytes<N>> {
    #[inline]
    fn into_flattened(self) -> Vec<u8> {
        let mut this = core::mem::ManuallyDrop::new(self);
        let (ptr, len, cap) = (this.as_mut_ptr(), this.len(), this.capacity());
        // SAFETY:
        // - `cap * N` cannot overflow because the allocation is already in
        // the address space.
        // - Each `[T; N]` has `N` valid elements, so there are `len * N`
        // valid elements in the allocation.
        let (new_len, new_cap) = unsafe { (len.unchecked_mul(N), cap.unchecked_mul(N)) };
        // SAFETY:
        // - `ptr` was allocated by `self`
        // - `ptr` is well-aligned because `FixedBytes<N>` has the same alignment as `u8` (since
        //   `FixedBytes<N>` is `repr(transparent)` over `[u8; N]`)
        // - `new_cap * size_of::<u8>()` == `cap * size_of::<FixedBytes<N>>()`
        // - `len <= cap`, so `len * N <= cap * N`
        unsafe { Vec::from_raw_parts(ptr.cast(), new_len, new_cap) }
    }
}

// Can't put in `wrap_fixed_bytes` macro due to orphan rules.
macro_rules! impl_flatten {
    ([$($gen:tt)*] $t:ty, $n:expr) => {
        impl<$($gen)*> $crate::FixedBytesSliceExt for [$t] {
            #[inline]
            fn as_flattened(&self) -> &[u8] {
                unsafe { core::mem::transmute::<&[$t], &[FixedBytes<$n>]>(self) }.as_flattened()
            }

            #[inline]
            fn as_flattened_mut(&mut self) -> &mut [u8] {
                unsafe { core::mem::transmute::<&mut [$t], &mut [FixedBytes<$n>]>(self) }
                    .as_flattened_mut()
            }
        }

        impl<$($gen)*> $crate::FixedBytesVecExt for $crate::private::Vec<$t> {
            #[inline]
            fn into_flattened(self) -> $crate::private::Vec<u8> {
                unsafe { core::mem::transmute::<Vec<$t>, Vec<FixedBytes<$n>>>(self) }
                    .into_flattened()
            }
        }
    };
}

impl_flatten!([] crate::Address, 20);
impl_flatten!([] crate::Bloom, 256);
impl_flatten!([const BITS: usize, const LIMBS: usize] crate::Uint<BITS, LIMBS>, 32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;

    #[test]
    fn test_as_flattened() {
        let arr = [FixedBytes::<4>::new([1, 2, 3, 4]), FixedBytes::new([5, 6, 7, 8])];
        assert_eq!(arr.as_flattened(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_as_flattened_empty() {
        let arr: [FixedBytes<4>; 0] = [];
        assert!(arr.as_flattened().is_empty());
    }

    #[test]
    fn test_as_flattened_mut() {
        let mut arr = [FixedBytes::<4>::new([1, 2, 3, 4]), FixedBytes::new([5, 6, 7, 8])];
        for b in arr.as_flattened_mut() {
            *b = b.wrapping_add(1);
        }
        assert_eq!(arr[0].as_slice(), &[2, 3, 4, 5]);
        assert_eq!(arr[1].as_slice(), &[6, 7, 8, 9]);
    }

    #[test]
    fn test_into_flattened() {
        let vec = vec![FixedBytes::<4>::new([1, 2, 3, 4]), FixedBytes::new([5, 6, 7, 8])];
        assert_eq!(vec.into_flattened(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_into_flattened_empty() {
        let vec: Vec<FixedBytes<4>> = vec![];
        assert!(vec.into_flattened().is_empty());
    }

    #[test]
    fn test_address_as_flattened() {
        let arr = [Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        let flattened = arr.as_flattened();
        assert_eq!(flattened.len(), 40);
        assert_eq!(&flattened[..20], &[0x11; 20]);
        assert_eq!(&flattened[20..], &[0x22; 20]);
    }

    #[test]
    fn test_address_as_flattened_mut() {
        let mut arr = [Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        arr.as_flattened_mut()[0] = 0xff;
        assert_eq!(arr[0].0[0], 0xff);
    }

    #[test]
    fn test_address_into_flattened() {
        let vec = vec![Address::repeat_byte(0x11), Address::repeat_byte(0x22)];
        let flattened = vec.into_flattened();
        assert_eq!(flattened.len(), 40);
        assert_eq!(&flattened[..20], &[0x11; 20]);
        assert_eq!(&flattened[20..], &[0x22; 20]);
    }
}
