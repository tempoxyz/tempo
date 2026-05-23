use cfg_if::cfg_if;
use core::hash::{BuildHasher, Hash, Hasher};

// Faster hashers.
cfg_if! {
    if #[cfg(feature = "map-fxhash")] {
        #[doc(no_inline)]
        pub use rustc_hash::{self, FxHasher};

        /// The [`FxHasher`] hasher builder.
        ///
        /// This is [`rustc_hash::FxBuildHasher`], unless both the "std" and "rand" features are
        /// enabled, in which case it will be [`rustc_hash::FxRandomState`] for better security at
        /// very little cost.
        pub type FxBuildHasher = FxBuildHasherInner;
    }
}

// Used by `FbHasher`.
cfg_if! {
    if #[cfg(all(feature = "std", feature = "rand"))] {
        pub(super) use rustc_hash::FxRandomState as FxBuildHasherInner;
    } else {
        pub(super) use rustc_hash::FxBuildHasher as FxBuildHasherInner;
    }
}

#[cfg(feature = "map-foldhash")]
#[doc(no_inline)]
pub use foldhash;

#[cfg(feature = "map-rapidhash")]
#[doc(no_inline)]
pub use rapidhash;

// Default hasher.
cfg_if! {
    if #[cfg(feature = "map-foldhash")] {
        type DefaultHashBuilderInner = foldhash::fast::RandomState;
    } else if #[cfg(feature = "map-rapidhash")] {
        type DefaultHashBuilderInner = rapidhash::fast::RandomState;
    } else if #[cfg(feature = "map-fxhash")] {
        type DefaultHashBuilderInner = FxBuildHasher;
    } else if #[cfg(any(feature = "map-hashbrown", not(feature = "std")))] {
        type DefaultHashBuilderInner = hashbrown::DefaultHashBuilder;
    } else {
        type DefaultHashBuilderInner = std::collections::hash_map::RandomState;
    }
}

/// The default [`BuildHasher`] used by [`HashMap`](super::HashMap) and [`HashSet`](super::HashSet).
///
/// See [the module documentation](super) for more information on the default hasher.
#[derive(Clone, Default)]
#[allow(missing_copy_implementations, missing_debug_implementations)]
pub struct DefaultHashBuilder {
    inner: DefaultHashBuilderInner,
}

impl BuildHasher for DefaultHashBuilder {
    type Hasher = DefaultHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        DefaultHasher { inner: self.inner.build_hasher() }
    }

    #[inline]
    fn hash_one<T: Hash>(&self, x: T) -> u64
    where
        Self: Sized,
        Self::Hasher: Hasher,
    {
        self.inner.hash_one(x)
    }
}

/// The default [`Hasher`] used by [`HashMap`](super::HashMap) and [`HashSet`](super::HashSet).
///
/// See [the module documentation](super) for more information on the default hasher.
#[derive(Clone)]
#[allow(missing_debug_implementations)]
pub struct DefaultHasher {
    inner: <DefaultHashBuilderInner as BuildHasher>::Hasher,
}

macro_rules! forward_writes {
    ($( $write:ident ( $ty:ty ) , )*) => {$(
        #[inline(always)]
        fn $write(&mut self, arg: $ty) {
            self.inner.$write(arg);
        }
    )*}
}

impl Hasher for DefaultHasher {
    forward_writes! {
        write(&[u8]),
        write_u8(u8),
        write_u16(u16),
        write_u32(u32),
        write_u64(u64),
        write_u128(u128),
        write_usize(usize),
        write_i8(i8),
        write_i16(i16),
        write_i32(i32),
        write_i64(i64),
        write_i128(i128),
        write_isize(isize),
    }

    // feature(hasher_prefixfree_extras)
    #[cfg(feature = "nightly")]
    forward_writes! {
        write_length_prefix(usize),
        write_str(&str),
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        self.inner.finish()
    }
}
