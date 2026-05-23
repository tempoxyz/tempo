//! A minimalistic one-way set associative cache for Keccak256 values.
//!
//! This cache has a fixed size to allow fast access and minimize per-call overhead.

use super::{hint::unlikely, keccak256_impl as keccak256};
use crate::{B256, KECCAK256_EMPTY};
use metrics::Counter;
use std::{mem::MaybeUninit, sync::LazyLock};

/// Maximum input length that can be cached.
pub(super) const MAX_INPUT_LEN: usize =
    128 - size_of::<B256>() - size_of::<u8>() - size_of::<usize>();

const COUNT: usize = 1 << 17; // ~131k entries * 128 bytes = 16MiB
static CACHE: LazyLock<fixed_cache::Cache<Key, B256, BuildHasher, CacheConfig>> =
    LazyLock::new(|| {
        let metrics = CacheMetrics {
            hits: metrics::counter!("reth_keccak_cache_hits"),
            misses: metrics::counter!("reth_keccak_cache_misses"),
            inserts: metrics::counter!("reth_keccak_cache_inserts"),
            collisions: metrics::counter!("reth_keccak_cache_collisions"),
        };
        fixed_cache::static_cache!(Key, B256, COUNT, BuildHasher::new())
            .with_stats(Some(fixed_cache::Stats::new(metrics)))
    });

struct CacheConfig {}
impl fixed_cache::CacheConfig for CacheConfig {
    const STATS: bool = true;
    const EPOCHS: bool = false;
}

#[derive(Clone)]
struct CacheMetrics {
    hits: Counter,
    misses: Counter,
    inserts: Counter,
    collisions: Counter,
}

impl fixed_cache::StatsHandler<Key, B256> for CacheMetrics {
    fn on_hit(&self, _key: &Key, _value: &B256) {
        self.hits.increment(1);
    }

    fn on_miss(&self, _key: fixed_cache::AnyRef<'_>) {
        self.misses.increment(1);
    }

    fn on_insert(&self, key: &Key, _value: &B256, evicted: Option<(&Key, &B256)>) {
        self.inserts.increment(1);
        if evicted.is_some_and(|(old_key, _)| old_key != key) {
            self.collisions.increment(1);
        }
    }
}

pub(super) fn compute(input: &[u8], imp: impl FnOnce(&[u8]) -> B256) -> B256 {
    if unlikely(input.is_empty() | (input.len() > MAX_INPUT_LEN)) {
        return if input.is_empty() { KECCAK256_EMPTY } else { keccak256(input) };
    }

    CACHE.get_or_insert_with_ref(input, imp, |input| {
        let mut data = [MaybeUninit::uninit(); MAX_INPUT_LEN];
        unsafe {
            std::ptr::copy_nonoverlapping(input.as_ptr(), data.as_mut_ptr().cast(), input.len())
        };
        Key { len: input.len() as u8, data }
    })
}

type BuildHasher = std::hash::BuildHasherDefault<Hasher>;
#[derive(Default)]
struct Hasher(u64);

impl std::hash::Hasher for Hasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // This is tricky because our most common inputs are medium length: 16..=88
        // `foldhash` and `rapidhash` have a fast-path for ..16 bytes and outline the rest,
        // but really we want the opposite, or at least the 16.. path to be inlined.

        // SAFETY: `bytes.len()` is checked to be within the bounds of `MAX_INPUT_LEN` by caller.
        unsafe { core::hint::assert_unchecked(bytes.len() <= MAX_INPUT_LEN) };
        if bytes.len() <= 16 {
            super::hint::cold_path();
        }
        self.0 = rapidhash::v3::rapidhash_v3_micro_inline::<false, false>(
            bytes,
            const { &rapidhash::v3::RapidSecrets::seed(0) },
        );
    }

    // We can just skip hashing the length prefix entirely since we know it's always
    // `<=MAX_INPUT_LEN`, and the hash is good enough.

    // `write_length_prefix` calls `write_usize` by default.
    #[inline]
    fn write_usize(&mut self, i: usize) {
        debug_assert!(i <= MAX_INPUT_LEN, "{i} > {MAX_INPUT_LEN}")
    }

    #[cfg(feature = "nightly")]
    #[inline]
    fn write_length_prefix(&mut self, len: usize) {
        debug_assert!(len <= MAX_INPUT_LEN, "{len} > {MAX_INPUT_LEN}")
    }
}

#[derive(Clone, Copy)]
struct Key {
    len: u8,
    data: [MaybeUninit<u8>; MAX_INPUT_LEN],
}

impl PartialEq for Key {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}
impl Eq for Key {}

impl std::borrow::Borrow<[u8]> for Key {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.get()
    }
}

impl std::hash::Hash for Key {
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.get());
    }
}

impl Key {
    #[inline]
    const fn get(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr().cast(), self.len as usize) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size_of::<Key>(), MAX_INPUT_LEN + 1);
        assert_eq!(size_of::<fixed_cache::Bucket<(Key, B256)>>(), 128);
    }

    #[test]
    fn caching() {
        let mut count: usize = 0;
        let mut compute = |input| {
            compute(input, |x| {
                count += 1;
                keccak256(x)
            })
        };

        let input = b"Hello World!";
        let input2 = b"Hello World! 2";

        let a = compute(input);
        let b = compute(input);
        let c = compute(input);
        assert_eq!(a, b);
        assert_eq!(a, c);

        let d = compute(input2);
        let e = compute(input2);
        assert_ne!(a, d);
        assert_eq!(d, e);

        assert_eq!(count, 2);
    }
}
