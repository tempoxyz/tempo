use alloy_primitives::map::HashMap;
use std::{cell::RefCell, hash::Hash, marker::PhantomData, ptr::NonNull};

const CACHE_THRESHOLD: usize = 100;

#[derive(Debug)]
pub(crate) struct LinearCache<K, H> {
    // Singleton caches need no backing vector. Handler allocations remain stable
    // when the cache grows or promotes to a map.
    first: Option<(K, CachedHandler<H>)>,
    entries: Vec<(K, CachedHandler<H>)>,
}

impl<K, H> Default for LinearCache<K, H> {
    #[inline]
    fn default() -> Self {
        Self {
            first: None,
            entries: Vec::new(),
        }
    }
}

impl<K: Eq + Clone, H> LinearCache<K, H> {
    #[inline]
    fn len(&self) -> usize {
        usize::from(self.first.is_some()) + self.entries.len()
    }

    #[inline]
    fn find(&self, key: &K) -> Option<*const H> {
        self.first
            .iter()
            .chain(self.entries.iter())
            .find(|(candidate, _)| candidate == key)
            .map(|(_, boxed)| boxed.as_ptr().cast_const())
    }

    #[inline]
    fn find_mut(&mut self, key: &K) -> Option<*mut H> {
        self.first
            .iter_mut()
            .chain(self.entries.iter_mut())
            .find(|(candidate, _)| candidate == key)
            .map(|(_, boxed)| boxed.as_ptr())
    }

    #[inline]
    fn insert(&mut self, key: &K, f: impl FnOnce() -> H) -> *const H {
        self.insert_mut(key, f).cast_const()
    }

    #[inline]
    fn insert_mut(&mut self, key: &K, f: impl FnOnce() -> H) -> *mut H {
        let entry = (key.clone(), CachedHandler::new(f()));
        let boxed = if self.first.is_none() {
            &mut self.first.insert(entry).1
        } else {
            self.entries.push(entry);
            &mut self
                .entries
                .last_mut()
                .expect("just pushed handler cache entry")
                .1
        };
        boxed.as_ptr()
    }
}

#[derive(Debug)]
pub(crate) struct MapCache<K, H> {
    entries: HashMap<K, usize>,
    // Keep ownership append-only even if cloning or hashing a key panics.
    handlers: LinearCache<K, H>,
}

impl<K: Hash + Eq + Clone, H> MapCache<K, H> {
    #[inline]
    fn get_or_insert(&mut self, key: &K, f: impl FnOnce() -> H) -> *const H {
        self.get_or_insert_mut(key, f).cast_const()
    }

    #[inline]
    fn get_or_insert_mut(&mut self, key: &K, f: impl FnOnce() -> H) -> *mut H {
        let index = if let Some(index) = self.entries.get(key) {
            *index
        } else {
            let index = self.handlers.len();
            self.handlers.insert_mut(key, f);
            self.entries.insert(key.clone(), index);
            index
        };
        if index == 0 {
            self.handlers
                .first
                .as_ref()
                .expect("cached first handler")
                .1
                .as_ptr()
        } else {
            self.handlers.entries[index - 1].1.as_ptr()
        }
    }
}

#[derive(Debug)]
enum HandlerCacheState<K, H> {
    Linear(LinearCache<K, H>),
    // Keep the uncommon map state out of the common linear cache footprint.
    Mapped(Box<MapCache<K, H>>),
}

/// Hybrid linear/map cache for lazily computed handlers with stable references.
///
/// Enables `Index` implementations on handlers by storing child handlers and
/// returning references that remain valid across insertions.
///
/// Uses `RefCell` for interior mutability with runtime borrow checking.
/// Re-entrant access will panic rather than cause undefined behavior.
#[derive(Debug)]
pub(crate) struct HandlerCache<K, H, const THRESHOLD: usize = CACHE_THRESHOLD> {
    inner: RefCell<HandlerCacheState<K, H>>,
}

impl<K, H, const THRESHOLD: usize> HandlerCache<K, H, THRESHOLD> {
    /// Creates a new empty handler cache.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: RefCell::new(HandlerCacheState::Linear(LinearCache::default())),
        }
    }
}

impl<K, H, const THRESHOLD: usize> HandlerCache<K, H, THRESHOLD>
where
    K: Eq + Hash + Clone,
{
    #[inline]
    fn promote_to_map(linear: &mut LinearCache<K, H>) -> Box<MapCache<K, H>> {
        let mut entries = HashMap::default();
        entries.reserve(THRESHOLD * 2);
        for (index, (key, _)) in linear.first.iter().chain(linear.entries.iter()).enumerate() {
            entries.insert(key.clone(), index);
        }
        // Do all potentially panicking key operations before moving ownership.
        Box::new(MapCache {
            entries,
            handlers: std::mem::take(linear),
        })
    }

    /// Returns a reference to a lazily initialized handler for the given key.
    #[inline]
    pub(crate) fn get_or_insert(&self, key: &K, f: impl FnOnce() -> H) -> &H {
        let mut cache = self.inner.borrow_mut();
        let ptr = match &mut *cache {
            HandlerCacheState::Linear(linear) => {
                if let Some(ptr) = linear.find(key) {
                    ptr
                } else if linear.len() < THRESHOLD {
                    linear.insert(key, f)
                } else {
                    let map = Self::promote_to_map(linear);
                    *cache = HandlerCacheState::Mapped(map);
                    match &mut *cache {
                        HandlerCacheState::Mapped(map) => map.get_or_insert(key, f),
                        HandlerCacheState::Linear(_) => unreachable!("handler cache was promoted"),
                    }
                }
            }
            HandlerCacheState::Mapped(map) => map.get_or_insert(key, f),
        };
        // SAFETY: CachedHandler owns a stable allocation without retagging it on moves.
        // The cache is append-only, and the returned reference cannot outlive it.
        unsafe { &*ptr }
    }

    /// Returns a mutable reference to a lazily initialized handler for the given key.
    #[inline]
    pub(crate) fn get_or_insert_mut(&mut self, key: &K, f: impl FnOnce() -> H) -> &mut H {
        // `&mut self` already guarantees exclusive access, so skip the `RefCell` borrow tracking.
        let cache = self.inner.get_mut();
        let ptr = match cache {
            HandlerCacheState::Linear(linear) => {
                if let Some(ptr) = linear.find_mut(key) {
                    ptr
                } else if linear.len() < THRESHOLD {
                    linear.insert_mut(key, f)
                } else {
                    let map = Self::promote_to_map(linear);
                    *cache = HandlerCacheState::Mapped(map);
                    match cache {
                        HandlerCacheState::Mapped(map) => map.get_or_insert_mut(key, f),
                        HandlerCacheState::Linear(_) => unreachable!("handler cache was promoted"),
                    }
                }
            }
            HandlerCacheState::Mapped(map) => map.get_or_insert_mut(key, f),
        };
        // SAFETY: CachedHandler owns a stable allocation without retagging it on moves.
        // The cache is append-only, and the returned reference cannot outlive it.
        // `&mut self` ensures exclusive access.
        unsafe { &mut *ptr }
    }
}

impl<K, H, const THRESHOLD: usize> Clone for HandlerCache<K, H, THRESHOLD> {
    /// Creates a new empty cache (cached handlers are not cloned).
    fn clone(&self) -> Self {
        Self::new()
    }
}

/// Owns a handler allocation while allowing outstanding references across owner moves.
///
/// Moving a `Box<H>` can invalidate references to `H` under Rust's aliasing rules.
/// Keep the allocation as a raw pointer until the cache is dropped instead.
#[derive(Debug)]
struct CachedHandler<H> {
    ptr: NonNull<H>,
    ownership: PhantomData<Box<H>>,
}

impl<H> CachedHandler<H> {
    #[inline]
    fn new(handler: H) -> Self {
        Self {
            ptr: NonNull::from(Box::leak(Box::new(handler))),
            ownership: PhantomData,
        }
    }

    #[inline]
    fn as_ptr(&self) -> *mut H {
        self.ptr.as_ptr()
    }
}

impl<H> Drop for CachedHandler<H> {
    fn drop(&mut self) {
        // SAFETY: The pointer comes from exactly one leaked Box and this owner is
        // never cloned. Cache references cannot outlive the owning cache.
        unsafe { drop(Box::from_raw(self.ptr.as_ptr())) }
    }
}

// SAFETY: This is an owning allocation with the same Send/Sync requirements as Box<H>.
unsafe impl<H: Send> Send for CachedHandler<H> {}
// SAFETY: Shared ownership never grants mutable access to the allocation.
unsafe impl<H: Sync> Sync for CachedHandler<H> {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    #[test]
    fn handlers_remain_valid_across_growth_and_promotion() {
        let cache = HandlerCache::<usize, usize, 3>::new();
        let first = cache.get_or_insert(&0, || 42);
        let second = cache.get_or_insert(&1, || 43);
        for key in 2..200 {
            assert_eq!(*cache.get_or_insert(&key, || key + 42), key + 42);
            assert_eq!(*first, 42);
            assert_eq!(*second, 43);
        }
        assert!(std::ptr::eq(
            first,
            cache.get_or_insert(&0, || unreachable!())
        ));
        assert!(std::ptr::eq(
            second,
            cache.get_or_insert(&1, || unreachable!())
        ));
    }

    #[test]
    fn mutable_handlers_are_initialized_once_across_promotion() {
        let mut cache = HandlerCache::<usize, usize, 3>::new();
        let initialized = Cell::new(0);
        for round in 0..3 {
            for key in 0..200 {
                let value = cache.get_or_insert_mut(&key, || {
                    initialized.set(initialized.get() + 1);
                    key
                });
                assert_eq!(*value, key + round);
                *value += 1;
            }
        }
        assert_eq!(initialized.get(), 200);
    }

    #[test]
    fn handlers_are_dropped_once_after_promotion() {
        struct Counted(Rc<Cell<usize>>);

        impl Drop for Counted {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        let dropped = Rc::new(Cell::new(0));
        {
            let cache = HandlerCache::<usize, Counted, 3>::new();
            for key in 0..200 {
                cache.get_or_insert(&key, || Counted(dropped.clone()));
            }
            assert_eq!(dropped.get(), 0);
        }
        assert_eq!(dropped.get(), 200);
    }

    #[test]
    fn handlers_survive_a_panicking_key_hash_during_promotion() {
        #[derive(Clone, PartialEq, Eq)]
        struct Key(usize, Rc<Cell<bool>>);

        impl Hash for Key {
            fn hash<S: std::hash::Hasher>(&self, state: &mut S) {
                assert!(!self.1.get(), "injected hash panic");
                self.0.hash(state);
            }
        }

        let panic = Rc::new(Cell::new(false));
        let cache = HandlerCache::<Key, usize, 1>::new();
        let first = cache.get_or_insert(&Key(0, panic.clone()), || 42);
        panic.set(true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.get_or_insert(&Key(1, panic.clone()), || 43);
        }));
        assert!(result.is_err());
        assert_eq!(*first, 42);
        panic.set(false);
        assert_eq!(*cache.get_or_insert(&Key(1, panic.clone()), || 43), 43);
        assert_eq!(*first, 42);
    }
}
