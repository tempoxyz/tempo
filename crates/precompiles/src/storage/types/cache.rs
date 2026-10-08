use alloy_primitives::map::HashMap;
use std::{cell::RefCell, hash::Hash};

const CACHE_THRESHOLD: usize = 100;

#[derive(Debug)]
pub(crate) struct LinearCache<K, H> {
    // Singleton caches need no backing vector. Keep handlers boxed so their addresses
    // remain stable when the cache grows or promotes to a map.
    first: Option<(K, Box<H>)>,
    entries: Vec<(K, Box<H>)>,
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
            .map(|(_, boxed)| boxed.as_ref() as *const H)
    }

    #[inline]
    fn find_mut(&mut self, key: &K) -> Option<*mut H> {
        self.first
            .iter_mut()
            .chain(self.entries.iter_mut())
            .find(|(candidate, _)| candidate == key)
            .map(|(_, boxed)| boxed.as_mut() as *mut H)
    }

    #[inline]
    fn insert(&mut self, key: &K, f: impl FnOnce() -> H) -> *const H {
        self.insert_mut(key, f).cast_const()
    }

    #[inline]
    fn insert_mut(&mut self, key: &K, f: impl FnOnce() -> H) -> *mut H {
        let entry = (key.clone(), Box::new(f()));
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
        boxed.as_mut() as *mut H
    }

    #[inline]
    fn drain_into_map(&mut self, map: &mut MapCache<K, H>)
    where
        K: Hash,
    {
        if let Some((key, value)) = self.first.take() {
            map.insert_boxed(key, value);
        }
        for (key, value) in self.entries.drain(..) {
            map.insert_boxed(key, value);
        }
    }
}

#[derive(Debug)]
pub(crate) struct MapCache<K, H> {
    entries: HashMap<K, Box<H>>,
}

impl<K, H> Default for MapCache<K, H> {
    #[inline]
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<K: Hash + Eq + Clone, H> MapCache<K, H> {
    #[inline]
    fn reserve(&mut self, additional: usize) {
        self.entries.reserve(additional);
    }

    #[inline]
    fn insert_boxed(&mut self, key: K, value: Box<H>) {
        self.entries.insert(key, value);
    }

    #[inline]
    fn get_or_insert(&mut self, key: &K, f: impl FnOnce() -> H) -> *const H {
        if let Some(boxed) = self.entries.get(key) {
            boxed.as_ref() as *const H
        } else {
            self.entries
                .entry(key.clone())
                .or_insert_with(|| Box::new(f()))
                .as_ref() as *const H
        }
    }

    #[inline]
    fn get_or_insert_mut(&mut self, key: &K, f: impl FnOnce() -> H) -> *mut H {
        if let Some(boxed) = self.entries.get_mut(key) {
            boxed.as_mut() as *mut H
        } else {
            self.entries
                .entry(key.clone())
                .or_insert_with(|| Box::new(f()))
                .as_mut() as *mut H
        }
    }
}

#[derive(Debug)]
enum HandlerCacheState<K, H> {
    Linear(LinearCache<K, H>),
    Mapped(MapCache<K, H>),
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
    fn promote_to_map(linear: &mut LinearCache<K, H>) -> MapCache<K, H> {
        let mut map = MapCache::default();
        map.reserve(THRESHOLD * 2);
        linear.drain_into_map(&mut map);
        map
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
        // SAFETY: Box provides stable heap address. Cache is append-only.
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
        // SAFETY: Box provides stable heap address. Cache is append-only. `&mut self` ensures exclusive access.
        unsafe { &mut *ptr }
    }
}

impl<K, H, const THRESHOLD: usize> Clone for HandlerCache<K, H, THRESHOLD> {
    /// Creates a new empty cache (cached handlers are not cloned).
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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
}
