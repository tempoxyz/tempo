use super::*;
use core::{
    fmt::{Debug, Formatter},
    hash::Hash,
};

impl From<ArchivedAddress> for Address {
    fn from(archived: ArchivedAddress) -> Self {
        Self::from(archived.0.0)
    }
}

impl Debug for ArchivedAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&Address::from(self.0.0), f)
    }
}

impl From<ArchivedBloom> for Bloom {
    fn from(archived: ArchivedBloom) -> Self {
        Self::from(archived.0.0)
    }
}

impl Debug for ArchivedBloom {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&Bloom::from(self.0.0), f)
    }
}

impl<const N: usize> From<ArchivedFixedBytes<N>> for FixedBytes<N> {
    fn from(archived: ArchivedFixedBytes<N>) -> Self {
        Self(archived.0)
    }
}

impl<const N: usize> Debug for ArchivedFixedBytes<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Debug::fmt(&FixedBytes(self.0), f)
    }
}

impl<const N: usize> Copy for ArchivedFixedBytes<N> {}

impl<const N: usize> Clone for ArchivedFixedBytes<N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<const N: usize> PartialEq for ArchivedFixedBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const N: usize> Eq for ArchivedFixedBytes<N> {}

impl<const N: usize> Hash for ArchivedFixedBytes<N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::rkyv::rancor;

    #[test]
    fn rkyv_roundtrip() {
        let bytes = FixedBytes([0, 0, 0, 0, 1, 35, 69, 103, 137, 171, 205, 239]);
        let ser = ::rkyv::to_bytes::<rancor::BoxedError>(&bytes).unwrap();
        let archived = ::rkyv::access::<ArchivedFixedBytes<12>, rancor::BoxedError>(&ser).unwrap();

        assert_eq!(bytes, FixedBytes::from(*archived));

        let des = ::rkyv::deserialize::<_, rancor::BoxedError>(archived).unwrap();
        assert_eq!(bytes, des);
    }
}
