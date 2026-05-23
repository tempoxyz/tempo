use crate::Bytes;
use rkyv::{
    Archive, Deserialize, Place, Serialize,
    bytecheck::CheckBytes,
    rancor::{Fallible, Source, Trace},
    ser::{Allocator, Writer},
    validation::ArchiveContext,
    vec::{ArchivedVec, VecResolver},
};

impl Archive for Bytes {
    type Archived = ArchivedVec<u8>;
    type Resolver = VecResolver;

    #[inline]
    fn resolve(&self, resolver: Self::Resolver, out: Place<Self::Archived>) {
        ArchivedVec::resolve_from_slice(self.as_ref(), resolver, out);
    }
}

impl<S: Fallible + Allocator + Writer + ?Sized> Serialize<S> for Bytes {
    #[inline]
    fn serialize(&self, serializer: &mut S) -> Result<Self::Resolver, S::Error> {
        ArchivedVec::serialize_from_slice(self, serializer)
    }
}

impl<D: Fallible + ?Sized> Deserialize<Bytes, D> for ArchivedVec<u8> {
    #[inline]
    fn deserialize(&self, _deserializer: &mut D) -> Result<Bytes, D::Error> {
        Ok(Bytes::copy_from_slice(self.as_slice()))
    }
}

unsafe impl<C: Fallible + ArchiveContext + Sized> CheckBytes<C> for Bytes
where
    <C as Fallible>::Error: Source + Trace,
{
    unsafe fn check_bytes(value: *const Self, context: &mut C) -> Result<(), C::Error> {
        unsafe { ArchivedVec::<u8>::check_bytes(value as *const ArchivedVec<u8>, context) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rkyv::{Archived, rancor};

    #[test]
    fn rkyv_roundtrip() {
        let bytes = Bytes::from_static(&[1, 35, 69, 103, 137, 171, 205, 239]);
        let ser = rkyv::to_bytes::<rancor::BoxedError>(&bytes).unwrap();
        let archived = rkyv::access::<Archived<Bytes>, rancor::BoxedError>(&ser).unwrap();

        assert_eq!(bytes.as_ref(), archived.as_slice());

        let des = rkyv::deserialize::<Bytes, rancor::BoxedError>(archived).unwrap();
        assert_eq!(bytes, des);
    }
}
