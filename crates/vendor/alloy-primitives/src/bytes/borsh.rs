use super::Bytes;
use alloc::vec::Vec;
use borsh::{
    BorshDeserialize, BorshSerialize,
    io::{Error, Read, Write},
};

#[cfg_attr(docsrs, doc(cfg(feature = "borsh")))]
impl BorshSerialize for Bytes {
    #[inline]
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        // Use the same approach as Vec<u8>: write length first, then data
        let bytes = self.as_ref();
        bytes.serialize(writer)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "borsh")))]
impl BorshDeserialize for Bytes {
    #[inline]
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        // Deserialize as Vec<u8> first, then convert to Bytes
        let vec = Vec::<u8>::deserialize_reader(reader)?;
        Ok(Self::from(vec))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes() {
        let original_data = vec![1, 2, 3, 4, 5];
        let bytes = Bytes::from(original_data.clone());

        let mut serialized = Vec::new();
        BorshSerialize::serialize(&bytes, &mut serialized).unwrap();

        let mut slice = serialized.as_slice();
        let deserialized = Bytes::deserialize_reader(&mut slice).unwrap();

        assert_eq!(deserialized.as_ref(), original_data.as_slice());
        assert_eq!(deserialized, bytes);
    }

    #[test]
    fn roundtrip_empty_bytes() {
        let bytes = Bytes::new();

        let mut serialized = Vec::new();
        BorshSerialize::serialize(&bytes, &mut serialized).unwrap();

        let mut slice = serialized.as_slice();
        let deserialized = Bytes::deserialize_reader(&mut slice).unwrap();

        assert_eq!(deserialized, bytes);
        assert!(deserialized.is_empty());
    }

    #[test]
    fn borsh_consistency_with_vec() {
        let data = vec![10, 20, 30, 40];
        let bytes = Bytes::from(data.clone());

        let mut bytes_serialized = Vec::new();
        let mut vec_serialized = Vec::new();

        BorshSerialize::serialize(&bytes, &mut bytes_serialized).unwrap();
        BorshSerialize::serialize(&data, &mut vec_serialized).unwrap();

        // Should produce identical serialization since we delegate to Vec<u8>
        assert_eq!(bytes_serialized, vec_serialized);
    }
}
