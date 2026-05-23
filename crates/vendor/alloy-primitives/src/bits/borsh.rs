use super::FixedBytes;
use borsh::{
    BorshDeserialize, BorshSerialize,
    io::{Error, Read, Write},
};

#[cfg_attr(docsrs, doc(cfg(feature = "borsh")))]
impl<const N: usize> BorshSerialize for FixedBytes<N> {
    #[inline]
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        writer.write_all(self.as_slice())
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "borsh")))]
impl<const N: usize> BorshDeserialize for FixedBytes<N> {
    #[inline]
    fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(Self(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn roundtrip_fixedbytes() {
        let v = FixedBytes::<4>::new([1, 2, 3, 4]);
        let mut out = Vec::new();
        BorshSerialize::serialize(&v, &mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4]);

        let mut slice = out.as_slice();
        let de = <FixedBytes<4> as BorshDeserialize>::deserialize_reader(&mut slice).unwrap();
        assert_eq!(de, v);
    }
}
