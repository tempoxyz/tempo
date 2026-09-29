use crate::transaction::tt_signature::{PrimitiveSignature, TempoSignature};
use alloy_primitives::Bytes;

impl reth_codecs::Compact for PrimitiveSignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        self.encode_bytes_into(buf);
        self.encoded_length()
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = Self::from_bytes(&bytes)
            .expect("Failed to decode PrimitiveSignature from compact encoding");
        (signature, rest)
    }
}

impl reth_codecs::Compact for TempoSignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        self.encode_bytes_into(buf);
        self.encoded_length()
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = Self::from_bytes(&bytes)
            .expect("Failed to decode TempoSignature from compact encoding");
        (signature, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use reth_codecs::Compact;

    fn assert_compact_encoding<T: Compact + PartialEq + core::fmt::Debug>(
        signature: &T,
        bytes: &Bytes,
    ) {
        let prefix = [0xaa, 0xbb];
        let suffix = [0xcc, 0xdd];
        let mut expected = prefix.to_vec();
        let expected_len = bytes.to_compact(&mut expected);
        let mut encoded = prefix.to_vec();
        let len = signature.to_compact(&mut encoded);
        assert_eq!(len, expected_len);
        assert_eq!(len, bytes.len());
        assert_eq!(encoded, expected);

        encoded.extend_from_slice(&suffix);
        let (decoded, rest) = T::from_compact(&encoded[prefix.len()..], len);
        assert_eq!(&decoded, signature);
        assert_eq!(rest, suffix);
    }

    proptest! {
        #[test]
        fn proptest_primitive_signature_compact_encoding(signature in arb::<PrimitiveSignature>()) {
            assert_compact_encoding(&signature, &signature.to_bytes());
        }

        #[test]
        fn proptest_tempo_signature_compact_encoding(signature in arb::<TempoSignature>()) {
            assert_compact_encoding(&signature, &signature.to_bytes());
        }
    }
}
