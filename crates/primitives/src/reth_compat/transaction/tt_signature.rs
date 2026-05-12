use crate::transaction::tt_signature::{PrimitiveSignature, TempoSignature};
use alloy_primitives::Bytes;

impl reth_codecs::Compact for PrimitiveSignature {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        let bytes = self.to_bytes();
        bytes.to_compact(buf)
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
        let bytes = self.to_bytes();
        bytes.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = Self::from_bytes(&bytes)
            .expect("Failed to decode TempoSignature from compact encoding");
        (signature, rest)
    }
}
