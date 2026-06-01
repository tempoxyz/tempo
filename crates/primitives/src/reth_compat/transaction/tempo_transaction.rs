use crate::TempoTransaction;

#[cfg(feature = "reth-codec")]
impl reth_codecs::Compact for crate::transaction::InitMultisig {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        use alloy_rlp::Encodable;
        self.encode(buf);
        self.length()
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        let item = alloy_rlp::Decodable::decode(&mut buf)
            .expect("Failed to decode InitMultisig from compact");
        (item, buf)
    }
}

impl reth_primitives_traits::InMemorySize for TempoTransaction {
    fn size(&self) -> usize {
        Self::size(self)
    }
}
