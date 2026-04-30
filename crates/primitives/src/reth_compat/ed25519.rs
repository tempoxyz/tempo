use alloy_rlp::Encodable;

use crate::ed25519::PublicKey;

impl reth_primitives_traits::InMemorySize for PublicKey {
    fn size(&self) -> usize {
        self.length()
    }
}

#[cfg(feature = "reth-codec")]
mod codec {
    use crate::ed25519::PublicKey;
    use alloy_primitives::B256;
    use reth_codecs::Compact;

    impl Compact for PublicKey {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: alloy_rlp::bytes::BufMut + AsMut<[u8]>,
        {
            B256::from(self).to_compact(buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            let (bytes, buf) = B256::from_compact(buf, len);
            (
                bytes.try_into().expect("well formed ed25519 public key"),
                buf,
            )
        }
    }
}
