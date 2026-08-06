impl reth_primitives_traits::InMemorySize for crate::ed25519::PublicKey {
    fn size(&self) -> usize {
        alloy_primitives::B256::len_bytes()
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use reth_primitives_traits::InMemorySize as _;

    use crate::ed25519::PublicKey;

    #[test]
    fn public_key_size_matches_b256() {
        let key = PublicKey::from_seed(42);

        assert_eq!(key.size(), B256::len_bytes());
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
