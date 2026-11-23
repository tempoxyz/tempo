use crate::transaction::tt_authorization::TempoSignedAuthorization;
use alloy_rlp::{Decodable, Encodable};

impl reth_codecs::Compact for TempoSignedAuthorization {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: alloy_rlp::BufMut + AsMut<[u8]>,
    {
        let start_len = buf.remaining_mut();
        self.encode(buf);
        start_len - buf.remaining_mut()
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let mut buf_slice = &buf[..len];
        let auth = Self::decode(&mut buf_slice).expect("valid RLP encoding");
        (auth, &buf[len..])
    }
}
