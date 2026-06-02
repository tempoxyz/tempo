use crate::transaction::{
    multisig::{MultisigSignature, SIGNATURE_TYPE_MULTISIG},
    tt_signature::{PrimitiveSignature, TempoSignature},
};
use alloc::vec::Vec;
use alloy_primitives::Bytes;
use alloy_rlp::Decodable;

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
        let mut bytes = Vec::with_capacity(1 + self.encoded_length());
        match self {
            Self::Primitive(_) => bytes.push(0),
            Self::Keychain(_) => bytes.push(1),
            Self::Multisig(_) => bytes.push(2),
        }
        bytes.extend_from_slice(&self.to_bytes());
        let bytes = Bytes::from(bytes);
        bytes.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (bytes, rest) = Bytes::from_compact(buf, len);
        let signature = decode_tagged_tempo_signature(&bytes)
            .or_else(|| Self::from_bytes(&bytes).ok())
            .expect("Failed to decode TempoSignature from compact encoding");
        (signature, rest)
    }
}

fn decode_tagged_tempo_signature(bytes: &[u8]) -> Option<TempoSignature> {
    let (&tag, payload) = bytes.split_first()?;
    match tag {
        0 => PrimitiveSignature::from_bytes(payload)
            .ok()
            .map(TempoSignature::Primitive),
        1 => match TempoSignature::from_bytes(payload).ok()? {
            TempoSignature::Keychain(signature) => Some(TempoSignature::Keychain(signature)),
            _ => None,
        },
        2 => decode_multisig_payload(payload).map(TempoSignature::Multisig),
        _ => None,
    }
}

fn decode_multisig_payload(payload: &[u8]) -> Option<MultisigSignature> {
    if payload.first().copied()? != SIGNATURE_TYPE_MULTISIG {
        return None;
    }
    let mut rlp = &payload[1..];
    let signature = MultisigSignature::decode(&mut rlp).ok()?;
    rlp.is_empty().then_some(signature)
}
