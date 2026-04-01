use crate::transaction::envelope::TempoTxEnvelope;

impl reth_primitives_traits::InMemorySize for TempoTxEnvelope {
    fn size(&self) -> usize {
        match self {
            Self::Legacy(tx) => tx.size(),
            Self::Eip2930(tx) => tx.size(),
            Self::Eip1559(tx) => tx.size(),
            Self::Eip7702(tx) => tx.size(),
            Self::AA(tx) => tx.size(),
        }
    }
}

#[cfg(feature = "reth-codec")]
mod codec {
    use crate::{
        TempoSignature, TempoTransaction,
        transaction::{
            envelope::{TEMPO_SYSTEM_TX_SIGNATURE, TempoTxEnvelope, TempoTxType},
            tt_signed::AASigned,
        },
    };

    use alloy_consensus::{TxEip1559, TxEip2930, TxEip7702, TxLegacy};
    use alloy_eips::eip2718::EIP7702_TX_TYPE_ID;
    use alloy_primitives::{
        Bytes, Signature,
        bytes::{self, BufMut},
    };
    use reth_codecs::{
        Compact, DecompressError,
        alloy::transaction::{CompactEnvelope, Envelope},
        txtype::{
            COMPACT_EXTENDED_IDENTIFIER_FLAG, COMPACT_IDENTIFIER_EIP1559,
            COMPACT_IDENTIFIER_EIP2930, COMPACT_IDENTIFIER_LEGACY,
        },
    };

    impl reth_codecs::alloy::transaction::FromTxCompact for TempoTxEnvelope {
        type TxType = TempoTxType;

        fn from_tx_compact(
            buf: &[u8],
            tx_type: Self::TxType,
            signature: Signature,
        ) -> (Self, &[u8]) {
            use alloy_consensus::Signed;
            use reth_codecs::Compact;

            match tx_type {
                TempoTxType::Legacy => {
                    let (tx, buf) = TxLegacy::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Legacy(tx), buf)
                }
                TempoTxType::Eip2930 => {
                    let (tx, buf) = TxEip2930::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip2930(tx), buf)
                }
                TempoTxType::Eip1559 => {
                    let (tx, buf) = TxEip1559::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip1559(tx), buf)
                }
                TempoTxType::Eip7702 => {
                    let (tx, buf) = TxEip7702::from_compact(buf, buf.len());
                    let tx = Signed::new_unhashed(tx, signature);
                    (Self::Eip7702(tx), buf)
                }
                TempoTxType::AA => {
                    let (tx, buf) = TempoTransaction::from_compact(buf, buf.len());
                    // The provided `signature` is unused for AA transactions. The real
                    // `TempoSignature` was appended to the buffer in `to_tx_compact` and
                    // is decoded here instead.
                    let (sig_bytes, buf) = Bytes::from_compact(buf, buf.len());
                    let aa_sig = TempoSignature::from_bytes(&sig_bytes)
                        .map_err(|e| panic!("Failed to decode AA signature: {e}"))
                        .unwrap();
                    let tx = AASigned::new_unhashed(tx, aa_sig);
                    (Self::AA(tx), buf)
                }
            }
        }
    }

    impl reth_codecs::alloy::transaction::ToTxCompact for TempoTxEnvelope {
        fn to_tx_compact(&self, buf: &mut (impl BufMut + AsMut<[u8]>)) {
            match self {
                Self::Legacy(tx) => tx.tx().to_compact(buf),
                Self::Eip2930(tx) => tx.tx().to_compact(buf),
                Self::Eip1559(tx) => tx.tx().to_compact(buf),
                Self::Eip7702(tx) => tx.tx().to_compact(buf),
                Self::AA(tx) => {
                    let mut len = tx.tx().to_compact(buf);
                    len += tx.signature().to_bytes().to_compact(buf);
                    len
                }
            };
        }
    }

    impl Envelope for TempoTxEnvelope {
        fn signature(&self) -> &Signature {
            match self {
                Self::Legacy(tx) => tx.signature(),
                Self::Eip2930(tx) => tx.signature(),
                Self::Eip1559(tx) => tx.signature(),
                Self::Eip7702(tx) => tx.signature(),
                Self::AA(_tx) => {
                    // The `Envelope` trait requires `&Signature` (ECDSA), but AA transactions
                    // use `TempoSignature` which is a different type. We return a dummy zero
                    // signature here because `CompactEnvelope::to_compact` calls this to
                    // serialize a signature into the buffer. The actual `TempoSignature` is
                    // encoded separately in `ToTxCompact::to_tx_compact` and decoded back in
                    // `FromTxCompact::from_tx_compact`, where the dummy signature passed in
                    // is ignored for the AA variant.
                    &TEMPO_SYSTEM_TX_SIGNATURE
                }
            }
        }

        fn tx_type(&self) -> Self::TxType {
            Self::tx_type(self)
        }
    }

    impl Compact for TempoTxType {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: BufMut + AsMut<[u8]>,
        {
            match self {
                Self::Legacy => COMPACT_IDENTIFIER_LEGACY,
                Self::Eip2930 => COMPACT_IDENTIFIER_EIP2930,
                Self::Eip1559 => COMPACT_IDENTIFIER_EIP1559,
                Self::Eip7702 => {
                    buf.put_u8(EIP7702_TX_TYPE_ID);
                    COMPACT_EXTENDED_IDENTIFIER_FLAG
                }
                Self::AA => {
                    buf.put_u8(crate::transaction::TEMPO_TX_TYPE_ID);
                    COMPACT_EXTENDED_IDENTIFIER_FLAG
                }
            }
        }

        fn from_compact(mut buf: &[u8], identifier: usize) -> (Self, &[u8]) {
            use bytes::Buf;
            (
                match identifier {
                    COMPACT_IDENTIFIER_LEGACY => Self::Legacy,
                    COMPACT_IDENTIFIER_EIP2930 => Self::Eip2930,
                    COMPACT_IDENTIFIER_EIP1559 => Self::Eip1559,
                    COMPACT_EXTENDED_IDENTIFIER_FLAG => {
                        let extended_identifier = buf.get_u8();
                        match extended_identifier {
                            EIP7702_TX_TYPE_ID => Self::Eip7702,
                            crate::transaction::TEMPO_TX_TYPE_ID => Self::AA,
                            _ => panic!("Unsupported TxType identifier: {extended_identifier}"),
                        }
                    }
                    _ => panic!("Unknown identifier for TxType: {identifier}"),
                },
                buf,
            )
        }
    }

    impl Compact for TempoTxEnvelope {
        fn to_compact<B>(&self, buf: &mut B) -> usize
        where
            B: BufMut + AsMut<[u8]>,
        {
            CompactEnvelope::to_compact(self, buf)
        }

        fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
            CompactEnvelope::from_compact(buf, len)
        }
    }

    impl reth_db_api::table::Compress for TempoTxEnvelope {
        type Compressed = alloc::vec::Vec<u8>;

        fn compress_to_buf<B: alloy_primitives::bytes::BufMut + AsMut<[u8]>>(&self, buf: &mut B) {
            let _ = Compact::to_compact(self, buf);
        }
    }

    impl reth_db_api::table::Decompress for TempoTxEnvelope {
        fn decompress(value: &[u8]) -> Result<Self, DecompressError> {
            let (obj, _) = Compact::from_compact(value, value.len());
            Ok(obj)
        }
    }
}
