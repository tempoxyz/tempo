//! Signed TIP-1120 funding requirements. Execution admission is gated separately.

use alloc::vec::Vec;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rlp::{Buf, Decodable, Encodable};

#[derive(
    Clone, Debug, Default, PartialEq, Eq, Hash, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct FundingSource {
    /// Contract or precompile implementing IFundingSource.
    pub address: Address,
    /// Signed source arguments, including any input cap.
    pub data: Bytes,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[cfg_attr(feature = "reth-codec", derive(reth_codecs::Compact))]
#[cfg_attr(any(test, feature = "arbitrary"), derive(arbitrary::Arbitrary))]
pub struct FundingRequirement {
    /// Requested TIP-20 token.
    pub token: Address,
    /// Target balance in token base units.
    pub amount: U256,
    /// Sources attempted in signed order.
    pub sources: Vec<FundingSource>,
    /// Aggregate tolerance; omission inherits the policy or defaults to zero for owners.
    #[cfg_attr(
        feature = "serde",
        serde(
            default,
            skip_serializing_if = "Option::is_none",
            with = "alloy_serde::quantity::opt"
        )
    )]
    pub slippage_bps: Option<u64>,
}

impl FundingRequirement {
    pub fn size(&self) -> usize {
        size_of::<Self>()
            + self
                .sources
                .iter()
                .map(|source| size_of::<FundingSource>() + source.data.len())
                .sum::<usize>()
    }
}

impl Encodable for FundingRequirement {
    fn encode(&self, out: &mut dyn alloy_rlp::BufMut) {
        let tolerance = self.slippage_bps.as_slice();
        let payload_length = self.token.length()
            + self.amount.length()
            + self.sources.length()
            + alloy_rlp::list_length::<u64, u64>(tolerance);
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .encode(out);
        self.token.encode(out);
        self.amount.encode(out);
        self.sources.encode(out);
        alloy_rlp::encode_list::<u64, u64>(tolerance, out);
    }

    fn length(&self) -> usize {
        let payload_length = self.token.length()
            + self.amount.length()
            + self.sources.length()
            + alloy_rlp::list_length::<u64, u64>(self.slippage_bps.as_slice());
        alloy_rlp::Header {
            list: true,
            payload_length,
        }
        .length_with_payload()
    }
}

impl Decodable for FundingRequirement {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let header = alloy_rlp::Header::decode(buf)?;
        if !header.list {
            return Err(alloy_rlp::Error::UnexpectedString);
        }
        if buf.len() < header.payload_length {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        let mut payload = &buf[..header.payload_length];
        let token = Address::decode(&mut payload)?;
        let amount = U256::decode(&mut payload)?;
        let sources = Vec::<FundingSource>::decode(&mut payload)?;
        // A zero-or-one-element list preserves the distinction between omission and explicit zero.
        let tolerance = Vec::<u64>::decode(&mut payload)?;
        if !payload.is_empty() || tolerance.len() > 1 {
            return Err(alloy_rlp::Error::UnexpectedLength);
        }
        let slippage_bps = tolerance.first().copied();
        if slippage_bps.is_some_and(|bps| bps > 10_000) {
            return Err(alloy_rlp::Error::Custom(
                "funding slippage exceeds 10000 basis points",
            ));
        }
        buf.advance(header.payload_length);
        Ok(Self {
            token,
            amount,
            sources,
            slippage_bps,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{
        AASigned, Call, KeyAuthorization, PrimitiveSignature, TempoSignature, TempoTransaction,
    };
    use alloy_primitives::{Signature, TxKind, hex};

    fn requirement() -> FundingRequirement {
        FundingRequirement {
            token: Address::repeat_byte(1),
            amount: U256::from(50),
            sources: vec![FundingSource {
                address: Address::repeat_byte(2),
                data: Bytes::from_static(&[0xab]),
            }],
            slippage_bps: Some(100),
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn requirement_json_uses_token_without_changing_signed_bytes() {
        let value = requirement();
        let mut json = serde_json::to_value(&value).unwrap();
        assert_eq!(json["token"], serde_json::to_value(value.token).unwrap());
        assert!(json.get("asset").is_none());
        let decoded: FundingRequirement = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(alloy_rlp::encode(&decoded), alloy_rlp::encode(&value));
        let token = json.as_object_mut().unwrap().remove("token").unwrap();
        json["asset"] = token;
        assert!(serde_json::from_value::<FundingRequirement>(json).is_err());
    }

    fn transaction() -> TempoTransaction {
        TempoTransaction {
            calls: vec![Call {
                to: TxKind::Call(Address::ZERO),
                value: U256::ZERO,
                input: Bytes::new(),
            }],
            require_funds: Some(vec![requirement()]),
            ..Default::default()
        }
    }

    fn signature() -> TempoSignature {
        TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()))
    }

    #[test]
    fn funding_requirement_golden() {
        let entry = requirement();
        let expected = hex!(
            "f194010101010101010101010101010101010101010132d8d794020202020202020202020202020202020202020281abc164"
        );
        let encoded = alloy_rlp::encode(&entry);
        assert_eq!(encoded, expected);
        assert_eq!(entry.length(), expected.len());
        assert_eq!(
            FundingRequirement::decode(&mut expected.as_slice()).unwrap(),
            entry
        );
    }

    #[test]
    fn funding_slippage_optional_zero_and_limits() {
        for tolerance in [None, Some(0), Some(1), Some(10_000)] {
            let entry = FundingRequirement {
                slippage_bps: tolerance,
                ..requirement()
            };
            let bytes = alloy_rlp::encode(&entry);
            assert_eq!(
                FundingRequirement::decode(&mut bytes.as_slice()).unwrap(),
                entry
            );
            for end in 0..bytes.len() {
                assert!(FundingRequirement::decode(&mut &bytes[..end]).is_err());
            }
        }
        let invalid = FundingRequirement {
            slippage_bps: Some(10_001),
            ..requirement()
        };
        assert!(FundingRequirement::decode(&mut alloy_rlp::encode(invalid).as_slice()).is_err());
        let mut entry = alloy_rlp::encode(requirement());
        // Replace the single tolerance with two elements and adjust both list lengths.
        entry[0] += 1;
        let end = entry.len();
        entry[end - 2] = 0xc2;
        entry.push(1);
        assert!(FundingRequirement::decode(&mut entry.as_slice()).is_err());
    }

    #[test]
    fn funding_signed_roundtrip_with_optional_key_authorization() {
        for key_authorization in [
            None,
            Some(
                KeyAuthorization::unrestricted(1, crate::SignatureType::Secp256k1, Address::ZERO)
                    .into_signed(PrimitiveSignature::Secp256k1(Signature::test_signature())),
            ),
        ] {
            let tx = TempoTransaction {
                key_authorization,
                ..transaction()
            };
            let bytes = alloy_rlp::encode(&tx);
            assert_eq!(bytes.len(), tx.length());
            assert_eq!(TempoTransaction::decode(&mut bytes.as_slice()).unwrap(), tx);
            let signed = AASigned::new_unhashed(tx.clone(), signature());
            let mut bytes = vec![];
            signed.rlp_encode(&mut bytes);
            let decoded = AASigned::rlp_decode(&mut bytes.as_slice()).unwrap();
            assert_eq!(decoded.tx(), &tx);
            assert_eq!(decoded.hash(), signed.hash());
            let mut sponsored = vec![];
            signed.encode_for_fee_payer_service(&mut sponsored);
            // The service encoding retains funding while replacing only the sponsor fields.
            let mut payload = alloy_rlp::Header::decode_bytes(&mut &sponsored[1..], true).unwrap();
            for _ in 0..11 {
                alloy_rlp::Header::decode_raw(&mut payload).unwrap();
            }
            assert_eq!(
                alloy_rlp::Header::decode_bytes(&mut payload, false).unwrap(),
                &[0]
            );
            alloy_rlp::Header::decode_raw(&mut payload).unwrap(); // Authorization list.
            alloy_rlp::Header::decode_raw(&mut payload).unwrap(); // Key authorization or placeholder.
            assert_eq!(
                Vec::<FundingRequirement>::decode(&mut payload).unwrap(),
                tx.require_funds.unwrap()
            );
            assert_eq!(
                Bytes::decode(&mut payload).unwrap(),
                signed.signature().to_bytes()
            );
            assert!(payload.is_empty());
        }
    }

    #[test]
    fn funding_transaction_golden() {
        // Four zero scalars, one zero-address call, empty access list, six absent scalars, empty authorization list.
        let legacy =
            hex!("e580808080d8d79400000000000000000000000000000000000000008080c0808080808080c0");
        let tx = TempoTransaction {
            require_funds: None,
            ..transaction()
        };
        assert_eq!(alloy_rlp::encode(&tx), legacy);
        let expected = hex!(
            "f85980808080d8d79400000000000000000000000000000000000000008080c0808080808080c080f2f194010101010101010101010101010101010101010132d8d794020202020202020202020202020202020202020281abc164"
        );
        assert_eq!(alloy_rlp::encode(transaction()), expected);
    }

    #[test]
    fn funding_empty_preserves_legacy_encoding_and_hashes() {
        let legacy = TempoTransaction {
            require_funds: None,
            ..transaction()
        };
        let empty = TempoTransaction {
            require_funds: Some(vec![]),
            ..legacy.clone()
        };
        assert_eq!(alloy_rlp::encode(&legacy), alloy_rlp::encode(&empty));
        assert_eq!(legacy.signature_hash(), empty.signature_hash());
        assert_eq!(
            legacy.fee_payer_signature_hash(Address::ZERO),
            empty.fee_payer_signature_hash(Address::ZERO)
        );
        assert_eq!(
            TempoTransaction::decode(&mut alloy_rlp::encode(empty).as_slice()).unwrap(),
            legacy
        );
    }

    #[test]
    fn funding_fields_are_committed_by_all_hashes() {
        let mut tx = transaction();
        tx.require_funds.as_mut().unwrap()[0]
            .sources
            .push(FundingSource {
                address: Address::repeat_byte(3),
                data: Bytes::new(),
            });
        tx.require_funds.as_mut().unwrap().push(FundingRequirement {
            token: Address::repeat_byte(4),
            ..requirement()
        });
        let signed = AASigned::new_unhashed(tx.clone(), signature());
        let mutations: &[fn(&mut Vec<FundingRequirement>)] = &[
            |v| v[0].token = Address::ZERO,
            |v| v[0].amount += U256::from(1),
            |v| v[0].sources[0].address = Address::ZERO,
            |v| v[0].sources[0].data = Bytes::from_static(&[0xcd]),
            |v| v[0].sources.swap(0, 1),
            |v| v.swap(0, 1),
            |v| v[0].slippage_bps = None,
            |v| v[0].slippage_bps = Some(0),
            |v| v[0].slippage_bps = Some(101),
        ];
        for mutate in mutations {
            let mut changed = tx.clone();
            mutate(changed.require_funds.as_mut().unwrap());
            assert_ne!(changed.signature_hash(), tx.signature_hash());
            assert_ne!(
                changed.fee_payer_signature_hash(Address::ZERO),
                tx.fee_payer_signature_hash(Address::ZERO)
            );
            let changed = AASigned::new_unhashed(changed, signature());
            assert_ne!(changed.hash(), signed.hash());
            assert_ne!(
                changed.expiring_nonce_hash(Address::ZERO),
                signed.expiring_nonce_hash(Address::ZERO)
            );
        }
    }

    #[test]
    fn funding_sponsored_signature_roundtrip() {
        use alloy_consensus::transaction::SignerRecoverable;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        let sender =
            PrivateKeySigner::from_bytes(&alloy_primitives::B256::with_last_byte(1)).unwrap();
        let sponsor =
            PrivateKeySigner::from_bytes(&alloy_primitives::B256::with_last_byte(2)).unwrap();
        let mut tx = transaction();
        tx.fee_payer_signature =
            Some(crate::transaction::tempo_transaction::FEE_PAYER_SIGNATURE_MARKER);
        let sender_signature = sender.sign_hash_sync(&tx.signature_hash()).unwrap();
        tx.fee_payer_signature = Some(
            sponsor
                .sign_hash_sync(&tx.fee_payer_signature_hash(sender.address()))
                .unwrap(),
        );
        let signed = AASigned::new_unhashed(
            tx,
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(sender_signature)),
        );
        let mut encoded = vec![];
        signed.rlp_encode(&mut encoded);
        let decoded = AASigned::rlp_decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.recover_signer().unwrap(), sender.address());
        assert_eq!(
            decoded.tx().recover_fee_payer(sender.address()).unwrap(),
            sponsor.address()
        );
    }

    #[test]
    fn funding_extension_rejects_noncanonical_empty_and_missing_list() {
        let tx = TempoTransaction {
            require_funds: None,
            ..transaction()
        };
        let mut fields = vec![];
        tx.rlp_encode_fields_default(&mut fields);
        for suffix in [&[0x80][..], &[0x80, 0xc0], &[0x80, 0x80]] {
            let mut payload = fields.clone();
            payload.extend_from_slice(suffix);
            let mut encoded = vec![];
            alloy_rlp::Header {
                list: true,
                payload_length: payload.len(),
            }
            .encode(&mut encoded);
            encoded.extend(payload);
            assert!(TempoTransaction::decode(&mut encoded.as_slice()).is_err());
        }
    }

    #[cfg(feature = "reth-codec")]
    #[test]
    fn funding_compact_roundtrip() {
        use reth_codecs::Compact;
        let tx = transaction();
        let mut bytes = vec![];
        let len = tx.to_compact(&mut bytes);
        let (decoded, rest) = TempoTransaction::from_compact(&bytes, len);
        assert!(rest.is_empty());
        assert_eq!(decoded, tx);
    }
}
