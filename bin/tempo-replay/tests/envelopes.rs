use alloy::{
    consensus::{
        SignableTransaction, TxEip1559, TxEip2930, TxEip7702, TxLegacy,
        transaction::SignerRecoverable,
    },
    eips::eip2718::{Decodable2718, Encodable2718},
    primitives::{Address, B256, Bytes, Signature, TxKind},
};
use tempo_primitives::{TempoSignature, TempoTransaction, TempoTxEnvelope, transaction::Call};

fn sign(hash: B256, key: u8) -> Signature {
    let key = k256::ecdsa::SigningKey::from_slice(&[key; 32]).unwrap();
    let (signature, recovery) = key.sign_prehash_recoverable(hash.as_slice()).unwrap();
    Signature::from_signature_and_parity(signature, recovery.is_y_odd())
}

fn envelopes() -> Vec<(&'static str, TempoTxEnvelope, B256)> {
    let legacy = TxLegacy {
        chain_id: Some(4217),
        nonce: 1,
        ..Default::default()
    };
    let eip2930 = TxEip2930 {
        chain_id: 4217,
        nonce: 2,
        ..Default::default()
    };
    let eip1559 = TxEip1559 {
        chain_id: 4217,
        nonce: 3,
        ..Default::default()
    };
    let eip7702 = TxEip7702 {
        chain_id: 4217,
        nonce: 4,
        ..Default::default()
    };
    let aa = TempoTransaction {
        chain_id: 4217,
        nonce: 5,
        calls: vec![Call {
            to: TxKind::Call(Address::repeat_byte(7)),
            value: Default::default(),
            input: Bytes::from_static(&[1, 2, 3]),
        }],
        ..Default::default()
    };

    vec![
        (
            "legacy",
            TempoTxEnvelope::Legacy(legacy.clone().into_signed(sign(legacy.signature_hash(), 1))),
            alloy::primitives::b256!(
                "50a95d2acb8c84492df3dae9da6030186eb6853c26f105785e2952504f61afa6"
            ),
        ),
        (
            "eip2930",
            TempoTxEnvelope::Eip2930(
                eip2930
                    .clone()
                    .into_signed(sign(eip2930.signature_hash(), 2)),
            ),
            alloy::primitives::b256!(
                "8f49fd45a90d5d26fef039c16a72160ba9561d7ebe83931cf4cef9d9e37e9b01"
            ),
        ),
        (
            "eip1559",
            TempoTxEnvelope::Eip1559(
                eip1559
                    .clone()
                    .into_signed(sign(eip1559.signature_hash(), 3)),
            ),
            alloy::primitives::b256!(
                "b8925dc60dc24651662999433314963ca6ee9a70f35f0632ecee8cb914076f6a"
            ),
        ),
        (
            "eip7702",
            TempoTxEnvelope::Eip7702(
                eip7702
                    .clone()
                    .into_signed(sign(eip7702.signature_hash(), 4)),
            ),
            alloy::primitives::b256!(
                "ddf83eda1929502153da05e58fd8990772496e8029f12b5a37c3add343625b93"
            ),
        ),
        (
            "tempo_aa",
            TempoTxEnvelope::AA(
                aa.clone()
                    .into_signed(TempoSignature::from(sign(aa.signature_hash(), 5))),
            ),
            alloy::primitives::b256!(
                "9e2a1ad5b7e435d6452e932f7eab14ab5e81f21b729e97f47b3f6e217678f1db"
            ),
        ),
    ]
}

#[test]
fn every_tempo_envelope_family_preserves_exact_signed_bytes() {
    for (family, envelope, expected_encoding_hash) in envelopes() {
        let encoded = envelope.encoded_2718();
        assert_eq!(
            alloy::primitives::keccak256(&encoded),
            expected_encoding_hash,
            "update only after intentionally reviewing the {family} wire encoding"
        );
        let decoded = TempoTxEnvelope::decode_2718(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.encoded_2718(), encoded, "{family} binary roundtrip");
        assert_eq!(
            decoded.recover_signer().unwrap(),
            envelope.recover_signer().unwrap(),
            "{family} signer"
        );
    }
}
