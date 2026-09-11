mod common;
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, Bytes, TxKind, U256};
use base64::Engine;
use common::*;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256};
use tempo_primitives::{
    TempoSignature, TempoTransaction, TempoTxEnvelope,
    transaction::{
        Call, PrimitiveSignature,
        tt_signature::{P256SignatureWithPreHash, WebAuthnSignature},
    },
};
use tempo_replay::model::Tx;

fn aa_template() -> TempoTransaction {
    TempoTransaction {
        chain_id: 4217,
        nonce: 3,
        nonce_key: U256::from(17),
        gas_limit: 200000,
        max_fee_per_gas: 1000000000,
        calls: vec![
            Call {
                to: TxKind::Create,
                value: U256::ZERO,
                input: Bytes::from_static(&[0x60, 0x00]),
            },
            Call {
                to: TxKind::Call(alloy_primitives::Address::repeat_byte(7)),
                value: U256::ZERO,
                input: Bytes::from_static(&[1, 2, 3, 4]),
            },
        ],
        ..Default::default()
    }
}
fn assert_roundtrip(tx: TempoTxEnvelope) {
    let raw = tx.encoded_2718();
    let decoded = TempoTxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
    assert_eq!(decoded.encoded_2718(), raw);
    let json = serde_json::to_value(&tx).unwrap();
    let decoded: TempoTxEnvelope = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.encoded_2718(), raw);
    assert_eq!(
        Tx::from_envelope(&tx, 4217).unwrap().sender,
        Tx::from_envelope(&decoded, 4217).unwrap().sender
    );
}
#[test]
fn p256_and_webauthn_batched_envelopes_preserve_signed_bytes() {
    let key = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let x = B256::from_slice(point.x().unwrap());
    let y = B256::from_slice(point.y().unwrap());
    for webauthn in [false, true] {
        let tx = aa_template();
        let hash = tx.signature_hash();
        let mut data = vec![0u8; 37];
        data[32] = 1;
        let digest = if webauthn {
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
            let client = format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\"}}");
            let mut signed = data.clone();
            signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
            data.extend_from_slice(client.as_bytes());
            B256::from_slice(&Sha256::digest(signed))
        } else {
            hash
        };
        let sig: p256::ecdsa::Signature = key.sign_prehash(digest.as_slice()).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        let bytes = sig.to_bytes();
        let r = B256::from_slice(&bytes[..32]);
        let s = B256::from_slice(&bytes[32..]);
        let signature = if webauthn {
            PrimitiveSignature::WebAuthn(WebAuthnSignature {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                webauthn_data: data.into(),
            })
        } else {
            PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                pre_hash: false,
            })
        };
        let envelope = TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Primitive(signature)));
        assert_eq!(
            Tx::from_envelope(&envelope, 4217).unwrap().sender,
            tempo_primitives::derive_p256_address(&x, &y)
        );
        assert_roundtrip(envelope);
    }
}
#[test]
fn sponsored_aa_retains_fee_payer_signature_and_batch() {
    let mut tx = aa_template();
    let sender = Tx::from_envelope(&legacy(0, 1), 4217).unwrap().sender;
    tx.fee_payer_signature = Some(sign(tx.fee_payer_signature_hash(sender), 2));
    let sig = sign(tx.signature_hash(), 1);
    let envelope = TempoTxEnvelope::AA(tx.into_signed(sig.into()));
    assert_eq!(Tx::from_envelope(&envelope, 4217).unwrap().sender, sender);
    assert_roundtrip(envelope);
}
#[test]
fn altered_p256_signature_is_not_accepted_as_compatible_source_traffic() {
    let tx = aa_template();
    let signature = PrimitiveSignature::P256(P256SignatureWithPreHash {
        r: B256::ZERO,
        s: B256::ZERO,
        pub_key_x: B256::ZERO,
        pub_key_y: B256::ZERO,
        pre_hash: false,
    });
    assert!(
        Tx::from_envelope(
            &TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Primitive(signature))),
            4217
        )
        .is_err()
    );
}

#[test]
fn keychain_v2_preserves_root_sender_and_expiring_key_authorization() {
    use tempo_primitives::transaction::{KeyAuthorization, KeychainSignature, SignatureType};
    let root = Tx::from_envelope(&legacy(0, 1), 4217).unwrap().sender;
    let access_key = Tx::from_envelope(&legacy(0, 2), 4217).unwrap().sender;
    let authorization = KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, access_key)
        .with_expiry(123456);
    let auth_sig = sign(authorization.signature_hash(), 1);
    let mut tx = aa_template();
    tx.key_authorization = Some(authorization.into_signed(PrimitiveSignature::Secp256k1(auth_sig)));
    let sig_hash = KeychainSignature::signing_hash(tx.signature_hash(), root);
    let sig = KeychainSignature::new(root, PrimitiveSignature::Secp256k1(sign(sig_hash, 2)));
    let envelope = TempoTxEnvelope::AA(tx.into_signed(TempoSignature::Keychain(sig)));
    assert_eq!(Tx::from_envelope(&envelope, 4217).unwrap().sender, root);
    assert_roundtrip(envelope);
}
#[test]
fn tempo_authorization_list_retains_authority_nonce() {
    use tempo_primitives::transaction::TempoSignedAuthorization;
    let authorization = alloy_eips::eip7702::Authorization {
        chain_id: U256::from(4217),
        address: alloy_primitives::Address::repeat_byte(9),
        nonce: 27,
    };
    let signature = sign(authorization.signature_hash(), 2);
    let mut tx = aa_template();
    tx.calls.remove(0); // Tempo forbids CREATE in a transaction with an AA authorization list.
    tx.tempo_authorization_list = vec![TempoSignedAuthorization::new_unchecked(
        authorization,
        signature.into(),
    )];
    let signature = sign(tx.signature_hash(), 1);
    let envelope = TempoTxEnvelope::AA(tx.into_signed(signature.into()));
    assert_eq!(
        envelope.as_aa().unwrap().tx().tempo_authorization_list[0]
            .inner()
            .nonce,
        27
    );
    assert_roundtrip(envelope);
}
