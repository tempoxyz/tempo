//! Bounded crypto evidence, not production hardware or gas calibration.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use tempo_primitives::{
    TempoTransaction,
    transaction::{
        MAX_WEBAUTHN_SIGNATURE_LENGTH,
        tt_signature::{WebAuthnSignature, derive_p256_address, normalize_p256_s},
    },
};

struct MaximumQuorums {
    roles: [(B256, MultisigSignature); 2],
    invalid_final: MultisigSignature,
    sponsor_tx: TempoTransaction,
    sponsor: Address,
}

impl MaximumQuorums {
    fn new() -> Self {
        // Distinct deterministic keys; select the final eight sorted owners.
        let mut keys = (1..=48)
            .map(|seed| {
                let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
                let point = key.verifying_key().to_encoded_point(false);
                let x = B256::from_slice(point.x().unwrap());
                let y = B256::from_slice(point.y().unwrap());
                (derive_p256_address(&x, &y), key, x, y)
            })
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| key.0);
        let roles = [0x31, 0x32].map(|role| {
            let config = MultisigConfig {
                salt: B256::repeat_byte(role),
                version: 0,
                threshold: 8,
                owners: keys
                    .iter()
                    .map(|key| MultisigOwner {
                        owner: key.0,
                        weight: 1,
                    })
                    .collect(),
            };
            let account = config.derive_account(Address::repeat_byte(0x71)).unwrap();
            let inner = B256::repeat_byte(role);
            let digest = tempo_primitives::transaction::multisig_digest(inner, account, 0);
            let approvals = keys[40..]
                .iter()
                .map(|(_, key, x, y)| Self::max_webauthn(key, *x, *y, digest))
                .collect();
            (
                inner,
                MultisigSignature::try_new(account, config, approvals).unwrap(),
            )
        });
        let mut approvals = roles[1].1.signatures().to_vec();
        let PrimitiveSignature::WebAuthn(last) = approvals.last_mut().unwrap() else {
            unreachable!()
        };
        // Valid low-s scalars from the same key, but the wrong prehash: parsing
        // succeeds and rejection requires the final P256 verification itself.
        let wrong: p256::ecdsa::Signature = keys[47].1.sign_prehash(&[0x99; 32]).unwrap();
        let wrong = wrong.to_bytes();
        last.r = B256::from_slice(&wrong[..32]);
        last.s = normalize_p256_s(&wrong[32..]).unwrap();
        let invalid_final = MultisigSignature::try_new(
            roles[1].1.account(),
            roles[1].1.config().clone(),
            approvals,
        )
        .unwrap();
        let sponsor_key = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x61)).unwrap();
        let mut sponsor_tx = TempoTransaction {
            chain_id: 1,
            gas_limit: 1_000_000,
            ..Default::default()
        };
        sponsor_tx.fee_payer_signature = Some(
            sponsor_key
                .sign_hash_sync(&sponsor_tx.fee_payer_signature_hash(roles[0].1.account()))
                .unwrap(),
        );
        Self {
            roles,
            invalid_final,
            sponsor_tx,
            sponsor: sponsor_key.address(),
        }
    }

    fn max_webauthn(key: &SigningKey, x: B256, y: B256, digest: B256) -> PrimitiveSignature {
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        let mut json = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://native.example"}}"#).into_bytes();
        // Whitespace is valid JSON and exercises the maximum bounded payload.
        json.resize(MAX_WEBAUTHN_SIGNATURE_LENGTH - 128 - 37, b' ');
        let mut data = vec![0; 37];
        data[32] = 1;
        let mut hash = Sha256::new();
        hash.update(&data);
        hash.update(Sha256::digest(&json));
        let signature: p256::ecdsa::Signature = key.sign_prehash(&hash.finalize()).unwrap();
        let signature = signature.to_bytes();
        data.extend(json);
        PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: data.into(),
            r: B256::from_slice(&signature[..32]),
            s: normalize_p256_s(&signature[32..]).unwrap(),
            pub_key_x: x,
            pub_key_y: y,
        })
    }

    fn verify(&self, invalid_final: bool, sponsored: bool) -> Result<(), NativeMultisigError> {
        // Include the actual optional secp recovery, not merely its fixture bytes.
        if sponsored {
            assert_eq!(
                self.sponsor_tx
                    .recover_fee_payer(self.roles[0].1.account())
                    .unwrap(),
                self.sponsor
            );
        }
        for (index, (inner_digest, signature)) in self.roles.iter().enumerate() {
            NativeAuthorization {
                inner_digest: *inner_digest,
                signature: if invalid_final && index == 1 {
                    &self.invalid_final
                } else {
                    signature
                },
            }
            .verify()?;
        }
        Ok(())
    }
}

#[test]
fn native_maximum_two_quorums_and_optional_sponsor() {
    let fixture = MaximumQuorums::new();
    for (_, signature) in &fixture.roles {
        assert_eq!(signature.config().owners.len(), 48);
        assert_eq!(signature.signatures().len(), 8);
        for approval in signature.signatures() {
            assert_eq!(approval.to_bytes().len(), 1 + MAX_WEBAUTHN_SIGNATURE_LENGTH);
        }
    }
    for sponsored in [false, true] {
        fixture.verify(false, sponsored).unwrap();
        assert!(matches!(
            fixture.verify(true, sponsored),
            Err(NativeMultisigError::OwnerSignatureRecoveryFailed { approval_index: 7 })
        ));
    }
}

#[test]
#[ignore = "local crypto timing only; run uninstrumented --release --ignored --nocapture"]
fn native_maximum_quorum_crypto_timing() {
    // Signing and fixture allocation are deliberately outside the timed region.
    let fixture = MaximumQuorums::new();
    let iterations = 100;
    for sponsored in [false, true] {
        for invalid_final in [false, true] {
            let start = std::time::Instant::now();
            for _ in 0..iterations {
                let result = std::hint::black_box(&fixture).verify(invalid_final, sponsored);
                assert_eq!(result.is_err(), invalid_final);
            }
            eprintln!(
                "quorum crypto only: debug_assertions={}, sponsor={sponsored}, invalid_final={invalid_final}, iterations={iterations}, elapsed={:?}; excludes state, gas accounting and fixture signing",
                cfg!(debug_assertions),
                start.elapsed()
            );
        }
    }
}
