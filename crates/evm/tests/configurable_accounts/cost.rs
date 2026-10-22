//! Bounded crypto evidence, not production hardware or gas calibration.
use super::*;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use sha2::{Digest, Sha256};
use tempo_primitives::{
    MAX_WEBAUTHN_SIGNATURE_LENGTH,
    transaction::{
        ConfigurableAccountQuorumError,
        tt_signature::{WebAuthnSignature, derive_p256_address, normalize_p256_s},
    },
};

/// A deterministic P256 owner key with its public coordinates and derived address.
struct OwnerKey {
    address: Address,
    key: SigningKey,
    x: B256,
    y: B256,
}

struct MaximumQuorums {
    roles: [(B256, ConfigurableAccountSignature); 2],
    invalid_final: ConfigurableAccountSignature,
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
                OwnerKey {
                    address: derive_p256_address(&x, &y),
                    key,
                    x,
                    y,
                }
            })
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| key.address);
        let roles = [0x31, 0x32].map(|role| {
            let config = ConfigurableAccountConfig {
                salt: B256::repeat_byte(role),
                version: 0,
                threshold: 8,
                owners: keys
                    .iter()
                    .map(|key| ConfigurableAccountOwner {
                        owner: key.address,
                        weight: 1,
                    })
                    .collect(),
            };
            let account = config.derive_account(Address::repeat_byte(0x71)).unwrap();
            let inner = B256::repeat_byte(role);
            let digest = configurable_account_digest(inner, account, 0);
            let approvals = keys[40..]
                .iter()
                .map(|owner| Self::max_webauthn(&owner.key, owner.x, owner.y, digest))
                .collect();
            (
                inner,
                ConfigurableAccountSignature::try_new(account, config, approvals).unwrap(),
            )
        });
        let mut approvals = roles[1].1.signatures().to_vec();
        let PrimitiveSignature::WebAuthn(last) = approvals.last_mut().unwrap() else {
            unreachable!()
        };
        // Valid low-s scalars from the same key, but the wrong prehash: parsing
        // succeeds and rejection requires the final P256 verification itself.
        let wrong: Signature = keys[47].key.sign_prehash(&[0x99; 32]).unwrap();
        let (r, s) = wrong.split_bytes();
        last.r = B256::from_slice(&r);
        last.s = normalize_p256_s(&s).unwrap();
        let invalid_final = ConfigurableAccountSignature::try_new(
            roles[1].1.account(),
            roles[1].1.config().clone(),
            approvals,
        )
        .unwrap();
        let sponsor_key = signer(0x61);
        let mut sponsor_tx = aa_tx(0, Vec::new());
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
        let signature: Signature = key.sign_prehash(&hash.finalize()).unwrap();
        let (r, s) = signature.split_bytes();
        data.extend(json);
        PrimitiveSignature::WebAuthn(WebAuthnSignature {
            webauthn_data: data.into(),
            r: B256::from_slice(&r),
            s: normalize_p256_s(&s).unwrap(),
            pub_key_x: x,
            pub_key_y: y,
        })
    }

    fn verify(
        &self,
        invalid_final: bool,
        sponsored: bool,
    ) -> Result<(), ConfigurableAccountQuorumError> {
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
            let signature = if invalid_final && index == 1 {
                &self.invalid_final
            } else {
                signature
            };
            signature.verify_approvals(*inner_digest)?;
        }
        Ok(())
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
