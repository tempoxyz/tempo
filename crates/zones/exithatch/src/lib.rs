//! Pure TIP-1012 codecs and root authorization. Stateful execution belongs to ZoneInbox.
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolStruct, SolType, SolValue, eip712_domain, sol_data};
type Plaintext = (sol_data::Uint<8>, ForcedExitAuthorization, sol_data::Bytes);
use tempo_contracts::zones::DepositType;
pub use tempo_contracts::zones::{
    ForcedExit, ForcedExitAuthorization, ForcedExitMetadata, ForcedExitReason,
};
use tempo_primitives::transaction::PrimitiveSignature;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

pub const VERSION: u8 = 1;
pub const FORCED_EXIT_COMPENSATION: u128 = 100_000;
pub const MIN_CIPHERTEXT_SIZE: usize = 384;
pub const MAX_CIPHERTEXT_SIZE: usize = 2368;
/// TIP-0001's maximum primitive encoding, including the type byte.
pub const MAX_SIGNATURE_SIZE: usize = 2049;

/// Admission checks length only; payload and authorization validity are determined on Zone.
pub const fn valid_ciphertext_length(length: usize) -> bool {
    length >= MIN_CIPHERTEXT_SIZE && length <= MAX_CIPHERTEXT_SIZE && length.is_multiple_of(32)
}

/// Encode the top-level ABI tuple, without an additional dynamic tuple wrapper.
pub fn encode_payload(auth: &ForcedExitAuthorization, signature: &[u8]) -> Vec<u8> {
    Plaintext::abi_encode_params(&(VERSION, auth.clone(), Bytes::copy_from_slice(signature)))
}

/// Decode only the payload category. Signature errors must remain InvalidAuthorization.
pub fn decode_payload(
    plaintext: &[u8],
) -> Result<(ForcedExitAuthorization, Bytes), ForcedExitReason> {
    if !valid_ciphertext_length(plaintext.len()) {
        return Err(ForcedExitReason::InvalidPayload);
    }
    let (version, auth, signature) =
        Plaintext::abi_decode_params(plaintext).map_err(|_| ForcedExitReason::InvalidPayload)?;
    if version != VERSION || encode_payload(&auth, &signature) != plaintext {
        return Err(ForcedExitReason::InvalidPayload);
    }
    Ok((auth, signature))
}

pub fn authorization_digest(
    auth: &ForcedExitAuthorization,
    l1_chain_id: U256,
    portal: Address,
) -> B256 {
    let mut domain = eip712_domain! {
        name: "TempoZoneForcedExit",
        version: "1",
        verifying_contract: portal,
    };
    domain.chain_id = Some(l1_chain_id);
    auth.eip712_signing_hash(&domain)
}

/// Check signed fields and root identity. Replay and balance/policy checks are separate stages.
/// `requested_at_time` must come from the authenticated queued entry, never the execution clock.
pub fn authorize(
    auth: &ForcedExitAuthorization,
    signature: &[u8],
    l1_chain_id: U256,
    portal: Address,
    zone_chain_id: U256,
    public_token: Address,
    requested_at_time: u64,
) -> Result<(), ForcedExitReason> {
    let invalid = ForcedExitReason::InvalidAuthorization;
    if auth.account.is_zero()
        || auth.recipient.is_zero()
        || auth.zoneChainId != zone_chain_id
        || auth.token != public_token
        || requested_at_time >= auth.admitBefore
        || signature.len() > MAX_SIGNATURE_SIZE
    {
        return Err(invalid);
    }
    // Decode primitives directly, never TempoSignature (which also accepts keychain envelopes).
    let primitive = PrimitiveSignature::from_bytes(signature).map_err(|_| invalid)?;
    // TIP-0001's P256 pre_hash is a boolean. The upstream decoder treats any nonzero byte as
    // true; the forced-exit envelope rejects noncanonical booleans instead of normalizing them.
    if matches!(primitive, PrimitiveSignature::P256(_)) && signature.last().is_some_and(|b| *b > 1)
    {
        return Err(invalid);
    }
    let signer = primitive
        .recover_signer(&authorization_digest(auth, l1_chain_id, portal))
        .map_err(|_| invalid)?;
    if signer != auth.account {
        return Err(invalid);
    }
    Ok(())
}

pub fn request_queue_hash(entry: &ForcedExit, previous: B256) -> B256 {
    keccak256((DepositType::ForcedExit, entry.clone(), previous).abi_encode_params())
}

/// Private per-request input to the normal withdrawal sender-tag formula.
/// Includes the root signature; callers must first validate canonical decoding and authorization.
/// Never publish this value on L1 or substitute the shared inbox transaction hash.
pub fn private_request_hash(auth: &ForcedExitAuthorization, signature: &[u8]) -> B256 {
    keccak256(encode_payload(auth, signature))
}

#[cfg(test)]
mod tests {
    use super::{test_utils::*, *};
    use alloy_primitives::{address, b256};
    use proptest::prelude::*;
    use tempo_contracts::zones::Withdrawal;

    const PORTAL: Address = address!("5ad0000000000000000000000000000000000001");
    const TOKEN: Address = address!("20c0000000000000000000000000000000000000");
    const L1_CHAIN: u64 = 42431;

    fn auth() -> ForcedExitAuthorization {
        ForcedExitAuthorization {
            account: k256_account(&k256_key(1)),
            zoneChainId: U256::from(1234),
            token: TOKEN,
            recipient: Address::repeat_byte(0x22),
            nonce: U256::from(42),
            admitBefore: 100,
        }
    }
    fn digest(a: &ForcedExitAuthorization) -> B256 {
        authorization_digest(a, U256::from(L1_CHAIN), PORTAL)
    }
    fn sign(a: &ForcedExitAuthorization) -> Vec<u8> {
        sign_k256(&k256_key(1), digest(a))
    }
    fn check(a: &ForcedExitAuthorization, sig: &[u8], time: u64) -> Result<(), ForcedExitReason> {
        authorize(
            a,
            sig,
            U256::from(L1_CHAIN),
            PORTAL,
            U256::from(1234),
            TOKEN,
            time,
        )
    }

    /// A valid (authorization, signature) pair for each supported root primitive.
    fn root_signatures() -> Vec<(ForcedExitAuthorization, Vec<u8>)> {
        let key = p256_key(1);
        let mut p256_auth = auth();
        p256_auth.account = p256_account(&key);
        let d = digest(&p256_auth);
        vec![
            (auth(), sign(&auth())),
            (p256_auth.clone(), sign_p256(&key, d, false)),
            (p256_auth.clone(), sign_p256(&key, d, true)),
            (p256_auth.clone(), sign_webauthn(&key, d, 300)),
            (p256_auth, sign_webauthn(&key, d, MAX_SIGNATURE_SIZE)),
        ]
    }

    #[test]
    fn authorization_binds_every_field_and_domain() {
        let a = auth();
        let sig = sign(&a);
        assert_eq!(check(&a, &sig, 99), Ok(()));
        for time in [100, 101] {
            assert_eq!(
                check(&a, &sig, time),
                Err(ForcedExitReason::InvalidAuthorization)
            );
        }
        for field in 0..6 {
            let mut changed = a.clone();
            match field {
                0 => changed.account = Address::repeat_byte(3),
                1 => changed.zoneChainId += U256::ONE,
                2 => changed.token = Address::repeat_byte(4),
                3 => changed.recipient = Address::repeat_byte(5),
                4 => changed.nonce += U256::ONE,
                _ => changed.admitBefore += 1,
            }
            assert_eq!(
                check(&changed, &sig, 99),
                Err(ForcedExitReason::InvalidAuthorization)
            );
        }
        for (l1_chain, portal) in [(L1_CHAIN + 1, PORTAL), (L1_CHAIN, Address::ZERO)] {
            assert_eq!(
                authorize(
                    &a,
                    &sig,
                    U256::from(l1_chain),
                    portal,
                    a.zoneChainId,
                    TOKEN,
                    99
                ),
                Err(ForcedExitReason::InvalidAuthorization)
            );
        }
        for field in 0..3 {
            let mut invalid = a.clone();
            match field {
                0 => invalid.account = Address::ZERO,
                1 => invalid.recipient = Address::ZERO,
                _ => invalid.admitBefore = 0,
            }
            assert_eq!(
                check(&invalid, &sign(&invalid), 0),
                Err(ForcedExitReason::InvalidAuthorization)
            );
        }
    }

    #[test]
    fn every_root_primitive_round_trips_and_authorizes() {
        for (a, sig) in root_signatures() {
            let bytes = encode_payload(&a, &sig);
            assert!(valid_ciphertext_length(bytes.len()), "{}", sig.len());
            let (decoded, signature) = decode_payload(&bytes).unwrap();
            assert_eq!((&decoded, signature.as_ref()), (&a, sig.as_slice()));
            assert_eq!(check(&decoded, &signature, 99), Ok(()));
        }
        // The largest WebAuthn primitive fills the admitted plaintext exactly.
        let (a, sig) = root_signatures().pop().unwrap();
        assert_eq!(encode_payload(&a, &sig).len(), MAX_CIPHERTEXT_SIZE);
        assert_eq!(
            encode_payload(&auth(), &sign(&auth())).len(),
            MIN_CIPHERTEXT_SIZE
        );
    }

    #[test]
    fn signature_edge_cases() {
        use SignatureMutation::*;
        let bases = root_signatures();
        let invalid = Err(ForcedExitReason::InvalidAuthorization);
        let cases = [
            // (base index, mutation, expected)
            (0, Keychain(3), invalid),
            (0, Keychain(4), invalid),
            (0, TypeByte(0), invalid),
            (0, RecoveryByte(2), invalid),
            (0, RecoveryByte(29), invalid),
            (1, Keychain(3), invalid),
            (1, PreHash(2), invalid),
            (2, PreHash(2), invalid),
            (1, HighS, invalid),
            (1, Resize(131), invalid),
            (1, Resize(129), invalid),
            (3, HighS, invalid),
            (3, WebAuthnFlags(0), invalid),
            (3, WebAuthnChallenge(0), invalid),
            (3, TypeByte(1), invalid),
            // secp256k1 decoding normalizes `v`, so these encode the same signature.
            (0, HighS, invalid),
            (0, RecoveryByte(27), Ok(())),
            (0, RecoveryByte(35), Ok(())),
        ];
        for (base, mutation, expected) in cases {
            let (a, sig) = &bases[base];
            let mut mutated = mutation.apply(sig, a.account);
            if matches!(mutation, RecoveryByte(_)) {
                // Keep the recovered parity: 27/35 pick parity 0, so offset by the original bit.
                mutated[64] += sig[64];
            }
            assert_ne!(&mutated, sig, "{mutation:?} is a no-op");
            if matches!(mutation, HighS) && sig.first() == Some(&2) {
                let s = sig.len() - 96..sig.len() - 64;
                assert_eq!(&mutated[..s.start], &sig[..s.start]);
                assert_eq!(&mutated[s.end..], &sig[s.end..]);
            }
            assert_eq!(check(a, &mutated, 99), expected, "{base} {mutation:?}");
        }
    }

    #[test]
    fn ciphertext_length_gate() {
        for length in [0, 64, 383, 385, 2367, 2369, 2400] {
            assert!(!valid_ciphertext_length(length));
        }
        for length in (384..=2368).step_by(32) {
            assert!(valid_ciphertext_length(length));
        }
    }

    #[test]
    fn sender_tag_uses_private_signed_payload_and_unique_fallback_nonce() {
        let a = auth();
        let sig = sign(&a);
        let hash = private_request_hash(&a, &sig);
        assert_eq!(hash, keccak256(encode_payload(&a, &sig)));
        assert_ne!(hash, digest(&a));
        let mut changed = sig;
        changed[0] ^= 1;
        assert_ne!(hash, private_request_hash(&a, &changed));
        let tag = Withdrawal::sender_tag(a.account, hash, 9);
        assert_ne!(tag, Withdrawal::sender_tag(a.account, hash, 10));
        assert_ne!(tag, Withdrawal::sender_tag(a.account, B256::ZERO, 9));
    }

    #[test]
    fn solidity_interop_vectors() {
        use tempo_contracts::zones::DepositPayload;
        let a = auth();
        let payload = encode_payload(&a, &[0x33; 65]);
        let entry = ForcedExit {
            requestId: 1,
            token: TOKEN,
            keyIndex: U256::from(3),
            encrypted: DepositPayload {
                ephemeralPubkeyX: b256!(
                    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                ),
                ephemeralPubkeyYParity: 2,
                ciphertext: vec![0x44; 384].into(),
                nonce: [0x55; 12].into(),
                tag: [0x66; 16].into(),
            },
            feePayer: Address::repeat_byte(0x77),
            requestedAtBlock: 80,
            requestedAtTime: 90,
        };
        let withdrawal = Withdrawal {
            token: TOKEN,
            senderTag: Withdrawal::sender_tag(a.account, private_request_hash(&a, &sign(&a)), 9),
            to: a.recipient,
            amount: 123456,
            memo: B256::ZERO,
            gasLimit: 0,
            fallbackNonce: 9,
            callbackData: Bytes::new(),
            encryptedSender: Bytes::new(),
        };
        let values = serde_json::json!({
            "typeHash": a.eip712_type_hash(),
            "digest": digest(&a),
            "signature": Bytes::from(sign(&a)),
            "payload": Bytes::from(payload),
            "queueHash": request_queue_hash(&entry, B256::repeat_byte(0x88)),
            "senderTag": withdrawal.senderTag,
            "privateRequestHash": private_request_hash(&a, &sign(&a)),
            "withdrawalHash": keccak256(withdrawal.abi_encode()),
            "withdrawalQueueHash": keccak256((withdrawal, B256::repeat_byte(0x99)).abi_encode_params()),
        });
        let expected: serde_json::Value = serde_json::from_str(include_str!(
            "../../contracts/test/fixtures/forcedExit.json"
        ))
        .unwrap();
        assert_eq!(values, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Structural edits of a canonical payload fail as InvalidPayload. An edit can only
        /// decode if it is itself the canonical encoding of a different signature (for example
        /// a length word grown into zero padding), which must then fail authorization.
        #[test]
        fn mutated_payload_is_invalid_payload(
            base in prop::sample::select(root_signatures()),
            mutation in payload_mutation(),
        ) {
            let (a, sig) = base;
            let payload = encode_payload(&a, &sig);
            let mutated = mutation.apply(&payload);
            match decode_payload(&mutated) {
                Ok((decoded, signature)) => {
                    prop_assert_eq!(encode_payload(&decoded, &signature), mutated.clone());
                    if mutated != payload {
                        prop_assert_eq!(
                            check(&decoded, &signature, 99),
                            Err(ForcedExitReason::InvalidAuthorization),
                            "{:?} decoded and authorized", mutation
                        );
                    }
                }
                Err(reason) => prop_assert_eq!(reason, ForcedExitReason::InvalidPayload),
            }
        }

        /// Arbitrary admitted-size plaintexts never panic and only fail as InvalidPayload.
        #[test]
        fn arbitrary_plaintext_is_invalid_payload(
            words in 12usize..=74,
            bytes in prop::collection::vec(any::<u8>(), 2368),
        ) {
            let plaintext = &bytes[..words * 32];
            if let Err(reason) = decode_payload(plaintext) {
                prop_assert_eq!(reason, ForcedExitReason::InvalidPayload);
            }
        }

        /// A mutated signature still decodes (when it fits) and only fails as
        /// InvalidAuthorization. The only accepted mutations are the original bytes and
        /// secp256k1 encodings that alloy normalizes to the same signature; the replay map,
        /// not the decoder, stops those from exiting twice.
        #[test]
        fn mutated_signature_is_invalid_authorization(
            base in prop::sample::select(root_signatures()),
            mutation in signature_mutation(),
        ) {
            let (a, sig) = base;
            let mutated = mutation.apply(&sig, a.account);
            let result = check(&a, &mutated, 99);
            if result.is_ok() {
                prop_assert!(
                    mutated == sig || is_secp256k1_malleation(&sig, &mutated),
                    "{:?} still authorizes", mutation
                );
                prop_assert_ne!(
                    mutated != sig,
                    private_request_hash(&a, &mutated) == private_request_hash(&a, &sig)
                );
            } else {
                prop_assert_eq!(result, Err(ForcedExitReason::InvalidAuthorization));
            }
            let payload = encode_payload(&a, &mutated);
            if valid_ciphertext_length(payload.len()) {
                let (decoded, signature) = decode_payload(&payload).unwrap();
                prop_assert_eq!(check(&decoded, &signature, 99), result);
            }
        }
    }
}
