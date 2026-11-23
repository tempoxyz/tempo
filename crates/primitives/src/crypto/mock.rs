//! Mock signatures: hashes of signer and message that [`super`]'s checks accept once [`install`] ran.
//! Each builder mirrors its [`super`] check, secp256k1 mirrors alloy's provider.
//!
//! | Scheme | Mock signature |
//! |---|---|
//! | secp256k1 | `r` = tag of digest and signer, `s` = the signer's address (never zero) |
//! | P256, WebAuthn | `r` = tag of digest and public key, `s` = 1 |
//! | Ed25519 | tag of key, namespace and message, then 32 zero bytes |
//! | P-384, COSE | tag of key and digest, then 64 zero bytes |
//! | P-384, X.509 | DER `SEQUENCE { INTEGER tag, INTEGER 1 }` of the same tag |
//!
//! tag = `keccak256("tempo-mock-crypto" || scheme || (u64_be(len) || part)...)`.

use super::{
    p384::FIXED_SIGNATURE_SIZE,
    webauthn::{MIN_AUTH_DATA_LEN, UP, webauthn_digest},
};
use crate::transaction::tt_signature::WebAuthnSignature;
use alloc::{sync::Arc, vec::Vec};
use alloy_consensus::crypto::{
    RecoveryError,
    backend::{CryptoProvider, install_default_provider},
};
use alloy_primitives::{Address, B256, Bytes, Keccak256, Signature, U256};
use base64::Engine;
use core::sync::atomic::{AtomicBool, Ordering};
use secp256k1::{
    Message, PublicKey, SECP256K1,
    ecdsa::{RecoverableSignature, RecoveryId, Signature as SecpSignature},
};

/// Mock format version, reported to fuzzers.
pub const VERSION: u32 = 1;

static ENABLED: AtomicBool = AtomicBool::new(false);

#[repr(u8)]
enum Scheme {
    Secp256k1 = 1,
    P256 = 2,
    Ed25519 = 3,
    P384 = 4,
}

/// Installs the mock-aware secp256k1 provider into alloy and turns mocks on, process-wide.
/// Fuzzers and tests only. Returns whether mocks are on.
pub fn install() -> bool {
    static INSTALLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *INSTALLED.get_or_init(|| {
        let installed = install_default_provider(Arc::new(Provider)).is_ok();
        ENABLED.store(installed, Ordering::Relaxed);
        installed
    })
}

/// alloy's secp256k1 provider: mocks, else the same real checks as alloy's own backend.
#[derive(Debug)]
struct Provider;

impl CryptoProvider for Provider {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let (rs, recid) = sig.split_first_chunk().expect("65 bytes");
        if let Some(signer) = recover_secp256k1(rs, msg).filter(|_| recid[0] <= 1) {
            return Ok(signer);
        }
        let id = RecoveryId::try_from(i32::from(recid[0])).map_err(|_| RecoveryError::new())?;
        let signature =
            RecoverableSignature::from_compact(rs, id).map_err(|_| RecoveryError::new())?;
        let key = SECP256K1
            .recover_ecdsa(&Message::from_digest(*msg), &signature)
            .map_err(|_| RecoveryError::new())?;
        Ok(Address::from_raw_public_key(
            &key.serialize_uncompressed()[1..],
        ))
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        let key = PublicKey::from_slice(pubkey).map_err(|_| RecoveryError::new())?;
        let signer = Address::from_raw_public_key(&key.serialize_uncompressed()[1..]);
        if recover_secp256k1(sig, msg) == Some(signer) {
            return Ok(signer);
        }
        let signature = SecpSignature::from_compact(sig).map_err(|_| RecoveryError::new())?;
        SECP256K1
            .verify_ecdsa(&Message::from_digest(*msg), &signature, &key)
            .map_err(|_| RecoveryError::new())?;
        Ok(signer)
    }
}

/// The secp256k1 mock by `signer` over `hash`, valid with any recovery id.
pub fn secp256k1(signer: Address, hash: &B256) -> Signature {
    let r = tag(Scheme::Secp256k1, &[hash.as_slice(), signer.as_slice()]);
    Signature::new(r.into(), U256::from_be_slice(signer.as_slice()), false)
}

/// The P256 mock `(r, s)` by `(x, y)` over `digest`.
pub fn p256(x: &B256, y: &B256, digest: &B256) -> (B256, B256) {
    let r = tag(
        Scheme::P256,
        &[digest.as_slice(), x.as_slice(), y.as_slice()],
    );
    (r, B256::with_last_byte(1))
}

/// The WebAuthn mock by `(x, y)` over `hash`, or `None` if `webauthn_data` fails the real checks.
pub fn webauthn(x: B256, y: B256, webauthn_data: Bytes, hash: &B256) -> Option<WebAuthnSignature> {
    if webauthn_data.len() > crate::MAX_WEBAUTHN_SIGNATURE_LENGTH - 128 {
        return None;
    }
    let digest = webauthn_digest(&webauthn_data, hash).ok()?;
    let (r, s) = p256(&x, &y, &digest);
    Some(WebAuthnSignature {
        r,
        s,
        pub_key_x: x,
        pub_key_y: y,
        webauthn_data,
    })
}

/// The smallest `webauthn_data` the check accepts for `hash`.
pub fn webauthn_data(hash: &B256) -> Bytes {
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    let mut data = alloc::vec![0; MIN_AUTH_DATA_LEN];
    data[32] = UP;
    data.extend_from_slice(br#"{"type":"webauthn.get","challenge":""#);
    data.extend_from_slice(challenge.as_bytes());
    data.extend_from_slice(br#"","origin":"https://tempo.xyz"}"#);
    data.into()
}

/// The Ed25519 mock by `key` over `message` in `namespace`.
pub fn ed25519(key: &[u8], namespace: &[u8], message: &[u8]) -> [u8; 64] {
    padded(tag(Scheme::Ed25519, &[key, namespace, message]))
}

/// The P-384 mock by `key` over `digest` in COSE's `r || s` form.
pub fn p384_fixed(key: &[u8], digest: &[u8]) -> [u8; FIXED_SIGNATURE_SIZE] {
    padded(tag(Scheme::P384, &[key, digest]))
}

/// The P-384 mock by `key` over `digest` in X.509's DER form.
pub fn p384_der(key: &[u8], digest: &[u8]) -> Vec<u8> {
    der(tag(Scheme::P384, &[key, digest]))
}

fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The signer whose secp256k1 mock `rs` is over `digest`.
fn recover_secp256k1(rs: &[u8; 64], digest: &[u8; 32]) -> Option<Address> {
    let (r, s) = rs.split_at(32);
    if !enabled() || s[..12] != [0; 12] {
        return None;
    }
    let signer = Address::from_slice(&s[12..]);
    (!signer.is_zero() && tag(Scheme::Secp256k1, &[digest, signer.as_slice()]) == r)
        .then_some(signer)
}

/// Whether `(r, s)` is the P256 mock of on-curve key `(x, y)` over `digest`.
pub fn verify_p256(r: &B256, s: &B256, x: &B256, y: &B256, digest: &B256) -> bool {
    if !enabled() || p256(x, y, digest) != (*r, *s) {
        return false;
    }
    let mut point = [0x04; 65];
    point[1..33].copy_from_slice(x.as_slice());
    point[33..].copy_from_slice(y.as_slice());
    p256::PublicKey::from_sec1_bytes(&point).is_ok()
}

/// Whether `signature` is the Ed25519 mock by `key` over `message` in `namespace`.
pub(super) fn verify_ed25519(
    key: &[u8],
    namespace: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    enabled() && signature == ed25519(key, namespace, message)
}

/// Whether `signature` is the DER P-384 mock by `key` over `digest`.
pub(super) fn verify_p384_der(key: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    enabled() && signature == p384_der(key, digest)
}

/// Whether `signature` is the `r || s` P-384 mock by `key` over `digest`.
pub(super) fn verify_p384_fixed(key: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    enabled() && signature == p384_fixed(key, digest)
}

fn tag(scheme: Scheme, parts: &[&[u8]]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(b"tempo-mock-crypto");
    hasher.update([scheme as u8]);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize()
}

/// `tag` followed by zero bytes, `N` bytes wide.
fn padded<const N: usize>(tag: B256) -> [u8; N] {
    let mut out = [0; N];
    out[..32].copy_from_slice(tag.as_slice());
    out
}

/// DER `SEQUENCE { INTEGER tag, INTEGER 1 }`.
fn der(tag: B256) -> Vec<u8> {
    let r = &tag[tag[..31].iter().take_while(|byte| **byte == 0).count()..];
    let pad = usize::from(r[0] >= 0x80);
    let r_len = (r.len() + pad) as u8;
    let mut der = alloc::vec![0x30, r_len + 5, 0x02, r_len];
    der.extend(core::iter::repeat_n(0, pad));
    der.extend_from_slice(r);
    der.extend_from_slice(&[0x02, 0x01, 0x01]);
    der
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::tt_signature::{
        KeychainSignature, P256SignatureWithPreHash, PrimitiveSignature, TempoSignature,
        p256_keypair,
    };
    use alloy_consensus::crypto::secp256k1::{recover_signer, sign_message};
    use secp256k1::SecretKey;

    /// Mocks reject malformed, ambiguous or foreign inputs. Valid ones are tested end to end.
    #[test]
    fn mock_signatures_reject_what_they_do_not_bind() {
        install();
        let digest = B256::repeat_byte(1);
        let zero = secp256k1(Address::ZERO, &digest);
        assert_eq!(
            recover_secp256k1(&zero.as_bytes()[..64].try_into().unwrap(), &digest.0),
            None,
            "s would be zero"
        );
        assert_eq!(recover_secp256k1(&[0; 64], &digest.0), None);

        let (_, x, y, _) = p256_keypair();
        let (r, _) = p256(&x, &y, &digest);
        assert!(!verify_p256(&r, &r, &x, &y, &digest));
        let (r, s) = p256(&x, &x, &digest);
        assert!(!verify_p256(&r, &s, &x, &x, &digest), "off the curve");

        let signature = ed25519(b"key", b"ns", b"msg");
        assert!(!verify_ed25519(b"key", b"nsm", b"sg", &signature));
        assert!(!verify_ed25519(b"ke", b"yns", b"msg", &signature));
        let (fixed, der) = (p384_fixed(b"key", b"digest"), p384_der(b"key", b"digest"));
        assert!(verify_p384_fixed(b"key", b"digest", &fixed));
        assert!(verify_p384_der(b"key", b"digest", &der));
        assert!(
            !verify_p384_der(b"key", b"digest", &fixed),
            "wrong encoding"
        );
        assert!(
            !verify_p384_fixed(b"key", b"digest", &der),
            "wrong encoding"
        );
        assert!(!verify_p384_der(b"other", b"digest", &der));
        assert!(!verify_p384_der(b"key", b"other", &der));
    }

    /// Real and mock secp256k1 signatures pass both alloy entry points only for their digest and a
    /// valid key.
    #[test]
    fn secp256k1_signatures_verify_through_the_alloy_provider() {
        install();
        let (digest, other) = (B256::repeat_byte(7), [8; 32]);
        let key = SecretKey::from_byte_array(&[0x11; 32]).unwrap();
        let mut pubkey = PublicKey::from_secret_key(SECP256K1, &key).serialize_uncompressed();
        let signer = Address::from_raw_public_key(&pubkey[1..]);
        let real = sign_message(B256::from(key.secret_bytes()), digest).unwrap();
        let mock = secp256k1(signer, &digest);
        for signature in [real, mock, mock.with_parity(true)] {
            assert_eq!(recover_signer(&signature, digest).ok(), Some(signer));
            assert_ne!(recover_signer(&signature, other.into()).ok(), Some(signer));
            let rs = signature.as_bytes()[..64].try_into().unwrap();
            assert_eq!(
                Provider
                    .verify_and_compute_signer_unchecked(&pubkey, &rs, &digest.0)
                    .ok(),
                Some(signer)
            );
            assert!(
                Provider
                    .verify_and_compute_signer_unchecked(&pubkey, &rs, &other)
                    .is_err()
            );
        }
        pubkey[0] = 0x05;
        let rs = mock.as_bytes()[..64].try_into().unwrap();
        assert!(
            Provider
                .verify_and_compute_signer_unchecked(&pubkey, &rs, &digest.0)
                .is_err(),
            "bad SEC1 prefix"
        );
    }

    /// P256 and keychain mocks recover their key only for their hash.
    #[test]
    fn p256_mocks_recover_their_key_only_for_their_hash() {
        install();
        let (hash, other) = (B256::repeat_byte(0xcc), B256::repeat_byte(0xdd));
        let (_, x, y, signer) = p256_keypair();
        let p256_signature = |hash: B256, pre_hash| {
            let (r, s) = p256(&x, &y, &P256SignatureWithPreHash::digest(&hash, pre_hash));
            PrimitiveSignature::P256(P256SignatureWithPreHash {
                r,
                s,
                pub_key_x: x,
                pub_key_y: y,
                pre_hash,
            })
        };
        for pre_hash in [false, true] {
            let signature = p256_signature(hash, pre_hash);
            assert_eq!(signature.recover_signer(&hash).ok(), Some(signer));
            assert!(signature.recover_signer(&other).is_err());
        }
        assert!(webauthn(x, y, webauthn_data(&other), &hash).is_none());
        // Valid content, too long to encode.
        let mut long = webauthn_data(&hash).to_vec();
        long.pop();
        long.extend_from_slice(br#","pad":""#);
        long.resize(crate::MAX_WEBAUTHN_SIGNATURE_LENGTH, b'a');
        long.extend_from_slice(br#""}"#);
        assert!(webauthn(x, y, long.into(), &hash).is_none());

        let user = Address::repeat_byte(0x42);
        let keychain = KeychainSignature::new(
            user,
            p256_signature(KeychainSignature::signing_hash(hash, user), false),
        );
        assert_eq!(keychain.key_id(&hash).ok(), Some(signer));
        assert_eq!(
            TempoSignature::Keychain(keychain)
                .recover_signer(&hash)
                .ok(),
            Some(user)
        );
    }
}
