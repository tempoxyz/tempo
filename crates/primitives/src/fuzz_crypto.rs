//! Keyed stand-ins for signatures, so a fuzzer can sign as any account without its key.
//!
//! A stand-in is a signature whose bytes are a hash of the signer's identity and of what it
//! signs. It still binds the message and the signer: a stand-in for another message or another
//! key is rejected. It only drops the need to hold the key, and the curve arithmetic.
//!
//! Checks accept stand-ins only after [`enable`], which only fuzzing harnesses call. Anything that
//! is not a stand-in goes through the real check, so real signatures behave as they always do.
//!
//! | Scheme | Stand-in |
//! |---|---|
//! | secp256k1 | `r` = [`tag`] of digest and signer, `s` = the signer's address |
//! | P256, WebAuthn | `r` = [`tag`] of digest and public key, `s` = 1 |
//! | Ed25519 | [`tag`] of key, namespace and message, then 32 zero bytes |
//! | P-384 | [`tag`] of key and digest, then zero bytes to the signature's width |

use crate::transaction::tt_signature::{
    P256SignatureWithPreHash, WebAuthnSignature, verify_webauthn_data_internal,
};
use alloy_primitives::{Address, B256, Bytes, Keccak256, Signature, U256};
use base64::Engine;
use core::sync::atomic::{AtomicBool, Ordering};
use sha2::{Digest, Sha256};

/// Version of the stand-in format, which harnesses report to fuzzers.
pub const VERSION: u32 = 1;

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Makes every check in this process accept stand-ins. Only fuzzing harnesses may call it.
pub fn enable() {
    ENABLED.store(true, Ordering::Relaxed);
}

/// Whether checks accept stand-ins.
#[inline]
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// The signature schemes stand-ins exist for, which separate their tags.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Scheme {
    Secp256k1 = 1,
    P256 = 2,
    Ed25519 = 3,
    P384 = 4,
}

/// The hash a stand-in carries: `keccak256("tempo-fuzz-crypto" || scheme || parts...)`.
pub fn tag(scheme: Scheme, parts: &[&[u8]]) -> B256 {
    let mut hasher = Keccak256::new();
    hasher.update(b"tempo-fuzz-crypto");
    hasher.update([scheme as u8]);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// The secp256k1 stand-in `(r, s)` for `signer` signing `digest`. Any recovery id works.
pub fn secp256k1(signer: Address, digest: &B256) -> (U256, U256) {
    let r = tag(Scheme::Secp256k1, &[digest.as_slice(), signer.as_slice()]);
    (r.into(), U256::from_be_slice(signer.as_slice()))
}

/// The signer of a secp256k1 stand-in, or `None` when `(r, s)` is not one for `digest`.
pub fn secp256k1_signer(r: &[u8], s: &[u8], digest: &[u8]) -> Option<Address> {
    if !enabled() || s.len() != 32 || s[..12] != [0; 12] {
        return None;
    }
    let signer = Address::from_slice(&s[12..]);
    (tag(Scheme::Secp256k1, &[digest, signer.as_slice()]) == r).then_some(signer)
}

/// The P256 stand-in `(r, s)` for the key `(x, y)` signing `digest`.
pub fn p256(digest: &B256, x: &B256, y: &B256) -> (B256, B256) {
    let r = tag(
        Scheme::P256,
        &[digest.as_slice(), x.as_slice(), y.as_slice()],
    );
    (r, B256::with_last_byte(1))
}

/// Whether `(r, s)` is the P256 stand-in for the key `(x, y)` signing `digest`. The key must still be
/// a point on the curve, as a real signature's must.
pub fn p256_accepts(r: &[u8], s: &[u8], x: &[u8], y: &[u8], digest: &[u8]) -> bool {
    if !enabled() || s != B256::with_last_byte(1) || tag(Scheme::P256, &[digest, x, y]) != r {
        return false;
    }
    let mut point = [0x04; 65];
    point[1..33].copy_from_slice(x);
    point[33..].copy_from_slice(y);
    p256::PublicKey::from_sec1_bytes(&point).is_ok()
}

/// The Ed25519 stand-in for `public_key` signing `message` under `namespace`.
pub fn ed25519(public_key: &[u8], namespace: &[u8], message: &[u8]) -> [u8; 64] {
    let namespace_len = (namespace.len() as u64).to_be_bytes();
    padded(tag(
        Scheme::Ed25519,
        &[public_key, &namespace_len, namespace, message],
    ))
}

/// Whether `signature` is the Ed25519 stand-in for `public_key` signing `message` under
/// `namespace`.
pub fn ed25519_accepts(
    public_key: &[u8],
    namespace: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    enabled() && signature == ed25519(public_key, namespace, message)
}

/// The P-384 stand-in for `public_key` signing `digest`, `N` bytes wide: 96 for COSE, any width of
/// at least 32 for an X.509 certificate.
pub fn p384<const N: usize>(public_key: &[u8], digest: &[u8]) -> [u8; N] {
    padded(tag(Scheme::P384, &[public_key, digest]))
}

/// Whether `signature` is the P-384 stand-in for `public_key` signing `digest`, at any width.
pub fn p384_accepts(public_key: &[u8], digest: &[u8], signature: &[u8]) -> bool {
    enabled()
        && signature.len() >= 32
        && signature[..32] == tag(Scheme::P384, &[public_key, digest])
        && signature[32..].iter().all(|byte| *byte == 0)
}

/// A secp256k1 stand-in signature by `signer` over `hash`: a transaction's or authorization's signature
/// hash, or a keychain V2 `KeychainSignature::signing_hash`.
pub fn secp256k1_signature(signer: Address, hash: &B256) -> Signature {
    let (r, s) = secp256k1(signer, hash);
    Signature::new(r, s, false)
}

/// A P256 stand-in signature by the key `(x, y)` over `hash`, pre-hashed with SHA-256 when
/// `pre_hash` is set, as the check then does.
pub fn p256_signature(hash: &B256, x: B256, y: B256, pre_hash: bool) -> P256SignatureWithPreHash {
    let digest = if pre_hash {
        B256::from_slice(&Sha256::digest(hash))
    } else {
        *hash
    };
    let (r, s) = p256(&digest, &x, &y);
    P256SignatureWithPreHash {
        r,
        s,
        pub_key_x: x,
        pub_key_y: y,
        pre_hash,
    }
}

/// A WebAuthn stand-in signature by the key `(x, y)` over `hash`, whose `webauthn_data` is
/// authenticatorData followed by clientDataJSON. Returns `None` when `webauthn_data` fails the
/// check's own WebAuthn rules, such as a challenge other than `hash`: those stay real.
pub fn webauthn_signature(
    hash: &B256,
    x: B256,
    y: B256,
    webauthn_data: Bytes,
) -> Option<WebAuthnSignature> {
    let digest = verify_webauthn_data_internal(&webauthn_data, hash).ok()?;
    let (r, s) = p256(&digest, &x, &y);
    Some(WebAuthnSignature {
        r,
        s,
        pub_key_x: x,
        pub_key_y: y,
        webauthn_data,
    })
}

/// The smallest `webauthn_data` the check accepts for `hash`: authenticatorData with only the
/// user-present flag, then a clientDataJSON of type `webauthn.get` challenging `hash`.
pub fn webauthn_data(hash: &B256) -> Bytes {
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    let mut data = alloc::vec![0; 32];
    data.push(0x01);
    data.extend_from_slice(&[0; 4]);
    data.extend_from_slice(br#"{"type":"webauthn.get","challenge":""#);
    data.extend_from_slice(challenge.as_bytes());
    data.extend_from_slice(br#"","origin":"https://tempo.xyz"}"#);
    data.into()
}

/// `tag` followed by zero bytes, `N` bytes wide.
fn padded<const N: usize>(tag: B256) -> [u8; N] {
    let mut out = [0; N];
    out[..32].copy_from_slice(tag.as_slice());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::tt_signature::{
        KeychainSignature, PrimitiveSignature, TempoSignature, p256_keypair,
    };

    #[test]
    fn stand_ins_bind_signer_and_message() {
        enable();
        let (digest, other) = (B256::repeat_byte(1), B256::repeat_byte(2));
        let signer = Address::repeat_byte(3);
        let (r, s) = secp256k1(signer, &digest);
        let (r, s) = (r.to_be_bytes::<32>(), s.to_be_bytes::<32>());
        assert_eq!(secp256k1_signer(&r, &s, digest.as_slice()), Some(signer));
        assert_eq!(secp256k1_signer(&r, &s, other.as_slice()), None);

        let (_, x, y, _) = p256_keypair();
        let (r, s) = p256(&digest, &x, &y);
        assert!(p256_accepts(
            r.as_slice(),
            s.as_slice(),
            x.as_slice(),
            y.as_slice(),
            digest.as_slice()
        ));
        assert!(!p256_accepts(
            r.as_slice(),
            s.as_slice(),
            x.as_slice(),
            y.as_slice(),
            other.as_slice()
        ));
        assert!(!p256_accepts(
            r.as_slice(),
            r.as_slice(),
            x.as_slice(),
            y.as_slice(),
            digest.as_slice()
        ));
        let (r, s) = p256(&digest, &x, &x);
        assert!(
            !p256_accepts(
                r.as_slice(),
                s.as_slice(),
                x.as_slice(),
                x.as_slice(),
                digest.as_slice()
            ),
            "off the curve"
        );

        let signature = ed25519(b"key", b"ns", b"msg");
        assert!(ed25519_accepts(b"key", b"ns", b"msg", &signature));
        assert!(!ed25519_accepts(b"key", b"nsm", b"sg", &signature));

        let signature = p384::<96>(b"key", b"digest");
        assert!(p384_accepts(b"key", b"digest", &signature));
        assert!(p384_accepts(
            b"key",
            b"digest",
            &p384::<32>(b"key", b"digest")
        ));
        assert!(!p384_accepts(b"other", b"digest", &signature));
    }

    #[test]
    fn p256_and_webauthn_stand_ins_recover_their_key_and_only_for_their_hash() {
        enable();
        let (hash, other) = (B256::repeat_byte(0xcc), B256::repeat_byte(0xdd));
        let (_, x, y, signer) = p256_keypair();

        for pre_hash in [false, true] {
            let signature = PrimitiveSignature::P256(p256_signature(&hash, x, y, pre_hash));
            assert_eq!(signature.recover_signer(&hash).ok(), Some(signer));
            assert!(signature.recover_signer(&other).is_err());
        }

        let signature = PrimitiveSignature::WebAuthn(
            webauthn_signature(&hash, x, y, webauthn_data(&hash)).unwrap(),
        );
        assert_eq!(signature.recover_signer(&hash).ok(), Some(signer));
        assert!(signature.recover_signer(&other).is_err());
        assert!(
            webauthn_signature(&hash, x, y, webauthn_data(&other)).is_none(),
            "a challenge for another hash stays invalid"
        );

        let user = Address::repeat_byte(0x42);
        let keychain = KeychainSignature::new(
            user,
            PrimitiveSignature::P256(p256_signature(
                &KeychainSignature::signing_hash(hash, user),
                x,
                y,
                false,
            )),
        );
        assert_eq!(keychain.key_id(&hash).ok(), Some(signer));
        let signature = TempoSignature::Keychain(keychain);
        assert_eq!(signature.recover_signer(&hash).ok(), Some(user));
    }
}
