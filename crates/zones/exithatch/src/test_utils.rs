//! Root-signature fixtures and structure-aware payload mutators for tests and fuzzing.
//!
//! Random byte mutation almost never survives the length gate or the canonical re-encoding
//! check, so the mutators here edit individual ABI words and signature fields while keeping the
//! rest of a valid payload intact.
use crate::{ForcedExitAuthorization, authorization_digest, encode_payload};
use alloc::{format, string::String, vec, vec::Vec};
use alloy_primitives::{Address, B256, U256, keccak256};
use core::ops::Range;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use proptest::{prelude::*, sample::Index};
use sha2::{Digest, Sha256};

pub use k256::ecdsa::SigningKey as K256Key;
pub use p256::ecdsa::SigningKey as P256Key;

/// ABI word holding the offset of the signature `bytes` tail.
pub const SIGNATURE_OFFSET_WORD: Range<usize> = 224..256;
/// ABI word holding the signature length.
pub const SIGNATURE_LENGTH_WORD: Range<usize> = 256..288;
/// Static head words narrower than 32 bytes: (word index, value width in bytes).
const NARROW_WORDS: [(usize, usize); 5] = [(0, 1), (1, 20), (3, 20), (4, 20), (6, 8)];

const SECP256K1_N: U256 = U256::from_be_bytes(alloy_primitives::hex!(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
));
const P256_N: U256 = U256::from_be_bytes(alloy_primitives::hex!(
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
));
/// Type byte, 37-byte authenticator data and the trailing r, s, x, y words.
const WEBAUTHN_OVERHEAD: usize = 1 + 37 + 128;

pub fn k256_key(seed: u64) -> K256Key {
    K256Key::from_slice(&U256::from(seed).to_be_bytes::<32>()).expect("nonzero seed")
}

pub fn k256_account(key: &K256Key) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// 65-byte `r || s || v` with `v` in {0, 1}.
pub fn sign_k256(key: &K256Key, digest: B256) -> Vec<u8> {
    let (sig, recovery) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    bytes
}

pub fn p256_key(seed: u64) -> P256Key {
    P256Key::from_slice(&U256::from(seed).to_be_bytes::<32>()).expect("nonzero seed")
}

pub fn p256_account(key: &P256Key) -> Address {
    let point = key.verifying_key().to_encoded_point(false);
    Address::from_slice(&keccak256(&point.as_bytes()[1..])[12..])
}

/// Low-s `r || s || x || y` over `hash`.
fn p256_tail(key: &P256Key, hash: &[u8]) -> Vec<u8> {
    let sig: p256::ecdsa::Signature = key.sign_prehash(hash).unwrap();
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut bytes = sig.to_bytes().to_vec();
    bytes.extend_from_slice(&key.verifying_key().to_encoded_point(false).as_bytes()[1..]);
    bytes
}

/// 130-byte TIP-0001 P256 primitive.
pub fn sign_p256(key: &P256Key, digest: B256, pre_hash: bool) -> Vec<u8> {
    let hash: [u8; 32] = if pre_hash {
        Sha256::digest(digest).into()
    } else {
        digest.0
    };
    let mut bytes = vec![1];
    bytes.extend_from_slice(&p256_tail(key, &hash));
    bytes.push(u8::from(pre_hash));
    bytes
}

/// Base64url without padding, encoded independently of the verifier.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in (0..4).take(chunk.len() + 1) {
            out.push(ALPHABET[((value >> (18 - 6 * shift)) & 63) as usize] as char);
        }
    }
    out
}

/// TIP-0001 WebAuthn primitive of exactly `length` bytes. The client data JSON is padded with a
/// field the verifier ignores, so `length = MAX_SIGNATURE_SIZE` gives the largest request.
pub fn sign_webauthn(key: &P256Key, digest: B256, length: usize) -> Vec<u8> {
    let challenge = base64url(digest.as_slice());
    let base = format!(r#"{{"type":"webauthn.get","challenge":"{challenge}","pad":""}}"#);
    let pad = length
        .checked_sub(WEBAUTHN_OVERHEAD + base.len())
        .expect("WebAuthn length too small");
    let json = format!(
        r#"{{"type":"webauthn.get","challenge":"{challenge}","pad":"{}"}}"#,
        "p".repeat(pad)
    );
    let mut auth_data = vec![0u8; 37];
    auth_data[32] = 1; // UP
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(json.as_bytes()));
    let mut bytes = vec![2];
    bytes.extend_from_slice(&auth_data);
    bytes.extend_from_slice(json.as_bytes());
    bytes.extend_from_slice(&p256_tail(key, &Sha256::digest(signed)));
    debug_assert_eq!(bytes.len(), length);
    bytes
}

/// Canonical plaintext for `auth` signed by a secp256k1 root key.
pub fn signed_payload(
    key: &K256Key,
    auth: &ForcedExitAuthorization,
    l1_chain_id: u64,
    portal: Address,
) -> Vec<u8> {
    let digest = authorization_digest(auth, U256::from(l1_chain_id), portal);
    encode_payload(auth, &sign_k256(key, digest))
}

/// Replacement value for one ABI word.
#[derive(Clone, Debug)]
pub enum WordValue {
    Delta(i64),
    /// The word's own byte position, a classic self-referencing offset.
    SelfPointing,
    /// One byte past the end of the payload.
    PastEnd,
    Zero,
    Max,
}

impl WordValue {
    pub fn apply(&self, payload: &mut [u8], word: Range<usize>) {
        let current = U256::from_be_slice(&payload[word.clone()]);
        let value = match self {
            Self::Delta(delta) if *delta >= 0 => current.wrapping_add(U256::from(*delta)),
            Self::Delta(delta) => current.wrapping_sub(U256::from(delta.unsigned_abs())),
            Self::SelfPointing => U256::from(word.start),
            Self::PastEnd => U256::from(payload.len() + 1),
            Self::Zero => U256::ZERO,
            Self::Max => U256::MAX,
        };
        payload[word].copy_from_slice(&value.to_be_bytes::<32>());
    }
}

fn word_value() -> impl Strategy<Value = WordValue> {
    prop_oneof![
        prop::sample::select(vec![-32i64, -1, 1, 32]).prop_map(WordValue::Delta),
        Just(WordValue::SelfPointing),
        Just(WordValue::PastEnd),
        Just(WordValue::Zero),
        Just(WordValue::Max),
    ]
}

/// Structural edit of a canonical payload that leaves every other word untouched.
#[derive(Clone, Debug)]
pub enum PayloadMutation {
    Offset(WordValue),
    Length(WordValue),
    /// Nonzero byte in the signature's right padding (a no-op for word-aligned signatures).
    TailPadding(u8),
    /// Nonzero byte above the value width of a version, address or uint64 head word.
    DirtyHighBits {
        word: Index,
        byte: Index,
        value: u8,
    },
    InsertWord {
        at: Index,
        fill: u8,
    },
    DropWord {
        at: Index,
    },
}

impl PayloadMutation {
    pub fn apply(&self, payload: &[u8]) -> Vec<u8> {
        let mut out = payload.to_vec();
        let words = out.len() / 32;
        match self {
            Self::Offset(value) => value.apply(&mut out, SIGNATURE_OFFSET_WORD),
            Self::Length(value) => value.apply(&mut out, SIGNATURE_LENGTH_WORD),
            Self::TailPadding(value) => {
                let signature_len =
                    U256::from_be_slice(&out[SIGNATURE_LENGTH_WORD]).saturating_to::<usize>();
                if !signature_len.is_multiple_of(32) {
                    *out.last_mut().unwrap() = *value;
                }
            }
            Self::DirtyHighBits { word, byte, value } => {
                let (word, width) = NARROW_WORDS[word.index(NARROW_WORDS.len())];
                out[word * 32 + byte.index(32 - width)] = *value;
            }
            Self::InsertWord { at, fill } => {
                let at = at.index(words + 1) * 32;
                out.splice(at..at, [*fill; 32]);
            }
            Self::DropWord { at } => {
                let at = at.index(words) * 32;
                out.drain(at..at + 32);
            }
        }
        out
    }

    /// Whether the mutation keeps the plaintext inside the admitted ciphertext size range.
    pub fn keeps_valid_length(&self, payload: &[u8]) -> bool {
        crate::valid_ciphertext_length(self.apply(payload).len())
    }
}

pub fn payload_mutation() -> impl Strategy<Value = PayloadMutation> {
    prop_oneof![
        word_value().prop_map(PayloadMutation::Offset),
        word_value().prop_map(PayloadMutation::Length),
        (1u8..).prop_map(PayloadMutation::TailPadding),
        (any::<Index>(), any::<Index>(), 1u8..).prop_map(|(word, byte, value)| {
            PayloadMutation::DirtyHighBits { word, byte, value }
        }),
        (any::<Index>(), any::<u8>())
            .prop_map(|(at, fill)| PayloadMutation::InsertWord { at, fill }),
        any::<Index>().prop_map(|at| PayloadMutation::DropWord { at }),
    ]
}

/// Edit of one field of an otherwise valid root signature.
#[derive(Clone, Debug)]
pub enum SignatureMutation {
    /// Replace the type byte of a typed primitive, or prepend one to a 65-byte secp256k1 one.
    TypeByte(u8),
    /// Truncate or zero-extend to a length on a TIP-0001 boundary.
    Resize(usize),
    /// Replace the secp256k1 recovery byte.
    RecoveryByte(u8),
    /// Replace `s` with `n - s` (and flip the secp256k1 parity).
    HighS,
    /// Replace the P256 `pre_hash` boolean.
    PreHash(u8),
    WebAuthnFlags(u8),
    /// Flip one character (0..43) of the WebAuthn challenge.
    WebAuthnChallenge(usize),
    /// Wrap the signature in a keychain envelope for the root account.
    Keychain(u8),
    FlipBit(Index, u8),
}

impl SignatureMutation {
    pub fn apply(&self, signature: &[u8], account: Address) -> Vec<u8> {
        let mut out = signature.to_vec();
        let secp256k1 = out.len() == 65;
        match self {
            Self::TypeByte(byte) if secp256k1 => out.insert(0, *byte),
            Self::TypeByte(byte) => out[0] = *byte,
            Self::Resize(length) => out.resize(*length, 0),
            Self::RecoveryByte(v) if secp256k1 => out[64] = *v,
            Self::HighS => {
                let s = if secp256k1 {
                    32..64
                } else if out.first() == Some(&2) {
                    out.len() - 96..out.len() - 64
                } else {
                    33..65
                };
                let n = if secp256k1 { SECP256K1_N } else { P256_N };
                let high = n - U256::from_be_slice(&out[s.clone()]);
                out[s].copy_from_slice(&high.to_be_bytes::<32>());
                if secp256k1 {
                    out[64] ^= 1;
                }
            }
            Self::PreHash(byte) if out.len() == 130 && out[0] == 1 => out[129] = *byte,
            Self::WebAuthnFlags(flags) if out.first() == Some(&2) => out[1 + 32] = *flags,
            Self::WebAuthnChallenge(position) if out.first() == Some(&2) => {
                let json = &out[38..out.len() - 128];
                let marker = br#""challenge":""#;
                if let Some(start) = json.windows(marker.len()).position(|w| w == marker) {
                    let at = 38 + start + marker.len() + position % 43;
                    out[at] = if out[at] == b'A' { b'B' } else { b'A' };
                }
            }
            Self::Keychain(prefix) => {
                let mut envelope = vec![*prefix];
                envelope.extend_from_slice(account.as_slice());
                envelope.extend_from_slice(&out);
                out = envelope;
            }
            Self::FlipBit(index, bit) => {
                let at = index.index(out.len());
                out[at] ^= 1 << (bit % 8);
            }
            _ => {}
        }
        out
    }
}

pub fn signature_mutation() -> impl Strategy<Value = SignatureMutation> {
    prop_oneof![
        any::<u8>().prop_map(SignatureMutation::TypeByte),
        prop::sample::select(vec![0usize, 1, 64, 65, 66, 129, 130, 131, 2049, 2050])
            .prop_map(SignatureMutation::Resize),
        prop_oneof![
            prop::sample::select(vec![0u8, 1, 2, 26, 27, 28, 29, 35, 36]),
            any::<u8>()
        ]
        .prop_map(SignatureMutation::RecoveryByte),
        Just(SignatureMutation::HighS),
        (2u8..).prop_map(SignatureMutation::PreHash),
        any::<u8>().prop_map(SignatureMutation::WebAuthnFlags),
        (0usize..43).prop_map(SignatureMutation::WebAuthnChallenge),
        prop::sample::select(vec![3u8, 4]).prop_map(SignatureMutation::Keychain),
        (any::<Index>(), any::<u8>()).prop_map(|(i, b)| SignatureMutation::FlipBit(i, b)),
    ]
}

/// Whether `mutated` is a secp256k1 encoding that alloy normalizes to the same signature as
/// `original`: the same `r` and `s` with an equivalent `v` (0/1, 27/28 or any EIP-155 value
/// >= 35). High-s twins are not included; recovery rejects them.
pub fn is_secp256k1_malleation(original: &[u8], mutated: &[u8]) -> bool {
    fn parity(v: u8) -> Option<bool> {
        match v {
            0 | 27 => Some(false),
            1 | 28 => Some(true),
            35.. => Some((v - 35) % 2 == 1),
            _ => None,
        }
    }
    original.len() == 65
        && mutated.len() == 65
        && original[..64] == mutated[..64]
        && parity(original[64]).is_some()
        && parity(original[64]) == parity(mutated[64])
}
