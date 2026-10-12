//! Sequencer-side ECIES operations for encrypted deposit decryption.
//!
//! These functions run **off-chain** in the payload builder to produce the
//! `DecryptionData` that the native ZoneInbox verifies with its Chaum-Pedersen
//! and AES-GCM implementations.

use alloc::vec::Vec;

use ::aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use alloy_primitives::{Address, B256};
use k256::{
    AffinePoint, ProjectivePoint, Scalar,
    elliptic_curve::{PrimeField, sec1::ToEncodedPoint},
};
use tempo_contracts::zones::{ChaumPedersenProof, Withdrawal};

use crate::{
    aes_gcm,
    chaum_pedersen::{challenge_hash, recover_point},
};

/// Plaintext size for encrypted deposits: 20 bytes (address) + 32 bytes (memo) + 12 bytes (padding).
pub const ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE: usize = 64;

/// Plaintext size for authenticated-withdrawal sender reveals: 20 bytes (sender) + 32 bytes (tx hash).
pub const AUTHENTICATED_WITHDRAWAL_PLAINTEXT_SIZE: usize = 52;

/// Encoded size of a compressed secp256k1 public key.
pub const COMPRESSED_PUBLIC_KEY_SIZE: usize = 33;

/// Total encoded size of `encryptedSender`.
pub const AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE: usize =
    COMPRESSED_PUBLIC_KEY_SIZE + 12 + AUTHENTICATED_WITHDRAWAL_PLAINTEXT_SIZE + 16;

/// Decode a SEC1-compressed secp256k1 public key.
pub(crate) fn decode_compressed_public_key(encoded: &[u8]) -> Option<AffinePoint> {
    let encoded: &[u8; COMPRESSED_PUBLIC_KEY_SIZE] = encoded.try_into().ok()?;
    let parity = encoded[0];
    if !matches!(parity, 0x02 | 0x03) {
        return None;
    }
    let x: &[u8; 32] = encoded[1..].try_into().ok()?;
    recover_point(x, parity)
}

const AUTH_WITHDRAWAL_EPHEMERAL_DOMAIN: &[u8] = b"tempo-zone-authenticated-withdrawal-ephemeral-v2";
const AUTH_WITHDRAWAL_NONCE_DOMAIN: &[u8] = b"tempo-zone-authenticated-withdrawal-nonce-v2";
const AUTH_WITHDRAWAL_DERIVATION_KEY_DOMAIN: &[u8] =
    b"tempo-zone-authenticated-withdrawal-derivation-key-v1";
const CP_NONCE_DOMAIN: &[u8] = b"tempo-zone-chaum-pedersen-nonce-v1";

/// Result of sequencer-side ECDH + Chaum-Pedersen proof derivation.
///
/// This is always producible as long as the ephemeral public key is valid
/// (on the secp256k1 curve). It does **not** depend on AES-GCM decryption
/// succeeding, so the sequencer can always provide a valid proof to the
/// on-chain contract — enabling the refund path for garbage ciphertext
/// instead of reverting with `InvalidSharedSecretProof`.
#[derive(Debug, Clone)]
pub struct EcdhProofResult {
    /// ECDH shared secret (x-coordinate of `privSeq * ephemeralPub`).
    pub shared_secret: B256,
    /// Y parity of the shared secret point (0x02 or 0x03).
    pub shared_secret_y_parity: u8,
    /// Chaum-Pedersen proof of correct shared secret derivation.
    pub cp_proof: ChaumPedersenProof,
}

/// Result of sequencer-side ECIES decryption of an encrypted deposit.
#[derive(Debug, Clone)]
pub struct DecryptedDeposit {
    /// ECDH shared secret and Chaum-Pedersen proof.
    pub proof: EcdhProofResult,
    /// Decrypted recipient address.
    pub to: Address,
    /// Decrypted memo.
    pub memo: B256,
}

/// Compute ECDH shared secret and Chaum-Pedersen proof for an encrypted deposit.
///
/// This succeeds as long as the ephemeral public key is a valid secp256k1 point.
/// It does **not** attempt AES-GCM decryption, so it can always provide the
/// on-chain contract with a valid proof — enabling the refund path for deposits
/// with garbage ciphertext instead of reverting.
///
/// Returns `None` if the ephemeral public key cannot be recovered or proof generation fails.
pub fn compute_ecdh_proof(
    sequencer_privkey: &k256::SecretKey,
    ephemeral_pub_x: &B256,
    ephemeral_pub_y_parity: u8,
) -> Option<EcdhProofResult> {
    // 1. Recover ephemeral public key
    let ephemeral_pub = recover_point(&ephemeral_pub_x.0, ephemeral_pub_y_parity)?;

    // 2. ECDH: sharedSecretPoint = privSeq * ephemeralPub
    let priv_scalar: Scalar = *sequencer_privkey.to_nonzero_scalar();
    let shared_secret_proj = ProjectivePoint::from(ephemeral_pub) * priv_scalar;
    let shared_secret_affine = AffinePoint::from(shared_secret_proj);

    let ss_encoded = shared_secret_affine.to_encoded_point(true);
    let shared_secret_x: [u8; 32] = ss_encoded.x()?.as_slice().try_into().ok()?;
    let shared_secret_y_parity = ss_encoded.as_bytes()[0]; // 0x02 or 0x03

    // 3. Generate Chaum-Pedersen proof
    let sequencer_pub = AffinePoint::from(ProjectivePoint::GENERATOR * priv_scalar);
    let (s, c) = generate_chaum_pedersen_proof(
        &priv_scalar,
        &ephemeral_pub,
        &shared_secret_affine,
        &sequencer_pub,
    )?;

    Some(EcdhProofResult {
        shared_secret: B256::from(shared_secret_x),
        shared_secret_y_parity,
        cp_proof: ChaumPedersenProof {
            s: B256::from_slice(s.to_repr().as_ref()),
            c: B256::from_slice(c.to_repr().as_ref()),
        },
    })
}

/// Perform ECIES decryption of an encrypted deposit using the sequencer's private key.
///
/// This implements the full ECIES flow:
/// 1. ECDH: compute `sharedSecret = privSeq * ephemeralPub`
/// 2. HKDF-SHA256: derive AES key from shared secret and deposit sender
/// 3. AES-256-GCM: decrypt ciphertext and verify tag
/// 4. Parse plaintext into `(to, memo)`
/// 5. Generate Chaum-Pedersen proof of correct shared secret derivation
///
/// Returns `None` if any step fails (invalid point, decryption failure, etc.).
pub fn decrypt_deposit(
    sequencer_privkey: &k256::SecretKey,
    ephemeral_pub_x: &B256,
    ephemeral_pub_y_parity: u8,
    ciphertext: &[u8],
    nonce: &[u8; 12],
    tag: &[u8; 16],
    portal_address: Address,
    key_index: alloy_primitives::U256,
    sender: Address,
) -> Option<DecryptedDeposit> {
    let proof = compute_ecdh_proof(sequencer_privkey, ephemeral_pub_x, ephemeral_pub_y_parity)?;

    // HKDF-SHA256: derive AES key
    let info = hkdf_info(&portal_address, &key_index, ephemeral_pub_x, &sender);
    let aes_key = hkdf_sha256(&proof.shared_secret.0, b"ecies-aes-key", &info);

    // AES-256-GCM decrypt
    let (plaintext, valid) = aes_gcm::decrypt(&aes_key, nonce, ciphertext, &[], tag);
    if !valid || plaintext.len() != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE {
        return None;
    }

    // Parse plaintext: [address(20)][memo(32)][padding(12)]
    let to = Address::from_slice(&plaintext[..20]);
    let memo = B256::from_slice(&plaintext[20..52]);

    Some(DecryptedDeposit { proof, to, memo })
}

/// Result of client-side ECIES encryption for a deposit.
///
/// Contains all fields needed to call `ZonePortal.deposit`.
pub struct EncryptedDepositArgs {
    /// Ephemeral public key x-coordinate.
    pub eph_pub_x: B256,
    /// Ephemeral public key y-parity (0x02 or 0x03).
    pub eph_pub_y_parity: u8,
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// AES-256-GCM nonce.
    pub nonce: [u8; 12],
    /// AES-256-GCM authentication tag.
    pub tag: [u8; 16],
}

/// Encrypt `(sender, tx_hash)` for authenticated withdrawals.
///
/// The output is:
/// `compressed_ephemeral_pubkey(33) || nonce(12) || ciphertext(52) || tag(16)`.
pub fn encrypt_authenticated_withdrawal(
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
) -> Option<Vec<u8>> {
    let eph_key = k256::SecretKey::random(&mut rand::thread_rng());
    let eph_scalar: Scalar = *eph_key.to_nonzero_scalar();
    let nonce_bytes: [u8; 12] = rand::random();

    encrypt_authenticated_withdrawal_with_material(
        reveal_to,
        sender,
        tx_hash,
        &eph_scalar,
        nonce_bytes,
    )
}

/// Deterministically encrypt `(sender, tx_hash)` for authenticated withdrawals.
///
/// This is the consensus-safe variant used by zone payload construction. It
/// derives both the ECIES ephemeral scalar and AES-GCM nonce from the sequencer
/// encryption key, zone id, reveal key, sender, withdrawal transaction hash, and fallback nonce.
pub fn encrypt_authenticated_withdrawal_deterministic(
    encryption_privkey: &k256::SecretKey,
    zone_id: u32,
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
    fallback_nonce: u64,
) -> Option<Vec<u8>> {
    let derivation_key = authenticated_withdrawal_derivation_key(encryption_privkey);
    let eph_scalar = derive_authenticated_withdrawal_ephemeral_scalar(
        &derivation_key,
        zone_id,
        reveal_to,
        sender,
        tx_hash,
        fallback_nonce,
    )?;
    let eph_pub = AffinePoint::from(ProjectivePoint::GENERATOR * eph_scalar);
    let eph_encoded = eph_pub.to_encoded_point(true);
    let eph_pubkey: [u8; 33] = eph_encoded.as_bytes().try_into().ok()?;
    let nonce_bytes = derive_authenticated_withdrawal_nonce(
        &derivation_key,
        zone_id,
        reveal_to,
        sender,
        tx_hash,
        fallback_nonce,
        &eph_pubkey,
    );

    encrypt_authenticated_withdrawal_with_material(
        reveal_to,
        sender,
        tx_hash,
        &eph_scalar,
        nonce_bytes,
    )
}

fn encrypt_authenticated_withdrawal_with_material(
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
    eph_scalar: &Scalar,
    nonce_bytes: [u8; 12],
) -> Option<Vec<u8>> {
    let reveal_pub = decode_compressed_public_key(reveal_to)?;

    let eph_pub = AffinePoint::from(ProjectivePoint::GENERATOR * *eph_scalar);
    let eph_encoded = eph_pub.to_encoded_point(true);
    let eph_pubkey: [u8; 33] = eph_encoded.as_bytes().try_into().ok()?;

    let shared_proj = ProjectivePoint::from(reveal_pub) * *eph_scalar;
    let shared_affine = AffinePoint::from(shared_proj);
    let ss_encoded = shared_affine.to_encoded_point(true);
    let shared_secret_x: [u8; 32] = ss_encoded.x()?.as_slice().try_into().ok()?;

    let info = authenticated_withdrawal_hkdf_info(&eph_pubkey);
    let aes_key = hkdf_sha256(&shared_secret_x, b"authenticated-withdrawal-aes-key", &info);

    let plaintext = build_authenticated_withdrawal_plaintext(&sender, &tx_hash);
    let cipher = Aes256Gcm::new((&aes_key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).ok()?;
    let ciphertext = &encrypted[..encrypted.len() - 16];
    let tag = &encrypted[encrypted.len() - 16..];

    let mut out = Vec::with_capacity(AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE);
    out.extend_from_slice(&eph_pubkey);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(ciphertext);
    out.extend_from_slice(tag);
    Some(out)
}

fn derive_authenticated_withdrawal_ephemeral_scalar(
    derivation_key: &[u8; 32],
    zone_id: u32,
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
    fallback_nonce: u64,
) -> Option<Scalar> {
    for counter in 0u32.. {
        let mut msg = authenticated_withdrawal_context(
            AUTH_WITHDRAWAL_EPHEMERAL_DOMAIN,
            zone_id,
            reveal_to,
            sender,
            tx_hash,
            fallback_nonce,
        );
        msg.extend_from_slice(&counter.to_be_bytes());

        let candidate = hmac_sha256(derivation_key, &msg);
        if let Ok(key) = k256::SecretKey::from_slice(&candidate) {
            return Some(*key.to_nonzero_scalar());
        }
    }

    None
}

fn derive_authenticated_withdrawal_nonce(
    derivation_key: &[u8; 32],
    zone_id: u32,
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
    fallback_nonce: u64,
    eph_pubkey: &[u8; 33],
) -> [u8; 12] {
    let mut msg = authenticated_withdrawal_context(
        AUTH_WITHDRAWAL_NONCE_DOMAIN,
        zone_id,
        reveal_to,
        sender,
        tx_hash,
        fallback_nonce,
    );
    msg.extend_from_slice(eph_pubkey);

    let digest = hmac_sha256(derivation_key, &msg);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

fn authenticated_withdrawal_derivation_key(encryption_privkey: &k256::SecretKey) -> [u8; 32] {
    let secret = encryption_privkey.to_bytes();
    // Derive a purpose-specific HMAC key first, so the raw ECIES private scalar
    // is not reused directly across the ephemeral-scalar and nonce derivations.
    hmac_sha256(&secret, AUTH_WITHDRAWAL_DERIVATION_KEY_DOMAIN)
}

fn authenticated_withdrawal_context(
    domain: &[u8],
    zone_id: u32,
    reveal_to: &[u8],
    sender: Address,
    tx_hash: B256,
    fallback_nonce: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(domain.len() + 4 + 4 + reveal_to.len() + 20 + 32 + 8);
    msg.extend_from_slice(domain);
    msg.extend_from_slice(&zone_id.to_be_bytes());
    msg.extend_from_slice(&(reveal_to.len() as u32).to_be_bytes());
    msg.extend_from_slice(reveal_to);
    msg.extend_from_slice(sender.as_slice());
    msg.extend_from_slice(tx_hash.as_slice());
    msg.extend_from_slice(&fallback_nonce.to_be_bytes());
    msg
}

/// Decrypt an authenticated-withdrawal `encryptedSender` payload.
pub fn decrypt_authenticated_withdrawal(
    reveal_privkey: &k256::SecretKey,
    encrypted_sender: &[u8],
) -> Option<(Address, B256)> {
    if encrypted_sender.len() != AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE {
        return None;
    }

    let parity = encrypted_sender[0];
    if parity != 0x02 && parity != 0x03 {
        return None;
    }

    let eph_pub_x = B256::from_slice(&encrypted_sender[1..33]);
    let nonce: [u8; 12] = encrypted_sender[33..45].try_into().ok()?;
    let ciphertext = &encrypted_sender[45..97];
    let tag: [u8; 16] = encrypted_sender[97..113].try_into().ok()?;

    let eph_pub = recover_point(&eph_pub_x.0, parity)?;
    let priv_scalar: Scalar = *reveal_privkey.to_nonzero_scalar();
    let shared_proj = ProjectivePoint::from(eph_pub) * priv_scalar;
    let shared_affine = AffinePoint::from(shared_proj);
    let ss_encoded = shared_affine.to_encoded_point(true);
    let shared_secret_x: [u8; 32] = ss_encoded.x()?.as_slice().try_into().ok()?;

    let mut eph_pubkey = [0u8; 33];
    eph_pubkey[0] = parity;
    eph_pubkey[1..].copy_from_slice(eph_pub_x.as_slice());
    let info = authenticated_withdrawal_hkdf_info(&eph_pubkey);
    let aes_key = hkdf_sha256(&shared_secret_x, b"authenticated-withdrawal-aes-key", &info);

    let (plaintext, valid) = aes_gcm::decrypt(&aes_key, &nonce, ciphertext, &[], &tag);
    if !valid || plaintext.len() != AUTHENTICATED_WITHDRAWAL_PLAINTEXT_SIZE {
        return None;
    }

    let sender = Address::from_slice(&plaintext[..20]);
    let tx_hash = B256::from_slice(&plaintext[20..]);
    Some((sender, tx_hash))
}

/// Encrypt deposit data for `ZonePortal.deposit`.
///
/// This is the depositor-side counterpart of [`decrypt_deposit`] — it performs
/// ECIES encryption of `(to, memo)` to the sequencer's public key:
/// 1. Recover sequencer public key from `(seq_pub_x, seq_pub_y_parity)`
/// 2. Generate ephemeral key pair
/// 3. ECDH: `sharedSecret = ephPriv * sequencerPub`
/// 4. HKDF-SHA256: derive AES key from the shared secret and deposit sender
/// 5. AES-256-GCM encrypt `[to(20) | memo(32) | padding(12)]`
pub fn encrypt_deposit(
    seq_pub_x: &B256,
    seq_pub_y_parity: u8,
    to: Address,
    memo: B256,
    sender: Address,
    portal_address: Address,
    key_index: alloy_primitives::U256,
) -> Option<EncryptedDepositArgs> {
    // 1. Recover sequencer public key
    let seq_pub = recover_point(&seq_pub_x.0, seq_pub_y_parity)?;

    // 2. Generate ephemeral key pair
    let eph_key = k256::SecretKey::random(&mut rand::thread_rng());
    let eph_scalar: Scalar = *eph_key.to_nonzero_scalar();
    let eph_pub = AffinePoint::from(ProjectivePoint::GENERATOR * eph_scalar);
    let (eph_pub_x, eph_pub_y_parity) = compressed_x_and_parity(&eph_pub);

    // 3. ECDH: shared = eph_scalar * sequencer_pub
    let shared_proj = ProjectivePoint::from(seq_pub) * eph_scalar;
    let shared_affine = AffinePoint::from(shared_proj);
    let ss_enc = shared_affine.to_encoded_point(true);
    let shared_secret_x: [u8; 32] = ss_enc.x()?.as_slice().try_into().ok()?;

    // 4. HKDF key derivation
    let info = hkdf_info(&portal_address, &key_index, &eph_pub_x, &sender);
    let aes_key = hkdf_sha256(&shared_secret_x, b"ecies-aes-key", &info);

    // 5. Encrypt plaintext with random nonce
    let plaintext = build_plaintext(&to, &memo);
    let cipher = Aes256Gcm::new((&aes_key).into());
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).ok()?;
    let ciphertext = encrypted[..encrypted.len() - 16].to_vec();
    let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().ok()?;

    Some(EncryptedDepositArgs {
        eph_pub_x,
        eph_pub_y_parity,
        ciphertext,
        nonce: nonce_bytes,
        tag,
    })
}

/// Generate a Chaum-Pedersen proof that `sharedSecret = privSeq * ephemeralPub`.
///
/// Returns `(s, c)` proof scalars.
fn generate_chaum_pedersen_proof(
    priv_seq: &Scalar,
    ephemeral_pub: &AffinePoint,
    shared_secret: &AffinePoint,
    sequencer_pub: &AffinePoint,
) -> Option<(Scalar, Scalar)> {
    // The proof is included in advanceTempo calldata, so runtime randomness here
    // would make otherwise identical zone blocks diverge. Derive the blinding
    // scalar from the encryption key and the complete public statement instead.
    let k = deterministic_cp_nonce(priv_seq, ephemeral_pub, sequencer_pub, shared_secret)?;
    let r1 = AffinePoint::from(ProjectivePoint::GENERATOR * k);
    let r2 = AffinePoint::from(ProjectivePoint::from(*ephemeral_pub) * k);

    // 2. Challenge via shared helper
    let c = challenge_hash(ephemeral_pub, sequencer_pub, shared_secret, &r1, &r2);

    // 3. Response: s = k + c * privSeq
    let s = k + c * priv_seq;

    Some((s, c))
}

/// Domain-separated deterministic Chaum-Pedersen nonce derivation.
///
/// Invalid scalar candidates are retried with a counter.
fn deterministic_cp_nonce(
    priv_seq: &Scalar,
    ephemeral_pub: &AffinePoint,
    sequencer_pub: &AffinePoint,
    shared_secret: &AffinePoint,
) -> Option<Scalar> {
    // Although the latter two points are derived from `priv_seq` and `ephemeral_pub`,
    // include the complete public statement so every challenge input also binds the nonce.
    let ephemeral_pub = ephemeral_pub.to_encoded_point(true);
    let sequencer_pub = sequencer_pub.to_encoded_point(true);
    let shared_secret = shared_secret.to_encoded_point(true);
    let mut input = Vec::with_capacity(CP_NONCE_DOMAIN.len() + 33 * 3 + 4);
    input.extend_from_slice(CP_NONCE_DOMAIN);
    input.extend_from_slice(ephemeral_pub.as_bytes());
    input.extend_from_slice(sequencer_pub.as_bytes());
    input.extend_from_slice(shared_secret.as_bytes());

    let secret = priv_seq.to_bytes();
    for counter in 0..=u32::MAX {
        input.extend_from_slice(&counter.to_be_bytes());
        let candidate = hmac_sha256(secret.as_ref(), &input);

        if let Ok(nonce) = k256::SecretKey::from_slice(&candidate) {
            return Some(*nonce.to_nonzero_scalar());
        }

        // Reset to try another counter
        input.truncate(input.len() - 4);
    }

    // Astronomically impossible that we didn't find a valid scalar, so if we're here, its a bug,
    // return None
    None
}

/// HMAC-SHA256 implementation matching ZoneInbox._hmacSha256.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    // Pad/hash key to 64 bytes
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // Inner hash: SHA256(ipad || message)
    let mut hasher = Sha256::new();
    hasher.update(ipad);
    hasher.update(message);
    let inner_hash = hasher.finalize();

    // Outer hash: SHA256(opad || innerHash)
    let mut hasher = Sha256::new();
    hasher.update(opad);
    hasher.update(inner_hash);
    let result = hasher.finalize();

    result.into()
}

/// HKDF-SHA256 key derivation matching ZoneInbox._hkdfSha256.
pub fn hkdf_sha256(ikm: &[u8; 32], salt: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let prk = hmac_sha256(salt, ikm);

    // Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
    let mut expand_input = Vec::with_capacity(info.len() + 1);
    expand_input.extend_from_slice(info);
    expand_input.push(0x01);
    hmac_sha256(&prk, &expand_input)
}

/// Extract the compressed x-coordinate and SEC1 parity byte from an affine point.
pub fn compressed_x_and_parity(point: &AffinePoint) -> (B256, u8) {
    let encoded = point.to_encoded_point(true);
    let x = B256::from_slice(encoded.x().unwrap().as_slice());
    let parity = encoded.as_bytes()[0];
    (x, parity)
}

/// Build a 64-byte plaintext from address + memo: `[to(20)|memo(32)|padding(12)]`.
pub fn build_plaintext(to: &Address, memo: &B256) -> [u8; ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE] {
    let mut buf = [0u8; ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE];
    buf[..20].copy_from_slice(to.as_slice());
    buf[20..52].copy_from_slice(memo.as_slice());
    // bytes 52..64 are zero padding
    buf
}

/// Build authenticated-withdrawal sender plaintext: `[sender(20)|tx_hash(32)]`.
pub fn build_authenticated_withdrawal_plaintext(
    sender: &Address,
    tx_hash: &B256,
) -> [u8; AUTHENTICATED_WITHDRAWAL_PLAINTEXT_SIZE] {
    Withdrawal::authenticated_sender_plaintext(*sender, *tx_hash)
}

/// Build the 104-byte HKDF info parameter:
/// `[portal(20) | key_index(32) | eph_pub_x(32) | sender(20)]`.
pub fn hkdf_info(
    portal: &Address,
    key_index: &alloy_primitives::U256,
    eph_pub_x: &B256,
    sender: &Address,
) -> [u8; 104] {
    let mut info = [0u8; 104];
    info[..20].copy_from_slice(portal.as_slice());
    info[20..52].copy_from_slice(&key_index.to_be_bytes::<32>());
    info[52..84].copy_from_slice(&eph_pub_x.0);
    info[84..].copy_from_slice(sender.as_slice());
    info
}

fn authenticated_withdrawal_hkdf_info(eph_pubkey: &[u8; 33]) -> Vec<u8> {
    let mut info = Vec::with_capacity(24 + eph_pubkey.len());
    info.extend_from_slice(b"authenticated-withdrawal");
    info.extend_from_slice(eph_pubkey);
    info
}

/// Encrypt plaintext with AES-256-GCM using a zero nonce, returning `(ciphertext, nonce, tag)`.
///
/// Uses a fixed zero nonce for deterministic tests.
pub fn encrypt_plaintext(aes_key: &[u8; 32], plaintext: &[u8]) -> (Vec<u8>, [u8; 12], [u8; 16]) {
    let cipher = Aes256Gcm::new(aes_key.into());
    let nonce_bytes = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let encrypted = cipher.encrypt(nonce, plaintext.as_ref()).expect("encrypt");
    let ct = encrypted[..encrypted.len() - 16].to_vec();
    let tag: [u8; 16] = encrypted[encrypted.len() - 16..].try_into().unwrap();
    (ct, nonce_bytes, tag)
}

#[cfg(test)]
mod tests {
    use super::{
        AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE, compressed_x_and_parity, compute_ecdh_proof,
        decrypt_authenticated_withdrawal, decrypt_deposit, encrypt_authenticated_withdrawal,
        encrypt_authenticated_withdrawal_deterministic, hkdf_sha256, hmac_sha256,
    };
    use crate::test_utils::{EncryptedDepositFixture, assert_cp_proof_valid};
    use alloy_primitives::{Address, B256, U256};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn test_ecies_decrypt_roundtrip() {
        let f = EncryptedDepositFixture::new();
        let dec = f.decrypt().expect("decryption should succeed");

        assert_eq!(dec.to, f.to);
        assert_eq!(dec.memo, f.memo);
        assert_cp_proof_valid(&dec, &f.eph_pub, &f.seq_pub);
    }

    #[test]
    fn test_cp_proof_is_deterministic() {
        let f = EncryptedDepositFixture::new();

        let proof_a = compute_ecdh_proof(&f.seq_key, &f.eph_pub_x, f.eph_pub_y_parity).unwrap();
        let proof_b = compute_ecdh_proof(&f.seq_key, &f.eph_pub_x, f.eph_pub_y_parity).unwrap();

        assert_eq!(proof_a.cp_proof, proof_b.cp_proof);
    }

    #[test]
    fn test_authenticated_withdrawal_roundtrip() {
        use sha2::{Digest, Sha256};

        let privkey_bytes: [u8; 32] = Sha256::digest(b"authenticated-withdrawal-key").into();
        let privkey = k256::SecretKey::from_slice(&privkey_bytes).unwrap();
        let pubkey = privkey.public_key();
        let encoded = pubkey.to_encoded_point(true);

        let sender = Address::repeat_byte(0x11);
        let tx_hash = B256::repeat_byte(0x22);
        let encrypted =
            encrypt_authenticated_withdrawal(encoded.as_bytes(), sender, tx_hash).unwrap();
        assert_eq!(encrypted.len(), AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE);

        let (decrypted_sender, decrypted_tx_hash) =
            decrypt_authenticated_withdrawal(&privkey, &encrypted).unwrap();
        assert_eq!(decrypted_sender, sender);
        assert_eq!(decrypted_tx_hash, tx_hash);
    }

    #[test]
    fn test_authenticated_withdrawal_deterministic_roundtrip_and_withdrawal_uniqueness() {
        use sha2::{Digest, Sha256};

        let reveal_key_bytes: [u8; 32] =
            Sha256::digest(b"authenticated-withdrawal-reveal-key").into();
        let reveal_key = k256::SecretKey::from_slice(&reveal_key_bytes).unwrap();
        let reveal_pub = reveal_key.public_key();
        let reveal_encoded = reveal_pub.to_encoded_point(true);

        let encryption_key_bytes: [u8; 32] =
            Sha256::digest(b"authenticated-withdrawal-encryption-key").into();
        let encryption_key = k256::SecretKey::from_slice(&encryption_key_bytes).unwrap();

        let zone_id = 17;
        let sender = Address::repeat_byte(0x11);
        let tx_hash = B256::repeat_byte(0x22);
        let encrypted_a = encrypt_authenticated_withdrawal_deterministic(
            &encryption_key,
            zone_id,
            reveal_encoded.as_bytes(),
            sender,
            tx_hash,
            7,
        )
        .unwrap();
        let encrypted_b = encrypt_authenticated_withdrawal_deterministic(
            &encryption_key,
            zone_id,
            reveal_encoded.as_bytes(),
            sender,
            tx_hash,
            7,
        )
        .unwrap();
        let encrypted_other_withdrawal = encrypt_authenticated_withdrawal_deterministic(
            &encryption_key,
            zone_id,
            reveal_encoded.as_bytes(),
            sender,
            tx_hash,
            8,
        )
        .unwrap();

        assert_eq!(encrypted_a, encrypted_b);
        assert_ne!(encrypted_a, encrypted_other_withdrawal);
        assert_eq!(encrypted_a.len(), AUTHENTICATED_WITHDRAWAL_ENCRYPTED_SIZE);

        let (decrypted_sender, decrypted_tx_hash) =
            decrypt_authenticated_withdrawal(&reveal_key, &encrypted_a).unwrap();
        assert_eq!(decrypted_sender, sender);
        assert_eq!(decrypted_tx_hash, tx_hash);
    }

    #[test]
    fn test_authenticated_withdrawal_deterministic_changes_by_zone() {
        use sha2::{Digest, Sha256};

        let reveal_key_bytes: [u8; 32] =
            Sha256::digest(b"authenticated-withdrawal-zone-reveal-key").into();
        let reveal_key = k256::SecretKey::from_slice(&reveal_key_bytes).unwrap();
        let reveal_pub = reveal_key.public_key();
        let reveal_encoded = reveal_pub.to_encoded_point(true);

        let encryption_key_bytes: [u8; 32] =
            Sha256::digest(b"authenticated-withdrawal-zone-encryption-key").into();
        let encryption_key = k256::SecretKey::from_slice(&encryption_key_bytes).unwrap();

        let sender = Address::repeat_byte(0x11);
        let tx_hash = B256::repeat_byte(0x22);
        let encrypted_a = encrypt_authenticated_withdrawal_deterministic(
            &encryption_key,
            17,
            reveal_encoded.as_bytes(),
            sender,
            tx_hash,
            7,
        )
        .unwrap();
        let encrypted_b = encrypt_authenticated_withdrawal_deterministic(
            &encryption_key,
            18,
            reveal_encoded.as_bytes(),
            sender,
            tx_hash,
            7,
        )
        .unwrap();

        assert_ne!(encrypted_a, encrypted_b);
    }

    #[test]
    fn test_ecies_decrypt_wrong_key() {
        let f = EncryptedDepositFixture::new();
        let wrong_key = {
            use sha2::{Digest, Sha256};
            let bytes: [u8; 32] = Sha256::digest(b"wrong-sequencer-key").into();
            k256::SecretKey::from_slice(&bytes).unwrap()
        };

        let result = decrypt_deposit(
            &wrong_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "wrong key should fail decryption");
    }

    #[test]
    fn test_ecies_decrypt_wrong_sender() {
        let f = EncryptedDepositFixture::new();
        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            f.portal,
            f.key_index,
            Address::repeat_byte(0xEE),
        );
        assert!(result.is_none(), "wrong sender should fail decryption");
    }

    #[test]
    fn test_ecies_decrypt_tampered_ciphertext() {
        let f = EncryptedDepositFixture::new();
        let mut ct = f.ciphertext.clone();
        ct[0] ^= 0x01;

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &ct,
            &f.nonce,
            &f.tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "tampered ciphertext should fail");
    }

    #[test]
    fn test_ecies_decrypt_tampered_tag() {
        let f = EncryptedDepositFixture::new();
        let mut tag = f.tag;
        tag[0] ^= 0x01;

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &f.nonce,
            &tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "tampered tag should fail");
    }

    #[test]
    fn test_ecies_decrypt_wrong_nonce() {
        let f = EncryptedDepositFixture::new();
        let wrong_nonce = [0xFFu8; 12];

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &wrong_nonce,
            &f.tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "wrong nonce should fail");
    }

    #[test]
    fn test_ecies_decrypt_wrong_portal_address() {
        let f = EncryptedDepositFixture::new();
        let wrong_portal = Address::repeat_byte(0xFF);

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            wrong_portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "wrong portal address should fail");
    }

    #[test]
    fn test_ecies_decrypt_wrong_key_index() {
        let f = EncryptedDepositFixture::new();
        let wrong_index = U256::from(999u64);

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            f.portal,
            wrong_index,
            f.sender,
        );
        assert!(result.is_none(), "wrong key_index should fail");
    }

    #[test]
    fn test_ecies_decrypt_invalid_ephemeral_parity() {
        let f = EncryptedDepositFixture::new();

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            0x00, // invalid SEC1 prefix
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "invalid y parity should fail");
    }

    #[test]
    fn test_ecies_decrypt_invalid_ephemeral_x() {
        let f = EncryptedDepositFixture::new();
        let bad_x = B256::repeat_byte(0xFF); // almost certainly not on curve

        let result = decrypt_deposit(
            &f.seq_key,
            &bad_x,
            0x02,
            &f.ciphertext,
            &f.nonce,
            &f.tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "invalid ephemeral x should fail");
    }

    #[test]
    fn test_ecies_decrypt_wrong_plaintext_length() {
        let f = EncryptedDepositFixture::new();

        // Encrypt a 63-byte plaintext (wrong length — should be 64)
        let short_plaintext = [0u8; 63];
        let aes_key = {
            use k256::{AffinePoint, ProjectivePoint, Scalar};
            let seq_scalar: Scalar = *f.seq_key.to_nonzero_scalar();
            let shared = AffinePoint::from(ProjectivePoint::from(f.eph_pub) * seq_scalar);
            let (ss_x, _) = super::compressed_x_and_parity(&shared);
            let info = super::hkdf_info(&f.portal, &f.key_index, &f.eph_pub_x, &f.sender);
            hkdf_sha256(&ss_x, b"ecies-aes-key", &info)
        };
        let (ct, nonce, tag) = crate::test_utils::encrypt_plaintext(&aes_key, &short_plaintext);

        let result = decrypt_deposit(
            &f.seq_key,
            &f.eph_pub_x,
            f.eph_pub_y_parity,
            &ct,
            &nonce,
            &tag,
            f.portal,
            f.key_index,
            f.sender,
        );
        assert!(result.is_none(), "wrong plaintext length should fail");
    }

    #[test]
    fn test_hmac_sha256_rfc4231_vector() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = alloy_primitives::hex!(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        assert_eq!(hmac_sha256(key, data), expected);
    }

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = [0x0bu8; 32];
        let salt = b"salt-value";
        let info = b"info-value";

        let out1 = hkdf_sha256(&ikm, salt, info);
        assert_ne!(out1, [0u8; 32], "output should not be all zeros");

        // Deterministic: same inputs → same output
        let out2 = hkdf_sha256(&ikm, salt, info);
        assert_eq!(out1, out2, "hkdf must be deterministic");

        // Different salt → different output
        let out3 = hkdf_sha256(&ikm, b"other-salt", info);
        assert_ne!(out1, out3, "different salt should produce different output");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use sha2::{Digest, Sha256};

        let seq_bytes: [u8; 32] = Sha256::digest(b"roundtrip-sequencer-key").into();
        let seq_key = k256::SecretKey::from_slice(&seq_bytes).expect("valid key");
        let seq_scalar: k256::Scalar = *seq_key.to_nonzero_scalar();
        let seq_pub = k256::AffinePoint::from(k256::ProjectivePoint::GENERATOR * seq_scalar);
        let (seq_pub_x, seq_pub_y_parity) = compressed_x_and_parity(&seq_pub);

        let to = Address::repeat_byte(0x42);
        let memo = B256::repeat_byte(0xAB);
        let sender = Address::repeat_byte(0xCD);
        let portal = Address::repeat_byte(0x01);
        let key_index = U256::from(7u64);

        let enc = super::encrypt_deposit(
            &seq_pub_x,
            seq_pub_y_parity,
            to,
            memo,
            sender,
            portal,
            key_index,
        )
        .expect("encryption should succeed");

        let dec = super::decrypt_deposit(
            &seq_key,
            &enc.eph_pub_x,
            enc.eph_pub_y_parity,
            &enc.ciphertext,
            &enc.nonce,
            &enc.tag,
            portal,
            key_index,
            sender,
        )
        .expect("decryption should succeed");

        assert_eq!(dec.to, to);
        assert_eq!(dec.memo, memo);
    }
}
