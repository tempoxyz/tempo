//! Experimental ML-DSA-65 OIDC statement shared by the guest, prover and node.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

#[cfg(feature = "verify")]
pub mod receipt;

/// Experimental scheme and namespace, isolated from RSA-backed OIDC addresses.
pub const SCHEME: u8 = 0x80;
/// Embedded-key signature prefix. The keychain stores algorithm identifier 3.
pub const SIGNATURE_TYPE: u8 = 0x80;
/// FIPS 204 ML-DSA-65 public key size.
pub const PUBLIC_KEY_LEN: usize = 1952;
/// FIPS 204 ML-DSA-65 signature size.
pub const SIGNATURE_LEN: usize = 3309;
/// Maximum private token size, including its base64url signature.
pub const MAX_TOKEN_LEN: usize = 8192;
/// Maximum receipt wire size, before deserialization.
pub const MAX_PROOF_LEN: usize = 8 * 1024 * 1024;
/// Maximum credential lifetime in seconds.
pub const MAX_WINDOW: u64 = 600;

/// Private sign-in witness. Never include this in diagnostics or logs.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Witness {
    /// Wallet-selected access key ID.
    pub access_key_id: [u8; 20],
    /// Fresh wallet randomness committed by the token nonce.
    pub blinding: [u8; 32],
    /// Issuer's encoded ML-DSA-65 public key.
    pub public_key: Vec<u8>,
    /// Durable private identity salt.
    pub salt: [u8; 32],
    /// Compact JWS ID token with the exact ML-DSA-65 algorithm.
    pub token: String,
    /// Wallet-selected credential expiry.
    pub valid_until: u64,
}

/// The exact public statement bound by a receipt's journal.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Statement {
    /// Wallet-selected access key ID.
    pub access_key_id: [u8; 20],
    /// Salted identity commitment.
    pub address_seed: [u8; 32],
    /// Issuer-authenticated issuance time.
    pub issued_at: u64,
    /// Normalized issuer commitment.
    pub issuer: [u8; 32],
    /// Issuer public-key commitment.
    pub key_hash: [u8; 32],
    /// Credential expiry, bound to the nonce and token expiry.
    pub valid_until: u64,
}

/// A witness fails without exposing its token or private values.
#[derive(Debug, thiserror::Error)]
#[error("invalid ML-DSA-65 OIDC witness")]
pub struct InvalidWitness;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
struct Claims {
    aud: String,
    exp: u64,
    iat: u64,
    iss: String,
    nonce: String,
    sub: String,
}

impl Statement {
    /// Fixed 133-byte journal encoding, with a scheme tag and big-endian times.
    pub fn journal(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(133);
        out.push(SCHEME);
        out.extend_from_slice(&self.issuer);
        out.extend_from_slice(&self.key_hash);
        out.extend_from_slice(&self.address_seed);
        out.extend_from_slice(&self.access_key_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.valid_until.to_be_bytes());
        out
    }
}

/// Verify the private token and derive its exact public statement.
pub fn evaluate(witness: &Witness) -> Result<Statement, InvalidWitness> {
    if witness.token.len() > MAX_TOKEN_LEN {
        return Err(InvalidWitness);
    }
    let mut parts = witness.token.split('.');
    let header = parts.next().ok_or(InvalidWitness)?;
    let payload = parts.next().ok_or(InvalidWitness)?;
    let signature = parts.next().ok_or(InvalidWitness)?;
    if parts.next().is_some() {
        return Err(InvalidWitness);
    }
    let header: Header = serde_json::from_slice(&decode(header)?).map_err(|_| InvalidWitness)?;
    if header.alg != "ML-DSA-65" || header.typ != "JWT" || header.kid.is_empty() {
        return Err(InvalidWitness);
    }
    let signed_len = witness.token.len() - signature.len() - 1;
    verify_signature(
        &witness.public_key,
        &decode(signature)?,
        &witness.token.as_bytes()[..signed_len],
    )?;
    let claims: Claims = serde_json::from_slice(&decode(payload)?).map_err(|_| InvalidWitness)?;
    if claims.iss.is_empty()
        || claims.iss.len() > 256
        || claims.aud.is_empty()
        || claims.aud.len() > 128
        || claims.sub.is_empty()
        || claims.sub.len() > 128
        || claims.exp < claims.iat
        || witness.valid_until < claims.iat
        || witness.valid_until > claims.exp
        || witness.valid_until - claims.iat > MAX_WINDOW
        || claims.nonce
            != nonce(
                &witness.access_key_id,
                witness.valid_until,
                &witness.blinding,
            )
    {
        return Err(InvalidWitness);
    }
    Ok(Statement {
        access_key_id: witness.access_key_id,
        address_seed: field_hash(
            b"tempo:pq:identity",
            &[
                normalize_issuer(&claims.iss).as_bytes(),
                claims.aud.as_bytes(),
                claims.sub.as_bytes(),
                &witness.salt,
            ],
        ),
        issued_at: claims.iat,
        issuer: issuer_hash(&claims.iss),
        key_hash: key_hash(&witness.public_key),
        valid_until: witness.valid_until,
    })
}

/// Verify pure ML-DSA-65 with an empty FIPS 204 context, also used by JWS.
pub fn verify_signature(
    key: &[u8],
    signature: &[u8],
    message: &[u8],
) -> Result<(), InvalidWitness> {
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(key).map_err(|_| InvalidWitness)?;
    let signature = Signature::<MlDsa65>::try_from(signature).map_err(|_| InvalidWitness)?;
    if !VerifyingKey::decode(&encoded).verify_with_context(message, b"", &signature) {
        return Err(InvalidWitness);
    }
    Ok(())
}

/// Domain-separated 20-byte access key ID, matching the node's primitive recovery.
pub fn access_key_id(key: &[u8]) -> Result<[u8; 20], InvalidWitness> {
    if key.len() != PUBLIC_KEY_LEN {
        return Err(InvalidWitness);
    }
    let mut hasher = Keccak256::new();
    hasher.update([SIGNATURE_TYPE]);
    hasher.update(key);
    Ok(hasher.finalize()[12..]
        .try_into()
        .map_err(|_| InvalidWitness)?)
}

/// The nonce echoed by the issuer, committing to the key, expiry and blinding.
pub fn nonce(key: &[u8; 20], valid_until: u64, blinding: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(hash(
        b"tempo:pq:nonce",
        &[key, &valid_until.to_be_bytes(), blinding],
    ))
}

/// Field-sized key hash accepted by the existing Key Publisher.
pub fn key_hash(key: &[u8]) -> [u8; 32] {
    field_hash(b"tempo:pq:issuer-key", &[key])
}

/// Field-sized normalized issuer hash accepted by the existing Key Publisher.
pub fn issuer_hash(issuer: &str) -> [u8; 32] {
    field_hash(b"tempo:pq:issuer", &[normalize_issuer(issuer).as_bytes()])
}

fn normalize_issuer(issuer: &str) -> &str {
    issuer.strip_prefix("https://").unwrap_or(issuer)
}

fn decode(value: &str) -> Result<Vec<u8>, InvalidWitness> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| InvalidWitness)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(InvalidWitness);
    }
    Ok(bytes)
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u32).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn field_hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut out = hash(domain, parts);
    out[0] &= 0x1f;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{Keypair as _, SigningKey};

    fn witness() -> Witness {
        let key = SigningKey::<MlDsa65>::from_seed(&[7; 32].into());
        let mut witness = Witness {
            access_key_id: [3; 20],
            blinding: [4; 32],
            public_key: key.verifying_key().encode().to_vec(),
            salt: [5; 32],
            token: String::new(),
            valid_until: 1540,
        };
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ML-DSA-65","kid":"test","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({
            "aud": "oidc-demo", "exp": 1600, "iat": 1000, "iss": "https://issuer.example",
            "nonce": nonce(&witness.access_key_id, witness.valid_until, &witness.blinding), "sub": "user"
        })).unwrap());
        let message = format!("{header}.{payload}");
        let signature = key
            .expanded_key()
            .sign_deterministic(message.as_bytes(), b"")
            .unwrap();
        witness.token = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.encode()));
        witness
    }

    #[test]
    fn token_binds_identity_key_and_expiry() {
        let witness = witness();
        let statement = evaluate(&witness).unwrap();
        assert_eq!(statement.journal().len(), 133);
        assert_eq!(statement.access_key_id, witness.access_key_id);
        assert_eq!(statement.issued_at, 1000);
        assert_eq!(statement.valid_until, 1540);
        for index in 0..5 {
            let mut changed = witness.clone();
            match index {
                0 => changed.access_key_id[0] ^= 1,
                1 => changed.blinding[0] ^= 1,
                2 => changed.valid_until += 1,
                3 => changed.public_key[0] ^= 1,
                _ => changed.token.push('.'),
            }
            assert!(evaluate(&changed).is_err());
        }
    }

    #[test]
    fn primitive_signature_binds_message() {
        let key = SigningKey::<MlDsa65>::from_seed(&[8; 32].into());
        let public_key = key.verifying_key().encode();
        let signature = key
            .expanded_key()
            .sign_deterministic(b"digest", b"")
            .unwrap()
            .encode();
        assert!(verify_signature(&public_key, &signature, b"digest").is_ok());
        assert!(verify_signature(&public_key, &signature, b"other").is_err());
        assert!(
            verify_signature(&public_key[..PUBLIC_KEY_LEN - 1], &signature, b"digest").is_err()
        );
        assert!(verify_signature(&public_key, &signature[..SIGNATURE_LEN - 1], b"digest").is_err());
    }
}
