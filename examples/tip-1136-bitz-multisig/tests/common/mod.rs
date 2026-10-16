//! Deterministic TEST-ONLY keys and approvals matching the Noir example's policy.

#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use k256::ecdsa::{SigningKey as K1Key, signature::hazmat::PrehashSigner};
use p256::ecdsa::SigningKey as R1Key;
use std::sync::{Mutex, OnceLock};

use tip_1136_bitz::{
    Authorizer,
    policy::{
        AUTH_DATA_LEN, Approval, Evidence, FLAG_UP, FLAG_UV, Kind, Member, Policy, Profile,
        Statement, sha256,
    },
};

/// One shared proof system per profile; setup takes seconds.
pub fn authorizer(profile: Profile) -> &'static Mutex<Authorizer> {
    static MIXED: OnceLock<Mutex<Authorizer>> = OnceLock::new();
    static SPLIT: OnceLock<Mutex<Authorizer>> = OnceLock::new();
    let cell = match profile {
        Profile::Mixed => &MIXED,
        Profile::Split => &SPLIT,
    };
    cell.get_or_init(|| Mutex::new(Authorizer::new(profile).unwrap()))
}

pub const RP_ID: &str = "wallet.tempo.xyz";

/// Stand-in for the chain-reconstructed approval statement digest.
pub fn digest() -> [u8; 32] {
    sha256(b"tempo:approval:v1|chain=4217|account=0xA11CE|cfg=7|op=transfer 250000 USD to 0xB0B|nonce=42")
}

pub fn other_digest() -> [u8; 32] {
    sha256(b"tempo:approval:v1|chain=4217|account=0xA11CE|cfg=7|op=transfer 9999999 USD to 0xEVE|nonce=42")
}

fn seed(name: &str) -> [u8; 32] {
    sha256(format!("tip-1136/{name}").as_bytes())
}

pub fn k1_key(name: &str) -> K1Key {
    K1Key::from_slice(&seed(name)).unwrap()
}

pub fn r1_key(name: &str) -> R1Key {
    R1Key::from_slice(&seed(name)).unwrap()
}

fn coordinates(encoded: &[u8]) -> ([u8; 32], [u8; 32]) {
    assert_eq!(encoded[0], 4);
    (
        encoded[1..33].try_into().unwrap(),
        encoded[33..65].try_into().unwrap(),
    )
}

pub fn k1_member(name: &str, weight: u32) -> Member {
    let point = k1_key(name).verifying_key().to_encoded_point(false);
    let (pk_x, pk_y) = coordinates(point.as_bytes());
    Member {
        kind: Kind::Secp256k1,
        weight,
        pk_x,
        pk_y,
        rp_id_hash: [0; 32],
    }
}

pub fn passkey_member(name: &str, weight: u32) -> Member {
    let point = r1_key(name).verifying_key().to_encoded_point(false);
    let (pk_x, pk_y) = coordinates(point.as_bytes());
    Member {
        kind: Kind::Passkey,
        weight,
        pk_x,
        pk_y,
        rp_id_hash: sha256(RP_ID.as_bytes()),
    }
}

/// alice, bob, eve: secp256k1 weight 1; carol: passkey weight 1; dave: passkey weight 2.
pub fn policy() -> Policy {
    Policy {
        members: vec![
            k1_member("alice", 1),
            k1_member("bob", 1),
            passkey_member("carol", 1),
            passkey_member("dave", 2),
            k1_member("eve", 1),
        ],
        threshold: 3,
        salt: sha256(b"tip-1136/salt"),
    }
}

pub const ALICE: usize = 0;
pub const BOB: usize = 1;
pub const CAROL: usize = 2;
pub const DAVE: usize = 3;
pub const EVE: usize = 4;

pub fn name(index: usize) -> &'static str {
    ["alice", "bob", "carol", "dave", "eve"][index]
}

pub fn statement() -> Statement {
    Statement {
        policy_commitment: policy().commitment(),
        authorization_digest: digest(),
    }
}

pub fn k1_sign(name: &str, digest: &[u8; 32]) -> [u8; 64] {
    let signature: k256::ecdsa::Signature = k1_key(name).sign_prehash(digest).unwrap();
    signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into()
}

pub struct WebAuthn {
    pub rp_id: String,
    pub flags: u8,
    pub challenge: [u8; 32],
}

impl WebAuthn {
    pub fn honest(challenge: [u8; 32]) -> Self {
        Self {
            rp_id: RP_ID.into(),
            flags: FLAG_UP | FLAG_UV,
            challenge,
        }
    }
}

pub fn passkey_evidence(name: &str, params: &WebAuthn) -> Evidence {
    let mut auth_data = [0; AUTH_DATA_LEN];
    auth_data[..32].copy_from_slice(&sha256(params.rp_id.as_bytes()));
    auth_data[32] = params.flags;
    auth_data[33..].copy_from_slice(&1_u32.to_be_bytes());
    let client_data_json = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"https://{}\",\"crossOrigin\":false}}",
        URL_SAFE_NO_PAD.encode(params.challenge),
        params.rp_id
    )
    .into_bytes();
    let mut signed = auth_data.to_vec();
    signed.extend_from_slice(&sha256(&client_data_json));
    let signature: p256::ecdsa::Signature = r1_key(name).sign_prehash(&sha256(&signed)).unwrap();
    Evidence::Passkey {
        signature: signature.to_bytes().into(),
        auth_data,
        client_data_json,
    }
}

/// Honest approval by roster member `index` over `digest`.
pub fn approve(index: usize, digest: &[u8; 32]) -> Approval {
    let evidence = match policy().members[index].kind {
        Kind::Secp256k1 => Evidence::Secp256k1 {
            signature: k1_sign(name(index), digest),
        },
        Kind::Passkey => passkey_evidence(name(index), &WebAuthn::honest(*digest)),
    };
    Approval {
        leaf_index: index,
        evidence,
    }
}
