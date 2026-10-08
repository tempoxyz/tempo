// TIP-1136 reference circuit: PrivateAuthorizationV1, "private weighted multisig" profile.
//
// Public statement:  (policy_commitment, authorization_digest)
// Private witness:   roster root opening, threshold, salt, up to MAX_APPROVALS approvals.
//
// The chain sees only that *some* subset of a *committed, hidden* roster with
// *hidden* weights met a *hidden* threshold and approved this exact digest.
// Roster size, members, threshold, and which members signed are not revealed
// (beyond the circuit profile's bounds: <= 2^DEPTH members, <= MAX_APPROVALS signers).
//
// Member kinds:
//   1 = secp256k1 ECDSA key (hardware wallet / EOA-style key), signs the raw digest.
//   2 = WebAuthn passkey (P-256), signs sha256(authenticatorData || sha256(clientDataJSON))
//       where clientDataJSON.challenge = base64url(authorization_digest).
//
// THIS IS A RESEARCH REFERENCE. It is unaudited and must not secure funds.

mod hashing;
mod webauthn;

use hashing::{member_leaf, merkle_root, policy_commitment};

pub global DEPTH: u32 = 4; // up to 16 members
pub global MAX_APPROVALS: u32 = 4; // up to 4 signers per proof
pub global MAX_CDJ: u32 = 256; // bounded clientDataJSON length

pub global KIND_SECP256K1: u8 = 1;
pub global KIND_PASSKEY: u8 = 2;

pub struct Approval {
    pub enabled: bool,
    pub kind: u8,
    pub weight: u32,
    pub leaf_index: u32,
    pub path: [Field; DEPTH],
    pub pk_x: [u8; 32],
    pub pk_y: [u8; 32],
    // Passkeys only; all-zero for secp256k1 members (it is part of the leaf either way).
    pub rp_id_hash: [u8; 32],
    pub signature: [u8; 64],
    pub auth_data: [u8; 37],
    pub client_data_json: [u8; MAX_CDJ],
    pub client_data_json_len: u32,
}

fn main(
    // ---- public ----
    policy_commitment_pub: pub Field,
    authorization_digest_hi: pub u128,
    authorization_digest_lo: pub u128,
    // ---- private ----
    roster_root: Field,
    threshold: u32,
    salt: Field,
    approvals: [Approval; MAX_APPROVALS],
) {
    authorize(
        policy_commitment_pub,
        authorization_digest_hi,
        authorization_digest_lo,
        roster_root,
        threshold,
        salt,
        approvals,
    );
}

pub fn authorize(
    policy_commitment_pub: Field,
    digest_hi: u128,
    digest_lo: u128,
    roster_root: Field,
    threshold: u32,
    salt: Field,
    approvals: [Approval; MAX_APPROVALS],
) {
    // (1) The private policy opens the configured commitment.
    assert(threshold >= 1, "threshold must be non-zero");
    assert(
        policy_commitment(roster_root, threshold, salt) == policy_commitment_pub,
        "policy opening mismatch",
    );

    // (5) Everyone signs the exact public statement. Typed u128 inputs are range-checked,
    // so the 256-bit digest has a unique (hi, lo) encoding.
    let digest = hashing::digest_bytes(digest_hi, digest_lo);

    let mut total_weight: u32 = 0;
    for i in 0..MAX_APPROVALS {
        let a = approvals[i];

        // (3) Distinctness: enabled slots are packed first and strictly increasing in
        // roster position, so no member can be counted twice and padding is inert.
        if i + 1 < MAX_APPROVALS {
            let next = approvals[i + 1];
            if next.enabled {
                assert(a.enabled, "enabled approvals must be packed first");
                assert(a.leaf_index < next.leaf_index, "approvals must be strictly increasing");
            }
        }

        if a.enabled {
            // (2) Membership under the hidden roster, including the member's weight & kind.
            assert(a.leaf_index < (1 << DEPTH), "leaf index out of range");
            let leaf = member_leaf(a.kind, a.weight, a.pk_x, a.pk_y, a.rp_id_hash);
            assert(merkle_root(leaf, a.leaf_index, a.path) == roster_root, "not a roster member");

            // (2)+(5) Valid credential evidence over this exact digest.
            if a.kind == KIND_SECP256K1 {
                assert(
                    std::ecdsa_secp256k1::verify_signature(a.pk_x, a.pk_y, a.signature, digest),
                    "bad secp256k1 approval",
                );
            } else {
                assert(a.kind == KIND_PASSKEY, "unknown member kind");
                let msg = webauthn::assertion_message(
                    digest,
                    a.rp_id_hash,
                    a.auth_data,
                    a.client_data_json,
                    a.client_data_json_len,
                );
                assert(
                    std::ecdsa_secp256r1::verify_signature(a.pk_x, a.pk_y, a.signature, msg),
                    "bad passkey approval",
                );
            }
            total_weight += a.weight;
        }
    }

    // (4) Hidden weighted threshold.
    assert(total_weight >= threshold, "threshold not met");
}

mod vectors;
mod tests;
