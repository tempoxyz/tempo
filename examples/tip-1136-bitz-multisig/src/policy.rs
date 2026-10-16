//! Native (out-of-circuit) encodings for the private weighted multisig profile.
//!
//! Every hash is standard SHA-256 so that commitments and test vectors can be
//! reproduced with any SHA-256 implementation:
//!
//! ```text
//! leaf              = SHA256("tempo:member:v1\0" || kind || weight_be32 || 0^11 || pkX || pkY || rpIdHash)  // 128 B
//! node              = SHA256(left || right)                                                                 //  64 B
//! roster_root       = depth-4 Merkle root over 16 leaves (unused leaves = 0^32)
//! policy_commitment = SHA256("tempo:policy:v1\0" || threshold_be32 || 0^12 || roster_root || salt)          //  96 B
//! ```
//!
//! Leaves, nodes, and commitments have distinct preimage lengths, so SHA-256's
//! length padding separates their domains in addition to the ASCII tags.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::ecdsa::Curve;

/// Merkle depth: up to 16 roster members.
pub const DEPTH: usize = 4;

/// Roster capacity.
pub const MAX_MEMBERS: usize = 1 << DEPTH;

/// Approval slots per proof.
pub const MAX_APPROVALS: usize = 4;

/// Maximum SHA-256 blocks of padded `clientDataJSON` (at most 247 bytes).
pub const CDJ_MAX_BLOCKS: usize = 4;

/// Minimum SHA-256 blocks of padded `clientDataJSON`; the 80-byte checked
/// prefix must lie inside the hashed blocks.
pub const CDJ_MIN_BLOCKS: usize = 2;

/// Accepted authenticator data: rpIdHash, flags, and signature counter.
pub const AUTH_DATA_LEN: usize = 37;

/// Leaf domain tag.
pub const LEAF_TAG: &[u8; 16] = b"tempo:member:v1\0";

/// Policy commitment domain tag.
pub const POLICY_TAG: &[u8; 16] = b"tempo:policy:v1\0";

/// Canonical `clientDataJSON` prefix before the base64url challenge.
pub const CDJ_PREFIX: &[u8; 36] = b"{\"type\":\"webauthn.get\",\"challenge\":\"";

/// Length of the checked `clientDataJSON` prefix: prefix, challenge, and `"`.
pub const CDJ_CHECKED_LEN: usize = CDJ_PREFIX.len() + 43 + 1;

/// User-present authenticator flag.
pub const FLAG_UP: u8 = 0x01;

/// User-verified authenticator flag.
pub const FLAG_UV: u8 = 0x04;

/// The credential kinds one approval slot accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    /// Either kind; the slot runs both verifiers.
    Any,
    Secp256k1,
    Passkey,
}

/// The circuit profile: the kinds of its [`MAX_APPROVALS`] slots.
///
/// The profile is public and fixed per registered circuit. It bounds which
/// quorums one proof can express but reveals nothing about a given approval.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Profile {
    /// Four slots of any kind: 8 ECDSA verifiers.
    #[default]
    Mixed,
    /// Two secp256k1 slots, then two passkey slots: 4 ECDSA verifiers.
    Split,
}

impl Profile {
    /// Slot kinds in circuit order; same-kind slots are contiguous.
    pub const fn slot_kinds(self) -> [SlotKind; MAX_APPROVALS] {
        match self {
            Self::Mixed => [SlotKind::Any; MAX_APPROVALS],
            Self::Split => [
                SlotKind::Secp256k1,
                SlotKind::Secp256k1,
                SlotKind::Passkey,
                SlotKind::Passkey,
            ],
        }
    }
}

/// Member credential type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// secp256k1 ECDSA over the raw authorization digest.
    Secp256k1 = 1,
    /// WebAuthn P-256 assertion whose challenge is the authorization digest.
    Passkey = 2,
}

/// A committed roster member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub kind: Kind,
    pub weight: u32,
    pub pk_x: [u8; 32],
    pub pk_y: [u8; 32],
    /// SHA-256 of the relying-party ID for passkeys; zero for secp256k1 keys.
    pub rp_id_hash: [u8; 32],
}

impl Member {
    /// Returns the member's leaf hash.
    pub fn leaf(&self) -> [u8; 32] {
        sha256(&leaf_preimage(
            self.kind == Kind::Passkey,
            self.weight,
            &self.pk_x,
            &self.pk_y,
            &self.rp_id_hash,
        ))
    }
}

/// A private policy: roster, threshold, and blinding salt.
#[derive(Clone, Debug)]
pub struct Policy {
    pub members: Vec<Member>,
    pub threshold: u32,
    pub salt: [u8; 32],
}

impl Policy {
    /// Leaves in roster order, padded with zero leaves.
    pub fn leaves(&self) -> [[u8; 32]; MAX_MEMBERS] {
        assert!(self.members.len() <= MAX_MEMBERS, "roster exceeds profile");
        let mut leaves = [[0; 32]; MAX_MEMBERS];
        for (leaf, member) in leaves.iter_mut().zip(&self.members) {
            *leaf = member.leaf();
        }
        leaves
    }

    /// Merkle root of the padded roster.
    pub fn roster_root(&self) -> [u8; 32] {
        let mut level = self.leaves().to_vec();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| node(&pair[0], &pair[1]))
                .collect();
        }
        level[0]
    }

    /// Sibling path for `index`, from the leaf level upwards.
    pub fn path(&self, index: usize) -> [[u8; 32]; DEPTH] {
        let mut level = self.leaves().to_vec();
        let mut path = [[0; 32]; DEPTH];
        let mut position = index;
        for sibling in &mut path {
            *sibling = level[position ^ 1];
            level = level
                .chunks(2)
                .map(|pair| node(&pair[0], &pair[1]))
                .collect();
            position >>= 1;
        }
        path
    }

    /// The commitment stored in the account's policy-owner descriptor.
    pub fn commitment(&self) -> [u8; 32] {
        policy_commitment(&self.roster_root(), self.threshold, &self.salt)
    }
}

/// The public statement reconstructed by the chain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statement {
    pub policy_commitment: [u8; 32],
    pub authorization_digest: [u8; 32],
}

/// Fresh credential evidence over the authorization digest.
#[derive(Clone, Debug)]
pub enum Evidence {
    /// `r || s`, big-endian.
    Secp256k1 { signature: [u8; 64] },
    /// WebAuthn assertion: `r || s` over `SHA256(authData || SHA256(clientDataJSON))`.
    Passkey {
        signature: [u8; 64],
        auth_data: [u8; AUTH_DATA_LEN],
        client_data_json: Vec<u8>,
    },
}

/// One member's approval.
#[derive(Clone, Debug)]
pub struct Approval {
    pub leaf_index: usize,
    pub evidence: Evidence,
}

/// Inputs to one embedded ECDSA verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaInputs {
    pub qx: BigUint,
    pub qy: BigUint,
    pub r: BigUint,
    pub s: BigUint,
}

impl EcdsaInputs {
    /// A signature anyone can produce for any digest `e`: the public key is the
    /// generator (private key 1), `r = Gx`, and `s = e + r`. Then
    /// `(e/s)G + (r/s)G = G`, whose x-coordinate is `r`. Inactive verifiers use
    /// it, so they constrain nothing about members.
    pub fn trivial(curve: Curve, e: &[u8; 32]) -> Self {
        let n = curve.order();
        let (gx, gy) = curve.generator();
        let r = gx % n;
        let s = (BigUint::from_bytes_be(e) + &r) % n;
        Self {
            qx: gx.clone(),
            qy: gy.clone(),
            r,
            s,
        }
    }

    fn real(pk_x: &[u8; 32], pk_y: &[u8; 32], signature: &[u8; 64]) -> Self {
        Self {
            qx: BigUint::from_bytes_be(pk_x),
            qy: BigUint::from_bytes_be(pk_y),
            r: BigUint::from_bytes_be(&signature[..32]),
            s: BigUint::from_bytes_be(&signature[32..]),
        }
    }
}

/// One approval slot of the circuit witness.
///
/// Fields are public so tests can construct adversarial witnesses.
#[derive(Clone, Debug)]
pub struct Slot {
    pub enabled: bool,
    pub is_passkey: bool,
    pub weight: u32,
    pub leaf_index: u8,
    pub path: [[u8; 32]; DEPTH],
    pub pk_x: [u8; 32],
    pub pk_y: [u8; 32],
    pub rp_id_hash: [u8; 32],
    pub secp256k1: EcdsaInputs,
    pub p256: EcdsaInputs,
    pub auth_data: [u8; AUTH_DATA_LEN],
    /// SHA-256-padded `clientDataJSON`, zero-filled to the maximum.
    pub cdj_blocks: [u8; 64 * CDJ_MAX_BLOCKS],
    /// Number of hashed blocks, in `CDJ_MIN_BLOCKS..=CDJ_MAX_BLOCKS`.
    pub cdj_block_count: usize,
}

impl Slot {
    /// An inert padding slot of `kind` for `digest`.
    pub fn disabled(kind: SlotKind, digest: &[u8; 32]) -> Self {
        let mut slot = Self {
            enabled: false,
            is_passkey: kind == SlotKind::Passkey,
            weight: 0,
            leaf_index: 0,
            path: [[0; 32]; DEPTH],
            pk_x: [0; 32],
            pk_y: [0; 32],
            rp_id_hash: [0; 32],
            secp256k1: EcdsaInputs::trivial(Curve::Secp256k1, digest),
            p256: EcdsaInputs::trivial(Curve::P256, &[0; 32]),
            auth_data: [0; AUTH_DATA_LEN],
            cdj_blocks: [0; 64 * CDJ_MAX_BLOCKS],
            cdj_block_count: CDJ_MIN_BLOCKS,
        };
        // The circuit checks SHA-256 padding in every slot that has a P-256
        // verifier, so padding slots carry a well-formed dummy message.
        let dummy = sha256_pad(&[0; CDJ_CHECKED_LEN]);
        slot.cdj_blocks[..dummy.len()].copy_from_slice(&dummy);
        slot.cdj_block_count = dummy.len() / 64;
        slot.refresh_p256_trivial();
        slot
    }

    /// The P-256 verifier's digest: `SHA256(authData || H(cdj blocks))`.
    pub fn webauthn_message(&self) -> [u8; 32] {
        let client_hash = sha256_blocks(&self.cdj_blocks[..64 * self.cdj_block_count]);
        let mut signed = self.auth_data.to_vec();
        signed.extend_from_slice(&client_hash);
        sha256(&signed)
    }

    /// Recomputes the trivial P-256 signature after editing WebAuthn data of a
    /// non-passkey slot.
    pub fn refresh_p256_trivial(&mut self) {
        self.p256 = EcdsaInputs::trivial(Curve::P256, &self.webauthn_message());
    }
}

/// The complete private witness.
#[derive(Clone, Debug)]
pub struct Witness {
    pub roster_root: [u8; 32],
    pub threshold: u32,
    pub salt: [u8; 32],
    pub slots: [Slot; MAX_APPROVALS],
}

impl Witness {
    /// Assembles a witness from a policy and approvals sorted by leaf index.
    pub fn new(
        profile: Profile,
        policy: &Policy,
        approvals: &[Approval],
        digest: &[u8; 32],
    ) -> anyhow::Result<Self> {
        let kinds = profile.slot_kinds();
        let mut slots = kinds.map(|kind| Slot::disabled(kind, digest));
        let mut used = [false; MAX_APPROVALS];
        for approval in approvals {
            let member = policy
                .members
                .get(approval.leaf_index)
                .ok_or_else(|| anyhow::anyhow!("approval for an empty roster slot"))?;
            let fits = |kind: SlotKind| match kind {
                SlotKind::Any => true,
                SlotKind::Secp256k1 => member.kind == Kind::Secp256k1,
                SlotKind::Passkey => member.kind == Kind::Passkey,
            };
            let position = (0..MAX_APPROVALS)
                .find(|&i| !used[i] && fits(kinds[i]))
                .ok_or_else(|| anyhow::anyhow!("profile has no free slot for this member kind"))?;
            used[position] = true;
            let slot = &mut slots[position];
            slot.enabled = true;
            slot.is_passkey = member.kind == Kind::Passkey;
            slot.weight = member.weight;
            slot.leaf_index = approval.leaf_index as u8;
            slot.path = policy.path(approval.leaf_index);
            slot.pk_x = member.pk_x;
            slot.pk_y = member.pk_y;
            slot.rp_id_hash = member.rp_id_hash;
            match (&approval.evidence, member.kind) {
                (Evidence::Secp256k1 { signature }, Kind::Secp256k1) => {
                    slot.secp256k1 = EcdsaInputs::real(&member.pk_x, &member.pk_y, signature);
                    slot.refresh_p256_trivial();
                }
                (
                    Evidence::Passkey {
                        signature,
                        auth_data,
                        client_data_json,
                    },
                    Kind::Passkey,
                ) => {
                    let padded = sha256_pad(client_data_json);
                    let blocks = padded.len() / 64;
                    anyhow::ensure!(
                        (CDJ_MIN_BLOCKS..=CDJ_MAX_BLOCKS).contains(&blocks),
                        "clientDataJSON length outside the profile"
                    );
                    slot.auth_data = *auth_data;
                    slot.cdj_blocks[..padded.len()].copy_from_slice(&padded);
                    slot.cdj_block_count = blocks;
                    slot.p256 = EcdsaInputs::real(&member.pk_x, &member.pk_y, signature);
                }
                _ => anyhow::bail!("evidence type does not match the member kind"),
            }
        }
        Ok(Self {
            roster_root: policy.roster_root(),
            threshold: policy.threshold,
            salt: policy.salt,
            slots,
        })
    }
}

/// Leaf preimage for the given fields.
pub fn leaf_preimage(
    is_passkey: bool,
    weight: u32,
    pk_x: &[u8; 32],
    pk_y: &[u8; 32],
    rp_id_hash: &[u8; 32],
) -> [u8; 128] {
    let mut preimage = [0; 128];
    preimage[..16].copy_from_slice(LEAF_TAG);
    preimage[16] = if is_passkey { 2 } else { 1 };
    preimage[17..21].copy_from_slice(&weight.to_be_bytes());
    preimage[32..64].copy_from_slice(pk_x);
    preimage[64..96].copy_from_slice(pk_y);
    preimage[96..].copy_from_slice(rp_id_hash);
    preimage
}

/// Merkle node hash.
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0; 64];
    preimage[..32].copy_from_slice(left);
    preimage[32..].copy_from_slice(right);
    sha256(&preimage)
}

/// Policy commitment preimage.
pub fn policy_preimage(roster_root: &[u8; 32], threshold: u32, salt: &[u8; 32]) -> [u8; 96] {
    let mut preimage = [0; 96];
    preimage[..16].copy_from_slice(POLICY_TAG);
    preimage[16..20].copy_from_slice(&threshold.to_be_bytes());
    preimage[32..64].copy_from_slice(roster_root);
    preimage[64..].copy_from_slice(salt);
    preimage
}

/// Policy commitment.
pub fn policy_commitment(roster_root: &[u8; 32], threshold: u32, salt: &[u8; 32]) -> [u8; 32] {
    sha256(&policy_preimage(roster_root, threshold, salt))
}

/// The checked `clientDataJSON` prefix for `digest`.
pub fn cdj_checked_prefix(digest: &[u8; 32]) -> [u8; CDJ_CHECKED_LEN] {
    let mut prefix = [0; CDJ_CHECKED_LEN];
    prefix[..CDJ_PREFIX.len()].copy_from_slice(CDJ_PREFIX);
    prefix[CDJ_PREFIX.len()..CDJ_CHECKED_LEN - 1].copy_from_slice(&base64url_32(digest));
    prefix[CDJ_CHECKED_LEN - 1] = b'"';
    prefix
}

/// Unpadded base64url of 32 bytes: exactly 43 characters.
pub fn base64url_32(bytes: &[u8; 32]) -> [u8; 43] {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = [0; 43];
    for (i, char) in out.iter_mut().enumerate() {
        let bit = 6 * i;
        let mut value = 0_u16;
        for offset in 0..6 {
            let index = bit + offset;
            let set = index < 256 && bytes[index / 8] >> (7 - index % 8) & 1 == 1;
            value = value << 1 | u16::from(set);
        }
        *char = ALPHABET[value as usize];
    }
    out
}

/// SHA-256 message padding.
pub fn sha256_pad(message: &[u8]) -> Vec<u8> {
    let mut padded = message.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((message.len() as u64) * 8).to_be_bytes());
    padded
}

/// Runs the SHA-256 compression chain over already-padded blocks.
pub fn sha256_blocks(blocks: &[u8]) -> [u8; 32] {
    assert!(blocks.len().is_multiple_of(64));
    let mut state = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19_u32,
    ];
    for block in blocks.chunks_exact(64) {
        let block: [u8; 64] = block.try_into().expect("64-byte block");
        sha2::compress256(&mut state, &[block.into()]);
    }
    let mut out = [0; 32];
    for (bytes, word) in out.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256.
pub fn sha256(message: &[u8]) -> [u8; 32] {
    Sha256::digest(message).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_chain_matches_sha256() {
        for len in [0, 55, 56, 64, 119, 200] {
            let message: Vec<u8> = (0..len).map(|i| i as u8).collect();
            assert_eq!(sha256_blocks(&sha256_pad(&message)), sha256(&message));
        }
    }

    #[test]
    fn base64url_matches_reference() {
        let bytes: [u8; 32] = std::array::from_fn(|i| ((i * 37 + 11) % 256) as u8);
        assert_eq!(
            base64url_32(&bytes).as_slice(),
            b"CzBVep_E6Q4zWH2ix-wRNluApcrvFDleg6jN8hc8YYY".as_slice()
        );
    }
}
