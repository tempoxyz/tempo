//! The `PrivateAuthorizationV1` private weighted multisig relation as a BitZ
//! circuit.
//!
//! Boolean witnesses live in F2; `bitz` lifts them to integers, where rank-1
//! constraints are checked. Integer gadgets therefore get range checks for
//! free: a value assembled from `k` lifted bits lies in `[0, 2^k)`.
//!
//! The relation mirrors the Noir reference circuit:
//!
//! 1. The private policy opens the public commitment, and `threshold >= 1`.
//! 2. Each enabled slot opens a roster leaf that commits to its kind and weight.
//! 3. Enabled slots are packed first with strictly increasing leaf indices.
//! 4. Each enabled slot carries a valid signature over the public digest:
//!    secp256k1 over the digest itself, or a strict WebAuthn P-256 assertion
//!    whose challenge is the digest.
//! 5. The enabled weights sum to at least the threshold.
//!
//! Slots follow a [`Profile`]:
//!
//! - [`Profile::Mixed`] has four slots of any kind. Each runs one secp256k1
//!   and one P-256 verifier. The verifier that does not match the slot (and
//!   both verifiers of a disabled slot) checks a signature under the generator,
//!   which anyone can produce; only the matching verifier is tied to the
//!   member's committed key.
//! - [`Profile::Split`] has two secp256k1 slots and two passkey slots, each
//!   with one verifier: half the circuit, at the cost of at most two approvals
//!   of each kind. Ordering is enforced within each group; a member cannot
//!   appear in both groups because its leaf commits to its kind.

use std::array;

use bitz_cli::end_to_end::{CircuitStatement, Error};
use circuit::{
    BoolRepresentation, Circuit, PackedBits,
    sha256::{INITIAL_STATE, Word, compress},
};
use num_bigint::BigUint;
use num_traits::Zero;

use crate::{
    ecdsa::Curve,
    ecdsa_fast::verify_digest_circuit,
    policy::{
        AUTH_DATA_LEN, CDJ_CHECKED_LEN, CDJ_MAX_BLOCKS, CDJ_MIN_BLOCKS, CDJ_PREFIX, DEPTH,
        EcdsaInputs, LEAF_TAG, MAX_APPROVALS, POLICY_TAG, Profile, SlotKind, Statement, Witness,
    },
};

/// Integer width for this module's gadgets: two signed 64-bit limbs.
const LIMBS: usize = 2;

/// Lift and compare in chunks small enough that no difference wraps modulo
/// the proof field.
const CHUNK: usize = 64;

/// One-hot selector width for the number of hashed `clientDataJSON` blocks.
const CDJ_COUNT_BITS: usize = CDJ_MAX_BLOCKS - CDJ_MIN_BLOCKS + 1;

/// ECDSA verifier words after the digest: Q.x, Q.y, r, s, r^-1, s^-1.
const ECDSA_WORDS_BITS: usize = 6 * 256;

/// Private input bits of one approval slot.
pub const SLOT_BITS: usize = 1 // enabled
    + 1 // is_passkey
    + 32 // weight
    + DEPTH // leaf index
    + DEPTH * 256 // Merkle path
    + 3 * 256 // pk_x, pk_y, rp_id_hash
    + 2 * ECDSA_WORDS_BITS // secp256k1 and P-256 verifier inputs
    + AUTH_DATA_LEN * 8
    + CDJ_MAX_BLOCKS * 512
    + CDJ_COUNT_BITS;

/// Public input bits: the policy commitment and the authorization digest.
pub const PUBLIC_BITS: usize = 2 * 256;

/// Offset of the private threshold bits.
const THRESHOLD_OFFSET: usize = PUBLIC_BITS + 256;

/// Offset of the first approval slot.
const SLOTS_OFFSET: usize = THRESHOLD_OFFSET + 32 + 256;

/// Input bits of the whole witness, public bits first.
pub const INPUT_BITS: usize = SLOTS_OFFSET + MAX_APPROVALS * SLOT_BITS;

/// base64url alphabet.
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

type Z<C> = <C as Circuit>::Z<LIMBS>;

/// The public statement of one approval proof under a circuit profile.
#[derive(Clone, Copy, Debug)]
pub struct PrivateAuthorization {
    pub profile: Profile,
    pub statement: Statement,
}

impl CircuitStatement for PrivateAuthorization {
    fn domain(&self) -> &'static [u8] {
        match self.profile {
            Profile::Mixed => b"tempo/tip-1136/private-weighted-multisig/bitz/mixed4/v1",
            Profile::Split => b"tempo/tip-1136/private-weighted-multisig/bitz/split2x2/v1",
        }
    }

    fn public_bytes(&self) -> Vec<u8> {
        let mut bytes = self.statement.policy_commitment.to_vec();
        bytes.extend_from_slice(&self.statement.authorization_digest);
        bytes
    }

    fn input_bits(&self) -> usize {
        INPUT_BITS
    }

    fn public_input_bits(&self) -> Vec<bool> {
        let mut bits = stream_bits(&self.statement.policy_commitment);
        bits.extend(stream_bits(&self.statement.authorization_digest));
        bits
    }

    fn synthesize<C: Circuit>(&self, cs: &mut C, inputs: &[C::Bool]) -> Result<(), Error> {
        if inputs.len() != INPUT_BITS {
            return Err(Error::Input("wrong private input length"));
        }
        authorize(cs, inputs, self.profile);
        Ok(())
    }
}

/// Reads consecutive input bits in layout order.
struct Cursor<'a, T> {
    items: &'a [T],
    position: usize,
}

impl<'a, T: Clone> Cursor<'a, T> {
    fn take(&mut self, count: usize) -> Vec<T> {
        let taken = self.items[self.position..self.position + count].to_vec();
        self.position += count;
        taken
    }

    fn bit(&mut self) -> T {
        self.take(1).remove(0)
    }
}

/// Lifted signals of one approval slot needed after its own checks.
struct SlotSignals<C: Circuit> {
    enabled: Z<C>,
    enabled_bit: C::Bool,
    index: Z<C>,
    index_bits: Vec<C::Bool>,
    counted_weight: Z<C>,
}

fn authorize<C: Circuit>(cs: &mut C, inputs: &[C::Bool], profile: Profile) {
    let mut cursor = Cursor {
        items: inputs,
        position: 0,
    };
    // Public: checked against the statement by the PCS, not by constants, so
    // one constraint system serves every statement.
    let policy_commitment = cursor.take(256);
    let digest = cursor.take(256);
    let roster_root = cursor.take(256);
    let threshold = cursor.take(32);
    let salt = cursor.take(256);
    let one = constant::<C>(1);

    // (1) The private policy opens the public commitment.
    let mut preimage = constant_stream::<C>(POLICY_TAG);
    preimage.extend(threshold.iter().cloned());
    preimage.extend(constant_stream::<C>(&[0; 12]));
    preimage.extend(roster_root.iter().cloned());
    preimage.extend(salt);
    let commitment = sha256(cs, &preimage);
    assert_eq_bits(cs, &one, &commitment, &policy_commitment);

    // threshold >= 1: threshold - 1 is a 32-bit natural number.
    let threshold = lift_be(cs, &threshold);
    let threshold_minus_one = hint_value(cs, 32, {
        let threshold = threshold_bits_capture(inputs);
        move |eval| eval_be(eval, &threshold).wrapping_sub(1)
    });
    let threshold_minus_one = lift(cs, &threshold_minus_one);
    assert_zero(cs, threshold.clone() - one.clone() - threshold_minus_one);

    let digest_le = stream_to_le(&digest);
    let challenge = base64url_chars(cs, &digest);
    let kinds = profile.slot_kinds();
    let slots: Vec<_> = kinds
        .iter()
        .map(|&kind| {
            let bits = cursor.take(SLOT_BITS);
            approval_slot(cs, &bits, kind, &roster_root, &digest_le, &challenge)
        })
        .collect();

    // (3) Within each group of same-kind slots: packed, strictly increasing
    // roster positions, so no member counts twice and padding cannot hide
    // approvals. Different groups hold members of different committed kinds.
    for (pair, kind_pair) in slots.windows(2).zip(kinds.windows(2)) {
        if kind_pair[0] != kind_pair[1] {
            continue;
        }
        let [current, next] = pair else {
            unreachable!()
        };
        cs.assert_r1c::<LIMBS>(
            next.enabled.clone(),
            one.clone() - current.enabled.clone(),
            Z::<C>::zero(),
        );
        let gap = hint_value(cs, DEPTH, {
            let (current, next, enabled) = (
                current.index_bits.clone(),
                next.index_bits.clone(),
                next.enabled_bit.clone(),
            );
            move |eval| {
                if eval(&enabled) {
                    eval_le(eval, &next)
                        .wrapping_sub(eval_le(eval, &current))
                        .wrapping_sub(1)
                } else {
                    0
                }
            }
        });
        let gap = lift(cs, &gap);
        cs.assert_r1c::<LIMBS>(
            next.enabled.clone(),
            next.index.clone() - current.index.clone() - one.clone() - gap,
            Z::<C>::zero(),
        );
    }

    // (5) Hidden weighted threshold: total - threshold is a natural number.
    let total = slots.iter().fold(Z::<C>::zero(), |sum, slot| {
        sum + slot.counted_weight.clone()
    });
    let slack = hint_value(cs, 35, {
        let weights: Vec<_> = (0..MAX_APPROVALS)
            .map(|slot| {
                let start = SLOTS_OFFSET + slot * SLOT_BITS;
                (
                    inputs[start].clone(),
                    inputs[start + 2..start + 34].to_vec(),
                )
            })
            .collect();
        let threshold = threshold_bits_capture(inputs);
        move |eval| {
            let total: u64 = weights
                .iter()
                .filter(|(enabled, _)| eval(enabled))
                .map(|(_, weight)| eval_be(eval, weight))
                .sum();
            total.wrapping_sub(eval_be(eval, &threshold)) & ((1 << 35) - 1)
        }
    });
    let slack = lift(cs, &slack);
    assert_zero(cs, total - threshold - slack);
}

fn threshold_bits_capture<B: Clone>(inputs: &[B]) -> Vec<B> {
    inputs[THRESHOLD_OFFSET..THRESHOLD_OFFSET + 32].to_vec()
}

/// The 43 base64url characters of the digest, as integers.
///
/// Each 6-bit group `v` selects a one-hot indicator vector with
/// `sum ind = 1` and `sum u * ind_u = v`; the character is then the linear
/// combination `sum ind_u * BASE64URL[u]`.
fn base64url_chars<C: Circuit>(cs: &mut C, digest: &[C::Bool]) -> Vec<Z<C>> {
    let one = constant::<C>(1);
    (0..43)
        .map(|group| {
            // Stream bits 6*group.., most significant first; the last group
            // is padded with two zero bits.
            let bits: Vec<C::Bool> = (0..6)
                .map(|offset| {
                    digest
                        .get(6 * group + offset)
                        .cloned()
                        .unwrap_or_else(|| C::Bool::from(false))
                })
                .collect();
            let value = lift_be(cs, &bits);
            let indicators = hint_indicators(cs, bits);
            let mut count = Z::<C>::zero();
            let mut weighted = Z::<C>::zero();
            let mut char = Z::<C>::zero();
            for (u, indicator) in indicators.into_iter().enumerate() {
                let indicator = cs.bitz::<LIMBS>(indicator);
                count += indicator.clone();
                weighted += indicator.clone() * C::Coefficient::<LIMBS>::from(u as u64);
                char += indicator * C::Coefficient::<LIMBS>::from(u64::from(BASE64URL[u]));
            }
            assert_zero(cs, count - one.clone());
            assert_zero(cs, weighted - value);
            char
        })
        .collect()
}

/// 64 hinted bits, one-hot at the big-endian value of `bits`.
fn hint_indicators<C: Circuit>(cs: &mut C, bits: Vec<C::Bool>) -> Vec<C::Bool> {
    let packed = cs.hint::<LIMBS, 64, 1, _>(move |context| {
        let eval = |b: &C::Bool| context.eval_bool(b);
        Ok(PackedBits::from_u64(1 << eval_be(&eval, &bits)))
    });
    (0..64).map(|i| packed.bit(i)).collect()
}

fn approval_slot<C: Circuit>(
    cs: &mut C,
    bits: &[C::Bool],
    kind: SlotKind,
    roster_root: &[C::Bool],
    digest_le: &[C::Bool],
    challenge: &[Z<C>],
) -> SlotSignals<C> {
    let mut cursor = Cursor {
        items: bits,
        position: 0,
    };
    let enabled_bit = cursor.bit();
    let passkey_bit = cursor.bit();
    let weight = cursor.take(32);
    let index_bits = cursor.take(DEPTH);
    let path: Vec<_> = (0..DEPTH).map(|_| cursor.take(256)).collect();
    let pk_x = cursor.take(256);
    let pk_y = cursor.take(256);
    let rp_id_hash = cursor.take(256);
    let k1_words = cursor.take(ECDSA_WORDS_BITS);
    let r1_words = cursor.take(ECDSA_WORDS_BITS);
    let auth_data = cursor.take(AUTH_DATA_LEN * 8);
    let cdj = cursor.take(CDJ_MAX_BLOCKS * 512);
    let cdj_count = cursor.take(CDJ_COUNT_BITS);

    let one = constant::<C>(1);
    let enabled = cs.bitz::<LIMBS>(enabled_bit.clone());
    let passkey = cs.bitz::<LIMBS>(passkey_bit.clone());
    let (secp256k1_selected, passkey_selected) = match kind {
        SlotKind::Any => {
            let selected = hint_value(cs, 1, {
                let (enabled, passkey) = (enabled_bit.clone(), passkey_bit.clone());
                move |eval| u64::from(eval(&enabled) && eval(&passkey))
            });
            let selected = cs.bitz::<LIMBS>(selected[0].clone());
            cs.assert_r1c::<LIMBS>(enabled.clone(), passkey, selected.clone());
            (enabled.clone() - selected.clone(), selected)
        }
        // A typed slot fixes the kind bit hashed into the leaf.
        SlotKind::Secp256k1 => {
            assert_zero(cs, passkey);
            (enabled.clone(), Z::<C>::zero())
        }
        SlotKind::Passkey => {
            assert_zero(cs, one.clone() - passkey);
            (Z::<C>::zero(), enabled.clone())
        }
    };

    // (2) The leaf commits to kind, weight, key, and RP ID hash.
    let kind_low = cs.xor(passkey_bit.clone(), C::Bool::from(true));
    let mut leaf = constant_stream::<C>(LEAF_TAG);
    leaf.extend(constant_stream::<C>(&[0]).into_iter().take(6));
    leaf.extend([passkey_bit, kind_low]);
    leaf.extend(weight.iter().cloned());
    leaf.extend(constant_stream::<C>(&[0; 11]));
    leaf.extend(pk_x.iter().cloned());
    leaf.extend(pk_y.iter().cloned());
    leaf.extend(rp_id_hash.iter().cloned());
    let mut current = sha256(cs, &leaf);

    for (direction, sibling) in index_bits.iter().zip(&path) {
        // left = direction ? sibling : current, constrained per chunk; then
        // right = current + sibling - left is linear over F2.
        let left = hint_bits(cs, 256, {
            let (direction, current, sibling) =
                (direction.clone(), current.clone(), sibling.clone());
            move |eval, i| {
                if eval(&direction) {
                    eval(&sibling[i])
                } else {
                    eval(&current[i])
                }
            }
        });
        let direction = cs.bitz::<LIMBS>(direction.clone());
        for ((current, sibling), left) in current
            .chunks(CHUNK)
            .zip(sibling.chunks(CHUNK))
            .zip(left.chunks(CHUNK))
        {
            let current = lift(cs, current);
            let sibling = lift(cs, sibling);
            let left = lift(cs, left);
            cs.assert_r1c::<LIMBS>(direction.clone(), sibling - current.clone(), left - current);
        }
        let right: Vec<_> = (0..256)
            .map(|i| {
                let sum = cs.xor(current[i].clone(), sibling[i].clone());
                cs.xor(sum, left[i].clone())
            })
            .collect();
        let mut node = left;
        node.extend(right);
        current = sha256(cs, &node);
    }
    assert_eq_bits(cs, &enabled, &current, roster_root);

    if kind != SlotKind::Passkey {
        secp256k1_approval(cs, digest_le, &k1_words, &pk_x, &pk_y, &secp256k1_selected);
    }
    if kind != SlotKind::Secp256k1 {
        passkey_approval(
            cs,
            &PasskeyEvidence {
                r1_words: &r1_words,
                auth_data: &auth_data,
                cdj: &cdj,
                cdj_count: &cdj_count,
            },
            &pk_x,
            &pk_y,
            &rp_id_hash,
            challenge,
            &passkey_selected,
        );
    }

    // (5) Weight counted only for enabled slots: counted = enabled * weight.
    let weight_value = lift_be(cs, &weight);
    let counted = hint_value(cs, 32, {
        let (enabled, weight) = (enabled_bit.clone(), weight.clone());
        move |eval| {
            if eval(&enabled) {
                eval_be(eval, &weight)
            } else {
                0
            }
        }
    });
    let counted_weight = lift(cs, &counted);
    cs.assert_r1c::<LIMBS>(enabled.clone(), weight_value, counted_weight.clone());

    let index = lift(cs, &index_bits);
    SlotSignals {
        enabled,
        enabled_bit,
        index,
        index_bits,
        counted_weight,
    }
}

/// (2) secp256k1 approval of the raw digest under the member's key.
fn secp256k1_approval<C: Circuit>(
    cs: &mut C,
    digest_le: &[C::Bool],
    k1_words: &[C::Bool],
    pk_x: &[C::Bool],
    pk_y: &[C::Bool],
    selected: &Z<C>,
) {
    let k1_inputs: [C::Bool; 7 * 256] = array::from_fn(|i| {
        if i < 256 {
            digest_le[i].clone()
        } else {
            k1_words[i - 256].clone()
        }
    });
    verify_digest_circuit(cs, Curve::Secp256k1, &k1_inputs);
    assert_eq_bits(cs, selected, &k1_words[..256], &stream_to_le(pk_x));
    assert_eq_bits(cs, selected, &k1_words[256..512], &stream_to_le(pk_y));
}

/// A passkey slot's WebAuthn inputs.
struct PasskeyEvidence<'a, B> {
    r1_words: &'a [B],
    auth_data: &'a [B],
    cdj: &'a [B],
    cdj_count: &'a [B],
}

/// (2) A strict WebAuthn P-256 assertion over the digest under the member's
/// key: H(cdj) over the selected number of prover-padded blocks, then P-256
/// over `SHA256(authData || H(cdj))`.
fn passkey_approval<C: Circuit>(
    cs: &mut C,
    evidence: &PasskeyEvidence<'_, C::Bool>,
    pk_x: &[C::Bool],
    pk_y: &[C::Bool],
    rp_id_hash: &[C::Bool],
    challenge: &[Z<C>],
    passkey_selected: &Z<C>,
) {
    let PasskeyEvidence {
        r1_words,
        auth_data,
        cdj,
        cdj_count,
    } = *evidence;
    let one = constant::<C>(1);
    let mut state = constant_state::<C>();
    let mut states = Vec::with_capacity(CDJ_MAX_BLOCKS);
    for block in cdj.chunks(512) {
        state = compress_stream(cs, &state, block);
        states.push(state.clone());
    }
    let candidates = &states[CDJ_MIN_BLOCKS - 1..];
    let client_hash = hint_bits(cs, 256, {
        let (count, candidates) = (cdj_count.to_vec(), candidates.to_vec());
        move |eval, i| {
            let selected = count.iter().position(eval).unwrap_or(0);
            eval(&candidates[selected][i])
        }
    });
    let mut count_sum = Z::<C>::zero();
    for (selector, candidate) in cdj_count.iter().zip(candidates) {
        let selector = cs.bitz::<LIMBS>(selector.clone());
        count_sum += selector.clone();
        assert_eq_bits(cs, &selector, &client_hash, candidate);
    }
    assert_zero(cs, count_sum - one.clone());

    assert_sha256_padding(cs, cdj, cdj_count);

    let mut signed = auth_data.to_vec();
    signed.extend(client_hash);
    let message = sha256(cs, &signed);
    let message_le = stream_to_le(&message);
    let r1_inputs: [C::Bool; 7 * 256] = array::from_fn(|i| {
        if i < 256 {
            message_le[i].clone()
        } else {
            r1_words[i - 256].clone()
        }
    });
    verify_digest_circuit(cs, Curve::P256, &r1_inputs);
    assert_eq_bits(cs, passkey_selected, &r1_words[..256], &stream_to_le(pk_x));
    assert_eq_bits(
        cs,
        passkey_selected,
        &r1_words[256..512],
        &stream_to_le(pk_y),
    );

    // Strict WebAuthn fields: canonical prefix with challenge = base64url(digest),
    // committed RP ID hash, and user presence and verification flags.
    let prefix_bits = CDJ_PREFIX.len() * 8;
    assert_eq_constant(cs, passkey_selected, &cdj[..prefix_bits], CDJ_PREFIX);
    for (k, char) in challenge.iter().enumerate() {
        let start = prefix_bits + 8 * k;
        let byte = lift_be(cs, &cdj[start..start + 8]);
        cs.assert_r1c::<LIMBS>(
            passkey_selected.clone(),
            byte - char.clone(),
            Z::<C>::zero(),
        );
    }
    let quote = (CDJ_CHECKED_LEN - 1) * 8;
    assert_eq_constant(cs, passkey_selected, &cdj[quote..quote + 8], b"\"");
    assert_eq_bits(cs, passkey_selected, &auth_data[..256], rp_id_hash);
    for flag_bit in [7, 5] {
        let flag = cs.bitz::<LIMBS>(auth_data[256 + flag_bit].clone());
        cs.assert_r1c::<LIMBS>(passkey_selected.clone(), one.clone() - flag, Z::<C>::zero());
    }
}

/// The prover-supplied `clientDataJSON` blocks are exactly SHA-256's padding
/// of a message of some length `L >= CDJ_CHECKED_LEN`, and the selected block
/// count is the padded length. Then the selected compression-chain output is
/// `SHA256(cdj[..L])`, and the checked prefix lies inside the message.
///
/// A one-hot marker `e` sits at byte `L`:
/// - `sum e = 1`, `L = sum i * e_i`, and no marker in the checked prefix;
/// - `e_i * (byte_i - 0x80) = 0`;
/// - `64 * blocks - (L + 9)` lies in `[0, 64)`;
/// - the selected block's last 8 bytes equal `8 * L`;
/// - bytes strictly after `L` and before the length field are zero.
fn assert_sha256_padding<C: Circuit>(cs: &mut C, cdj: &[C::Bool], cdj_count: &[C::Bool]) {
    const BYTES: usize = CDJ_MAX_BLOCKS * 64;
    let bytes: Vec<Z<C>> = (0..BYTES)
        .map(|i| lift_be(cs, &cdj[8 * i..8 * i + 8]))
        .collect();
    let counts: Vec<Z<C>> = cdj_count
        .iter()
        .map(|bit| cs.bitz::<LIMBS>(bit.clone()))
        .collect();
    let blocks = counts
        .iter()
        .enumerate()
        .fold(Z::<C>::zero(), |sum, (k, selector)| {
            sum + selector.clone() * C::Coefficient::<LIMBS>::from((CDJ_MIN_BLOCKS + k) as u64)
        });

    // The marker at L, read off the selected block's length field.
    let markers = hint_bits(cs, BYTES, {
        let (cdj, count) = (cdj.to_vec(), cdj_count.to_vec());
        move |eval, i| {
            let blocks = CDJ_MIN_BLOCKS + count.iter().position(eval).unwrap_or(0);
            let field = &cdj[(64 * blocks - 8) * 8..64 * blocks * 8];
            (eval_be(eval, field) / 8) as usize == i
        }
    });
    let markers: Vec<Z<C>> = markers
        .iter()
        .map(|bit| cs.bitz::<LIMBS>(bit.clone()))
        .collect();
    let one = constant::<C>(1);
    let count = markers
        .iter()
        .cloned()
        .fold(Z::<C>::zero(), |sum, e| sum + e);
    assert_zero(cs, count - one.clone());
    let length = markers
        .iter()
        .enumerate()
        .fold(Z::<C>::zero(), |sum, (i, e)| {
            sum + e.clone() * C::Coefficient::<LIMBS>::from(i as u64)
        });
    let in_prefix = markers[..CDJ_CHECKED_LEN]
        .iter()
        .cloned()
        .fold(Z::<C>::zero(), |sum, e| sum + e);
    assert_zero(cs, in_prefix);
    for (marker, byte) in markers.iter().zip(&bytes) {
        cs.assert_r1c::<LIMBS>(
            marker.clone(),
            byte.clone() - constant::<C>(0x80),
            Z::<C>::zero(),
        );
    }

    // The block count is the padded length of L bytes.
    let slack = hint_value(cs, 6, {
        let (markers_bits, count) = (cdj.to_vec(), cdj_count.to_vec());
        move |eval| {
            let blocks = (CDJ_MIN_BLOCKS + count.iter().position(eval).unwrap_or(0)) as u64;
            let field = &markers_bits[((64 * blocks - 8) * 8) as usize..(64 * blocks * 8) as usize];
            (64 * blocks).wrapping_sub(eval_be(eval, field) / 8 + 9)
        }
    });
    let slack = lift(cs, &slack);
    assert_zero(
        cs,
        blocks * C::Coefficient::<LIMBS>::from(64) - length.clone() - constant::<C>(9) - slack,
    );

    // The selected block ends with the 64-bit big-endian bit length.
    for (k, selector) in counts.iter().enumerate() {
        let end = 64 * (CDJ_MIN_BLOCKS + k);
        let field = lift_be(cs, &cdj[(end - 8) * 8..end * 8]);
        cs.assert_r1c::<LIMBS>(
            selector.clone(),
            field - length.clone() * C::Coefficient::<LIMBS>::from(8),
            Z::<C>::zero(),
        );
    }

    // Zero fill: byte i is zero when L < i and i precedes the length field.
    let fill = hint_bits(cs, BYTES, {
        let (cdj, count) = (cdj.to_vec(), cdj_count.to_vec());
        move |eval, i| {
            let blocks = CDJ_MIN_BLOCKS + count.iter().position(eval).unwrap_or(0);
            let field = &cdj[(64 * blocks - 8) * 8..64 * blocks * 8];
            let length = (eval_be(eval, field) / 8) as usize;
            length < i && i < 64 * blocks - 8
        }
    });
    let mut after = Z::<C>::zero();
    for (i, (marker, byte)) in markers.iter().zip(&bytes).enumerate() {
        let before_field = counts
            .iter()
            .enumerate()
            .filter(|(k, _)| i + 8 < 64 * (CDJ_MIN_BLOCKS + k))
            .fold(Z::<C>::zero(), |sum, (_, selector)| sum + selector.clone());
        let fill = cs.bitz::<LIMBS>(fill[i].clone());
        cs.assert_r1c::<LIMBS>(after.clone(), before_field, fill.clone());
        cs.assert_r1c::<LIMBS>(fill, byte.clone(), Z::<C>::zero());
        after += marker.clone();
    }
}

/// SHA-256 of a fixed-length message given in stream bit order (bytes in
/// order, most significant bit first). Returns the digest in stream order.
fn sha256<C: Circuit>(cs: &mut C, message: &[C::Bool]) -> Vec<C::Bool> {
    assert!(message.len().is_multiple_of(8));
    let mut padded = message.to_vec();
    let mut tail = vec![0x80];
    while (message.len() / 8 + tail.len()) % 64 != 56 {
        tail.push(0);
    }
    tail.extend_from_slice(&(message.len() as u64).to_be_bytes());
    padded.extend(constant_stream::<C>(&tail));
    let mut state = constant_state::<C>();
    for block in padded.chunks(512) {
        state = compress_stream(cs, &state, block);
    }
    state
}

/// One SHA-256 compression on stream-ordered state and block bits.
fn compress_stream<C: Circuit>(cs: &mut C, state: &[C::Bool], block: &[C::Bool]) -> Vec<C::Bool> {
    let word = |bits: &[C::Bool], w: usize| -> Word<C::Bool, 32> {
        Word::new(array::from_fn(|bit| bits[w * 32 + 31 - bit].clone()))
    };
    let block = array::from_fn(|w| word(block, w));
    let state = array::from_fn(|w| word(state, w));
    let output = compress(cs, block, state);
    (0..256)
        .map(|i| output[i / 32].word.bit(31 - i % 32))
        .collect()
}

fn constant_state<C: Circuit>() -> Vec<C::Bool> {
    let bytes: Vec<u8> = INITIAL_STATE.iter().flat_map(|w| w.to_be_bytes()).collect();
    constant_stream::<C>(&bytes)
}

fn constant_stream<C: Circuit>(bytes: &[u8]) -> Vec<C::Bool> {
    stream_bits(bytes).into_iter().map(C::Bool::from).collect()
}

/// Reverses a 256-bit big-endian stream into little-endian integer bits.
fn stream_to_le<B: Clone>(stream: &[B]) -> Vec<B> {
    stream.iter().rev().cloned().collect()
}

/// Stream bit order: bytes in order, most significant bit first.
pub fn stream_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |bit| byte >> bit & 1 == 1))
        .collect()
}

fn constant<C: Circuit>(value: u64) -> Z<C> {
    Z::<C>::from(C::Coefficient::<LIMBS>::from(value))
}

/// `sum 2^i bits[i]` for at most 64 little-endian bits.
fn lift<C: Circuit>(cs: &mut C, bits: &[C::Bool]) -> Z<C> {
    assert!(bits.len() <= CHUNK);
    let mut sum = Z::<C>::zero();
    for (i, bit) in bits.iter().enumerate() {
        sum += cs.bitz::<LIMBS>(bit.clone()) * C::Coefficient::<LIMBS>::from(1_u64 << i);
    }
    sum
}

/// Lifts big-endian stream bits.
fn lift_be<C: Circuit>(cs: &mut C, bits: &[C::Bool]) -> Z<C> {
    lift(cs, &stream_to_le(bits))
}

fn assert_zero<C: Circuit>(cs: &mut C, value: Z<C>) {
    cs.assert_r1c::<LIMBS>(constant::<C>(1), value, Z::<C>::zero());
}

/// `gate * (a - b) = 0` per chunk: when the 0/1 gate is set, `a == b`.
fn assert_eq_bits<C: Circuit>(cs: &mut C, gate: &Z<C>, a: &[C::Bool], b: &[C::Bool]) {
    assert_eq!(a.len(), b.len());
    for (a, b) in a.chunks(CHUNK).zip(b.chunks(CHUNK)) {
        let difference = lift(cs, a) - lift(cs, b);
        cs.assert_r1c::<LIMBS>(gate.clone(), difference, Z::<C>::zero());
    }
}

/// `gate * (a - bytes) = 0` per chunk, for stream-ordered `a`.
fn assert_eq_constant<C: Circuit>(cs: &mut C, gate: &Z<C>, a: &[C::Bool], bytes: &[u8]) {
    let expected = stream_bits(bytes);
    assert_eq!(a.len(), expected.len());
    for (a, expected) in a.chunks(CHUNK).zip(expected.chunks(CHUNK)) {
        let value = expected
            .iter()
            .enumerate()
            .fold(0_u64, |sum, (i, bit)| sum | u64::from(*bit) << i);
        let difference = lift(cs, a) - constant::<C>(value);
        cs.assert_r1c::<LIMBS>(gate.clone(), difference, Z::<C>::zero());
    }
}

type Eval<'a, B> = &'a dyn Fn(&B) -> bool;

/// Allocates `count` hinted bits; `bit(eval, i)` computes bit `i`.
fn hint_bits<C, H>(cs: &mut C, count: usize, bit: H) -> Vec<C::Bool>
where
    C: Circuit,
    H: Fn(Eval<'_, C::Bool>, usize) -> bool + Send + Sync + 'static,
{
    assert_eq!(count, 256, "hint_bits allocates 256-bit words");
    let packed = cs.hint::<LIMBS, 256, 4, _>(move |context| {
        let eval = |b: &C::Bool| context.eval_bool(b);
        Ok(PackedBits::from_fn(|i| bit(&eval, i)))
    });
    (0..count).map(|i| packed.bit(i)).collect()
}

/// Allocates `width <= 64` hinted little-endian bits holding `value(eval)`.
fn hint_value<C, H>(cs: &mut C, width: usize, value: H) -> Vec<C::Bool>
where
    C: Circuit,
    H: Fn(Eval<'_, C::Bool>) -> u64 + Send + Sync + 'static,
{
    assert!(width <= CHUNK);
    let packed = cs.hint::<LIMBS, 64, 1, _>(move |context| {
        let eval = |b: &C::Bool| context.eval_bool(b);
        Ok(PackedBits::from_u64(value(&eval)))
    });
    (0..width).map(|i| packed.bit(i)).collect()
}

fn eval_le<B>(eval: Eval<'_, B>, bits: &[B]) -> u64 {
    bits.iter()
        .enumerate()
        .fold(0, |sum, (i, bit)| sum | u64::from(eval(bit)) << i)
}

fn eval_be<B>(eval: Eval<'_, B>, bits: &[B]) -> u64 {
    bits.iter()
        .fold(0, |sum, bit| sum << 1 | u64::from(eval(bit)))
}

/// Encodes the statement and witness as input bits in the layout read by the
/// circuit.
pub fn witness_bits(statement: &Statement, witness: &Witness) -> Vec<bool> {
    let mut bits = Vec::with_capacity(INPUT_BITS);
    bits.extend(stream_bits(&statement.policy_commitment));
    bits.extend(stream_bits(&statement.authorization_digest));
    bits.extend(stream_bits(&witness.roster_root));
    bits.extend(stream_bits(&witness.threshold.to_be_bytes()));
    bits.extend(stream_bits(&witness.salt));
    for slot in &witness.slots {
        bits.push(slot.enabled);
        bits.push(slot.is_passkey);
        bits.extend(stream_bits(&slot.weight.to_be_bytes()));
        bits.extend((0..DEPTH).map(|level| slot.leaf_index >> level & 1 == 1));
        for sibling in &slot.path {
            bits.extend(stream_bits(sibling));
        }
        bits.extend(stream_bits(&slot.pk_x));
        bits.extend(stream_bits(&slot.pk_y));
        bits.extend(stream_bits(&slot.rp_id_hash));
        ecdsa_bits(&mut bits, Curve::Secp256k1, &slot.secp256k1);
        ecdsa_bits(&mut bits, Curve::P256, &slot.p256);
        bits.extend(stream_bits(&slot.auth_data));
        bits.extend(stream_bits(&slot.cdj_blocks));
        bits.extend((CDJ_MIN_BLOCKS..=CDJ_MAX_BLOCKS).map(|count| count == slot.cdj_block_count));
    }
    assert_eq!(bits.len(), INPUT_BITS);
    bits
}

fn ecdsa_bits(bits: &mut Vec<bool>, curve: Curve, inputs: &EcdsaInputs) {
    let order = curve.order();
    // n is prime, so x^(n-2) is the inverse of nonzero x and 0 otherwise.
    let inverse = |x: &BigUint| x.modpow(&(order - 2_u32), order);
    for word in [
        inputs.qx.clone(),
        inputs.qy.clone(),
        inputs.r.clone(),
        inputs.s.clone(),
        inverse(&inputs.r),
        inverse(&inputs.s),
    ] {
        bits.extend((0..256).map(|i| word.bit(i)));
    }
}
