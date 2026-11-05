//! Block-level key release and decryption, optimized for whole batches on raw blst.
//!
//! Everything that does not need a decryption key runs when the including block arrives:
//! hashing each identity to G1, signing key shares (kept until the validator may release them),
//! and precomputing the Miller-loop lines of each ciphertext's G2 point. Once a quorum of shares
//! is in, each body costs one 11-point multi-scalar multiplication (for 16 validators), one
//! Miller loop over precomputed lines and one final exponentiation. The Fujisaki-Okamoto
//! re-encryption check, a G2 scalar multiplication per body in [`crate::tle`], is replaced by one
//! random linear combination over the whole batch.
//!
//! Outputs match [`crate::key_shares`], [`crate::recover_keys`] and [`crate::EncryptedBody::decrypt`]
//! bit for bit; the tests check this.

use crate::{EncryptedBody, Error, NAMESPACE, NetworkIdentity};
use alloy_primitives::B256;
use blst::{
    BLST_ERROR, blst_bendian_from_fp12, blst_final_exp, blst_fp6, blst_fp12, blst_fp12_is_equal,
    blst_hash_to_g1, blst_miller_loop, blst_miller_loop_lines, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_affine_compress, blst_p1_affine_in_g1, blst_p1_affine_serialize,
    blst_p1_deserialize, blst_p1_from_affine, blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress,
    blst_p1s_mult_pippenger, blst_p1s_mult_pippenger_scratch_sizeof, blst_p2_affine,
    blst_p2_affine_generator, blst_p2_uncompress, blst_precompute_lines, blst_scalar,
    blst_scalar_from_bendian, limb_t,
};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::{G2, Scalar, Share, SmallScalar},
    variant::{MinSig, Variant},
};
use commonware_math::algebra::{Additive, CryptoGroup, Field, Space};
use commonware_parallel::Strategy;
use commonware_utils::{Participant, union_unique};
use rand_core::CryptoRng;
use sha2::{Digest, Sha256};

/// Number of Miller-loop line coefficients blst precomputes for one G2 point.
const LINES: usize = 68;

/// Domain separation tag of [`crate::tle`]'s H3, which derives the encryption randomness.
const H3_DST: &[u8] = b"TLE_BLS12381_XMD:SHA-256_SSWU_RO_H3_";

/// Size of a key share on the wire, compressed.
pub const SHARE_COMPRESSED: usize = 48;

/// Size of a key share on the wire, uncompressed: twice the bytes, no square root to decode.
pub const SHARE_UNCOMPRESSED: usize = 96;

/// Chunk of points one worker sums in a batched verification.
const MSM_CHUNK: usize = 512;

/// A decryption key as a G1 point in affine form.
pub type Key = blst_p1_affine;

/// An encrypted body prepared when its block arrives, before any key can exist.
pub struct Prepared {
    /// H(identity) in G1: the message every key share signs.
    hashed: blst_p1_affine,
    /// Miller-loop lines of the ciphertext's U.
    lines: Box<[blst_fp6]>,
    /// U, for the batched Fujisaki-Okamoto check.
    u: G2,
    /// sigma masked by the pairing.
    v: [u8; 32],
    /// The body key masked by H4(sigma).
    w: [u8; 32],
}

impl Prepared {
    /// Hashes the identity and precomputes the pairing lines of a body's ciphertext.
    pub fn new(identity: B256, body: &EncryptedBody) -> Result<Self, Error> {
        let message = union_unique(NAMESPACE, identity.as_slice());
        let dst = <MinSig as Variant>::MESSAGE;
        let u_bytes = body.key.u.encode();
        let mut hashed = blst_p1::default();
        let mut hashed_affine = blst_p1_affine::default();
        let mut u = blst_p2_affine::default();
        let mut lines = vec![blst_fp6::default(); LINES].into_boxed_slice();
        // SAFETY: every pointer is valid for the length passed; lines holds LINES entries.
        unsafe {
            blst_hash_to_g1(
                &mut hashed,
                message.as_ptr(),
                message.len(),
                dst.as_ptr(),
                dst.len(),
                core::ptr::null(),
                0,
            );
            blst_p1_to_affine(&mut hashed_affine, &hashed);
            // U was decoded and subgroup-checked with the transaction; this only recovers its
            // affine coordinates.
            if blst_p2_uncompress(&mut u, u_bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return Err(Error::InvalidPoint);
            }
            blst_precompute_lines(lines.as_mut_ptr(), &u);
        }
        Ok(Self {
            hashed: hashed_affine,
            lines,
            u: body.key.u,
            v: block(body.key.v.as_ref()),
            w: block(body.key.w.as_ref()),
        })
    }
}

/// Prepares a whole block's bodies.
pub fn prepare(
    bodies: &[(B256, EncryptedBody)],
    strategy: &impl Strategy,
) -> Result<Vec<Prepared>, Error> {
    strategy
        .map_collect_vec(bodies, |(identity, body)| Prepared::new(*identity, body))
        .into_iter()
        .collect()
}

/// The network identity in the form batched key verification pairs with.
pub fn network_point(network: &NetworkIdentity) -> Result<blst_p2_affine, Error> {
    let bytes = network.encode();
    let mut point = blst_p2_affine::default();
    // SAFETY: bytes holds a 96-byte compressed G2 point.
    if unsafe { blst_p2_uncompress(&mut point, bytes.as_ptr()) } != BLST_ERROR::BLST_SUCCESS {
        return Err(Error::InvalidPoint);
    }
    Ok(point)
}

/// Signs every prepared identity with this validator's share. Validators sign when the block
/// arrives and hold the shares until they may release them.
pub fn sign(share: &Share, prepared: &[Prepared], strategy: &impl Strategy) -> Vec<Key> {
    let scalar = share.private.expose(to_blst_scalar);
    strategy.map_collect_vec(prepared, |p| {
        let mut base = blst_p1::default();
        let mut signed = blst_p1::default();
        let mut out = blst_p1_affine::default();
        // SAFETY: valid pointers; the scalar is 32 bytes and at most 255 bits.
        unsafe {
            blst_p1_from_affine(&mut base, &p.hashed);
            blst_p1_mult(&mut signed, &base, scalar.b.as_ptr(), 255);
            blst_p1_to_affine(&mut out, &signed);
        }
        out
    })
}

/// Encodes shares compressed, 48 bytes each.
pub fn encode_compressed(shares: &[Key]) -> Vec<u8> {
    let mut out = vec![0u8; shares.len() * SHARE_COMPRESSED];
    for (share, chunk) in shares.iter().zip(out.as_chunks_mut::<SHARE_COMPRESSED>().0) {
        // SAFETY: chunk is 48 bytes.
        unsafe { blst_p1_affine_compress(chunk.as_mut_ptr(), share) };
    }
    out
}

/// Encodes shares uncompressed, 96 bytes each.
pub fn encode_uncompressed(shares: &[Key]) -> Vec<u8> {
    let mut out = vec![0u8; shares.len() * SHARE_UNCOMPRESSED];
    for (share, chunk) in shares
        .iter()
        .zip(out.as_chunks_mut::<SHARE_UNCOMPRESSED>().0)
    {
        // SAFETY: chunk is 96 bytes.
        unsafe { blst_p1_affine_serialize(chunk.as_mut_ptr(), share) };
    }
    out
}

/// Decodes one validator's shares. Points are only checked to be on the curve: recovered keys
/// are subgroup-checked and verified instead, which is one check per body rather than one per
/// share.
pub fn decode(bytes: &[u8], compressed: bool, strategy: &impl Strategy) -> Result<Vec<Key>, Error> {
    let size = if compressed {
        SHARE_COMPRESSED
    } else {
        SHARE_UNCOMPRESSED
    };
    if !bytes.len().is_multiple_of(size) {
        return Err(Error::InvalidPoint);
    }
    strategy
        .map_collect_vec(bytes.chunks_exact(size).collect::<Vec<_>>(), |chunk| {
            let mut point = blst_p1_affine::default();
            // SAFETY: chunk holds exactly one encoded point.
            let result = unsafe {
                if compressed {
                    blst_p1_uncompress(&mut point, chunk.as_ptr())
                } else {
                    blst_p1_deserialize(&mut point, chunk.as_ptr())
                }
            };
            (result == BLST_ERROR::BLST_SUCCESS)
                .then_some(point)
                .ok_or(Error::InvalidPoint)
        })
        .into_iter()
        .collect()
}

/// Lagrange weights at zero for the participants of a quorum, whose evaluation points are their
/// index plus one (`Mode::NonZeroCounter`).
fn lagrange_weights(indices: &[Participant]) -> Vec<blst_scalar> {
    let xs: Vec<Scalar> = indices
        .iter()
        .map(|i| Scalar::from(u64::from(i.get()) + 1))
        .collect();
    xs.iter()
        .enumerate()
        .map(|(j, xj)| {
            let mut weight = Scalar::from(1u64);
            for (m, xm) in xs.iter().enumerate() {
                if m != j {
                    weight *= &(xm.clone() * &(xm.clone() - xj).inv());
                }
            }
            to_blst_scalar(&weight)
        })
        .collect()
}

/// Recovers every body's key from one quorum of validators' shares: `quorum[v]` is validator
/// `v`'s index and its share for every body. Each key is subgroup-checked; verify the batch
/// with [`verify_keys`] before using it.
pub fn recover(
    quorum: &[(Participant, Vec<Key>)],
    strategy: &impl Strategy,
) -> Result<Vec<Key>, Error> {
    let count = quorum.first().map_or(0, |(_, shares)| shares.len());
    for (_, shares) in quorum {
        if shares.len() != count {
            return Err(Error::LengthMismatch {
                expected: count,
                actual: shares.len(),
            });
        }
    }
    let indices: Vec<_> = quorum.iter().map(|(index, _)| *index).collect();
    let weights = lagrange_weights(&indices);
    let scratch_words =
        // SAFETY: pure size query.
        unsafe { blst_p1s_mult_pippenger_scratch_sizeof(quorum.len()) }.div_ceil(size_of::<limb_t>());
    strategy
        .map_init_collect_vec(
            0..count,
            || vec![0 as limb_t; scratch_words],
            |scratch, i| {
                let points: Vec<*const blst_p1_affine> = quorum
                    .iter()
                    .map(|(_, shares)| &shares[i] as *const _)
                    .collect();
                let weight_ptrs: Vec<*const u8> = weights.iter().map(|w| w.b.as_ptr()).collect();
                let mut sum = blst_p1::default();
                let mut key = blst_p1_affine::default();
                // SAFETY: points and weights hold quorum.len() valid entries; scratch is sized
                // by blst for that count.
                let in_group = unsafe {
                    blst_p1s_mult_pippenger(
                        &mut sum,
                        points.as_ptr(),
                        points.len(),
                        weight_ptrs.as_ptr(),
                        255,
                        scratch.as_mut_ptr(),
                    );
                    blst_p1_to_affine(&mut key, &sum);
                    blst_p1_affine_in_g1(&key)
                };
                in_group.then_some(key).ok_or(Error::InvalidPoint)
            },
        )
        .into_iter()
        .collect()
}

/// Checks every recovered key against the network identity with two 128-bit multi-scalar
/// multiplications and two pairings: e(sum rho_i key_i, G2) = e(sum rho_i H(id_i), network).
pub fn verify_keys(
    rng: &mut impl CryptoRng,
    network: &blst_p2_affine,
    prepared: &[Prepared],
    keys: &[Key],
    strategy: &impl Strategy,
) -> Result<(), Error> {
    if prepared.len() != keys.len() {
        return Err(Error::LengthMismatch {
            expected: prepared.len(),
            actual: keys.len(),
        });
    }
    let rhos: Vec<[u8; 32]> = (0..keys.len())
        .map(|_| {
            let mut rho = [0u8; 32];
            rng.fill_bytes(&mut rho[..16]);
            rho
        })
        .collect();
    let hashed: Vec<_> = prepared.iter().map(|p| p.hashed).collect();
    let (key_sum, hash_sum) = strategy.join(
        || msm_128(keys, &rhos, strategy),
        || msm_128(&hashed, &rhos, strategy),
    );
    let mut lhs = blst_fp12::default();
    let mut rhs = blst_fp12::default();
    // SAFETY: valid affine points; the generator pointer is a static.
    let equal = unsafe {
        blst_miller_loop(&mut lhs, blst_p2_affine_generator(), &key_sum);
        blst_final_exp(&mut lhs, &lhs);
        blst_miller_loop(&mut rhs, network, &hash_sum);
        blst_final_exp(&mut rhs, &rhs);
        blst_fp12_is_equal(&lhs, &rhs)
    };
    if equal {
        Ok(())
    } else {
        Err(Error::InvalidKey)
    }
}

/// Recovers each body's sigma, the opening that [`verify_openings`] checks, with its verified
/// decryption key: one Miller loop over precomputed lines and one final exponentiation per body.
///
/// Validators can split a block between them by body, decrypt only their slice and exchange
/// sigmas, since checking an opening costs far less than producing it.
pub fn decrypt_sigmas(
    prepared: &[Prepared],
    keys: &[Key],
    strategy: &impl Strategy,
) -> Result<Vec<[u8; 32]>, Error> {
    if prepared.len() != keys.len() {
        return Err(Error::LengthMismatch {
            expected: prepared.len(),
            actual: keys.len(),
        });
    }
    Ok(
        strategy.map_collect_vec(prepared.iter().zip(keys), |(p, key)| {
            let mut gt = blst_fp12::default();
            let mut gt_bytes = [0u8; 576];
            // SAFETY: lines holds LINES entries; key is a valid affine point.
            unsafe {
                blst_miller_loop_lines(&mut gt, p.lines.as_ptr(), key);
                blst_final_exp(&mut gt, &gt);
                blst_bendian_from_fp12(gt_bytes.as_mut_ptr(), &gt);
            }
            xor(
                &p.v,
                &Sha256::new()
                    .chain_update(b"h2")
                    .chain_update(gt_bytes)
                    .finalize()
                    .into(),
            )
        }),
    )
}

/// Checks each body's sigma against its ciphertext and returns its body key, with one random
/// linear combination for the whole batch in place of a G2 multiplication per body. `None`
/// marks a sigma that does not open its ciphertext.
///
/// A sigma that passes is the only one that opens an honestly built ciphertext: it fixes
/// r = H3(sigma, M) with U = rG. A sender that builds U and W from a sigma but masks it wrongly in
/// V can open its own body here although decryption with the key fails.
pub fn verify_openings(
    rng: &mut impl CryptoRng,
    prepared: &[Prepared],
    sigmas: &[[u8; 32]],
    strategy: &impl Strategy,
) -> Result<Vec<Option<[u8; 32]>>, Error> {
    if prepared.len() != sigmas.len() {
        return Err(Error::LengthMismatch {
            expected: prepared.len(),
            actual: sigmas.len(),
        });
    }
    let openings: Vec<([u8; 32], Scalar)> =
        strategy.map_collect_vec(prepared.iter().zip(sigmas), |(p, sigma)| {
            let body_key = xor(
                &p.w,
                &Sha256::new()
                    .chain_update(b"h4")
                    .chain_update(sigma)
                    .finalize()
                    .into(),
            );
            let mut h3_input = [0u8; 64];
            h3_input[..32].copy_from_slice(sigma);
            h3_input[32..].copy_from_slice(&body_key);
            (body_key, Scalar::map(H3_DST, &h3_input))
        });

    // U_i = r_i G for every i iff, except with probability 2^-128 over random 128-bit rho_i,
    // sum rho_i U_i = (sum rho_i r_i) G.
    let rhos: Vec<SmallScalar> = (0..openings.len())
        .map(|_| SmallScalar::random(&mut *rng))
        .collect();
    let us: Vec<G2> = prepared.iter().map(|p| p.u).collect();
    let lhs = G2::msm(&us, &rhos, strategy);
    let mut combined = Scalar::zero();
    for (rho, (_, r)) in rhos.iter().zip(&openings) {
        combined += &(Scalar::from(rho.clone()) * r);
    }
    if lhs == G2::generator() * &combined {
        return Ok(openings
            .into_iter()
            .map(|(body_key, _)| Some(body_key))
            .collect());
    }
    // Some body does not open: check each on its own. Only a sender's malformed ciphertext or a
    // wrong sigma causes this.
    Ok(
        strategy.map_collect_vec(us.iter().zip(openings), |(u, (body_key, r))| {
            (*u == G2::generator() * &r).then_some(body_key)
        }),
    )
}

/// Opens every sealed body with its body key, in parallel.
pub fn open_bodies(
    bodies: &[(B256, EncryptedBody)],
    body_keys: &[Option<[u8; 32]>],
    strategy: &impl Strategy,
) -> Vec<Option<Vec<u8>>> {
    strategy.map_collect_vec(bodies.iter().zip(body_keys), |((_, body), key)| {
        let key = (*key)?;
        ChaCha20Poly1305::new(&key.into())
            .decrypt(&Default::default(), body.sealed.as_slice())
            .ok()
    })
}

/// Sums `rho_i points_i` with 128-bit little-endian scalars, one blst MSM per chunk in parallel.
fn msm_128(
    points: &[blst_p1_affine],
    rhos: &[[u8; 32]],
    strategy: &impl Strategy,
) -> blst_p1_affine {
    let chunks: Vec<_> = points
        .chunks(MSM_CHUNK)
        .zip(rhos.chunks(MSM_CHUNK))
        .collect();
    let partials = strategy.map_collect_vec(chunks, |(points, rhos)| {
        let point_ptrs: Vec<*const blst_p1_affine> = points.iter().map(|p| p as *const _).collect();
        let rho_ptrs: Vec<*const u8> = rhos.iter().map(|r| r.as_ptr()).collect();
        // SAFETY: pure size query, then pointers to points.len() valid entries each.
        let words = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(points.len()) }
            .div_ceil(size_of::<limb_t>());
        let mut scratch = vec![0 as limb_t; words];
        let mut sum = blst_p1::default();
        unsafe {
            blst_p1s_mult_pippenger(
                &mut sum,
                point_ptrs.as_ptr(),
                points.len(),
                rho_ptrs.as_ptr(),
                128,
                scratch.as_mut_ptr(),
            );
        }
        sum
    });
    let mut total = blst_p1::default();
    for partial in partials {
        // SAFETY: valid points; blst handles the point at infinity.
        unsafe { blst_p1_add_or_double(&mut total, &total, &partial) };
    }
    let mut affine = blst_p1_affine::default();
    // SAFETY: valid point.
    unsafe { blst_p1_to_affine(&mut affine, &total) };
    affine
}

fn to_blst_scalar(scalar: &Scalar) -> blst_scalar {
    let bytes = scalar.encode();
    let mut out = blst_scalar::default();
    // SAFETY: a Scalar encodes to 32 big-endian bytes.
    unsafe { blst_scalar_from_bendian(&mut out, bytes.as_ptr()) };
    out
}

fn block(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("tle blocks are 32 bytes")
}

fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    core::array::from_fn(|i| a[i] ^ b[i])
}
