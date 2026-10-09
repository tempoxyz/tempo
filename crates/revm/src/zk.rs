//! ZK signature validation ([TIP-1131]).
//!
//! Sender recovery only decodes a ZK signature and derives its address. Validation then runs in
//! increasing cost: activation, scheme, and time checks in `validate_env`, the issuer key read
//! from the Key Publisher, and finally the access key signature and the proof.
//!
//! [TIP-1131]: https://docs.tempo.xyz/protocol/tips/tip-1131

use alloy_primitives::{Address, B256, U256, keccak256};
use parking_lot::Mutex;
use rayon::prelude::*;
use revm::context::JournalTr;
use std::sync::LazyLock;
use tempo_precompiles::key_publisher::{
    KEY_PUBLISHER_ADDRESS, is_key_active_at, key_valid_until_slot,
};
use tempo_primitives::transaction::ZkSignature;
use tempo_zk::{Fr, Proof, Scheme, SignatureStatement, verify_many};

/// Allowance for issuer clocks running ahead of block time, in seconds.
pub const MAX_FUTURE_SKEW: u64 = 60;

/// Successful verifications kept for reuse between pool admission and block import.
const VERIFIED_CACHE_SIZE: u32 = 65_536;

/// Successful verifications, keyed by `keccak256(zk_signature || d)`.
static VERIFIED: LazyLock<Mutex<schnellru::LruMap<B256, Address>>> = LazyLock::new(|| {
    Mutex::new(schnellru::LruMap::new(schnellru::ByLength::new(
        VERIFIED_CACHE_SIZE,
    )))
});

/// Why a ZK signature was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, thiserror::Error)]
pub enum ZkSignatureError {
    /// ZK signatures are not active at this block.
    #[error("ZK signatures are not active")]
    NotActive,
    /// The scheme is unknown or has no verifying key.
    #[error("unknown ZK signature scheme {0}")]
    UnknownScheme(u8),
    /// The issuer signed the statement more than [`MAX_FUTURE_SKEW`] after the block timestamp.
    #[error(
        "ZK signature issued at {issued_at}, after block timestamp {timestamp} plus 60 seconds"
    )]
    IssuedInFuture {
        /// When the issuer signed the statement.
        issued_at: u64,
        /// The block timestamp.
        timestamp: u64,
    },
    /// The block timestamp is after `valid_until`.
    #[error("ZK signature expired at {valid_until}, before block timestamp {timestamp}")]
    Expired {
        /// When the signature expired.
        valid_until: u64,
        /// The block timestamp.
        timestamp: u64,
    },
    /// `valid_until` exceeds `issued_at` plus the scheme's maximum window.
    #[error("ZK signature validity window exceeds the scheme's maximum")]
    WindowTooLong,
    /// The publisher does not treat the issuer key as active.
    #[error("ZK signature issuer key is not active for its publisher")]
    KeyInactive,
    /// The access key signature or the proof does not verify.
    #[error("ZK signature is invalid")]
    Invalid,
    /// A ZK signature appears where it is not accepted.
    #[error("ZK signatures are not accepted in authorization lists")]
    NotAccepted,
    /// A ZK-signed key authorization names an account other than the transaction sender.
    #[error("ZK-signed key authorization does not sign for the transaction sender")]
    SignerNotSender,
}

impl ZkSignatureError {
    /// Returns `true` if the transaction can never become valid.
    pub const fn is_bad_transaction(&self) -> bool {
        !matches!(
            self,
            Self::NotActive
                | Self::UnknownScheme(_)
                | Self::IssuedInFuture { .. }
                | Self::Expired { .. }
                | Self::KeyInactive
        )
    }
}

/// Checks a ZK signature's scheme and validity window against `timestamp`.
pub fn check_scheme_and_time(
    signature: &ZkSignature,
    timestamp: u64,
    chain_id: u64,
) -> Result<&'static Scheme, ZkSignatureError> {
    let scheme = tempo_zk::scheme(signature.scheme)
        .filter(|scheme| scheme.verifying_key_on(chain_id).is_some())
        .ok_or(ZkSignatureError::UnknownScheme(signature.scheme))?;
    if signature.issued_at > timestamp.saturating_add(MAX_FUTURE_SKEW) {
        return Err(ZkSignatureError::IssuedInFuture {
            issued_at: signature.issued_at,
            timestamp,
        });
    }
    if timestamp > signature.valid_until {
        return Err(ZkSignatureError::Expired {
            valid_until: signature.valid_until,
            timestamp,
        });
    }
    if signature.valid_until > signature.issued_at.saturating_add(scheme.max_window) {
        return Err(ZkSignatureError::WindowTooLong);
    }
    Ok(scheme)
}

/// Reads the issuer key's status from Key Publisher storage at the journal's position and
/// requires it to be active at `timestamp`.
pub fn check_issuer_key<JOURNAL: JournalTr>(
    journal: &mut JOURNAL,
    signature: &ZkSignature,
    timestamp: u64,
) -> Result<Result<(), ZkSignatureError>, <JOURNAL::Database as revm::Database>::Error> {
    journal.load_account(KEY_PUBLISHER_ADDRESS)?;
    let slot = key_valid_until_slot(signature.publisher_id, signature.issuer, signature.key_hash);
    let value: U256 = journal.sload(KEY_PUBLISHER_ADDRESS, slot)?.data;
    // The slot holds a `uint64`.
    let valid_until = value.as_limbs()[0];
    Ok(if is_key_active_at(valid_until, timestamp) {
        Ok(())
    } else {
        Err(ZkSignatureError::KeyInactive)
    })
}

/// Verifies a ZK signature's access key signature and proof for the context digest `d`, and
/// returns the access key.
///
/// The outcome is cached on the signature, and successes are also cached process-wide, so a
/// signature checked by the pool is not checked again on import. Callers must still run the
/// scheme, time, and issuer key checks for every block.
pub fn verify(signature: &ZkSignature, d: &B256) -> Result<Address, ZkSignatureError> {
    if let Some(outcome) = signature.cached_verification(d) {
        return outcome.ok_or(ZkSignatureError::Invalid);
    }
    let key = cache_key(signature, d);
    if let Some(access_key) = VERIFIED.lock().get(&key).copied() {
        signature.cache_verification(*d, Some(access_key));
        return Ok(access_key);
    }

    let outcome = prepare(signature, d).and_then(|prepared| {
        prepared
            .key
            .verify(&prepared.proof, &prepared.input)
            .then_some(prepared.access_key)
    });
    record(signature, d, key, outcome);
    outcome.ok_or(ZkSignatureError::Invalid)
}

/// Verifies many ZK signatures ahead of execution, in parallel and with batched proof checks,
/// caching each outcome for [`verify`]. Signatures with a cached outcome are skipped.
pub fn preverify(items: &[(&ZkSignature, B256)]) {
    let pending: Vec<_> = items
        .par_iter()
        .filter(|(signature, d)| signature.cached_verification(d).is_none())
        .map(|(signature, d)| {
            let key = cache_key(signature, d);
            let cached = VERIFIED.lock().get(&key).copied();
            (*signature, *d, key, cached)
        })
        .collect();

    let mut uncached = Vec::new();
    for (signature, d, key, cached) in pending {
        match cached {
            Some(access_key) => signature.cache_verification(d, Some(access_key)),
            None => uncached.push((signature, d, key)),
        }
    }

    let prepared: Vec<_> = uncached
        .par_iter()
        .map(|(signature, d, _)| prepare(signature, d))
        .collect();

    // Batch proofs that share a verifying key; only one scheme exists today.
    let mut groups: Vec<(&'static tempo_zk::PreparedVerifyingKey, Vec<usize>)> = Vec::new();
    for (index, prepared) in prepared.iter().enumerate() {
        let Some(prepared) = prepared else { continue };
        match groups
            .iter_mut()
            .find(|(key, _)| core::ptr::eq(*key, prepared.key))
        {
            Some((_, members)) => members.push(index),
            None => groups.push((prepared.key, vec![index])),
        }
    }

    let mut outcomes: Vec<Option<Address>> = vec![None; uncached.len()];
    for (key, members) in groups {
        let batch: Vec<(&Proof, Fr)> = members
            .iter()
            .map(|index| {
                let prepared = prepared[*index]
                    .as_ref()
                    .expect("grouped entries are prepared");
                (&prepared.proof, prepared.input)
            })
            .collect();
        for (index, valid) in members.iter().zip(verify_many(key, &batch)) {
            if valid {
                outcomes[*index] = prepared[*index]
                    .as_ref()
                    .map(|prepared| prepared.access_key);
            }
        }
    }

    for ((signature, d, key), outcome) in uncached.into_iter().zip(outcomes) {
        record(signature, &d, key, outcome);
    }
}

/// The parts of a ZK signature check that precede the pairing.
struct Prepared {
    key: &'static tempo_zk::PreparedVerifyingKey,
    proof: Proof,
    input: Fr,
    access_key: Address,
}

/// Recovers the access key, decodes the proof, and computes the public input.
fn prepare(signature: &ZkSignature, d: &B256) -> Option<Prepared> {
    let key = tempo_zk::scheme(signature.scheme)?.verifying_key()?;
    let access_key = signature.recover_access_key(d).ok()?;
    let proof = Proof::decode(&signature.proof.0).ok()?;
    let input = SignatureStatement {
        scheme: signature.scheme,
        issuer: signature.issuer,
        key_hash: signature.key_hash,
        address_seed: signature.address_seed,
        access_key_id: access_key,
        valid_until: signature.valid_until,
        issued_at: signature.issued_at,
    }
    .public_input()?;
    Some(Prepared {
        key,
        proof,
        input,
        access_key,
    })
}

fn record(signature: &ZkSignature, d: &B256, key: B256, outcome: Option<Address>) {
    signature.cache_verification(*d, outcome);
    if let Some(access_key) = outcome {
        VERIFIED.lock().insert(key, access_key);
    }
}

fn cache_key(signature: &ZkSignature, d: &B256) -> B256 {
    let mut buf = Vec::with_capacity(signature.encoded_length() + 32);
    signature.encode_bytes_into(&mut buf);
    buf.extend_from_slice(d.as_slice());
    keccak256(buf)
}
