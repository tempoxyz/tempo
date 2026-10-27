//! The account keychain invariants.

use std::fmt;

use alloy_primitives::U256;
use invariants_core::{check, ensure};

use super::Key;
use crate::{Check, Checked};

pub const REVOKED: &str = "TEMPO-KEYCHAIN-REVOKED-KEY-SPENDS";
pub const EXPIRED: &str = "TEMPO-KEYCHAIN-EXPIRED-KEY-SPENDS";
pub const SPEND_LIMIT: &str = "TEMPO-KEYCHAIN-SPEND-LIMIT";

pub const CHECKS: &[Check<Spend>] = &[
    check! {
        id: REVOKED,
        judge: |s: &Spend| ensure!(!s.key.info.isRevoked, "the key was revoked at the parent state"),
    },
    check! {
        id: EXPIRED,
        judge: |s: &Spend| {
            let info = &s.key.info;
            if info.isRevoked || info.keyId.is_zero() {
                return None;
            }
            ensure!(
                s.timestamp < info.expiry,
                "block timestamp {} is at or past the key's expiry {}",
                s.timestamp,
                info.expiry
            )
        },
    },
    check! {
        id: SPEND_LIMIT,
        judge: |s: &Spend| {
            let (info, limit) = (&s.key.info, &s.key.limit);
            let refilled = limit.periodEnd != 0 && s.timestamp >= limit.periodEnd;
            if info.keyId.is_zero() || !info.enforceLimits || s.limit_updated || refilled {
                return None;
            }
            ensure!(
                s.amount <= limit.remaining,
                "the key's transactions moved {}, its remaining limit was {}",
                s.amount,
                limit.remaining
            )
        },
    },
];

/// A spend of `amount` by `key` (observed at the state
/// before it) in a block at `timestamp` breaks. A key that state does not
/// know may have been authorized in the same block, so it is not judged.
/// `getKey` zeroes a revoked key's id, so revocation is judged first. The
/// limit is not judged when the key has none, when a new period began by
/// `timestamp` (the limit refills), or when the block also updated this key's
/// limit for the token (`limit_updated`).
pub struct Spend {
    pub key: Key,
    pub timestamp: u64,
    pub limit_updated: bool,
    pub amount: U256,
}

impl fmt::Display for Spend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spend of {} by key {}", self.amount, self.key.info.keyId)
    }
}

impl Checked for Spend {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
