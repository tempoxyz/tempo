//! The account keychain invariants.

use invariants_core::{check, ensure};

use super::Spend;
use crate::{Check, Checked, Severity};

pub const REVOKED: &str = "TEMPO-KEYCHAIN-REVOKED-KEY-SPENDS";
pub const EXPIRED: &str = "TEMPO-KEYCHAIN-EXPIRED-KEY-SPENDS";
pub const SPEND_LIMIT: &str = "TEMPO-KEYCHAIN-SPEND-LIMIT";

pub const CHECKS: &[Check<Spend>] = &[
    check! {
        id: REVOKED,
        doc: "A revoked access key never authorizes a spend.",
        tip: "TIP-0001",
        severity: Severity::Critical,
        judge: |s: &Spend| ensure!(!s.key.info.isRevoked, "the key was revoked at the parent state"),
    },
    check! {
        id: EXPIRED,
        doc: "An access key never authorizes a spend at or after its expiry.",
        tip: "TIP-0001",
        severity: Severity::Critical,
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
        doc: "An access key with enforced limits never spends more of a token in a period than its remaining limit for it.",
        tip: "TIP-1011",
        severity: Severity::Critical,
        since: "T3",
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

impl Checked for Spend {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}
