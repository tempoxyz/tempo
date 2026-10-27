//! The account keychain: an access key's spend, judged against the key as the
//! keychain reports it at the state before the spend.

use std::fmt;

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;

use invariants_core::{check, ensure};

use crate::{Check, ObserveError, Views, Violation, judge, view};

sol! {
    #[derive(Debug, PartialEq, Eq)]
    interface IAccountKeychain {
        enum SignatureType { Secp256k1, P256, WebAuthn }
        struct KeyInfo {
            SignatureType signatureType;
            address keyId;
            uint64 expiry;
            bool enforceLimits;
            bool isRevoked;
        }
        function getKey(address account, address keyId) external view returns (KeyInfo memory);
        function getRemainingLimitWithPeriod(address account, address keyId, address token)
            external view returns (uint256 remaining, uint64 periodEnd);
        function isAdminKey(address account, address keyId) external view returns (bool);
    }
}

pub use IAccountKeychain::{
    KeyInfo, getKeyCall, getRemainingLimitWithPeriodCall, getRemainingLimitWithPeriodReturn,
    isAdminKeyCall,
};

/// An access key and its remaining limit for one token, as the keychain
/// reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub info: KeyInfo,
    pub limit: getRemainingLimitWithPeriodReturn,
}

/// Reads `account`'s access key `key` and its remaining limit for `token`
/// from the keychain at `keychain`.
pub fn observe<V: Views>(
    views: &mut V,
    keychain: Address,
    account: Address,
    key: Address,
    token: Address,
) -> Result<Key, ObserveError<V::Error>> {
    Ok(Key {
        info: view(
            views,
            keychain,
            getKeyCall {
                account,
                keyId: key,
            },
        )?,
        limit: view(
            views,
            keychain,
            getRemainingLimitWithPeriodCall {
                account,
                keyId: key,
                token,
            },
        )?,
    })
}

pub const REVOKED: &str = "TEMPO-KEYCHAIN-REVOKED-KEY-SPENDS";
pub const EXPIRED: &str = "TEMPO-KEYCHAIN-EXPIRED-KEY-SPENDS";
pub const SPEND_LIMIT: &str = "TEMPO-KEYCHAIN-SPEND-LIMIT";

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

pub static CHECKS: &[Check<Spend>] = &[
    check! {
        id: REVOKED,
        over: |spend: &Spend| [spend],
        judge: |_, s| ensure!(!s.key.info.isRevoked, "the key was revoked at the parent state"),
    },
    check! {
        id: EXPIRED,
        over: |spend: &Spend| [spend],
        judge: |_, s| {
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
        over: |spend: &Spend| [spend],
        judge: |_, s| {
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

/// The violations of [`CHECKS`] by a spend of `amount` by `key`.
pub fn check_spend(key: &Key, timestamp: u64, limit_updated: bool, amount: U256) -> Vec<Violation> {
    judge(
        CHECKS,
        &Spend {
            key: key.clone(),
            timestamp,
            limit_updated,
            amount,
        },
    )
}
