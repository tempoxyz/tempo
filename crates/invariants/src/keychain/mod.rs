//! The account keychain: an access key's spend, judged against the key as the
//! keychain reports it at the state before the spend.

use std::fmt;

use alloy_primitives::{Address, U256};

use crate::{Observe, ObserveError, Views, view};

pub use tempo_contracts::precompiles::IAccountKeychain::{
    self, KeyInfo, getKeyCall, getRemainingLimitWithPeriodCall, getRemainingLimitWithPeriodReturn,
    isAdminKeyCall,
};

mod checks;

pub use checks::{CHECKS, EXPIRED, REVOKED, SPEND_LIMIT};

/// An access key and its remaining limit for one token, as the keychain
/// reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub info: KeyInfo,
    pub limit: getRemainingLimitWithPeriodReturn,
}

impl Observe for Key {
    type At<'a> = At;

    /// Reads `account`'s access key `key` and its remaining limit for `token`
    /// from the keychain at `keychain`.
    fn observe<V: Views>(views: &mut V, at: Self::At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            keychain,
            account,
            key,
            token,
        } = at;
        Ok(Self {
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
}

/// The keychain, an account's access key and a token whose remaining limit to read.
#[derive(Debug, Clone, Copy)]
pub struct At {
    pub keychain: Address,
    pub account: Address,
    pub key: Address,
    pub token: Address,
}

/// A spend of `amount` by `key` (observed at the state before it) in a block
/// at `timestamp`. A key that state does not know may have been authorized in
/// the same block, so it is not judged.
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
