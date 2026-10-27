//! The account keychain: an access key's spend, judged against the key as the
//! keychain reports it at the state before the spend.

use alloy_primitives::Address;
use alloy_sol_types::sol;

use crate::{ObserveError, Views, view};

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

mod checks;

pub use checks::{CHECKS, EXPIRED, REVOKED, SPEND_LIMIT, Spend};

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
