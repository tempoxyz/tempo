//! Native TIP-20 targets and local decoding. No EVM calls or RPC scalar fallbacks.

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use tempo_primitives::{is_tip20_prefix, tip20};
use tempo_state_proof::{ProofTargets, StorageReadKey};
#[cfg(any(feature = "client", test))]
use {
    alloy_consensus::constants::KECCAK_EMPTY,
    alloy_primitives::{B256, U256},
    alloy_trie::TrieAccount,
};

/// Latest-only read. A caller cannot choose a block or an arbitrary contract call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum ReadRequest {
    Balance {
        token: Address,
        holder: Address,
    },
    Allowance {
        token: Address,
        owner: Address,
        spender: Address,
    },
    TotalSupply {
        token: Address,
    },
}

impl ReadRequest {
    pub fn key(self) -> Result<StorageReadKey, Error> {
        let (token, slot) = match self {
            Self::Balance { token, holder } => (token, tip20::balance_slot(holder)),
            Self::Allowance {
                token,
                owner,
                spender,
            } => (token, tip20::allowance_slot(owner, spender)),
            Self::TotalSupply { token } => (token, tip20::TOTAL_SUPPLY_SLOT.into()),
        };
        if !is_tip20_prefix(token) {
            return Err(Error::UnsupportedToken(token));
        }
        Ok(StorageReadKey {
            account: token,
            slot,
        })
    }
}

pub fn targets(requests: &[ReadRequest]) -> Result<ProofTargets, Error> {
    let mut targets = ProofTargets::new();
    for request in requests {
        let key = request.key()?;
        targets.entry(key.account).or_default().insert(key.slot);
    }
    Ok(targets)
}

/// Matches native TIP20Factory::is_tip20 and ContractStorage::is_initialized: prefix plus code.
/// Merely proving an absent token account or an arbitrary non-prefix account is not a zero token.
#[cfg(any(feature = "client", test))]
pub(crate) fn decode(
    key: StorageReadKey,
    account: Option<&TrieAccount>,
    word: B256,
) -> Result<U256, Error> {
    if !is_tip20_prefix(key.account) {
        return Err(Error::UnsupportedToken(key.account));
    }
    if account
        .is_none_or(|account| account.code_hash.is_zero() || account.code_hash == KECCAK_EMPTY)
    {
        return Err(Error::UninitializedToken(key.account));
    }
    Ok(U256::from_be_bytes(word.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    #[test]
    fn native_requests_deduplicate_targets_and_reject_historical_fields() {
        let token = address!("20c0000000000000000000000000000000000001");
        let balance = ReadRequest::Balance {
            token,
            holder: Address::ZERO,
        };
        let allowance = ReadRequest::Allowance {
            token,
            owner: Address::ZERO,
            spender: Address::repeat_byte(1),
        };
        let supply = ReadRequest::TotalSupply { token };
        let grouped = targets(&[balance, balance, allowance, supply]).unwrap();
        assert_eq!(grouped[&token].len(), 3);
        assert_eq!(supply.key().unwrap().slot, B256::from(U256::from(8)));
        assert!(
            ReadRequest::TotalSupply {
                token: Address::ZERO
            }
            .key()
            .is_err()
        );
        let mut wire = serde_json::to_value(balance).unwrap();
        wire["blockHash"] = serde_json::json!(B256::ZERO);
        assert!(serde_json::from_value::<ReadRequest>(wire).is_err());
    }

    #[test]
    fn authenticated_zero_is_only_a_token_value_after_initialization() {
        let key = ReadRequest::TotalSupply {
            token: address!("20c0000000000000000000000000000000000001"),
        }
        .key()
        .unwrap();
        assert!(decode(key, None, B256::ZERO).is_err());
        let mut account = TrieAccount {
            code_hash: KECCAK_EMPTY,
            ..Default::default()
        };
        assert!(decode(key, Some(&account), B256::ZERO).is_err());
        account.code_hash = B256::ZERO;
        assert!(decode(key, Some(&account), B256::ZERO).is_err());
        account.code_hash = alloy_primitives::keccak256([0xef]);
        assert_eq!(decode(key, Some(&account), B256::ZERO).unwrap(), U256::ZERO);
        assert_eq!(
            decode(key, Some(&account), B256::repeat_byte(255)).unwrap(),
            U256::MAX
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported native TIP-20 address: {0}")]
    UnsupportedToken(Address),
    #[error("TIP-20 token is not initialized at the selected snapshot: {0}")]
    UninitializedToken(Address),
}
