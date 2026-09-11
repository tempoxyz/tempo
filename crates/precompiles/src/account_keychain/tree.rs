//! Transaction-local authenticated policy state; only the account commitment persists.
use super::*;
use crate::StorageCtx;
use alloy_primitives::{B256, LogData};
use alloy_rlp::{Decodable, RlpDecodable, RlpEncodable};
use tempo_primitives::{
    account::tree::{AccountOpening, PolicyLeaf, replace_root},
    transaction::SignedKeyAuthorization,
};

#[derive(Clone, RlpEncodable, RlpDecodable)]
pub struct WorkingTree {
    pub opening: AccountOpening,
    pub index: u16,
    pub leaf: PolicyLeaf,
    pub siblings: Vec<B256>,
    pub tokens: Vec<tempo_primitives::transaction::TokenLimit>,
}

/// Minimal receipt state transition. Policy bytes and old path are already in the transaction.
#[derive(Clone, RlpEncodable, RlpDecodable)]
pub struct TreeTransition {
    pub opening: AccountOpening,
    pub index: u16,
    pub leaf: PolicyLeaf,
}

/// Conservative settlement allowance, charged before execution to avoid a recursive fee.
/// Full-width counters may enlarge RLP after the reservation. Bound the entire working
/// record, two reads, one rewrite, parsing/hashing, and the final transition log.
pub fn settlement_gas(tokens: usize, siblings: usize) -> u64 {
    let bytes = 256 + 120 * tokens as u64 + 34 * siblings as u64;
    10_000 + 400 * bytes.div_ceil(32) + 8 * bytes + 200 * siblings as u64
}

fn slot(account: Address, word: u64) -> U256 {
    let mut bytes = Vec::from(b"tempo:account-tree:working:v2".as_slice());
    bytes.extend_from_slice(account.as_slice());
    bytes.extend_from_slice(&word.to_be_bytes());
    keccak256(bytes).into()
}

pub fn load(account: Address) -> Result<Option<WorkingTree>> {
    let len = StorageCtx
        .tload(ACCOUNT_KEYCHAIN_ADDRESS, slot(account, 0))?
        .to::<usize>();
    if len == 0 {
        return Ok(None);
    }
    if len > 8192 {
        return Err(AccountKeychainError::unauthorized_caller().into());
    }
    let mut bytes = Vec::new();
    for i in 0..len.div_ceil(32) {
        bytes.extend_from_slice(
            &StorageCtx
                .tload(ACCOUNT_KEYCHAIN_ADDRESS, slot(account, i as u64 + 1))?
                .to_be_bytes::<32>(),
        );
    }
    bytes.truncate(len);
    let mut input = bytes.as_slice();
    let result =
        WorkingTree::decode(&mut input).map_err(|_| AccountKeychainError::unauthorized_caller())?;
    if !input.is_empty() {
        return Err(AccountKeychainError::unauthorized_caller().into());
    }
    Ok(Some(result))
}

pub fn save(account: Address, tree: &mut WorkingTree) -> Result<()> {
    tree.opening.policies = replace_root(
        tree.leaf.hash(),
        tree.index.into(),
        tree.opening.count.into(),
        &tree.siblings,
    )
    .map_err(|_| AccountKeychainError::unauthorized_caller())?;
    let bytes = alloy_rlp::encode(&*tree);
    // Meter parsing, leaf/envelope hashing and all branch work, not validator cache hits.
    StorageCtx.deduct_gas(
        1_000 + 80 * (bytes.len() as u64).div_ceil(32) + 100 * tree.siblings.len() as u64,
    )?;
    StorageCtx.tstore(
        ACCOUNT_KEYCHAIN_ADDRESS,
        slot(account, 0),
        U256::from(bytes.len()),
    )?;
    for (i, chunk) in bytes.chunks(32).enumerate() {
        let mut word = [0; 32];
        word[..chunk.len()].copy_from_slice(chunk);
        StorageCtx.tstore(
            ACCOUNT_KEYCHAIN_ADDRESS,
            slot(account, i as u64 + 1),
            U256::from_be_bytes(word),
        )?;
    }
    // The field write is prepaid once per transaction; intermediate state remains journaled.
    StorageCtx.set_config_commitment(
        account,
        tree.opening.commitment(),
        crate::storage::ConfigCommitmentWriteGas::PrepaidTreeUpdate,
    )
}

pub fn emit(account: Address, tree: &WorkingTree) -> Result<()> {
    // Do not log the old sibling path or immutable token list a second time.
    StorageCtx.emit_event(
        ACCOUNT_KEYCHAIN_ADDRESS,
        LogData::new_unchecked(
            vec![
                keccak256(b"TempoAccountTreeTransitionV2"),
                B256::left_padding_from(account.as_slice()),
            ],
            alloy_rlp::encode(TreeTransition {
                opening: tree.opening.clone(),
                index: tree.index,
                leaf: tree.leaf.clone(),
            })
            .into(),
        ),
    )
}

impl AccountKeychain {
    pub fn install_tree(&mut self, account: Address, auth: &SignedKeyAuthorization) -> Result<()> {
        let tree = auth
            .tree
            .as_ref()
            .ok_or_else(AccountKeychainError::unauthorized_caller)?;
        let tokens = auth.limits.clone().unwrap_or_default();
        let (opening, leaf) = tree
            .open(auth.signature_hash(), tokens.len())
            .map_err(|_| AccountKeychainError::unauthorized_caller())?;
        let mut working = WorkingTree {
            opening,
            leaf,
            index: tree.witness.index,
            siblings: tree.witness.siblings.clone(),
            tokens,
        };
        save(account, &mut working)?;
        if tree.grant_id == tree.witness.opening.next_id {
            emit(account, &working)?;
        }
        Ok(())
    }

    pub fn debit_tree(
        &mut self,
        account: Address,
        token: Address,
        amount: U256,
        emit_event: bool,
        mut tree: WorkingTree,
    ) -> Result<()> {
        let index = tree
            .tokens
            .binary_search_by_key(&token, |t| t.token)
            .map_err(|_| AccountKeychainError::spending_limit_exceeded())?;
        let limit = &tree.tokens[index];
        let usage = &mut tree.leaf.usage[index];
        if limit.period != 0 {
            let anchor = self.carried_read(3, Address::ZERO)?.to::<u64>();
            let now = self.storage.timestamp().saturating_to::<u64>();
            let window = now
                .checked_sub(anchor)
                .and_then(|elapsed| elapsed.checked_div(limit.period))
                .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
            if usage.window != window {
                usage.spent = U256::ZERO;
                usage.window = window;
            }
        }
        usage.spent = usage
            .spent
            .checked_add(amount)
            .filter(|n| *n <= limit.limit)
            .ok_or_else(AccountKeychainError::spending_limit_exceeded)?;
        save(account, &mut tree)?;
        if emit_event {
            emit(account, &tree)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{PrecompileStorageProvider, hashmap::HashMapStorageProvider};
    use tempo_primitives::account::tree::{Usage, proof};

    #[test]
    fn account_tree_settlement_allowance_covers_full_width_records() {
        for tokens in 1..=32 {
            for count in [1, 2, 4, 8, 16, 64, 256] {
                let account = Address::repeat_byte(0x71);
                let mut working = WorkingTree {
                    opening: AccountOpening {
                        authority: B256::repeat_byte(1),
                        epoch: u64::MAX,
                        next_id: u64::MAX,
                        count,
                        policies: B256::ZERO,
                    },
                    index: 0,
                    leaf: PolicyLeaf {
                        id: u64::MAX - 1,
                        policy: B256::repeat_byte(2),
                        usage: vec![
                            Usage {
                                spent: U256::MAX,
                                window: u64::MAX
                            };
                            tokens
                        ],
                    },
                    siblings: proof(&vec![B256::repeat_byte(3); count as usize], 0).unwrap(),
                    tokens: (1..=tokens)
                        .map(|i| tempo_primitives::transaction::TokenLimit {
                            token: Address::repeat_byte(i as u8),
                            limit: U256::MAX,
                            period: u64::MAX,
                        })
                        .collect(),
                };
                let mut storage = HashMapStorageProvider::new_with_spec(
                    1,
                    tempo_chainspec::hardfork::TempoHardfork::T12,
                );
                StorageCtx::enter(&mut storage, || {
                    StorageCtx
                        .set_config_commitment(
                            account,
                            working.opening.authority,
                            crate::storage::ConfigCommitmentWriteGas::Intrinsic,
                        )
                        .unwrap();
                    save(account, &mut working).unwrap();
                });
                let before = storage.gas_used();
                StorageCtx::enter(&mut storage, || {
                    let mut tree = load(account).unwrap().unwrap();
                    save(account, &mut tree).unwrap();
                    emit(account, &load(account).unwrap().unwrap()).unwrap();
                    // Headroom for key activation, flags and fee-token dispatch.
                    StorageCtx.deduct_gas(5_000).unwrap();
                });
                assert!(
                    storage.gas_used() - before <= settlement_gas(tokens, working.siblings.len()),
                    "tokens={tokens}, count={count}: {}",
                    storage.gas_used() - before
                );
            }
        }
    }
}
