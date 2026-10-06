use alloc::{
    boxed::Box,
    collections::{BTreeMap, btree_map::Entry},
};
use alloy_primitives::{Address, B256, KECCAK256_EMPTY, keccak256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use alloy_trie::{
    EMPTY_ROOT_HASH, Nibbles, TrieAccount,
    proof::{ProofVerificationError, verify_proof},
};

use crate::{ProofTargets, StorageReadKey};

/// Work ceilings checked before hashing/verifying. Transport must separately bound JSON bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofLimits {
    pub max_accounts: usize,
    pub max_slots: usize,
    pub max_nodes: usize,
    pub max_node_bytes: usize,
    pub max_total_bytes: usize,
}
impl Default for ProofLimits {
    fn default() -> Self {
        Self {
            max_accounts: 64,
            max_slots: 1024,
            max_nodes: 65_536,
            max_node_bytes: 4096,
            max_total_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Accounts,
    Slots,
    Nodes,
    NodeBytes,
    TotalBytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetError {
    AccountCount,
    UnexpectedAccount(Address),
    DuplicateAccount(Address),
    SlotCount(Address),
    UnexpectedSlot(StorageReadKey),
    DuplicateSlot(StorageReadKey),
}

#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("proof {kind:?} limit {limit} exceeded (observed {observed:?})")]
    LimitExceeded {
        kind: ResourceKind,
        limit: usize,
        observed: Option<usize>,
    },
    #[error("proof target mismatch: {0:?}")]
    Targets(TargetError),
    #[error("empty-trie marker hides additional nodes for {account}, slot {slot:?}")]
    NonCanonicalEmptyProof {
        account: Address,
        slot: Option<B256>,
    },
    #[error("invalid proof for {account}, slot {slot:?}: {source}")]
    InvalidProof {
        account: Address,
        slot: Option<B256>,
        #[source]
        source: Box<ProofVerificationError>,
    },
}

/// Complete authenticated metadata (or proven absence) plus authenticated requested words.
/// Only verification and authenticated composition can populate this type.
///
/// ```compile_fail
/// use tempo_state_proof::VerifiedAccount;
/// let forged = VerifiedAccount { account: None, slots: Default::default() };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccount {
    pub(crate) account: Option<TrieAccount>,
    pub(crate) slots: BTreeMap<B256, B256>,
}
impl VerifiedAccount {
    pub const fn account(&self) -> Option<&TrieAccount> {
        self.account.as_ref()
    }
    pub fn storage_root(&self) -> B256 {
        storage_root(self.account.as_ref())
    }
    pub const fn slots(&self) -> &BTreeMap<B256, B256> {
        &self.slots
    }
}

/// Authenticated value evidence at one root, not evidence of finality or retained proof nodes.
///
/// ```compile_fail
/// use tempo_state_proof::VerifiedBatch;
/// use alloy_primitives::B256;
/// let forged = VerifiedBatch { state_root: B256::ZERO, accounts: Default::default() };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatch {
    state_root: B256,
    pub(crate) accounts: BTreeMap<Address, VerifiedAccount>,
}
impl VerifiedBatch {
    /// Vacuous evidence: no authenticated values can be inserted by downstream callers.
    pub fn empty(state_root: B256) -> Self {
        Self {
            state_root,
            accounts: BTreeMap::new(),
        }
    }
    pub const fn state_root(&self) -> B256 {
        self.state_root
    }
    pub const fn accounts(&self) -> &BTreeMap<Address, VerifiedAccount> {
        &self.accounts
    }
    pub fn word(&self, key: StorageReadKey) -> Option<B256> {
        self.accounts
            .get(&key.account)?
            .slots
            .get(&key.slot)
            .copied()
    }
    /// Check all conflicts before changing the destination. Roots are never flattened together.
    pub fn merge(&mut self, other: Self) -> Result<(), CompositionError> {
        if self.state_root != other.state_root {
            return Err(CompositionError::StateRoot {
                expected: self.state_root,
                actual: other.state_root,
            });
        }
        for (&address, incoming) in &other.accounts {
            if let Some(existing) = self.accounts.get(&address) {
                check_account(self.state_root, address, existing.account, incoming.account)?;
                let storage_root = incoming.storage_root();
                for (&slot, &word) in &incoming.slots {
                    check_word(
                        StorageReadKey::new(address, slot),
                        storage_root,
                        existing.slots.get(&slot),
                        word,
                    )?;
                }
            }
        }
        for (address, incoming) in other.accounts {
            match self.accounts.entry(address) {
                Entry::Vacant(entry) => {
                    entry.insert(incoming);
                }
                Entry::Occupied(mut entry) => {
                    entry.get_mut().slots.extend(incoming.slots);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CompositionError {
    #[error("wrong state root: expected {expected}, got {actual}")]
    StateRoot { expected: B256, actual: B256 },
    #[error("conflicting account metadata at {state_root} for {account}")]
    Account { state_root: B256, account: Address },
    #[error("conflicting word for {key:?} under {storage_root}")]
    Word {
        key: StorageReadKey,
        storage_root: B256,
    },
}

pub(crate) fn storage_root(account: Option<&TrieAccount>) -> B256 {
    account.map_or(EMPTY_ROOT_HASH, |account| account.storage_root)
}
pub(crate) fn check_account(
    root: B256,
    address: Address,
    existing: Option<TrieAccount>,
    incoming: Option<TrieAccount>,
) -> Result<(), CompositionError> {
    if existing != incoming {
        return Err(CompositionError::Account {
            state_root: root,
            account: address,
        });
    }
    Ok(())
}
pub(crate) fn check_word(
    key: StorageReadKey,
    root: B256,
    existing: Option<&B256>,
    incoming: B256,
) -> Result<(), CompositionError> {
    if existing.is_some_and(|value| *value != incoming) {
        return Err(CompositionError::Word {
            key,
            storage_root: root,
        });
    }
    Ok(())
}

/// Authenticate exactly the supplied targets; duplicate, omitted or unexpected targets fail.
pub fn verify_multi_proof(
    root: B256,
    targets: &ProofTargets,
    responses: &[EIP1186AccountProofResponse],
    limits: ProofLimits,
) -> Result<VerifiedBatch, ProofError> {
    check_limits(targets, responses, limits)?;
    if responses.len() != targets.len() {
        return Err(ProofError::Targets(TargetError::AccountCount));
    }
    let mut batch = VerifiedBatch::empty(root);
    for response in responses {
        let address = response.address;
        let requested = targets
            .get(&address)
            .ok_or(ProofError::Targets(TargetError::UnexpectedAccount(address)))?;
        if batch.accounts.contains_key(&address) {
            return Err(ProofError::Targets(TargetError::DuplicateAccount(address)));
        }
        if requested.len() != response.storage_proof.len() {
            return Err(ProofError::Targets(TargetError::SlotCount(address)));
        }
        let mut slots = BTreeMap::new();
        for proof in &response.storage_proof {
            let key = StorageReadKey::new(address, proof.key.as_b256());
            if !requested.contains(&key.slot) {
                return Err(ProofError::Targets(TargetError::UnexpectedSlot(key)));
            }
            if slots
                .insert(key.slot, B256::from(proof.value.to_be_bytes::<32>()))
                .is_some()
            {
                return Err(ProofError::Targets(TargetError::DuplicateSlot(key)));
            }
        }
        let candidate = TrieAccount {
            nonce: response.nonce,
            balance: response.balance,
            storage_root: response.storage_hash,
            code_hash: response.code_hash,
        };
        let path = Nibbles::unpack(keccak256(address));
        // Authenticate presence first: an empty-looking present leaf is not absence.
        let present = verify_proof(
            root,
            path,
            Some(alloy_rlp::encode(candidate)),
            &response.account_proof,
        );
        let account = match present {
            Ok(()) => Some(candidate),
            Err(source) => {
                let absence_compatible = response.nonce == 0
                    && response.balance.is_zero()
                    && (response.code_hash == KECCAK256_EMPTY || response.code_hash.is_zero())
                    && (response.storage_hash == EMPTY_ROOT_HASH
                        || response.storage_hash.is_zero());
                if !absence_compatible
                    || verify_proof(root, path, None, &response.account_proof).is_err()
                {
                    return Err(ProofError::InvalidProof {
                        account: address,
                        slot: None,
                        source: Box::new(source),
                    });
                }
                None
            }
        };
        let storage_root = storage_root(account.as_ref());
        for proof in &response.storage_proof {
            verify_proof(
                storage_root,
                Nibbles::unpack(keccak256(proof.key.as_b256())),
                (!proof.value.is_zero()).then(|| alloy_rlp::encode(proof.value)),
                &proof.proof,
            )
            .map_err(|source| ProofError::InvalidProof {
                account: address,
                slot: Some(proof.key.as_b256()),
                source: Box::new(source),
            })?;
        }
        batch
            .accounts
            .insert(address, VerifiedAccount { account, slots });
    }
    Ok(batch)
}

fn bounded(
    total: &mut usize,
    amount: usize,
    limit: usize,
    kind: ResourceKind,
) -> Result<(), ProofError> {
    let observed = total.checked_add(amount);
    *total = observed
        .filter(|value| *value <= limit)
        .ok_or(ProofError::LimitExceeded {
            kind,
            limit,
            observed,
        })?;
    Ok(())
}
fn check_limits(
    targets: &ProofTargets,
    responses: &[EIP1186AccountProofResponse],
    limits: ProofLimits,
) -> Result<(), ProofError> {
    for count in [targets.len(), responses.len()] {
        bounded(&mut 0, count, limits.max_accounts, ResourceKind::Accounts)?;
    }
    let mut slots = 0;
    for requested in targets.values() {
        bounded(
            &mut slots,
            requested.len(),
            limits.max_slots,
            ResourceKind::Slots,
        )?;
    }
    let (mut slots, mut nodes, mut bytes) = (0, 0, 0);
    for response in responses {
        bounded(
            &mut slots,
            response.storage_proof.len(),
            limits.max_slots,
            ResourceKind::Slots,
        )?;
        for (slot, proof) in core::iter::once((None, &response.account_proof)).chain(
            response
                .storage_proof
                .iter()
                .map(|proof| (Some(proof.key.as_b256()), &proof.proof)),
        ) {
            bounded(
                &mut nodes,
                proof.len(),
                limits.max_nodes,
                ResourceKind::Nodes,
            )?;
            if proof.len() > 1 && proof[0].as_ref() == [alloy_rlp::EMPTY_STRING_CODE] {
                return Err(ProofError::NonCanonicalEmptyProof {
                    account: response.address,
                    slot,
                });
            }
            for node in proof {
                bounded(
                    &mut 0,
                    node.len(),
                    limits.max_node_bytes,
                    ResourceKind::NodeBytes,
                )?;
                bounded(
                    &mut bytes,
                    node.len(),
                    limits.max_total_bytes,
                    ResourceKind::TotalBytes,
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsumedError {
    #[error("missing consumed word {0:?}")]
    Missing(StorageReadKey),
    #[error("unexpected proved word {0:?}")]
    Unexpected(StorageReadKey),
    #[error("consumed {consumed} but proved {proved} for {key:?}")]
    Mismatch {
        key: StorageReadKey,
        consumed: B256,
        proved: B256,
    },
}

/// Compare exactly the slot-key sets and words; the caller separately owns checkpoint binding.
pub fn check_consumed(
    batch: &VerifiedBatch,
    consumed: &BTreeMap<StorageReadKey, B256>,
) -> Result<usize, ConsumedError> {
    for (&key, &value) in consumed {
        let proved = batch.word(key).ok_or(ConsumedError::Missing(key))?;
        if proved != value {
            return Err(ConsumedError::Mismatch {
                key,
                consumed: value,
                proved,
            });
        }
    }
    for (&address, account) in batch.accounts() {
        for &slot in account.slots.keys() {
            let key = StorageReadKey::new(address, slot);
            if !consumed.contains_key(&key) {
                return Err(ConsumedError::Unexpected(key));
            }
        }
    }
    Ok(consumed.len())
}
