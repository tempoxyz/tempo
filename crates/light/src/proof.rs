//! Exact-target, transport-neutral EIP-1186 proof verification.
//!
//! Adapted from Zones PR #1426's completeness checks. The cryptographic verifier is Alloy's
//! established MPT verifier, also used by Reth. No RPC scalar is returned before its proof passes.

use std::collections::{BTreeMap, BTreeSet};

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, keccak256};
use alloy_rpc_types_eth::EIP1186AccountProofResponse;
use alloy_trie::{
    EMPTY_ROOT_HASH, Nibbles, TrieAccount,
    proof::{ProofVerificationError, verify_proof},
};

/// Canonical raw storage target; values are cached before protocol-specific decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageReadKey {
    pub account: Address,
    pub slot: B256,
}

/// Grouped and deduplicated proof targets. An empty slot set requests only the account proof.
pub type ProofTargets = BTreeMap<Address, BTreeSet<B256>>;

/// Verification work limits. Transport must separately bound bytes *before* JSON decoding.
/// Defaults are conservative provisional limits, not measured performance guarantees.
#[derive(Clone, Copy, Debug)]
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

/// Account metadata and requested raw slots authenticated at one global state root.
/// Fields cannot be constructed or changed by consumers of the verified API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccount {
    account: Option<TrieAccount>,
    slots: BTreeMap<B256, B256>,
}

impl VerifiedAccount {
    /// `None` means complete account non-membership, not missing proof material.
    pub const fn account(&self) -> Option<&TrieAccount> {
        self.account.as_ref()
    }

    pub fn storage_root(&self) -> B256 {
        account_storage_root(self.account.as_ref())
    }

    pub const fn slots(&self) -> &BTreeMap<B256, B256> {
        &self.slots
    }
}

/// A complete verified batch. It is not evidence of finality by itself: the caller must bind
/// `state_root` to an authenticated snapshot, never an upstream's claimed latest state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBatch {
    state_root: B256,
    accounts: BTreeMap<Address, VerifiedAccount>,
}

impl VerifiedBatch {
    pub const fn state_root(&self) -> B256 {
        self.state_root
    }

    pub const fn accounts(&self) -> &BTreeMap<Address, VerifiedAccount> {
        &self.accounts
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("proof resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
    #[error("proof target mismatch: {0}")]
    TargetMismatch(&'static str),
    #[error("empty-trie proof contains unexpected additional nodes")]
    NonCanonicalEmptyProof,
    #[error("invalid account or storage proof: {0}")]
    InvalidProof(#[from] ProofVerificationError),
}

/// Authenticate the *exact* requested account/slot set against a locally selected state root.
///
/// This supports `eth_getMultiProof` responses and grouped standard `eth_getProof` responses.
/// Missing, duplicate, substituted, and unexpected targets fail. Complete non-membership proves
/// zero; truncated or missing evidence does not. No cache is mutated, even on a late batch failure.
pub fn verify_multi_proof(
    state_root: B256,
    targets: &ProofTargets,
    responses: &[EIP1186AccountProofResponse],
    limits: ProofLimits,
) -> Result<VerifiedBatch, Error> {
    check_limits(targets, responses, limits)?;
    if responses.len() != targets.len() {
        return Err(Error::TargetMismatch("account count"));
    }
    let mut accounts = BTreeMap::new();
    for response in responses {
        let requested = targets
            .get(&response.address)
            .ok_or(Error::TargetMismatch("unexpected account"))?;
        if accounts.contains_key(&response.address) {
            return Err(Error::TargetMismatch("duplicate account"));
        }
        if requested.len() != response.storage_proof.len() {
            return Err(Error::TargetMismatch("slot count"));
        }
        let mut slots = BTreeMap::new();
        for proof in &response.storage_proof {
            let slot = proof.key.as_b256();
            if !requested.contains(&slot) {
                return Err(Error::TargetMismatch("unexpected slot"));
            }
            if slots
                .insert(slot, B256::from(proof.value.to_be_bytes::<32>()))
                .is_some()
            {
                return Err(Error::TargetMismatch("duplicate slot"));
            }
        }

        // Reth uses empty hashes for absent accounts; geth uses zero hashes. Both are normalized
        // only after proving account non-membership. A storage-bearing account is never absent.
        let absent = response.nonce == 0
            && response.balance.is_zero()
            && (response.code_hash == KECCAK_EMPTY || response.code_hash.is_zero())
            && (response.storage_hash == EMPTY_ROOT_HASH || response.storage_hash.is_zero());
        let account = (!absent).then_some(TrieAccount {
            nonce: response.nonce,
            balance: response.balance,
            storage_root: response.storage_hash,
            code_hash: response.code_hash,
        });
        verify_proof(
            state_root,
            Nibbles::unpack(keccak256(response.address)),
            account.as_ref().map(alloy_rlp::encode),
            &response.account_proof,
        )?;
        let storage_root = account_storage_root(account.as_ref());
        for proof in &response.storage_proof {
            let value = (!proof.value.is_zero()).then(|| alloy_rlp::encode(proof.value));
            verify_proof(
                storage_root,
                Nibbles::unpack(keccak256(proof.key.as_b256())),
                value,
                &proof.proof,
            )?;
        }
        accounts.insert(response.address, VerifiedAccount { account, slots });
    }
    Ok(VerifiedBatch {
        state_root,
        accounts,
    })
}

/// Complete account non-membership authenticates the empty storage trie.
pub(crate) fn account_storage_root(account: Option<&TrieAccount>) -> B256 {
    account.map_or(EMPTY_ROOT_HASH, |account| account.storage_root)
}

fn check_limits(
    targets: &ProofTargets,
    responses: &[EIP1186AccountProofResponse],
    limits: ProofLimits,
) -> Result<(), Error> {
    if targets.len() > limits.max_accounts || responses.len() > limits.max_accounts {
        return Err(Error::ResourceLimit("accounts"));
    }
    fn add(
        total: &mut usize,
        amount: usize,
        limit: usize,
        name: &'static str,
    ) -> Result<(), Error> {
        *total = total
            .checked_add(amount)
            .filter(|total| *total <= limit)
            .ok_or(Error::ResourceLimit(name))?;
        Ok(())
    }
    let mut slots = 0;
    for requested in targets.values() {
        add(
            &mut slots,
            requested.len(),
            limits.max_slots,
            "requested slots",
        )?;
    }
    let (mut slots, mut nodes, mut bytes) = (0, 0, 0);
    for response in responses {
        add(
            &mut slots,
            response.storage_proof.len(),
            limits.max_slots,
            "response slots",
        )?;
        for proof in std::iter::once(&response.account_proof)
            .chain(response.storage_proof.iter().map(|proof| &proof.proof))
        {
            add(&mut nodes, proof.len(), limits.max_nodes, "proof nodes")?;
            if proof.len() > 1 && proof[0].as_ref() == [alloy_rlp::EMPTY_STRING_CODE] {
                return Err(Error::NonCanonicalEmptyProof);
            }
            for node in proof {
                if node.len() > limits.max_node_bytes {
                    return Err(Error::ResourceLimit("proof node bytes"));
                }
                add(
                    &mut bytes,
                    node.len(),
                    limits.max_total_bytes,
                    "proof bytes",
                )?;
            }
        }
    }
    Ok(())
}
