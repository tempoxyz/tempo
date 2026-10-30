//! Configurable accounts (TIP-1107, TIP-1111, TIP-1113).

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, KECCAK256_EMPTY};

use crate::{Observe, ObserveError, Tx, Views, optional, view_many};

pub use tempo_contracts::precompiles::IConfigurableAccount::{
    self, AccountUpgraded, ConfigurableAccountConfig, ConfigurableAccountConfigUpdated,
    ConfigurableAccountOwner,
};

mod checks;
pub mod spec;

pub use checks::{LEAF_CHECKS, STEP_CHECKS, VIEW};

/// The configuration commitments of the observed accounts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitments {
    /// The precompile read.
    pub precompile: Address,
    /// Each observed account's commitment, zero for an account without a configuration.
    pub of: BTreeMap<Address, B256>,
}

impl Observe for Commitments {
    type At<'a> = At<'a>;

    /// Reads each account's commitment, leaving out unanswered ones.
    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            precompile,
            accounts,
        } = at;
        let calls: Vec<_> = accounts
            .iter()
            .map(|&account| {
                (
                    precompile,
                    IConfigurableAccount::getConfigCommitmentCall { account },
                )
            })
            .collect();
        let read = view_many(views, &calls)?;
        let mut of = BTreeMap::new();
        for (&account, commitment) in accounts.iter().zip(read) {
            let commitment = commitment.map(Ok).unwrap_or(Err(ObserveError::NotAnswered {
                call: "getConfigCommitment(address)",
                to: precompile,
            }));
            if let Some(commitment) = optional(views, commitment)? {
                of.insert(account, commitment);
            }
        }
        Ok(Self { precompile, of })
    }
}

/// The precompile and the accounts whose commitments to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub precompile: Address,
    pub accounts: &'a [Address],
}

/// Who a transaction's signatures authorize it for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authority {
    /// Whether configurable accounts are active (T14) at the transaction's block.
    pub active: bool,
    /// Each configurable-account signature: an owner quorum approving for its account.
    pub quorums: Vec<Quorum>,
    /// Each ordinary signature acting as account authority.
    pub keys: Vec<Key>,
    /// The inline key authorization's grant.
    pub grant: Option<Grant>,
}

impl Authority {
    /// The quorums approving for `account`.
    pub fn quorums_of(&self, account: Address) -> impl Iterator<Item = &Quorum> {
        self.quorums.iter().filter(move |q| q.account == account)
    }

    /// The accounts the signatures act for, and the grant's key ID.
    pub fn accounts(&self) -> impl Iterator<Item = Address> + '_ {
        self.quorums
            .iter()
            .map(|q| q.account)
            .chain(self.keys.iter().map(|k| k.account))
            .chain(self.grant.iter().map(|g| g.key_id))
    }
}

/// What a signature authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The transaction's own signature, for its sender.
    Sender,
    /// An access key's signature inside a keychain envelope, for its key ID.
    AccessKey,
    /// The inline key authorization's signature, for the parent granting the key.
    KeyAuthorization,
    /// The fee payer's signature.
    FeePayer,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sender => "sender",
            Self::AccessKey => "access key",
            Self::KeyAuthorization => "key authorization signer",
            Self::FeePayer => "fee payer",
        })
    }
}

/// An ordinary signature acting as `account`'s authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub role: Role,
    pub account: Address,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.role, self.account)
    }
}

/// A configurable-account signature: the configuration it carries and its approvals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quorum {
    pub role: Role,
    /// The account the signature names.
    pub account: Address,
    pub config: ConfigurableAccountConfig,
    pub approvals: Vec<Approval>,
}

impl fmt::Display for Quorum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} quorum of {} at version {}",
            self.role, self.account, self.config.version
        )
    }
}

/// One owner approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Approval {
    /// The owner it recovers to, if any.
    pub owner: Option<Address>,
    /// Its encoded length in bytes.
    pub len: usize,
}

/// An inline key authorization's grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grant {
    pub key_type: u8,
    pub key_id: Address,
}

/// One account's leaf fields the configurable-account checks read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Leaf {
    /// Zero without a configuration.
    pub commitment: B256,
    /// `keccak256("")` for an account without code, or one that does not exist.
    pub code_hash: B256,
}

impl Leaf {
    /// The leaf of an account that does not exist.
    pub const EMPTY: Self = Self {
        commitment: B256::ZERO,
        code_hash: KECCAK256_EMPTY,
    };
}

/// Each changed or signing account's leaf before and after a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaves {
    pub of: BTreeMap<Address, (Leaf, Leaf)>,
    pub tx: Tx,
}
