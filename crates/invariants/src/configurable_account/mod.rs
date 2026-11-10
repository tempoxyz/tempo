//! Configurable accounts (TIP-1107, TIP-1111, TIP-1113).

use std::{collections::BTreeMap, fmt};

use alloy_primitives::{Address, B256, KECCAK256_EMPTY, Log};
use alloy_sol_types::SolEvent;
use tempo_contracts::precompiles::IAccountKeychain::{KeyAuthorized, isAdminKeyCall};

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
    /// Whether each queried `(account, key)` is the account's root or an active admin key, as the
    /// keychain reports it; unanswered reads are left out.
    pub admins: BTreeMap<(Address, Address), bool>,
}

impl Observe for Commitments {
    type At<'a> = At<'a>;

    /// Reads each account's commitment, leaving out unanswered ones.
    fn observe<V: Views>(views: &mut V, at: At<'_>) -> Result<Self, ObserveError<V::Error>> {
        let At {
            precompile,
            accounts,
            keychain,
            admins: queries,
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
            let commitment = commitment.ok_or(ObserveError::NotAnswered {
                call: "getConfigCommitment(address)",
                to: precompile,
            });
            if let Some(commitment) = optional(views, commitment)? {
                of.insert(account, commitment);
            }
        }
        let calls: Vec<_> = queries
            .iter()
            .map(|&(account, key_id)| {
                (
                    keychain,
                    isAdminKeyCall {
                        account,
                        keyId: key_id,
                    },
                )
            })
            .collect();
        let admins = queries
            .iter()
            .zip(view_many(views, &calls)?)
            .filter_map(|(&query, admin)| Some((query, admin?)))
            .collect();
        Ok(Self {
            precompile,
            of,
            admins,
        })
    }
}

/// The precompile and the accounts whose commitments to read, and the keychain and the
/// `(account, key)` pairs whose admin status to read.
#[derive(Debug, Clone, Copy)]
pub struct At<'a> {
    pub precompile: Address,
    pub accounts: &'a [Address],
    pub keychain: Address,
    pub admins: &'a [(Address, Address)],
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
    /// Whether the transaction carries a nonempty EIP-7702 or Tempo authorization list.
    pub authorization_list: bool,
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

    /// The accounts the inline key authorization's signatures act for.
    pub fn key_authorization_signers(&self) -> impl Iterator<Item = Address> + '_ {
        self.quorums
            .iter()
            .filter(|q| q.role == Role::KeyAuthorization)
            .map(|q| q.account)
            .chain(
                self.keys
                    .iter()
                    .filter(|k| k.role == Role::KeyAuthorization)
                    .map(|k| k.account),
            )
    }

    /// The `(sender, signer)` pairs whose admin status judges the inline key authorization: its
    /// ordinary signers other than the sender.
    pub fn admin_queries(&self, sender: Address) -> Vec<(Address, Address)> {
        self.keys
            .iter()
            .filter(|k| k.role == Role::KeyAuthorization && k.account != sender)
            .map(|k| (sender, k.account))
            .collect()
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

/// One account's leaf before and after a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafChange {
    pub before: Leaf,
    pub after: Leaf,
}

/// Each changed or signing account's leaf before and after a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaves {
    pub of: BTreeMap<Address, LeafChange>,
    pub tx: Tx,
    /// The grants to configurable delegates the transaction made.
    pub delegates: Vec<DelegateGrant>,
}

/// A grant of key type 3: `parent` granting its configurable delegate `delegate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegateGrant {
    pub parent: Address,
    pub delegate: Address,
}

impl fmt::Display for DelegateGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "grant of {} to delegate {}", self.parent, self.delegate)
    }
}

/// The grants to configurable delegates the keychain at `keychain` made in `logs` (its
/// `KeyAuthorized` events of key type 3), and `tx`'s inline grant when it names one.
pub fn delegate_grants<'a>(
    keychain: Address,
    logs: impl IntoIterator<Item = &'a Log>,
    tx: &Tx,
) -> Vec<DelegateGrant> {
    let mut grants: Vec<DelegateGrant> = logs
        .into_iter()
        .filter(|log| log.address == keychain)
        .filter_map(|log| KeyAuthorized::decode_log_data(&log.data).ok())
        .filter(|e| e.signatureType == spec::CONFIGURABLE_KEY_TYPE)
        .map(|e| DelegateGrant {
            parent: e.account,
            delegate: e.publicKey,
        })
        .chain(
            tx.authority
                .grant
                .filter(|g| g.key_type == spec::CONFIGURABLE_KEY_TYPE)
                .map(|g| DelegateGrant {
                    parent: tx.sender,
                    delegate: g.key_id,
                }),
        )
        .collect();
    grants.sort_unstable();
    grants.dedup();
    grants
}
