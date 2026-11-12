//! Sequencer-local allowlist of L1 depositors and Zone transfer parties, split into groups.
//!
//! When a Zone portal runs with access mode disabled, anyone can deposit on L1. The leader then
//! bounces deposits the list does not admit by supplying zeroed decryption data, which the inbox
//! treats as a failed decryption and refunds through the ordinary deposit bounce-back path.
//!
//! The list is a set of named groups of Zone accounts, such as one per tenant of a shared Zone,
//! and the L1 routers each group may use. Users keep the same address on L1 and the Zone, so the
//! same groups decide every movement of funds:
//!
//! - **Deposits:** the decrypted recipient must be in a group that also holds the L1 sender or
//!   lists the sender as one of its routers.
//! - **Transfers:** the sender, the recipient and any spender must share a group whose
//!   `transfers` flag is set (see [`TransferAllowlist`]).
//! - **Withdrawals to a router:** the withdrawer must be in one of the router's groups, so only
//!   those groups can reach the router's vault. Withdrawals to any other address stay open, so
//!   removing an account never traps its funds.
//!
//! The checks run only where blocks are built, so they need no hardfork. RPC-only nodes keep an
//! [`AllowlistMirror`] of the leader's list so they can reject such transfers on submission
//! instead of forwarding them.
//!
//! The single list of earlier releases is the group [`DEFAULT_GROUP`], which allows transfers.
//! `zoneAdmin_setDepositAllowed` and `zoneAdmin_replaceDepositAllowlist` edit only that group, so a
//! Zone that never writes other groups behaves as before. `zoneAdmin_replaceDepositAllowlistGroups`
//! replaces every group and router at once.
//!
//! A sequencer with no persisted list is uninitialized and credits every deposit until its first
//! write, so enabling the allowlist does not bounce deposits before the admin fills the list.
//! Each sequencer keeps its own file, which consensus does not replicate; the operator runbook in
//! `zones/docs/ZONES.md` covers enabling the allowlist and adding or restoring sequencers.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    fs::File,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::{Address, B256, Bytes, Signature};
use alloy_sol_types::{Eip712Domain, SolStruct as _, eip712_domain, sol};
use eyre::{WrapErr as _, ensure};
use jsonrpsee::{core::RpcResult, proc_macros::rpc, types::ErrorObjectOwned};
use parking_lot::{Mutex, RwLock};
use reth_transaction_pool::TransactionPool;
use serde::{Deserialize, Serialize};
use tempo_transaction_pool::transaction::TempoPooledTransaction;
use tokio::sync::Notify;
use tracing::{info, warn};
use zone_l1::{FAILED_DECRYPTION, abi::DecryptionData};
use zone_payload::{Movement, TransferAllowlist, validate_transfer_calls};

mod relay;
pub(crate) use relay::{AllowlistRelay, apply_relayed_requests, mirror_leader};

/// File name of the persisted allowlist inside the node data directory.
pub(crate) const DEPOSIT_ALLOWLIST_FILE_NAME: &str = "deposit-allowlist.json";

/// Longest time a signed write stays valid, bounding how long it can wait before it is applied.
pub(crate) const MAX_SIGNED_WRITE_VALIDITY: Duration = Duration::from_secs(10 * 60);

/// Most entries the list may hold, counting every group membership and every group a router
/// serves, so a full list read through an RPC-only node fits in one P2P allowlist frame.
pub(crate) const MAX_DEPOSIT_ALLOWLIST_LEN: usize = 80_000;

/// Group that `zoneAdmin_setDepositAllowed` and `zoneAdmin_replaceDepositAllowlist` edit. It is
/// created with transfers allowed, matching the single list of earlier releases.
pub(crate) const DEFAULT_GROUP: &str = "default";

/// Longest group ID, in bytes.
const MAX_GROUP_ID_LEN: usize = 32;

/// Most groups the list may hold. With [`MAX_ROUTERS`] and [`MAX_GROUP_ID_LEN`], this keeps a full
/// list within one P2P allowlist frame whatever mix of members and routes it holds.
const MAX_GROUPS: usize = 256;

/// Most routers the list may hold.
const MAX_ROUTERS: usize = 256;

sol! {
    /// EIP-712 message authorizing the admin to add (`allowed`) or remove members of the
    /// default group.
    struct SetDepositAllowed {
        address[] addresses;
        bool allowed;
        uint64 nonce;
        uint64 deadline;
    }

    /// EIP-712 message authorizing the admin to replace the members of the default group.
    struct ReplaceDepositAllowlist {
        address[] addresses;
        uint64 nonce;
        uint64 deadline;
    }

    /// A named set of Zone accounts.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllowlistGroup {
        /// Non-empty and at most 32 bytes, unique within the policy.
        string id;
        address[] members;
        /// Whether members may send Zone transfers to each other.
        bool transfers;
    }

    /// An L1 router, such as a vault's Earn router, and the groups it serves: their members may
    /// withdraw to it, and its deposits may credit them.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllowlistRouter {
        address router;
        string[] groups;
    }

    /// Every group and router of the allowlist.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllowlistPolicy {
        AllowlistGroup[] groups;
        AllowlistRouter[] routers;
    }

    /// EIP-712 message authorizing the admin to replace every group and router.
    struct ReplaceDepositAllowlistGroups {
        AllowlistPolicy policy;
        uint64 nonce;
        uint64 deadline;
    }
}

/// The address whose EIP-712 signatures authorize allowlist writes, and the zone those
/// signatures are bound to.
#[derive(Debug, Clone, Copy)]
pub struct DepositAllowlistAdmin {
    /// Signer that every write must recover to.
    pub address: Address,
    /// Chain ID of this zone, used as the EIP-712 domain chain ID.
    pub zone_chain_id: u64,
}

impl DepositAllowlistAdmin {
    fn domain(&self) -> Eip712Domain {
        eip712_domain! {
            name: "TempoZoneDepositAllowlist",
            version: "1",
            chain_id: self.zone_chain_id,
        }
    }

    /// Check that the admin signed `write` and that its deadline is within the validity window,
    /// returning its EIP-712 signing hash.
    pub(crate) fn authorize(&self, write: &SignedWrite) -> Result<B256, DepositAllowlistError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| DepositAllowlistError::Internal(err.to_string()))?
            .as_secs();
        if write.deadline < now {
            return Err(DepositAllowlistError::Expired {
                deadline: write.deadline,
            });
        }
        if write.deadline > now.saturating_add(MAX_SIGNED_WRITE_VALIDITY.as_secs()) {
            return Err(DepositAllowlistError::DeadlineTooFar {
                deadline: write.deadline,
            });
        }
        let hash = write.signing_hash(&self.domain());
        let signer = Signature::try_from(write.signature.as_ref())
            .and_then(|signature| signature.recover_address_from_prehash(&hash))
            .map_err(|_| DepositAllowlistError::MalformedSignature)?;
        if signer != self.address {
            return Err(DepositAllowlistError::Unauthorized { signer });
        }
        Ok(hash)
    }
}

/// An allowlist change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Write {
    /// Add or remove members of the default group.
    Set {
        addresses: Vec<Address>,
        allowed: bool,
    },
    /// Replace the members of the default group, keeping every other group and router.
    Replace { addresses: Vec<Address> },
    /// Replace every group and router.
    ReplaceGroups { policy: AllowlistPolicy },
}

/// An allowlist change with the admin signature that authorizes it once, until `deadline`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SignedWrite {
    pub(crate) write: Write,
    /// Must exceed the nonce of the last write the sequencer applied.
    pub(crate) nonce: u64,
    /// Unix timestamp in seconds after which the signature is rejected.
    pub(crate) deadline: u64,
    pub(crate) signature: Bytes,
}

impl SignedWrite {
    fn signing_hash(&self, domain: &Eip712Domain) -> B256 {
        match &self.write {
            Write::Set { addresses, allowed } => SetDepositAllowed {
                addresses: addresses.clone(),
                allowed: *allowed,
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
            Write::Replace { addresses } => ReplaceDepositAllowlist {
                addresses: addresses.clone(),
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
            Write::ReplaceGroups { policy } => ReplaceDepositAllowlistGroups {
                policy: policy.clone(),
                nonce: self.nonce,
                deadline: self.deadline,
            }
            .eip712_signing_hash(domain),
        }
    }
}

/// Why an allowlist request was rejected. Serializable so a sequencer can return it to the
/// RPC-only node that relayed the request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum DepositAllowlistError {
    #[error("signed write expired at {deadline}")]
    Expired { deadline: u64 },
    #[error(
        "signed write deadline {deadline} is more than {}s in the future",
        MAX_SIGNED_WRITE_VALIDITY.as_secs()
    )]
    DeadlineTooFar { deadline: u64 },
    #[error("malformed signature")]
    MalformedSignature,
    #[error("write is signed by {signer}, not the allowlist admin")]
    Unauthorized { signer: Address },
    #[error("nonce {nonce} does not exceed the last applied nonce {applied}")]
    StaleNonce { nonce: u64, applied: u64 },
    #[error("the allowlist is uninitialized; the first write must replace the whole list")]
    Uninitialized,
    #[error("allowlist would hold {len} entries; the limit is {MAX_DEPOSIT_ALLOWLIST_LEN}")]
    TooLarge { len: usize },
    #[error("allowlist would hold {count} groups; the limit is {MAX_GROUPS}")]
    TooManyGroups { count: usize },
    #[error("allowlist would hold {count} routers; the limit is {MAX_ROUTERS}")]
    TooManyRouters { count: usize },
    #[error("group ID {id:?} must be 1 to {MAX_GROUP_ID_LEN} bytes")]
    InvalidGroupId { id: String },
    #[error("group {id:?} is listed more than once")]
    DuplicateGroup { id: String },
    #[error("router {router} is listed more than once")]
    DuplicateRouter { router: Address },
    #[error("router {router} names unknown group {id:?}")]
    UnknownGroup { router: Address, id: String },
    #[error("failed to persist the allowlist: {0}")]
    Persist(String),
    #[error("deposit allowlist is not enabled on this sequencer")]
    Disabled,
    #[error("too many allowlist requests in flight; retry later")]
    Busy,
    #[error("internal error: {0}")]
    Internal(String),
}

impl DepositAllowlistError {
    /// JSON-RPC error code: invalid params for a rejected request, internal error otherwise.
    pub(crate) const fn code(&self) -> i32 {
        match self {
            Self::Persist(_) | Self::Disabled | Self::Busy | Self::Internal(_) => {
                jsonrpsee::types::error::INTERNAL_ERROR_CODE
            }
            _ => jsonrpsee::types::error::INVALID_PARAMS_CODE,
        }
    }
}

impl From<DepositAllowlistError> for ErrorObjectOwned {
    fn from(error: DepositAllowlistError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

/// Every group and router, indexed for the checks. Serialized as a canonical [`AllowlistPolicy`]:
/// groups sorted by ID, members and routers ascending, and each router's groups sorted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "AllowlistPolicy", into = "AllowlistPolicy")]
pub(crate) struct Policy {
    groups: BTreeMap<String, Group>,
    /// Each router's groups, all of which exist in `groups`.
    routers: BTreeMap<Address, BTreeSet<String>>,
}

impl Policy {
    /// Entries counted against [`MAX_DEPOSIT_ALLOWLIST_LEN`]: every membership and every group a
    /// router serves.
    fn len(&self) -> usize {
        let members = self.groups.values().map(|group| group.members.len());
        let routes = self.routers.values().map(BTreeSet::len);
        members.chain(routes).sum()
    }

    /// Fails when the list exceeds [`MAX_DEPOSIT_ALLOWLIST_LEN`], [`MAX_GROUPS`] or [`MAX_ROUTERS`].
    fn check_limits(&self) -> Result<(), DepositAllowlistError> {
        let len = self.len();
        if len > MAX_DEPOSIT_ALLOWLIST_LEN {
            return Err(DepositAllowlistError::TooLarge { len });
        }
        if self.groups.len() > MAX_GROUPS {
            return Err(DepositAllowlistError::TooManyGroups {
                count: self.groups.len(),
            });
        }
        if self.routers.len() > MAX_ROUTERS {
            return Err(DepositAllowlistError::TooManyRouters {
                count: self.routers.len(),
            });
        }
        Ok(())
    }

    /// EIP-712 struct hash of the canonical [`AllowlistPolicy`], which sequencers compare to find
    /// drift.
    fn hash(&self) -> B256 {
        AllowlistPolicy::from(self.clone()).eip712_hash_struct()
    }

    /// The default group, created with transfers allowed if it does not exist yet.
    fn default_group(&mut self) -> &mut Group {
        self.groups
            .entry(DEFAULT_GROUP.to_owned())
            .or_insert_with(|| Group {
                members: BTreeSet::new(),
                transfers: true,
            })
    }

    /// Whether a deposit from L1 `sender` may credit zone `recipient`: some group holds the
    /// recipient and either holds the sender or is served by it as a router. A deposit whose
    /// recipient did not decrypt (`None`) refunds anyway, so it needs only a sender that is a
    /// member or router of some group.
    fn admits_deposit(&self, sender: Address, recipient: Option<Address>) -> bool {
        let routes = self.routers.get(&sender);
        let reaches = |(id, group): &(&String, &Group)| {
            group.members.contains(&sender) || routes.is_some_and(|routes| routes.contains(*id))
        };
        match recipient {
            Some(recipient) => self
                .groups
                .iter()
                .filter(|(_, group)| group.members.contains(&recipient))
                .any(|entry| reaches(&entry)),
            None => self.groups.iter().any(|entry| reaches(&entry)),
        }
    }

    /// Whether every one of `movements` is allowed. A transfer needs one group with transfers
    /// allowed that holds both parties and any spender. A withdrawal to a router needs the
    /// withdrawer in one of the router's groups; one to any other address is always allowed.
    fn admits(&self, movements: &[Movement]) -> bool {
        movements.iter().all(|movement| match *movement {
            Movement::Transfer { spender, from, to } => self.groups.values().any(|group| {
                group.transfers
                    && group.members.contains(&from)
                    && group.members.contains(&to)
                    && spender.is_none_or(|spender| group.members.contains(&spender))
            }),
            Movement::Withdrawal { sender, to } => self.routers.get(&to).is_none_or(|routes| {
                routes.iter().any(|id| {
                    self.groups
                        .get(id)
                        .is_some_and(|group| group.members.contains(&sender))
                })
            }),
        })
    }
}

impl TryFrom<AllowlistPolicy> for Policy {
    type Error = DepositAllowlistError;

    fn try_from(policy: AllowlistPolicy) -> Result<Self, Self::Error> {
        let mut groups = BTreeMap::new();
        for group in policy.groups {
            if group.id.is_empty() || group.id.len() > MAX_GROUP_ID_LEN {
                return Err(DepositAllowlistError::InvalidGroupId { id: group.id });
            }
            match groups.entry(group.id) {
                Entry::Occupied(entry) => {
                    return Err(DepositAllowlistError::DuplicateGroup {
                        id: entry.key().clone(),
                    });
                }
                Entry::Vacant(entry) => {
                    entry.insert(Group {
                        members: group.members.into_iter().collect(),
                        transfers: group.transfers,
                    });
                }
            }
        }
        let mut routers = BTreeMap::new();
        for router in policy.routers {
            if let Some(id) = router.groups.iter().find(|id| !groups.contains_key(*id)) {
                return Err(DepositAllowlistError::UnknownGroup {
                    router: router.router,
                    id: id.clone(),
                });
            }
            match routers.entry(router.router) {
                Entry::Occupied(entry) => {
                    return Err(DepositAllowlistError::DuplicateRouter {
                        router: *entry.key(),
                    });
                }
                Entry::Vacant(entry) => {
                    entry.insert(router.groups.into_iter().collect());
                }
            }
        }
        Ok(Self { groups, routers })
    }
}

impl From<Policy> for AllowlistPolicy {
    fn from(policy: Policy) -> Self {
        Self {
            groups: policy
                .groups
                .into_iter()
                .map(|(id, group)| AllowlistGroup {
                    id,
                    members: group.members.into_iter().collect(),
                    transfers: group.transfers,
                })
                .collect(),
            routers: policy
                .routers
                .into_iter()
                .map(|(router, groups)| AllowlistRouter {
                    router,
                    groups: groups.into_iter().collect(),
                })
                .collect(),
        }
    }
}

/// A group's members and whether they may transfer to each other.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Group {
    members: BTreeSet<Address>,
    transfers: bool,
}

/// Persisted allowlist and the last signed write applied to it. A sequencer without one is
/// uninitialized and credits every deposit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct State {
    /// Nonce of the last applied signed write.
    nonce: u64,
    /// EIP-712 signing hash of the last applied signed write, so a retry of that write succeeds
    /// without being applied again.
    last_write: B256,
    policy: Policy,
}

/// The single-list file that earlier releases wrote. Its addresses load as the default group.
// TODO: remove once every sequencer has rewritten its file in the grouped shape.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FlatState {
    nonce: u64,
    last_write: B256,
    addresses: BTreeSet<Address>,
}

impl From<FlatState> for State {
    fn from(flat: FlatState) -> Self {
        let mut policy = Policy::default();
        policy.default_group().members = flat.addresses;
        Self {
            nonce: flat.nonce,
            last_write: flat.last_write,
            policy,
        }
    }
}

/// The status of `state`, where `None` is an uninitialized list.
fn status_of(state: Option<&State>) -> DepositAllowlistStatus {
    let policy = state.map(|state| &state.policy);
    DepositAllowlistStatus {
        initialized: state.is_some(),
        nonce: state.map_or(0, |state| state.nonce),
        list_hash: policy.cloned().unwrap_or_default().hash(),
        count: policy.map_or(0, Policy::len),
    }
}

fn log_status(status: DepositAllowlistStatus, message: &'static str) {
    metrics::gauge!("zone_deposit_allowlist_entries").set(status.count as f64);
    info!(
        target: "zone::allowlist",
        initialized = status.initialized,
        nonce = status.nonce,
        count = status.count,
        list_hash = %status.list_hash,
        "{message}"
    );
}

/// Which version of the allowlist a sequencer holds, for comparing sequencers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DepositAllowlistStatus {
    /// Whether the list has been written; an uninitialized sequencer credits every deposit.
    pub(crate) initialized: bool,
    /// Nonce of the last applied signed write; 0 before the first one.
    pub(crate) nonce: u64,
    /// EIP-712 struct hash of the canonical `AllowlistPolicy`; that of an empty policy while
    /// uninitialized.
    pub(crate) list_hash: B256,
    /// Entries counted against [`MAX_DEPOSIT_ALLOWLIST_LEN`].
    pub(crate) count: usize,
}

/// A sequencer's allowlist and its status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepositAllowlistSnapshot {
    #[serde(flatten)]
    pub(crate) status: DepositAllowlistStatus,
    /// Every group and router in canonical order; empty while uninitialized.
    pub(crate) policy: Policy,
}

/// One sequencer's entry in `zoneAdmin_getDepositAllowlistStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SequencerAllowlistStatus {
    /// The sequencer's P2P public key; omitted when a sequencer reports itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sequencer: Option<String>,
    #[serde(flatten)]
    pub(crate) status: DepositAllowlistStatus,
}

/// Groups of accounts whose L1 deposits the leader credits and whose Zone transfers and router
/// withdrawals it admits, persisted as JSON.
///
/// Cloning shares the same list.
#[derive(Debug, Clone)]
pub struct DepositAllowlist {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Persisted list location, rewritten atomically on every update.
    path: PathBuf,
    /// Authorizes writes received over RPC.
    admin: DepositAllowlistAdmin,
    /// Current state, `None` until the first write; the engine reads it on every block build.
    state: RwLock<Option<State>>,
    /// Serializes writers so updates persist and apply in order without holding `state` across
    /// disk I/O.
    write_lock: Mutex<()>,
}

impl DepositAllowlist {
    /// Load the persisted list from `path`, starting uninitialized when it does not exist yet.
    pub fn load(path: PathBuf, admin: DepositAllowlistAdmin) -> eyre::Result<Self> {
        // Only a missing path means uninitialized. Any other I/O error, or a dangling symlink,
        // fails startup rather than crediting every deposit.
        let state = match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(err).wrap_err_with(|| {
                    format!("failed to check deposit allowlist {}", path.display())
                });
            }
            Ok(_) => Some(read_state(&path)?),
        };
        log_status(status_of(state.as_ref()), "Loaded deposit allowlist");
        if state.is_none() {
            warn!(
                target: "zone::allowlist",
                path = %path.display(),
                "Deposit allowlist is uninitialized: this sequencer credits every deposit until the admin writes the list"
            );
        } else if state.as_ref().is_some_and(|state| {
            state
                .policy
                .groups
                .values()
                .all(|group| group.members.is_empty())
        }) {
            warn!(
                target: "zone::allowlist",
                path = %path.display(),
                "Deposit allowlist has no members: this sequencer bounces every deposit while it leads"
            );
        }
        Ok(Self {
            inner: Arc::new(Inner {
                path,
                admin,
                state: RwLock::new(state),
                write_lock: Mutex::new(()),
            }),
        })
    }

    pub(crate) fn status(&self) -> DepositAllowlistStatus {
        status_of(self.inner.state.read().as_ref())
    }

    pub(crate) fn snapshot(&self) -> DepositAllowlistSnapshot {
        let state = self.inner.state.read();
        DepositAllowlistSnapshot {
            status: status_of(state.as_ref()),
            policy: state
                .as_ref()
                .map(|state| state.policy.clone())
                .unwrap_or_default(),
        }
    }

    /// Add or remove `addresses` in the default group, persisting the result before it takes
    /// effect. Fails while the list is uninitialized, because a partial first write would stop
    /// crediting everyone else.
    pub fn set(&self, addresses: &[Address], allowed: bool) -> Result<(), DepositAllowlistError> {
        self.update(|state| {
            let mut next = state.ok_or(DepositAllowlistError::Uninitialized)?.clone();
            apply_set(&mut next.policy.default_group().members, addresses, allowed);
            Ok(Some(next))
        })
    }

    /// Replace the members of the default group, persisting the result before it takes effect.
    pub fn replace(&self, addresses: Vec<Address>) -> Result<(), DepositAllowlistError> {
        self.update(|state| {
            let mut next = state.cloned().unwrap_or_default();
            next.policy.default_group().members = addresses.into_iter().collect();
            Ok(Some(next))
        })
    }

    /// Apply `write` if the admin signed it, its deadline has not passed, and its nonce exceeds
    /// the last applied one. A retry of the last applied write succeeds without reapplying it.
    /// Only a replacement can initialize the list.
    pub(crate) fn apply_signed(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        let hash = self.inner.admin.authorize(&write)?;
        self.update(|state| {
            if let Some(state) = state {
                if write.nonce == state.nonce && hash == state.last_write {
                    return Ok(None);
                }
                if write.nonce <= state.nonce {
                    return Err(DepositAllowlistError::StaleNonce {
                        nonce: write.nonce,
                        applied: state.nonce,
                    });
                }
            } else if matches!(write.write, Write::Set { .. }) {
                return Err(DepositAllowlistError::Uninitialized);
            }
            let mut policy = state.map(|state| state.policy.clone()).unwrap_or_default();
            match write.write {
                Write::Set { addresses, allowed } => {
                    apply_set(&mut policy.default_group().members, &addresses, allowed);
                }
                Write::Replace { addresses } => {
                    policy.default_group().members = addresses.into_iter().collect();
                }
                Write::ReplaceGroups { policy: next } => policy = Policy::try_from(next)?,
            }
            Ok(Some(State {
                nonce: write.nonce,
                last_write: hash,
                policy,
            }))
        })
    }

    async fn apply_signed_blocking(&self, write: SignedWrite) -> Result<(), DepositAllowlistError> {
        let allowlist = self.clone();
        tokio::task::spawn_blocking(move || allowlist.apply_signed(write))
            .await
            .map_err(|err| DepositAllowlistError::Internal(err.to_string()))?
    }

    /// Replace the decryption data of every deposit the list does not admit: one whose recipient
    /// shares no group with its L1 sender and no group the sender serves as a router. An
    /// uninitialized list admits every deposit.
    ///
    /// `senders` holds the L1 sender of each user deposit in queue order; `prepare_many` emits
    /// exactly one entry in `recipients` and `decryptions` per user deposit in the same order.
    /// A `None` recipient failed decryption and is refunded anyway. Returns the number of rejected
    /// deposits.
    pub fn reject_unlisted(
        &self,
        senders: &[Address],
        recipients: &[Option<Address>],
        decryptions: &mut [DecryptionData],
    ) -> eyre::Result<usize> {
        ensure!(
            senders.len() == decryptions.len() && recipients.len() == decryptions.len(),
            "{} deposit senders and {} recipients but {} decryptions",
            senders.len(),
            recipients.len(),
            decryptions.len()
        );
        let state = self.inner.state.read();
        let Some(state) = state.as_ref() else {
            return Ok(0);
        };
        let mut rejected = 0;
        for ((sender, recipient), decryption) in senders.iter().zip(recipients).zip(decryptions) {
            if !state.policy.admits_deposit(*sender, *recipient) {
                *decryption = FAILED_DECRYPTION;
                rejected += 1;
            }
        }
        Ok(rejected)
    }

    /// Persist and install the state `next` derives from the current one. `None` leaves the
    /// state unchanged.
    fn update(
        &self,
        next: impl FnOnce(Option<&State>) -> Result<Option<State>, DepositAllowlistError>,
    ) -> Result<(), DepositAllowlistError> {
        let _writer = self.inner.write_lock.lock();
        // Only writers change `state`, so this snapshot stays current until the swap below.
        let Some(next) = next(self.inner.state.read().as_ref())? else {
            return Ok(());
        };
        next.policy.check_limits()?;
        persist(&self.inner.path, &next)
            .map_err(|err| DepositAllowlistError::Persist(format!("{err:#}")))?;
        log_status(status_of(Some(&next)), "Updated deposit allowlist");
        *self.inner.state.write() = Some(next);
        Ok(())
    }
}

impl TransferAllowlist for DepositAllowlist {
    fn admits(&self, movements: &[Movement]) -> bool {
        self.inner
            .state
            .read()
            .as_ref()
            .is_none_or(|state| state.policy.admits(movements))
    }
}

/// Copy of the leader's allowlist that an RPC-only node keeps to reject transfers on submission,
/// refreshed by the relay's `mirror_leader` task.
///
/// It admits every transfer until the leader reports a written list, and again once it no longer
/// holds one; the leader still enforces its own list. Cloning shares the same copy.
#[derive(Debug, Clone, Default)]
pub(crate) struct AllowlistMirror {
    inner: Arc<MirrorInner>,
}

#[derive(Debug, Default)]
struct MirrorInner {
    /// The leader's written list, `None` while the leader has none or none is known.
    list: RwLock<Option<MirroredList>>,
    /// Wakes the refresh task early, after this node relays a write.
    refresh: Notify,
}

#[derive(Debug)]
struct MirroredList {
    /// Always initialized: the refresh clears the copy instead of installing an unwritten list.
    status: DepositAllowlistStatus,
    policy: Policy,
}

impl AllowlistMirror {
    /// The version of the copy, `None` while the leader has no written list or none is known.
    pub(crate) fn status(&self) -> Option<DepositAllowlistStatus> {
        self.inner.list.read().as_ref().map(|list| list.status)
    }

    /// Install the leader's `snapshot`, returning whether its version differs from the current
    /// copy.
    pub(crate) fn replace(&self, snapshot: DepositAllowlistSnapshot) -> bool {
        let list = MirroredList {
            status: snapshot.status,
            policy: snapshot.policy,
        };
        let mut current = self.inner.list.write();
        let changed = current.as_ref().map(|current| current.status) != Some(list.status);
        *current = Some(list);
        changed
    }

    /// Drop the copy once the leader has no written list, so every transfer is admitted again.
    /// Returns whether it held one.
    pub(crate) fn clear(&self) -> bool {
        self.inner.list.write().take().is_some()
    }

    /// Ask the refresh task to check the sequencers now instead of at its next interval.
    pub(crate) fn request_refresh(&self) {
        self.inner.refresh.notify_one();
    }

    /// Resolves once [`Self::request_refresh`] was called.
    pub(crate) async fn refresh_requested(&self) {
        self.inner.refresh.notified().await;
    }
}

impl TransferAllowlist for AllowlistMirror {
    fn admits(&self, movements: &[Movement]) -> bool {
        self.inner
            .list
            .read()
            .as_ref()
            .is_none_or(|list| list.policy.admits(movements))
    }
}

/// Remove pooled transactions that `allowlist` no longer admits, so this node stops forwarding
/// them after the list changes. Returns how many were removed.
///
/// This scans pending and queued transactions whether or not they propagate, since the forwarder
/// resends local transactions either way.
pub(crate) fn evict_unlisted_transfers<P>(pool: &P, allowlist: &dyn TransferAllowlist) -> usize
where
    P: TransactionPool<Transaction = TempoPooledTransaction>,
{
    let unlisted = pool
        .all_transactions()
        .iter()
        .filter(|tx| validate_transfer_calls(allowlist, &tx.transaction).is_err())
        .map(|tx| *tx.hash())
        .collect::<Vec<_>>();
    let count = unlisted.len();
    if count > 0 {
        pool.remove_transactions(unlisted);
    }
    count
}

fn apply_set(list: &mut BTreeSet<Address>, addresses: &[Address], allowed: bool) {
    for address in addresses {
        if allowed {
            list.insert(*address);
        } else {
            list.remove(address);
        }
    }
}

/// `zoneAdmin` methods for managing the deposit allowlist.
///
/// Served by a sequencer for its own list, or by an RPC-only node that relays each request to
/// every sequencer. Writes carry an EIP-712 signature from the configured admin over
/// [`SetDepositAllowed`], [`ReplaceDepositAllowlist`] or [`ReplaceDepositAllowlistGroups`]. Each
/// write's `nonce` must exceed the last applied one (Unix milliseconds work), and its `deadline`
/// (Unix seconds) must be at most [`MAX_SIGNED_WRITE_VALIDITY`] ahead. Callers must wait for each
/// write to return before sending the next one, and retry a failed write unchanged.
#[rpc(server, namespace = "zoneAdmin")]
pub(crate) trait DepositAllowlistApi {
    /// Add (`allowed = true`) or remove (`allowed = false`) members of the default group.
    #[method(name = "setDepositAllowed")]
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Replace the members of the default group, keeping every other group and router.
    #[method(name = "replaceDepositAllowlist")]
    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Replace every group and router. Rejects empty, overlong or duplicate group IDs, duplicate
    /// routers, and routers naming a group the policy does not hold.
    #[method(name = "replaceDepositAllowlistGroups")]
    async fn replace_deposit_allowlist_groups(
        &self,
        policy: AllowlistPolicy,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()>;

    /// Returns the allowlist and its status. Through an RPC-only node, fails unless every
    /// sequencer holds the same list, naming each sequencer's status.
    #[method(name = "getDepositAllowlist")]
    async fn get_deposit_allowlist(&self) -> RpcResult<DepositAllowlistSnapshot>;

    /// Returns each sequencer's allowlist status, so a sequencer that missed writes or is
    /// uninitialized can be found and fixed with a signed replacement.
    #[method(name = "getDepositAllowlistStatus")]
    async fn get_deposit_allowlist_status(&self) -> RpcResult<Vec<SequencerAllowlistStatus>>;
}

impl DepositAllowlistApiServer for DepositAllowlist {
    async fn set_deposit_allowed(
        &self,
        addresses: Vec<Address>,
        allowed: bool,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        Ok(self
            .apply_signed_blocking(SignedWrite {
                write: Write::Set { addresses, allowed },
                nonce,
                deadline,
                signature,
            })
            .await?)
    }

    async fn replace_deposit_allowlist(
        &self,
        addresses: Vec<Address>,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        Ok(self
            .apply_signed_blocking(SignedWrite {
                write: Write::Replace { addresses },
                nonce,
                deadline,
                signature,
            })
            .await?)
    }

    async fn replace_deposit_allowlist_groups(
        &self,
        policy: AllowlistPolicy,
        nonce: u64,
        deadline: u64,
        signature: Bytes,
    ) -> RpcResult<()> {
        Ok(self
            .apply_signed_blocking(SignedWrite {
                write: Write::ReplaceGroups { policy },
                nonce,
                deadline,
                signature,
            })
            .await?)
    }

    async fn get_deposit_allowlist(&self) -> RpcResult<DepositAllowlistSnapshot> {
        Ok(self.snapshot())
    }

    async fn get_deposit_allowlist_status(&self) -> RpcResult<Vec<SequencerAllowlistStatus>> {
        Ok(vec![SequencerAllowlistStatus {
            sequencer: None,
            status: self.status(),
        }])
    }
}

/// Read the persisted list, in the grouped shape or the single-list shape of earlier releases.
fn read_state(path: &Path) -> eyre::Result<State> {
    let file = File::open(path)
        .wrap_err_with(|| format!("failed to open deposit allowlist {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_reader(std::io::BufReader::new(file))
        .wrap_err_with(|| format!("failed to parse deposit allowlist {}", path.display()))?;
    let state = if value.get("addresses").is_some() {
        serde_json::from_value::<FlatState>(value).map(State::from)
    } else {
        serde_json::from_value::<State>(value)
    }
    .wrap_err_with(|| format!("failed to parse deposit allowlist {}", path.display()))?;
    state
        .policy
        .check_limits()
        .wrap_err_with(|| format!("deposit allowlist {} is too large", path.display()))?;
    Ok(state)
}

/// Atomically replace `path` with `state`: write a sibling temp file, fsync it, rename it over
/// `path`, then fsync the directory so the rename survives a crash.
fn persist(path: &Path, state: &State) -> eyre::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| eyre::eyre!("deposit allowlist {} has no parent", path.display()))?;
    std::fs::create_dir_all(dir).wrap_err_with(|| format!("failed to create {}", dir.display()))?;
    let mut file = tempfile::NamedTempFile::new_in(dir)
        .wrap_err_with(|| format!("failed to create temp file in {}", dir.display()))?;
    serde_json::to_writer_pretty(&mut file, state)
        .wrap_err("failed to serialize deposit allowlist")?;
    file.write_all(b"\n")
        .and_then(|()| file.as_file().sync_all())
        .wrap_err("failed to write deposit allowlist")?;
    file.persist(path)
        .wrap_err_with(|| format!("failed to replace {}", path.display()))?;
    File::open(dir)
        .and_then(|dir| dir.sync_all())
        .wrap_err_with(|| format!("failed to sync {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{TxKind, U256, address};
    use alloy_signer::SignerSync as _;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall as _;
    use reth_primitives_traits::Recovered;
    use reth_transaction_pool::{
        Pool, PoolConfig, TransactionOrigin, blobstore::InMemoryBlobStore,
        noop::MockTransactionValidator,
    };
    use tempo_precompiles::tip20::ITIP20;
    use tempo_primitives::{
        TempoAddressExt as _,
        transaction::{Call, TempoTransaction},
    };
    use tempo_transaction_pool::{ordering::TempoTipOrdering, transaction::TempoPooledTransaction};
    use zone_l1::abi::ChaumPedersenProof;

    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const BOB: Address = address!("0x0000000000000000000000000000000000000b0b");
    const CAROL: Address = address!("0x00000000000000000000000000000000000ca201");
    const DAVE: Address = address!("0x0000000000000000000000000000000000000da7");
    const GATEWAY: Address = address!("0x0000000000000000000000000000000000000ca7");
    const ROUTER: Address = address!("0x00000000000000000000000000000000000c0de0");
    const ZONE_CHAIN_ID: u64 = 421_700_003;

    fn admin_signer() -> PrivateKeySigner {
        PrivateKeySigner::from_bytes(&B256::repeat_byte(0xad)).unwrap()
    }

    fn admin() -> DepositAllowlistAdmin {
        DepositAllowlistAdmin {
            address: admin_signer().address(),
            zone_chain_id: ZONE_CHAIN_ID,
        }
    }

    fn load(path: PathBuf) -> DepositAllowlist {
        DepositAllowlist::load(path, admin()).unwrap()
    }

    /// Members of the default group.
    fn members(allowlist: &DepositAllowlist) -> Vec<Address> {
        allowlist
            .snapshot()
            .policy
            .groups
            .get(DEFAULT_GROUP)
            .map(|group| group.members.iter().copied().collect())
            .unwrap_or_default()
    }

    fn transfer(from: Address, to: Address) -> Movement {
        Movement::Transfer {
            spender: None,
            from,
            to,
        }
    }

    fn group(id: &str, members: &[Address], transfers: bool) -> AllowlistGroup {
        AllowlistGroup {
            id: id.to_owned(),
            members: members.to_vec(),
            transfers,
        }
    }

    fn router(router: Address, groups: &[&str]) -> AllowlistRouter {
        AllowlistRouter {
            router,
            groups: groups.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// Two tenants: `custodial` (ALICE, BOB and GATEWAY, transfers allowed) and `embedded`
    /// (CAROL and GATEWAY, no transfers), with ROUTER serving only `custodial`.
    fn tenants() -> AllowlistPolicy {
        AllowlistPolicy {
            groups: vec![
                group("custodial", &[ALICE, BOB, GATEWAY], true),
                group("embedded", &[CAROL, GATEWAY], false),
            ],
            routers: vec![router(ROUTER, &["custodial"])],
        }
    }

    /// An allowlist holding [`tenants`].
    fn grouped(dir: &Path) -> DepositAllowlist {
        let allowlist = load(dir.join(DEPOSIT_ALLOWLIST_FILE_NAME));
        allowlist
            .apply_signed(sign(Write::ReplaceGroups { policy: tenants() }, 1))
            .unwrap();
        allowlist
    }

    /// An allowlist holding only ALICE.
    fn alice_only(dir: &Path) -> DepositAllowlist {
        let allowlist = load(dir.join(DEPOSIT_ALLOWLIST_FILE_NAME));
        allowlist.replace(vec![ALICE]).unwrap();
        allowlist
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign_for(
        signer: &PrivateKeySigner,
        zone_chain_id: u64,
        write: Write,
        nonce: u64,
        deadline: u64,
    ) -> SignedWrite {
        let mut signed = SignedWrite {
            write,
            nonce,
            deadline,
            signature: Bytes::new(),
        };
        let domain = DepositAllowlistAdmin {
            address: signer.address(),
            zone_chain_id,
        }
        .domain();
        let signature = signer
            .sign_hash_sync(&signed.signing_hash(&domain))
            .unwrap();
        signed.signature = Bytes::from(signature.as_bytes());
        signed
    }

    /// A write the admin signed for this zone, valid for a minute.
    fn sign(write: Write, nonce: u64) -> SignedWrite {
        sign_for(&admin_signer(), ZONE_CHAIN_ID, write, nonce, now() + 60)
    }

    fn set(addresses: &[Address], allowed: bool) -> Write {
        Write::Set {
            addresses: addresses.to_vec(),
            allowed,
        }
    }

    fn valid_decryption() -> DecryptionData {
        DecryptionData {
            sharedSecret: B256::repeat_byte(1),
            sharedSecretYParity: 0x03,
            cpProof: ChaumPedersenProof {
                s: B256::repeat_byte(2),
                c: B256::repeat_byte(3),
            },
        }
    }

    #[test]
    fn starts_uninitialized_and_persists_updates_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join(DEPOSIT_ALLOWLIST_FILE_NAME);

        let allowlist = load(path.clone());
        assert!(!allowlist.status().initialized);
        assert!(!path.exists(), "loading must not create the file");
        // An uninitialized list credits every sender.
        let mut decryptions = vec![valid_decryption()];
        assert_eq!(
            allowlist
                .reject_unlisted(&[BOB], &[Some(BOB)], &mut decryptions)
                .unwrap(),
            0
        );
        assert_eq!(decryptions, vec![valid_decryption()]);

        // Only a full replacement initializes the list: a first add or remove would stop
        // crediting every sender outside it.
        for allowed in [true, false] {
            assert_eq!(
                allowlist.apply_signed(sign(set(&[ALICE], allowed), 1)),
                Err(DepositAllowlistError::Uninitialized)
            );
        }
        assert_eq!(
            allowlist.set(&[ALICE], true),
            Err(DepositAllowlistError::Uninitialized)
        );
        assert!(!allowlist.status().initialized);
        assert!(!path.exists());

        allowlist
            .apply_signed(sign(
                Write::Replace {
                    addresses: vec![ALICE, BOB],
                },
                3,
            ))
            .unwrap();
        allowlist
            .apply_signed(sign(set(&[ALICE], false), 7))
            .unwrap();
        assert!(allowlist.status().initialized);

        let reloaded = load(path);
        assert!(reloaded.status().initialized);
        assert_eq!(members(&reloaded), vec![BOB]);
        // The nonce survives the restart, so the applied write cannot be replayed afterwards.
        assert_eq!(
            reloaded.apply_signed(sign(set(&[ALICE], true), 7)),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 7,
                applied: 7
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_allowlist_symlink_fails_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        std::os::unix::fs::symlink(dir.path().join("moved.json"), &path).unwrap();

        // Starting uninitialized here would credit every deposit.
        let err = DepositAllowlist::load(path, admin()).unwrap_err();
        assert!(format!("{err:#}").contains("failed to open"), "{err:#}");
    }

    #[test]
    fn a_written_empty_list_bounces_every_sender_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let allowlist = alice_only(dir.path());

        allowlist
            .apply_signed(sign(set(&[ALICE], false), 1))
            .unwrap();

        // Emptying the list must not make it uninitialized again, before or after a restart.
        for allowlist in [allowlist, load(path)] {
            let status = allowlist.status();
            assert!(status.initialized);
            assert_eq!(status.count, 0);
            let mut decryptions = vec![valid_decryption()];
            assert_eq!(
                allowlist
                    .reject_unlisted(&[ALICE], &[Some(ALICE)], &mut decryptions)
                    .unwrap(),
                1
            );
            assert_eq!(decryptions, vec![FAILED_DECRYPTION]);
        }
    }

    #[test]
    fn replace_overwrites_the_persisted_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let allowlist = alice_only(dir.path());

        allowlist.replace(vec![BOB]).unwrap();

        assert_eq!(members(&allowlist), vec![BOB]);
        assert_eq!(
            read_state(&path).unwrap().policy.groups[DEFAULT_GROUP].members,
            BTreeSet::from([BOB])
        );
    }

    #[test]
    fn failed_persist_leaves_the_list_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let allowlist = alice_only(dir.path());

        // A directory at the target path makes the rename fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        let err = allowlist.set(&[BOB], true).unwrap_err();
        assert!(err.to_string().contains("failed to replace"), "{err}");
        assert_eq!(members(&allowlist), vec![ALICE]);
    }

    #[test]
    fn applies_only_writes_the_admin_signed_for_this_zone() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let deadline = now() + 60;

        let stranger = PrivateKeySigner::from_bytes(&B256::repeat_byte(0x5e)).unwrap();
        assert_eq!(
            allowlist.apply_signed(sign_for(
                &stranger,
                ZONE_CHAIN_ID,
                set(&[BOB], true),
                1,
                deadline
            )),
            Err(DepositAllowlistError::Unauthorized {
                signer: stranger.address()
            })
        );
        // The admin's signature for another zone recovers to a different address here.
        assert!(matches!(
            allowlist.apply_signed(sign_for(
                &admin_signer(),
                ZONE_CHAIN_ID + 1,
                set(&[BOB], true),
                1,
                deadline
            )),
            Err(DepositAllowlistError::Unauthorized { signer }) if signer != admin().address
        ));
        // A signature does not carry over to a different write or nonce.
        let mut tampered = sign(set(&[BOB], true), 1);
        tampered.write = set(&[ALICE], false);
        assert!(matches!(
            allowlist.apply_signed(tampered),
            Err(DepositAllowlistError::Unauthorized { .. })
        ));
        let mut renonced = sign(set(&[BOB], true), 1);
        renonced.nonce = 2;
        assert!(matches!(
            allowlist.apply_signed(renonced),
            Err(DepositAllowlistError::Unauthorized { .. })
        ));
        let mut malformed = sign(set(&[BOB], true), 1);
        malformed.signature = Bytes::from_static(&[1, 2, 3]);
        assert_eq!(
            allowlist.apply_signed(malformed),
            Err(DepositAllowlistError::MalformedSignature)
        );
        assert_eq!(members(&allowlist), vec![ALICE]);

        allowlist.apply_signed(sign(set(&[BOB], true), 1)).unwrap();
        allowlist
            .apply_signed(sign(
                Write::Replace {
                    addresses: vec![BOB],
                },
                2,
            ))
            .unwrap();
        assert_eq!(members(&allowlist), vec![BOB]);
    }

    #[test]
    fn rejects_replayed_writes_but_accepts_a_retry_of_the_last_one() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let add_bob = sign(set(&[BOB], true), 10);
        let remove_bob = sign(set(&[BOB], false), 20);

        allowlist.apply_signed(add_bob.clone()).unwrap();
        allowlist.apply_signed(remove_bob.clone()).unwrap();
        // Retrying the last write succeeds and changes nothing.
        allowlist.apply_signed(remove_bob).unwrap();
        assert_eq!(members(&allowlist), vec![ALICE]);

        // Replaying the earlier add cannot undo the removal.
        assert_eq!(
            allowlist.apply_signed(add_bob),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 10,
                applied: 20
            })
        );
        // A different write reusing the last nonce is rejected too.
        assert_eq!(
            allowlist.apply_signed(sign(set(&[BOB], true), 20)),
            Err(DepositAllowlistError::StaleNonce {
                nonce: 20,
                applied: 20
            })
        );
        assert_eq!(members(&allowlist), vec![ALICE]);
    }

    #[test]
    fn rejects_writes_outside_the_signature_window() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let max = MAX_SIGNED_WRITE_VALIDITY.as_secs();
        let sign_until = |deadline| {
            sign_for(
                &admin_signer(),
                ZONE_CHAIN_ID,
                set(&[BOB], true),
                1,
                deadline,
            )
        };

        let expired = now() - 1;
        assert_eq!(
            allowlist.apply_signed(sign_until(expired)),
            Err(DepositAllowlistError::Expired { deadline: expired })
        );
        let too_far = now() + max + 60;
        assert_eq!(
            allowlist.apply_signed(sign_until(too_far)),
            Err(DepositAllowlistError::DeadlineTooFar { deadline: too_far })
        );
        assert_eq!(members(&allowlist), vec![ALICE]);

        allowlist
            .apply_signed(sign_until(now() + max - 60))
            .unwrap();
        assert_eq!(members(&allowlist), vec![BOB, ALICE]);
    }

    #[test]
    fn transfer_parties_are_restricted_once_the_list_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME));
        assert!(allowlist.admits(&[transfer(BOB, BOB)]));

        allowlist.replace(vec![ALICE]).unwrap();
        assert!(allowlist.admits(&[transfer(ALICE, ALICE)]));
        assert!(!allowlist.admits(&[transfer(ALICE, BOB)]));

        allowlist.replace(Vec::new()).unwrap();
        assert!(!allowlist.admits(&[transfer(ALICE, ALICE)]));
    }

    #[test]
    fn rejects_writes_that_exceed_the_list_limit() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = load(dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME));
        let addresses = (0..=MAX_DEPOSIT_ALLOWLIST_LEN)
            .map(|index| Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes()))
            .collect::<Vec<_>>();

        assert_eq!(
            allowlist.replace(addresses.clone()),
            Err(DepositAllowlistError::TooLarge {
                len: MAX_DEPOSIT_ALLOWLIST_LEN + 1
            })
        );
        allowlist
            .replace(addresses[..MAX_DEPOSIT_ALLOWLIST_LEN].to_vec())
            .unwrap();
        assert_eq!(
            allowlist.set(&addresses[MAX_DEPOSIT_ALLOWLIST_LEN..], true),
            Err(DepositAllowlistError::TooLarge {
                len: MAX_DEPOSIT_ALLOWLIST_LEN + 1
            })
        );
        assert_eq!(members(&allowlist).len(), MAX_DEPOSIT_ALLOWLIST_LEN);
    }

    #[test]
    fn reject_unlisted_zeroes_only_unlisted_senders_and_recipients() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());
        let valid = valid_decryption();
        let mut decryptions = vec![valid.clone(); 5];

        let rejected = allowlist
            .reject_unlisted(
                &[ALICE, BOB, ALICE, BOB, ALICE],
                &[Some(ALICE), Some(ALICE), Some(BOB), None, None],
                &mut decryptions,
            )
            .unwrap();

        assert_eq!(rejected, 3);
        assert_eq!(
            decryptions,
            vec![
                valid.clone(),
                FAILED_DECRYPTION,
                FAILED_DECRYPTION,
                FAILED_DECRYPTION,
                valid,
            ]
        );
    }

    #[test]
    fn reject_unlisted_requires_one_decryption_per_deposit() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = alice_only(dir.path());

        for (senders, recipients) in [(&[ALICE][..], &[][..]), (&[][..], &[Some(ALICE)][..])] {
            let err = allowlist
                .reject_unlisted(senders, recipients, &mut [])
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "{} deposit senders and {} recipients but 0 decryptions",
                    senders.len(),
                    recipients.len()
                )
            );
        }
    }

    #[test]
    fn deposits_need_the_recipients_group_to_hold_or_route_the_sender() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());
        let cases = [
            // Same group.
            (ALICE, Some(BOB), true),
            // A sender in several groups funds each of them.
            (GATEWAY, Some(BOB), true),
            (GATEWAY, Some(CAROL), true),
            // Across groups.
            (ALICE, Some(CAROL), false),
            (CAROL, Some(ALICE), false),
            // A router credits only the groups it serves.
            (ROUTER, Some(ALICE), true),
            (ROUTER, Some(CAROL), false),
            // Unlisted parties.
            (DAVE, Some(ALICE), false),
            (ALICE, Some(DAVE), false),
            // An undecrypted recipient refunds anyway, so only the sender is checked.
            (ROUTER, None, true),
            (CAROL, None, true),
            (DAVE, None, false),
        ];
        let senders = cases.map(|(sender, _, _)| sender);
        let recipients = cases.map(|(_, recipient, _)| recipient);
        let mut decryptions = vec![valid_decryption(); cases.len()];

        let rejected = allowlist
            .reject_unlisted(&senders, &recipients, &mut decryptions)
            .unwrap();

        assert_eq!(
            rejected,
            cases.iter().filter(|(_, _, admitted)| !admitted).count()
        );
        for ((sender, recipient, admitted), decryption) in cases.iter().zip(&decryptions) {
            assert_eq!(
                *decryption != FAILED_DECRYPTION,
                *admitted,
                "{sender} -> {recipient:?}"
            );
        }
    }

    #[test]
    fn transfers_need_one_group_that_allows_them() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());

        assert!(allowlist.admits(&[transfer(ALICE, BOB)]));
        // `embedded` holds both parties but does not allow transfers.
        assert!(!allowlist.admits(&[transfer(CAROL, GATEWAY)]));
        assert!(!allowlist.admits(&[transfer(ALICE, CAROL)]));
        assert!(!allowlist.admits(&[transfer(ALICE, DAVE)]));
        // The spender must be in the same group as both parties.
        let spend = |spender| Movement::Transfer {
            spender: Some(spender),
            from: ALICE,
            to: BOB,
        };
        assert!(allowlist.admits(&[spend(GATEWAY)]));
        assert!(!allowlist.admits(&[spend(CAROL)]));
        // One rejected movement rejects them all.
        assert!(!allowlist.admits(&[transfer(ALICE, BOB), transfer(ALICE, CAROL)]));
    }

    #[test]
    fn only_a_routers_groups_may_withdraw_to_it() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());
        let withdraw = |sender, to| Movement::Withdrawal { sender, to };

        assert!(allowlist.admits(&[withdraw(ALICE, ROUTER)]));
        assert!(!allowlist.admits(&[withdraw(CAROL, ROUTER)]));
        assert!(!allowlist.admits(&[withdraw(DAVE, ROUTER)]));
        // Withdrawals to any other address stay open, even for unlisted accounts.
        assert!(allowlist.admits(&[withdraw(CAROL, CAROL)]));
        assert!(allowlist.admits(&[withdraw(DAVE, ALICE)]));
    }

    #[test]
    fn default_group_writes_keep_the_other_groups() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());

        allowlist.apply_signed(sign(set(&[DAVE], true), 2)).unwrap();
        allowlist
            .apply_signed(sign(
                Write::Replace {
                    addresses: vec![DAVE, BOB],
                },
                3,
            ))
            .unwrap();

        let policy = allowlist.snapshot().policy;
        assert_eq!(
            policy.groups[DEFAULT_GROUP],
            Group {
                members: BTreeSet::from([BOB, DAVE]),
                transfers: true,
            }
        );
        let mut expected = Policy::try_from(tenants()).unwrap();
        expected.groups.remove(DEFAULT_GROUP);
        let mut rest = policy;
        rest.groups.remove(DEFAULT_GROUP);
        assert_eq!(rest, expected);
        // BOB's groups do not combine: transfers need one group holding both parties.
        assert!(allowlist.admits(&[transfer(BOB, DAVE)]));
        assert!(!allowlist.admits(&[transfer(ALICE, DAVE)]));
    }

    #[test]
    fn rejects_invalid_policies() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());
        let long_id = "g".repeat(MAX_GROUP_ID_LEN + 1);
        let cases = [
            (
                AllowlistPolicy {
                    groups: vec![group("", &[], true)],
                    routers: vec![],
                },
                DepositAllowlistError::InvalidGroupId { id: String::new() },
            ),
            (
                AllowlistPolicy {
                    groups: vec![group(&long_id, &[], true)],
                    routers: vec![],
                },
                DepositAllowlistError::InvalidGroupId {
                    id: long_id.clone(),
                },
            ),
            (
                AllowlistPolicy {
                    groups: vec![group("a", &[ALICE], true), group("a", &[BOB], true)],
                    routers: vec![],
                },
                DepositAllowlistError::DuplicateGroup { id: "a".to_owned() },
            ),
            (
                AllowlistPolicy {
                    groups: vec![group("a", &[], true)],
                    routers: vec![router(ROUTER, &["a"]), router(ROUTER, &[])],
                },
                DepositAllowlistError::DuplicateRouter { router: ROUTER },
            ),
            (
                AllowlistPolicy {
                    groups: vec![group("a", &[], true)],
                    routers: vec![router(ROUTER, &["a", "b"])],
                },
                DepositAllowlistError::UnknownGroup {
                    router: ROUTER,
                    id: "b".to_owned(),
                },
            ),
        ];
        for (nonce, (policy, error)) in (2..).zip(cases) {
            assert_eq!(
                allowlist.apply_signed(sign(Write::ReplaceGroups { policy }, nonce)),
                Err(error)
            );
        }
        assert_eq!(
            allowlist.snapshot().policy,
            Policy::try_from(tenants()).unwrap()
        );
    }

    #[test]
    fn rejects_policies_over_the_group_and_router_limits() {
        let dir = tempfile::tempdir().unwrap();
        let allowlist = grouped(dir.path());
        let groups = (0..=MAX_GROUPS)
            .map(|index| group(&index.to_string(), &[], false))
            .collect::<Vec<_>>();
        let routers = (0..=MAX_ROUTERS)
            .map(|index| {
                let address =
                    Address::left_padding_from(&u32::try_from(index).unwrap().to_be_bytes());
                router(address, &[])
            })
            .collect::<Vec<_>>();

        assert_eq!(
            allowlist.apply_signed(sign(
                Write::ReplaceGroups {
                    policy: AllowlistPolicy {
                        groups: groups.clone(),
                        routers: vec![],
                    },
                },
                2
            )),
            Err(DepositAllowlistError::TooManyGroups {
                count: MAX_GROUPS + 1
            })
        );
        assert_eq!(
            allowlist.apply_signed(sign(
                Write::ReplaceGroups {
                    policy: AllowlistPolicy {
                        groups: vec![],
                        routers: routers.clone(),
                    },
                },
                3
            )),
            Err(DepositAllowlistError::TooManyRouters {
                count: MAX_ROUTERS + 1
            })
        );
        allowlist
            .apply_signed(sign(
                Write::ReplaceGroups {
                    policy: AllowlistPolicy {
                        groups: groups[..MAX_GROUPS].to_vec(),
                        routers: routers[..MAX_ROUTERS].to_vec(),
                    },
                },
                4,
            ))
            .unwrap();
    }

    #[test]
    fn list_hash_is_independent_of_write_order() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let shuffled = AllowlistPolicy {
            groups: vec![
                group("embedded", &[GATEWAY, CAROL, CAROL], false),
                group("custodial", &[GATEWAY, BOB, ALICE], true),
            ],
            routers: vec![router(ROUTER, &["custodial"])],
        };
        let allowlist = load(second.path().join(DEPOSIT_ALLOWLIST_FILE_NAME));
        allowlist
            .apply_signed(sign(Write::ReplaceGroups { policy: shuffled }, 1))
            .unwrap();

        let expected = grouped(first.path()).status();
        assert_eq!(allowlist.status(), expected);
        assert_eq!(expected.count, 6);
        assert_eq!(
            expected.list_hash,
            AllowlistPolicy::from(Policy::try_from(tenants()).unwrap()).eip712_hash_struct()
        );
    }

    #[test]
    fn loads_a_single_list_file_as_the_default_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(DEPOSIT_ALLOWLIST_FILE_NAME);
        let last_write = B256::repeat_byte(7);
        std::fs::write(
            &path,
            serde_json::json!({
                "nonce": 5,
                "lastWrite": last_write,
                "addresses": [ALICE, BOB],
            })
            .to_string(),
        )
        .unwrap();

        let allowlist = load(path.clone());
        assert_eq!(allowlist.status().nonce, 5);
        assert_eq!(members(&allowlist), vec![BOB, ALICE]);
        assert!(allowlist.admits(&[transfer(ALICE, BOB)]));

        // The next write stores the grouped shape, which loads back the same.
        allowlist
            .apply_signed(sign(set(&[CAROL], true), 6))
            .unwrap();
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(!stored.contains("addresses"), "{stored}");
        assert_eq!(load(path).snapshot(), allowlist.snapshot());
    }

    #[tokio::test]
    async fn eviction_covers_local_transactions_that_do_not_propagate() {
        let pool = Pool::new(
            MockTransactionValidator::no_propagate_local(),
            TempoTipOrdering::default(),
            InMemoryBlobStore::default(),
            PoolConfig::default(),
        );
        let transaction = TempoTransaction {
            gas_limit: 100_000,
            max_fee_per_gas: 2_000_000_000,
            calls: vec![Call {
                to: TxKind::Call(Address::new_tip20(0)),
                value: U256::ZERO,
                input: ITIP20::transferCall {
                    to: BOB,
                    amount: U256::ONE,
                }
                .abi_encode()
                .into(),
            }],
            ..Default::default()
        };
        pool.add_transaction(
            TransactionOrigin::Local,
            TempoPooledTransaction::new(Recovered::new_unchecked(
                transaction
                    .into_signed(Signature::test_signature().into())
                    .into(),
                ALICE,
            )),
        )
        .await
        .unwrap();
        // The forwarder resends it although it is not offered for propagation.
        assert!(pool.pooled_transactions().is_empty());

        let dir = tempfile::tempdir().unwrap();
        assert_eq!(evict_unlisted_transfers(&pool, &alice_only(dir.path())), 1);
        assert!(
            pool.get_transactions_by_origin(TransactionOrigin::Local)
                .is_empty()
        );
    }
}
