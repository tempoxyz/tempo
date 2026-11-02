//! Configurable account invariants (TIP-1107, TIP-1111, TIP-1113).

use alloy_primitives::{Address, B256, KECCAK256_EMPTY};
use alloy_sol_types::SolEvent;
use invariants_core::{check, ensure};

use super::{
    AccountUpgraded, Commitments, ConfigurableAccountConfig, ConfigurableAccountConfigUpdated, Key,
    Leaves, Quorum, Role,
    spec::{self, CONFIGURABLE_KEY_TYPE, MARKER_CODE_HASH, MAX_APPROVAL_BYTES, MAX_APPROVALS},
};
use crate::{Check, Checked, Step, StepChecked, Tx, Verdict};

/// The configurable account precompile's views answer. Counted by runners, not judged here.
pub const VIEW: &str = "TEMPO-ACCOUNT-VIEW";

type AccountStep = Step<Commitments, Option<Tx>>;

/// Checks of a step against its signatures and events.
pub const STEP_CHECKS: &[Check<AccountStep>] = &[
    // A commitment is never cleared.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L477>
    check! {
        id: "TEMPO-ACCOUNT-COMMITMENT-KEPT",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            if pre.is_zero() {
                return None;
            }
            ensure!(!post.is_zero(), "commitment {pre} cleared")
        },
    },
    // Only the sender's own migration or owner update changes its commitment.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L477>
    check! {
        id: "TEMPO-ACCOUNT-COMMITMENT-BY-SELF",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            let tx = s.tx.as_ref()?;
            if pre == post {
                return None;
            }
            ensure!(
                tx.sender == **account,
                "commitment {pre} -> {post} in a transaction from {}",
                tx.sender
            )
        },
    },
    // A changed commitment is announced.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L442>
    check! {
        id: "TEMPO-ACCOUNT-COMMITMENT-EVENT",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            if pre == post {
                return None;
            }
            let precompile = s.post.precompile;
            let upgraded = s
                .events::<AccountUpgraded>(precompile)
                .iter()
                .any(|e| e.account == **account && e.commitment == post);
            let updated = s
                .events::<ConfigurableAccountConfigUpdated>(precompile)
                .iter()
                .any(|e| e.account == **account);
            ensure!(
                upgraded || updated,
                "commitment {pre} -> {post} without an event announcing it"
            )
        },
    },
    // The commitment is the hash of the configuration that wrote it.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L478>
    check! {
        id: "TEMPO-ACCOUNT-COMMITMENT-HASH",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            if pre == post {
                return None;
            }
            // A change no event announces is judged by COMMITMENT-EVENT.
            let written = configs_written(s, **account).last()?.clone();
            let want = spec::commitment(&written);
            ensure!(
                want == Some(post),
                "commitment {pre} -> {post}, the configuration written (version {}) hashes to {}",
                written.version,
                want.map_or_else(|| "nothing".to_string(), |want| want.to_string())
            )
        },
    },
    // Every carried or announced configuration passes the configuration rules.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L489>
    check! {
        id: "TEMPO-ACCOUNT-CONFIG-RULES",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let quorums = s
                .tx
                .iter()
                .flat_map(|tx| tx.authority.quorums_of(**account))
                .map(|q| q.config.clone());
            let mut configs = quorums.chain(configs_written(s, **account)).peekable();
            configs.peek()?;
            let broken = configs.find_map(|c| {
                spec::broken_rule(c.threshold, &c.owners).map(|rule| (c.version, rule))
            });
            Some(match broken {
                None => Verdict::Holds,
                Some((version, rule)) => {
                    Verdict::Broken(format!("its configuration at version {version}: {rule}"))
                }
            })
        },
    },
    // Every configurable-account signature names an account with a commitment.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L475>
    check! {
        id: "TEMPO-ACCOUNT-SIGNER-COMMITTED",
        over: |step: &AccountStep| quorums(step),
        judge: |s, q| {
            let pre = s.pre.of.get(&q.account)?;
            ensure!(!pre.is_zero(), "signs for an account without a commitment")
        },
    },
    // A quorum's configuration hashes to its account's commitment.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L486>
    check! {
        id: "TEMPO-ACCOUNT-QUORUM-COMMITMENT",
        over: |step: &AccountStep| quorums(step),
        judge: |s, q| {
            let pre = *s.pre.of.get(&q.account)?;
            // An account without a commitment is judged by SIGNER-COMMITTED.
            if pre.is_zero() {
                return None;
            }
            let hash = spec::commitment(&q.config);
            ensure!(
                hash == Some(pre),
                "carries a configuration hashing to {hash:?}, the commitment is {pre}"
            )
        },
    },
    // Approvals are ascending owners that first reach the threshold at the last one.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L486-L487>
    check! {
        id: "TEMPO-ACCOUNT-QUORUM-WEIGHT",
        over: |step: &AccountStep| quorums(step),
        judge: |_, q| Some(quorum_weight(q).map_or(Verdict::Holds, Verdict::Broken)),
    },
    // 1 to 8 approvals, each at most 2,049 bytes.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L488>
    check! {
        id: "TEMPO-ACCOUNT-APPROVAL-BOUNDS",
        over: |step: &AccountStep| quorums(step),
        judge: |_, q| {
            let count = q.approvals.len();
            let largest = q.approvals.iter().map(|a| a.len).max().unwrap_or(0);
            ensure!(
                (1..=MAX_APPROVALS).contains(&count) && largest <= MAX_APPROVAL_BYTES,
                "carries {count} approvals, the largest {largest} bytes"
            )
        },
    },
    // Owner updates are signed directly by the account's quorum.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L493>
    check! {
        id: "TEMPO-ACCOUNT-UPDATE-QUORUM",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let updates = updates_of(s, **account);
            if updates.is_empty() {
                return None;
            }
            let tx = s.tx.as_ref()?;
            let direct = tx
                .authority
                .quorums_of(**account)
                .any(|q| q.role == Role::Sender);
            ensure!(
                direct && tx.sender == **account,
                "updated {} times in a transaction from {} its quorum did not sign directly",
                updates.len(),
                tx.sender
            )
        },
    },
    // Each owner update keeps the salt and bumps the version by one.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L494>
    check! {
        id: "TEMPO-ACCOUNT-UPDATE-VERSION",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let updates = updates_of(s, **account);
            let signed = s
                .tx
                .as_ref()?
                .authority
                .quorums_of(**account)
                .find(|q| q.role == Role::Sender)?;
            let first = updates.first()?;
            let mut previous = (signed.config.salt, signed.config.version);
            for update in &updates {
                let want = previous.1.checked_add(1);
                if update.salt != previous.0 || Some(update.version) != want {
                    return Some(Verdict::Broken(format!(
                        "updated to salt {} version {} from salt {} version {} (first update to \
                         version {})",
                        update.salt, update.version, previous.0, previous.1, first.version
                    )));
                }
                previous = (update.salt, update.version);
            }
            Some(Verdict::Holds)
        },
    },
    // Migration is signed by the sender's own original key.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1113.md#L65-L71>
    check! {
        id: "TEMPO-ACCOUNT-UPGRADE-ROOT",
        over: |step: &AccountStep| upgrades(step),
        judge: |s, e| {
            let tx = s.tx.as_ref()?;
            let root = Key {
                role: Role::Sender,
                account: e.account,
            };
            ensure!(
                tx.sender == e.account
                    && tx.authority.keys.contains(&root)
                    && tx.authority.grant.is_none(),
                "in a transaction from {} signed by {:?}, {:?}, grant {:?}",
                tx.sender,
                tx.authority.keys,
                tx.authority.quorums.iter().map(ToString::to_string).collect::<Vec<_>>(),
                tx.authority.grant
            )
        },
    },
    // Only an account without a commitment migrates.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1113.md#L259>
    check! {
        id: "TEMPO-ACCOUNT-UPGRADE-FRESH",
        over: |step: &AccountStep| upgrades(step),
        judge: |s, e| {
            let pre = s.pre.of.get(&e.account)?;
            ensure!(pre.is_zero(), "already had commitment {pre}")
        },
    },
    // Migration stores the version-1 configuration's hash under the upgrade salt.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1113.md#L259>
    check! {
        id: "TEMPO-ACCOUNT-UPGRADE-CONFIG",
        over: |step: &AccountStep| upgrades(step),
        judge: |s, e| {
            let post = s.post.of.get(&e.account)?;
            let config = ConfigurableAccountConfig {
                salt: e.salt,
                version: 1,
                threshold: e.threshold,
                owners: e.owners.clone(),
            };
            let want = spec::commitment(&config);
            ensure!(
                e.salt == spec::upgrade_salt(e.account)
                    && want == Some(e.commitment)
                    && *post == e.commitment,
                "salt {}, event commitment {}, stored {post}, the version-1 configuration hashes \
                 to {want:?}",
                e.salt,
                e.commitment
            )
        },
    },
    // An ordinary signature is never authority for an account with a commitment.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1113.md#L263>
    check! {
        id: "TEMPO-ACCOUNT-ROOT-KEY-RETIRED",
        over: |step: &AccountStep| {
            step.tx
                .iter()
                .filter(|tx| tx.authority.active)
                .flat_map(|tx| tx.authority.keys.iter())
        },
        judge: |s, key| {
            let pre = s.pre.of.get(&key.account)?;
            ensure!(pre.is_zero(), "signed with an ordinary key, its commitment is {pre}")
        },
    },
    // Before T14, no configurable signatures or key-type-3 grants.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1111.md#L176>
    check! {
        id: "TEMPO-ACCOUNT-FORK-GATED",
        over: |step: &AccountStep| {
            step.tx.iter().filter(|tx| !tx.authority.active).map(|tx| tx.sender)
        },
        judge: |s, _| {
            let authority = &s.tx.as_ref()?.authority;
            let grant = authority.grant.map(|g| g.key_type);
            ensure!(
                authority.quorums.is_empty() && grant != Some(CONFIGURABLE_KEY_TYPE),
                "before T14 carries {} configurable-account signatures, grant key type {grant:?}",
                authority.quorums.len()
            )
        },
    },
];

impl StepChecked<Option<Tx>> for Commitments {
    const STEP_CHECKS: &'static [Check<Step<Self, Option<Tx>>>] = STEP_CHECKS;
}

/// A transaction's effect on the leaves of the accounts it changed or named.
pub const LEAF_CHECKS: &[Check<Leaves>] = &[
    // An account with a commitment has the 0xef marker as code.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L480>
    check! {
        id: "TEMPO-ACCOUNT-MARKER",
        over: |l: &Leaves| l.of.keys(),
        judge: |l, account| {
            let (_, post) = l.of.get(*account)?;
            if post.commitment.is_zero() {
                return None;
            }
            ensure!(
                post.code_hash == MARKER_CODE_HASH,
                "has commitment {} and code hash {}",
                post.commitment,
                post.code_hash
            )
        },
    },
    // Only migration installs the marker.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1107.md#L481>
    check! {
        id: "TEMPO-ACCOUNT-MARKER-INSTALL",
        over: |l: &Leaves| l.of.keys(),
        judge: |l, account| {
            let (pre, post) = l.of.get(*account)?;
            let installed = pre.code_hash != MARKER_CODE_HASH && post.code_hash == MARKER_CODE_HASH;
            if !installed || is_tip20(**account) {
                return None;
            }
            ensure!(
                pre.code_hash == KECCAK256_EMPTY
                    && pre.commitment.is_zero()
                    && !post.commitment.is_zero(),
                "marker installed over code hash {} with commitment {} -> {}",
                pre.code_hash,
                pre.commitment,
                post.commitment
            )
        },
    },
    // A key-type-3 grant names a delegate other than the parent, without other code.
    // <https://github.com/tempoxyz/tempo/blob/74c38cd1d7ae26d9ae28799e036f3887038b0c7d/tips/tip-1111.md#L175>
    check! {
        id: "TEMPO-ACCOUNT-GRANT-DELEGATE",
        over: |l: &Leaves| {
            l.tx.authority
                .grant
                .filter(|g| g.key_type == CONFIGURABLE_KEY_TYPE)
                .map(|g| g.key_id)
        },
        judge: |l, delegate| {
            let (pre, _) = l.of.get(delegate)?;
            ensure!(
                *delegate != l.tx.sender
                    && (pre.code_hash == KECCAK256_EMPTY || pre.code_hash == MARKER_CODE_HASH),
                "granted by {} to a delegate with code hash {}",
                l.tx.sender,
                pre.code_hash
            )
        },
    },
];

impl Checked for Leaves {
    const CHECKS: &'static [Check<Self>] = LEAF_CHECKS;
}

/// `account`'s commitment before and after the step, when both reads answered.
fn commitments(s: &AccountStep, account: &Address) -> Option<(B256, B256)> {
    Some((*s.pre.of.get(account)?, *s.post.of.get(account)?))
}

/// The quorums of the step's transaction.
fn quorums(step: &AccountStep) -> impl Iterator<Item = &Quorum> {
    step.tx.iter().flat_map(|tx| tx.authority.quorums.iter())
}

/// The step's `AccountUpgraded` events.
fn upgrades(step: &AccountStep) -> Vec<Upgrade> {
    step.events::<AccountUpgraded>(step.post.precompile)
        .into_iter()
        .map(Upgrade)
        .collect()
}

/// An `AccountUpgraded` event, shown by its account.
struct Upgrade(AccountUpgraded);

impl std::ops::Deref for Upgrade {
    type Target = AccountUpgraded;

    fn deref(&self) -> &AccountUpgraded {
        &self.0
    }
}

impl std::fmt::Display for Upgrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "migration of {}", self.0.account)
    }
}

/// The step's `ConfigurableAccountConfigUpdated` events for `account`, in order.
fn updates_of(s: &AccountStep, account: Address) -> Vec<ConfigurableAccountConfigUpdated> {
    s.events::<ConfigurableAccountConfigUpdated>(s.post.precompile)
        .into_iter()
        .filter(|e| e.account == account)
        .collect()
}

/// The configurations the step's events wrote for `account`, in order.
fn configs_written(s: &AccountStep, account: Address) -> Vec<ConfigurableAccountConfig> {
    let precompile = s.post.precompile;
    s.logs_from(precompile)
        .filter_map(|log| {
            if let Ok(e) = AccountUpgraded::decode_log_data(&log.data) {
                return (e.account == account).then_some(ConfigurableAccountConfig {
                    salt: e.salt,
                    version: 1,
                    threshold: e.threshold,
                    owners: e.owners,
                });
            }
            let e = ConfigurableAccountConfigUpdated::decode_log_data(&log.data).ok()?;
            (e.account == account).then_some(ConfigurableAccountConfig {
                salt: e.salt,
                version: e.version,
                threshold: e.threshold,
                owners: e.owners,
            })
        })
        .collect()
}

/// Why `q`'s approvals do not make a quorum of its configuration, `None` when they do.
fn quorum_weight(q: &Quorum) -> Option<String> {
    let mut total = 0u32;
    let mut last: Option<Address> = None;
    let threshold = u32::from(q.config.threshold);
    for (index, approval) in q.approvals.iter().enumerate() {
        let Some(owner) = approval.owner else {
            return Some(format!("approval {index} recovers to no signer"));
        };
        if last.is_some_and(|last| last >= owner) {
            return Some(format!(
                "approval {index} by {owner} is out of ascending order"
            ));
        }
        last = Some(owner);
        let Some(weight) = q
            .config
            .owners
            .iter()
            .find(|o| o.owner == owner)
            .map(|o| o.weight)
        else {
            return Some(format!("approval {index} by {owner}, not an owner"));
        };
        if total >= threshold {
            return Some(format!(
                "approval {index} follows the approval that reached threshold {threshold}"
            ));
        }
        total += u32::from(weight);
    }
    (total < threshold).then(|| format!("approvals weigh {total}, the threshold is {threshold}"))
}

/// Whether `account` is in the TIP-20 token address space.
fn is_tip20(account: Address) -> bool {
    account
        .as_slice()
        .starts_with(&[0x20, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}
