//! Configurable account invariants (TIP-1107, TIP-1111, TIP-1113).

use alloy_primitives::{Address, B256, KECCAK256_EMPTY};
use alloy_sol_types::SolEvent;
use invariants_core::{check, ensure};
use tempo_contracts::precompiles::{
    ACCOUNT_KEYCHAIN_ADDRESS,
    IAccountKeychain::{AdminKeyAuthorized, KeyAuthorized, KeyRevoked, SpendingLimitUpdated},
};
use tempo_primitives::is_tip20_prefix;

use super::{
    AccountUpgraded, Commitments, ConfigurableAccountConfig, ConfigurableAccountConfigUpdated, Key,
    LeafChange, Leaves, Quorum, Role,
    spec::{self, CONFIGURABLE_KEY_TYPE, MARKER_CODE_HASH, MAX_APPROVAL_BYTES, MAX_APPROVALS},
};
use crate::{Check, Checked, Step, StepChecked, Tx, Verdict};

/// The configurable account precompile's views answer. Counted by runners, not judged here.
pub const VIEW: &str = "TEMPO-ACCOUNT-VIEW";

/// Checks of a step against its signatures and events.
pub const STEP_CHECKS: &[Check<AccountStep>] = &[
    // A commitment is never cleared.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L508>
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
    // Only registration, the account's own owner update or its migration changes its commitment.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L508>
    check! {
        id: "TEMPO-ACCOUNT-COMMITMENT-BY-SELF",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let (pre, post) = commitments(s, account)?;
            let tx = s.tx.as_ref()?;
            if pre == post {
                return None;
            }
            let registered = pre.is_zero()
                && tx
                    .authority
                    .quorums_of(**account)
                    .any(|q| q.config.version == 0);
            let own = tx.sender == **account && !own_writes(s, **account).is_empty();
            ensure!(
                registered || own,
                "commitment {pre} -> {post} in a transaction from {} that neither registers,                  updates nor migrates it",
                tx.sender
            )
        },
    },
    // A changed commitment is announced, registration included.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L465>
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L509-L510>
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L522>
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
    // Every configurable signer has a commitment afterwards.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L505>
    check! {
        id: "TEMPO-ACCOUNT-SIGNER-REGISTERED",
        over: |step: &AccountStep| quorums(step),
        judge: |s, q| {
            let post = s.post.of.get(&q.account)?;
            ensure!(!post.is_zero(), "has no commitment after the transaction")
        },
    },
    // A quorum matches its account's commitment, or derives its address.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L519>
    check! {
        id: "TEMPO-ACCOUNT-QUORUM-COMMITMENT",
        over: |step: &AccountStep| quorums(step),
        judge: |s, q| {
            let pre = *s.pre.of.get(&q.account)?;
            let config = &q.config;
            if !pre.is_zero() {
                let hash = spec::commitment(config);
                return ensure!(
                    hash == Some(pre),
                    "carries a configuration hashing to {hash:?}, the commitment is {pre}"
                );
            }
            let derived = spec::derived_address(config);
            let listed = config.owners.iter().any(|o| o.owner == q.account);
            // Without a later owner update, registration stores the configuration that signed.
            let stored = s
                .post
                .of
                .get(&q.account)
                .filter(|_| own_writes(s, q.account).is_empty());
            let other = stored.filter(|post| spec::commitment(config) != Some(**post));
            ensure!(
                config.version == 0 && derived == Some(q.account) && !listed && other.is_none(),
                "registers with a version-{} configuration deriving {derived:?}{}{}",
                config.version,
                if listed { " that lists the account as an owner" } else { "" },
                other.map_or_else(String::new, |post| format!(", storing commitment {post}"))
            )
        },
    },
    // The transaction's own configurable signature names its sender.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L338>
    check! {
        id: "TEMPO-ACCOUNT-SENDER-QUORUM",
        over: |step: &AccountStep| quorums(step).filter(|q| q.role == Role::Sender),
        judge: |s, q| {
            let sender = s.tx.as_ref()?.sender;
            ensure!(q.account == sender, "authorizes a transaction from {sender}")
        },
    },
    // Approvals are ascending owners that first reach the threshold at the last one.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L519-L520>
    check! {
        id: "TEMPO-ACCOUNT-QUORUM-WEIGHT",
        over: |step: &AccountStep| quorums(step),
        judge: |_, q| Some(quorum_weight(q).map_or(Verdict::Holds, Verdict::Broken)),
    },
    // 1 to 8 approvals, each at most 2,049 bytes.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L521>
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L526>
    check! {
        id: "TEMPO-ACCOUNT-UPDATE-QUORUM",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let updates = updates_of(s, **account)?;
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L527>
    check! {
        id: "TEMPO-ACCOUNT-UPDATE-VERSION",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let updates = updates_of(s, **account)?;
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
    // Migration is signed by the sender's own original key, without an authorization list.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1113.md#L65-L71>
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
                    && !tx.authority.authorization_list,
                "in a transaction from {} signed by {:?}, {:?}{}",
                tx.sender,
                tx.authority.keys,
                tx.authority.quorums.iter().map(ToString::to_string).collect::<Vec<_>>(),
                if tx.authority.authorization_list { ", with an authorization list" } else { "" }
            )
        },
    },
    // Only an account without a commitment migrates.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1113.md#L260>
    check! {
        id: "TEMPO-ACCOUNT-UPGRADE-FRESH",
        over: |step: &AccountStep| upgrades(step),
        judge: |s, e| {
            let pre = s.pre.of.get(&e.account)?;
            ensure!(pre.is_zero(), "already had commitment {pre}")
        },
    },
    // Migration stores the version-1 configuration's hash under the upgrade salt.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1113.md#L260>
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1113.md#L264>
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L178>
    check! {
        id: "TEMPO-ACCOUNT-FORK-GATED",
        over: |step: &AccountStep| {
            step.tx.iter().filter(|tx| !tx.authority.active).map(|tx| tx.sender)
        },
        judge: |s, _| {
            let authority = &s.tx.as_ref()?.authority;
            let grant = authority.grant.map(|g| g.key_type);
            let granted = s
                .events::<KeyAuthorized>(ACCOUNT_KEYCHAIN_ADDRESS)
                .into_iter()
                .filter(|e| e.signatureType == CONFIGURABLE_KEY_TYPE)
                .count();
            ensure!(
                authority.quorums.is_empty() && grant != Some(CONFIGURABLE_KEY_TYPE) && granted == 0,
                "before T14 carries {} configurable-account signatures, grant key type {grant:?}, \
                 {granted} key-type-3 grants",
                authority.quorums.len()
            )
        },
    },
    // A failed transaction keeps no owner update or migration, only registration.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L528>
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1113.md#L261>
    check! {
        id: "TEMPO-ACCOUNT-FAILED-ROLLBACK",
        over: |step: &AccountStep| step.post.of.keys(),
        judge: |s, account| {
            let tx = s.tx.as_ref()?;
            if tx.success {
                return None;
            }
            let (pre, post) = commitments(s, account)?;
            let writes = own_writes(s, **account).len();
            let registered = pre.is_zero()
                && tx.authority.quorums_of(**account).any(|q| {
                    q.config.version == 0 && spec::commitment(&q.config) == Some(post)
                });
            ensure!(
                writes == 0 && (pre == post || registered),
                "failed, yet commitment {pre} -> {post} with {writes} updates or migrations kept"
            )
        },
    },
    // A registering account's address is outside the reserved address spaces.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L501>
    check! {
        id: "TEMPO-ACCOUNT-DERIVED-ADDRESS",
        over: |step: &AccountStep| {
            quorums(step)
                .filter(|q| q.config.version == 0)
                .filter(|q| step.pre.of.get(&q.account).is_some_and(|c| c.is_zero()))
        },
        judge: |_, q| {
            Some(match spec::reserved(q.account) {
                None => Verdict::Holds,
                Some(space) => Verdict::Broken(format!("registers at {space}")),
            })
        },
    },
    // An inline grant is signed by its parent's own key or quorum, or by an admin key the
    // parent already had that also signs the transaction.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L61>
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L175>
    check! {
        id: "TEMPO-ACCOUNT-GRANT-SIGNER",
        over: |step: &AccountStep| {
            step.tx
                .iter()
                .filter(|tx| tx.authority.active && tx.authority.grant.is_some())
                .map(|tx| tx.sender)
        },
        judge: |s, sender| {
            let tx = s.tx.as_ref()?;
            let signers: Vec<Address> = tx.authority.key_authorization_signers().collect();
            if signers.is_empty() {
                return Some(Verdict::Broken(
                    "carries a grant whose signature recovers to no signer".to_string(),
                ));
            }
            let mut unknown = false;
            for signer in signers {
                if signer == *sender {
                    continue;
                }
                let by_quorum = tx
                    .authority
                    .quorums
                    .iter()
                    .any(|q| q.role == Role::KeyAuthorization && q.account == signer);
                let signs_tx = tx.authority.keys.contains(&Key {
                    role: Role::AccessKey,
                    account: signer,
                });
                if by_quorum || !signs_tx {
                    return Some(Verdict::Broken(format!(
                        "grant signed by {signer}, not the parent or its acting admin key"
                    )));
                }
                match s.pre.admins.get(&(*sender, signer)) {
                    Some(true) => {}
                    Some(false) => {
                        return Some(Verdict::Broken(format!(
                            "grant signed by {signer}, not an admin key"
                        )));
                    }
                    None => unknown = true,
                }
            }
            (!unknown).then_some(Verdict::Holds)
        },
    },
    // A key-type-3 grant is used only by its delegate's quorum, never by an ordinary access key.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L177>
    check! {
        id: "TEMPO-ACCOUNT-GRANT-TYPE",
        over: |step: &AccountStep| {
            step.tx
                .iter()
                .filter(|tx| tx.authority.active)
                .filter_map(|tx| tx.authority.grant)
                .filter(|g| g.key_type == CONFIGURABLE_KEY_TYPE)
                .map(|g| g.key_id)
        },
        judge: |s, key_id| {
            let tx = s.tx.as_ref()?;
            let ordinary = tx.authority.keys.contains(&Key {
                role: Role::AccessKey,
                account: *key_id,
            });
            ensure!(!ordinary, "a key-type-3 grant used by an ordinary access-key signature")
        },
    },
    // An access key signs as the key type its grant stores, except that a configurable
    // signature may use an ordinary grant whose key ID already has a commitment.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L184>
    check! {
        id: "TEMPO-ACCOUNT-ACCESS-KEY-TYPE",
        over: |step: &AccountStep| {
            step.tx.iter().filter(|tx| tx.authority.active).map(|tx| tx.sender)
        },
        judge: |s, sender| {
            let tx = s.tx.as_ref()?;
            let inline = tx.authority.grant.map(|g| g.key_id);
            let mut judged = false;
            for (key, configurable) in tx.authority.access_keys() {
                // A grant made in the same transaction is judged by TEMPO-ACCOUNT-GRANT-TYPE.
                if inline == Some(key) {
                    continue;
                }
                let Some(info) = s.pre.keys.get(&(*sender, key)) else {
                    continue;
                };
                if info.keyId != key || info.isRevoked {
                    continue;
                }
                let stored = info.signatureType as u8;
                let ok = if configurable {
                    let Some(commitment) = s.pre.of.get(&key) else {
                        continue;
                    };
                    stored == CONFIGURABLE_KEY_TYPE || !commitment.is_zero()
                } else {
                    stored != CONFIGURABLE_KEY_TYPE
                };
                if !ok {
                    return Some(Verdict::Broken(format!(
                        "access key {key} signs {} under a grant of key type {stored}",
                        if configurable { "as a configurable account" } else { "ordinarily" }
                    )));
                }
                judged = true;
            }
            judged.then_some(Verdict::Holds)
        },
    },
    // Grants change only in the parent's own transactions, by its key or quorum, and never as an admin key.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L175-L176>
    check! {
        id: "TEMPO-ACCOUNT-GRANT-AUTHORITY",
        over: |step: &AccountStep| grant_changes(step),
        judge: |s, change| {
            let tx = s.tx.as_ref()?;
            if !tx.authority.active {
                return None;
            }
            if change.account != tx.sender {
                return Some(Verdict::Broken(format!(
                    "changed in a transaction from {}",
                    tx.sender
                )));
            }
            if change.kind == GrantKind::Admin {
                return Some(Verdict::Broken("authorized an admin key".to_string()));
            }
            let by_access_key = tx.authority.keys.iter().any(|k| k.role == Role::AccessKey)
                || tx.authority.quorums.iter().any(|q| q.role == Role::AccessKey);
            let inline = change.kind == GrantKind::Authorized
                && tx.authority.grant.is_some_and(|g| g.key_id == change.key);
            ensure!(
                !by_access_key || inline,
                "changed in a transaction an access key signed"
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
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L513>
    check! {
        id: "TEMPO-ACCOUNT-MARKER",
        over: |l: &Leaves| l.of.keys(),
        judge: |l, account| {
            let post = l.of.get(*account)?.after;
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
    // Only registration and migration install the marker.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L514>
    check! {
        id: "TEMPO-ACCOUNT-MARKER-INSTALL",
        over: |l: &Leaves| l.of.keys(),
        judge: |l, account| {
            let LeafChange {
                before: pre,
                after: post,
            } = *l.of.get(*account)?;
            let installed = pre.code_hash != MARKER_CODE_HASH && post.code_hash == MARKER_CODE_HASH;
            if !installed || is_tip20_prefix(**account) {
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
    // A key-type-3 grant names a delegate other than the parent, outside the reserved spaces, without other code.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1111.md#L177>
    check! {
        id: "TEMPO-ACCOUNT-GRANT-DELEGATE",
        over: |l: &Leaves| l.delegates.iter(),
        judge: |l, grant| {
            let delegate = &grant.delegate;
            let pre = l.of.get(delegate)?.before;
            let reserved = spec::reserved(*delegate);
            ensure!(
                *delegate != grant.parent
                    && reserved.is_none()
                    && (pre.code_hash == KECCAK256_EMPTY || pre.code_hash == MARKER_CODE_HASH),
                "granted by {} to a delegate with code hash {}{}",
                grant.parent,
                pre.code_hash,
                reserved.map_or_else(String::new, |space| format!(" at {space}"))
            )
        },
    },
    // Nothing changes or clears the marker.
    // <https://github.com/tempoxyz/tempo/blob/84040258b7d8696ff7c84cfb9622c5841e515bd4/tips/tip-1107.md#L514>
    check! {
        id: "TEMPO-ACCOUNT-MARKER-KEPT",
        over: |l: &Leaves| l.of.keys(),
        judge: |l, account| {
            let LeafChange { before, after } = *l.of.get(*account)?;
            if before.code_hash != MARKER_CODE_HASH {
                return None;
            }
            ensure!(
                after.code_hash == MARKER_CODE_HASH,
                "marker replaced by code hash {}",
                after.code_hash
            )
        },
    },
];

type AccountStep = Step<Commitments, Option<Tx>>;

impl Checked for Leaves {
    const CHECKS: &'static [Check<Self>] = LEAF_CHECKS;
}

/// `account`'s commitment before and after the step, when both reads answered.
fn commitments(s: &AccountStep, account: &Address) -> Option<(B256, B256)> {
    Some((*s.pre.of.get(account)?, *s.post.of.get(account)?))
}

/// The step's owner updates (version above 0) and migrations of `account`.
fn own_writes(s: &AccountStep, account: Address) -> Vec<u64> {
    let precompile = s.post.precompile;
    let updates = s
        .events::<ConfigurableAccountConfigUpdated>(precompile)
        .into_iter()
        .filter(|e| e.account == account && e.version != 0)
        .map(|e| e.version);
    let upgrades = s
        .events::<AccountUpgraded>(precompile)
        .into_iter()
        .filter(|e| e.account == account)
        .map(|_| 1);
    updates.chain(upgrades).collect()
}

/// What a keychain event did to a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantKind {
    Authorized,
    Admin,
    Revoked,
    Limit,
}

/// A grant a keychain event changed.
struct GrantChange {
    kind: GrantKind,
    account: Address,
    key: Address,
}

impl std::fmt::Display for GrantChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} grant of key {} for {}",
            self.kind, self.key, self.account
        )
    }
}

/// The grants the step's keychain events changed.
fn grant_changes(step: &AccountStep) -> Vec<GrantChange> {
    let keychain = ACCOUNT_KEYCHAIN_ADDRESS;
    let change = |kind, account, key| GrantChange { kind, account, key };
    let mut changes: Vec<GrantChange> = step
        .events::<KeyAuthorized>(keychain)
        .into_iter()
        .map(|e| change(GrantKind::Authorized, e.account, e.publicKey))
        .collect();
    changes.extend(
        step.events::<AdminKeyAuthorized>(keychain)
            .into_iter()
            .map(|e| change(GrantKind::Admin, e.account, e.publicKey)),
    );
    changes.extend(
        step.events::<KeyRevoked>(keychain)
            .into_iter()
            .map(|e| change(GrantKind::Revoked, e.account, e.publicKey)),
    );
    changes.extend(
        step.events::<SpendingLimitUpdated>(keychain)
            .into_iter()
            .map(|e| change(GrantKind::Limit, e.account, e.publicKey)),
    );
    changes
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

/// The step's owner-update events for `account`, in order; `None` when its prior commitment is unknown.
fn updates_of(s: &AccountStep, account: Address) -> Option<Vec<ConfigurableAccountConfigUpdated>> {
    // Registration's version-0 event, for an account without a commitment, is not an owner update.
    let unregistered = s.pre.of.get(&account)?.is_zero();
    Some(
        s.events::<ConfigurableAccountConfigUpdated>(s.post.precompile)
            .into_iter()
            .filter(|e| e.account == account && !(unregistered && e.version == 0))
            .collect(),
    )
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
