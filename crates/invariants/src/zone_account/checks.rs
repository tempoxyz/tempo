//! Zone configurable account invariants (TIP-1154).

use alloy_primitives::KECCAK256_EMPTY;
use invariants_core::{check, ensure};
use tempo_contracts::zones::TempoState::TempoBlockFinalized;

use super::{Mirror, ZoneLeaves, ZoneStep, reserved};
use crate::{
    Check, Checked, StepChecked, Tx, Verdict,
    configurable_account::{
        Quorum,
        spec::{self, MARKER_CODE_HASH},
    },
};

/// The zone's and Tempo's views answer. Counted by runners, not judged here.
pub const VIEW: &str = "TEMPO-ZONE-ACCOUNT-VIEW";

/// A zone state against Tempo at its anchor.
pub const CHECKS: &[Check<Mirror>] = &[
    // The zone's anchor is a canonical Tempo block.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L29>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-ANCHOR-CANONICAL",
        over: |m: &Mirror| [m.zone.anchor],
        judge: |m, anchor| {
            let hash = m.tempo.as_ref()?.hash?;
            ensure!(
                hash == anchor.hash,
                "is not Tempo's block {}, whose hash is {hash}",
                anchor.number
            )
        },
    },
    // Every commitment the zone reads is Tempo's commitment at the anchor.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L182>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        over: |m: &Mirror| m.zone.of.keys(),
        judge: |m, account| {
            if m.ineligible(**account).is_some() {
                return None;
            }
            let (zone, tempo) = (m.zone.of[*account], m.tempo(**account)?);
            ensure!(
                zone == tempo,
                "the zone reads commitment {zone}, Tempo holds {tempo} at {}",
                m.zone.anchor
            )
        },
    },
    // Reserved addresses and accounts with zone code read nothing from Tempo.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L59>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-INELIGIBLE",
        over: |m: &Mirror| m.zone.of.keys(),
        judge: |m, account| {
            let why = m.ineligible(**account)?;
            let zone = m.zone.of[*account];
            ensure!(zone.is_zero(), "is {why}, yet the zone reads commitment {zone}")
        },
    },
    // An eligible account answers as the account marker exactly when Tempo holds a commitment for
    // it at the anchor.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L185>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L76>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-MARKER-CALL",
        over: |m: &Mirror| m.zone.marked.keys(),
        judge: |m, account| {
            let (marked, tempo) = (m.zone.marked[*account], m.tempo(**account)?);
            ensure!(
                marked != tempo.is_zero(),
                "{} as the account marker, Tempo's commitment at {} is {tempo}",
                if marked { "answers" } else { "does not answer" },
                m.zone.anchor
            )
        },
    },
];

/// A zone transaction or block against its events and signatures.
pub const STEP_CHECKS: &[Check<ZoneStep>] = &[
    // Only a system transaction moves the anchor, forward, to the last Tempo block it finalized.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L58>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L163>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE",
        over: |step: &ZoneStep| [step.post.zone.anchor],
        judge: |s, post| {
            let pre = s.pre.zone.anchor;
            let finalized = s.events::<TempoBlockFinalized>(s.post.zone.tempo_state);
            let Some(last) = finalized.last() else {
                return ensure!(pre == *post, "moved from {pre} without a TempoBlockFinalized event");
            };
            let ascending = finalized[0].blockNumber > pre.number
                && finalized
                    .windows(2)
                    .all(|pair| pair[0].blockNumber < pair[1].blockNumber);
            ensure!(
                s.tx.is_none()
                    && ascending
                    && last.blockNumber == post.number
                    && last.blockHash == post.hash,
                "follows {pre} after {} TempoBlockFinalized events, the last for block {} ({}){}",
                finalized.len(),
                last.blockNumber,
                last.blockHash,
                if s.tx.is_some() { ", in a user transaction" } else { "" }
            )
        },
    },
    // While the anchor stays, no zone step changes a commitment or the marker.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L183>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L113>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-COMMITMENT-ANCHORED",
        over: |step: &ZoneStep| step.post.zone.of.keys(),
        judge: |s, account| {
            let (pre, post) = (s.pre.zone.of.get(*account)?, s.post.zone.of.get(*account)?);
            if s.pre.zone.anchor != s.post.zone.anchor {
                return None;
            }
            let marker = (s.pre.zone.marked.get(*account), s.post.zone.marked.get(*account));
            let marker_kept = !matches!(marker, (Some(before), Some(after)) if before != after);
            ensure!(
                pre == post && marker_kept,
                "commitment {pre} -> {post}, marker {marker:?}, while the zone stayed at {}",
                s.post.zone.anchor
            )
        },
    },
    // A zone never writes a commitment: the precompile emits no configuration event, even when
    // the transaction fails.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L82-L85>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-NO-WRITE",
        over: |step: &ZoneStep| [step.post.zone.precompile],
        judge: |s, precompile| {
            let logs = s.logs_from(*precompile).count();
            ensure!(logs == 0, "emitted {logs} configuration events on a zone")
        },
    },
    // No zone transaction carries an authorization list, so no zone account has a delegation.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L59>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST",
        over: |step: &ZoneStep| step.tx.iter().map(|tx| tx.sender),
        judge: |s, _| {
            ensure!(
                !s.tx.as_ref()?.authority.authorization_list,
                "sent a zone transaction with an authorization list"
            )
        },
    },
    // A configurable-account signature matches Tempo's commitment at the anchor, or derives its
    // unregistered account at version zero.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L68-L69>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L186>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT",
        over: |step: &ZoneStep| quorums(step),
        judge: |s, q| {
            let at = at_tx(s)?;
            if let Some(why) = at.ineligible(q.account) {
                return Some(Verdict::Broken(format!("signs for {why}")));
            }
            let tempo = at.tempo(q.account)?;
            let config = &q.config;
            if !tempo.is_zero() {
                let hash = spec::commitment(config);
                return ensure!(
                    hash == Some(tempo),
                    "carries a configuration hashing to {hash:?}, Tempo's commitment at {} is {tempo}",
                    at.zone.anchor
                );
            }
            let derived = spec::derived_address(config);
            let listed = config.owners.iter().any(|o| o.owner == q.account);
            ensure!(
                config.version == 0 && derived == Some(q.account) && !listed,
                "is unregistered on Tempo at {}, signs with a version-{} configuration deriving \
                 {derived:?}{}",
                at.zone.anchor,
                config.version,
                if listed { " that lists the account as an owner" } else { "" }
            )
        },
    },
    // An ordinary signature never authorizes for an account with a Tempo commitment at the
    // anchor.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L184>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-ROOT-KEY-RETIRED",
        over: |step: &ZoneStep| {
            step.tx
                .iter()
                .filter(|tx| tx.authority.active)
                .flat_map(|tx| tx.authority.keys.iter())
        },
        judge: |s, key| {
            let at = at_tx(s)?;
            if at.ineligible(key.account).is_some() {
                return None;
            }
            let tempo = at.tempo(key.account)?;
            ensure!(
                tempo.is_zero(),
                "signed with an ordinary key, Tempo's commitment at {} is {tempo}",
                at.zone.anchor
            )
        },
    },
    // An account unregistered on Tempo that signs a zone transaction is still unregistered after.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L181>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-SIGNER-UNREGISTERED",
        over: |step: &ZoneStep| quorums(step),
        judge: |s, q| {
            let at = at_tx(s)?;
            if !at.tempo(q.account)?.is_zero() {
                return None;
            }
            let post = s.post.zone.of.get(&q.account)?;
            ensure!(
                post.is_zero(),
                "is unregistered on Tempo at {}, yet the zone reads commitment {post} after it signed",
                at.zone.anchor
            )
        },
    },
];

/// The zone's stored leaves after a step, beside what it serves for them.
pub const LEAF_CHECKS: &[Check<ZoneLeaves>] = &[
    // Zone state never stores a commitment or the account marker.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L86>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
        over: |l: &ZoneLeaves| l.of.keys(),
        judge: |l, account| {
            let stored = l.of.get(*account)?.stored;
            let marker = stored.code_hash == MARKER_CODE_HASH && reserved(**account).is_none();
            ensure!(
                stored.commitment.is_zero() && !marker,
                "zone state stores commitment {} and code hash {}",
                stored.commitment,
                stored.code_hash
            )
        },
    },
    // The zone serves the code execution sees: the marker for an eligible account without code
    // whose Tempo commitment at the anchor is nonzero, its stored code otherwise.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L152>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L78>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
        over: |l: &ZoneLeaves| l.of.keys(),
        judge: |l, account| {
            let leaf = l.of.get(*account)?;
            let (served, stored) = (leaf.served?, leaf.stored.code_hash);
            let overlaid = l.active && reserved(**account).is_none() && stored == KECCAK256_EMPTY;
            let want = match overlaid {
                true if leaf.tempo?.is_zero() => KECCAK256_EMPTY,
                true => MARKER_CODE_HASH,
                false => stored,
            };
            ensure!(
                served == want,
                "serves code hash {served}, not {want} (stored code hash {stored}, Tempo \
                 commitment {:?})",
                leaf.tempo
            )
        },
    },
];

impl Checked for Mirror {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Option<Tx>> for Mirror {
    const STEP_CHECKS: &'static [Check<ZoneStep>] = STEP_CHECKS;
}

impl Checked for ZoneLeaves {
    const CHECKS: &'static [Check<Self>] = LEAF_CHECKS;
}

/// The quorums of the step's transaction.
fn quorums(step: &ZoneStep) -> impl Iterator<Item = &Quorum> {
    step.tx.iter().flat_map(|tx| tx.authority.quorums.iter())
}

/// The mirror a transaction's authority is judged against: the one before it, when the step kept
/// the anchor (a step that moved it is judged by ANCHOR-ADVANCE).
fn at_tx(s: &ZoneStep) -> Option<&Mirror> {
    (s.pre.zone.anchor == s.post.zone.anchor).then_some(&s.pre)
}
