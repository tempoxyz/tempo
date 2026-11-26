//! Zone configurable account invariants (TIP-1154).

use std::fmt;

use alloy_primitives::{Address, KECCAK256_EMPTY};
use invariants_core::{check, ensure};
use tempo_contracts::{precompiles::ITIP20::permitCall, zones::TempoState::TempoBlockFinalized};
use tempo_primitives::is_tip20_prefix;

use super::{Mirror, ZoneLeaves, ZoneStep};
use crate::{
    Check, Checked, Ran, StepChecked, TempoHardfork, Verdict,
    configurable_account::{
        Quorum,
        spec::{self, MARKER_CODE_HASH},
    },
};

/// The zone's and Tempo's views answer. Counted by runners, not judged here.
pub const VIEW: &str = "TEMPO-ZONE-ACCOUNT-VIEW";

/// A zone state against Tempo at its anchor.
pub const CHECKS: &[Check<Mirror>] = &[
    // Every commitment the zone reads is Tempo's commitment at the anchor.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L182>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
        doc: "Every commitment the zone reads is Tempo's at the zone's anchor.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
        doc: "A reserved address or an account with zone code reads no commitment from Tempo.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
        doc: "An eligible account answers as the account marker exactly when Tempo holds a commitment for it at the anchor.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
        doc: "Only a system transaction moves the anchor, forward, to the last Tempo block it finalized.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
                s.ran.tx().is_none()
                    && ascending
                    && last.blockNumber == post.number
                    && last.blockHash == post.hash,
                "follows {pre} after {} TempoBlockFinalized events, the last for block {} ({}){}",
                finalized.len(),
                last.blockNumber,
                last.blockHash,
                if s.ran.tx().is_some() { ", in a user transaction" } else { "" }
            )
        },
    },
    // While the anchor stays, no zone step changes a commitment or the marker.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L183>
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L113>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-COMMITMENT-ANCHORED",
        doc: "While the anchor stays, no step changes a commitment or the account marker.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
        doc: "A zone never writes a commitment: the precompile emits no configuration event.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |step: &ZoneStep| [step.post.zone.precompile],
        judge: |s, precompile| {
            let logs = s.logs_from(*precompile).count();
            ensure!(logs == 0, "emitted {logs} configuration events on a zone")
        },
    },
    // A committed TIP-20 `permit` is signed by its owner's root key, which Tempo's commitment at
    // the anchor must not have retired.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L60>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-PERMIT-RETIRED",
        doc: "A permit's owner has no Tempo commitment at the anchor, whose root key it would have retired.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |step: &ZoneStep| permits(step),
        judge: |s, permit| {
            let Permit { token, owner } = permit;
            let at = at_tx(s)?;
            // The zone reads no commitment for an ineligible owner, so its root key is live.
            if at.ineligible(*owner).is_some() {
                return None;
            }
            let tempo = at.tempo(*owner)?;
            ensure!(
                tempo.is_zero(),
                "{token} accepted a permit signed by the root key of {owner}, Tempo's commitment \
                 at {} is {tempo}",
                s.pre.zone.anchor
            )
        },
    },
    // No zone transaction carries an authorization list, so no zone account has a delegation.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L59>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST",
        doc: "No zone transaction carries an authorization list.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |step: &ZoneStep| step.ran.tx().into_iter().map(|tx| tx.sender),
        judge: |s, _| {
            ensure!(
                !s.ran.tx()?.authority.authorization_list,
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
        doc: "A configurable-account signature matches Tempo's commitment at the anchor, or derives its unregistered account at version zero.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
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
        doc: "An ordinary signature never authorizes for an account with a Tempo commitment at the anchor.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |step: &ZoneStep| {
            step.ran
                .tx()
                .into_iter()
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
];

/// The zone's stored leaves after a step, beside what it serves for them.
pub const LEAF_CHECKS: &[Check<ZoneLeaves>] = &[
    // Zone state never stores a commitment or the account marker.
    // <https://github.com/tempoxyz/tempo/blob/4008a2986ad18fa3bf55838d2d63bbb878ee7da7/tips/tip-1154.md#L86>
    check! {
        id: "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
        doc: "Zone state never stores a commitment or the account marker.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |l: &ZoneLeaves| l.of.keys(),
        judge: |l, account| {
            let leaf = l.of.get(*account)?;
            let stored = leaf.stored;
            let marker = stored.code_hash == MARKER_CODE_HASH && !leaf.reserved;
            ensure!(
                !leaf.extension && stored.commitment.is_zero() && !marker,
                "zone state stores {}commitment {} and code hash {}",
                if leaf.extension { "an extension, " } else { "" },
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
        doc: "The zone serves the marker for an eligible account without code that has a Tempo commitment, its stored code otherwise.",
        tip: "TIP-1154",
        since: TempoHardfork::T14,
        over: |l: &ZoneLeaves| l.of.keys(),
        judge: |l, account| {
            let leaf = l.of.get(*account)?;
            let (served, stored) = (leaf.served?, leaf.stored.code_hash);
            let overlaid = l.active && !leaf.reserved && stored == KECCAK256_EMPTY;
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

impl Checked<TempoHardfork> for Mirror {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Ran, TempoHardfork> for Mirror {
    const STEP_CHECKS: &'static [Check<ZoneStep>] = STEP_CHECKS;
}

impl Checked<TempoHardfork> for ZoneLeaves {
    const CHECKS: &'static [Check<Self>] = LEAF_CHECKS;
}

/// A TIP-20 approval `permit` made for `owner`.
#[derive(Debug, Clone, Copy)]
struct Permit {
    token: Address,
    owner: Address,
}

impl fmt::Display for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "permit of {} on {}", self.owner, self.token)
    }
}

/// The token and owner of each committed TIP-20 `permit` call in the step's call trace; none when
/// the trace was not kept.
fn permits(step: &ZoneStep) -> impl Iterator<Item = Permit> + '_ {
    step.calls
        .iter()
        .flatten()
        .filter(|frame| frame.committed && is_tip20_prefix(frame.target))
        .filter_map(|frame| {
            let permit = frame.decode::<permitCall>()?;
            Some(Permit {
                token: frame.target,
                owner: permit.owner,
            })
        })
}

/// The quorums of the step's transaction.
fn quorums(step: &ZoneStep) -> impl Iterator<Item = &Quorum> {
    step.ran
        .tx()
        .into_iter()
        .flat_map(|tx| tx.authority.quorums.iter())
}

/// The mirror a transaction's authority is judged against: the one before it, when the step kept
/// the anchor (a step that moved it is judged by ANCHOR-ADVANCE).
fn at_tx(s: &ZoneStep) -> Option<&Mirror> {
    (s.pre.zone.anchor == s.post.zone.anchor).then_some(&s.pre)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::{Address, B256, Bytes, Log, LogData, U256, address};
    use invariants_core::{Effects, Outcome, Report};
    use tempo_contracts::precompiles::IConfigurableAccount::ConfigurableAccountOwner;

    use super::*;
    use crate::{
        Tx,
        configurable_account::{Authority, ConfigurableAccountConfig, Key, Leaf, Quorum, Role},
        zone_account::{Anchor, Tempo, Zone, ZoneLeaf},
    };

    const TEMPO_STATE: Address = address!("0x1c00000000000000000000000000000000000000");
    const PRECOMPILE: Address = address!("0xaaaa000000000000000000000000000000000000");
    const TOKEN: Address = address!("0x20c0000000000000000000000000000000000001");
    const ALICE: Address = address!("0x00000000000000000000000000000000000a11ce");
    const SENDER: Address = address!("0x0000000000000000000000000000000000005e1d");

    fn word(byte: u8) -> B256 {
        B256::with_last_byte(byte)
    }

    fn anchor(number: u64) -> Anchor {
        Anchor {
            number,
            hash: word(number as u8),
        }
    }

    /// A zone at `number` reading `of`, with nothing marked, coded or reserved.
    fn zone(number: u64, of: &[(Address, B256)]) -> Zone {
        Zone {
            tempo_state: TEMPO_STATE,
            precompile: PRECOMPILE,
            anchor: anchor(number),
            of: of.iter().copied().collect(),
            marked: BTreeMap::new(),
            coded: Default::default(),
            reserved: Default::default(),
        }
    }

    fn mirror(zone: Zone, tempo: &[(Address, B256)]) -> Mirror {
        let block = zone.anchor.number;
        Mirror::new(
            zone,
            Some(Tempo::new(block, tempo.iter().copied().collect())),
        )
        .unwrap()
    }

    fn tx(authority: Authority) -> Ran {
        Ran::Tx(Tx {
            sender: SENDER,
            success: true,
            authority,
        })
    }

    fn effects(ran: Ran) -> Effects<Ran> {
        Effects {
            changes: Vec::new(),
            logs: Vec::new(),
            calls: None,
            ran,
        }
    }

    /// A step from `pre` to `post` whose transaction `authority` signed.
    fn step(pre: Mirror, post: Mirror, effects: Effects<Ran>) -> ZoneStep {
        ZoneStep::new(pre, post, effects)
    }

    /// The (ID, subject, detail) of each violation `checks` find on `ctx` at T14.
    fn broken<C>(checks: &[Check<C>], ctx: &C) -> Vec<(String, String, String)> {
        let mut report = Report::default();
        report.run(checks, ctx, Some(&TempoHardfork::T14));
        report
            .violations
            .into_iter()
            .map(|v| (v.id.into_owned(), v.subject, v.detail))
            .collect()
    }

    fn one(id: &str, subject: impl ToString, detail: &str) -> Vec<(String, String, String)> {
        vec![(id.to_owned(), subject.to_string(), detail.to_owned())]
    }

    #[test]
    fn a_commitment_other_than_tempos_breaks_the_mirror() {
        let m = mirror(zone(7, &[(ALICE, word(1))]), &[(ALICE, word(2))]);
        assert_eq!(
            broken(CHECKS, &m),
            one(
                "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR",
                ALICE,
                &format!(
                    "the zone reads commitment {}, Tempo holds {} at {}",
                    word(1),
                    word(2),
                    anchor(7)
                ),
            )
        );
    }

    #[test]
    fn a_reserved_address_reading_a_commitment_breaks_ineligible() {
        let mut z = zone(7, &[(ALICE, word(1))]);
        z.reserved.insert(ALICE);
        let m = mirror(z, &[(ALICE, word(1))]);
        assert_eq!(
            broken(CHECKS, &m),
            one(
                "TEMPO-ZONE-ACCOUNT-INELIGIBLE",
                ALICE,
                &format!(
                    "is an address the zone never reads Tempo for, yet the zone reads commitment {}",
                    word(1)
                ),
            )
        );
    }

    #[test]
    fn a_coded_account_reading_a_commitment_breaks_ineligible() {
        let mut z = zone(7, &[(ALICE, word(1))]);
        z.coded.insert(ALICE);
        let m = mirror(z, &[(ALICE, word(1))]);
        assert_eq!(
            broken(CHECKS, &m),
            one(
                "TEMPO-ZONE-ACCOUNT-INELIGIBLE",
                ALICE,
                &format!(
                    "is an account with zone code, yet the zone reads commitment {}",
                    word(1)
                ),
            )
        );
    }

    #[test]
    fn a_marker_without_a_tempo_commitment_breaks_marker_call() {
        let mut z = zone(7, &[(ALICE, B256::ZERO)]);
        z.marked.insert(ALICE, true);
        let m = mirror(z, &[(ALICE, B256::ZERO)]);
        assert_eq!(
            broken(CHECKS, &m),
            one(
                "TEMPO-ZONE-ACCOUNT-MARKER-CALL",
                ALICE,
                &format!(
                    "answers as the account marker, Tempo's commitment at {} is {}",
                    anchor(7),
                    B256::ZERO
                ),
            )
        );
    }

    #[test]
    fn a_user_transaction_moving_the_anchor_breaks_anchor_advance() {
        let s = step(
            mirror(zone(7, &[]), &[]),
            mirror(zone(8, &[]), &[]),
            effects(tx(Authority::default())),
        );
        assert_eq!(
            broken(STEP_CHECKS, &s),
            one(
                "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE",
                anchor(8),
                &format!(
                    "moved from {} without a TempoBlockFinalized event",
                    anchor(7)
                ),
            )
        );
    }

    #[test]
    fn a_commitment_changing_at_the_same_anchor_breaks_commitment_anchored() {
        let s = step(
            mirror(zone(7, &[(ALICE, word(1))]), &[]),
            mirror(zone(7, &[(ALICE, word(2))]), &[]),
            effects(Ran::PreBlock),
        );
        assert_eq!(
            broken(STEP_CHECKS, &s),
            one(
                "TEMPO-ZONE-ACCOUNT-COMMITMENT-ANCHORED",
                ALICE,
                &format!(
                    "commitment {} -> {}, marker (None, None), while the zone stayed at {}",
                    word(1),
                    word(2),
                    anchor(7)
                ),
            )
        );
    }

    #[test]
    fn a_configuration_event_breaks_no_write() {
        let mut e = effects(Ran::PreBlock);
        e.logs.push(Log {
            address: PRECOMPILE,
            data: LogData::new_unchecked(vec![word(9)], Bytes::new()),
        });
        let s = step(mirror(zone(7, &[]), &[]), mirror(zone(7, &[]), &[]), e);
        assert_eq!(
            broken(STEP_CHECKS, &s),
            one(
                "TEMPO-ZONE-ACCOUNT-NO-WRITE",
                PRECOMPILE,
                "emitted 1 configuration events on a zone",
            )
        );
    }

    fn permit(owner: Address) -> permitCall {
        permitCall {
            owner,
            spender: SENDER,
            value: U256::from(1),
            deadline: U256::MAX,
            v: 27,
            r: word(1),
            s: word(2),
        }
    }

    #[test]
    fn a_permit_of_a_committed_owner_breaks_permit_retired() {
        let m = || mirror(zone(7, &[]), &[(ALICE, word(1))]);
        let e = effects(tx(Authority::default())).call(
            SENDER,
            TOKEN,
            &permit(ALICE),
            Outcome::Return(Bytes::new()),
        );
        assert_eq!(
            broken(STEP_CHECKS, &step(m(), m(), e)),
            one(
                "TEMPO-ZONE-ACCOUNT-PERMIT-RETIRED",
                format!("permit of {ALICE} on {TOKEN}"),
                &format!(
                    "{TOKEN} accepted a permit signed by the root key of {ALICE}, Tempo's \
                     commitment at {} is {}",
                    anchor(7),
                    word(1)
                ),
            )
        );
    }

    #[test]
    fn a_permit_of_an_owner_with_zone_code_is_not_judged() {
        let m = || {
            let mut z = zone(7, &[]);
            z.coded.insert(ALICE);
            mirror(z, &[(ALICE, word(1))])
        };
        let e = effects(tx(Authority::default())).call(
            SENDER,
            TOKEN,
            &permit(ALICE),
            Outcome::Return(Bytes::new()),
        );
        assert_eq!(broken(STEP_CHECKS, &step(m(), m(), e)), vec![]);
    }

    #[test]
    fn a_reverted_permit_is_not_judged() {
        let m = || mirror(zone(7, &[]), &[(ALICE, word(1))]);
        let e = effects(tx(Authority::default())).call(
            SENDER,
            TOKEN,
            &permit(ALICE),
            Outcome::Revert(Bytes::new()),
        );
        assert_eq!(broken(STEP_CHECKS, &step(m(), m(), e)), vec![]);
    }

    #[test]
    fn an_authorization_list_breaks_no_authorization_list() {
        let m = || mirror(zone(7, &[]), &[]);
        let authority = Authority {
            authorization_list: true,
            ..Default::default()
        };
        assert_eq!(
            broken(STEP_CHECKS, &step(m(), m(), effects(tx(authority)))),
            one(
                "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST",
                SENDER,
                "sent a zone transaction with an authorization list",
            )
        );
    }

    #[test]
    fn a_quorum_off_tempos_commitment_breaks_quorum_commitment() {
        let m = || mirror(zone(7, &[]), &[(ALICE, word(1))]);
        let config = ConfigurableAccountConfig {
            salt: word(3),
            version: 1,
            threshold: 1,
            owners: vec![ConfigurableAccountOwner {
                owner: SENDER,
                weight: 1,
            }],
        };
        let hash = spec::commitment(&config);
        let quorum = Quorum {
            role: Role::Sender,
            account: ALICE,
            config,
            approvals: Vec::new(),
        };
        let subject = quorum.to_string();
        let authority = Authority {
            quorums: vec![quorum],
            ..Default::default()
        };
        assert_eq!(
            broken(STEP_CHECKS, &step(m(), m(), effects(tx(authority)))),
            one(
                "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT",
                subject,
                &format!(
                    "carries a configuration hashing to {hash:?}, Tempo's commitment at {} is {}",
                    anchor(7),
                    word(1)
                ),
            )
        );
    }

    #[test]
    fn an_ordinary_key_of_a_committed_account_breaks_root_key_retired() {
        let m = || mirror(zone(7, &[]), &[(ALICE, word(1))]);
        let key = Key {
            role: Role::Sender,
            account: ALICE,
        };
        let authority = Authority {
            keys: vec![key],
            ..Default::default()
        };
        assert_eq!(
            broken(STEP_CHECKS, &step(m(), m(), effects(tx(authority)))),
            one(
                "TEMPO-ZONE-ACCOUNT-ROOT-KEY-RETIRED",
                key,
                &format!(
                    "signed with an ordinary key, Tempo's commitment at {} is {}",
                    anchor(7),
                    word(1)
                ),
            )
        );
    }

    fn leaves(leaf: ZoneLeaf) -> ZoneLeaves {
        ZoneLeaves {
            active: true,
            of: [(ALICE, leaf)].into(),
        }
    }

    fn leaf(code_hash: B256) -> ZoneLeaf {
        ZoneLeaf {
            stored: Leaf {
                commitment: B256::ZERO,
                code_hash,
            },
            extension: false,
            reserved: false,
            served: Some(code_hash),
            tempo: Some(B256::ZERO),
        }
    }

    #[test]
    fn a_stored_extension_breaks_state_clean() {
        let l = leaves(ZoneLeaf {
            extension: true,
            ..leaf(KECCAK256_EMPTY)
        });
        assert_eq!(
            broken(LEAF_CHECKS, &l),
            one(
                "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
                ALICE,
                &format!(
                    "zone state stores an extension, commitment {} and code hash {KECCAK256_EMPTY}",
                    B256::ZERO
                ),
            )
        );
    }

    #[test]
    fn stored_marker_code_breaks_state_clean_unless_reserved() {
        assert_eq!(
            broken(LEAF_CHECKS, &leaves(leaf(MARKER_CODE_HASH))),
            one(
                "TEMPO-ZONE-ACCOUNT-STATE-CLEAN",
                ALICE,
                &format!(
                    "zone state stores commitment {} and code hash {MARKER_CODE_HASH}",
                    B256::ZERO
                ),
            )
        );
        let reserved = leaves(ZoneLeaf {
            reserved: true,
            ..leaf(MARKER_CODE_HASH)
        });
        assert_eq!(broken(LEAF_CHECKS, &reserved), vec![]);
    }

    #[test]
    fn no_marker_served_for_a_committed_account_breaks_code_served() {
        let l = leaves(ZoneLeaf {
            tempo: Some(word(1)),
            ..leaf(KECCAK256_EMPTY)
        });
        assert_eq!(
            broken(LEAF_CHECKS, &l),
            one(
                "TEMPO-ZONE-ACCOUNT-CODE-SERVED",
                ALICE,
                &format!(
                    "serves code hash {KECCAK256_EMPTY}, not {MARKER_CODE_HASH} (stored code hash \
                     {KECCAK256_EMPTY}, Tempo commitment {:?})",
                    Some(word(1))
                ),
            )
        );
    }
}
