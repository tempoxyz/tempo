use std::{collections::BTreeMap, convert::Infallible};

use alloy_primitives::{Address, B256, Bytes, Log, LogData};
use alloy_sol_types::{SolCall, SolEvent};
use tempo_contracts::{
    precompiles::{CONFIGURABLE_ACCOUNT_ADDRESS, IConfigurableAccount, PATH_USD_ADDRESS},
    zones::{
        TEMPO_STATE_ADDRESS,
        TempoState::{tempoBlockHashCall, tempoBlockNumberCall},
        ZONE_INBOX_ADDRESS,
    },
};

use super::*;
use crate::{
    Observe, ObserveError, Report, Step,
    configurable_account::{
        Authority, ConfigurableAccountConfig, ConfigurableAccountOwner, Key, Leaf, Role,
    },
    zone_account::{Anchor, Misanchored, Tempo, Zone, ZoneAt, ZoneLeaf},
};

const ANCHOR: Anchor = Anchor {
    number: 42,
    hash: B256::repeat_byte(0x42),
};
const NEXT: Anchor = Anchor {
    number: 43,
    hash: B256::repeat_byte(0x43),
};
/// An eligible account without zone code.
const ALICE: Address = Address::repeat_byte(0x51);
/// A commitment.
const C: B256 = B256::repeat_byte(0xc1);

fn zone(anchor: Anchor, of: &[(Address, B256)], marked: &[(Address, bool)]) -> Zone {
    Zone {
        tempo_state: TEMPO_STATE_ADDRESS,
        precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
        anchor,
        of: of.iter().copied().collect(),
        marked: marked.iter().copied().collect(),
        coded: Default::default(),
    }
}

fn tempo(anchor: Anchor, of: &[(Address, B256)]) -> Tempo {
    Tempo {
        block: anchor.number,
        hash: Some(anchor.hash),
        of: of.iter().copied().collect(),
    }
}

/// The zone at `anchor` reading `zone_of`, beside Tempo holding `tempo_of` there.
fn mirror(anchor: Anchor, zone_of: &[(Address, B256)], tempo_of: &[(Address, B256)]) -> Mirror {
    Mirror::new(zone(anchor, zone_of, &[]), Some(tempo(anchor, tempo_of))).unwrap()
}

fn step(pre: Mirror, post: Mirror, logs: Vec<Log>, tx: Option<Tx>) -> ZoneStep {
    Step {
        pre,
        post,
        changes: vec![],
        logs,
        tx,
    }
}

fn finalized(anchor: Anchor) -> Log {
    Log {
        address: TEMPO_STATE_ADDRESS,
        data: TempoBlockFinalized {
            blockHash: anchor.hash,
            blockNumber: anchor.number,
            stateRoot: B256::ZERO,
        }
        .encode_log_data(),
    }
}

fn tx(authority: Authority) -> Option<Tx> {
    Some(Tx {
        sender: ALICE,
        success: true,
        authority: Authority {
            active: true,
            ..authority
        },
    })
}

fn config(version: u64) -> ConfigurableAccountConfig {
    ConfigurableAccountConfig {
        salt: B256::repeat_byte(0x5a),
        version,
        threshold: 1,
        owners: vec![ConfigurableAccountOwner {
            owner: Address::repeat_byte(0x0a),
            weight: 1,
        }],
    }
}

/// The account `config(0)` derives.
fn derived() -> Address {
    spec::derived_address(&config(0)).unwrap()
}

fn signed(account: Address, config: ConfigurableAccountConfig) -> Option<Tx> {
    tx(Authority {
        quorums: vec![Quorum {
            role: Role::Sender,
            account,
            config,
            approvals: vec![],
        }],
        ..Default::default()
    })
}

fn run<T: Checked>(ctx: &T) -> Report {
    let mut report = Report::default();
    report.run(T::CHECKS, ctx);
    report
}

fn fired(report: &Report) -> Vec<&'static str> {
    report.violations.iter().map(|v| v.id).collect()
}

fn armed(report: &Report, id: &str) -> u64 {
    report.counts[id].armed
}

/// Requires `ctx` to break exactly `ids`.
fn breaks<T: Checked>(ctx: &T, ids: &[&str]) {
    assert_eq!(fired(&run(ctx)), ids, "{:?}", run(ctx).violations);
}

/// Requires `ctx` to break nothing while arming `id`.
fn holds<T: Checked>(ctx: &T, id: &str) {
    let report = run(ctx);
    assert!(report.violations.is_empty(), "{:?}", report.violations);
    assert!(armed(&report, id) > 0, "{id} was not armed");
}

#[test]
fn commitment_mirror() {
    let id = "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR";
    holds(&mirror(ANCHOR, &[(ALICE, C)], &[(ALICE, C)]), id);
    holds(
        &mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, B256::ZERO)]),
        id,
    );
    // The overlay was not applied.
    breaks(
        &mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, C)]),
        &[id],
    );
    // A stale read: the previous anchor's commitment.
    breaks(
        &mirror(ANCHOR, &[(ALICE, C)], &[(ALICE, B256::repeat_byte(2))]),
        &[id],
    );
}

#[test]
fn accounts_with_zone_code_or_reserved_addresses_read_nothing() {
    let id = "TEMPO-ZONE-ACCOUNT-INELIGIBLE";
    let mut coded = mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, C)]);
    coded.zone.coded.insert(ALICE);
    holds(&coded, id);
    coded.zone.of.insert(ALICE, C);
    // An account with zone code is judged here, never against Tempo.
    breaks(&coded, &[id]);
    for reserved in [
        PATH_USD_ADDRESS,
        ZONE_INBOX_ADDRESS,
        CONFIGURABLE_ACCOUNT_ADDRESS,
    ] {
        holds(
            &mirror(ANCHOR, &[(reserved, B256::ZERO)], &[(reserved, C)]),
            id,
        );
        breaks(&mirror(ANCHOR, &[(reserved, C)], &[(reserved, C)]), &[id]);
    }
}

#[test]
fn marker_call() {
    let id = "TEMPO-ZONE-ACCOUNT-MARKER-CALL";
    let marked = |marked, commitment| {
        let zone = zone(ANCHOR, &[(ALICE, commitment)], &[(ALICE, marked)]);
        Mirror::new(zone, Some(tempo(ANCHOR, &[(ALICE, commitment)]))).unwrap()
    };
    holds(&marked(true, C), id);
    holds(&marked(false, B256::ZERO), id);
    // Commitment overlaid, code not: ERC-1271 verifiers fall back to the retired key.
    breaks(&marked(false, C), &[id]);
    breaks(&marked(true, B256::ZERO), &[id]);
}

#[test]
fn a_non_canonical_anchor_disarms_the_cross_chain_checks() {
    let mut forked = mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, C)]);
    holds(
        &mirror(ANCHOR, &[(ALICE, C)], &[(ALICE, C)]),
        "TEMPO-ZONE-ACCOUNT-ANCHOR-CANONICAL",
    );
    forked.tempo.as_mut().unwrap().hash = Some(B256::repeat_byte(0xff));
    let report = run(&forked);
    assert_eq!(fired(&report), ["TEMPO-ZONE-ACCOUNT-ANCHOR-CANONICAL"]);
    assert_eq!(armed(&report, "TEMPO-ZONE-ACCOUNT-COMMITMENT-MIRROR"), 0);
}

#[test]
fn tempo_read_at_another_block_is_rejected() {
    let read = tempo(
        Anchor {
            number: 41,
            hash: ANCHOR.hash,
        },
        &[],
    );
    assert_eq!(
        Mirror::new(zone(ANCHOR, &[], &[]), Some(read)),
        Err(Misanchored {
            anchor: 42,
            read: 41
        })
    );
}

#[test]
fn anchor_advance() {
    let id = "TEMPO-ZONE-ACCOUNT-ANCHOR-ADVANCE";
    let at = |anchor| mirror(anchor, &[], &[]);
    holds(&step(at(ANCHOR), at(ANCHOR), vec![], None), id);
    holds(&step(at(ANCHOR), at(NEXT), vec![finalized(NEXT)], None), id);
    let far = Anchor {
        number: 45,
        hash: B256::repeat_byte(0x45),
    };
    let headers = vec![
        finalized(NEXT),
        finalized(Anchor {
            number: 44,
            hash: B256::repeat_byte(0x44),
        }),
        finalized(far),
    ];
    holds(&step(at(ANCHOR), at(far), headers, None), id);
    // Moved without the event.
    breaks(&step(at(ANCHOR), at(NEXT), vec![], None), &[id]);
    // Moved in a user transaction.
    breaks(
        &step(
            at(ANCHOR),
            at(NEXT),
            vec![finalized(NEXT)],
            tx(Authority::default()),
        ),
        &[id],
    );
    // Moved to another block than the event finalized.
    breaks(
        &step(at(ANCHOR), at(NEXT), vec![finalized(far)], None),
        &[id],
    );
    // Moved back.
    let back = Anchor {
        number: 41,
        hash: B256::repeat_byte(0x41),
    };
    breaks(
        &step(at(ANCHOR), at(back), vec![finalized(back)], None),
        &[id],
    );
}

#[test]
fn commitment_anchored() {
    let id = "TEMPO-ZONE-ACCOUNT-COMMITMENT-ANCHORED";
    let zone_only = |anchor, commitment, marked| {
        Mirror::new(
            zone(anchor, &[(ALICE, commitment)], &[(ALICE, marked)]),
            None,
        )
        .unwrap()
    };
    holds(
        &step(
            zone_only(ANCHOR, C, true),
            zone_only(ANCHOR, C, true),
            vec![],
            None,
        ),
        id,
    );
    // A zone registering locally.
    breaks(
        &step(
            zone_only(ANCHOR, B256::ZERO, false),
            zone_only(ANCHOR, C, false),
            vec![],
            None,
        ),
        &[id],
    );
    breaks(
        &step(
            zone_only(ANCHOR, C, false),
            zone_only(ANCHOR, C, true),
            vec![],
            None,
        ),
        &[id],
    );
    // Once the anchor moves, the new value is judged against Tempo instead.
    let moved = step(
        zone_only(ANCHOR, B256::ZERO, false),
        zone_only(NEXT, C, true),
        vec![finalized(NEXT)],
        None,
    );
    let report = run(&moved);
    assert!(report.violations.is_empty(), "{:?}", report.violations);
    assert_eq!(armed(&report, id), 0);
}

#[test]
fn no_write() {
    let id = "TEMPO-ZONE-ACCOUNT-NO-WRITE";
    let at = || mirror(ANCHOR, &[], &[]);
    let event = |address| Log {
        address,
        data: LogData::new_unchecked(vec![B256::repeat_byte(1)], Bytes::new()),
    };
    holds(&step(at(), at(), vec![event(ALICE)], None), id);
    let mut failed = tx(Authority::default()).unwrap();
    failed.success = false;
    // Tempo keeps a registration event when calls revert; a zone has none at all.
    breaks(
        &step(
            at(),
            at(),
            vec![event(CONFIGURABLE_ACCOUNT_ADDRESS)],
            Some(failed),
        ),
        &[id],
    );
}

#[test]
fn no_authorization_list() {
    let id = "TEMPO-ZONE-ACCOUNT-NO-AUTHORIZATION-LIST";
    let at = || mirror(ANCHOR, &[], &[]);
    holds(&step(at(), at(), vec![], tx(Authority::default())), id);
    let listed = tx(Authority {
        authorization_list: true,
        ..Default::default()
    });
    breaks(&step(at(), at(), vec![], listed), &[id]);
}

#[test]
fn quorum_commitment() {
    let id = "TEMPO-ZONE-ACCOUNT-QUORUM-COMMITMENT";
    let registered = spec::commitment(&config(1)).unwrap();
    let rotated = spec::commitment(&config(2)).unwrap();
    let at = |zone_c, tempo_c| mirror(ANCHOR, &[(ALICE, zone_c)], &[(ALICE, tempo_c)]);
    holds(
        &step(
            at(registered, registered),
            at(registered, registered),
            vec![],
            signed(ALICE, config(1)),
        ),
        id,
    );
    // The rotated-out owners still sign, and the zone's own view is stale in the same way: this
    // check judges Tempo's value, so it still fires (with the mirror check on the state).
    breaks(
        &step(
            at(registered, rotated),
            at(registered, rotated),
            vec![],
            signed(ALICE, config(1)),
        ),
        &[id],
    );
    let account = derived();
    let both = [(account, B256::ZERO), (ALICE, B256::ZERO)];
    let unregistered = || mirror(ANCHOR, &both, &both);
    holds(
        &step(
            unregistered(),
            unregistered(),
            vec![],
            signed(account, config(0)),
        ),
        id,
    );
    breaks(
        &step(
            unregistered(),
            unregistered(),
            vec![],
            signed(account, config(1)),
        ),
        &[id],
    );
    // A configuration deriving another account.
    breaks(
        &step(
            unregistered(),
            unregistered(),
            vec![],
            signed(ALICE, config(0)),
        ),
        &[id],
    );
    let token = || mirror(ANCHOR, &[], &[]);
    breaks(
        &step(
            token(),
            token(),
            vec![],
            signed(PATH_USD_ADDRESS, config(0)),
        ),
        &[id],
    );
}

#[test]
fn root_key_retired() {
    let id = "TEMPO-ZONE-ACCOUNT-ROOT-KEY-RETIRED";
    for role in [
        Role::Sender,
        Role::AccessKey,
        Role::KeyAuthorization,
        Role::FeePayer,
    ] {
        let keyed = tx(Authority {
            keys: vec![Key {
                role,
                account: ALICE,
            }],
            ..Default::default()
        });
        let free = || mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, B256::ZERO)]);
        holds(&step(free(), free(), vec![], keyed.clone()), id);
        // Retirement judged against Tempo, though the zone's own view reads zero.
        let migrated = || mirror(ANCHOR, &[(ALICE, B256::ZERO)], &[(ALICE, C)]);
        let report = run(&step(migrated(), migrated(), vec![], keyed.clone()));
        assert_eq!(fired(&report), [id], "{role}");
        let mut before_t14 = keyed.unwrap();
        before_t14.authority.active = false;
        let report = run(&step(migrated(), migrated(), vec![], Some(before_t14)));
        assert_eq!(armed(&report, id), 0);
    }
}

#[test]
fn signer_unregistered() {
    let id = "TEMPO-ZONE-ACCOUNT-SIGNER-UNREGISTERED";
    let account = derived();
    let at = |zone_c| mirror(ANCHOR, &[(account, zone_c)], &[(account, B256::ZERO)]);
    holds(
        &step(
            at(B256::ZERO),
            at(B256::ZERO),
            vec![],
            signed(account, config(0)),
        ),
        id,
    );
    let report = run(&step(
        at(B256::ZERO),
        at(C),
        vec![],
        signed(account, config(0)),
    ));
    assert!(fired(&report).contains(&id), "{:?}", report.violations);
}

fn leaves(account: Address, leaf: ZoneLeaf) -> ZoneLeaves {
    ZoneLeaves {
        active: true,
        of: BTreeMap::from([(account, leaf)]),
    }
}

fn leaf(commitment: B256, code_hash: B256, served: B256, tempo: B256) -> ZoneLeaf {
    ZoneLeaf {
        stored: Leaf {
            commitment,
            code_hash,
        },
        served: Some(served),
        tempo: Some(tempo),
    }
}

#[test]
fn state_clean() {
    let id = "TEMPO-ZONE-ACCOUNT-STATE-CLEAN";
    let empty = alloy_primitives::KECCAK256_EMPTY;
    holds(
        &leaves(ALICE, leaf(B256::ZERO, empty, empty, B256::ZERO)),
        id,
    );
    // Precompile accounts store the marker as their code.
    holds(
        &leaves(
            PATH_USD_ADDRESS,
            leaf(B256::ZERO, MARKER_CODE_HASH, MARKER_CODE_HASH, B256::ZERO),
        ),
        id,
    );
    breaks(&leaves(ALICE, leaf(C, empty, empty, B256::ZERO)), &[id]);
    breaks(
        &leaves(
            ALICE,
            leaf(B256::ZERO, MARKER_CODE_HASH, MARKER_CODE_HASH, C),
        ),
        &[id],
    );
}

#[test]
fn code_served() {
    let id = "TEMPO-ZONE-ACCOUNT-CODE-SERVED";
    let empty = alloy_primitives::KECCAK256_EMPTY;
    holds(
        &leaves(ALICE, leaf(B256::ZERO, empty, MARKER_CODE_HASH, C)),
        id,
    );
    holds(
        &leaves(ALICE, leaf(B256::ZERO, empty, empty, B256::ZERO)),
        id,
    );
    let contract = B256::repeat_byte(0xcc);
    holds(&leaves(ALICE, leaf(B256::ZERO, contract, contract, C)), id);
    let mut before_t14 = leaves(ALICE, leaf(B256::ZERO, empty, empty, C));
    before_t14.active = false;
    holds(&before_t14, id);
    // An operator `eth_getCode` answering `0x` for a registered account.
    breaks(&leaves(ALICE, leaf(B256::ZERO, empty, empty, C)), &[id]);
    breaks(
        &leaves(ALICE, leaf(B256::ZERO, empty, MARKER_CODE_HASH, B256::ZERO)),
        &[id],
    );
    breaks(
        &leaves(ALICE, leaf(B256::ZERO, contract, MARKER_CODE_HASH, C)),
        &[id],
    );
}

#[test]
fn every_check_is_registered_once_and_zone_contexts_run_no_l1_check() {
    let ids: Vec<&str> = CHECKS
        .iter()
        .map(|c| c.id)
        .chain(STEP_CHECKS.iter().map(|c| c.id))
        .chain(LEAF_CHECKS.iter().map(|c| c.id))
        .collect();
    assert_eq!(ids.len(), 13);
    for id in &ids {
        assert!(id.starts_with("TEMPO-ZONE-ACCOUNT-"), "{id}");
        assert_eq!(crate::all().filter(|c| c.id() == *id).count(), 1, "{id}");
    }
    let mut report = Report::default();
    let at = || mirror(ANCHOR, &[], &[]);
    report.run_any(
        crate::all(),
        &step(at(), at(), vec![], signed(derived(), config(0))),
    );
    assert_eq!(
        report.counts["TEMPO-ACCOUNT-SIGNER-REGISTERED"].evaluated,
        0
    );
    assert!(report.counts["TEMPO-ZONE-ACCOUNT-SIGNER-UNREGISTERED"].evaluated > 0);
}

type Answers = Result<Vec<Option<Bytes>>, Infallible>;

/// Answers the zone's views: the anchor, `commitments` and, per probed account, `probes`.
fn zone_views(
    commitments: &[(Address, B256)],
    probes: &[(Address, Bytes)],
) -> impl FnMut(&[(Address, Bytes)]) -> Answers + use<> {
    let commitments: BTreeMap<_, _> = commitments.iter().copied().collect();
    let probes: BTreeMap<_, _> = probes.iter().cloned().collect();
    move |calls| {
        Ok(calls
            .iter()
            .map(|(to, input)| {
                let selector: [u8; 4] = input[..4].try_into().unwrap();
                match (*to, selector) {
                    (TEMPO_STATE_ADDRESS, tempoBlockNumberCall::SELECTOR) => {
                        Some(tempoBlockNumberCall::abi_encode_returns(&ANCHOR.number).into())
                    }
                    (TEMPO_STATE_ADDRESS, tempoBlockHashCall::SELECTOR) => {
                        Some(tempoBlockHashCall::abi_encode_returns(&ANCHOR.hash).into())
                    }
                    (CONFIGURABLE_ACCOUNT_ADDRESS, _) => {
                        let call = IConfigurableAccount::getConfigCommitmentCall::abi_decode(input)
                            .unwrap();
                        commitments.get(&call.account).map(|c| {
                            IConfigurableAccount::getConfigCommitmentCall::abi_encode_returns(c)
                                .into()
                        })
                    }
                    (account, _) => Some(
                        probes
                            .get(&account)
                            .unwrap_or_else(|| panic!("probed {account}"))
                            .clone(),
                    ),
                }
            })
            .collect())
    }
}

fn magic() -> Bytes {
    use tempo_contracts::precompiles::IConfigurableAccountShim::onERC721ReceivedCall;
    onERC721ReceivedCall::abi_encode_returns(&onERC721ReceivedCall::SELECTOR.into()).into()
}

#[test]
fn zone_reads_anchor_commitments_and_markers() {
    let bob = Address::repeat_byte(0x52);
    let carol = Address::repeat_byte(0x53);
    let accounts = [ALICE, bob, carol, PATH_USD_ADDRESS];
    let mut views = zone_views(
        &[
            (ALICE, C),
            (bob, B256::ZERO),
            (PATH_USD_ADDRESS, B256::ZERO),
        ],
        &[(ALICE, magic()), (bob, Bytes::new())],
    );
    // `carol` has zone code, so it is never probed; nor is the token.
    let at = ZoneAt {
        tempo_state: TEMPO_STATE_ADDRESS,
        precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
        accounts: &accounts,
        coded: &[carol],
    };
    let zone = Zone::observe(&mut views, at).unwrap();
    assert_eq!(zone.anchor(), ANCHOR);
    assert_eq!(zone.of.get(&ALICE), Some(&C));
    // Unanswered reads are left out.
    assert_eq!(zone.of.get(&carol), None);
    assert_eq!(zone.marked, BTreeMap::from([(ALICE, true), (bob, false)]));
}

#[test]
fn an_unexpected_probe_output_is_malformed() {
    let mut views = zone_views(&[(ALICE, C)], &[(ALICE, Bytes::from_static(&[1]))]);
    let at = ZoneAt {
        tempo_state: TEMPO_STATE_ADDRESS,
        precompile: CONFIGURABLE_ACCOUNT_ADDRESS,
        accounts: &[ALICE],
        coded: &[],
    };
    assert!(matches!(
        Zone::observe(&mut views, at),
        Err(ObserveError::Malformed { to: ALICE, .. })
    ));
}

#[test]
fn reserved_addresses() {
    for address in [
        TEMPO_STATE_ADDRESS,
        ZONE_INBOX_ADDRESS,
        tempo_contracts::zones::ZONE_OUTBOX_ADDRESS,
        tempo_contracts::zones::ZONE_FEE_MANAGER_ADDRESS,
        PATH_USD_ADDRESS,
        CONFIGURABLE_ACCOUNT_ADDRESS,
        Address::ZERO,
        Address::with_last_byte(1),
    ] {
        assert!(reserved(address).is_some(), "{address}");
    }
    assert_eq!(reserved(ALICE), None);
}
