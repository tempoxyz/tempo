//! Zone portal invariants: what a portal's state, events and calls must satisfy on Tempo.

use std::fmt;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, SolEvent};
use invariants_core::{check, ensure};
use tempo_contracts::precompiles::ITIP20;

use super::{
    CIPHERTEXT_LEN, FIXED_DEPOSIT_GAS, MAX_GAS_FEE_RATE, NO_QUEUE_INDEX, Portal, PortalStep,
    ZONE_MESSENGER_ADDRESS, ZoneMessenger, ZonePortal, deposits, enqueued, is_compressed_point,
    next_enablement_hash, portal_address, settled, submitted_prev_hashes, withdrawal_chain,
};
use crate::{Check, Checked, Severity, StepChecked, Tx, Verdict};

/// The portal's views answer. Counted by runners that read the model, not judged by a check here.
pub const VIEW: &str = "TEMPO-ZONE-PORTAL-VIEW";

pub const ADMIN_NONZERO: &str = "TEMPO-ZONE-ADMIN-NONZERO";
pub const PORTAL_PAIRING: &str = "TEMPO-ZONE-PORTAL-PAIRING";
pub const GENESIS_BINDING: &str = "TEMPO-ZONE-GENESIS-BINDING";
pub const GAS_RATE_BOUNDED: &str = "TEMPO-ZONE-GAS-RATE-BOUNDED";
pub const TOKEN_ENABLEMENT_APPEND_ONLY: &str = "TEMPO-ZONE-TOKEN-ENABLEMENT-APPEND-ONLY";
pub const TOKEN_DEPOSIT_PAUSE_ONLY: &str = "TEMPO-ZONE-TOKEN-DEPOSIT-PAUSE-ONLY";
pub const ENCRYPTION_KEY_APPEND_ONLY: &str = "TEMPO-ZONE-ENCRYPTION-KEY-APPEND-ONLY";
pub const ENCRYPTION_KEY_GRACE: &str = "TEMPO-ZONE-ENCRYPTION-KEY-GRACE";
pub const ENCRYPTED_PAYLOAD_SHAPE: &str = "TEMPO-ZONE-ENCRYPTED-PAYLOAD-SHAPE";
pub const DEPOSIT_QUEUE_HASH: &str = "TEMPO-ZONE-DEPOSIT-QUEUE-HASH";
pub const PORTAL_DEPOSIT_NUMBER: &str = "TEMPO-ZONE-PORTAL-DEPOSIT-NUMBER";
pub const DEPOSIT_ENABLED_ACTIVE: &str = "TEMPO-ZONE-DEPOSIT-ENABLED-ACTIVE";
pub const DEPOSIT_MIN_AMOUNT: &str = "TEMPO-ZONE-DEPOSIT-MIN-AMOUNT";
pub const DEPOSIT_FEE_SNAPSHOT: &str = "TEMPO-ZONE-DEPOSIT-FEE-SNAPSHOT";
pub const DEPOSIT_BOUNCEBACK_NONZERO: &str = "TEMPO-ZONE-DEPOSIT-BOUNCEBACK-NONZERO";
pub const DEPOSIT_BOUNCEBACK_FEE_CAP: &str = "TEMPO-ZONE-DEPOSIT-BOUNCEBACK-FEE-CAP";
pub const BOUNCEBACK_FUNDS_PRESERVED: &str = "TEMPO-ZONE-BOUNCEBACK-FUNDS-PRESERVED";
pub const WITHDRAWAL_QUEUE_FIFO: &str = "TEMPO-ZONE-WITHDRAWAL-QUEUE-FIFO";
pub const PORTAL_BATCH_INDEX: &str = "TEMPO-ZONE-PORTAL-BATCH-INDEX";
pub const WITHDRAWAL_DEQUEUE_AUTH: &str = "TEMPO-ZONE-WITHDRAWAL-DEQUEUE-AUTH";
pub const WITHDRAWAL_FAIL_BOUNCEBACK: &str = "TEMPO-ZONE-WITHDRAWAL-FAIL-BOUNCEBACK";
pub const BATCH_PREV_HASH: &str = "TEMPO-ZONE-BATCH-PREV-HASH";
pub const PORTAL_SOLVENCY: &str = "TEMPO-ZONE-PORTAL-SOLVENCY";
pub const ADMIN_ONLY_GOVERNANCE: &str = "TEMPO-ZONE-ADMIN-ONLY-GOVERNANCE";
pub const SEQUENCER_ONLY_OPS: &str = "TEMPO-ZONE-SEQUENCER-ONLY-OPS";
pub const MESSENGER_AUTH: &str = "TEMPO-ZONE-MESSENGER-AUTH";

/// The specification every portal invariant comes from.
const SPEC: &str = "Tempo Zones";
/// The fork that enshrined the zone factory, before which no portal exists.
const SINCE: &str = "T10";

/// A portal's state.
pub const CHECKS: &[Check<Portal>] = &[
    check! {
        id: ADMIN_NONZERO,
        doc: "A zone portal's `admin` is never the zero address.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        judge: |p: &Portal| ensure!(!p.admin.is_zero(), "admin is the zero address"),
    },
    check! {
        id: PORTAL_PAIRING,
        doc: "The zone factory registers each portal under the zone ID the portal reports, at the address derived from that ID, and the portal relays through the factory's shared messenger.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        judge: |p: &Portal| ensure!(
            p.registered == p.portal
                && p.is_zone_portal
                && p.portal == portal_address(p.zone_id)
                && p.messenger == ZONE_MESSENGER_ADDRESS,
            "factory registers {} for zone {}, isZonePortal {}, derived address {}, messenger {}",
            p.registered,
            p.zone_id,
            p.is_zone_portal,
            portal_address(p.zone_id),
            p.messenger
        ),
    },
    check! {
        id: GENESIS_BINDING,
        doc: "A portal's `blockHash` is zero until its first batch settles.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        judge: |p: &Portal| {
            if p.withdrawal_batch_index != 0 {
                return None;
            }
            ensure!(p.block_hash.is_zero(), "no batch settled, blockHash is {}", p.block_hash)
        },
    },
    check! {
        id: GAS_RATE_BOUNDED,
        doc: "A portal's `zoneGasRate` and `maxTempoGasRate` never exceed `MAX_GAS_FEE_RATE` (10^18).",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        judge: |p: &Portal| ensure!(
            p.zone_gas_rate <= MAX_GAS_FEE_RATE && p.max_tempo_gas_rate <= MAX_GAS_FEE_RATE,
            "zoneGasRate {}, maxTempoGasRate {}",
            p.zone_gas_rate,
            p.max_tempo_gas_rate
        ),
    },
];

/// What a step did to a portal, read before and after it, with its events and calls.
pub const STEP_CHECKS: &[Check<PortalStep>] = &[
    check! {
        id: TOKEN_ENABLEMENT_APPEND_ONLY,
        doc: "Once enabled, a token stays enabled and keeps its place in the portal's enabled-token list, which grows only by the tokens its `TokenEnabled` events name, each advancing `tokenEnablementHash` to `keccak256(abi.encode(previous, token, name, symbol, currency))`.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| token_enablement_append_only(s),
    },
    check! {
        id: TOKEN_DEPOSIT_PAUSE_ONLY,
        doc: "Pausing or resuming a token's deposits leaves it enabled and in the enabled-token list and sets only its `depositsActive` flag.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| deposit_switches(s),
        judge: |s, switch| {
            let Some(token) = s.post.token(switch.value.0) else {
                if s.post.tokens.len() as u64 != s.post.token_count {
                    return None;
                }
                return Some(Verdict::Broken("is not listed".to_string()));
            };
            ensure!(
                token.enabled && token.deposits_active == switch.value.1,
                "enabled {}, depositsActive {} after its last switch set it {}",
                token.enabled,
                token.deposits_active,
                switch.value.1
            )
        },
    },
    check! {
        id: ENCRYPTION_KEY_APPEND_ONLY,
        doc: "The portal's encryption keys are only appended, each a valid compressed secp256k1 point that a `SequencerEncryptionKeyUpdated` event announces with its index and activation block, and no entry changes once added.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| encryption_key_append_only(s),
    },
    check! {
        id: ENCRYPTION_KEY_GRACE,
        doc: "Every deposit names an encryption key that `isEncryptionKeyValid` accepts in its block: the current key, or an earlier one less than `ENCRYPTION_KEY_GRACE_PERIOD` blocks after its successor's activation.",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |s, deposit| {
            let index = deposit.value.keyIndex;
            let known = s.pre.key_count.max(s.post.key_count);
            if index >= U256::from(known) {
                return Some(Verdict::Broken(format!("names key {index} of {known}")));
            }
            let index = index.to::<usize>();
            let valid = |p: &Portal| p.keys.get(index).map(|key| key.valid);
            match (valid(&s.pre), valid(&s.post)) {
                (None, None) => None,
                (pre, post) => ensure!(
                    pre == Some(true) || post == Some(true),
                    "names key {index}, which isEncryptionKeyValid rejects"
                ),
            }
        },
    },
    check! {
        id: ENCRYPTED_PAYLOAD_SHAPE,
        doc: "Every queued deposit carries an ephemeral public key that is a valid compressed secp256k1 point and exactly 64 bytes of ciphertext.",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |_s, deposit| {
            let d = &deposit.value;
            ensure!(
                is_compressed_point(d.ephemeralPubkeyX, d.ephemeralPubkeyYParity)
                    && d.ciphertext.len() == CIPHERTEXT_LEN,
                "ephemeral key ({}, parity {}), {} bytes of ciphertext",
                d.ephemeralPubkeyX,
                d.ephemeralPubkeyYParity,
                d.ciphertext.len()
            )
        },
    },
    check! {
        id: DEPOSIT_QUEUE_HASH,
        doc: "The portal's deposit queue hash changes only by the entries its `DepositMade` and `WithdrawalBounceBack` events report, each advancing it to `keccak256(abi.encode(depositType, entry, previous))`.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| {
            let mut hash = s.pre.deposit_queue_hash;
            for entry in enqueued(s) {
                let next = entry.next_hash(hash);
                if entry.reported_hash() != next {
                    return Some(Verdict::Broken(format!(
                        "entry {} reports queue hash {}, its entry hashes to {next}",
                        entry.number(),
                        entry.reported_hash()
                    )));
                }
                hash = next;
            }
            ensure!(
                s.post.deposit_queue_hash == hash,
                "queue hash {} -> {}, its events replay to {hash}",
                s.pre.deposit_queue_hash,
                s.post.deposit_queue_hash
            )
        },
    },
    check! {
        id: PORTAL_DEPOSIT_NUMBER,
        doc: "`depositCount` grows by one per queued entry, whose event reports the new count as its number, and `lastProcessedDepositNumber` changes only to the number a `BatchSubmitted` event reports, never decreasing or passing `depositCount`.",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| deposit_numbers(s),
    },
    check! {
        id: DEPOSIT_ENABLED_ACTIVE,
        doc: "A deposit enters the queue only for a token that is enabled with deposits active, while the portal is not paused.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |s, deposit| {
            let token = deposit.value.token;
            if s.pre.token(token).is_none() && s.post.token(token).is_none() {
                let read_all = |p: &Portal| p.tokens.len() as u64 == p.token_count;
                if !read_all(&s.pre) || !read_all(&s.post) {
                    return None;
                }
            }
            ensure!(
                (s.pre.accepts_deposits(token) || s.post.accepts_deposits(token))
                    && !(s.pre.paused && s.post.paused),
                "token {token} accepts deposits before {} after {}, paused before {} after {}",
                s.pre.accepts_deposits(token),
                s.post.accepts_deposits(token),
                s.pre.paused,
                s.post.paused
            )
        },
    },
    check! {
        id: DEPOSIT_MIN_AMOUNT,
        doc: "A queued deposit's amount covers its deposit fee plus the bounce-back fee in force, so its net amount is at least `calculateBouncebackFee()`.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |s, deposit| {
            let floor = s.pre.bounceback_fee.min(s.post.bounceback_fee);
            ensure!(
                deposit.value.netAmount >= floor,
                "net amount {} is below the bounce-back fee {floor}",
                deposit.value.netAmount
            )
        },
    },
    check! {
        id: DEPOSIT_FEE_SNAPSHOT,
        doc: "A queued deposit's fee is `FIXED_DEPOSIT_GAS * zoneGasRate` at enqueue time, its entry holds the amount less that fee, and the fee is transferred to the admin in the same step.",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |s, deposit| {
            let d = &deposit.value;
            let fees = [s.pre.zone_gas_rate, s.post.zone_gas_rate]
                .map(|rate| FIXED_DEPOSIT_GAS.checked_mul(rate));
            if !fees.contains(&Some(d.fee)) {
                return Some(Verdict::Broken(format!(
                    "fee {}, zoneGasRate before {} after {}",
                    d.fee, s.pre.zone_gas_rate, s.post.zone_gas_rate
                )));
            }
            if d.fee == 0 {
                return Some(Verdict::Holds);
            }
            let admins = [s.pre.admin, s.post.admin];
            let paid = s.events::<ITIP20::Transfer>(d.token).iter().any(|t| {
                t.from == s.post.portal && admins.contains(&t.to) && t.amount == U256::from(d.fee)
            });
            ensure!(paid, "fee {} of {} was not transferred to the admin", d.fee, d.token)
        },
    },
    check! {
        id: DEPOSIT_BOUNCEBACK_NONZERO,
        doc: "Every queued deposit names a non-zero `tempoRefundRecipient`.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| queued(s),
        judge: |_s, deposit| ensure!(
            !deposit.value.tempoRefundRecipient.is_zero(),
            "names the zero address as its tempoRefundRecipient"
        ),
    },
    check! {
        id: DEPOSIT_BOUNCEBACK_FEE_CAP,
        doc: "A deposit bounce-back's collected fee is at most `calculateBouncebackFee()` at processing time.",
        tip: SPEC,
        severity: Severity::Medium,
        since: SINCE,
        over: |s: &PortalStep| deposit_bounce_backs(s),
        judge: |s, bounce| {
            let cap = s.pre.bounceback_fee.max(s.post.bounceback_fee);
            ensure!(bounce.value.fee <= cap, "collected fee {} above {cap}", bounce.value.fee)
        },
    },
    check! {
        id: BOUNCEBACK_FUNDS_PRESERVED,
        doc: "A deposit bounce-back the portal cannot deliver adds its amount to `refunds(token, recipient)`, and `claimRefund` pays out and zeroes that whole balance.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| refund_accounts(s),
        judge: |s, account| refund_balance(s, account.value.0, account.value.1),
    },
    check! {
        id: WITHDRAWAL_QUEUE_FIFO,
        doc: "The withdrawal queue's `head` and `tail` only grow, with `head <= tail`; the slots in `[head, tail)` hold non-zero hash chains and the others are zero; a batch with withdrawals takes the next `tail` index and a batch without takes none.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| withdrawal_queue(s),
    },
    check! {
        id: PORTAL_BATCH_INDEX,
        doc: "`withdrawalBatchIndex` grows by exactly one per `BatchSubmitted` event, which reports the new index, and by nothing else.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| {
            let batches = settled(s);
            let first = s.pre.withdrawal_batch_index;
            for (k, batch) in batches.iter().enumerate() {
                let expected = first + k as u64 + 1;
                if batch.batch_index != expected {
                    return Some(Verdict::Broken(format!(
                        "batch event {k} reports index {}, expected {expected}",
                        batch.batch_index
                    )));
                }
            }
            ensure!(
                s.post.withdrawal_batch_index == first + batches.len() as u64,
                "index {first} -> {} over {} batches",
                s.post.withdrawal_batch_index,
                batches.len()
            )
        },
    },
    check! {
        id: WITHDRAWAL_DEQUEUE_AUTH,
        doc: "A `processWithdrawals` call that returns dequeues only withdrawals whose hash chain `keccak256(abi.encode(withdrawal, remainingQueue))` equals the head slot, which it leaves holding `remainingQueue`, or clears as `head` advances when that is zero.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        when: |s: &PortalStep| s.traced(),
        over: |s: &PortalStep| whole(s),
        judge: |s, _| dequeue_auth(s),
    },
    check! {
        id: WITHDRAWAL_FAIL_BOUNCEBACK,
        doc: "Each user withdrawal the portal fails to deliver enqueues exactly one `WithdrawalBounceBack` for its token and full amount, and nothing else enqueues one.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| withdrawal_bounce_backs(s),
    },
    check! {
        id: BATCH_PREV_HASH,
        doc: "A portal's `blockHash` changes only to the `nextBlockHash` a `BatchSubmitted` event reports, and each accepted `submitBatch` starts from the `blockHash` before it.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| whole(s),
        judge: |s, _| {
            let batches = settled(s);
            let prevs = submitted_prev_hashes(s);
            let traced = s.traced() && prevs.len() == batches.len();
            let mut hash = s.pre.block_hash;
            for (k, batch) in batches.iter().enumerate() {
                if traced && prevs[k] != hash {
                    return Some(Verdict::Broken(format!(
                        "batch {} starts from {}, blockHash was {hash}",
                        batch.batch_index, prevs[k]
                    )));
                }
                hash = batch.block_hash;
            }
            ensure!(
                s.post.block_hash == hash,
                "blockHash {} -> {}, its batches report {hash}",
                s.pre.block_hash,
                s.post.block_hash
            )
        },
    },
    check! {
        id: PORTAL_SOLVENCY,
        doc: "Over each step, a portal's balance of an enabled token changes by at least the deposits it takes in less the withdrawals it delivers, the deposit fees and bounce-backs it pays out and the refunds it pays claimants.",
        tip: SPEC,
        severity: Severity::Critical,
        since: SINCE,
        over: |s: &PortalStep| s.post.tokens.iter().map(|t| t.token).collect::<Vec<_>>(),
        judge: |s, token| solvency(s, *token),
    },
    check! {
        id: ADMIN_ONLY_GOVERNANCE,
        doc: "Only the portal's admin calls its governance functions successfully (token enablement and deposit pausing, access and gateway modes, roles, the sequencer set, `zoneGasRate`, `maxTempoGasRate`, `bouncebackGas`, `transferAdmin`, `resume` and `abdicate`), and only the pending admin `acceptAdmin`.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        when: |s: &PortalStep| s.traced(),
        over: |s: &PortalStep| restricted_calls(s, GOVERNANCE),
        judge: |s, call| {
            let allowed = if call.value.selector == ZonePortal::acceptAdminCall::SELECTOR {
                vec![s.pre.pending_admin]
            } else {
                vec![s.pre.admin, s.post.admin]
            };
            ensure!(allowed.contains(&call.value.caller), "admin is {}", s.pre.admin)
        },
    },
    check! {
        id: SEQUENCER_ONLY_OPS,
        doc: "Only a registered sequencer calls `setRpcUrl`, `submitBatch` or `processWithdrawals` successfully, and only the admin or a sequencer `setSequencerEncryptionKey` or `setLeader`.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        when: |s: &PortalStep| s.traced(),
        over: |s: &PortalStep| restricted_calls(s, SEQUENCER_OPS),
        judge: |s, call| {
            let caller = call.value.caller;
            let sequencer = s.pre.is_sequencer(caller) || s.post.is_sequencer(caller);
            let admin_too = [
                ZonePortal::setSequencerEncryptionKeyCall::SELECTOR,
                ZonePortal::setLeaderCall::SELECTOR,
            ]
            .contains(&call.value.selector);
            ensure!(
                sequencer || (admin_too && caller == s.pre.admin),
                "the caller is not a sequencer{}",
                if admin_too { " or the admin" } else { "" }
            )
        },
    },
    check! {
        id: MESSENGER_AUTH,
        doc: "The shared messenger relays a withdrawal for a zone only when the portal the zone factory registered for that zone calls it.",
        tip: SPEC,
        severity: Severity::High,
        since: SINCE,
        when: |s: &PortalStep| s.traced(),
        over: |s: &PortalStep| {
            s.calls_of::<ZoneMessenger::relayMessageCall>(ZONE_MESSENGER_ADDRESS)
                .into_iter()
                .filter(|(frame, call)| frame.success && call.zoneId == s.post.zone_id)
                .map(|(frame, _)| Named::new(format!("relayMessage from {}", frame.caller), frame.caller))
                .collect::<Vec<_>>()
        },
        judge: |s, caller| ensure!(
            caller.value == s.post.registered,
            "zone {}'s registered portal is {}",
            s.post.zone_id,
            s.post.registered
        ),
    },
];

impl Checked for Portal {
    const CHECKS: &'static [Check<Self>] = CHECKS;
}

impl StepChecked<Option<Tx>> for Portal {
    const STEP_CHECKS: &'static [Check<PortalStep>] = STEP_CHECKS;
}

/// A subject of a check with the name its violations show.
#[derive(Debug, Clone)]
pub struct Named<T> {
    pub name: String,
    pub value: T,
}

impl<T> Named<T> {
    fn new(name: String, value: T) -> Self {
        Self { name, value }
    }
}

impl<T> fmt::Display for Named<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

/// The step as the one subject of a check that judges it whole.
fn whole(s: &PortalStep) -> [String; 1] {
    [s.post.to_string()]
}

fn broken(detail: String) -> Option<Verdict> {
    Some(Verdict::Broken(detail))
}

/// The deposits the step queued, each named by its number.
fn queued(s: &PortalStep) -> Vec<Named<ZonePortal::DepositMade>> {
    deposits(s)
        .into_iter()
        .map(|d| Named::new(format!("deposit {} of {}", d.depositNumber, d.token), d))
        .collect()
}

/// Each token the step paused or resumed deposits of, with whether its last switch resumed them.
fn deposit_switches(s: &PortalStep) -> Vec<Named<(Address, bool)>> {
    let mut last: Vec<(Address, bool)> = Vec::new();
    for log in s.logs_from(s.post.portal) {
        let switch = if let Ok(e) = ZonePortal::DepositsPaused::decode_log_data(&log.data) {
            (e.token, false)
        } else if let Ok(e) = ZonePortal::DepositsResumed::decode_log_data(&log.data) {
            (e.token, true)
        } else {
            continue;
        };
        last.retain(|(token, _)| *token != switch.0);
        last.push(switch);
    }
    last.into_iter()
        .map(|switch| Named::new(format!("token {}", switch.0), switch))
        .collect()
}

/// A deposit bounce-back the step processed.
#[derive(Debug, Clone)]
pub struct DepositBounce {
    pub recipient: Address,
    pub token: Address,
    pub amount: u128,
    pub fee: u128,
    /// Whether it was parked as a refund rather than delivered.
    pub pending: bool,
}

fn deposit_bounce_backs(s: &PortalStep) -> Vec<Named<DepositBounce>> {
    s.logs_from(s.post.portal)
        .filter_map(|log| {
            if let Ok(e) = ZonePortal::DepositBounceBack::decode_log_data(&log.data) {
                return Some(DepositBounce {
                    recipient: e.tempoRefundRecipient,
                    token: e.token,
                    amount: e.amount,
                    fee: e.bouncebackFee,
                    pending: false,
                });
            }
            let e = ZonePortal::DepositBounceBackPending::decode_log_data(&log.data).ok()?;
            Some(DepositBounce {
                recipient: e.tempoRefundRecipient,
                token: e.token,
                amount: e.amount,
                fee: e.bouncebackFee,
                pending: true,
            })
        })
        .map(|b| {
            Named::new(
                format!("bounce-back of {} {} to {}", b.amount, b.token, b.recipient),
                b,
            )
        })
        .collect()
}

fn token_enablement_append_only(s: &PortalStep) -> Option<Verdict> {
    let (pre, post) = (&s.pre, &s.post);
    let enabled: Vec<ZonePortal::TokenEnabled> = s.events(post.portal);
    let count = pre.token_count + enabled.len() as u64;
    if post.token_count != count {
        return broken(format!(
            "enabled-token count {} -> {} with {} TokenEnabled events",
            pre.token_count,
            post.token_count,
            enabled.len()
        ));
    }
    for (index, (before, after)) in pre.tokens.iter().zip(&post.tokens).enumerate() {
        if before.token != after.token {
            return broken(format!(
                "entry {index} was {}, is {}",
                before.token, after.token
            ));
        }
    }
    for (k, event) in enabled.iter().enumerate() {
        let index = pre.token_count as usize + k;
        if let Some(listed) = post.tokens.get(index)
            && listed.token != event.token
        {
            return broken(format!(
                "entry {index} is {}, its event enabled {}",
                listed.token, event.token
            ));
        }
    }
    if let Some(token) = post.tokens.iter().find(|t| !t.enabled) {
        return broken(format!("listed token {} is not enabled", token.token));
    }
    let hash = enabled
        .iter()
        .fold(pre.token_enablement_hash, |hash, event| {
            next_enablement_hash(hash, event)
        });
    ensure!(
        post.token_enablement_hash == hash,
        "tokenEnablementHash {} -> {}, its events replay to {hash}",
        pre.token_enablement_hash,
        post.token_enablement_hash
    )
}

fn encryption_key_append_only(s: &PortalStep) -> Option<Verdict> {
    let (pre, post) = (&s.pre, &s.post);
    let updates: Vec<ZonePortal::SequencerEncryptionKeyUpdated> = s.events(post.portal);
    if post.key_count != pre.key_count + updates.len() as u64 {
        return broken(format!(
            "key count {} -> {} with {} SequencerEncryptionKeyUpdated events",
            pre.key_count,
            post.key_count,
            updates.len()
        ));
    }
    for (index, (before, after)) in pre.keys.iter().zip(&post.keys).enumerate() {
        let entry = |k: &super::Key| (k.x, k.y_parity, k.activation_block);
        if entry(before) != entry(after) {
            return broken(format!(
                "key {index} changed from {:?} to {:?}",
                entry(before),
                entry(after)
            ));
        }
    }
    for (k, update) in updates.iter().enumerate() {
        let index = pre.key_count + k as u64;
        if update.keyIndex != U256::from(index) {
            return broken(format!(
                "key event {k} reports index {}, expected {index}",
                update.keyIndex
            ));
        }
        if let Some(key) = post.keys.get(index as usize)
            && (key.x, key.y_parity, key.activation_block)
                != (update.x, update.yParity, update.activationBlock)
        {
            return broken(format!("key {index} differs from its event"));
        }
    }
    if let Some((index, key)) = post
        .keys
        .iter()
        .enumerate()
        .find(|(_, key)| !is_compressed_point(key.x, key.y_parity))
    {
        return broken(format!(
            "key {index} ({}, parity {}) is not a secp256k1 point",
            key.x, key.y_parity
        ));
    }
    let ordered = post
        .keys
        .windows(2)
        .all(|pair| pair[0].activation_block <= pair[1].activation_block);
    ensure!(ordered, "key activation blocks decrease")
}

fn deposit_numbers(s: &PortalStep) -> Option<Verdict> {
    let (pre, post) = (&s.pre, &s.post);
    let entries = enqueued(s);
    for (k, entry) in entries.iter().enumerate() {
        let expected = pre.deposit_count + k as u64 + 1;
        if entry.number() != expected {
            return broken(format!(
                "queued entry {k} reports number {}, expected {expected}",
                entry.number()
            ));
        }
    }
    if post.deposit_count != pre.deposit_count + entries.len() as u64 {
        return broken(format!(
            "depositCount {} -> {} with {} queued entries",
            pre.deposit_count,
            post.deposit_count,
            entries.len()
        ));
    }
    let processed = settled(s)
        .last()
        .map_or(pre.last_processed_deposit, |batch| {
            batch.last_processed_deposit
        });
    ensure!(
        post.last_processed_deposit == processed
            && processed >= pre.last_processed_deposit
            && processed <= post.deposit_count,
        "lastProcessedDepositNumber {} -> {} (batches report {processed}), depositCount {}",
        pre.last_processed_deposit,
        post.last_processed_deposit,
        post.deposit_count
    )
}

/// The (token, owner) refund balances the step's bounce-backs and claims name.
fn refund_accounts(s: &PortalStep) -> Vec<Named<(Address, Address)>> {
    let mut accounts: Vec<(Address, Address)> = deposit_bounce_backs(s)
        .into_iter()
        .filter(|b| b.value.pending)
        .map(|b| (b.value.token, b.value.recipient))
        .chain(
            s.events::<ZonePortal::RefundClaimed>(s.post.portal)
                .into_iter()
                .map(|e| (e.token, e.recipient)),
        )
        .collect();
    accounts.sort_unstable();
    accounts.dedup();
    accounts
        .into_iter()
        .map(|(token, owner)| Named::new(format!("refund of {token} to {owner}"), (token, owner)))
        .collect()
}

fn refund_balance(s: &PortalStep, token: Address, owner: Address) -> Option<Verdict> {
    let before = if s.pre.token(token).is_some() {
        *s.pre.refunds.get(&(token, owner))?
    } else {
        0
    };
    let after = *s.post.refunds.get(&(token, owner))?;
    let mut balance = before;
    for log in s.logs_from(s.post.portal) {
        if let Ok(e) = ZonePortal::DepositBounceBackPending::decode_log_data(&log.data)
            && (e.token, e.tempoRefundRecipient) == (token, owner)
        {
            balance = balance.saturating_add(e.amount);
        } else if let Ok(e) = ZonePortal::RefundClaimed::decode_log_data(&log.data)
            && (e.token, e.recipient) == (token, owner)
        {
            if e.amount != balance {
                return broken(format!(
                    "claimed {} of a refund balance of {balance}",
                    e.amount
                ));
            }
            balance = 0;
        }
    }
    ensure!(
        after == balance,
        "refund {before} -> {after}, its events leave {balance}"
    )
}

fn withdrawal_queue(s: &PortalStep) -> Option<Verdict> {
    let (pre, post) = (&s.pre.queue, &s.post.queue);
    if post.head > post.tail || post.head < pre.head || post.tail < pre.tail {
        return broken(format!(
            "head {} -> {}, tail {} -> {}",
            pre.head, post.head, pre.tail, post.tail
        ));
    }
    for (&index, &slot) in &post.slots {
        let live = index >= post.head && index < post.tail;
        if live == slot.is_zero() {
            return broken(format!(
                "slot {index} holds {slot}, with head {} and tail {}",
                post.head, post.tail
            ));
        }
    }
    let mut tail = pre.tail;
    for batch in settled(s) {
        let expected = if batch.withdrawal_queue_hash.is_zero() {
            NO_QUEUE_INDEX
        } else {
            tail += U256::ONE;
            tail - U256::ONE
        };
        if batch.queue_index != expected {
            return broken(format!(
                "batch {} with withdrawal hash {} took queue index {}, expected {expected}",
                batch.batch_index, batch.withdrawal_queue_hash, batch.queue_index
            ));
        }
    }
    ensure!(
        post.tail == tail,
        "tail {} -> {}, its batches take it to {tail}",
        pre.tail,
        post.tail
    )
}

fn dequeue_auth(s: &PortalStep) -> Option<Verdict> {
    if !s.tx.is_some_and(|tx| tx.success) {
        return None;
    }
    let calls: Vec<_> = s
        .calls_of::<ZonePortal::processWithdrawalsCall>(s.post.portal)
        .into_iter()
        .filter(|(frame, _)| frame.success)
        .collect();
    let [(_, call)] = calls.as_slice() else {
        return None;
    };
    if call.withdrawals.is_empty() {
        return None;
    }
    let head = s.pre.queue.head;
    let slot = *s.pre.queue.slots.get(&head)?;
    let chain = withdrawal_chain(&call.withdrawals, call.remainingQueue);
    if slot != chain {
        return broken(format!(
            "dequeued {} withdrawals hashing to {chain}, head slot {head} held {slot}",
            call.withdrawals.len()
        ));
    }
    let after = s.post.queue.slots.get(&head).copied().unwrap_or(B256::ZERO);
    let (expected_head, expected_slot) = if call.remainingQueue.is_zero() {
        (head + U256::ONE, B256::ZERO)
    } else {
        (head, call.remainingQueue)
    };
    ensure!(
        s.post.queue.head == expected_head && after == expected_slot,
        "head {head} -> {}, slot {head} holds {after}; expected head {expected_head} holding {expected_slot}",
        s.post.queue.head
    )
}

fn withdrawal_bounce_backs(s: &PortalStep) -> Option<Verdict> {
    enum Event {
        BounceBack(Address, u128),
        Processed(Address, u128, bool),
        Other,
    }
    let events: Vec<Event> = s
        .logs_from(s.post.portal)
        .map(|log| {
            if let Ok(e) = ZonePortal::WithdrawalBounceBack::decode_log_data(&log.data) {
                Event::BounceBack(e.token, e.amount)
            } else if let Ok(e) = ZonePortal::WithdrawalProcessed::decode_log_data(&log.data) {
                Event::Processed(e.token, e.amount, e.callbackSuccess)
            } else {
                Event::Other
            }
        })
        .collect();
    if events.iter().all(|e| matches!(e, Event::Other)) {
        return None;
    }
    for (index, event) in events.iter().enumerate() {
        match event {
            Event::BounceBack(token, amount) => {
                let delivered = events.get(index + 1);
                if !matches!(delivered, Some(Event::Processed(t, a, false)) if t == token && a == amount)
                {
                    return broken(format!(
                        "bounce-back of {amount} {token} is not for a failed withdrawal of it"
                    ));
                }
            }
            Event::Processed(token, amount, false) => {
                let bounced = index.checked_sub(1).and_then(|i| events.get(i));
                if !matches!(bounced, Some(Event::BounceBack(t, a)) if t == token && a == amount) {
                    return broken(format!(
                        "failed withdrawal of {amount} {token} did not bounce back"
                    ));
                }
            }
            _ => {}
        }
    }
    Some(Verdict::Holds)
}

fn solvency(s: &PortalStep, token: Address) -> Option<Verdict> {
    let before = s.pre.token(token)?.balance?;
    let after = s.post.token(token)?.balance?;
    let portal = s.post.portal;
    let mut gained = U256::ZERO;
    let mut paid = U256::ZERO;
    for deposit in deposits(s).into_iter().filter(|d| d.token == token) {
        gained += U256::from(deposit.netAmount) + U256::from(deposit.fee);
        paid += U256::from(deposit.fee);
    }
    for log in s.logs_from(portal) {
        if let Ok(e) = ZonePortal::WithdrawalProcessed::decode_log_data(&log.data)
            && e.token == token
            && e.callbackSuccess
        {
            paid += U256::from(e.amount);
        } else if let Ok(e) = ZonePortal::DepositBounceBack::decode_log_data(&log.data)
            && e.token == token
        {
            paid += U256::from(e.amount) + U256::from(e.bouncebackFee);
        } else if let Ok(e) = ZonePortal::DepositBounceBackPending::decode_log_data(&log.data)
            && e.token == token
        {
            paid += U256::from(e.bouncebackFee);
        } else if let Ok(e) = ZonePortal::RefundClaimed::decode_log_data(&log.data)
            && e.token == token
        {
            paid += U256::from(e.amount);
        }
    }
    if before == after && gained.is_zero() && paid.is_zero() {
        return None;
    }
    ensure!(
        after + paid >= before + gained,
        "holds {before} -> {after} of {token}, took in {gained} and paid out {paid}; short {}",
        (before + gained) - (after + paid)
    )
}

/// A call into the portal that only some accounts may make, and who made it.
#[derive(Debug, Clone, Copy)]
pub struct Restricted {
    pub selector: [u8; 4],
    pub caller: Address,
}

const GOVERNANCE: &[(&str, [u8; 4])] = &[
    ("setZoneGasRate", ZonePortal::setZoneGasRateCall::SELECTOR),
    (
        "setMaxTempoGasRate",
        ZonePortal::setMaxTempoGasRateCall::SELECTOR,
    ),
    (
        "setBouncebackGas",
        ZonePortal::setBouncebackGasCall::SELECTOR,
    ),
    ("enableToken", ZonePortal::enableTokenCall::SELECTOR),
    ("pauseDeposits", ZonePortal::pauseDepositsCall::SELECTOR),
    ("resumeDeposits", ZonePortal::resumeDepositsCall::SELECTOR),
    ("setAccessMode", ZonePortal::setAccessModeCall::SELECTOR),
    ("setGatewayMode", ZonePortal::setGatewayModeCall::SELECTOR),
    (
        "setAllowedAccount",
        ZonePortal::setAllowedAccountCall::SELECTOR,
    ),
    ("setGateway", ZonePortal::setGatewayCall::SELECTOR),
    (
        "setPauseGuardian",
        ZonePortal::setPauseGuardianCall::SELECTOR,
    ),
    ("setSequencerSet", ZonePortal::setSequencerSetCall::SELECTOR),
    ("transferAdmin", ZonePortal::transferAdminCall::SELECTOR),
    ("acceptAdmin", ZonePortal::acceptAdminCall::SELECTOR),
    ("resume", ZonePortal::resumeCall::SELECTOR),
    ("abdicate", ZonePortal::abdicateCall::SELECTOR),
];

const SEQUENCER_OPS: &[(&str, [u8; 4])] = &[
    ("setRpcUrl", ZonePortal::setRpcUrlCall::SELECTOR),
    ("submitBatch", ZonePortal::submitBatch_0Call::SELECTOR),
    ("submitBatch", ZonePortal::submitBatch_1Call::SELECTOR),
    (
        "processWithdrawals",
        ZonePortal::processWithdrawalsCall::SELECTOR,
    ),
    (
        "setSequencerEncryptionKey",
        ZonePortal::setSequencerEncryptionKeyCall::SELECTOR,
    ),
    ("setLeader", ZonePortal::setLeaderCall::SELECTOR),
];

/// The step's calls into the portal that returned and whose selector `functions` lists.
fn restricted_calls(s: &PortalStep, functions: &[(&str, [u8; 4])]) -> Vec<Named<Restricted>> {
    s.calls_to(s.post.portal)
        .filter(|frame| frame.success)
        .filter_map(|frame| {
            let selector = frame.selector()?;
            let (name, _) = functions.iter().find(|(_, s)| *s == selector)?;
            let call = Restricted {
                selector,
                caller: frame.caller,
            };
            Some(Named::new(format!("{name} from {}", frame.caller), call))
        })
        .collect()
}
