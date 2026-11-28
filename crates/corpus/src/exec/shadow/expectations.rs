//! Reviewed baseline and fork-specific expectations for shadow replay.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::{
    Arms, Boundary, Evidence, ObservedTx, TxEvidence,
    analysis::Field,
    fees::{fee_hook_slot_change, post_tx_fee},
};
use alloy_consensus::Transaction as _;
use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::*,
    zones::{
        T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
        T14_ZONE_PORTAL_RUNTIME, T15_ZONE_PORTAL_RUNTIME, ZONE_MESSENGER_RUNTIME,
        ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
    },
};
use tempo_precompiles::{storage::StorageAction, tip_fee_manager::amm::compute_amount_out};
use tempo_primitives::{TempoTxEnvelope, transaction::calc_gas_balance_spending};

#[derive(Debug)]
pub(crate) struct Expectation {
    pub id: &'static str,
    pub check: fn(&Context<'_>, &Field) -> Option<()>,
}

#[derive(Clone, Copy)]
pub(crate) struct Context<'a> {
    pub boundary: Boundary,
    pub evidence: &'a Evidence,
    pub base_fee: Option<u64>,
    pub tx: Option<&'a TempoTxEnvelope>,
}

impl Context<'_> {
    /// Returns the observed transaction pair as `(real, shadow)` at this boundary.
    fn observed_txs(&self) -> Option<(&ObservedTx, &ObservedTx)> {
        let Boundary::Transaction(index) = self.boundary else {
            return None;
        };
        let TxEvidence::Differs(arms) = self.evidence.txs.get(index)? else {
            return None;
        };
        Some((&arms.real, &arms.shadow))
    }

    /// Returns normalized log hashes only when both fee transfers match their gas charges.
    /// Normalization already checked each logged amount against its recorded hook charge.
    pub(super) fn verified_fee_log_hashes(&self) -> Option<(B256, B256)> {
        let (real, shadow) = self.observed_txs()?;
        let (real_fee, shadow_fee) = (post_tx_fee(&real.actions)?, post_tx_fee(&shadow.actions)?);
        let price = self.tx?.effective_gas_price(self.base_fee);
        (real_fee.log == shadow_fee.log
            && real_fee.charged == calc_gas_balance_spending(real.charged_gas, price)
            && shadow_fee.charged == calc_gas_balance_spending(shadow.charged_gas, price))
        .then_some((real.fee_normalized?, shadow.fee_normalized?))
    }
}

/// Accepts only the storage effect of a verified, gas-derived post-transaction fee hook.
const FEE_STATE: Expectation = Expectation {
    id: "fee.post-tx-state",
    check: |ctx, field| {
        if field.name != "storage" || !field.fee_associated {
            return None;
        }
        let (address, slot) = (field.address?, field.slot?);
        let (real, shadow) = ctx.observed_txs()?;
        ctx.verified_fee_log_hashes()?;
        let (real_fee, shadow_fee) = (post_tx_fee(&real.actions)?, post_tx_fee(&shadow.actions)?);
        if (real_fee.token, real_fee.payer, real_fee.max)
            != (shadow_fee.token, shadow_fee.payer, shadow_fee.max)
        {
            return None;
        }
        // With the same charge and refund, a gas-derived hook leaves the same fee state, so any
        // remaining difference comes from the hook itself.
        if real_fee.charged == shadow_fee.charged {
            return None;
        }
        // A different fee route cannot be inferred from a changed fee amount alone.
        let route = |actions: &[StorageAction], mut amount: U256| -> Option<Vec<U256>> {
            let mut keys = Vec::new();
            for action in actions {
                if let StorageAction::FeeAmmSwap(key, _, amount_in) = action {
                    if *amount_in != amount || keys.len() == 2 {
                        return None;
                    }
                    keys.push(*key);
                    amount = compute_amount_out(amount).ok()?;
                }
            }
            Some(keys)
        };
        if route(real_fee.actions, real_fee.charged)?
            != route(shadow_fee.actions, shadow_fee.charged)?
        {
            return None;
        }
        let (real_before, real_after) = fee_hook_slot_change(real_fee.actions, address, slot)?;
        let (shadow_before, shadow_after) =
            fee_hook_slot_change(shadow_fee.actions, address, slot)?;
        // Compare application state at hook entry, not merely the transaction's initial state.
        if real_before != shadow_before {
            return None;
        }
        let real_net = real.changes.account(address).storage(slot)?;
        let shadow_net = shadow.changes.account(address).storage(slot)?;
        (real_net.0 == shadow_net.0 && real_net.1 == real_after && shadow_net.1 == shadow_after)
            .then_some(())
    },
};

const T13_ZONE_RUNTIME_UPGRADE: Expectation = Expectation {
    id: "t13.zone-runtime-upgrade",
    check: |ctx, field| {
        shadow_runtime_upgrade(ctx, field, |address| match address {
            ZONE_PORTAL_IMPL_ADDRESS => Some((vec![ZONE_PORTAL_RUNTIME], T13_ZONE_PORTAL_RUNTIME)),
            ZONE_VERIFIER_ADDRESS => Some((vec![ZONE_VERIFIER_RUNTIME], T13_ZONE_VERIFIER_RUNTIME)),
            ZONE_MESSENGER_ADDRESS => {
                Some((vec![ZONE_MESSENGER_RUNTIME], T13_ZONE_MESSENGER_RUNTIME))
            }
            _ => None,
        })
    },
};

const T14_ZONE_PORTAL_UPGRADE: Expectation = Expectation {
    id: "t14.zone-portal-upgrade",
    check: |ctx, field| {
        // T14 replaces only the portal runtime. A shadow arm that skips T13 upgrades directly.
        shadow_runtime_upgrade(ctx, field, |address| {
            (address == ZONE_PORTAL_IMPL_ADDRESS).then(|| {
                (
                    vec![ZONE_PORTAL_RUNTIME, T13_ZONE_PORTAL_RUNTIME],
                    T14_ZONE_PORTAL_RUNTIME,
                )
            })
        })
    },
};

const T15_ZONE_RUNTIME_UPGRADE: Expectation = Expectation {
    id: "t15.zone-runtime-upgrade",
    check: |ctx, field| {
        // T15 replaces only the portal runtime. A shadow arm that skips earlier upgrades moves
        // directly to it.
        shadow_runtime_upgrade(ctx, field, |address| {
            (address == ZONE_PORTAL_IMPL_ADDRESS).then(|| {
                (
                    vec![
                        ZONE_PORTAL_RUNTIME,
                        T13_ZONE_PORTAL_RUNTIME,
                        T14_ZONE_PORTAL_RUNTIME,
                    ],
                    T15_ZONE_PORTAL_RUNTIME,
                )
            })
        })
    },
};

/// Accepts a pre-block code change made by the shadow arm, from empty code or one of the selected
/// old runtimes to the selected new runtime.
fn shadow_runtime_upgrade(
    ctx: &Context<'_>,
    field: &Field,
    runtimes: impl FnOnce(Address) -> Option<(Vec<Bytes>, Bytes)>,
) -> Option<()> {
    if ctx.boundary != Boundary::PreBlock || field.name != "code" || field.slot.is_some() {
        return None;
    }
    let address = field.address?;
    let (old_runtimes, new_runtime) = runtimes(address)?;
    let Arms { real, shadow } = ctx.evidence.pre_block.as_ref()?;

    // The canonical arm may activate an earlier expected runtime on this block, while the shadow
    // arm advances directly to the candidate runtime.
    if real
        .account(address)
        .info(|info| info.code_hash)
        .is_some_and(|(_, after)| !old_runtimes.iter().any(|old| after == keccak256(old)))
    {
        return None;
    }
    let change = shadow.account(address).0?;
    let after = change.after.as_ref()?.code_hash;

    (change.before.as_ref().is_none_or(|info| {
        info.is_empty_code_hash()
            || old_runtimes
                .iter()
                .any(|old| info.code_hash == keccak256(old))
    }) && after == keccak256(&new_runtime))
    .then_some(())
}

/// Fork-specific checks are ordered oldest-first; baseline fee normalization is added separately.
const REGISTRY: &[(TempoHardfork, &[Expectation])] = &[
    (TempoHardfork::T13, &[T13_ZONE_RUNTIME_UPGRADE]),
    (TempoHardfork::T14, &[T14_ZONE_PORTAL_UPGRADE]),
    (TempoHardfork::T15, &[T15_ZONE_RUNTIME_UPGRADE]),
];

pub(crate) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    // Gas-derived fee differences can occur for any fork pair.
    std::iter::once(&FEE_STATE)
        .chain(
            REGISTRY
                .iter()
                .filter(|(fork, _)| *fork > canonical && *fork <= candidate)
                .flat_map(|(_, rules)| *rules),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        super::{
            Block, Failure, RecoveredBlock, ReplayOutcome,
            analysis::{AccountChange, MAX_SAMPLES, Report, StepChanges},
            tests::missing_account,
        },
        *,
    };
    use alloy_primitives::{Address, KECCAK256_EMPTY, Signature};
    use evm2::evm::AccountInfo;
    use tempo_precompiles::storage::FeeHook;
    use tempo_primitives::{TempoTransaction, transaction::Call};

    fn changes(address: Address, change: AccountChange) -> StepChanges {
        StepChanges([(address, change)].into())
    }

    fn code_change(before: Option<AccountInfo>, code_hash: B256) -> AccountChange {
        AccountChange {
            before,
            after: Some(AccountInfo {
                code_hash,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn accepts_pre_block(
        rule: &Expectation,
        field: &Field,
        real: StepChanges,
        shadow: StepChanges,
    ) -> bool {
        let evidence = Evidence {
            pre_block: Some(Arms { real, shadow }),
            ..Default::default()
        };
        let ctx = Context {
            boundary: Boundary::PreBlock,
            evidence: &evidence,
            base_fee: None,
            tx: None,
        };
        (rule.check)(&ctx, field).is_some()
    }

    #[test]
    fn accepts_exact_bytecode_upgrades() {
        let address = ZONE_PORTAL_IMPL_ADDRESS;
        let step = |before, code_hash| changes(address, code_change(before, code_hash));
        let unchanged = || step(Some(AccountInfo::default()), KECCAK256_EMPTY);
        let upgraded = |runtime: &Bytes| step(None, keccak256(runtime));
        let code = Field {
            name: "code",
            address: Some(address),
            slot: None,
            fee_associated: false,
        };
        let t13 = &T13_ZONE_RUNTIME_UPGRADE;
        let t14 = &T14_ZONE_PORTAL_UPGRADE;
        assert!(accepts_pre_block(
            t13,
            &code,
            unchanged(),
            upgraded(&T13_ZONE_PORTAL_RUNTIME)
        ));
        assert!(accepts_pre_block(
            t14,
            &code,
            unchanged(),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(accepts_pre_block(
            t14,
            &code,
            upgraded(&T13_ZONE_PORTAL_RUNTIME),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(!accepts_pre_block(
            t14,
            &code,
            step(None, keccak256("unexpected")),
            upgraded(&T14_ZONE_PORTAL_RUNTIME)
        ));
        assert!(!accepts_pre_block(
            t13,
            &code,
            unchanged(),
            upgraded(&ZONE_PORTAL_RUNTIME)
        ));

        let verifier = Field {
            address: Some(ZONE_VERIFIER_ADDRESS),
            ..code
        };
        let upgraded = || {
            changes(
                ZONE_VERIFIER_ADDRESS,
                code_change(None, keccak256(&T13_ZONE_VERIFIER_RUNTIME)),
            )
        };
        let real = StepChanges::default;
        assert!(accepts_pre_block(t13, &verifier, real(), upgraded()));
        // T14 and T15 leave the verifier on its T13 runtime.
        assert!(!accepts_pre_block(t14, &verifier, real(), upgraded()));
        assert!(!accepts_pre_block(
            &T15_ZONE_RUNTIME_UPGRADE,
            &verifier,
            real(),
            upgraded()
        ));
    }

    #[test]
    fn accepts_t15_portal_upgrade_from_any_earlier_runtime() {
        let address = ZONE_PORTAL_IMPL_ADDRESS;
        let code = Field {
            name: "code",
            address: Some(address),
            slot: None,
            fee_associated: false,
        };
        let accepts = |before: &Bytes, after: &Bytes| {
            let before = AccountInfo {
                code_hash: keccak256(before),
                ..Default::default()
            };
            let shadow = changes(address, code_change(Some(before), keccak256(after)));
            accepts_pre_block(
                &T15_ZONE_RUNTIME_UPGRADE,
                &code,
                StepChanges::default(),
                shadow,
            )
        };
        for before in [
            ZONE_PORTAL_RUNTIME,
            T13_ZONE_PORTAL_RUNTIME,
            T14_ZONE_PORTAL_RUNTIME,
        ] {
            assert!(accepts(&before, &T15_ZONE_PORTAL_RUNTIME));
        }
        assert!(!accepts(&ZONE_PORTAL_RUNTIME, &T13_ZONE_PORTAL_RUNTIME));
    }

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        let ids = |a, b| {
            between(a, b)
                .into_iter()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(T11, T12), [FEE_STATE.id]);
        assert_eq!(ids(T12, T13), [FEE_STATE.id, T13_ZONE_RUNTIME_UPGRADE.id]);
        assert_eq!(ids(T11, T13), ids(T12, T13));
        assert_eq!(ids(T13, T14), [FEE_STATE.id, T14_ZONE_PORTAL_UPGRADE.id]);
        assert_eq!(ids(T12, T14).len(), 3);
        assert_eq!(ids(T12, T12), [FEE_STATE.id]);
        assert_eq!(ids(T13, T12), [FEE_STATE.id]);
        assert_eq!(ids(T14, T15), [FEE_STATE.id, T15_ZONE_RUNTIME_UPGRADE.id]);
        assert_eq!(
            ids(T13, T15),
            [
                FEE_STATE.id,
                T14_ZONE_PORTAL_UPGRADE.id,
                T15_ZONE_RUNTIME_UPGRADE.id
            ]
        );
        assert_eq!(
            ids(T12, T15),
            [
                FEE_STATE.id,
                T13_ZONE_RUNTIME_UPGRADE.id,
                T14_ZONE_PORTAL_UPGRADE.id,
                T15_ZONE_RUNTIME_UPGRADE.id
            ]
        );
    }

    /// A block of `txs` empty transactions at a zero base fee.
    fn block(txs: usize) -> RecoveredBlock<Block> {
        let mut block = Block::default();
        block.header.inner.base_fee_per_gas = Some(0);
        block.body.transactions = vec![signed_tx(vec![]); txs];
        let senders = vec![Address::ZERO; txs];
        RecoveredBlock::new_unhashed(block, senders)
    }

    /// Complete evidence of `txs` transactions the candidate reproduced exactly.
    fn evidence(txs: usize) -> Evidence {
        Evidence {
            pre_block: Some(Arms::default()),
            txs: (0..txs).map(|_| TxEvidence::Same).collect(),
            post_block: Some(Arms::default()),
            failure: None,
        }
    }

    /// Marks transaction `index` as differing, charged `gas` in each arm, and returns both arms.
    fn differs(evidence: &mut Evidence, index: usize, gas: [u64; 2]) -> &mut Arms<ObservedTx> {
        let observed = |charged_gas| ObservedTx {
            charged_gas,
            ..Default::default()
        };
        evidence.txs[index] = TxEvidence::Differs(Box::new(Arms {
            real: observed(gas[0]),
            shadow: observed(gas[1]),
        }));
        let TxEvidence::Differs(arms) = &mut evidence.txs[index] else {
            unreachable!("set above");
        };
        arms
    }

    fn write_slot(tx: &mut ObservedTx, value: u64) {
        let address = Address::ZERO;
        let slot = U256::ZERO;
        tx.changes = changes(
            address,
            AccountChange {
                before: Some(AccountInfo::default()),
                after: Some(AccountInfo::default()),
                storage: [(slot, (U256::from(1_000), U256::from(value)))].into(),
                ..Default::default()
            },
        );
        tx.actions = post_fee(U256::ZERO, 0);
        tx.actions.insert(
            3,
            StorageAction::Sstore(address, slot, U256::from(1_000), U256::from(value)),
        );
    }

    #[test]
    fn equal_boundaries_do_not_invoke_rules() {
        let rule = Expectation {
            id: "must-not-run",
            check: |_, _| panic!("equal values"),
        };
        let mut evidence = evidence(2);
        differs(&mut evidence, 1, [21_000, 21_000]);
        let report = Report::analyze(&evidence, &[&rule], &block(2));
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Match);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
    }

    #[test]
    fn gas_only_difference_does_not_hide_unverified_fee_state() {
        let mut evidence = evidence(2);
        differs(&mut evidence, 0, [21_000, 21_200]);
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Match);

        write_slot(&mut differs(&mut evidence, 0, [21_000, 21_200]).shadow, 800);
        let report = Report::analyze(&evidence, &[&FEE_STATE], &block(2));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Findings);
        let field = report.samples[0].1.field;
        assert_eq!(field.name, "storage");
        assert_eq!(field.address, Some(Address::ZERO));
        assert_eq!(field.slot, Some(U256::ZERO));
        assert!(field.fee_associated);
    }

    /// Charges `tx` its gas from a 5_000 maximum while its post-fee hook writes `value` to slot
    /// zero.
    fn fee_hook(tx: &mut ObservedTx, value: u64) {
        let max = U256::from(5_000);
        write_slot(tx, value);
        tx.actions[0] = StorageAction::Marker(FeeHook::PreTx {
            payer: Address::ZERO,
            token: Address::ZERO,
            amount: max,
        });
        tx.actions[2] = StorageAction::Marker(FeeHook::PostTx {
            refund: max - U256::from(tx.charged_gas),
            log: 0,
        });
        tx.fee_normalized = Some(B256::repeat_byte(1));
    }

    #[test]
    fn fee_state_rejects_hook_change_with_equal_charge() {
        let block = block(1);
        let analyze = |gas, values: [u64; 2]| {
            let mut evidence = evidence(1);
            let arms = differs(&mut evidence, 0, gas);
            fee_hook(&mut arms.real, values[0]);
            fee_hook(&mut arms.shadow, values[1]);
            let report = Report::analyze(&evidence, &[&FEE_STATE], &block);
            (report.unexplained, report.outcome(&evidence))
        };
        assert_eq!(
            analyze([1_000, 1_200], [2_000, 2_200]),
            (0, ReplayOutcome::Expected)
        );
        assert_eq!(
            analyze([1_000, 1_000], [2_000, 3_000]),
            (1, ReplayOutcome::Findings)
        );
    }

    fn post_fee(charged: U256, log: usize) -> Vec<StorageAction> {
        vec![
            StorageAction::Marker(FeeHook::PreTx {
                payer: Address::ZERO,
                token: Address::ZERO,
                amount: charged,
            }),
            StorageAction::Marker(FeeHook::End),
            StorageAction::Marker(FeeHook::PostTx {
                refund: U256::ZERO,
                log,
            }),
            StorageAction::Marker(FeeHook::End),
        ]
    }

    fn signed_tx(calls: Vec<Call>) -> TempoTxEnvelope {
        TempoTransaction {
            max_priority_fee_per_gas: 1_000_000_000_000,
            max_fee_per_gas: 1_000_000_000_000,
            gas_limit: 35_212,
            calls,
            ..Default::default()
        }
        .into_signed(Signature::test_signature().into())
        .into()
    }

    #[test]
    fn only_verified_fee_amount_is_masked_in_ordered_receipt_logs() {
        let original = B256::repeat_byte(1);
        let changed = B256::repeat_byte(2);
        let normalized = B256::repeat_byte(3);
        let mut evidence = evidence(1);
        let arms = differs(&mut evidence, 0, [1_000, 1_200]);
        for (tx, amount, hash) in [
            (&mut arms.real, 1_000, original),
            (&mut arms.shadow, 1_200, changed),
        ] {
            tx.receipt_logs_hash = hash;
            tx.actions = post_fee(U256::from(amount), 0);
            tx.fee_normalized = Some(normalized);
        }
        let block = block(1);
        let report = |evidence: &Evidence| Report::analyze(evidence, &[], &block);
        assert_eq!(report(&evidence).outcome(&evidence), ReplayOutcome::Match);

        fn shadow(evidence: &mut Evidence) -> &mut ObservedTx {
            match &mut evidence.txs[0] {
                TxEvidence::Differs(arms) => &mut arms.shadow,
                _ => unreachable!("set above"),
            }
        }
        shadow(&mut evidence).fee_normalized = Some(B256::repeat_byte(4));
        assert_eq!(report(&evidence).unexplained, 1);
        shadow(&mut evidence).fee_normalized = Some(normalized);
        shadow(&mut evidence).actions = post_fee(U256::ZERO, 0);
        assert_eq!(report(&evidence).unexplained, 1);
        shadow(&mut evidence).actions = post_fee(U256::from(1_200), 1);
        assert_eq!(report(&evidence).unexplained, 1);
    }

    #[test]
    fn first_accepting_rule_owns_attribution() {
        let first = Expectation {
            id: "test.first-output",
            check: |_, field| (field.name == "output").then_some(()),
        };
        let second = Expectation {
            id: "test.second-output",
            check: |_, field| (field.name == "output").then_some(()),
        };
        let unreachable = Expectation {
            id: "must-not-run",
            check: |_, _| panic!("already accepted"),
        };
        let mut evidence = evidence(1);
        differs(&mut evidence, 0, [21_000, 21_200])
            .shadow
            .output_hash = B256::repeat_byte(1);
        for rules in [
            [&first, &second, &unreachable],
            [&second, &first, &unreachable],
        ] {
            let report = Report::analyze(&evidence, &rules, &block(1));
            assert_eq!(report.unexplained, 0);
            assert_eq!(report.expected, [(rules[0].id, 1)].into());
        }
    }

    #[test]
    fn uncaptured_shadow_reads_are_inconclusive() {
        let mut evidence = evidence(2);
        evidence.txs[0] = TxEvidence::Failed(missing_account());
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.unexplained, 0);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Inconclusive);

        let evidence = Evidence {
            failure: Some(Failure {
                boundary: Boundary::PreBlock,
                error: missing_account(),
            }),
            ..Default::default()
        };
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.boundaries_not_evaluated, 4);
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Inconclusive);
    }

    #[test]
    fn rejected_shadow_tx_does_not_hide_later_transaction_findings() {
        let mut evidence = evidence(2);
        evidence.txs[0] = TxEvidence::Failed(eyre::eyre!("rejected"));
        differs(&mut evidence, 1, [21_000, 21_000]).shadow.outcome = (1, "Revert".into());

        let report = Report::analyze(&evidence, &[], &block(2));

        assert_eq!(report.unexplained, 2);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
        assert_eq!(report.samples[0].1.field.name, "execution");
        assert_eq!(report.outcome(&evidence), ReplayOutcome::Findings);
    }

    #[test]
    fn created_code_is_compared_even_when_both_accounts_are_created() {
        let mut evidence = evidence(1);
        let arms = differs(&mut evidence, 0, [21_000, 21_000]);
        for (tx, hash) in [
            (&mut arms.real, B256::repeat_byte(1)),
            (&mut arms.shadow, B256::repeat_byte(2)),
        ] {
            tx.changes = changes(Address::ZERO, code_change(None, hash));
        }
        let report = Report::analyze(&evidence, &[], &block(1));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "code");
    }

    #[test]
    fn sampling_does_not_truncate_counts() {
        let mut evidence = evidence(20);
        for index in 0..20 {
            differs(&mut evidence, index, [21_000, 21_000])
                .shadow
                .output_hash = B256::repeat_byte(1);
        }
        let report = Report::analyze(&evidence, &[], &block(20));
        assert_eq!(report.unexplained, 20);
        assert_eq!(report.samples.len(), MAX_SAMPLES);
        assert_eq!(report.boundaries_evaluated, 22);
    }

    #[test]
    fn storage_reset_is_compared_without_enumerated_slots() {
        let mut evidence = evidence(2);
        differs(&mut evidence, 0, [21_000, 21_000]).shadow.changes = changes(
            Address::ZERO,
            AccountChange {
                before: Some(AccountInfo::default()),
                after: Some(AccountInfo::default()),
                storage_reset: true,
                ..Default::default()
            },
        );
        let report = Report::analyze(&evidence, &[], &block(2));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "storage_reset");
    }
}
