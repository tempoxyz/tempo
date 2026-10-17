//! Reviewed baseline and fork-specific expectations for shadow replay.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::analysis::{AccountDelta, Field};
use crate::shadow_replay::{Boundary, Evidence, ObservedTx, fees::post_fee_slot_change};
use alloy::{
    consensus::Transaction as _,
    primitives::{B256, KECCAK256_EMPTY, U256, keccak256},
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::*,
    zones::{
        T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
        ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
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
    pub real: &'a Evidence,
    pub shadow: &'a Evidence,
    pub base_fee: Option<u64>,
    pub tx: Option<&'a TempoTxEnvelope>,
}

impl Context<'_> {
    /// Returns the observed transaction pair as `(real, shadow)` at this boundary.
    fn observed_txs(&self) -> Option<(&ObservedTx, &ObservedTx)> {
        let Boundary::Transaction(index) = self.boundary else {
            return None;
        };
        Some((
            self.real.txs.get(index)?.as_ref().ok()?,
            self.shadow.txs.get(index)?.as_ref().ok()?,
        ))
    }

    /// Returns normalized log hashes only when both fee transfers match their gas charges.
    /// Normalization already checked each logged amount against its recorded hook charge.
    pub(super) fn verified_fee_log_hashes(&self) -> Option<(B256, B256)> {
        let (real, shadow) = self.observed_txs()?;
        let (real_hash, real_amount) = (real.fee_normalized?, real.fee.post_tx_transfer?.3);
        let (shadow_hash, shadow_amount) = (shadow.fee_normalized?, shadow.fee.post_tx_transfer?.3);
        let price = self.tx?.effective_gas_price(self.base_fee);
        (real.fee.log_ranges == shadow.fee.log_ranges
            && real_amount == calc_gas_balance_spending(real.gas.tx_gas_used(), price)
            && shadow_amount == calc_gas_balance_spending(shadow.gas.tx_gas_used(), price))
        .then_some((real_hash, shadow_hash))
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
        let (real_log, real_token, real_payer, real_charge, real_refund) =
            real.fee.post_tx_transfer?;
        let (shadow_log, shadow_token, shadow_payer, shadow_charge, shadow_refund) =
            shadow.fee.post_tx_transfer?;
        if (real_log, real_token, real_payer) != (shadow_log, shadow_token, shadow_payer) {
            return None;
        }
        let max = real.fee.pre_tx_max?;
        if shadow.fee.pre_tx_max != Some(max)
            || max.checked_sub(real_charge) != Some(real_refund)
            || max.checked_sub(shadow_charge) != Some(shadow_refund)
        {
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
        if route(&real.fee.post_tx_actions, real_charge)?
            != route(&shadow.fee.post_tx_actions, shadow_charge)?
        {
            return None;
        }
        let (real_before, real_after) =
            post_fee_slot_change(&real.fee.post_tx_actions, address, slot)?;
        let (shadow_before, shadow_after) =
            post_fee_slot_change(&shadow.fee.post_tx_actions, address, slot)?;
        // Compare application state at hook entry, not merely the transaction's initial state.
        if real_before != shadow_before {
            return None;
        }
        let real_net = AccountDelta(real.state.transitions.get(&address)).storage(slot)?;
        let shadow_net = AccountDelta(shadow.state.transitions.get(&address)).storage(slot)?;
        (real_net.0 == shadow_net.0 && real_net.1 == real_after && shadow_net.1 == shadow_after)
            .then_some(())
    },
};

const T13_ZONE_RUNTIME_UPGRADE: Expectation = Expectation {
    id: "t13.zone-runtime-upgrade",
    check: |ctx, field| {
        if ctx.boundary != Boundary::PreBlock || field.name != "code" || field.slot.is_some() {
            return None;
        }
        let address = field.address?;
        let (old_runtime, new_runtime) = match address {
            ZONE_PORTAL_IMPL_ADDRESS => (ZONE_PORTAL_RUNTIME, T13_ZONE_PORTAL_RUNTIME),
            ZONE_VERIFIER_ADDRESS => (ZONE_VERIFIER_RUNTIME, T13_ZONE_VERIFIER_RUNTIME),
            ZONE_MESSENGER_ADDRESS => (ZONE_MESSENGER_RUNTIME, T13_ZONE_MESSENGER_RUNTIME),
            _ => return None,
        };
        let real = ctx.real.pre_block.as_ref()?;
        let shadow = ctx.shadow.pre_block.as_ref()?;

        // The canonical arm must not change code. The shadow arm activates the new bytecode.
        if AccountDelta(real.transitions.get(&address))
            .info(|info| info.code_hash)
            .is_some()
        {
            return None;
        }
        let transition = shadow.transitions.get(&address)?;
        let before = transition
            .previous_info
            .as_ref()
            .map_or(KECCAK256_EMPTY, |info| info.code_hash);
        let after = transition.info.as_ref()?.code_hash;

        ((before == KECCAK256_EMPTY || before == keccak256(&old_runtime))
            && after == keccak256(&new_runtime))
        .then_some(())
    },
};

/// Fork-specific checks are ordered oldest-first; baseline fee normalization is added separately.
const REGISTRY: &[(TempoHardfork, &[Expectation])] =
    &[(TempoHardfork::T13, &[T13_ZONE_RUNTIME_UPGRADE])];

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
        super::{Block, RecoveredBlock, ReplayOutcome, TransitionState, TxOutcome},
        *,
    };
    use crate::shadow_replay::analysis::{MAX_SAMPLES, Report};
    use alloy::primitives::{Address, Signature};
    use evm2::evm::TxResultExt;
    use reth_revm::{
        db::states::{StorageSlot, TransitionAccount},
        state::AccountInfo,
    };
    use tempo_primitives::{TempoTransaction, transaction::Call};

    #[test]
    fn accepts_exact_bytecode_upgrades() {
        let address = ZONE_VERIFIER_ADDRESS;
        let transition = |info: Option<AccountInfo>, code_hash| {
            let mut state = reth_revm::db::TransitionState::default();
            state.transitions.insert(
                address,
                TransitionAccount {
                    previous_info: info,
                    info: Some(AccountInfo {
                        code_hash,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            );
            Evidence {
                pre_block: Some(state),
                ..Default::default()
            }
        };
        let real = transition(Some(AccountInfo::default()), KECCAK256_EMPTY);
        let ctx = |shadow| Context {
            boundary: Boundary::PreBlock,
            real: &real,
            shadow,
            base_fee: None,
            tx: None,
        };
        let code = Field {
            name: "code",
            address: Some(address),
            slot: None,
            fee_associated: false,
        };
        let upgraded = transition(None, keccak256(&T13_ZONE_VERIFIER_RUNTIME));
        assert!((T13_ZONE_RUNTIME_UPGRADE.check)(&ctx(&upgraded), &code).is_some());
        let unexpected = transition(None, keccak256(&ZONE_VERIFIER_RUNTIME));
        assert!((T13_ZONE_RUNTIME_UPGRADE.check)(&ctx(&unexpected), &code).is_none());
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
        assert_eq!(ids(T12, T12), [FEE_STATE.id]);
        assert_eq!(ids(T13, T12), [FEE_STATE.id]);
    }

    fn block(txs: Vec<TempoTxEnvelope>) -> RecoveredBlock<Block> {
        let mut block = Block::default();
        block.header.inner.base_fee_per_gas = Some(0);
        block.body.transactions = txs;
        let senders = vec![Address::ZERO; block.body.transactions.len()];
        RecoveredBlock::new_unhashed(block, senders)
    }

    fn evidence(gas: &[u64]) -> Evidence {
        Evidence {
            pre_block: Some(TransitionState::default()),
            post_block: Some(TransitionState::default()),
            txs: gas
                .iter()
                .map(|&gas_used| {
                    Ok(ObservedTx {
                        outcome: TxOutcome::Success,
                        gas: TxResultExt {
                            total_gas_spent: gas_used,
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                })
                .collect(),
            failure: None,
        }
    }

    fn tx_mut(evidence: &mut Evidence, index: usize) -> &mut ObservedTx {
        evidence.txs[index].as_mut().unwrap()
    }

    fn write_slot(tx: &mut ObservedTx, value: u64) {
        let address = Address::ZERO;
        let slot = U256::ZERO;
        tx.state.transitions.insert(
            address,
            TransitionAccount {
                info: Some(AccountInfo::default()),
                previous_info: Some(AccountInfo::default()),
                storage: [(
                    slot,
                    StorageSlot::new_changed(U256::from(1_000), U256::from(value)),
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            },
        );
        tx.fee.slots.insert((address, slot));
    }

    #[test]
    fn equal_boundaries_do_not_invoke_rules() {
        let rule = Expectation {
            id: "must-not-run",
            check: |_, _| panic!("equal values"),
        };
        let real = evidence(&[21_000, 21_000]);
        let report = Report::analyze(&real, &real, &[&rule], &block(vec![]));
        assert_eq!(report.outcome(&real), ReplayOutcome::Match);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
    }

    #[test]
    fn gas_only_difference_does_not_hide_unverified_fee_state() {
        let real = evidence(&[21_000, 21_000]);
        let mut shadow = evidence(&[21_200, 21_000]);
        let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Match);

        write_slot(tx_mut(&mut shadow, 0), 800);
        let report = Report::analyze(&real, &shadow, &[&FEE_STATE], &block(vec![]));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
        let field = report.samples[0].1.field;
        assert_eq!(field.name, "storage");
        assert_eq!(field.address, Some(Address::ZERO));
        assert_eq!(field.slot, Some(U256::ZERO));
        assert!(field.fee_associated);
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
        let mut real = evidence(&[1_000]);
        let mut shadow = evidence(&[1_200]);
        for (tx, amount, hash) in [
            (tx_mut(&mut real, 0), 1_000, original),
            (tx_mut(&mut shadow, 0), 1_200, changed),
        ] {
            tx.receipt_logs_hash = hash;
            tx.fee.log_ranges = std::iter::once(0..1).collect();
            tx.fee.post_tx_transfer = Some((
                0,
                Address::ZERO,
                Address::ZERO,
                U256::from(amount),
                U256::ZERO,
            ));
            tx.fee_normalized = Some(normalized);
        }
        let block = block(vec![signed_tx(vec![])]);
        let report = |shadow: &Evidence| Report::analyze(&real, shadow, &[], &block);
        assert_eq!(report(&shadow).outcome(&shadow), ReplayOutcome::Match);

        let mut wrong = shadow;
        tx_mut(&mut wrong, 0).fee_normalized = Some(B256::repeat_byte(4));
        assert_eq!(report(&wrong).unexplained, 1);
        tx_mut(&mut wrong, 0).fee_normalized = Some(normalized);
        let fee = &mut tx_mut(&mut wrong, 0).fee;
        fee.post_tx_transfer.as_mut().unwrap().3 = U256::ZERO;
        assert_eq!(report(&wrong).unexplained, 1);
        let fee = &mut tx_mut(&mut wrong, 0).fee;
        fee.post_tx_transfer.as_mut().unwrap().3 = U256::from(1_000);
        tx_mut(&mut wrong, 0).fee.log_ranges = std::iter::once(1..2).collect();
        assert_eq!(report(&wrong).unexplained, 1);
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
        let real = evidence(&[21_000]);
        let mut shadow = evidence(&[21_200]);
        tx_mut(&mut shadow, 0).output_hash = B256::repeat_byte(1);
        for rules in [
            [&first, &second, &unreachable],
            [&second, &first, &unreachable],
        ] {
            let report = Report::analyze(&real, &shadow, &rules, &block(vec![]));
            assert_eq!(report.unexplained, 0);
            assert_eq!(report.expected, [(rules[0].id, 1)].into());
        }
    }

    #[test]
    fn rejected_shadow_tx_does_not_hide_later_transaction_findings() {
        let real = evidence(&[21_000, 21_000]);
        let mut shadow = evidence(&[21_000, 21_000]);
        shadow.txs[0] = Err("rejected".into());
        tx_mut(&mut shadow, 1).outcome = TxOutcome::Revert;

        let report = Report::analyze(&real, &shadow, &[], &block(vec![]));

        assert_eq!(report.unexplained, 2);
        assert_eq!(report.boundaries_evaluated, 4);
        assert_eq!(report.boundaries_not_evaluated, 0);
        assert_eq!(report.samples[0].1.field.name, "execution");
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
    }

    #[test]
    fn created_code_is_compared_even_when_both_accounts_are_created() {
        let mut real = evidence(&[21_000]);
        let mut shadow = evidence(&[21_000]);
        for (evidence, hash) in [
            (&mut real, B256::repeat_byte(1)),
            (&mut shadow, B256::repeat_byte(2)),
        ] {
            tx_mut(evidence, 0).state.transitions.insert(
                Address::ZERO,
                TransitionAccount {
                    info: Some(AccountInfo {
                        code_hash: hash,
                        ..Default::default()
                    }),
                    previous_info: None,
                    ..Default::default()
                },
            );
        }
        let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "code");
    }

    #[test]
    fn sampling_does_not_truncate_counts() {
        let real = evidence(&[21_000; 20]);
        let mut shadow = evidence(&[21_000; 20]);
        for tx in &mut shadow.txs {
            tx.as_mut().unwrap().output_hash = B256::repeat_byte(1);
        }
        let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
        assert_eq!(report.unexplained, 20);
        assert_eq!(report.samples.len(), MAX_SAMPLES);
        assert_eq!(report.boundaries_evaluated, 22);
    }

    #[test]
    fn storage_reset_is_compared_without_enumerated_slots() {
        let real = evidence(&[21_000, 21_000]);
        let mut shadow = evidence(&[21_000, 21_000]);
        tx_mut(&mut shadow, 0).state.transitions.insert(
            Address::ZERO,
            TransitionAccount {
                info: Some(AccountInfo::default()),
                previous_info: Some(AccountInfo::default()),
                storage_was_destroyed: true,
                ..Default::default()
            },
        );
        let report = Report::analyze(&real, &shadow, &[], &block(vec![]));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.samples[0].1.field.name, "storage_reset");
    }
}
