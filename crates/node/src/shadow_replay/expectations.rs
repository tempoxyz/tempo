//! Native baseline fee expectation and selection of the embedded data-driven rules.
//!
//! Checks receive one difference, not a transaction, and either accept it or leave it unexplained.

use super::analysis::{AccountDelta, Field};
use crate::shadow_replay::{
    Boundary, Evidence, ObservedTx,
    fees::post_fee_slot_change,
    rules::{self, Rule},
};
use alloy::{
    consensus::Transaction as _,
    primitives::{Address, B256, Bytes, TxKind, U256},
};
use std::sync::LazyLock;
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::precompiles::*;
use tempo_precompiles::{
    abi_decoder_config_for_spec, storage::StorageAction, tip_fee_manager::amm::compute_amount_out,
};
use tempo_primitives::{
    TempoAddressExt as _, TempoTxEnvelope, transaction::calc_gas_balance_spending,
};

/// A check that may accept one difference: native Rust or an embedded data rule.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Expectation {
    Native {
        id: &'static str,
        check: fn(&Context<'_>, &Field) -> Option<()>,
    },
    Rule(&'static Rule),
}

impl Expectation {
    pub(super) fn id(&self) -> &'static str {
        match self {
            Self::Native { id, .. } => id,
            Self::Rule(rule) => &rule.id,
        }
    }

    pub(super) fn accepts(&self, ctx: &Context<'_>, field: &Field) -> bool {
        match self {
            Self::Native { check, .. } => check(ctx, field).is_some(),
            Self::Rule(rule) => rule.accepts(ctx, field),
        }
    }
}

/// An envelope target and calldata; it may not have been reached during execution.
pub(super) type EnvelopeCall<'a> = (TxKind, &'a Bytes);

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
    pub(super) fn observed_txs(&self) -> Option<(&ObservedTx, &ObservedTx)> {
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
const FEE_STATE: Expectation = Expectation::Native {
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

/// Returns whether T11 rejects `calldata` for the Tempo precompile at `address` only because of
/// trailing bytes, which T12 accepts per TIP-1116.
pub(super) fn rejects_only_trailing_bytes(to: Address, calldata: &[u8]) -> bool {
    fn check<C: alloy::sol_types::SolInterface>(calldata: &[u8]) -> Option<bool> {
        let decodes =
            |spec| C::abi_decode_with_config(calldata, abi_decoder_config_for_spec(spec)).is_ok();
        C::valid_selector(*calldata.first_chunk::<4>()?)
            .then(|| decodes(TempoHardfork::T12) && !decodes(TempoHardfork::T11))
    }

    // Mirrors the interfaces routed by each precompile's `dispatch!`.
    match to {
        TIP20_FACTORY_ADDRESS => check::<ITIP20Factory::ITIP20FactoryCalls>(calldata),
        TIP20_CHANNEL_RESERVE_ADDRESS => {
            check::<ITIP20ChannelReserve::ITIP20ChannelReserveCalls>(calldata)
        }
        ADDRESS_REGISTRY_ADDRESS => check::<IAddressRegistry::IAddressRegistryCalls>(calldata),
        TIP403_REGISTRY_ADDRESS => check::<ITIP403Registry::ITIP403RegistryCalls>(calldata),
        TIP_FEE_MANAGER_ADDRESS => check::<IFeeManager::IFeeManagerCalls>(calldata)
            .or_else(|| check::<ITIPFeeAMM::ITIPFeeAMMCalls>(calldata)),
        STABLECOIN_DEX_ADDRESS => check::<IStablecoinDEX::IStablecoinDEXCalls>(calldata),
        NONCE_PRECOMPILE_ADDRESS => check::<INonce::INonceCalls>(calldata),
        VALIDATOR_CONFIG_ADDRESS => check::<IValidatorConfig::IValidatorConfigCalls>(calldata),
        ACCOUNT_KEYCHAIN_ADDRESS => check::<IAccountKeychain::IAccountKeychainCalls>(calldata),
        VALIDATOR_CONFIG_V2_ADDRESS => {
            check::<IValidatorConfigV2::IValidatorConfigV2Calls>(calldata)
        }
        SIGNATURE_VERIFIER_ADDRESS => {
            check::<ISignatureVerifier::ISignatureVerifierCalls>(calldata)
        }
        RECEIVE_POLICY_GUARD_ADDRESS => {
            check::<IReceivePolicyGuard::IReceivePolicyGuardCalls>(calldata)
        }
        STORAGE_CREDITS_ADDRESS => check::<IStorageCredits::IStorageCreditsCalls>(calldata),
        CURRENT_COMMITTEE_ADDRESS => check::<ICurrentCommittee::ICurrentCommitteeCalls>(calldata),
        ZONE_FACTORY_ADDRESS => check::<IZoneFactory::IZoneFactoryCalls>(calldata),
        address if address.is_tip20() => check::<ITIP20::ITIP20Calls>(calldata)
            .or_else(|| check::<IRolesAuth::IRolesAuthCalls>(calldata)),
        _ => None,
    }
    .unwrap_or(false)
}

/// Embedded rule files by introducing hardfork, oldest first; attribution follows this order.
const RULE_FILES: &[(TempoHardfork, &str)] = &[
    (TempoHardfork::T12, include_str!("expectations/t12.json")),
    (TempoHardfork::T13, include_str!("expectations/t13.json")),
];

static RULES: LazyLock<Vec<(TempoHardfork, Rule)>> =
    LazyLock::new(|| rules::load(RULE_FILES).expect("failed to load embedded expectations"));

pub(crate) fn between(canonical: TempoHardfork, candidate: TempoHardfork) -> Vec<Expectation> {
    // Gas-derived fee differences can occur for any fork pair, not just when T12 is new.
    std::iter::once(FEE_STATE)
        .chain(
            RULES
                .iter()
                .filter(|(hardfork, _)| *hardfork > canonical && *hardfork <= candidate)
                .map(|(_, rule)| Expectation::Rule(rule)),
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
    use alloy::primitives::{KECCAK256_EMPTY, Signature, address, keccak256};
    use reth_revm::{
        context::result::ResultGas,
        context_interface::cfg::gas::CALL_STIPEND,
        db::states::{StorageSlot, TransitionAccount},
        state::AccountInfo,
    };
    use tempo_contracts::zones::{
        T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
        ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
    };
    use tempo_primitives::{
        TempoTransaction,
        transaction::{AASigned, Call, PrimitiveSignature, TempoSignature},
    };

    fn rule(id: &str) -> Expectation {
        Expectation::Rule(&RULES.iter().find(|(_, rule)| rule.id == id).unwrap().1)
    }

    #[test]
    fn accepts_exact_bytecode_upgrades() {
        let rules = between(TempoHardfork::T12, TempoHardfork::T13);
        for (address, old, new) in [
            (
                ZONE_PORTAL_IMPL_ADDRESS,
                ZONE_PORTAL_RUNTIME,
                T13_ZONE_PORTAL_RUNTIME,
            ),
            (
                ZONE_VERIFIER_ADDRESS,
                ZONE_VERIFIER_RUNTIME,
                T13_ZONE_VERIFIER_RUNTIME,
            ),
            (
                ZONE_MESSENGER_ADDRESS,
                ZONE_MESSENGER_RUNTIME,
                T13_ZONE_MESSENGER_RUNTIME,
            ),
        ] {
            let transition = |before: Option<B256>, after| {
                let info = |code_hash| AccountInfo {
                    code_hash,
                    ..Default::default()
                };
                let mut state = reth_revm::db::TransitionState::default();
                state.transitions.insert(
                    address,
                    TransitionAccount {
                        previous_info: before.map(info),
                        info: Some(info(after)),
                        ..Default::default()
                    },
                );
                Evidence {
                    pre_block: Some(state),
                    ..Default::default()
                }
            };
            let accepts = |real: &Evidence, shadow: &Evidence| {
                let ctx = Context {
                    boundary: Boundary::PreBlock,
                    real,
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
                rules.iter().any(|rule| rule.accepts(&ctx, &code))
            };
            let unchanged = transition(Some(KECCAK256_EMPTY), KECCAK256_EMPTY);
            let (old, new) = (keccak256(old), keccak256(new));
            assert!(accepts(&unchanged, &transition(None, new)));
            assert!(accepts(&unchanged, &transition(Some(old), new)));
            assert!(!accepts(&unchanged, &transition(None, old)));
            assert!(!accepts(
                &unchanged,
                &transition(Some(B256::repeat_byte(1)), new)
            ));
            assert!(!accepts(&transition(None, old), &transition(None, new)));
        }
    }

    /// Every file in `expectations/` is embedded exactly once, under the hardfork it is named for.
    #[test]
    fn rule_files_match_the_directory() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/shadow_replay/expectations"
        );
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        let mut expected: Vec<_> = RULE_FILES
            .iter()
            .map(|(hardfork, _)| format!("{}.json", hardfork.to_string().to_lowercase()))
            .collect();
        expected.sort();
        assert_eq!(names, expected);
        assert!(RULE_FILES.windows(2).all(|w| w[0].0 < w[1].0));
        for (hardfork, json) in RULE_FILES {
            let path = format!("{dir}/{}.json", hardfork.to_string().to_lowercase());
            assert_eq!(std::fs::read_to_string(path).unwrap(), *json);
        }
        assert!(!RULES.is_empty());
    }

    #[test]
    fn selects_only_newly_active_forks() {
        use TempoHardfork::*;
        let ids = |a, b| {
            between(a, b)
                .into_iter()
                .map(|rule| rule.id())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(T11, T12),
            [
                FEE_STATE.id(),
                "t12.allow-abi-suffix",
                "t12.tip20-channel-reserve",
                "t12.stablecoin-dex",
                "t12.sstore-sentry",
            ]
        );
        assert_eq!(
            ids(T12, T13),
            [
                FEE_STATE.id(),
                "t13.zone-runtime-upgrade",
                "t13.zone-verifier-upgrade",
                "t13.zone-messenger-upgrade"
            ]
        );
        let mut combined = ids(T11, T12);
        combined.extend(ids(T12, T13).into_iter().skip(1)); // baseline runs only once
        assert_eq!(ids(T11, T13), combined);
        assert_eq!(ids(T12, T12), [FEE_STATE.id()]);
        assert_eq!(ids(T13, T12), [FEE_STATE.id()]);
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
                        gas: ResultGas::default().with_total_gas_spent(gas_used),
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
        let rule = Expectation::Native {
            id: "must-not-run",
            check: |_, _| panic!("equal values"),
        };
        let real = evidence(&[21_000, 21_000]);
        let report = Report::analyze(&real, &real, &[rule], &block(vec![]));
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
        let report = Report::analyze(&real, &shadow, &[FEE_STATE], &block(vec![]));
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
        let field = report.samples[0].1.field;
        assert_eq!(field.name, "storage");
        assert_eq!(field.address, Some(Address::ZERO));
        assert_eq!(field.slot, Some(U256::ZERO));
        assert!(field.fee_associated);
    }

    fn signed_tx(calls: Vec<Call>) -> TempoTxEnvelope {
        AASigned::new_unhashed(
            TempoTransaction {
                max_priority_fee_per_gas: 1_000_000_000_000,
                max_fee_per_gas: 1_000_000_000_000,
                gas_limit: 35_212,
                calls,
                ..Default::default()
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        )
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
        let first = Expectation::Native {
            id: "test.first-output",
            check: |_, field| (field.name == "output").then_some(()),
        };
        let second = Expectation::Native {
            id: "test.second-output",
            check: |_, field| (field.name == "output").then_some(()),
        };
        let unreachable = Expectation::Native {
            id: "must-not-run",
            check: |_, _| panic!("already accepted"),
        };
        let real = evidence(&[21_000]);
        let mut shadow = evidence(&[21_200]);
        tx_mut(&mut shadow, 0).output_hash = B256::repeat_byte(1);
        for rules in [[first, second, unreachable], [second, first, unreachable]] {
            let report = Report::analyze(&real, &shadow, &rules, &block(vec![]));
            assert_eq!(report.unexplained, 0);
            assert_eq!(report.expected, [(rules[0].id(), 1)].into());
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

    #[test]
    fn sentry_expectation_requires_low_gas_headroom_regardless_of_calls() {
        let call = Call {
            to: TxKind::Call(Address::repeat_byte(0x11)),
            value: U256::ZERO,
            input: Default::default(),
        };
        let mut real = evidence(&[32_366, 21_000]);
        let mut shadow = evidence(&[35_212, 21_000]);
        // Refunds lower receipt gas used, but do not increase gas available during execution.
        tx_mut(&mut real, 0).gas = ResultGas::default()
            .with_total_gas_spent(35_166)
            .with_refunded(2_800);
        let halted = tx_mut(&mut shadow, 0);
        halted.outcome = TxOutcome::Halt;
        halted.receipt_logs_hash = B256::repeat_byte(1);
        halted.output_hash = KECCAK256_EMPTY;
        write_slot(tx_mut(&mut real, 0), 900);
        write_slot(tx_mut(&mut shadow, 0), 800);

        let block = block(vec![signed_tx(vec![call.clone()])]);
        let rules = between(TempoHardfork::T11, TempoHardfork::T12);
        let report = Report::analyze(&real, &shadow, &rules, &block);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
        assert_eq!(report.expected, [("t12.sstore-sentry", 4)].into());

        for gas_spent in [35_212 - CALL_STIPEND, 35_212] {
            tx_mut(&mut real, 0).gas.set_total_gas_spent(gas_spent);
            assert_eq!(
                Report::analyze(&real, &shadow, &rules, &block).outcome(&shadow),
                ReplayOutcome::Expected
            );
        }
        for gas_spent in [35_212 - CALL_STIPEND - 1, 35_213] {
            tx_mut(&mut real, 0).gas.set_total_gas_spent(gas_spent);
            assert_eq!(
                Report::analyze(&real, &shadow, &rules, &block).unexplained,
                4
            );
        }
        tx_mut(&mut real, 0).gas.set_total_gas_spent(35_166);
        for outcome in [TxOutcome::Success, TxOutcome::Revert] {
            tx_mut(&mut shadow, 0).outcome = outcome;
            assert!(Report::analyze(&real, &shadow, &rules, &block).unexplained > 0);
        }
        tx_mut(&mut shadow, 0).outcome = TxOutcome::Halt;
        tx_mut(&mut real, 0).outcome = TxOutcome::Revert;
        assert_eq!(
            Report::analyze(&real, &shadow, &rules, &block).unexplained,
            4
        );
        tx_mut(&mut real, 0).outcome = TxOutcome::Success;

        let field = Field {
            name: "outcome",
            address: None,
            slot: None,
            fee_associated: false,
        };
        for calls in [
            vec![call.clone()],
            vec![call.clone(), call.clone()],
            vec![Call {
                to: TxKind::Create,
                ..call.clone()
            }],
            vec![Call {
                to: TxKind::Call(address!("2cacae8e22418e65dcf7651c67aebe6288eb8243")),
                ..call.clone()
            }],
            vec![Call {
                to: TxKind::Call(address!("20c0000000000000000000000000000000000001")),
                ..call
            }],
        ] {
            let tx = signed_tx(calls);
            let ctx = Context {
                boundary: Boundary::Transaction(0),
                real: &real,
                shadow: &shadow,
                base_fee: None,
                tx: Some(&tx),
            };
            assert!(rule("t12.sstore-sentry").accepts(&ctx, &field));
        }

        // No acceptance outside the activation boundary or at another transaction.
        let rules = between(TempoHardfork::T12, TempoHardfork::T12);
        assert_eq!(
            Report::analyze(&real, &shadow, &rules, &block).unexplained,
            4
        );
        tx_mut(&mut shadow, 1).outcome = TxOutcome::Halt;
        let rules = between(TempoHardfork::T11, TempoHardfork::T12);
        assert_eq!(
            Report::analyze(&real, &shadow, &rules, &block).unexplained,
            1
        );
    }
}
