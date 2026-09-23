//! Reviewed expectations registered at the fork introducing a feature.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::analysis::{AccountDelta, Field};
use crate::shadow_replay::{Boundary, Evidence, ObservedTx, TxOutcome, fees::post_fee_slot_change};
use alloy::{
    consensus::Transaction as _,
    primitives::{Address, B256, KECCAK256_EMPTY, TxKind, U256, address, keccak256},
    sol_types::SolCall as _,
};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_contracts::{
    precompiles::*,
    zones::{
        T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
        ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
    },
};
use tempo_precompiles::{
    abi_decoder_config_for_spec, storage::StorageAction, storage_credits::StorageCredits,
    tip_fee_manager::amm::compute_amount_out,
};
use tempo_primitives::{
    TempoAddressExt as _, TempoTxEnvelope, transaction::calc_gas_balance_spending,
};

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

    /// Returns the normalized log hashes only when both fee transfers match their gas charges.
    pub(super) fn verified_fee_log_hashes(&self) -> Option<(B256, B256)> {
        let (real, shadow) = self.observed_txs()?;
        let (real_amount, real_hash) = real.fee_normalized?;
        let (shadow_amount, shadow_hash) = shadow.fee_normalized?;
        let price = self.tx?.effective_gas_price(self.base_fee);
        (real.fee.log_ranges == shadow.fee.log_ranges
            && real_amount == calc_gas_balance_spending(real.gas_used, price)
            && shadow_amount == calc_gas_balance_spending(shadow.gas_used, price))
        .then_some((real_hash, shadow_hash))
    }

    /// Borrows all top-level calls (including AA subcalls) from the canonical transaction.
    /// Internal EVM calls are not present in the transaction envelope.
    fn call(&self) -> impl Iterator<Item = (TxKind, &[u8])> + '_ {
        self.tx
            .into_iter()
            .flat_map(TempoTxEnvelope::calls)
            .map(|(kind, input)| (kind, input.as_ref()))
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

/// Fields accepted by a precompile-scoped expectation, including its TIP-1060 credit balance.
fn precompile_gas_or_storage(field: &Field, precompile: Address) -> bool {
    matches!(field.name, "gas" | "block_gas")
        || (field.name == "storage"
            && (field.address == Some(precompile)
                || (field.address == Some(STORAGE_CREDITS_ADDRESS)
                    && field.slot == Some(StorageCredits::slot(precompile)))))
}

/// Returns whether T11 rejects `calldata` for the Tempo precompile at `address` only because of
/// trailing bytes, which T12 accepts per TIP-1116.
fn rejects_only_trailing_bytes(to: Address, calldata: &[u8]) -> bool {
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

/// Accepts the effects of a direct precompile call that T11 rejected only for trailing bytes.
const T12_ALLOW_PRECOMPILE_ABI_SUFFIX: Expectation = Expectation {
    id: "t12.allow-abi-suffix",
    check: |ctx, field| {
        if !ctx.call().any(|(kind, calldata)| {
            kind.to()
                .is_some_and(|to| rejects_only_trailing_bytes(*to, calldata))
        }) {
            return None;
        }

        // After T11's empty-revert rejection, accept any T12 effect except tx invalidation.
        let (real, _) = ctx.observed_txs()?;
        (real.outcome == TxOutcome::Revert
            && real.output_hash == KECCAK256_EMPTY
            && field.name != "execution")
            .then_some(())
    },
};

const T12_TIP20_CHANNEL: Expectation = Expectation {
    id: "t12.tip20-channel-reserve",
    check: |ctx, field| {
        if !precompile_gas_or_storage(field, TIP20_CHANNEL_RESERVE_ADDRESS) {
            return None;
        }

        let is_related = ctx.call().any(|(kind, calldata)| {
            kind.to() == Some(&TIP20_CHANNEL_RESERVE_ADDRESS)
                && [
                    ITIP20ChannelReserve::openCall::SELECTOR,
                    ITIP20ChannelReserve::settleCall::SELECTOR,
                    ITIP20ChannelReserve::topUpCall::SELECTOR,
                    ITIP20ChannelReserve::closeCall::SELECTOR,
                    ITIP20ChannelReserve::withdrawCall::SELECTOR,
                ]
                .iter()
                .any(|selector| calldata.starts_with(selector))
        });
        is_related.then_some(())?;
        ctx.observed_txs().map(|_| ())
    },
};

// LiFiDiamond delegates this selector to GenericSwapFacetV3; swaps can call the DEX internally.
const LIFI_DIAMOND: Address = address!("2cacae8e22418e65dcf7651c67aebe6288eb8243");
const LIFI_SWAP_TOKENS_MULTIPLE_V3: [u8; 4] = [0x5f, 0xd9, 0xae, 0x2e];

const T12_STABLECOIN_DEX: Expectation = Expectation {
    id: "t12.stablecoin-dex",
    check: |ctx, field| {
        if !precompile_gas_or_storage(field, STABLECOIN_DEX_ADDRESS) {
            return None;
        }

        let is_related = ctx.call().any(|(kind, calldata)| {
            let selector = calldata.get(..4);
            match kind.to() {
                Some(to) if to == &STABLECOIN_DEX_ADDRESS => selector.is_some_and(|selector| {
                    [
                        IStablecoinDEX::placeCall::SELECTOR,
                        IStablecoinDEX::placeFlipCall::SELECTOR,
                        IStablecoinDEX::cancelCall::SELECTOR,
                        IStablecoinDEX::cancelStaleOrderCall::SELECTOR,
                        IStablecoinDEX::swapExactAmountInCall::SELECTOR,
                        IStablecoinDEX::swapExactAmountOutCall::SELECTOR,
                        IStablecoinDEX::quoteSwapExactAmountInCall::SELECTOR,
                        IStablecoinDEX::quoteSwapExactAmountOutCall::SELECTOR,
                        IStablecoinDEX::getTickLevelCall::SELECTOR,
                    ]
                    .iter()
                    .any(|expected| selector == expected.as_slice())
                }),
                Some(to) if to == &LIFI_DIAMOND => {
                    selector == Some(LIFI_SWAP_TOKENS_MULTIPLE_V3.as_slice())
                }
                _ => false,
            }
        });
        is_related.then_some(())?;
        ctx.observed_txs().map(|_| ())
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

        // The canonical arm must not change code. The shadow arm must perform exactly the reviewed
        // T10-to-T13 upgrade. An empty prior hash is also valid when replay activates the T10
        // installation and T13 upgrade together at the same boundary.
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

/// Forks are ordered oldest-first; canonical features are excluded.
const REGISTRY: &[(TempoHardfork, &[Expectation])] = &[
    (
        TempoHardfork::T12,
        &[
            T12_ALLOW_PRECOMPILE_ABI_SUFFIX,
            T12_TIP20_CHANNEL,
            T12_STABLECOIN_DEX,
            FEE_STATE,
        ],
    ),
    (TempoHardfork::T13, &[T13_ZONE_RUNTIME_UPGRADE]),
];

pub(crate) fn between(
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    select(REGISTRY, canonical, candidate)
}

fn select(
    registry: &'static [(TempoHardfork, &[Expectation])],
    canonical: TempoHardfork,
    candidate: TempoHardfork,
) -> Vec<&'static Expectation> {
    registry
        .iter()
        .filter(|(fork, _)| *fork > canonical && *fork <= candidate)
        .flat_map(|(_, rules)| *rules)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        super::{Block, RecoveredBlock, ReplayOutcome, TransitionState},
        *,
    };
    use crate::shadow_replay::analysis::{MAX_SAMPLES, Report};
    use alloy::primitives::Signature;
    use reth_revm::{
        db::states::{StorageSlot, TransitionAccount},
        state::AccountInfo,
    };
    use tempo_primitives::{
        TempoTransaction,
        transaction::{AASigned, PrimitiveSignature, TempoSignature},
    };

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
        const T11_RULE: Expectation = Expectation {
            id: "t11",
            check: |_, _| None,
        };
        const SPARSE: &[(TempoHardfork, &[Expectation])] =
            &[(T11, &[T11_RULE]), (T13, &[T13_ZONE_RUNTIME_UPGRADE])];

        let ids = |a, b| {
            select(SPARSE, a, b)
                .into_iter()
                .map(|rule| rule.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(T10, T13), ["t11", T13_ZONE_RUNTIME_UPGRADE.id]);
        assert_eq!(ids(T12, T13), [T13_ZONE_RUNTIME_UPGRADE.id]);
        assert!(ids(T11, T12).is_empty());
        assert!(ids(T13, T12).is_empty());
    }

    // Synthetic checks exercise the classifier contract; these are NOT TIP-1016 validators.
    const GAS: Expectation = Expectation {
        id: "test.gas",
        check: |ctx, field| {
            if field.name != "gas" {
                return None;
            }
            let Boundary::Transaction(index) = ctx.boundary else {
                return None;
            };
            let (real, shadow) = (
                ctx.real.txs[index].as_ref().ok()?,
                ctx.shadow.txs[index].as_ref().ok()?,
            );
            (real.gas_used.checked_add(200) == Some(shadow.gas_used)
                && real.outcome == shadow.outcome)
                .then_some(())
        },
    };

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
                        gas_used,
                        block_gas_used: 21_000,
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
    fn accepted_gas_does_not_hide_unverified_fee_state() {
        let real = evidence(&[21_000, 21_000]);
        let mut shadow = evidence(&[21_200, 21_000]);
        write_slot(tx_mut(&mut shadow, 0), 800);
        let report = Report::analyze(&real, &shadow, &[&GAS], &block(vec![]));
        assert_eq!(report.expected[GAS.id], 1);
        assert_eq!(report.unexplained, 1);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Findings);
        let field = report.samples[0].1.field;
        assert_eq!(field.name, "storage");
        assert_eq!(field.address, Some(Address::ZERO));
        assert_eq!(field.slot, Some(U256::ZERO));
        assert!(field.fee_associated);
    }

    #[test]
    fn only_verified_fee_amount_is_masked_in_ordered_receipt_logs() {
        let tx: TempoTxEnvelope = AASigned::new_unhashed(
            TempoTransaction {
                max_priority_fee_per_gas: 1_000_000_000_000,
                max_fee_per_gas: 1_000_000_000_000,
                ..Default::default()
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        )
        .into();
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
            tx.fee_normalized = Some((U256::from(amount), normalized));
        }
        let block = block(vec![tx]);
        let report = |shadow: &Evidence, rules: &[&Expectation]| {
            Report::analyze(&real, shadow, rules, &block)
        };
        let accepted = report(&shadow, &[&GAS]);
        assert_eq!(accepted.outcome(&shadow), ReplayOutcome::Expected);
        assert_eq!(accepted.expected[GAS.id], 1);
        assert_eq!(accepted.unexplained, 0);
        // Without a reviewed gas rule, the fee change is still masked, but gas is a finding.
        assert_eq!(report(&shadow, &[]).unexplained, 1);

        let mut wrong = shadow;
        tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().1 = B256::repeat_byte(4);
        assert_eq!(report(&wrong, &[&GAS]).unexplained, 1);
        tx_mut(&mut wrong, 0).fee_normalized.as_mut().unwrap().1 = normalized;
        tx_mut(&mut wrong, 0).fee.log_ranges = std::iter::once(1..2).collect();
        assert_eq!(report(&wrong, &[&GAS]).unexplained, 1);
    }

    #[test]
    fn first_accepting_rule_owns_attribution() {
        let stop = Expectation {
            id: "test.stop-gas",
            check: |_, field| (field.name == "gas").then_some(()),
        };
        let unreachable = Expectation {
            id: "must-not-run",
            check: |_, _| panic!("already accepted"),
        };
        let real = evidence(&[21_000, 21_000]);
        let shadow = evidence(&[21_200, 21_000]);
        for rules in [[&GAS, &stop, &unreachable], [&stop, &GAS, &unreachable]] {
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

    #[test]
    fn accepted_post_block_change_is_expected() {
        let real = evidence(&[]);
        let mut shadow = evidence(&[]);
        shadow.post_block.as_mut().unwrap().transitions.insert(
            Address::ZERO,
            TransitionAccount {
                info: Some(AccountInfo {
                    balance: U256::from(1),
                    ..Default::default()
                }),
                previous_info: Some(AccountInfo::default()),
                ..Default::default()
            },
        );
        let rule = Expectation {
            id: "test.post-block",
            check: |ctx, field| {
                (ctx.boundary == Boundary::PostBlock && field.name == "balance").then_some(())
            },
        };
        let report = Report::analyze(&real, &shadow, &[&rule], &block(vec![]));
        assert_eq!(report.boundaries_not_evaluated, 0);
        assert_eq!(report.outcome(&shadow), ReplayOutcome::Expected);
    }
}
