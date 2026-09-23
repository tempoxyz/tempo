//! Reviewed expectations registered at the fork introducing a feature.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::{AccountDelta, Field};
use crate::shadow_replay::{Boundary, Evidence, ObservedTx, TxOutcome, fees::post_fee_slot_change};
use alloy::{
    consensus::Transaction as _,
    primitives::{Address, B256, KECCAK256_EMPTY, TxKind, U256, keccak256},
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
    abi_decoder_config_for_spec, storage::StorageAction, tip_fee_manager::amm::compute_amount_out,
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
        if matches!(field.name, "gas" | "block_gas")
            && ctx.call().any(|(kind, calldata)| {
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
            })
        {
            ctx.observed_txs()?;
            return Some(());
        }
        None
    },
};

const T12_STABLECOIN_DEX: Expectation = Expectation {
    id: "t12.stablecoin-dex",
    check: |ctx, field| {
        if matches!(field.name, "gas" | "block_gas" | "storage")
            && (field.name != "storage" || field.address == Some(STABLECOIN_DEX_ADDRESS))
            && ctx.call().any(|(kind, calldata)| {
                kind.to() == Some(&STABLECOIN_DEX_ADDRESS)
                    && [
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
                    .any(|selector| calldata.starts_with(selector))
            })
        {
            ctx.observed_txs()?;
            return Some(());
        }
        None
    },
};

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
    use super::*;
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
    fn accepts_only_verified_post_fee_storage_effects() {
        let token = Address::repeat_byte(1);
        let payer = Address::repeat_byte(2);
        let slot = U256::from(3);
        let tx: TempoTxEnvelope = AASigned::new_unhashed(
            TempoTransaction {
                max_fee_per_gas: 1_000_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000_000,
                ..Default::default()
            },
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature())),
        )
        .into();
        let observed = |charge: u64| {
            let after = U256::from(100 - charge);
            let mut fee = crate::shadow_replay::fees::FeeWrites {
                pre_tx_max: Some(U256::from(100)),
                post_tx_transfer: Some((
                    0,
                    token,
                    payer,
                    U256::from(charge),
                    U256::from(100 - charge),
                )),
                post_tx_actions: vec![StorageAction::Sdec(
                    token,
                    slot,
                    U256::from(100),
                    U256::from(charge),
                )],
                log_ranges: std::iter::once(0..1).collect(),
                ..Default::default()
            };
            fee.slots.insert((token, slot));
            let mut state = reth_revm::db::TransitionState::default();
            state.transitions.insert(
                token,
                TransitionAccount {
                    previous_info: Some(AccountInfo::default()),
                    info: Some(AccountInfo::default()),
                    storage: [(slot, StorageSlot::new_changed(U256::from(50), after))]
                        .into_iter()
                        .collect(),
                    ..Default::default()
                },
            );
            Evidence {
                txs: vec![Ok(ObservedTx {
                    gas_used: charge,
                    fee_normalized: Some((U256::from(charge), KECCAK256_EMPTY)),
                    fee,
                    state,
                    ..Default::default()
                })],
                ..Default::default()
            }
        };
        let real = observed(10);
        let mut shadow = observed(20);
        let field = Field {
            name: "storage",
            address: Some(token),
            slot: Some(slot),
            fee_associated: true,
        };
        let check = |shadow: &Evidence, field: &Field| {
            (FEE_STATE.check)(
                &Context {
                    boundary: Boundary::Transaction(0),
                    real: &real,
                    shadow,
                    base_fee: Some(0),
                    tx: Some(&tx),
                },
                field,
            )
            .is_some()
        };
        assert!(check(&shadow, &field));
        assert!(!check(
            &shadow,
            &Field {
                fee_associated: false,
                ..field
            }
        ));
        assert!(!check(
            &shadow,
            &Field {
                slot: Some(U256::from(4)),
                ..field
            }
        ));

        let tx = shadow.txs[0].as_mut().unwrap();
        tx.fee.post_tx_actions[0] =
            StorageAction::Sdec(token, slot, U256::from(101), U256::from(20));
        assert!(!check(&shadow, &field));
        let tx = shadow.txs[0].as_mut().unwrap();
        tx.fee.post_tx_actions[0] =
            StorageAction::Sdec(token, slot, U256::from(100), U256::from(20));
        tx.state
            .transitions
            .get_mut(&token)
            .unwrap()
            .storage
            .get_mut(&slot)
            .unwrap()
            .present_value = U256::from(79);
        assert!(!check(&shadow, &field));
        let tx = shadow.txs[0].as_mut().unwrap();
        tx.state
            .transitions
            .get_mut(&token)
            .unwrap()
            .storage
            .get_mut(&slot)
            .unwrap()
            .present_value = U256::from(80);
        tx.fee.post_tx_transfer.as_mut().unwrap().4 = U256::from(79);
        assert!(!check(&shadow, &field));
        shadow.txs[0]
            .as_mut()
            .unwrap()
            .fee
            .post_tx_transfer
            .as_mut()
            .unwrap()
            .4 = U256::from(80);
        assert!(check(&shadow, &field));
        shadow.txs[0]
            .as_mut()
            .unwrap()
            .fee
            .post_tx_actions
            .push(StorageAction::FeeAmmSwap(
                U256::ZERO,
                U256::ZERO,
                U256::from(21),
            ));
        assert!(!check(&shadow, &field));
        shadow.txs[0].as_mut().unwrap().fee.post_tx_actions.pop();
        shadow.txs[0]
            .as_mut()
            .unwrap()
            .fee_normalized
            .as_mut()
            .unwrap()
            .0 = U256::from(21);
        assert!(!check(&shadow, &field));
    }

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
}
