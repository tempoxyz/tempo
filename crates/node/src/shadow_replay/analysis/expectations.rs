//! Reviewed expectations registered at the fork introducing a feature.
//!
//! Checks receive one difference, not a transaction. `None` means unexplained and `Some(())`
//! accepts it.

use super::{AccountDelta, Field};
use crate::shadow_replay::{Boundary, Evidence, ObservedTx, TxOutcome};
use alloy::{
    primitives::{Address, KECCAK256_EMPTY, keccak256},
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
use tempo_precompiles::abi_decoder_config_for_spec;
use tempo_primitives::{TempoAddressExt as _, TempoTxEnvelope};

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

    /// Borrows the direct call `(to, calldata)` from the canonical transaction.
    fn call(&self) -> Option<(alloy::primitives::Address, &[u8])> {
        let mut calls = self.tx?.calls();
        let (kind, input) = calls.next()?;
        if calls.next().is_some() {
            return None;
        }
        Some((*kind.to()?, input.as_ref()))
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
        let (to, calldata) = ctx.call()?;
        if !rejects_only_trailing_bytes(to, calldata) {
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
            && ctx.call().is_some_and(|(address, calldata)| {
                address == TIP20_CHANNEL_RESERVE_ADDRESS
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
            && ctx.call().is_some_and(|(address, calldata)| {
                address == STABLECOIN_DEX_ADDRESS
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
    use reth_revm::{db::states::TransitionAccount, state::AccountInfo};

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
