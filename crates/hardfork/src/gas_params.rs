//! Tempo's EVM2 gas schedule.

use crate::{
    TempoHardfork,
    constants::gas::{SSTORE_CREATE_COST, SSTORE_SET_COST, STORAGE_CREDIT_VALUE},
};
use evm2::{EvmFeatures, SpecId, Version, version::GasId};

const CONTRACT_CREATE_COST: u32 = 500_000;
const NEW_ACCOUNT_COST: u32 = 250_000;
const CODE_DEPOSIT_COST_T1: u32 = 1_000;
const EIP7702_PER_EMPTY_ACCOUNT_COST_T1: u32 = 12_500;

const AMSTERDAM_NEW_ACCOUNT_REGULAR: u32 = 25_000;
const AMSTERDAM_CREATE_REGULAR: u32 = 32_000;
const AMSTERDAM_CODE_DEPOSIT_REGULAR: u32 = 200;

const AMSTERDAM_NEW_ACCOUNT_STATE: u32 = NEW_ACCOUNT_COST - AMSTERDAM_NEW_ACCOUNT_REGULAR;
const AMSTERDAM_CREATE_STATE: u32 = CONTRACT_CREATE_COST - AMSTERDAM_CREATE_REGULAR;
const AMSTERDAM_CODE_DEPOSIT_STATE: u32 = 2_300;

/// Applies Tempo's hardfork-specific features and gas parameters to an EVM2 version.
pub fn configure_version(
    mut version: Version,
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
) -> Version {
    // T14 activates TIP-1016. The explicit switch also allows exercising the
    // reservoir model on earlier forks in tests.
    let amsterdam_eip8037_enabled = amsterdam_eip8037_enabled || spec.is_t14();
    if amsterdam_eip8037_enabled {
        version.features.insert(EvmFeatures::EIP8037);
        // TIP-1016 limits execution gas, not the user's execution + state budget.
        version.features.remove(EvmFeatures::BLOCK_GAS_LIMIT_CHECK);
        apply_amsterdam(&mut version);
    } else {
        version.features.remove(EvmFeatures::EIP8037);
        if spec.is_t1() {
            apply_t1(&mut version);
        }
        if spec.is_t7() {
            apply_t7(&mut version);
        }
    }

    version
}

/// Creates an EVM2 version with Tempo's hardfork-specific gas schedule.
pub fn version(spec_id: SpecId, spec: TempoHardfork, amsterdam_eip8037_enabled: bool) -> Version {
    configure_version(Version::new(spec_id), spec, amsterdam_eip8037_enabled)
}

fn apply_t1(version: &mut Version) {
    let gas = &mut version.gas_params;
    gas[GasId::SstoreSetWithoutLoadCost] = SSTORE_CREATE_COST as u32;
    gas[GasId::TxCreateCost] = CONTRACT_CREATE_COST;
    gas[GasId::Create] = CONTRACT_CREATE_COST;
    gas[GasId::NewAccountCost] = NEW_ACCOUNT_COST;
    gas[GasId::NewAccountCostForSelfdestruct] = NEW_ACCOUNT_COST;
    gas[GasId::CodeDepositCost] = CODE_DEPOSIT_COST_T1;
    gas[GasId::TxEip7702PerEmptyAccountCost] = EIP7702_PER_EMPTY_ACCOUNT_COST_T1;
    gas[GasId::TxEip7702AuthRefund] = 0;
}

fn apply_t7(version: &mut Version) {
    let gas = &mut version.gas_params;
    gas[GasId::SstoreSetWithoutLoadCost] = SSTORE_SET_COST as u32;
    gas[GasId::SstoreSetRefund] = SSTORE_SET_COST as u32;
    gas[GasId::SstoreClearingSlotRefund] = 0;
    // The creditable cost is unchanged when TIP-1016 moves it to state gas.
    gas[GasId::SstoreSetState] = STORAGE_CREDIT_VALUE as u32;
    gas[GasId::MaxRefundQuotient] = 1;
}

fn apply_amsterdam(version: &mut Version) {
    // TIP-1016 activates after TIP-1060 and inherits its storage-credit schedule.
    apply_t7(version);
    let gas = &mut version.gas_params;
    gas[GasId::TxCreateCost] = AMSTERDAM_CREATE_REGULAR;
    gas[GasId::Create] = AMSTERDAM_CREATE_REGULAR;
    gas[GasId::CreateState] = AMSTERDAM_CREATE_STATE;
    gas[GasId::NewAccountCost] = AMSTERDAM_NEW_ACCOUNT_REGULAR;
    gas[GasId::NewAccountState] = AMSTERDAM_NEW_ACCOUNT_STATE;
    gas[GasId::NewAccountCostForSelfdestruct] = AMSTERDAM_NEW_ACCOUNT_REGULAR;
    gas[GasId::CodeDepositCost] = AMSTERDAM_CODE_DEPOSIT_REGULAR;
    gas[GasId::CodeDepositState] = AMSTERDAM_CODE_DEPOSIT_STATE;
    gas[GasId::TxEip7702PerEmptyAccountCost] = AMSTERDAM_NEW_ACCOUNT_REGULAR;
    gas[GasId::TxEip7702AuthRefund] = 0;
    // evm2 sums NewAccountState + TxEip7702PerAuthState per authorization.
    // The former already provides TIP-1016's fixed 225k charge; no extra
    // delegation-bytecode component is charged (matching the revm schedule).
    gas[GasId::TxEip7702PerAuthState] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tip1016_preserves_t7_sstore_prices() {
        let t7 = version(SpecId::OSAKA, TempoHardfork::T7, false).gas_params;
        for &spec in TempoHardfork::VARIANTS.iter().filter(|spec| spec.is_t7()) {
            let gas = version(SpecId::OSAKA, spec, false).gas_params;
            for id in [
                GasId::SstoreStatic,
                GasId::SstoreSetWithoutLoadCost,
                GasId::SstoreResetWithoutColdLoadCost,
                GasId::SstoreSetState,
                GasId::SstoreSetRefund,
                GasId::SstoreResetRefund,
                GasId::SstoreClearingSlotRefund,
                GasId::ColdStorageCost,
                GasId::WarmStorageReadCost,
                GasId::MaxRefundQuotient,
            ] {
                assert_eq!(gas[id], t7[id], "{spec:?}: {id:?}");
            }
        }
    }

    /// Ported from origin/tip1016: uncapped refunds may only reverse execution
    /// charges, and each restore pair must retain both warm accesses.
    #[test]
    fn test_t14_restore_refunds_net_warm_access_costs() {
        let gas = version(SpecId::OSAKA, TempoHardfork::T14, false).gas_params;
        let warm = gas[GasId::SstoreStatic];
        for (write, refund) in [
            (GasId::SstoreSetWithoutLoadCost, GasId::SstoreSetRefund),
            (
                GasId::SstoreResetWithoutColdLoadCost,
                GasId::SstoreResetRefund,
            ),
        ] {
            assert_eq!(warm + gas[write] + warm - gas[refund], 2 * warm);
        }
        assert_eq!(gas[GasId::SstoreClearingSlotRefund], 0);
        assert_eq!(gas[GasId::SelfdestructRefund], 0);
        assert_eq!(gas[GasId::TxEip7702AuthRefund], 0);
    }

    #[test]
    fn tip1016_activates_at_t14() {
        for &spec in TempoHardfork::VARIANTS {
            let version = version(SpecId::OSAKA, spec, false);
            assert_eq!(
                version.feature(EvmFeatures::EIP8037),
                spec.is_t14(),
                "{spec:?}"
            );
            if spec.is_t14() {
                assert_eq!(version.gas_params[GasId::SstoreSetState], 245_000);
                assert_eq!(version.gas_params[GasId::CodeDepositState], 2_300);
            }
        }
    }

    #[test]
    fn tip1016_preserves_tip1060_credits_and_execution_refunds() {
        let version = version(SpecId::OSAKA, TempoHardfork::T14, false);
        let gas = version.gas_params;
        assert!(version.feature(EvmFeatures::EIP8037));
        assert!(!version.feature(EvmFeatures::BLOCK_GAS_LIMIT_CHECK));
        assert_eq!(gas[GasId::SstoreSetWithoutLoadCost], 5_000);
        assert_eq!(gas[GasId::SstoreSetState], 245_000);
        assert_eq!(gas[GasId::SstoreSetRefund], 5_000);
        assert_eq!(gas[GasId::SstoreClearingSlotRefund], 0);
        assert_eq!(gas[GasId::MaxRefundQuotient], 1);
        assert_eq!(
            gas[GasId::CodeDepositCost] + gas[GasId::CodeDepositState],
            2_500
        );
        assert_eq!(
            gas[GasId::NewAccountCost] + gas[GasId::NewAccountState],
            250_000
        );
        assert_eq!(gas[GasId::Create] + gas[GasId::CreateState], 500_000);
    }

    #[test]
    fn test_tempo_override_gas_params_match_across_forks() {
        let t1 = version(SpecId::OSAKA, TempoHardfork::T1, false);
        let t5 = version(SpecId::OSAKA, TempoHardfork::T5, false);
        assert_eq!(
            t1.gas_params, t5.gas_params,
            "T1+ TIP-1000 gas params should have equal values"
        );
    }

    /// TIP-1060 (T7): SSTORE creation charges only the 5k residual through the
    /// gas function; other TIP-1000 creation costs are unchanged, and there is
    /// no TIP-1016 state-gas split (production T7 runs with EIP-8037 disabled).
    #[test]
    fn test_t7_gas_params_sstore_residual() {
        let t7 = version(SpecId::OSAKA, TempoHardfork::T7, false);
        let gas = t7.gas_params;

        // SSTORE creation cost drops to the 5k residual; the 245k creditable
        // portion is charged by the storage-credit hook, not the gas function.
        assert_eq!(
            gas[GasId::SstoreSetWithoutLoadCost],
            5_000,
            "T7 SSTORE creation charges only the 5k residual"
        );
        assert!(
            gas[GasId::SstoreSetWithoutLoadCost] >= gas[GasId::SstoreSetRefund],
            "T7 restore-to-original-zero refund must not exceed the residual set charge"
        );
        assert_eq!(
            gas[GasId::SstoreClearingSlotRefund],
            0,
            "TIP-1060 removes the legacy SSTORE clearing refund"
        );

        // Other TIP-1000 creation costs are unchanged by TIP-1060.
        assert_eq!(gas[GasId::NewAccountCost], 250_000);
        assert_eq!(gas[GasId::TxCreateCost], 500_000);
        assert_eq!(gas[GasId::Create], 500_000);
        assert_eq!(gas[GasId::CodeDepositCost], 1_000);

        // The creditable price exists at T7, but stays in execution gas until TIP-1016.
        assert!(!t7.feature(EvmFeatures::EIP8037));
        assert_eq!(
            gas[GasId::SstoreSetState],
            STORAGE_CREDIT_VALUE as u32,
            "T7 defines the storage-credit price inherited by TIP-1016"
        );

        assert_eq!(gas[GasId::MaxRefundQuotient], 1);

        // T7+ has equal gas parameters.
        assert_eq!(
            gas,
            version(SpecId::OSAKA, TempoHardfork::T8, false).gas_params,
            "T7+ TIP-1060 gas params should have equal values"
        );
    }

    #[test]
    fn test_t1_gas_params_no_state_gas_split() {
        let version = version(SpecId::OSAKA, TempoHardfork::T1, false);
        let gas = version.gas_params;

        // T1 has full 250k costs in regular gas, no state gas split
        assert_eq!(gas[GasId::SstoreSetWithoutLoadCost], 250_000);
        assert_eq!(gas[GasId::NewAccountCost], 250_000);
        assert_eq!(gas[GasId::TxCreateCost], 500_000);
        assert_eq!(gas[GasId::Create], 500_000);
        assert_eq!(gas[GasId::CodeDepositCost], 1_000);
        assert_eq!(gas[GasId::TxEip7702PerEmptyAccountCost], 12_500);
        assert_eq!(gas[GasId::TxEip7702AuthRefund], 0);
        assert!(!version.feature(EvmFeatures::EIP8037));

        // State gas params should remain at upstream defaults (not Tempo-bumped)
        let upstream = evm2::Version::new(SpecId::OSAKA).gas_params;
        assert_eq!(gas[GasId::SstoreSetState], upstream[GasId::SstoreSetState]);
        assert_eq!(
            gas[GasId::NewAccountState],
            upstream[GasId::NewAccountState]
        );
        assert_eq!(gas[GasId::CreateState], upstream[GasId::CreateState]);
    }

    /// TIP-1016 production prices inherit TIP-1060's SSTORE decomposition.
    #[test]
    fn test_t14_gas_params_splits_storage_costs() {
        let version = version(SpecId::OSAKA, TempoHardfork::T14, false);
        let gas = version.gas_params;
        assert!(version.feature(EvmFeatures::EIP8037));

        // T14 execution gas (regular/computational overhead)
        // SSTORE keeps the decomposed accounting: static(100) + set_without_load(5,000),
        // with cold slot access (2,100) retained separately through `ColdStorageCost`.
        assert_eq!(
            gas[GasId::SstoreSetWithoutLoadCost],
            5_000,
            "SSTORE set_without_load matches the retained zero->non-zero write component"
        );
        assert_eq!(
            gas[GasId::NewAccountCost],
            25_000,
            "Account creation regular gas per spec"
        );
        assert_eq!(gas[GasId::NewAccountCostForSelfdestruct], 25_000);
        assert_eq!(
            gas[GasId::TxCreateCost],
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(
            gas[GasId::Create],
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(gas[GasId::CodeDepositCost], 200);

        // T14 state gas (permanent storage burden)
        assert_eq!(
            gas[GasId::SstoreSetState],
            245_000,
            "SSTORE state gas per spec"
        );
        assert_eq!(
            gas[GasId::NewAccountState],
            225_000,
            "Account creation state gas per spec"
        );
        assert_eq!(
            gas[GasId::CreateState],
            468_000,
            "CREATE base state gas per spec"
        );
        assert_eq!(gas[GasId::CodeDepositState], 2_300);

        // EIP-7702 delegation: 25,000 regular + 225,000 state per auth
        assert_eq!(
            gas[GasId::TxEip7702PerEmptyAccountCost],
            25_000,
            "EIP-7702 per auth regular gas per spec"
        );
        assert_eq!(gas[GasId::TxEip7702PerAuthState], 0);
        assert_eq!(gas.eip7702_auth_state_gas(), 225_000);
        assert_eq!(
            u64::from(gas[GasId::TxEip7702PerEmptyAccountCost]) + gas.eip7702_auth_state_gas(),
            250_000,
            "EIP-7702 per auth total = 25k regular + 225k state per spec"
        );
        assert_eq!(
            gas[GasId::TxEip7702AuthRefund],
            0,
            "TIP-1000: no refund for existing accounts on T1+"
        );

        // Restoration refunds execution only; the credit-backed state gas
        // is settled through TIP-1060 storage credits.
        assert_eq!(gas[GasId::SstoreSetRefund], 5_000);
        assert_eq!(gas[GasId::SstoreClearingSlotRefund], 0);
    }

    /// TIP-1016: Verify totals (regular + state) match the clarified spec table.
    /// Note: SSTORE total comparison needs to account for decomposed gas and the cold-slot charge.
    ///
    /// T1 SstoreSetWithoutLoadCost = 250,000 (full TIP-1000 cost as override).
    /// T14 warm SSTORE = set_without_load(5,000) + warm_read(100) + state(245,000) = 250,100.
    /// T14 cold SSTORE = warm path + cold_slot_access(2,100) = 252,200.
    #[test]
    fn test_t14_totals_match_spec() {
        let gas = version(SpecId::OSAKA, TempoHardfork::T14, false).gas_params;

        // Warm SSTORE total: write component(5,000) + warm read(100) + state(245,000)
        let warm_sstore_regular = u64::from(gas[GasId::SstoreSetWithoutLoadCost])
            + u64::from(gas[GasId::WarmStorageReadCost]);
        assert_eq!(
            warm_sstore_regular + u64::from(gas[GasId::SstoreSetState]),
            250_100,
            "warm SSTORE total must be 250,100"
        );

        // Cold SSTORE total: warm path + Berlin cold slot access(2,100)
        let cold_sstore_regular = warm_sstore_regular + u64::from(gas[GasId::ColdStorageCost]);
        assert_eq!(
            cold_sstore_regular + u64::from(gas[GasId::SstoreSetState]),
            252_200,
            "cold SSTORE total must include Berlin cold slot access charging"
        );

        // New account: 25,000 + 225,000 = 250,000
        assert_eq!(
            gas[GasId::NewAccountCost] + gas[GasId::NewAccountState],
            250_000,
            "new_account total must be 250,000"
        );

        // CREATE: 32,000 + 468,000 = 500,000
        assert_eq!(
            gas[GasId::Create] + gas[GasId::CreateState],
            500_000,
            "CREATE total must be 500,000"
        );

        // Code deposit: 200 + 2,300 = 2,500/byte
        assert_eq!(
            gas[GasId::CodeDepositCost] + gas[GasId::CodeDepositState],
            2_500,
            "code_deposit total must be 2,500/byte"
        );

        // EIP-7702: 25,000 regular + 225,000 state = 250,000 per auth
        assert_eq!(
            u64::from(gas[GasId::TxEip7702PerEmptyAccountCost]) + gas.eip7702_auth_state_gas(),
            250_000,
            "EIP-7702 per auth total must be 250,000"
        );
    }
}
