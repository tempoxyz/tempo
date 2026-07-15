//! Tempo's EVM2 gas schedule.

use crate::{
    TempoHardfork,
    constants::gas::{SSTORE_CREATE_COST, SSTORE_SET_COST},
};
use evm2::{EvmFeatures, SpecId, Version, version::GasId};

const CONTRACT_CREATE_COST: u32 = 500_000;
const NEW_ACCOUNT_COST: u32 = 250_000;
const CODE_DEPOSIT_COST_T1: u32 = 1_000;
const EIP7702_PER_EMPTY_ACCOUNT_COST_T1: u32 = 12_500;

const AMSTERDAM_SSTORE_SET_REGULAR: u32 = 20_000;
const AMSTERDAM_NEW_ACCOUNT_REGULAR: u32 = 25_000;
const AMSTERDAM_CREATE_REGULAR: u32 = 32_000;
const AMSTERDAM_CODE_DEPOSIT_REGULAR: u32 = 200;

const AMSTERDAM_SSTORE_SET_STATE: u32 = SSTORE_CREATE_COST as u32 - AMSTERDAM_SSTORE_SET_REGULAR;
const AMSTERDAM_NEW_ACCOUNT_STATE: u32 = NEW_ACCOUNT_COST - AMSTERDAM_NEW_ACCOUNT_REGULAR;
const AMSTERDAM_CREATE_STATE: u32 = CONTRACT_CREATE_COST - AMSTERDAM_CREATE_REGULAR;
const AMSTERDAM_CODE_DEPOSIT_STATE: u32 = 2_300;
const AMSTERDAM_SSTORE_SET_REFUND: u32 = AMSTERDAM_SSTORE_SET_STATE + 17_800;

/// Applies Tempo's hardfork-specific features and gas parameters to an EVM2 version.
pub fn configure_version(
    mut version: Version,
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
) -> Version {
    debug_assert!(
        !(spec.is_t7() && amsterdam_eip8037_enabled),
        "TIP-1060 and TIP-1016 do not yet have a combined gas schedule"
    );

    if amsterdam_eip8037_enabled {
        version.features.insert(EvmFeatures::EIP8037);
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

    if spec.is_t7() {
        version.gas_params[GasId::MaxRefundQuotient] = 1;
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
}

fn apply_amsterdam(version: &mut Version) {
    let gas = &mut version.gas_params;
    gas[GasId::SstoreSetWithoutLoadCost] = AMSTERDAM_SSTORE_SET_REGULAR;
    gas[GasId::SstoreSetState] = AMSTERDAM_SSTORE_SET_STATE;
    gas[GasId::SstoreSetRefund] = AMSTERDAM_SSTORE_SET_REFUND;
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
    gas[GasId::TxEip7702PerAuthState] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_override_gas_params_are_cached() {
        let t1 = version(SpecId::OSAKA, TempoHardfork::T1, false);
        let t5 = version(SpecId::OSAKA, TempoHardfork::T5, false);
        assert_eq!(
            t1.gas_params, t5.gas_params,
            "T1+ TIP-1000 gas params should share the same table"
        );

        let amsterdam_t4 = version(SpecId::OSAKA, TempoHardfork::T4, true);
        let amsterdam_t5 = version(SpecId::OSAKA, TempoHardfork::T5, true);
        assert_eq!(
            amsterdam_t4.gas_params, amsterdam_t5.gas_params,
            "Amsterdam gas params should share the same table"
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

        // No TIP-1016 state-gas split: state gas params stay at upstream defaults.
        let upstream = evm2::Version::new(SpecId::OSAKA).gas_params;
        assert_eq!(
            gas[GasId::SstoreSetState],
            upstream[GasId::SstoreSetState],
            "T7 (EIP-8037 disabled) must not split SSTORE into state gas"
        );

        assert_eq!(gas[GasId::MaxRefundQuotient], 1);

        // T7+ shares the same table.
        assert_eq!(
            gas,
            version(SpecId::OSAKA, TempoHardfork::T8, false).gas_params,
            "T7+ TIP-1060 gas params should share the same table"
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

    /// TIP-1016 spec table: regular/state gas splits must match the spec exactly.
    ///
    /// | Operation                      | Execution Gas | Storage Gas | Total   |
    /// |--------------------------------|---------------|-------------|---------|
    /// | Cold SSTORE (zero → non-zero)  | 22,200        | 230,000     | 252,200 |
    /// | Account creation (nonce 0 → 1) | 25,000        | 225,000     | 250,000 |
    /// | Contract metadata (CREATE)     | 32,000        | 468,000     | 500,000 |
    /// | Contract code storage (/byte)  | 200           | 2,300       | 2,500   |
    /// | EIP-7702 delegation (per auth) | 25,000        | 225,000     | 250,000 |
    ///
    /// Note: The cold SSTORE total keeps Berlin's access charging. In EVM2 terms the
    /// zero->non-zero write path is: warm read (100) + `SstoreSetWithoutLoadCost` (20,000)
    /// + cold slot surcharge (2,100) + state gas (230,000) = 252,200.
    #[test]
    fn test_t4_gas_params_splits_storage_costs() {
        let version = version(SpecId::OSAKA, TempoHardfork::T4, true);
        let gas = version.gas_params;
        assert!(version.feature(EvmFeatures::EIP8037));

        // T4 execution gas (regular/computational overhead)
        // SSTORE keeps the decomposed accounting: static(100) + set_without_load(20,000),
        // with cold slot access (2,100) retained separately through `ColdStorageCost`.
        assert_eq!(
            gas[GasId::SstoreSetWithoutLoadCost],
            20_000,
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

        // T4 state gas (permanent storage burden)
        assert_eq!(
            gas[GasId::SstoreSetState],
            230_000,
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

        // SSTORE set refund for 0→X→0 restoration (combined state + regular)
        // Spec: state_gas(230,000) + regular(20,000 - 2,100 - 100 = 17,800) = 247,800
        assert_eq!(
            gas[GasId::SstoreSetRefund],
            247_800,
            "SSTORE set refund = state(230k) + regular(17.8k) per spec"
        );
    }

    /// TIP-1016: Verify totals (regular + state) match the clarified spec table.
    /// Note: SSTORE total comparison needs to account for decomposed gas and the cold-slot charge.
    ///
    /// T1 SstoreSetWithoutLoadCost = 250,000 (full TIP-1000 cost as override).
    /// T4 warm SSTORE = set_without_load(20,000) + warm_read(100) + state(230,000) = 250,100.
    /// T4 cold SSTORE = warm path + cold_slot_access(2,100) = 252,200.
    #[test]
    fn test_t4_totals_match_spec() {
        let gas = version(SpecId::OSAKA, TempoHardfork::T4, true).gas_params;

        // Warm SSTORE total: write component(20,000) + warm read(100) + state(230,000)
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
