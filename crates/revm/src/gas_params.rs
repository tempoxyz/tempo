use auto_impl::auto_impl;
use revm::context_interface::cfg::{GasId, GasParams};
use tempo_chainspec::hardfork::TempoHardfork;

/// Extending [`GasParams`] for Tempo use case.
#[auto_impl(&, Arc, Box, &mut)]
pub trait TempoGasParams {
    fn gas_params(&self) -> &GasParams;

    fn tx_tip1000_auth_account_creation_cost(&self) -> u64 {
        self.gas_params().get(GasId::new(255))
    }

    fn tx_tip1000_auth_account_creation_state_gas(&self) -> u64 {
        self.gas_params().get(GasId::new(254))
    }
}

impl TempoGasParams for GasParams {
    fn gas_params(&self) -> &GasParams {
        self
    }
}

// TIP-1000 total gas costs (used by T1)
const SSTORE_SET_COST: u64 = 250_000;
const CREATE_COST: u64 = 500_000;
const NEW_ACCOUNT_COST: u64 = 250_000;
const CODE_DEPOSIT_COST_T1: u64 = 1_000;
const AUTH_ACCOUNT_CREATION_COST: u64 = 250_000;
const EIP7702_PER_EMPTY_ACCOUNT_COST_T1: u64 = 12_500;

// TIP-1016 regular gas (computational overhead) — matches pre-TIP-1000 EVM costs.
// These values are "at least the pre-TIP-1000 (standard EVM) cost" per spec invariant 15.
//
// For SSTORE: revm decomposes the cost as sstore_static(WARM_STORAGE_READ=100) +
// sstore_set_without_load_cost. So the GasId value = 20,000 - 100 = 19,900.
const T3_SSTORE_SET_REGULAR: u64 = 20_000;
const T3_SSTORE_SET_WITHOUT_LOAD: u64 = T3_SSTORE_SET_REGULAR - 100; // minus warm_storage_read
const T3_NEW_ACCOUNT_REGULAR: u64 = 25_000;
const T3_CREATE_REGULAR: u64 = 32_000;
const T3_CODE_DEPOSIT_REGULAR: u64 = 200;
const T3_EIP7702_PER_AUTH_TOTAL: u64 = 250_000; // 25k regular + 225k state

// TIP-1016 state gas (permanent storage burden)
const T3_SSTORE_SET_STATE: u64 = SSTORE_SET_COST - T3_SSTORE_SET_REGULAR; // 230,000
const T3_NEW_ACCOUNT_STATE: u64 = NEW_ACCOUNT_COST - T3_NEW_ACCOUNT_REGULAR; // 225,000
const T3_CREATE_STATE: u64 = CREATE_COST - T3_CREATE_REGULAR; // 468,000
const T3_CODE_DEPOSIT_STATE: u64 = 2_300;

// TIP-1016 SSTORE set refund for 0→X→0 restoration (combined state + regular).
// Spec: state_gas(230,000) + regular(GAS_STORAGE_UPDATE - GAS_COLD_SLOAD - GAS_WARM_ACCESS)
//      = 230,000 + (20,000 - 2,100 - 100) = 247,800
const T3_SSTORE_SET_REFUND: u64 = T3_SSTORE_SET_STATE + 17_800; // 230,000 + 17,800 = 247,800

/// Tempo gas params override.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    let mut gas_params = GasParams::new_spec(spec.into());
    let mut overrides = vec![];
    if spec.is_t3() {
        // TIP-1016: Split storage creation costs into regular gas + state gas.
        // Regular gas (computational overhead) = at least pre-TIP-1000 EVM cost.
        // State gas (permanent storage burden) = total - regular.
        overrides.extend([
            // SSTORE (zero → non-zero): 20k regular + 230k state
            (
                GasId::sstore_set_without_load_cost(),
                T3_SSTORE_SET_WITHOUT_LOAD,
            ),
            (GasId::sstore_set_state_gas(), T3_SSTORE_SET_STATE),
            (GasId::sstore_set_refund(), T3_SSTORE_SET_REFUND),
            // Contract metadata (CREATE base): 32k regular + 468k state
            (GasId::tx_create_cost(), T3_CREATE_REGULAR),
            (GasId::create(), T3_CREATE_REGULAR),
            (GasId::create_state_gas(), T3_CREATE_STATE),
            // Account creation: 25k regular + 225k state
            (GasId::new_account_cost(), T3_NEW_ACCOUNT_REGULAR),
            (GasId::new_account_state_gas(), T3_NEW_ACCOUNT_STATE),
            (
                GasId::new_account_cost_for_selfdestruct(),
                T3_NEW_ACCOUNT_REGULAR,
            ),
            // Code deposit: 200 regular + 2,300 state per byte
            (GasId::code_deposit_cost(), T3_CODE_DEPOSIT_REGULAR),
            (GasId::code_deposit_state_gas(), T3_CODE_DEPOSIT_STATE),
            // EIP-7702 delegation: 25k regular + 225k state = 250k per auth
            (
                GasId::tx_eip7702_per_empty_account_cost(),
                T3_EIP7702_PER_AUTH_TOTAL,
            ),
            // Auth account creation (keychain): same split as account creation
            (GasId::new(255), T3_NEW_ACCOUNT_REGULAR),
            (GasId::new(254), T3_NEW_ACCOUNT_STATE),
        ]);
    } else if spec.is_t1() {
        // TIP-1000: All storage creation costs in regular gas (no state gas split).
        overrides.extend([
            (GasId::sstore_set_without_load_cost(), SSTORE_SET_COST),
            (GasId::tx_create_cost(), CREATE_COST),
            (GasId::create(), CREATE_COST),
            (GasId::new_account_cost(), NEW_ACCOUNT_COST),
            (GasId::new_account_cost_for_selfdestruct(), NEW_ACCOUNT_COST),
            (GasId::code_deposit_cost(), CODE_DEPOSIT_COST_T1),
            (
                GasId::tx_eip7702_per_empty_account_cost(),
                EIP7702_PER_EMPTY_ACCOUNT_COST_T1,
            ),
            (GasId::new(255), AUTH_ACCOUNT_CREATION_COST),
        ]);
    }

    gas_params.override_gas(overrides);
    gas_params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_t1_gas_params_no_state_gas_split() {
        let gas_params = tempo_gas_params(TempoHardfork::T1);

        // T1 has full 250k costs in regular gas, no state gas split
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            250_000
        );
        assert_eq!(gas_params.get(GasId::new_account_cost()), 250_000);
        assert_eq!(gas_params.get(GasId::tx_create_cost()), 500_000);
        assert_eq!(gas_params.get(GasId::create()), 500_000);
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 1_000);

        // State gas params should remain at upstream defaults (not Tempo-bumped)
        let upstream = GasParams::new_spec(TempoHardfork::T1.into());
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            upstream.get(GasId::sstore_set_state_gas()),
            "T1 should not override state gas params"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_state_gas()),
            upstream.get(GasId::new_account_state_gas()),
        );
        assert_eq!(
            gas_params.get(GasId::create_state_gas()),
            upstream.get(GasId::create_state_gas()),
        );
    }

    /// TIP-1016 spec table: regular/state gas splits must match the spec exactly.
    ///
    /// | Operation                      | Execution Gas | Storage Gas | Total   |
    /// |--------------------------------|---------------|-------------|---------|
    /// | Cold SSTORE (zero → non-zero)  | 20,000        | 230,000     | 250,000 |
    /// | Account creation (nonce 0 → 1) | 25,000        | 225,000     | 250,000 |
    /// | Contract metadata (CREATE)     | 32,000        | 468,000     | 500,000 |
    /// | Contract code storage (/byte)  | 200           | 2,300       | 2,500   |
    /// | EIP-7702 delegation (per auth) | 25,000        | 225,000     | 250,000 |
    ///
    /// Note: For SSTORE, `sstore_set_without_load_cost` excludes the warm storage
    /// read cost (100) that revm charges as `sstore_static_gas`. So the GasId value
    /// = spec_regular - WARM_STORAGE_READ_COST = 20,000 - 100 = 19,900.
    #[test]
    fn test_t3_gas_params_splits_storage_costs() {
        let gas_params = tempo_gas_params(TempoHardfork::T3);

        // T3 execution gas (regular/computational overhead)
        // SSTORE: spec says 20,000 regular; revm decomposes as static(100) + sstore_set_without_load
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            19_900,
            "SSTORE set_without_load = spec 20,000 - warm_storage_read(100)"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost()),
            25_000,
            "Account creation regular gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost_for_selfdestruct()),
            25_000
        );
        assert_eq!(
            gas_params.get(GasId::tx_create_cost()),
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::create()),
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 200);

        // T3 state gas (permanent storage burden)
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            230_000,
            "SSTORE state gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_state_gas()),
            225_000,
            "Account creation state gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::create_state_gas()),
            468_000,
            "CREATE base state gas per spec"
        );
        assert_eq!(gas_params.get(GasId::code_deposit_state_gas()), 2_300);

        // Auth account creation: same split as account creation
        assert_eq!(
            gas_params.get(GasId::new(255)),
            25_000,
            "Auth account creation regular gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::new(254)),
            225_000,
            "Auth account creation state gas per spec"
        );

        // EIP-7702 delegation: 25,000 regular + 225,000 state per auth
        assert_eq!(
            gas_params.get(GasId::tx_eip7702_per_empty_account_cost()),
            250_000,
            "EIP-7702 per auth total = 25k regular + 225k state per spec"
        );

        // SSTORE set refund for 0→X→0 restoration (combined state + regular)
        // Spec: state_gas(230,000) + regular(20,000 - 2,100 - 100 = 17,800) = 247,800
        assert_eq!(
            gas_params.get(GasId::sstore_set_refund()),
            247_800,
            "SSTORE set refund = state(230k) + regular(17.8k) per spec"
        );
    }

    /// TIP-1016: Verify totals (regular + state) match spec table.
    /// Note: SSTORE total comparison needs to account for revm decomposition.
    /// T1 sstore_set_without_load_cost = 250,000 (full TIP-1000 cost as override).
    /// T3 total SSTORE = sstore_set_without_load_cost(19,900) + warm_read(100) + state(230,000) = 250,000.
    #[test]
    fn test_t3_totals_match_spec() {
        let t3 = tempo_gas_params(TempoHardfork::T3);

        // SSTORE set total: regular(20,000) + state(230,000) = 250,000
        // In revm terms: sstore_set_without_load_cost(19,900) + warm_read(100) + state(230,000)
        let sstore_regular = t3.get(GasId::sstore_set_without_load_cost()) + 100; // add warm_storage_read
        assert_eq!(
            sstore_regular + t3.get(GasId::sstore_set_state_gas()),
            250_000,
            "SSTORE total must be 250,000"
        );

        // New account: 25,000 + 225,000 = 250,000
        assert_eq!(
            t3.get(GasId::new_account_cost()) + t3.get(GasId::new_account_state_gas()),
            250_000,
            "new_account total must be 250,000"
        );

        // CREATE: 32,000 + 468,000 = 500,000
        assert_eq!(
            t3.get(GasId::create()) + t3.get(GasId::create_state_gas()),
            500_000,
            "CREATE total must be 500,000"
        );

        // Code deposit: 200 + 2,300 = 2,500/byte
        assert_eq!(
            t3.get(GasId::code_deposit_cost()) + t3.get(GasId::code_deposit_state_gas()),
            2_500,
            "code_deposit total must be 2,500/byte"
        );

        // Auth account creation: 25,000 + 225,000 = 250,000
        assert_eq!(
            t3.get(GasId::new(255)) + t3.get(GasId::new(254)),
            250_000,
            "auth_account_creation total must be 250,000"
        );

        // EIP-7702: 250,000 total per auth
        assert_eq!(
            t3.get(GasId::tx_eip7702_per_empty_account_cost()),
            250_000,
            "EIP-7702 per auth total must be 250,000"
        );
    }
}
