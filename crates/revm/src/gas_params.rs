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

// TIP-1000 total gas costs (used by both T1 and T2)
const SSTORE_SET_COST: u64 = 250_000;
const CREATE_COST: u64 = 500_000;
const NEW_ACCOUNT_COST: u64 = 250_000;
const CODE_DEPOSIT_COST_T1: u64 = 1_000;
const CODE_DEPOSIT_COST_T2: u64 = 2_500;
const AUTH_ACCOUNT_CREATION_COST: u64 = 250_000;
const EIP7702_PER_EMPTY_ACCOUNT_COST: u64 = 12_500;

// T2 execution gas (computational overhead only)
const T2_EXEC_GAS: u64 = 5_000;
const T2_CODE_DEPOSIT_EXEC_GAS: u64 = 200;

/// Tempo gas params override.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    let mut gas_params = GasParams::new_spec(spec.into());
    let mut overrides = vec![];
    if spec.is_t2() {
        // TIP-1016: Split storage creation costs into execution gas + state gas.
        // Execution gas (computational overhead) stays in regular params.
        // Storage creation gas (permanent storage burden) moves to state gas params.
        overrides.extend([
            (GasId::sstore_set_without_load_cost(), T2_EXEC_GAS),
            (GasId::sstore_set_state_gas(), SSTORE_SET_COST - T2_EXEC_GAS),
            (GasId::tx_create_cost(), T2_EXEC_GAS),
            (GasId::create(), T2_EXEC_GAS),
            (GasId::create_state_gas(), CREATE_COST - T2_EXEC_GAS),
            (GasId::new_account_cost(), T2_EXEC_GAS),
            (
                GasId::new_account_state_gas(),
                NEW_ACCOUNT_COST - T2_EXEC_GAS,
            ),
            (GasId::new_account_cost_for_selfdestruct(), T2_EXEC_GAS),
            (GasId::code_deposit_cost(), T2_CODE_DEPOSIT_EXEC_GAS),
            (
                GasId::code_deposit_state_gas(),
                CODE_DEPOSIT_COST_T2 - T2_CODE_DEPOSIT_EXEC_GAS,
            ),
            (
                GasId::tx_eip7702_per_empty_account_cost(),
                EIP7702_PER_EMPTY_ACCOUNT_COST,
            ),
            (GasId::new(255), T2_EXEC_GAS),
            (GasId::new(254), AUTH_ACCOUNT_CREATION_COST - T2_EXEC_GAS),
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
                EIP7702_PER_EMPTY_ACCOUNT_COST,
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

    #[test]
    fn test_t2_gas_params_splits_storage_costs() {
        let gas_params = tempo_gas_params(TempoHardfork::T2);

        // T2 execution gas (computational overhead only)
        assert_eq!(gas_params.get(GasId::sstore_set_without_load_cost()), 5_000);
        assert_eq!(gas_params.get(GasId::new_account_cost()), 5_000);
        assert_eq!(
            gas_params.get(GasId::new_account_cost_for_selfdestruct()),
            5_000
        );
        assert_eq!(gas_params.get(GasId::tx_create_cost()), 5_000);
        assert_eq!(gas_params.get(GasId::create()), 5_000);
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 200);

        // T2 state gas (storage creation burden)
        assert_eq!(gas_params.get(GasId::sstore_set_state_gas()), 245_000);
        assert_eq!(gas_params.get(GasId::new_account_state_gas()), 245_000);
        assert_eq!(gas_params.get(GasId::create_state_gas()), 495_000);
        assert_eq!(gas_params.get(GasId::code_deposit_state_gas()), 2_300);

        // Auth account creation also split
        assert_eq!(gas_params.get(GasId::new(255)), 5_000);
        assert_eq!(gas_params.get(GasId::new(254)), 245_000);
    }

    #[test]
    fn test_t2_total_gas_matches_t1() {
        let t1 = tempo_gas_params(TempoHardfork::T1);
        let t2 = tempo_gas_params(TempoHardfork::T2);

        // SSTORE set: exec + state should equal T1 total
        assert_eq!(
            t2.get(GasId::sstore_set_without_load_cost()) + t2.get(GasId::sstore_set_state_gas()),
            t1.get(GasId::sstore_set_without_load_cost()),
            "SSTORE set: T2 exec + state must equal T1 total"
        );

        // New account: exec + state should equal T1 total
        assert_eq!(
            t2.get(GasId::new_account_cost()) + t2.get(GasId::new_account_state_gas()),
            t1.get(GasId::new_account_cost()),
            "new_account: T2 exec + state must equal T1 total"
        );

        // CREATE: exec + state should equal T1 total
        assert_eq!(
            t2.get(GasId::create()) + t2.get(GasId::create_state_gas()),
            t1.get(GasId::create()),
            "CREATE: T2 exec + state must equal T1 total"
        );

        // Code deposit: T2 total is higher (2,500/byte vs 1,000/byte) per TIP-1016
        assert_eq!(
            t2.get(GasId::code_deposit_cost()) + t2.get(GasId::code_deposit_state_gas()),
            2_500,
            "code_deposit: T2 total should be 2,500/byte per TIP-1016"
        );

        // Auth account creation: exec + state should equal T1 total
        assert_eq!(
            t2.get(GasId::new(255)) + t2.get(GasId::new(254)),
            t1.get(GasId::new(255)),
            "auth_account_creation: T2 exec + state must equal T1 total"
        );
    }
}
