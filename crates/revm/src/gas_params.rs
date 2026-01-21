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
}

impl TempoGasParams for GasParams {
    fn gas_params(&self) -> &GasParams {
        self
    }
}

/// Tempo gas params override.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    let mut gas_params = GasParams::new_spec(spec.into());
    let mut overrides = vec![];
    if spec.is_t1() {
        overrides.extend([
            // storage set with SSTORE opcode.
            (GasId::sstore_set_without_load_cost(), 250_000),
            // Base cost of Create kind transaction.
            (GasId::tx_create_cost(), 500_000),
            // create cost for CREATE/CREATE2 opcodes.
            (GasId::create(), 500_000),
            // new account cost for new accounts.
            (GasId::new_account_cost(), 250_000),
            // Selfdestruct will not be possible to create new account as this can only be
            // done when account value is not zero.
            (GasId::new_account_cost_for_selfdestruct(), 250_000),
            // code deposit cost is 1000 per byte.
            (GasId::code_deposit_cost(), 1_000),
            // The base cost per authorization is reduced to 12,500 gas
            (GasId::tx_eip7702_per_empty_account_cost(), 12500),
            // Auth account creation cost.
            (GasId::new(255), 250_000),
        ]);
    }

    gas_params.override_gas(overrides);
    gas_params
}
