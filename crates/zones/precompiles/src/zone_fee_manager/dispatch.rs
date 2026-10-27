//! ABI dispatch for the [`ZoneFeeManager`] precompile.

use alloy_primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_precompiles::{
    Precompile as TempoPrecompile, charge_input_cost,
    dispatch::{missing_selector_result, selector_from_calldata, unknown_selector_result},
};

use super::ZoneFeeManager;

impl TempoPrecompile for ZoneFeeManager {
    fn call(&mut self, calldata: &[u8], _sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }

        // Zone fee settlement is protocol-only, this precompile does not accept external calls.
        if selector_from_calldata(calldata).is_none() {
            return missing_selector_result();
        }
        unknown_selector_result(calldata)
    }
}
