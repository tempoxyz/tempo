use super::NativeMultisig;
use crate::{Precompile, charge_input_cost, dispatch, mutate_void, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INativeMultisig;

impl Precompile for NativeMultisig {
    fn call(&mut self, calldata: &[u8], sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            INativeMultisig::INativeMultisigCalls {
                deriveAccount(call) => view(call, |c| self.derive_account(c.salt, c.threshold, c.owners)),
                getConfigCommitment(call) => view(call, |c| self.get_config_commitment(c.account)),
                updateConfig(call) => mutate_void(call, sender, |sender, c| self.update_config(sender, c.current, c.threshold, c.owners)),
            }
        })
    }
}
