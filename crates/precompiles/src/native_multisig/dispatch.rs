//! ABI dispatch for the [`NativeMultisig`] precompile.

use super::NativeMultisig;
use crate::{Precompile, charge_input_cost, dispatch, mutate_void, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INativeMultisig;

impl Precompile for NativeMultisig {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                INativeMultisig::INativeMultisigCalls {
                    isMultisigAccount(call) => view(call, |c| self.is_multisig_account(c.account)),
                    getMultisigConfigId(call) => {
                        view(call, |c| self.get_multisig_config_id(c.account))
                    },
                    getMultisigConfig(call) => {
                        view(call, |c| self.get_multisig_config(c.account, c.configId))
                    },
                    updateMultisigConfig(call) => mutate_void(call, msg_sender, |sender, c| {
                        self.update_multisig_config(sender, c.configId, c.threshold, c.owners)
                    })
                }
            }
        )
    }
}
