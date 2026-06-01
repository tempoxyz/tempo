//! ABI dispatch for the [`NativeMultisig`] precompile.

use super::NativeMultisig;
use crate::{Precompile, charge_input_cost, dispatch_call, mutate_void, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::INativeMultisig::INativeMultisigCalls;

impl Precompile for NativeMultisig {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            INativeMultisigCalls::abi_decode,
            |call| match call {
                INativeMultisigCalls::isMultisigAccount(call) => {
                    view(call, |c| self.is_multisig_account(c.account))
                }
                INativeMultisigCalls::getMultisigConfigId(call) => {
                    view(call, |c| self.get_multisig_config_id(c.account))
                }
                INativeMultisigCalls::getMultisigConfig(call) => {
                    view(call, |c| self.get_multisig_config(c.account, c.configId))
                }
                INativeMultisigCalls::updateMultisigConfig(call) => {
                    mutate_void(call, msg_sender, |sender, c| {
                        self.update_multisig_config(sender, c.configId, c.threshold, c.owners)
                    })
                }
            },
        )
    }
}
