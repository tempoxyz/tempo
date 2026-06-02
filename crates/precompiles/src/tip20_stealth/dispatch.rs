//! ABI dispatch for the [`TIP20Stealth`] precompile.

use crate::{Precompile, charge_input_cost, dispatch_call, mutate, tip20_stealth::TIP20Stealth};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP20Stealth::ITIP20StealthCalls;

impl Precompile for TIP20Stealth {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP20StealthCalls::abi_decode,
            |call| match call {
                ITIP20StealthCalls::transfer(call) => {
                    mutate(call, msg_sender, |sender, c| self.transfer(sender, c))
                }
            },
        )
    }
}
