//! ABI dispatch for the [`TIP1028BlockedTransfers`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void,
    tip1028_blocked_transfers::TIP1028BlockedTransfers, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP1028BlockedTransfers::ITIP1028BlockedTransfersCalls;

impl Precompile for TIP1028BlockedTransfers {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP1028BlockedTransfersCalls::abi_decode,
            |call| match call {
                ITIP1028BlockedTransfersCalls::balanceOf(call) => {
                    view(call, |c| self.balance_of(c))
                }
                ITIP1028BlockedTransfersCalls::claim(call) => {
                    mutate_void(call, msg_sender, |s, c| self.claim(s, c))
                }
            },
        )
    }
}
