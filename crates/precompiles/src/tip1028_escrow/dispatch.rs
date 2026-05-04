//! ABI dispatch for the [`TIP1028Escrow`] precompile.

use crate::{Precompile, charge_input_cost, dispatch_call, mutate_void, tip1028_escrow::TIP1028Escrow, view};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::ITIP1028Escrow::ITIP1028EscrowCalls;

impl Precompile for TIP1028Escrow {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            ITIP1028EscrowCalls::abi_decode,
            |call| match call {
                ITIP1028EscrowCalls::blockedReceiptBalance(call) => {
                    view(call, |c| self.blocked_receipt_balance(c))
                }
                ITIP1028EscrowCalls::claimBlocked(call) => {
                    mutate_void(call, msg_sender, |s, c| self.claim_blocked(s, c))
                }
                ITIP1028EscrowCalls::storeBlocked(call) => {
                    crate::mutate(call, msg_sender, |s, c| self.store_blocked(s, c))
                }
            },
        )
    }
}
