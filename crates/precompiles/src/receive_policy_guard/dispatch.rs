//! ABI dispatch for the [`ReceivePolicyGuard`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate, receive_policy_guard::ReceivePolicyGuard, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IReceivePolicyGuard;
impl Precompile for ReceivePolicyGuard {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IReceivePolicyGuard::IReceivePolicyGuardCalls {
                    balanceOf(call) => view(call, |c| self.balance_of(c.receipt)),
                    claim(call) => mutate(call, msg_sender, |sender, c| self.claim(sender, c.to, c.receipt)),
                    burnBlockedReceipt(call) => mutate(call, msg_sender, |sender, c| {
                        self.burn_blocked_receipt(sender, c.receipt)
                    })
                }
            }
        )
    }
}
