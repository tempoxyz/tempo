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
                    balanceOf(call) => view(self, call, |this, c| this.balance_of(c.receipt)),
                    claim(call) => mutate(self, call, msg_sender, |this, s, c| this.claim(s, c.to, c.receipt)),
                    burnBlockedReceipt(call) => mutate(self, call, msg_sender, |this, s, c| {
                        this.burn_blocked_receipt(s, c.receipt)
                    })
                }
            }
        )
    }
}
