//! ABI dispatch for the [`ReceivePolicyGuard`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch, mutate_void, receive_policy_guard::ReceivePolicyGuard,
    view,
};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
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
                    claim(call) => mutate_void(call, msg_sender, |s, c| self.claim(s, c.to, c.receipt)),
                    burnBlockedReceipt(call) => mutate_void(call, msg_sender, |s, c| {
                        self.burn_blocked_receipt(s, c.receipt)
                    })
                }
            }
        )
    }
}
