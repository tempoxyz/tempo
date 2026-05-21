//! ABI dispatch for the [`ReceivePolicyGuard`] precompile.

use crate::{
    Precompile, charge_input_cost, dispatch_call, mutate_void,
    receive_policy_guard::ReceivePolicyGuard, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IReceivePolicyGuard::IReceivePolicyGuardCalls;

impl Precompile for ReceivePolicyGuard {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
            IReceivePolicyGuardCalls::abi_decode,
            |call| match call {
                IReceivePolicyGuardCalls::balanceOf(call) => {
                    view(call, |c| self.balance_of(c.proof))
                }
                IReceivePolicyGuardCalls::claim(call) => {
                    mutate_void(call, msg_sender, |s, c| self.claim(s, c.to, c.proof))
                }
                IReceivePolicyGuardCalls::burnBlockedProof(call) => {
                    mutate_void(call, msg_sender, |s, c| self.burn_blocked_proof(s, c.proof))
                }
            },
        )
    }
}
