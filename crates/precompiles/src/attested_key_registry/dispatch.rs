//! ABI dispatch for the [`AttestedKeyRegistry`] precompile.

use super::AttestedKeyRegistry;
use crate::{Precompile, charge_input_cost, dispatch, mutate, storage::Handler, view};
use alloy::primitives::Address;
use evm2::precompiles::PrecompileResult;
use tempo_contracts::precompiles::IAttestedKeyRegistry;

impl Precompile for AttestedKeyRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAttestedKeyRegistry::IAttestedKeyRegistryCalls {
                    createPolicy(call) => mutate(call, msg_sender, |sender, c| {
                        self.create_policy(sender, c)
                    }),
                    computePolicyId(call) => view(call, |c| self.compute_policy_id(c.creator, c.salt)),
                    proposeMeasurement(call) => mutate(call, msg_sender, |sender, c| {
                        self.propose_measurement(sender, c.policyId, c.measurement)
                    }),
                    proposeAnchor(call) => mutate(call, msg_sender, |sender, c| {
                        self.propose_anchor(sender, c.policyId)
                    }),
                    cancelProposal(call) => mutate(call, msg_sender, |sender, c| {
                        self.cancel_proposal(sender, c.policyId, c.entry, c.isAnchor)
                    }),
                    removeMeasurement(call) => mutate(call, msg_sender, |sender, c| {
                        self.remove_measurement(sender, c.policyId, c.measurement)
                    }),
                    removeAnchor(call) => mutate(call, msg_sender, |sender, c| {
                        self.remove_anchor(sender, c.policyId)
                    }),
                    revokeKeys(call) => mutate(call, msg_sender, |sender, c| {
                        self.revoke_keys(sender, c.policyId)
                    }),
                    pause(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_paused(sender, c.policyId, true)
                    }),
                    unpause(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_paused(sender, c.policyId, false)
                    }),
                    setDelay(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_delay(sender, c.policyId, c.newDelay)
                    }),
                    setGuardian(call) => mutate(call, msg_sender, |sender, c| {
                        self.set_guardian(sender, c.policyId, c.newGuardian)
                    }),
                    transferOwnership(call) => mutate(call, msg_sender, |sender, c| {
                        self.transfer_ownership(sender, c.policyId, c.newOwner)
                    }),
                    registerKey(call) => mutate(call, msg_sender, |_, c| self.register_key(c)),
                    policy(call) => view(call, |c| self.policy(c.policyId)),
                    measurementActiveAt(call) => view(call, |c| {
                        self.measurement_active_at[c.policyId][c.measurement].read()
                    }),
                    anchorActiveAt(call) => view(call, |c| {
                        self.anchor_active_at[c.policyId][c.anchor].read()
                    }),
                    keyValidUntil(call) => view(call, |c| {
                        self.key_valid_until(c.policyId, c.programKeyX, c.programKeyY)
                    }),
                }
            }
        )
    }
}
