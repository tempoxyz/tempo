//! ABI dispatch for the key publisher.

use super::KeyPublisher;
use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IKeyPublisher;

impl Precompile for KeyPublisher {
    fn call(&mut self, calldata: &[u8], sender: Address) -> PrecompileResult {
        if let Some(error) = charge_input_cost(&mut self.storage, calldata) {
            return error;
        }
        dispatch!(calldata, |call| match call {
            IKeyPublisher::IKeyPublisherCalls {
                computePublisherId(call) => view(call, |call| Ok(Self::compute_publisher_id(call.creator, call.salt))),
                owner(call) => view(call, |call| self.owner(call.publisherId)),
                activeKeys(call) => view(call, |call| self.active_keys(call.publisherId, call.issuer)),
                keyValidUntil(call) => view(call, |call| self.key_valid_until(call.publisherId, call.issuer, call.keyHash)),
                isKeyActive(call) => view(call, |call| self.is_key_active(call.publisherId, call.issuer, call.keyHash)),
                createPublisher(call) => mutate(call, sender, |sender, call| self.create_publisher(sender, call)),
                transferOwnership(call) => mutate(call, sender, |sender, call| self.transfer_ownership(sender, call)),
                setKeys(call) => mutate(call, sender, |sender, call| self.set_keys(sender, call)),
                revokeKey(call) => mutate(call, sender, |sender, call| self.revoke_key(sender, call))
            }
        })
    }
}
