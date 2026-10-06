use crate::{Precompile, charge_input_cost, dispatch, key_publisher::KeyPublisher, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IKeyPublisher;

impl Precompile for KeyPublisher {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IKeyPublisher::IKeyPublisherCalls {
                    // Publishers
                    createPublisher(call) => mutate(call, msg_sender, |sender, c| {
                        self.create_publisher(sender, c)
                    }),
                    computePublisherId(call) => view(call, |c| self.publisher_id(c.creator, c.salt)),
                    transferOwnership(call) => mutate(call, msg_sender, |sender, c| {
                        self.transfer_ownership(sender, c)
                    }),
                    // Keys
                    setKeys(call) => mutate(call, msg_sender, |sender, c| self.set_keys(sender, c)),
                    revokeKey(call) => mutate(call, msg_sender, |sender, c| {
                        self.revoke_key(sender, c)
                    }),
                    // View functions
                    owner(call) => view(call, |c| self.owner(c.publisherId)),
                    activeKeys(call) => view(call, |c| self.active_keys(c.publisherId, c.issuer)),
                    keyValidUntil(call) => view(call, |c| {
                        self.key_valid_until(c.publisherId, c.issuer, c.keyHash)
                    }),
                    isKeyActive(call) => view(call, |c| {
                        self.is_key_active(c.publisherId, c.issuer, c.keyHash)
                    })
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        key_publisher::compute_publisher_id,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{B256, U256},
        sol_types::{SolCall, SolValue},
    };
    use tempo_chainspec::hardfork::TempoHardfork;
    use tempo_contracts::precompiles::{IKeyPublisher::IKeyPublisherCalls, KeyPublisherError};

    #[test]
    fn selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        StorageCtx::enter(&mut storage, || {
            let mut publisher = KeyPublisher::new();
            let unsupported = check_selector_coverage(
                &mut publisher,
                IKeyPublisherCalls::SELECTORS,
                "IKeyPublisher",
                IKeyPublisherCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }

    #[test]
    fn calls_through_abi() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T14);
        storage.set_timestamp(U256::from(1_000u64));
        StorageCtx::enter(&mut storage, || {
            let mut publisher = KeyPublisher::new();
            let creator = Address::repeat_byte(1);
            let owner = Address::repeat_byte(2);
            let salt = B256::repeat_byte(3);

            let calldata = IKeyPublisher::createPublisherCall {
                salt,
                owner,
                initialKeys: vec![IKeyPublisher::IssuerKeys {
                    issuer: B256::with_last_byte(1),
                    keyHashes: vec![B256::with_last_byte(2)],
                }],
            }
            .abi_encode();
            let output = publisher.call(&calldata, creator)?;
            let id = B256::abi_decode(&output.bytes)?;
            assert_eq!(id, compute_publisher_id(creator, salt));

            let calldata = IKeyPublisher::computePublisherIdCall { creator, salt }.abi_encode();
            let output = publisher.call(&calldata, Address::ZERO)?;
            assert_eq!(B256::abi_decode(&output.bytes)?, id);

            let calldata = IKeyPublisher::isKeyActiveCall {
                publisherId: id,
                issuer: B256::with_last_byte(1),
                keyHash: B256::with_last_byte(2),
            }
            .abi_encode();
            let output = publisher.call(&calldata, Address::ZERO)?;
            assert!(bool::abi_decode(&output.bytes)?);

            let calldata = IKeyPublisher::setKeysCall {
                publisherId: id,
                issuer: B256::with_last_byte(1),
                keyHashes: vec![],
            }
            .abi_encode();
            expect_precompile_revert(
                &publisher.call(&calldata, creator),
                KeyPublisherError::unauthorized(),
            );
            Ok(())
        })
    }
}
