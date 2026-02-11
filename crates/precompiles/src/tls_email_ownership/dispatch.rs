use super::TLSEmailOwnership;
use crate::{Precompile, dispatch_call, input_cost, mutate, mutate_void, view};
use alloy::{
    primitives::Address,
    sol_types::SolInterface,
};
use revm::precompile::{PrecompileError, PrecompileResult};
use tempo_contracts::precompiles::ITLSEmailOwnership::ITLSEmailOwnershipCalls;

impl Precompile for TLSEmailOwnership {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        dispatch_call(
            calldata,
            ITLSEmailOwnershipCalls::abi_decode,
            |call| match call {
                // View functions
                ITLSEmailOwnershipCalls::owner(call) => view(call, |_| self.owner()),
                ITLSEmailOwnershipCalls::getVerifiedEmail(call) => {
                    view(call, |c| self.get_verified_email(c))
                }
                ITLSEmailOwnershipCalls::isVerified(call) => {
                    view(call, |c| self.is_verified(c))
                }
                ITLSEmailOwnershipCalls::getNotaryKey(call) => {
                    view(call, |c| self.get_notary_key(c))
                }

                // Mutate functions
                ITLSEmailOwnershipCalls::verifyEmail(call) => {
                    mutate(call, msg_sender, |s, c| self.verify_email(s, c))
                }
                ITLSEmailOwnershipCalls::changeOwner(call) => {
                    mutate_void(call, msg_sender, |s, c| self.change_owner(s, c))
                }
                ITLSEmailOwnershipCalls::setNotaryKey(call) => {
                    mutate_void(call, msg_sender, |s, c| self.set_notary_key(s, c))
                }
                ITLSEmailOwnershipCalls::removeNotaryKey(call) => {
                    mutate_void(call, msg_sender, |s, c| self.remove_notary_key(s, c))
                }
                ITLSEmailOwnershipCalls::revokeMyEmail(call) => {
                    mutate_void(call, msg_sender, |s, _c| self.revoke_my_email(s))
                }
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        expect_precompile_revert,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::{
        primitives::{Address, FixedBytes},
        sol_types::{SolCall, SolValue},
    };
    use tempo_contracts::precompiles::{
        ITLSEmailOwnership, ITLSEmailOwnership::ITLSEmailOwnershipCalls, TLSEmailOwnershipError,
    };

    #[test]
    fn test_function_selector_dispatch() -> eyre::Result<()> {
        let sender = Address::random();
        let owner = Address::random();

        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || -> eyre::Result<()> {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let result = tls.call(&[0x12, 0x34, 0x56, 0x78], sender)?;
            assert!(result.reverted);

            Ok(())
        })
    }

    #[test]
    fn test_owner_view_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let sender = Address::random();
        let owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let owner_call = ITLSEmailOwnership::ownerCall {};
            let calldata = owner_call.abi_encode();

            let result = tls.call(&calldata, sender)?;
            assert_eq!(result.gas_used, 0);

            let decoded = Address::abi_decode(&result.bytes)?;
            assert_eq!(decoded, owner);

            Ok(())
        })
    }

    #[test]
    fn test_unauthorized_set_notary_key_dispatch() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        let owner = Address::random();
        let non_owner = Address::random();
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();
            tls.initialize(owner)?;

            let call = ITLSEmailOwnership::setNotaryKeyCall {
                notaryKeyId: FixedBytes::<32>::from([0x01; 32]),
                notaryAddress: Address::random(),
            };
            let calldata = call.abi_encode();

            let result = tls.call(&calldata, non_owner);
            expect_precompile_revert(&result, TLSEmailOwnershipError::unauthorized());

            Ok(())
        })
    }

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut tls = TLSEmailOwnership::new();

            let unsupported = check_selector_coverage(
                &mut tls,
                ITLSEmailOwnershipCalls::SELECTORS,
                "ITLSEmailOwnership",
                ITLSEmailOwnershipCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }
}
