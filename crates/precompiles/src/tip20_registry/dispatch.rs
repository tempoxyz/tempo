use crate::{
    Precompile, dispatch_call, input_cost, mutate,
    tip20_registry::{
        AddressRegistry, MasterId, UserTag, decode_virtual_address, is_virtual_address,
    },
    view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};
use tempo_contracts::precompiles::IAddressRegistry::IAddressRegistryCalls;

impl Precompile for AddressRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        self.storage
            .deduct_gas(input_cost(calldata.len()))
            .map_err(|_| PrecompileError::OutOfGas)?;

        // Pre-T3: behave like an empty contract (call succeeds, no execution)
        if !self.storage.spec().is_t3() {
            return Ok(PrecompileOutput::new(
                self.storage.gas_used(),
                Default::default(),
            ));
        }

        dispatch_call(
            calldata,
            IAddressRegistryCalls::abi_decode,
            |call| match call {
                // Registration
                IAddressRegistryCalls::registerVirtualMaster(call) => {
                    mutate(call, msg_sender, |s, c| self.register_virtual_master(s, c))
                }
                // View functions
                IAddressRegistryCalls::getMaster(call) => view(call, |c| {
                    Ok(self.get_master(c.masterId)?.unwrap_or(Address::ZERO))
                }),
                IAddressRegistryCalls::resolveRecipient(call) => {
                    view(call, |c| self.resolve_recipient(c.to))
                }
                IAddressRegistryCalls::resolveVirtualAddress(call) => {
                    view(call, |c| self.resolve_virtual_address(c.virtualAddr))
                }
                // Pure functions
                IAddressRegistryCalls::isVirtualAddress(call) => {
                    view(call, |c| Ok(is_virtual_address(c.addr)))
                }
                IAddressRegistryCalls::decodeVirtualAddress(call) => view(call, |c| {
                    let (is_virtual, master_id, user_tag) = match decode_virtual_address(c.addr) {
                        Some((mid, tag)) => (true, mid, tag),
                        None => (false, MasterId::ZERO, UserTag::ZERO),
                    };
                    Ok((is_virtual, master_id, user_tag).into())
                }),
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
        tip20_registry::IAddressRegistry,
    };
    use alloy::sol_types::{SolCall, SolValue};
    use tempo_chainspec::hardfork::TempoHardfork;

    #[test]
    fn test_selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            let unsupported = check_selector_coverage(
                &mut registry,
                IAddressRegistryCalls::SELECTORS,
                "IAddressRegistry",
                IAddressRegistryCalls::name_by_selector,
            );

            assert_full_coverage([unsupported]);

            Ok(())
        })
    }

    #[test]
    fn test_get_master_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            // Unregistered masterId returns address(0)
            let call = IAddressRegistry::getMasterCall {
                masterId: Default::default(),
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!result.reverted);
            let addr = Address::abi_decode(&result.bytes).unwrap();
            assert_eq!(addr, Address::ZERO);

            Ok(())
        })
    }

    #[test]
    fn test_is_virtual_address_precompile() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new_with_spec(1, TempoHardfork::T3);
        StorageCtx::enter(&mut storage, || {
            let mut registry = AddressRegistry::new();

            // Non-virtual
            let call = IAddressRegistry::isVirtualAddressCall {
                addr: Address::random(),
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(!bool::abi_decode(&result.bytes).unwrap());

            // Virtual
            let mut bytes = [0u8; 20];
            bytes[4..14].fill(0xFD);
            let call = IAddressRegistry::isVirtualAddressCall {
                addr: Address::from(bytes),
            };
            let result = registry.call(&call.abi_encode(), Address::ZERO)?;
            assert!(bool::abi_decode(&result.bytes).unwrap());

            Ok(())
        })
    }

    #[test]
    fn test_pre_t3_calls_return_empty() -> eyre::Result<()> {
        for hardfork in [TempoHardfork::T2, TempoHardfork::T1] {
            let mut storage = HashMapStorageProvider::new_with_spec(1, hardfork);
            StorageCtx::enter(&mut storage, || {
                let mut registry = AddressRegistry::new();

                let call = IAddressRegistry::getMasterCall {
                    masterId: Default::default(),
                };
                let result = registry.call(&call.abi_encode(), Address::ZERO)?;
                assert!(!result.reverted);
                assert!(result.bytes.is_empty());

                Ok::<_, revm::precompile::PrecompileError>(())
            })?;
        }
        Ok(())
    }
}
