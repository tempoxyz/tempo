use crate::{
    Precompile,
    address_registry::{
        AddressRegistry, MasterId, UserTag, decode_virtual_address, is_virtual_address,
    },
    charge_input_cost, dispatch_call, mutate, view,
};
use alloy::{primitives::Address, sol_types::SolInterface};
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IAddressRegistry::IAddressRegistryCalls;

impl Precompile for AddressRegistry {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch_call(
            calldata,
            &[],
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
        address_registry::IAddressRegistry,
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
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
            assert!(!result.is_revert());
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
}
