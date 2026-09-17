//! ABI dispatch for the [`ZoneFactory`] precompile.

use crate::{Precompile, charge_input_cost, dispatch, mutate, view};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IZoneFactory;

use super::ZoneFactory;

impl Precompile for ZoneFactory {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IZoneFactory::IZoneFactoryCalls {
                    owner(call) => view(self, call, |this, _| this.owner()),
                    transferOwnership(call) => {
                        mutate(self, call, msg_sender, |this, sender, call| {
                            this.transfer_ownership(sender, call)
                        })
                    },
                    createZone(call) => {
                        mutate(self, call, msg_sender, |this, sender, call| this.create_zone(sender, call))
                    },
                    nextZoneId(call) => view(self, call, |this, _| this.next_zone_id()),
                    zones(call) => view(self, call, |this, call| this.zone(call.id)),
                    isZonePortal(call) => view(self, call, |this, call| this.is_zone_portal(call.portal)),
                }
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{StorageCtx, hashmap::HashMapStorageProvider},
        test_util::{assert_full_coverage, check_selector_coverage},
    };
    use alloy::sol_types::SolCall;
    use tempo_contracts::precompiles::IZoneFactory::IZoneFactoryCalls;

    #[test]
    fn create_zone_selector_matches_tip_1091() {
        assert_eq!(
            IZoneFactory::createZoneCall::SELECTOR,
            [0x89, 0x67, 0x7d, 0x9e]
        );
    }

    #[test]
    fn selector_coverage() -> eyre::Result<()> {
        let mut storage = HashMapStorageProvider::new(1);
        StorageCtx::enter(&mut storage, || {
            let mut factory = ZoneFactory::new();
            let unsupported = check_selector_coverage(
                &mut factory,
                IZoneFactoryCalls::SELECTORS,
                "IZoneFactory",
                IZoneFactoryCalls::name_by_selector,
            );
            assert_full_coverage([unsupported]);
            Ok(())
        })
    }
}
