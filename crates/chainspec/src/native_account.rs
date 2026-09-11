use alloy_primitives::Address;
use tempo_primitives::TempoAddressExt;

use crate::TempoHardfork;

/// Checks namespace eligibility only; account code and commitment state are checked by callers.
pub fn is_valid_native_account(address: Address, hardfork: TempoHardfork) -> bool {
    !address.is_zero()
        && !address.is_virtual()
        && !address.is_precompile(hardfork)
        && !alloy_evm::revm::precompile::Precompiles::new(
            alloy_evm::revm::precompile::PrecompileSpecId::from_spec_id(hardfork.into()),
        )
        .contains(&address)
        && address.zone_portal_id().is_none()
}
