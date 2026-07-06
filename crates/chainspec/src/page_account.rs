use crate::spec::{TempoChainSpec, TempoHardforks};
use alloc::sync::Arc;
use alloy_primitives::{Address, address};
use tempo_primitives::TempoAddressExt;

/// Fixed system precompile addresses committed via page storage.
///
/// Mirrors `tempo_contracts::precompiles::SYSTEM_PRECOMPILES` (kept in sync by a test) so
/// this crate stays free of the contracts/sol-codegen dependency. Precompiles not yet
/// activated by their own hardfork have no storage, so listing them here is harmless.
const PAGE_STORAGE_SYSTEM_PRECOMPILES: &[Address] = &[
    address!("0x403C000000000000000000000000000000000000"), // TIP403 registry
    address!("0xfeec000000000000000000000000000000000000"), // tip fee manager
    address!("0xdec0000000000000000000000000000000000000"), // stablecoin DEX
    address!("0x4E4F4E4345000000000000000000000000000000"), // nonce manager
    address!("0xAAAAAAAA00000000000000000000000000000000"), // account keychain
    address!("0xCCCCCCCC00000000000000000000000000000000"), // validator config
    address!("0xCCCCCCCC00000000000000000000000000000001"), // validator config v2
    address!("0x20FC000000000000000000000000000000000000"), // TIP20 factory
    address!("0xFDC0000000000000000000000000000000000000"), // address registry
    address!("0x5165300000000000000000000000000000000000"), // signature verifier
    address!("0x4D50500000000000000000000000000000000000"), // TIP20 channel reserve
    address!("0xB10C000000000000000000000000000000000000"), // receive policy guard
    address!("0x1060000000000000000000000000000000000000"), // storage credits
];

/// Hardfork-gated page-account predicate used by the page-state commitment layer.
#[derive(Clone, Debug)]
pub struct PageAccountPredicate {
    spec: Arc<TempoChainSpec>,
}

impl PageAccountPredicate {
    pub const fn new(spec: Arc<TempoChainSpec>) -> Self {
        Self { spec }
    }

    pub fn is_active(&self, timestamp: u64) -> bool {
        self.spec.tempo_hardfork_at(timestamp).is_page_storage()
    }

    pub fn is_page_account(&self, timestamp: u64, address: &Address) -> bool {
        self.is_active(timestamp)
            && (address.is_tip20() || PAGE_STORAGE_SYSTEM_PRECOMPILES.contains(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::DEV;

    #[test]
    fn predicate_accepts_system_precompiles() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        for address in PAGE_STORAGE_SYSTEM_PRECOMPILES {
            assert!(predicate.is_page_account(0, address));
        }
    }

    #[test]
    fn predicate_accepts_tip20_prefix() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        let mut bytes = [0u8; 20];
        bytes[..12].copy_from_slice(&<Address as TempoAddressExt>::TIP20_PREFIX);
        bytes[19] = 1;
        assert!(predicate.is_page_account(0, &Address::from(bytes)));
    }

    #[test]
    fn predicate_rejects_non_page_accounts() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        assert!(!predicate.is_page_account(0, &Address::repeat_byte(0x55)));
    }

    #[test]
    fn system_precompile_list_matches_contracts() {
        let mut ours: alloc::vec::Vec<_> = PAGE_STORAGE_SYSTEM_PRECOMPILES.to_vec();
        let mut theirs: alloc::vec::Vec<_> = tempo_contracts::precompiles::SYSTEM_PRECOMPILES
            .iter()
            .map(|(address, _)| *address)
            .collect();
        ours.sort_unstable();
        theirs.sort_unstable();
        assert_eq!(
            ours, theirs,
            "PAGE_STORAGE_SYSTEM_PRECOMPILES is out of sync with SYSTEM_PRECOMPILES"
        );
    }
}
