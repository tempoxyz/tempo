use crate::spec::{TempoChainSpec, TempoHardforks};
use alloc::sync::Arc;
use alloy_primitives::{Address, address};
use tempo_primitives::TempoAddressExt;

const PAGE_STORAGE_DEX_ADDRESS: Address = address!("0xdec0000000000000000000000000000000000000");

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
        self.is_active(timestamp) && (*address == PAGE_STORAGE_DEX_ADDRESS || address.is_tip20())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::DEV;
    use tempo_primitives::address::TIP20_TOKEN_PREFIX;

    #[test]
    fn predicate_is_hardfork_gated() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        assert!(predicate.is_page_account(0, &PAGE_STORAGE_DEX_ADDRESS));
    }

    #[test]
    fn predicate_accepts_tip20_prefix() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        let mut bytes = [0u8; 20];
        bytes[..12].copy_from_slice(&TIP20_TOKEN_PREFIX);
        bytes[19] = 1;
        assert!(predicate.is_page_account(0, &Address::from(bytes)));
    }

    #[test]
    fn predicate_rejects_non_page_accounts() {
        let predicate = PageAccountPredicate::new(DEV.clone());
        assert!(!predicate.is_page_account(0, &Address::repeat_byte(0x55)));
    }
}
