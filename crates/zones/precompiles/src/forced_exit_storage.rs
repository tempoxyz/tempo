//! Admission storage extension to Tempo's portal view.
//!
//! Tempo's pinned view ends at the T13 token cursor (slot 28). Keep its existing definition
//! authoritative for legacy fields; this view mirrors its final packed fields before TIP-1012. Reads
//! must use `L1State::read_l1`, just like other authenticated portal reads.
//!
//! TODO: Move these fields into Tempo's existing portal storage definition when we update
//! the Tempo dependency, then remove this local extension.
use alloy_primitives::{Address, U256};
use tempo_precompiles::storage::Mapping;
use tempo_precompiles_macros::{Storable, contract};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Storable)]
pub struct ForcedExitAdmissionMetadata {
    pub token: Address,
    pub deposit_number: u64,
}

#[contract]
pub struct ForcedExitPortalStorage {
    /// Preserve established slots, then mirror the prover fields at the start of slot 28.
    _legacy: [U256; 28],
    _last_processed_enabled_token_count: u64,
    _token_enablement_cursor_initialized: bool,
    pub forced_exit_version: u64,
    pub forced_exit_count: u64,
    pub forced_exit_requests: Mapping<u64, ForcedExitAdmissionMetadata>,
    _last_processed_forced_exit_id: u64,
}

impl ForcedExitPortalStorage {
    pub fn new(portal: Address) -> Self {
        Self::__new(portal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appended_slots_match_solidity_layout() {
        let portal = ForcedExitPortalStorage::new(Address::repeat_byte(1));
        assert_eq!(
            portal._last_processed_enabled_token_count.slot(),
            U256::from(28)
        );
        assert_eq!(
            portal
                ._last_processed_enabled_token_count
                .ctx()
                .packed_offset(),
            Some(0)
        );
        assert_eq!(
            portal._token_enablement_cursor_initialized.slot(),
            U256::from(28)
        );
        assert_eq!(
            portal
                ._token_enablement_cursor_initialized
                .ctx()
                .packed_offset(),
            Some(8)
        );
        assert_eq!(portal._last_processed_forced_exit_id.slot(), U256::from(30));
        assert_eq!(portal.forced_exit_count.slot(), U256::from(28));
        assert_eq!(portal.forced_exit_requests.slot(), U256::from(29));
        assert_eq!(portal.forced_exit_version.slot(), U256::from(28));
        assert_eq!(portal.forced_exit_version.ctx().packed_offset(), Some(9));
        // Mapping keys use standard Solidity ABI words; the value packs address + uint64.
        let mut key = [0u8; 64];
        key[31] = 1;
        key[63] = 29;
        assert_eq!(
            portal.forced_exit_requests[1].as_slot().slot(),
            U256::from_be_bytes(alloy_primitives::keccak256(key).0)
        );
        let value = &portal.forced_exit_requests[1];
        assert_eq!(value.token.slot(), value.deposit_number.slot());
        assert_eq!(value.deposit_number.ctx().packed_offset(), Some(20));
        assert_eq!(portal.forced_exit_count.ctx().packed_offset(), Some(17));
    }
}
