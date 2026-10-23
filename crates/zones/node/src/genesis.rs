//! Zone genesis template and L1 anchoring.
//!
//! The bundled template initializes the native zone precompile accounts. It is standalone:
//! TempoState is anchored at block 0 with a zero block hash. [`l1_anchored_genesis`] patches
//! the L1 anchor and default fee token; the portal address is supplied to the runtime L1 overlay.

use alloy_consensus::Sealable;
use alloy_genesis::Genesis;
use alloy_primitives::{Address, U256};
use tempo_primitives::TempoHeader;
use zone_precompiles::{ZONE_FEE_MANAGER_ADDRESS, tempo_state, zone_fee_manager};
use zone_primitives::constants::TEMPO_STATE_ADDRESS;

/// Bundled zone dev genesis artifact.
pub const GENESIS_TEMPLATE_JSON: &str = include_str!("../assets/zone-dev-genesis.json");

/// Parses the bundled zone genesis template.
pub fn genesis_template() -> eyre::Result<Genesis> {
    serde_json::from_str(GENESIS_TEMPLATE_JSON).map_err(Into::into)
}

/// Builds a zone genesis anchored to a real L1 block.
///
/// Applies two patches to the [template](genesis_template):
///
/// 1. **TempoState storage**: `tempoBlockHash` and `tempoBlockNumber` must reflect the
///    L1 block that serves as the zone's genesis anchor. Without this, `finalizeTempo`
///    rejects the first L1 block for parent hash mismatch.
///
/// 2. **Default fee token**: ZoneFeeManager stores the portal's creation-time token in canonical
///    Zone state so fee resolution does not depend on node-local L1 cache state.
///
/// Returns `(genesis, genesis_block_number)`.
pub fn l1_anchored_genesis(
    l1_header: &TempoHeader,
    default_fee_token: Address,
) -> eyre::Result<(Genesis, u64)> {
    let genesis_block_number = l1_header.inner.number;

    let l1_genesis_hash = l1_header.hash_slow();

    let mut genesis = genesis_template()?;

    // Patch 1: TempoState storage.
    let tempo_state_account = genesis
        .alloc
        .get_mut(&TEMPO_STATE_ADDRESS)
        .ok_or_else(|| eyre::eyre!("TempoState not found in genesis alloc"))?;
    let storage = tempo_state_account
        .storage
        .get_or_insert_with(Default::default);
    storage.insert(tempo_state::slots::TEMPO_BLOCK_HASH.into(), l1_genesis_hash);
    storage.insert(
        tempo_state::slots::TEMPO_BLOCK_NUMBER.into(),
        U256::from(l1_header.inner.number).into(),
    );

    // Patch 2: canonical default fee token.
    let fee_manager_account = genesis
        .alloc
        .get_mut(&ZONE_FEE_MANAGER_ADDRESS)
        .ok_or_else(|| eyre::eyre!("ZoneFeeManager not found in genesis alloc"))?;
    fee_manager_account
        .storage
        .get_or_insert_with(Default::default)
        .insert(
            zone_fee_manager::slots::DEFAULT_FEE_TOKEN.into(),
            default_fee_token.into_word(),
        );

    Ok((genesis, genesis_block_number))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, address};
    use tempo_contracts::precompiles::PATH_USD_ADDRESS;
    use zone_primitives::constants::{ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS};

    #[test]
    fn template_has_native_system_account_markers() {
        let genesis = genesis_template().unwrap();
        for address in [TEMPO_STATE_ADDRESS, ZONE_INBOX_ADDRESS, ZONE_OUTBOX_ADDRESS] {
            assert_eq!(
                genesis.alloc[&address].code.as_ref().unwrap().as_ref(),
                &[0xef]
            );
        }
    }

    #[test]
    fn template_has_default_fee_token() {
        let genesis = genesis_template().unwrap();
        let fee_manager_storage = genesis.alloc[&ZONE_FEE_MANAGER_ADDRESS]
            .storage
            .as_ref()
            .unwrap();
        assert_eq!(
            fee_manager_storage[&B256::from(zone_fee_manager::slots::DEFAULT_FEE_TOKEN)],
            PATH_USD_ADDRESS.into_word(),
        );
    }

    #[test]
    fn anchored_genesis_patches_state() {
        let l1_header = TempoHeader::default();
        let default_fee_token = address!("0x20c0000000000000000000000000000000001234");

        let (genesis, genesis_block_number) =
            l1_anchored_genesis(&l1_header, default_fee_token).unwrap();
        assert_eq!(genesis_block_number, l1_header.inner.number);

        let storage = genesis.alloc[&TEMPO_STATE_ADDRESS]
            .storage
            .as_ref()
            .unwrap();
        assert_eq!(
            storage[&B256::from(tempo_state::slots::TEMPO_BLOCK_HASH)],
            l1_header.hash_slow(),
        );

        let fee_manager_storage = genesis.alloc[&ZONE_FEE_MANAGER_ADDRESS]
            .storage
            .as_ref()
            .unwrap();
        assert_eq!(
            fee_manager_storage[&B256::from(zone_fee_manager::slots::DEFAULT_FEE_TOKEN)],
            default_fee_token.into_word(),
        );
    }
}
