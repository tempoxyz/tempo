use revm::{
    context_interface::cfg::{GasId, GasParams},
    primitives::OnceLock,
};
use tempo_chainspec::{constants::gas::SSTORE_SET_COST, hardfork::TempoHardfork};

/// The current Tempo gas table. The argument is chain metadata only; it cannot
/// select historical or deferred execution rules.
#[inline]
pub fn tempo_gas_params(_metadata: TempoHardfork) -> GasParams {
    static TABLE: OnceLock<GasParams> = OnceLock::new();
    TABLE.get_or_init(current_gas_params).clone()
}

fn current_gas_params() -> GasParams {
    let mut gas_params = GasParams::new_spec(TempoHardfork::CURRENT.into());
    gas_params.override_gas([
        // TIP-1060: the storage-credit hook handles the remaining 245k.
        (GasId::sstore_set_without_load_cost(), SSTORE_SET_COST),
        (GasId::sstore_set_refund(), SSTORE_SET_COST),
        (GasId::sstore_clearing_slot_refund(), 0),
        (GasId::tx_create_cost(), 500_000),
        (GasId::create(), 500_000),
        (GasId::new_account_cost(), 250_000),
        (GasId::new_account_cost_for_selfdestruct(), 250_000),
        (GasId::code_deposit_cost(), 1_000),
        (GasId::tx_eip7702_regular_gas(), 12_500),
        (GasId::tx_eip7702_regular_refund(), 0),
    ]);
    gas_params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_table_is_current_and_cached_for_every_metadata_version() {
        let current = tempo_gas_params(TempoHardfork::CURRENT);
        for &metadata in TempoHardfork::VARIANTS {
            let params = tempo_gas_params(metadata);
            assert!(
                std::ptr::eq(current.table(), params.table()),
                "{metadata:?}"
            );
        }
    }

    #[test]
    fn current_creation_costs_and_storage_credit_refunds() {
        let params = tempo_gas_params(TempoHardfork::CURRENT);
        for (id, expected) in [
            (GasId::sstore_set_without_load_cost(), 5_000),
            (GasId::sstore_set_refund(), 5_000),
            (GasId::sstore_clearing_slot_refund(), 0),
            (GasId::new_account_cost(), 250_000),
            (GasId::new_account_cost_for_selfdestruct(), 250_000),
            (GasId::tx_create_cost(), 500_000),
            (GasId::create(), 500_000),
            (GasId::code_deposit_cost(), 1_000),
            (GasId::tx_eip7702_regular_gas(), 12_500),
            (GasId::tx_eip7702_regular_refund(), 0),
        ] {
            assert_eq!(params.get(id), expected);
        }
    }

    #[test]
    fn current_table_has_no_deferred_state_gas_split() {
        let params = tempo_gas_params(TempoHardfork::CURRENT);
        let upstream = GasParams::new_spec(TempoHardfork::CURRENT.into());
        for id in [
            GasId::sstore_set_state_gas(),
            GasId::new_account_state_gas(),
            GasId::create_state_gas(),
            GasId::code_deposit_state_gas(),
        ] {
            assert_eq!(params.get(id), upstream.get(id));
        }
    }
}
