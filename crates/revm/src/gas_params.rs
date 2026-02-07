use alloy_primitives::U256;
use auto_impl::auto_impl;
use revm::context::transaction::AccessListItemTr;
use revm::context_interface::cfg::{GasId, GasParams};
use revm::interpreter::gas::{COLD_SLOAD_COST, SSTORE_SET, WARM_SSTORE_RESET};
use tempo_chainspec::hardfork::TempoHardfork;
use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

pub const EXISTING_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + WARM_SSTORE_RESET;
pub const NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD_COST + SSTORE_SET;
pub const EXPIRING_NONCE_GAS: u64 = 2 * COLD_SLOAD_COST + 100 + 3 * WARM_SSTORE_RESET;

const GAS_ID_TIP1000_AUTH_ACCOUNT_CREATION: u8 = 255;

/// Extending [`GasParams`] for Tempo use case.
#[auto_impl(&, Arc, Box, &mut)]
pub trait TempoGasParams {
    fn gas_params(&self) -> &GasParams;

    /// TIP-1000: account creation cost for auth list entries with nonce == 0.
    fn tip1000_auth_list_creation_gas(&self, nonce_zero_count: u64) -> u64 {
        nonce_zero_count
            * self
                .gas_params()
                .get(GasId::new(GAS_ID_TIP1000_AUTH_ACCOUNT_CREATION))
    }

    fn tip1000_nonce_zero_gas(&self, nonce_key: U256) -> u64 {
        if nonce_key == TEMPO_EXPIRING_NONCE_KEY {
            EXPIRING_NONCE_GAS
        } else {
            self.gas_params().get(GasId::new_account_cost())
        }
    }

    fn cold_account_access_cost(&self) -> u64 {
        self.gas_params().warm_storage_read_cost()
            + self.gas_params().cold_account_additional_cost()
    }

    fn access_list_gas(&self, accounts: u64, storage_slots: u64) -> u64 {
        accounts * self.gas_params().tx_access_list_address_cost()
            + storage_slots * self.gas_params().tx_access_list_storage_key_cost()
    }
}

impl TempoGasParams for GasParams {
    fn gas_params(&self) -> &GasParams {
        self
    }
}

pub fn count_access_list<T: AccessListItemTr>(access_list: impl Iterator<Item = T>) -> (u64, u64) {
    access_list.fold((0, 0), |(acc_count, storage_count), item| {
        (
            acc_count + 1,
            storage_count + item.storage_slots().count() as u64,
        )
    })
}

/// Counts access list items using a custom closure for storage slot counting.
/// Used when access list items don't implement AccessListItemTr.
pub fn count_access_list_raw<T, F>(
    access_list: impl Iterator<Item = T>,
    storage_count_fn: F,
) -> (u64, u64)
where
    F: Fn(&T) -> usize,
{
    access_list.fold((0, 0), |(acc_count, storage_count), item| {
        (
            acc_count + 1,
            storage_count + storage_count_fn(&item) as u64,
        )
    })
}

/// TIP-1000 intrinsic gas additions for auth list and first-tx costs.
#[inline]
pub fn tip1000_intrinsic_gas(
    gas_params: &GasParams,
    spec: TempoHardfork,
    nonce_zero_auths: u64,
    tx_nonce: u64,
    nonce_key: U256,
) -> u64 {
    let mut gas = gas_params.tip1000_auth_list_creation_gas(nonce_zero_auths);
    if spec.is_t1() && tx_nonce == 0 {
        gas += gas_params.tip1000_nonce_zero_gas(nonce_key);
    }
    gas
}

/// Tempo gas params override.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    let mut gas_params = GasParams::new_spec(spec.into());
    let mut overrides = vec![];
    if spec.is_t1() {
        overrides.extend([
            // storage set with SSTORE opcode.
            (GasId::sstore_set_without_load_cost(), 250_000),
            // Base cost of Create kind transaction.
            (GasId::tx_create_cost(), 500_000),
            // create cost for CREATE/CREATE2 opcodes.
            (GasId::create(), 500_000),
            // new account cost for new accounts.
            (GasId::new_account_cost(), 250_000),
            // Selfdestruct will not be possible to create new account as this can only be
            // done when account value is not zero.
            (GasId::new_account_cost_for_selfdestruct(), 250_000),
            // code deposit cost is 1000 per byte.
            (GasId::code_deposit_cost(), 1_000),
            // The base cost per authorization is reduced to 12,500 gas
            (GasId::tx_eip7702_per_empty_account_cost(), 12500),
            // TIP-1000: auth account creation cost.
            (GasId::new(GAS_ID_TIP1000_AUTH_ACCOUNT_CREATION), 250_000),
        ]);
    }

    gas_params.override_gas(overrides);
    gas_params
}
