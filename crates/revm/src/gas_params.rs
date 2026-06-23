use revm::{
    context_interface::cfg::{GasId, GasParams},
    primitives::OnceLock,
};
use tempo_chainspec::{
    constants::gas::{SSTORE_CREATE_COST, SSTORE_SET_COST},
    hardfork::TempoHardfork,
};

// TIP-1000 total gas costs (used by T1)
const CONTRACT_CREATE_COST: u64 = 500_000;
const NEW_ACCOUNT_COST: u64 = 250_000;
const CODE_DEPOSIT_COST_T1: u64 = 1_000;
const EIP7702_PER_EMPTY_ACCOUNT_COST_T1: u64 = 12_500;

// TIP-1060 (T7): the SSTORE gas function charges only the 5,000-gas residual
// (`SSTORE_SET_COST`) on a clean creation (`original == present == 0`). The
// remaining 245,000-gas creditable portion of the TIP-1000 creation cost is
// governed by the storage-credit hook (see `sstore_storage_credits`), so it is
// no longer charged through the SSTORE gas function.

// TIP-1016 regular gas (computational overhead) — matches pre-TIP-1000 EVM costs.
// These values are "at least the pre-TIP-1000 (standard EVM) cost" per spec invariant 15.
//
// For SSTORE: revm decomposes the cost as sstore_static(WARM_STORAGE_READ=100) +
// sstore_set_without_load_cost(20,000), with the cold-slot surcharge applied separately.
const T4_SSTORE_SET_REGULAR: u64 = 20_000;
const T4_NEW_ACCOUNT_REGULAR: u64 = 25_000;
const T4_CREATE_REGULAR: u64 = 32_000;
const T4_CODE_DEPOSIT_REGULAR: u64 = 200;

// TIP-1016 state gas (permanent storage burden)
const T4_SSTORE_SET_STATE: u64 = SSTORE_CREATE_COST - T4_SSTORE_SET_REGULAR; // 230,000
const T4_NEW_ACCOUNT_STATE: u64 = NEW_ACCOUNT_COST - T4_NEW_ACCOUNT_REGULAR; // 225,000
const T4_CREATE_STATE: u64 = CONTRACT_CREATE_COST - T4_CREATE_REGULAR; // 468,000
const T4_CODE_DEPOSIT_STATE: u64 = 2_300;

// TIP-1016 SSTORE set refund for 0→X→0 restoration (combined state + regular).
// Spec: state_gas(230,000) + regular(GAS_STORAGE_UPDATE - GAS_COLD_SLOAD - GAS_WARM_ACCESS)
//      = 230,000 + (20,000 - 2,100 - 100) = 247,800
const T4_SSTORE_SET_REFUND: u64 = T4_SSTORE_SET_STATE + 17_800; // 230,000 + 17,800 = 247,800

/// Tempo gas params override.
///
/// `amsterdam_eip8037_enabled` mirrors `CfgEnv::enable_amsterdam_eip8037` and gates the
/// TIP-1016 regular/state gas split. When `false` on T1+, TIP-1000 (T1) costs are used,
/// so TIP-1016 can be deferred independently of the T4 hardfork activation.
#[inline]
pub fn tempo_gas_params_with_amsterdam(
    spec: TempoHardfork,
    amsterdam_eip8037_enabled: bool,
) -> GasParams {
    debug_assert!(
        !(spec.is_t7() && amsterdam_eip8037_enabled),
        "TODO(TIP-1016): generate combined TIP-1060 + EIP-8037 gas params before enabling both"
    );

    if amsterdam_eip8037_enabled {
        static TABLE: OnceLock<GasParams> = OnceLock::new();
        return TABLE.get_or_init(amsterdam_gas_params).clone();
    }

    // TIP-1060 (T7+): the SSTORE creation cost drops to the 5k residual; the
    // 245k creditable portion is handled by the storage-credit hook.
    if spec.is_t7() {
        static TABLE: OnceLock<GasParams> = OnceLock::new();
        return TABLE.get_or_init(t7_gas_params).clone();
    }

    if spec.is_t1() {
        static TABLE: OnceLock<GasParams> = OnceLock::new();
        return TABLE.get_or_init(t1_gas_params).clone();
    }

    GasParams::new_spec(spec.into())
}

/// Builds the T7 gas table: TIP-1000 creation costs, but the SSTORE creation
/// cost is lowered to the 5k residual (`SSTORE_SET_COST`) per TIP-1060.
///
/// revm charges this residual through `sstore_dynamic_gas` under the same
/// `original == present == 0` condition as the upstream storage-set cost, so a
/// dirty recreation (`x→0→y`) is charged neither the residual nor the base
/// set cost. The 245k creditable portion is charged (or covered by a credit) by
/// the storage-credit hook in `sstore_storage_credits`.
fn t7_gas_params() -> GasParams {
    // T7 starts from the TIP-1000 (T1) table so that every creation cost is inherited unchanged.
    // TIP-1060 only touches the SSTORE creation, clear, and restore-to-original-zero refund
    // entries overridden below; everything else (tx_create_cost, create, new_account_cost,
    // code_deposit_cost, eip7702 costs, auth refund) is exactly as in `t1_gas_params`.
    let mut gas_params = t1_gas_params();
    gas_params.override_gas([
        // SSTORE (zero -> non-zero): only the 5k residual; the 245k creditable portion is governed
        // by the TIP-1060 storage-credit hook (T1 charged the full `SSTORE_CREATE_COST` here).
        (GasId::sstore_set_without_load_cost(), SSTORE_SET_COST),
        // Restore (non-zero -> zero) refund must not exceed the T7 residual. Important with
        // TIP-1060 because the refund cap is removed. Otherwise, 0→x→0 could be refund-positive.
        (GasId::sstore_set_refund(), SSTORE_SET_COST),
        // TIP-1060: SSTORE_CLEARS_SCHEDULE = 0. The nonzero-to-zero clear is now handled by storage
        // credit minting, so the legacy clearing refund is removed. Restore-to-original-nonzero
        // refunds (sstore_reset_refund) remain at their upstream reset refund.
        (GasId::sstore_clearing_slot_refund(), 0),
    ]);
    gas_params
}

/// Builds the Amsterdam gas table with the TIP-1016 regular/state split.
fn amsterdam_gas_params() -> GasParams {
    let mut gas_params = GasParams::new_spec(TempoHardfork::T4.into());
    // TIP-1016: Split storage creation costs into regular gas + state gas.
    // Regular gas (computational overhead) = at least pre-TIP-1000 EVM cost.
    // State gas (permanent storage burden) = total - regular.
    gas_params.override_gas([
        // SSTORE (zero -> non-zero): 20k regular + 230k state
        (GasId::sstore_set_without_load_cost(), T4_SSTORE_SET_REGULAR),
        (GasId::sstore_set_state_gas(), T4_SSTORE_SET_STATE),
        (GasId::sstore_set_refund(), T4_SSTORE_SET_REFUND),
        // Contract metadata (CREATE base): 32k regular + 468k state
        (GasId::tx_create_cost(), T4_CREATE_REGULAR),
        (GasId::create(), T4_CREATE_REGULAR),
        (GasId::create_state_gas(), T4_CREATE_STATE),
        // Account creation: 25k regular + 225k state
        (GasId::new_account_cost(), T4_NEW_ACCOUNT_REGULAR),
        (GasId::new_account_state_gas(), T4_NEW_ACCOUNT_STATE),
        (
            GasId::new_account_cost_for_selfdestruct(),
            T4_NEW_ACCOUNT_REGULAR,
        ),
        // Code deposit: 200 regular + 2,300 state per byte
        (GasId::code_deposit_cost(), T4_CODE_DEPOSIT_REGULAR),
        (GasId::code_deposit_state_gas(), T4_CODE_DEPOSIT_STATE),
        // EIP-7702 delegation: 25k regular + 225k state = 250k per auth
        (
            GasId::tx_eip7702_per_empty_account_cost(),
            T4_NEW_ACCOUNT_REGULAR,
        ),
        // Auth refund is disabled post-T1.
        (GasId::tx_eip7702_auth_refund(), 0),
        // For each auth revm charges new_account_state_gas + tx_eip7702_state_gas_bytecode state gas
        //
        // Per TIP-1016, we only need 225k unconditional state gas charge (another 250k is charged only
        // if nonce is zero). Thus, we are zeroing the bytecode cost so that only new_account_state_gas (225k) is charged.
        (GasId::tx_eip7702_state_gas_bytecode(), 0),
    ]);
    gas_params
}

/// Builds the T1+ gas table with TIP-1000 costs and no state gas split.
fn t1_gas_params() -> GasParams {
    let mut gas_params = GasParams::new_spec(TempoHardfork::T1.into());
    // TIP-1000: All storage creation costs in regular gas (no state gas split).
    gas_params.override_gas([
        (GasId::sstore_set_without_load_cost(), SSTORE_CREATE_COST),
        (GasId::tx_create_cost(), CONTRACT_CREATE_COST),
        (GasId::create(), CONTRACT_CREATE_COST),
        (GasId::new_account_cost(), NEW_ACCOUNT_COST),
        (GasId::new_account_cost_for_selfdestruct(), NEW_ACCOUNT_COST),
        (GasId::code_deposit_cost(), CODE_DEPOSIT_COST_T1),
        (
            GasId::tx_eip7702_per_empty_account_cost(),
            EIP7702_PER_EMPTY_ACCOUNT_COST_T1,
        ),
        // Auth refund is disabled post-T1.
        (GasId::tx_eip7702_auth_refund(), 0),
    ]);
    gas_params
}

/// Backward-compatible alias for [`tempo_gas_params_with_amsterdam`] with TIP-1016 disabled.
///
/// External consumers (e.g. foundry) that depend on the single-argument signature continue
/// to work: TIP-1016 is opt-in via `tempo_gas_params_with_amsterdam(spec, true)`.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    tempo_gas_params_with_amsterdam(spec, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_override_gas_params_are_cached() {
        let t1 = tempo_gas_params_with_amsterdam(TempoHardfork::T1, false);
        let t5 = tempo_gas_params_with_amsterdam(TempoHardfork::T5, false);
        assert!(
            std::ptr::eq(t1.table(), t5.table()),
            "T1+ TIP-1000 gas params should share the cached table"
        );

        let amsterdam_t4 = tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);
        let amsterdam_t5 = tempo_gas_params_with_amsterdam(TempoHardfork::T5, true);
        assert!(
            std::ptr::eq(amsterdam_t4.table(), amsterdam_t5.table()),
            "Amsterdam gas params should share the cached table"
        );
    }

    /// TIP-1060 (T7): SSTORE creation charges only the 5k residual through the
    /// gas function; other TIP-1000 creation costs are unchanged, and there is
    /// no TIP-1016 state-gas split (production T7 runs with EIP-8037 disabled).
    #[test]
    fn test_t7_gas_params_sstore_residual() {
        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T7, false);

        // SSTORE creation cost drops to the 5k residual; the 245k creditable
        // portion is charged by the storage-credit hook, not the gas function.
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            5_000,
            "T7 SSTORE creation charges only the 5k residual"
        );
        assert!(
            gas_params.get(GasId::sstore_set_without_load_cost())
                >= gas_params.get(GasId::sstore_set_refund()),
            "T7 restore-to-original-zero refund must not exceed the residual set charge"
        );
        assert_eq!(
            gas_params.get(GasId::sstore_clearing_slot_refund()),
            0,
            "TIP-1060 removes the legacy SSTORE clearing refund"
        );

        // Other TIP-1000 creation costs are unchanged by TIP-1060.
        assert_eq!(gas_params.get(GasId::new_account_cost()), 250_000);
        assert_eq!(gas_params.get(GasId::tx_create_cost()), 500_000);
        assert_eq!(gas_params.get(GasId::create()), 500_000);
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 1_000);

        // No TIP-1016 state-gas split: state gas params stay at upstream defaults.
        let upstream = GasParams::new_spec(TempoHardfork::T7.into());
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            upstream.get(GasId::sstore_set_state_gas()),
            "T7 (EIP-8037 disabled) must not split SSTORE into state gas"
        );

        // T7+ shares the cached table.
        let t8 = tempo_gas_params_with_amsterdam(TempoHardfork::T8, false);
        assert!(
            std::ptr::eq(gas_params.table(), t8.table()),
            "T7+ TIP-1060 gas params should share the cached table"
        );
    }

    #[test]
    fn test_t1_gas_params_no_state_gas_split() {
        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T1, false);

        // T1 has full 250k costs in regular gas, no state gas split
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            250_000
        );
        assert_eq!(gas_params.get(GasId::new_account_cost()), 250_000);
        assert_eq!(gas_params.get(GasId::tx_create_cost()), 500_000);
        assert_eq!(gas_params.get(GasId::create()), 500_000);
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 1_000);

        // State gas params should remain at upstream defaults (not Tempo-bumped)
        let upstream = GasParams::new_spec(TempoHardfork::T1.into());
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            upstream.get(GasId::sstore_set_state_gas()),
            "T1 should not override state gas params"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_state_gas()),
            upstream.get(GasId::new_account_state_gas()),
        );
        assert_eq!(
            gas_params.get(GasId::create_state_gas()),
            upstream.get(GasId::create_state_gas()),
        );
    }

    /// TIP-1016 spec table: regular/state gas splits must match the spec exactly.
    ///
    /// | Operation                      | Execution Gas | Storage Gas | Total   |
    /// |--------------------------------|---------------|-------------|---------|
    /// | Cold SSTORE (zero → non-zero)  | 22,200        | 230,000     | 252,200 |
    /// | Account creation (nonce 0 → 1) | 25,000        | 225,000     | 250,000 |
    /// | Contract metadata (CREATE)     | 32,000        | 468,000     | 500,000 |
    /// | Contract code storage (/byte)  | 200           | 2,300       | 2,500   |
    /// | EIP-7702 delegation (per auth) | 25,000        | 225,000     | 250,000 |
    ///
    /// Note: The cold SSTORE total keeps Berlin's access charging. In revm terms the
    /// zero->non-zero write path is: warm read (100) + `sstore_set_without_load_cost` (20,000)
    /// + cold slot surcharge (2,100) + state gas (230,000) = 252,200.
    #[test]
    fn test_t4_gas_params_splits_storage_costs() {
        let gas_params = tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);

        // T4 execution gas (regular/computational overhead)
        // SSTORE keeps revm's decomposed accounting: static(100) + sstore_set_without_load(20,000),
        // with cold slot access (2,100) retained separately through `cold_storage_cost`.
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            20_000,
            "SSTORE set_without_load matches the retained zero->non-zero write component"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost()),
            25_000,
            "Account creation regular gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_cost_for_selfdestruct()),
            25_000
        );
        assert_eq!(
            gas_params.get(GasId::tx_create_cost()),
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::create()),
            32_000,
            "CREATE base regular gas per spec"
        );
        assert_eq!(gas_params.get(GasId::code_deposit_cost()), 200);

        // T4 state gas (permanent storage burden)
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            230_000,
            "SSTORE state gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::new_account_state_gas()),
            225_000,
            "Account creation state gas per spec"
        );
        assert_eq!(
            gas_params.get(GasId::create_state_gas()),
            468_000,
            "CREATE base state gas per spec"
        );
        assert_eq!(gas_params.get(GasId::code_deposit_state_gas()), 2_300);

        // EIP-7702 delegation: 25,000 regular + 225,000 state per auth
        assert_eq!(
            gas_params.get(GasId::tx_eip7702_per_empty_account_cost()),
            25_000,
            "EIP-7702 per auth total = 25k regular + 225k state per spec"
        );
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost(),
            250_000,
            "EIP-7702 per auth state gas per spec"
        );
        assert_eq!(
            gas_params.new_account_state_gas(),
            225_000,
            "EIP-7702 per auth state gas per spec"
        );
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost() - gas_params.new_account_state_gas(),
            25_000,
            "EIP-7702 per auth regular gas = total - state = 25k"
        );
        assert_eq!(
            gas_params.tx_eip7702_auth_refund_regular(),
            0,
            "TIP-1000: no refund for existing accounts on T1+"
        );

        // SSTORE set refund for 0→X→0 restoration (combined state + regular)
        // Spec: state_gas(230,000) + regular(20,000 - 2,100 - 100 = 17,800) = 247,800
        assert_eq!(
            gas_params.get(GasId::sstore_set_refund()),
            247_800,
            "SSTORE set refund = state(230k) + regular(17.8k) per spec"
        );
    }

    /// TIP-1016: Verify totals (regular + state) match the clarified spec table.
    /// Note: SSTORE total comparison needs to account for revm decomposition and the cold-slot charge.
    ///
    /// T1 sstore_set_without_load_cost = 250,000 (full TIP-1000 cost as override).
    /// T4 warm SSTORE = sstore_set_without_load_cost(20,000) + warm_read(100) + state(230,000) = 250,100.
    /// T4 cold SSTORE = warm path + cold_slot_access(2,100) = 252,200.
    #[test]
    fn test_t4_totals_match_spec() {
        let t4 = tempo_gas_params_with_amsterdam(TempoHardfork::T4, true);

        // Warm SSTORE total: write component(20,000) + warm read(100) + state(230,000)
        let warm_sstore_regular =
            t4.get(GasId::sstore_set_without_load_cost()) + t4.warm_storage_read_cost();
        assert_eq!(
            warm_sstore_regular + t4.get(GasId::sstore_set_state_gas()),
            250_100,
            "warm SSTORE total must be 250,100"
        );

        // Cold SSTORE total: warm path + Berlin cold slot access(2,100)
        let cold_sstore_regular = warm_sstore_regular + t4.cold_storage_cost();
        assert_eq!(
            cold_sstore_regular + t4.get(GasId::sstore_set_state_gas()),
            252_200,
            "cold SSTORE total must include Berlin cold slot access charging"
        );

        // New account: 25,000 + 225,000 = 250,000
        assert_eq!(
            t4.get(GasId::new_account_cost()) + t4.get(GasId::new_account_state_gas()),
            250_000,
            "new_account total must be 250,000"
        );

        // CREATE: 32,000 + 468,000 = 500,000
        assert_eq!(
            t4.get(GasId::create()) + t4.get(GasId::create_state_gas()),
            500_000,
            "CREATE total must be 500,000"
        );

        // Code deposit: 200 + 2,300 = 2,500/byte
        assert_eq!(
            t4.get(GasId::code_deposit_cost()) + t4.get(GasId::code_deposit_state_gas()),
            2_500,
            "code_deposit total must be 2,500/byte"
        );

        // EIP-7702: 25,000 regular + 225,000 state = 250,000 per auth
        assert_eq!(
            t4.tx_eip7702_per_empty_account_cost(),
            250_000,
            "EIP-7702 per auth total must be 250,000"
        );
    }
}
