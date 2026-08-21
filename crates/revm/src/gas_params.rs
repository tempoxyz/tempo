use revm::{
    context_interface::cfg::{GasId, GasParams},
    primitives::OnceLock,
};
use tempo_chainspec::{
    constants::gas::{SSTORE_CREATE_COST, SSTORE_SET_COST, STORAGE_CREDIT_VALUE},
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

// TIP-1016 regular gas (computational overhead).
//
// SSTORE is not listed here: the T11 table inherits the whole TIP-1060 SSTORE
// family (5k residual set cost, matching restore refund, removed clearing
// refund, 245k creditable portion) from the T7 table it is built on.
const TIP1016_NEW_ACCOUNT_REGULAR: u64 = 25_000;
const TIP1016_CREATE_REGULAR: u64 = 32_000;
const TIP1016_CODE_DEPOSIT_REGULAR: u64 = 200;

// TIP-1016 state gas (permanent storage burden)
const TIP1016_NEW_ACCOUNT_STATE: u64 = NEW_ACCOUNT_COST - TIP1016_NEW_ACCOUNT_REGULAR; // 225,000
const TIP1016_CREATE_STATE: u64 = CONTRACT_CREATE_COST - TIP1016_CREATE_REGULAR; // 468,000
const TIP1016_CODE_DEPOSIT_STATE: u64 = 2_300;

/// Tempo gas params override.
///
/// The TIP-1016 regular/state gas split activates with the T11 hardfork; earlier
/// T1+ specs use the TIP-1000 (T1) / TIP-1060 (T7) costs.
#[inline]
pub fn tempo_gas_params(spec: TempoHardfork) -> GasParams {
    // TIP-1016 (T11): storage creation costs split into regular + state gas.
    // SSTORE is priced exactly as on T7 (TIP-1060); only the remaining creation
    // costs (CREATE, new account, code deposit, EIP-7702) gain the split.
    if spec.is_t11() {
        static TABLE: OnceLock<GasParams> = OnceLock::new();
        return TABLE.get_or_init(t11_gas_params).clone();
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
        // Used in sstore to charge first creation of storage. After first creation, credit is minted.
        (GasId::sstore_set_state_gas(), STORAGE_CREDIT_VALUE),
    ]);
    gas_params
}

/// Builds the T11 gas table: the TIP-1016 regular/state gas split.
///
/// Starts from the T7 (TIP-1060) table, inheriting the whole SSTORE family
/// unchanged: the 5k residual set cost, the matching restore-to-original-zero
/// refund, the removed clearing refund, and the 245k creditable portion in
/// `sstore_set_state_gas` (charged as state gas once EIP-8037 is enabled).
///
/// The remaining creation costs are split into a regular component
/// (computational overhead, the pre-TIP-1000 EVM cost) counted toward protocol
/// limits, and a state component (permanent storage burden) that is charged to
/// the user but exempt from block capacity: CREATE 32k + 468k, new account
/// 25k + 225k, code deposit 200 + 2,300 per byte, EIP-7702 auth 25k + 225k
/// (bytecode state gas deliberately zeroed).
fn t11_gas_params() -> GasParams {
    // All Tempo hardforks share the upstream Osaka base table, so building on
    // the T7 table only inherits the TIP-1000/TIP-1060 overrides; every
    // TIP-1000 creation cost T11 re-splits is overridden below.
    let mut gas_params = t7_gas_params();
    // TIP-1016: Split storage creation costs into regular gas + state gas.
    // Regular gas (computational overhead) = pre-TIP-1000 EVM cost.
    // State gas (permanent storage burden) = total - regular.
    gas_params.override_gas([
        // Contract metadata (CREATE base): 32k regular + 468k state
        (GasId::tx_create_cost(), TIP1016_CREATE_REGULAR),
        (GasId::create(), TIP1016_CREATE_REGULAR),
        (GasId::create_state_gas(), TIP1016_CREATE_STATE),
        // Account creation: 25k regular + 225k state
        (GasId::new_account_cost(), TIP1016_NEW_ACCOUNT_REGULAR),
        (GasId::new_account_state_gas(), TIP1016_NEW_ACCOUNT_STATE),
        (
            GasId::new_account_cost_for_selfdestruct(),
            TIP1016_NEW_ACCOUNT_REGULAR,
        ),
        // Code deposit: 200 regular + 2,300 state per byte
        (GasId::code_deposit_cost(), TIP1016_CODE_DEPOSIT_REGULAR),
        (GasId::code_deposit_state_gas(), TIP1016_CODE_DEPOSIT_STATE),
        // EIP-7702 delegation: 25k regular + 225k state = 250k per auth
        // (the disabled post-T1 auth refund is inherited from the T7 table)
        (GasId::tx_eip7702_regular_gas(), TIP1016_NEW_ACCOUNT_REGULAR),
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
            GasId::tx_eip7702_regular_gas(),
            EIP7702_PER_EMPTY_ACCOUNT_COST_T1,
        ),
        // Auth refund is disabled post-T1.
        (GasId::tx_eip7702_regular_refund(), 0),
    ]);
    gas_params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_override_gas_params_are_cached() {
        let t1 = tempo_gas_params(TempoHardfork::T1);
        let t5 = tempo_gas_params(TempoHardfork::T5);
        assert!(
            std::ptr::eq(t1.table(), t5.table()),
            "T1+ TIP-1000 gas params should share the cached table"
        );

        let amsterdam_a = tempo_gas_params(TempoHardfork::T11);
        let amsterdam_b = tempo_gas_params(TempoHardfork::T11);
        assert!(
            std::ptr::eq(amsterdam_a.table(), amsterdam_b.table()),
            "T11 Amsterdam gas params should share the cached table"
        );
    }

    /// TIP-1060 (T7): SSTORE creation charges only the 5k residual through the
    /// gas function; other TIP-1000 creation costs are unchanged. The 245k
    /// creditable portion sits in `sstore_set_state_gas` for the storage-credit
    /// hook, which charges it as execution gas (T7 runs with EIP-8037 disabled).
    #[test]
    fn test_t7_gas_params_sstore_residual() {
        let gas_params = tempo_gas_params(TempoHardfork::T7);

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

        // The creditable portion lives in `sstore_set_state_gas` for the
        // storage-credit hook, which charges it as execution gas on T7
        // (EIP-8037 stays disabled until T11).
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            STORAGE_CREDIT_VALUE,
            "T7 exposes the creditable portion via sstore_set_state_gas for the credit hook"
        );

        // T7+ shares the cached table.
        let t8 = tempo_gas_params(TempoHardfork::T8);
        assert!(
            std::ptr::eq(gas_params.table(), t8.table()),
            "T7+ TIP-1060 gas params should share the cached table"
        );
    }

    #[test]
    fn test_t1_gas_params_no_state_gas_split() {
        let gas_params = tempo_gas_params(TempoHardfork::T1);

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
    /// | Cold SSTORE (zero → non-zero)  | 7,200         | 245,000     | 252,200 |
    /// | Account creation (nonce 0 → 1) | 25,000        | 225,000     | 250,000 |
    /// | Contract metadata (CREATE)     | 32,000        | 468,000     | 500,000 |
    /// | Contract code storage (/byte)  | 200           | 2,300       | 2,500   |
    /// | EIP-7702 delegation (per auth) | 25,000        | 225,000     | 250,000 |
    ///
    /// SSTORE storage gas is the TIP-1060 creditable portion (`STORAGE_CREDIT_VALUE`
    /// = 245,000), charged as state gas by the storage-credit hook, and execution
    /// gas is charged exactly as on T7: warm read (100) +
    /// `sstore_set_without_load_cost` (`SSTORE_SET_COST` = 5,000), plus the
    /// Berlin cold slot surcharge (2,100) when cold.
    #[test]
    fn test_t11_gas_params_splits_storage_costs() {
        let gas_params = tempo_gas_params(TempoHardfork::T11);

        // T11 execution gas (regular/computational overhead)
        // SSTORE is inherited from the T7 table: static(100) +
        // sstore_set_without_load (5,000), with cold slot access (2,100)
        // retained separately through `cold_storage_cost`.
        assert_eq!(
            gas_params.get(GasId::sstore_set_without_load_cost()),
            SSTORE_SET_COST,
            "SSTORE set_without_load is the TIP-1060 residual, as on T7"
        );
        assert_eq!(
            gas_params.get(GasId::sstore_clearing_slot_refund()),
            0,
            "the storage-credit mint replaces the legacy SSTORE clearing refund"
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

        // T11 state gas (permanent storage burden)
        assert_eq!(
            gas_params.get(GasId::sstore_set_state_gas()),
            STORAGE_CREDIT_VALUE,
            "SSTORE state gas is the TIP-1060 creditable portion (245,000)"
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

        // EIP-7702 delegation: 25,000 regular + 225,000 state per auth.
        // `tx_eip7702_per_empty_account_cost` returns only the regular
        // portion; the state portion lives in `new_account_state_gas` (+ the
        // zeroed bytecode state gas).
        assert_eq!(
            gas_params.get(GasId::tx_eip7702_regular_gas()),
            25_000,
            "EIP-7702 per auth regular gas per spec"
        );
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost(),
            25_000,
            "EIP-7702 per auth regular gas per spec"
        );
        assert_eq!(
            gas_params.new_account_state_gas(),
            225_000,
            "EIP-7702 per auth state gas per spec"
        );
        assert_eq!(
            gas_params.tx_eip7702_per_empty_account_cost()
                + gas_params.new_account_state_gas()
                + gas_params.tx_eip7702_state_gas_bytecode(),
            250_000,
            "EIP-7702 per auth total = 25k regular + 225k state per spec"
        );
        assert_eq!(
            gas_params.tx_eip7702_auth_refund_regular(),
            0,
            "TIP-1000: no refund for existing accounts on T1+"
        );

        // SSTORE set refund for 0→X→0 restoration: capped at the residual set
        // charge. The 245k creditable portion is not routed through the refund
        // counter — the x→0 transition mints a storage credit instead.
        assert_eq!(
            gas_params.get(GasId::sstore_set_refund()),
            SSTORE_SET_COST,
            "SSTORE set refund = the T7 residual only; creditable portion mints a credit"
        );
    }

    /// TIP-1016 block accounting relies on the uncapped refund counter never
    /// exceeding the rolled-back regular charges of the same transaction
    /// (`tempo_block_regular_gas_used` subtracts the full refund from block
    /// gas). On the T11 table the counter can only hold the two
    /// restore-to-original SSTORE refunds, and each set/restore pair must net
    /// exactly the two warm accesses actually executed — upstream's EIP-3529
    /// calibration. Every other refund source must be zero.
    #[test]
    fn test_t11_restore_refunds_net_warm_access_costs() {
        let t11 = tempo_gas_params(TempoHardfork::T11);
        let warm = t11.get(GasId::sstore_static());

        // 0→x→0: charge (warm + set) + warm, refund sstore_set_refund.
        assert_eq!(
            (warm + t11.get(GasId::sstore_set_without_load_cost()) + warm)
                .saturating_sub(t11.get(GasId::sstore_set_refund())),
            2 * warm,
            "a 0→x→0 restore pair must net exactly two warm accesses"
        );
        // x→y→x: charge (warm + reset) + warm, refund sstore_reset_refund.
        assert_eq!(
            (warm + t11.get(GasId::sstore_reset_without_cold_load_cost()) + warm)
                .saturating_sub(t11.get(GasId::sstore_reset_refund())),
            2 * warm,
            "an x→y→x restore pair must net exactly two warm accesses"
        );

        // No other refund may reach the uncapped counter.
        assert_eq!(
            t11.get(GasId::sstore_clearing_slot_refund()),
            0,
            "clearing refund must stay zero: it would refund committed work"
        );
        assert_eq!(
            t11.get(GasId::selfdestruct_refund()),
            0,
            "selfdestruct refund must stay zero: it would refund committed work"
        );
        assert_eq!(
            t11.tx_eip7702_auth_refund_regular(),
            0,
            "EIP-7702 auth refund must stay zero on T1+"
        );
    }

    /// TIP-1016: Verify totals (regular + state) match the clarified spec table.
    /// Note: SSTORE total comparison needs to account for revm decomposition and the cold-slot charge.
    ///
    /// T1 sstore_set_without_load_cost = 250,000 (full TIP-1000 cost as override).
    /// T11 warm SSTORE = sstore_set_without_load_cost(5,000) + warm_read(100) + state(245,000) = 250,100.
    /// T11 cold SSTORE = warm path + cold_slot_access(2,100) = 252,200.
    #[test]
    fn test_t11_totals_match_spec() {
        let t11 = tempo_gas_params(TempoHardfork::T11);

        // Warm SSTORE total: write component(5,000) + warm read(100) + state(245,000)
        let warm_sstore_regular =
            t11.get(GasId::sstore_set_without_load_cost()) + t11.warm_storage_read_cost();
        assert_eq!(
            warm_sstore_regular + t11.get(GasId::sstore_set_state_gas()),
            250_100,
            "warm SSTORE total must be 250,100 (5,100 execution + 245,000 creditable state), as on T7"
        );

        // Cold SSTORE total: warm path + Berlin cold slot access(2,100)
        let cold_sstore_regular = warm_sstore_regular + t11.cold_storage_cost();
        assert_eq!(
            cold_sstore_regular + t11.get(GasId::sstore_set_state_gas()),
            252_200,
            "cold SSTORE total must include Berlin cold slot access charging"
        );

        // New account: 25,000 + 225,000 = 250,000
        assert_eq!(
            t11.get(GasId::new_account_cost()) + t11.get(GasId::new_account_state_gas()),
            250_000,
            "new_account total must be 250,000"
        );

        // CREATE: 32,000 + 468,000 = 500,000
        assert_eq!(
            t11.get(GasId::create()) + t11.get(GasId::create_state_gas()),
            500_000,
            "CREATE total must be 500,000"
        );

        // Code deposit: 200 + 2,300 = 2,500/byte
        assert_eq!(
            t11.get(GasId::code_deposit_cost()) + t11.get(GasId::code_deposit_state_gas()),
            2_500,
            "code_deposit total must be 2,500/byte"
        );

        // EIP-7702: 25,000 regular + 225,000 state = 250,000 per auth
        assert_eq!(
            t11.tx_eip7702_per_empty_account_cost()
                + t11.new_account_state_gas()
                + t11.tx_eip7702_state_gas_bytecode(),
            250_000,
            "EIP-7702 per auth total must be 250,000"
        );
    }
}
