//! Tempo constants shared by both the published surface and the reth-backed spec implementation.
//!
//! Gas-accounting constants are grouped under [`gas`].
//! Hardfork activation schedules live in [`mainnet`] and [`moderato`].

pub mod gas {
    //! Gas-accounting constants shared with `spec.rs`.

    use alloy_eips::eip1559::BaseFeeParams;

    const COLD_SLOAD: u64 = 2100;
    const WARM_SLOAD: u64 = 100;
    const WARM_SSTORE_RESET: u64 = 2900;
    const T1_SSTORE_SET: u64 = 20_000;

    /// TIP-1000 storage creation component for a zero-to-nonzero SSTORE.
    pub const SSTORE_CREATE_COST: u64 = 250_000;

    /// TIP-1060 SSTORE residual: EVM `0→x` base cost paid even when a credit applies.
    pub const SSTORE_SET_COST: u64 = 5_000;

    /// TIP-1060 value credited for clearing one occupied storage slot.
    pub const STORAGE_CREDIT_VALUE: u64 = SSTORE_CREATE_COST - SSTORE_SET_COST;

    /// T0 base fee: 10 billion attodollars (1×10^10).
    ///
    /// Attodollars are the atomic gas accounting units at 10^-18 USD precision.
    /// Basefee is denominated in attodollars.
    pub const TEMPO_T0_BASE_FEE: u64 = 10_000_000_000;

    /// T1 base fee: 20 billion attodollars (2×10^10).
    ///
    /// Attodollars are the atomic gas accounting units at 10^-18 USD precision.
    /// Basefee is denominated in attodollars.
    ///
    /// At this basefee, a standard TIP-20 transfer (~50,000 gas) costs:
    /// - Gas: 50,000 × 20 billion attodollars/gas = 1 quadrillion attodollars
    /// - Tokens: 1 quadrillion attodollars / 10^12 = 1,000 microdollars
    /// - Economic: 1,000 microdollars = 0.001 USD = 0.1 cents
    pub const TEMPO_T1_BASE_FEE: u64 = 20_000_000_000;

    /// TIP-1067 base fee cap: below the T1 fixed base fee.
    pub const TEMPO_T7_BASE_FEE_CAP: u64 = 12_000_000_000;

    /// TIP-1067 base fee floor: one twentieth of the TIP-1067 cap.
    pub const TEMPO_T7_BASE_FEE_FLOOR: u64 = TEMPO_T7_BASE_FEE_CAP / 20;

    /// TIP-1067 gas target for the dynamic base fee controller.
    pub const TEMPO_T7_BASE_FEE_GAS_TARGET: u64 = 10_000_000;

    /// TIP-1067 uses EIP-1559's base-fee update formula with a fixed 10M gas target.
    ///
    /// The params are `(max_change_denominator = 8, elasticity_multiplier = 1)`: `8` keeps the
    /// standard EIP-1559 maximum 12.5% per-block base-fee delta, while `1` prevents EIP-1559's
    /// usual target-halving because TIP-1067 supplies [`TEMPO_T7_BASE_FEE_GAS_TARGET`] directly.
    ///
    /// [TIP-1067]: <https://docs.tempo.xyz/protocol/tips/tip-1067>
    pub const TEMPO_T7_BASE_FEE_PARAMS: BaseFeeParams = BaseFeeParams::new(8, 1);

    /// Returns the TIP-1067 base fee for the child of a block.
    ///
    /// The update follows EIP-1559's integer formula against a fixed 10M gas target, then clamps the
    /// result to `[TEMPO_T7_BASE_FEE_FLOOR, TEMPO_T7_BASE_FEE_CAP]`.
    pub fn tempo_t7_next_block_base_fee(parent_base_fee: u64, parent_gas_used: u64) -> u64 {
        TEMPO_T7_BASE_FEE_PARAMS
            .next_block_base_fee(
                parent_gas_used,
                TEMPO_T7_BASE_FEE_GAS_TARGET,
                parent_base_fee,
            )
            .clamp(TEMPO_T7_BASE_FEE_FLOOR, TEMPO_T7_BASE_FEE_CAP)
    }
    /// [TIP-1010] general (non-payment) gas limit: 30 million gas per block.
    /// Cap for non-payment transactions.
    ///
    /// [TIP-1010]: <https://docs.tempo.xyz/protocol/tips/tip-1010>
    pub const TEMPO_T1_GENERAL_GAS_LIMIT: u64 = 30_000_000;

    /// TIP-1010 per-transaction gas limit cap: 30 million gas.
    /// Allows maximum-sized contract deployments under [TIP-1000] state creation costs.
    ///
    /// [TIP-1000]: <https://docs.tempo.xyz/protocol/tips/tip-1000>
    pub const TEMPO_T1_TX_GAS_LIMIT_CAP: u64 = 30_000_000;

    /// Gas cost for using an existing 2D nonce key (cold SLOAD + warm SSTORE reset).
    pub const TEMPO_T1_EXISTING_NONCE_KEY_GAS: u64 = COLD_SLOAD + WARM_SSTORE_RESET;
    /// T2 adds 2 warm SLOADs for the extended nonce key lookup.
    pub const TEMPO_T2_EXISTING_NONCE_KEY_GAS: u64 =
        TEMPO_T1_EXISTING_NONCE_KEY_GAS + 2 * WARM_SLOAD;

    /// Gas cost for using a new 2D nonce key (cold SLOAD + SSTORE set for 0 -> non-zero).
    pub const TEMPO_T1_NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD + T1_SSTORE_SET;
    /// T2 adds 2 warm SLOADs for the extended nonce key lookup.
    pub const TEMPO_T2_NEW_NONCE_KEY_GAS: u64 = TEMPO_T1_NEW_NONCE_KEY_GAS + 2 * WARM_SLOAD;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn tip1067_dynamic_base_fee_steady_state() {
            assert_eq!(
                tempo_t7_next_block_base_fee(
                    TEMPO_T7_BASE_FEE_CAP / 2,
                    TEMPO_T7_BASE_FEE_GAS_TARGET
                ),
                TEMPO_T7_BASE_FEE_CAP / 2
            );
        }

        #[test]
        fn tip1067_dynamic_base_fee_decays_to_floor() {
            let mut base_fee = TEMPO_T7_BASE_FEE_CAP;
            for _ in 0..64 {
                base_fee = tempo_t7_next_block_base_fee(base_fee, 0);
            }
            assert_eq!(base_fee, TEMPO_T7_BASE_FEE_FLOOR);
            assert_eq!(
                tempo_t7_next_block_base_fee(base_fee, 0),
                TEMPO_T7_BASE_FEE_FLOOR
            );
        }

        #[test]
        fn tip1067_dynamic_base_fee_rises_to_cap() {
            let mut base_fee = TEMPO_T7_BASE_FEE_FLOOR;
            for _ in 0..16 {
                base_fee = tempo_t7_next_block_base_fee(base_fee, 500_000_000);
            }
            assert_eq!(base_fee, TEMPO_T7_BASE_FEE_CAP);
            assert_eq!(
                tempo_t7_next_block_base_fee(base_fee, 500_000_000),
                TEMPO_T7_BASE_FEE_CAP
            );
        }

        #[test]
        fn tip1067_dynamic_base_fee_minimum_increase() {
            assert_eq!(
                tempo_t7_next_block_base_fee(
                    TEMPO_T7_BASE_FEE_FLOOR,
                    TEMPO_T7_BASE_FEE_GAS_TARGET + 1
                ),
                TEMPO_T7_BASE_FEE_FLOOR + 7
            );
        }

        #[test]
        fn tip1067_dynamic_base_fee_clamps_equal_branch() {
            assert_eq!(
                tempo_t7_next_block_base_fee(
                    TEMPO_T7_BASE_FEE_FLOOR - 1,
                    TEMPO_T7_BASE_FEE_GAS_TARGET
                ),
                TEMPO_T7_BASE_FEE_FLOOR
            );
            assert_eq!(
                tempo_t7_next_block_base_fee(
                    TEMPO_T7_BASE_FEE_CAP + 1,
                    TEMPO_T7_BASE_FEE_GAS_TARGET
                ),
                TEMPO_T7_BASE_FEE_CAP
            );
        }
    }
}

pub mod mainnet {
    //! Tempo mainnet (Presto) chain id and hardfork activation constants.
    pub const MAINNET_CHAIN_ID: u64 = 4217;

    /// Genesis activation block.
    pub const MAINNET_GENESIS_BLOCK: u64 = 0;
    /// Genesis activation timestamp.
    pub const MAINNET_GENESIS_TIMESTAMP: u64 = 0;

    /// T0 activation block (active from genesis).
    pub const MAINNET_T0_BLOCK: u64 = 0;
    /// T0 activation timestamp (active from genesis).
    pub const MAINNET_T0_TIMESTAMP: u64 = 0;

    /// T1 activation block.
    pub const MAINNET_T1_BLOCK: u64 = 4_494_230;
    /// T1 activation timestamp (Feb 12th 2026 15:00 UTC).
    pub const MAINNET_T1_TIMESTAMP: u64 = 1_770_908_400;

    /// T1A activation block (same as T1 on mainnet).
    pub const MAINNET_T1A_BLOCK: u64 = MAINNET_T1_BLOCK;
    /// T1A activation timestamp (same as T1 on mainnet).
    pub const MAINNET_T1A_TIMESTAMP: u64 = MAINNET_T1_TIMESTAMP;

    /// T1B activation block.
    pub const MAINNET_T1B_BLOCK: u64 = 6_253_936;
    /// T1B activation timestamp (Feb 23rd 2026 15:00 UTC).
    pub const MAINNET_T1B_TIMESTAMP: u64 = 1_771_858_800;

    /// T1C activation block.
    pub const MAINNET_T1C_BLOCK: u64 = 8_967_991;
    /// T1C activation timestamp (Mar 12th 2026 15:00 UTC).
    pub const MAINNET_T1C_TIMESTAMP: u64 = 1_773_327_600;

    /// T2 activation block.
    pub const MAINNET_T2_BLOCK: u64 = 12_286_033;
    /// T2 activation timestamp (Mar 31st 2026 14:00 UTC).
    pub const MAINNET_T2_TIMESTAMP: u64 = 1_774_965_600;

    /// T3 activation timestamp (Apr 27th 2026 14:00 UTC).
    pub const MAINNET_T3_TIMESTAMP: u64 = 1_777_298_400;

    /// T4 activation timestamp (May 18th 2026 14:00 UTC).
    pub const MAINNET_T4_TIMESTAMP: u64 = 1_779_112_800;

    /// T5 activation timestamp (Jun 9th 2026 14:00 UTC).
    pub const MAINNET_T5_TIMESTAMP: u64 = 1_781_013_600;

    /// T6 activation timestamp (Jun 23rd 2026 14:00 UTC).
    pub const MAINNET_T6_TIMESTAMP: u64 = 1_782_223_200;

    /// T7 activation timestamp (Jul 9th 2026 14:00 UTC).
    pub const MAINNET_T7_TIMESTAMP: u64 = 1_783_605_600;
}

pub mod moderato {
    //! Moderato testnet chain id and hardfork activation constants.
    pub const MODERATO_CHAIN_ID: u64 = 42431;

    /// Genesis activation block.
    pub const MODERATO_GENESIS_BLOCK: u64 = 0;
    /// Genesis activation timestamp.
    pub const MODERATO_GENESIS_TIMESTAMP: u64 = 0;

    /// T0 activation block (same as T1 on moderato).
    pub const MODERATO_T0_BLOCK: u64 = 3_767_359;
    /// T0 activation timestamp (Feb 5th 2026 15:00 UTC).
    pub const MODERATO_T0_TIMESTAMP: u64 = 1_770_303_600;

    /// T1 activation block (same as T0 on moderato).
    pub const MODERATO_T1_BLOCK: u64 = MODERATO_T0_BLOCK;
    /// T1 activation timestamp (same as T0 on moderato).
    pub const MODERATO_T1_TIMESTAMP: u64 = MODERATO_T0_TIMESTAMP;

    /// T1A activation block (same as T1B on moderato).
    pub const MODERATO_T1A_BLOCK: u64 = 6_033_587;
    /// T1A activation timestamp (Feb 23rd 2026 15:00 UTC).
    pub const MODERATO_T1A_TIMESTAMP: u64 = 1_771_858_800;

    /// T1B activation block (same as T1A on moderato).
    pub const MODERATO_T1B_BLOCK: u64 = MODERATO_T1A_BLOCK;
    /// T1B activation timestamp (same as T1A on moderato).
    pub const MODERATO_T1B_TIMESTAMP: u64 = MODERATO_T1A_TIMESTAMP;

    /// T1C activation block.
    pub const MODERATO_T1C_BLOCK: u64 = 7_768_256;
    /// T1C activation timestamp (Mar 9th 2026 15:00 UTC).
    pub const MODERATO_T1C_TIMESTAMP: u64 = 1_773_068_400;

    /// T2 activation block.
    pub const MODERATO_T2_BLOCK: u64 = 10_072_242;
    /// T2 activation timestamp (Mar 26th 2026 14:00 UTC).
    pub const MODERATO_T2_TIMESTAMP: u64 = 1_774_537_200;

    /// T3 activation timestamp (Apr 21st 2026 14:00 UTC).
    pub const MODERATO_T3_TIMESTAMP: u64 = 1_776_780_000;

    /// T4 activation timestamp (May 14th 2026 14:00 UTC).
    pub const MODERATO_T4_TIMESTAMP: u64 = 1_778_767_200;

    /// T5 activation timestamp (Jun 3rd 2026 14:00 UTC).
    pub const MODERATO_T5_TIMESTAMP: u64 = 1_780_495_200;

    /// T6 activation timestamp (Jun 18th 2026 14:00 UTC).
    pub const MODERATO_T6_TIMESTAMP: u64 = 1_781_791_200;

    /// T7 activation timestamp (Jul 2nd 2026 14:00 UTC).
    pub const MODERATO_T7_TIMESTAMP: u64 = 1_783_000_800;
}
