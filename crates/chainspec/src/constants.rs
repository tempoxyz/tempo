//! Tempo constants shared by both the published surface and the reth-backed spec implementation.
//!
//! Gas-accounting constants are grouped under [`gas`].
//! Hardfork activation schedules live in [`mainnet`] and [`moderato`].

pub mod gas {
    //! Gas-accounting constants shared with `spec.rs`.

    use alloy_evm::revm::interpreter::gas::{
        COLD_SLOAD_COST as COLD_SLOAD, SSTORE_SET, WARM_SSTORE_RESET,
        WARM_STORAGE_READ_COST as WARM_SLOAD,
    };

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
    pub const TEMPO_T1_NEW_NONCE_KEY_GAS: u64 = COLD_SLOAD + SSTORE_SET;
    /// T2 adds 2 warm SLOADs for the extended nonce key lookup.
    pub const TEMPO_T2_NEW_NONCE_KEY_GAS: u64 = TEMPO_T1_NEW_NONCE_KEY_GAS + 2 * WARM_SLOAD;
}

pub mod mainnet {
    //! Tempo mainnet (Presto) hardfork activation constants.

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
}

pub mod moderato {
    //! Moderato testnet hardfork activation constants.

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
}
