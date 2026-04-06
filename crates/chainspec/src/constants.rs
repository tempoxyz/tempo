//! Tempo hardfork activation block numbers and timestamps for mainnet and moderato.
//!
//! Block numbers are informational — Tempo hardforks activate by **timestamp**.

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
}
