//! Shared Zone contract addresses and protocol limits.

use alloy_primitives::{Address, U256, address};

pub use crate::precompiles::PATH_USD_ADDRESS as ZONE_TOKEN_ADDRESS;

/// Sentinel emitted as `BatchSubmitted.withdrawalQueueIndex` when a batch carried no
/// withdrawals and therefore consumed no queue index (`NO_QUEUE_INDEX` in Solidity).
pub const NO_QUEUE_INDEX: U256 = U256::MAX;

/// Maximum callback gas a withdrawal may request.
///
/// The L1 processor adds fixed overhead, so this value keeps the outer
/// `processWithdrawals` transaction well below a 30M gas block.
pub const MAX_WITHDRAWAL_GAS_LIMIT: u64 = 10_000_000;

/// Maximum deposit entries that may remain outstanding on a ZonePortal.
pub const MAX_UNPROCESSED_DEPOSITS: usize = 230;

/// Maximum token enablements that may remain outstanding on a ZonePortal.
pub const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: usize = 8;

/// TempoState predeploy address on Zone L2.
pub const TEMPO_STATE_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000000");

/// ZoneInbox predeploy address on Zone L2.
pub const ZONE_INBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000001");

/// ZoneOutbox predeploy address on Zone L2.
pub const ZONE_OUTBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000002");

/// ZoneAllowlist precompile address on Zone L2, active from T15.
pub const ZONE_ALLOWLIST_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000003");

/// Maximum number of accounts the ZoneAllowlist precompile may hold.
pub const MAX_ZONE_ALLOWLIST_LEN: usize = 1_000_000;

/// Maximum number of accounts one `IZoneAllowlist.setAllowed` call may change.
pub const MAX_ZONE_ALLOWLIST_BATCH: usize = 5_000;

/// Zone-native fee manager precompile address.
///
/// This is adjacent to, but distinct from, Tempo L1's fee manager at `0xfeec...0000`.
pub const ZONE_FEE_MANAGER_ADDRESS: Address =
    address!("0xfeec000000000000000000000000000000000001");
