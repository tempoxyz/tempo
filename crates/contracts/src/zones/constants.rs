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

/// Deposit-queue entries between consecutive ZonePortal checkpoints (TIP-1171).
///
/// A full Zone block verifies at most this many queue entries. Portal runtimes before T15 capped
/// outstanding entries at the same count, so ranges that start before the first checkpoint fit.
pub const DEPOSITS_PER_BUCKET: usize = 230;

/// Most deposit-queue weight a full Zone block executes (TIP-1171).
///
/// The block only hashes the entries of its range past this budget; later blocks execute them.
pub const MAX_DEPOSIT_WEIGHT_PER_BLOCK: u64 = 230;

/// Maximum token enablements that may remain outstanding on a ZonePortal.
pub const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: usize = 8;

/// TempoState predeploy address on Zone L2.
pub const TEMPO_STATE_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000000");

/// ZoneInbox predeploy address on Zone L2.
pub const ZONE_INBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000001");

/// ZoneOutbox predeploy address on Zone L2.
pub const ZONE_OUTBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000002");

/// Zone-native fee manager precompile address.
///
/// This is adjacent to, but distinct from, Tempo L1's fee manager at `0xfeec...0000`.
pub const ZONE_FEE_MANAGER_ADDRESS: Address =
    address!("0xfeec000000000000000000000000000000000001");
