//! Zone protocol constants shared between host and guest.

use alloy_primitives::{Address, U256, address};
use tempo_hardfork::constants::{mainnet::MAINNET_CHAIN_ID, moderato::MODERATO_CHAIN_ID};

/// Sentinel emitted as `BatchSubmitted.withdrawalQueueIndex` when a batch carried no
/// withdrawals and therefore consumed no queue index (`NO_QUEUE_INDEX` in Solidity).
pub const NO_QUEUE_INDEX: U256 = U256::MAX;

/// Maximum callback gas a withdrawal may request.
///
/// The L1 processor adds fixed overhead, so this value keeps the outer
/// keeps the outer `processWithdrawals` transaction well below a 30M gas block.
pub const MAX_WITHDRAWAL_GAS_LIMIT: u64 = 10_000_000;

/// Maximum number of Tempo headers authenticated by one checkpoint-only Zone block.
pub const MAX_TEMPO_HEADERS_PER_ZONE_BLOCK: usize = 1024;

/// Maximum deposit entries that may remain outstanding on a ZonePortal.
pub const MAX_UNPROCESSED_DEPOSITS: usize = 230;

/// Capacity reserved for one maximum-size withdrawal batch to bounce back.
pub const WITHDRAWAL_BOUNCEBACK_RESERVE: usize = 20;

/// Maximum token enablements that may remain outstanding on a ZonePortal.
pub const MAX_UNPROCESSED_TOKEN_ENABLEMENTS: usize = 8;

/// Maximum RLP-encoded block size.
///
/// This follows EIP-7934's `MAX_BLOCK_SIZE - SAFETY_MARGIN` and matches
/// `reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE`.
pub const MAX_RLP_BLOCK_SIZE: usize = 8_388_608;

/// TempoState predeploy address on Zone L2.
pub const TEMPO_STATE_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000000");

/// ZoneInbox predeploy address on Zone L2.
pub const ZONE_INBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000001");

/// ZoneOutbox predeploy address on Zone L2.
pub const ZONE_OUTBOX_ADDRESS: Address = address!("0x1c00000000000000000000000000000000000002");

/// Protocol-level contract deployers permitted to create contracts on Zones.
///
/// WARNING: Updating this list is a consensus change.
pub const CONTRACT_DEPLOYER_ALLOWLIST: &[Address] = &[];

/// Zone-native fee manager precompile address.
///
/// This is adjacent to, but distinct from, Tempo L1's fee manager at `0xfeec...0000`.
pub const ZONE_FEE_MANAGER_ADDRESS: Address =
    address!("0xfeec000000000000000000000000000000000001");

/// Default zone token address (pathUSD TIP-20).
pub const ZONE_TOKEN_ADDRESS: Address = address!("0x20C0000000000000000000000000000000000000");

/// Base offset for deriving **mainnet** zone chain IDs.
///
/// # Range safety
///
/// EIP-2294 and ENSIP-11 reserve bit 31 (`0x8000_0000`) for coin-type flags,
/// making chain IDs ≥ 2^31 (2,147,483,648) unsafe in parts of the ecosystem
/// (ENS multi-chain address resolution, some JavaScript tooling that uses
/// 32-bit integers, etc.).
///
/// The ranges are chosen so that both mainnet and testnet zones stay well below
/// that limit while remaining non-overlapping:
///
/// | Network  | Base            | Range size        | Chain ID span                         |
/// |----------|-----------------|-------------------|---------------------------------------|
/// | Mainnet  | `421_700_000`   | `1_002_610_000`   | `421_700_000 ..= 1_424_309_999`       |
/// | Testnet  | `1_424_310_000` | `723_173_648`     | `1_424_310_000 ..= 2_147_483_647`     |
///
pub const ZONE_CHAIN_ID_BASE: u64 = 421_700_000;

/// Number of distinct mainnet zone chain IDs.
///
/// Equal to `ZONE_CHAIN_ID_BASE_TESTNET - ZONE_CHAIN_ID_BASE`, keeping the
/// mainnet range strictly below the testnet range.
pub const ZONE_CHAIN_ID_RANGE: u64 = 1_002_610_000;

/// Base offset for deriving **testnet** (Moderato) zone chain IDs.
///
/// See [`ZONE_CHAIN_ID_BASE`] for range-safety rationale.
pub const ZONE_CHAIN_ID_BASE_TESTNET: u64 = 1_424_310_000;

/// Number of distinct Moderato zone chain IDs.
///
/// Equal to `2^31 - ZONE_CHAIN_ID_BASE_TESTNET`, keeping the testnet range
/// strictly below the EIP-2294 safe ceiling.
pub const ZONE_CHAIN_ID_RANGE_TESTNET: u64 = 723_173_648;

/// Largest generic parent chain ID accepted by [`zone_chain_id`].
///
/// This leaves enough headroom that every `u32` zone ID produces an EIP-155
/// legacy signature `v` value below JavaScript's `Number.MAX_SAFE_INTEGER`.
pub const MAX_GENERIC_PARENT_CHAIN_ID: u64 = (1 << 20) - 2;

/// Failure to derive a unique zone chain ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ZoneChainIdError {
    /// Production zone IDs must fit in the reserved range.
    #[error("zone ID {zone_id} exhausts the reserved range for parent chain {parent_chain_id}")]
    ZoneIdOutOfRange { parent_chain_id: u64, zone_id: u32 },
    /// Generic parent chain IDs must fit the supported tooling-safe range.
    #[error("generic parent chain ID must be in 1..={MAX_GENERIC_PARENT_CHAIN_ID}, got {0}")]
    InvalidParentChainId(u64),
    /// The chain ID is not a valid Zone chain ID.
    #[error("chain ID {0} is not a valid zone chain ID")]
    InvalidZoneChainId(u64),
}

/// Derives a zone EIP-155 chain ID from its parent Tempo chain and ZoneFactory ID.
///
/// The production branches remain below 2^31 for ecosystem compatibility. Other
/// parents use the high 32 bits, making the mapping injective for accepted inputs.
pub fn zone_chain_id(parent_chain_id: u64, zone_id: u32) -> Result<u64, ZoneChainIdError> {
    validate_chain_id(parent_chain_id, zone_id)?;

    let chain_id = match parent_chain_id {
        MAINNET_CHAIN_ID => ZONE_CHAIN_ID_BASE + zone_id as u64,
        MODERATO_CHAIN_ID => ZONE_CHAIN_ID_BASE_TESTNET + zone_id as u64,
        _ => (parent_chain_id << 32) | zone_id as u64,
    };

    Ok(chain_id)
}

/// Decodes the parent Tempo chain ID and ZoneFactory ID from a Zone chain ID.
pub fn decode_zone_chain_id(chain_id: u64) -> Result<(u64, u32), ZoneChainIdError> {
    let (parent_chain_id, zone_id) =
        if (ZONE_CHAIN_ID_BASE..ZONE_CHAIN_ID_BASE + ZONE_CHAIN_ID_RANGE).contains(&chain_id) {
            (MAINNET_CHAIN_ID, (chain_id - ZONE_CHAIN_ID_BASE) as u32)
        } else if (ZONE_CHAIN_ID_BASE_TESTNET
            ..ZONE_CHAIN_ID_BASE_TESTNET + ZONE_CHAIN_ID_RANGE_TESTNET)
            .contains(&chain_id)
        {
            (
                MODERATO_CHAIN_ID,
                (chain_id - ZONE_CHAIN_ID_BASE_TESTNET) as u32,
            )
        } else if chain_id >= 1 << 32 {
            (chain_id >> 32, chain_id as u32)
        } else {
            return Err(ZoneChainIdError::InvalidZoneChainId(chain_id));
        };

    if zone_chain_id(parent_chain_id, zone_id) == Ok(chain_id) {
        Ok((parent_chain_id, zone_id))
    } else {
        Err(ZoneChainIdError::InvalidZoneChainId(chain_id))
    }
}

/// Decodes the parent Tempo chain ID from a Zone chain ID.
pub fn decode_l1_chain_id(chain_id: u64) -> Result<u64, ZoneChainIdError> {
    decode_zone_chain_id(chain_id).map(|(parent_chain_id, _)| parent_chain_id)
}

fn validate_chain_id(parent_chain_id: u64, zone_id: u32) -> Result<(), ZoneChainIdError> {
    if parent_chain_id == 0 || parent_chain_id > MAX_GENERIC_PARENT_CHAIN_ID {
        return Err(ZoneChainIdError::InvalidParentChainId(parent_chain_id));
    }

    if (parent_chain_id == MAINNET_CHAIN_ID && zone_id as u64 >= ZONE_CHAIN_ID_RANGE)
        || (parent_chain_id == MODERATO_CHAIN_ID && zone_id as u64 >= ZONE_CHAIN_ID_RANGE_TESTNET)
    {
        return Err(ZoneChainIdError::ZoneIdOutOfRange {
            parent_chain_id,
            zone_id,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_domain_separated_chain_ids() {
        assert_eq!(zone_chain_id(MAINNET_CHAIN_ID, 7), Ok(421_700_007));
        assert_eq!(zone_chain_id(MODERATO_CHAIN_ID, 7), Ok(1_424_310_007));
        assert_ne!(zone_chain_id(1_337, 7), zone_chain_id(1_338, 7));

        let production = [
            zone_chain_id(MAINNET_CHAIN_ID, 42).unwrap(),
            zone_chain_id(MODERATO_CHAIN_ID, 42).unwrap(),
        ];
        let generic = zone_chain_id(1, 42).unwrap();
        assert!(production.into_iter().all(|id| id < 1 << 31));
        assert!(generic >= 1 << 32);
        assert!(!production.contains(&generic));
    }

    #[test]
    fn rejects_exhausted_ranges_and_invalid_generic_parents() {
        assert!(matches!(
            zone_chain_id(MAINNET_CHAIN_ID, ZONE_CHAIN_ID_RANGE as u32),
            Err(ZoneChainIdError::ZoneIdOutOfRange { .. })
        ));
        assert!(matches!(
            zone_chain_id(MODERATO_CHAIN_ID, ZONE_CHAIN_ID_RANGE_TESTNET as u32),
            Err(ZoneChainIdError::ZoneIdOutOfRange { .. })
        ));
        assert_eq!(
            zone_chain_id(0, 1),
            Err(ZoneChainIdError::InvalidParentChainId(0))
        );
        assert!(matches!(
            zone_chain_id(MAX_GENERIC_PARENT_CHAIN_ID + 1, 1),
            Err(ZoneChainIdError::InvalidParentChainId(_))
        ));

        let max_generic_chain_id = zone_chain_id(MAX_GENERIC_PARENT_CHAIN_ID, u32::MAX).unwrap();
        let max_legacy_v = max_generic_chain_id * 2 + 36;
        assert!(max_legacy_v < (1 << 53));
    }

    #[test]
    fn decodes_parent_chain_id() {
        for (parent_chain_id, zone_id) in [
            (MAINNET_CHAIN_ID, 7),
            (MODERATO_CHAIN_ID, 8),
            (1_337, 9),
            (MAX_GENERIC_PARENT_CHAIN_ID, u32::MAX),
        ] {
            let chain_id = zone_chain_id(parent_chain_id, zone_id).unwrap();
            assert_eq!(
                decode_zone_chain_id(chain_id),
                Ok((parent_chain_id, zone_id))
            );
            assert_eq!(decode_l1_chain_id(chain_id), Ok(parent_chain_id));
        }

        assert!(decode_l1_chain_id(ZONE_CHAIN_ID_BASE - 1).is_err());
        assert!(decode_l1_chain_id(1 << 31).is_err());
        assert!(decode_l1_chain_id((MAINNET_CHAIN_ID << 32) | 7).is_err());
    }
}
