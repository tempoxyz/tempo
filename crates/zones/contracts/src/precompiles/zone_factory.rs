//! Native TIP-1091 `ZoneFactory` precompile ABI.

use alloy_primitives::{Address, FixedBytes, address, fixed_bytes};

pub use ZoneFactory::ZoneInfo;

/// Maximum number of sequencers in a Zone's active sequencer set.
pub const MAX_SEQUENCERS: usize = 8;

/// Protocol-managed ZoneFactory address defined by TIP-1091.
pub const ZONE_FACTORY_ADDRESS: Address = address!("0x5aF2000000000000000000000000000000000000");
pub const ZONE_PORTAL_PREFIX: FixedBytes<12> = fixed_bytes!("5AD000000000000000000000");
pub const ZONE_PORTAL_IMPL_ADDRESS: Address =
    address!("0x5AD1000000000000000000000000000000000000");
pub const ZONE_VERIFIER_ADDRESS: Address = address!("0x5a56000000000000000000000000000000000000");
pub const ZONE_MESSENGER_ADDRESS: Address = address!("0x5A4d000000000000000000000000000000000000");

crate::sol! {
    #[sol(abi)]
    #[derive(Debug)]
    contract ZoneFactory {
        struct ZoneInfo {
            uint32 zoneId;
            address portal;
            bool accessMode;
            bool gatewayMode;
            address admin;
            address[] sequencers;
            uint8 threshold;
            address verifier;
            string rpcUrl;
        }
        struct CreateZoneParams {
            address initialToken;
            bool accessMode;
            bool gatewayMode;
            address[] allowedAccounts;
            address[] zoneGateways;
            address admin;
            address[] sequencers;
            uint8 threshold;
            string rpcUrl;
        }
        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
        event ZoneCreated(
            uint32 indexed zoneId,
            address indexed portal,
            address initialToken,
            bool accessMode,
            bool gatewayMode,
            address admin,
            address[] sequencers,
            uint8 threshold,
            address verifier
        );
        error InvalidToken();
        error NotOwner();
        error InvalidAdmin();
        error InvalidSequencerSet();
        error InvalidClosedLoopConfig();
        error DuplicateAllowedAccount();
        error DuplicateZoneGateway();
        function owner() external view returns (address);
        function transferOwnership(address newOwner) external;
        function createZone(CreateZoneParams calldata params) external returns (uint32 zoneId, address portal);
        function zones(uint32 zoneId) external view returns (ZoneInfo memory);
        function nextZoneId() external view returns (uint32);
        function isZonePortal(address portal) external view returns (bool);
    }
}
