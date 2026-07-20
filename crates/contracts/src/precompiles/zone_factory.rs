use alloy_primitives::{Address, address};

pub use IZoneFactory::{
    IZoneFactoryErrors as ZoneFactoryError, IZoneFactoryEvents as ZoneFactoryEvent,
};
pub use IZonePortal::IZonePortalEvents as ZonePortalEvent;

/// Native TIP-1091 ZoneFactory precompile address.
pub const ZONE_FACTORY_ADDRESS: Address = address!("0x5AF2000000000000000000000000000000000000");

// TODO: Set the final T9 ZoneFactory owner before merging this PR.
/// Initial ZoneFactory owner installed by the T9 activation.
pub const INITIAL_FACTORY_OWNER: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// Protocol-managed shared ZonePortal implementation address.
pub const ZONE_PORTAL_IMPL_ADDRESS: Address =
    address!("0x5AD1000000000000000000000000000000000000");

/// Protocol-managed Zone verifier address.
pub const ZONE_VERIFIER_ADDRESS: Address = address!("0x5A56000000000000000000000000000000000000");

/// Protocol-managed shared ZoneMessenger address.
pub const ZONE_MESSENGER_ADDRESS: Address = address!("0x5A4D000000000000000000000000000000000000");

crate::sol! {
    /// Zone metadata recorded by the native factory.
    #[derive(Debug, PartialEq, Eq)]
    struct ZoneInfo {
        uint32 zoneId;
        address portal;
        address initialToken;
        address admin;
        address[] sequencers;
        uint8 threshold;
        address verifier;
        string rpcUrl;
    }

    /// Native ZoneFactory ABI from TIP-1091.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZoneFactory {
        struct CreateZoneParams {
            address initialToken;
            address admin;
            address[] sequencers;
            uint8 threshold;
            string rpcUrl;
        }

        event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

        event PortalImplementationUpdated(address indexed source, bytes32 indexed codeHash);
        event ZoneMessengerImplementationUpdated(address indexed source, bytes32 indexed codeHash);
        event VerifierImplementationUpdated(address indexed source, bytes32 indexed codeHash);

        event ZoneCreated(
            uint32 indexed zoneId,
            address indexed portal,
            address initialToken,
            address admin,
            address[] sequencers,
            uint8 threshold,
            address verifier
        );

        error InvalidToken();
        error InvalidOwner();
        error NotOwner();
        error InvalidAdmin();
        error InvalidSequencerSet();
        error InvalidPortalImplementation();
        error InvalidZoneMessengerImplementation();
        error InvalidVerifierImplementation();

        function owner() external view returns (address);
        function transferOwnership(address newOwner) external;
        function setPortalImplementation(address source) external;
        function setZoneMessengerImplementation(address source) external;
        function setVerifierImplementation(address source) external;
        function createZone(CreateZoneParams calldata params)
            external
            returns (uint32 zoneId, address portal);
        function nextZoneId() external view returns (uint32);
        function zones(uint32 id) external view returns (ZoneInfo memory info);
        function isZonePortal(address portal) external view returns (bool);
    }

    /// Minimal portal ABI needed for constructor-equivalent native initialization.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZonePortal {
        event SequencerSetUpdated(uint64 indexed version, uint8 threshold, address[] sequencers);
        event TokenEnabled(address indexed token, string name, string symbol, string currency);
    }
}
