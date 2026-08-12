use crate::zones::{ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME};
use alloy_primitives::{Address, Bytes, U256, address};

pub use IZoneFactory::{
    IZoneFactoryErrors as ZoneFactoryError, IZoneFactoryEvents as ZoneFactoryEvent,
};
pub use IZonePortal::{
    Capability as ZonePortalCapability, IZonePortalEvents as ZonePortalEvent,
    Role as ZonePortalRole,
};

/// Native TIP-1091 ZoneFactory precompile address.
pub const ZONE_FACTORY_ADDRESS: Address = address!("0x5AF2000000000000000000000000000000000000");

/// Initial ZoneFactory owner installed by the T10 activation.
pub const INITIAL_FACTORY_OWNER: Address = address!("0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14");

/// Protocol-managed shared ZonePortal implementation address.
pub const ZONE_PORTAL_IMPL_ADDRESS: Address =
    address!("0x5AD1000000000000000000000000000000000000");

/// Protocol-managed Zone verifier address.
pub const ZONE_VERIFIER_ADDRESS: Address = address!("0x5A56000000000000000000000000000000000000");

/// Protocol-managed shared ZoneMessenger address.
pub const ZONE_MESSENGER_ADDRESS: Address = address!("0x5A4D000000000000000000000000000000000000");

/// One account installed as part of the native ZoneFactory state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialZoneFactoryAccount {
    /// Account address.
    pub address: Address,
    /// Runtime bytecode.
    pub code: Bytes,
    /// Optional initial storage slot and value.
    pub storage: Option<(U256, U256)>,
}

fn initial_zone_factory_config(owner: Address) -> U256 {
    U256::from(1) | (U256::from_be_slice(owner.as_slice()) << u32::BITS)
}

/// Returns the complete native ZoneFactory state for the given owner.
pub fn initial_zone_factory_state(owner: Address) -> [InitialZoneFactoryAccount; 4] {
    [
        InitialZoneFactoryAccount {
            address: ZONE_FACTORY_ADDRESS,
            code: Bytes::from_static(&[0xef]),
            storage: Some((U256::ZERO, initial_zone_factory_config(owner))),
        },
        InitialZoneFactoryAccount {
            address: ZONE_PORTAL_IMPL_ADDRESS,
            code: ZONE_PORTAL_RUNTIME,
            storage: None,
        },
        InitialZoneFactoryAccount {
            address: ZONE_VERIFIER_ADDRESS,
            code: ZONE_VERIFIER_RUNTIME,
            storage: None,
        },
        InitialZoneFactoryAccount {
            address: ZONE_MESSENGER_ADDRESS,
            code: ZONE_MESSENGER_RUNTIME,
            storage: None,
        },
    ]
}

crate::sol! {
    /// Zone metadata recorded by the native factory.
    #[derive(Debug, PartialEq, Eq)]
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

    /// Native ZoneFactory ABI from TIP-1091.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IZoneFactory {
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
        error TokenTransferPolicyNotSet();
        error InvalidClosedLoopConfig();
        error NotOwner();
        error InvalidAdmin();
        error InvalidSequencerSet();
        error AlreadyInitialized();
        error TokenMetadataTooLong();

        function owner() external view returns (address);
        function transferOwnership(address newOwner) external;
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
        enum Role {
            None,
            Sequencer,
            Account,
            CallbackGateway,
            PauseGuardian
        }

        enum Capability {
            PausePortal,
            AccessPolicy
        }

        event SequencerSetUpdated(uint64 indexed nonce, uint8 threshold, address[] sequencers);
        event TokenEnabled(address indexed token, string name, string symbol, string currency);
        event RoleUpdated(address indexed account, Role prev, Role next);
        event EnforcementModesUpdated(bool accessMode, bool gatewayMode);
        event LeaderUpdated(
            address indexed previousLeader,
            address indexed newLeader,
            uint64 indexed leaderEpoch,
            uint64 leaderActivationTempoBlock
        );
    }
}
