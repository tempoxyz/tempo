use crate::zones::{
    T13_ZONE_MESSENGER_RUNTIME, T13_ZONE_PORTAL_RUNTIME, T13_ZONE_VERIFIER_RUNTIME,
    T14_ZONE_PORTAL_RUNTIME, ZONE_MESSENGER_RUNTIME, ZONE_PORTAL_RUNTIME, ZONE_VERIFIER_RUNTIME,
};
use alloy_primitives::{Address, B256, Bytes, U256, address, b256};

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

/// Cross-component compatibility pin for the T14 fast protocol.
pub const FAST_PROTOCOL_NATIVE_PIN: B256 =
    b256!("8e57521218d8ec9db175a95bca2c3a2061d54f8b60cd443c2c34735741534f8f");
/// Explicit operator-attested settlement mode. This mode does not claim proof verification.
pub const FAST_PROOF_MODE_OPERATOR_ATTESTED: u8 = 1;
/// Explicit proof-required settlement mode.
pub const FAST_PROOF_MODE_REQUIRED: u8 = 2;
/// Canonical nonzero commitment for an empty unresolved-lock set.
pub const FAST_EMPTY_UNRESOLVED_ROOT: B256 =
    b256!("9926609188c0819360afc29d8a841336912689fd33ce43cd524280a13263456e");
/// Runtime code hash of the T13 prototype verifier, which always returns true.
pub const T13_PROTOTYPE_VERIFIER_CODE_HASH: B256 =
    b256!("cf7b19d3c186e4fd235c94907d10bba5c1ce21d6e815676b00aaf298b456de14");

/// Canonical T14 Portal storage slots consumed by finalized cross-domain reads.
pub const PORTAL_FAST_EPOCH_SLOT: U256 = U256::from_limbs([28, 0, 0, 0]);
pub const PORTAL_FAST_EPOCHS_SLOT: U256 = U256::from_limbs([29, 0, 0, 0]);
pub const PORTAL_FAST_EPOCH_MEMBERS_SLOT: U256 = U256::from_limbs([30, 0, 0, 0]);
pub const PORTAL_FAST_EPOCH_MEMBER_FLAGS_SLOT: U256 = U256::from_limbs([31, 0, 0, 0]);
pub const PORTAL_FAST_EPOCH_PEERS_SLOT: U256 = U256::from_limbs([32, 0, 0, 0]);
pub const PORTAL_FAST_EPOCH_PEER_FLAGS_SLOT: U256 = U256::from_limbs([33, 0, 0, 0]);
pub const PORTAL_FAST_PEER_BARRIERS_SLOT: U256 = U256::from_limbs([34, 0, 0, 0]);

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

/// Returns the initial packed ZoneFactory configuration for the given owner.
pub fn initial_zone_factory_config(owner: Address) -> U256 {
    U256::ONE | (U256::from_be_slice(owner.as_slice()) << u32::BITS)
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

/// Returns the native ZoneFactory state with the T13 shared runtimes.
pub fn t13_zone_factory_state(owner: Address) -> [InitialZoneFactoryAccount; 4] {
    let [factory, _, _, _] = initial_zone_factory_state(owner);
    [
        factory,
        InitialZoneFactoryAccount {
            address: ZONE_PORTAL_IMPL_ADDRESS,
            code: T13_ZONE_PORTAL_RUNTIME,
            storage: None,
        },
        InitialZoneFactoryAccount {
            address: ZONE_VERIFIER_ADDRESS,
            code: T13_ZONE_VERIFIER_RUNTIME,
            storage: None,
        },
        InitialZoneFactoryAccount {
            address: ZONE_MESSENGER_ADDRESS,
            code: T13_ZONE_MESSENGER_RUNTIME,
            storage: None,
        },
    ]
}

/// Returns the native ZoneFactory state with the T14 Portal runtime.
pub fn t14_zone_factory_state(owner: Address) -> [InitialZoneFactoryAccount; 4] {
    let [factory, _, verifier, messenger] = t13_zone_factory_state(owner);
    [
        factory,
        InitialZoneFactoryAccount {
            address: ZONE_PORTAL_IMPL_ADDRESS,
            code: T14_ZONE_PORTAL_RUNTIME,
            storage: None,
        },
        verifier,
        messenger,
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
        error FastProtocolUnavailable();
        error InvalidFastEpoch();
        error FastEpochActive(uint64 epoch);
        error FastEpochNotDrained(uint64 epoch);
        error InvalidFastPeer(address peerPortal);
        error FastPeerBarrierAlreadyRecorded(address peerPortal);
        error FastPeerBarrierNotRecorded(address peerPortal);
        error FastPeerBarrierAlreadyFinalized(address peerPortal);
        error InvalidFastCertificate();
        error InvalidFastProofConfiguration();

        struct FastBarrierStatement {
            address destinationPortal;
            uint64 destinationEpoch;
            bytes32 closureHash;
            address sourcePortal;
            uint64 sourceEpoch;
            uint64 importedAnchorNumber;
            bytes32 importedAnchorHash;
            uint64 logTerm;
            uint64 logIndex;
            uint256 blockHeight;
            bytes32 blockHash;
            bytes32 stateRoot;
            uint64 lockLogWatermark;
            bytes32 completeLockRoot;
            bytes32 unresolvedRoot;
            uint64 unresolvedCount;
        }

        struct FastBarrierResolution {
            bytes32 barrierHash;
            bytes32 terminalRoot;
            bytes32 dispositionRoot;
            uint64 resolvedCount;
            bytes32 remainingUnresolvedRoot;
            uint64 remainingUnresolvedCount;
        }

        struct FastCheckpointStatement {
            address portal;
            uint64 oldEpoch;
            uint64 nextEpoch;
            bytes32 nextRosterHash;
            uint256 finalZoneHeight;
            bytes32 finalBlockHash;
            uint64 finalWithdrawalBatchIndex;
            bytes32 finalSettlementHash;
            uint64 checkpointLogTerm;
            uint64 checkpointLogIndex;
            uint256 checkpointHeight;
            bytes32 checkpointBlockHash;
            bytes32 checkpointStateRoot;
        }

        function owner() external view returns (address);
        function transferOwnership(address newOwner) external;
        function createZone(CreateZoneParams calldata params)
            external
            returns (uint32 zoneId, address portal);
        function nextZoneId() external view returns (uint32);
        function zones(uint32 id) external view returns (ZoneInfo memory info);
        function isZonePortal(address portal) external view returns (bool);
        function FAST_PROTOCOL_NATIVE_PIN() external view returns (bytes32);
        function configureFastEpoch(
            address portal,
            uint64 epoch,
            uint32 protocolVersion,
            uint8 proofMode,
            bytes32 expectedVerifierCodeHash,
            bytes32 expectedVerifierConfigHash,
            address[] calldata members,
            address[] calldata peerPortals,
            bytes32 rosterHash
        ) external;
        function closeFastEpoch(address portal, uint64 epoch, bytes32 closureHash) external;
        function recordFastPeerBarrier(
            address portal,
            FastBarrierStatement calldata statement,
            bytes[] calldata signatures
        ) external;
        function finalizeFastPeerBarrier(
            address portal,
            uint64 epoch,
            address peerPortal,
            FastBarrierResolution calldata resolution,
            bytes[] calldata signatures
        ) external;
        function recordFastFinalSettlement(
            address portal,
            uint64 epoch,
            uint256 zoneHeight,
            bytes32 blockHash,
            uint64 withdrawalBatchIndex,
            bytes[] calldata signatures
        ) external;
        function installFastCheckpoint(
            address portal,
            FastCheckpointStatement calldata statement,
            address[] calldata nextMembers,
            bytes[] calldata signatures
        ) external;
        function retireFastEpoch(address portal, uint64 epoch) external;
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
        event FastEpochActivated(
            uint64 indexed epoch,
            uint32 indexed protocolVersion,
            bytes32 indexed rosterHash,
            bytes32 peersHash,
            uint8 proofMode,
            bytes32 expectedVerifierCodeHash,
            bytes32 expectedVerifierConfigHash,
            address[] members,
            address[] peerPortals
        );
        event FastEpochClosed(uint64 indexed epoch, bytes32 indexed closureHash);
        event FastPeerBarrierRecorded(
            uint64 indexed epoch,
            address indexed peerPortal,
            uint64 sourceEpoch,
            uint64 lockLogWatermark,
            bytes32 barrierHash,
            bytes32 completeLockRoot,
            bytes32 unresolvedRoot,
            uint64 unresolvedCount
        );
        event FastPeerBarrierFinalized(
            uint64 indexed epoch,
            address indexed peerPortal,
            bytes32 resolutionHash,
            bytes32 terminalRoot,
            bytes32 dispositionRoot
        );
        event FastFinalSettlementRecorded(
            uint64 indexed epoch,
            uint256 zoneHeight,
            bytes32 indexed blockHash,
            uint64 withdrawalBatchIndex,
            bytes32 settlementHash
        );
        event FastCheckpointInstalled(
            uint64 indexed epoch, uint64 indexed nextEpoch, bytes32 indexed checkpointHash
        );
        event FastEpochRetired(uint64 indexed epoch);
    }
}
