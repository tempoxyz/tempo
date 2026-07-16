// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @notice Zone metadata recorded by the native factory.
struct ZoneInfo {
    uint32 zoneId;
    address portal;
    address initialToken;
    address admin;
    address sequencer;
    bytes32 genesisBlockHash;
    bytes32 genesisTempoBlockHash;
    uint64 genesisTempoBlockNumber;
    string rpcUrl;
}

/// @notice Zone genesis parameters supplied during creation.
struct ZoneParams {
    bytes32 genesisBlockHash;
    bytes32 genesisTempoBlockHash;
    uint64 genesisTempoBlockNumber;
}

/// @notice Minimal initializer interface required by the native factory.
interface IZonePortalInitializer {

    function initialize(
        uint32 zoneId,
        address initialToken,
        address messenger,
        address admin,
        address sequencer,
        address verifier,
        bytes32 genesisBlockHash,
        uint64 genesisTempoBlockNumber,
        string calldata rpcUrl
    )
        external;

}

/// @title IZoneFactory
/// @notice Interface exposed by the native ZoneFactory.
interface IZoneFactory {

    struct CreateZoneParams {
        address initialToken;
        address admin;
        address sequencer;
        ZoneParams zoneParams;
        string rpcUrl;
    }

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    event ZoneCreated(
        uint32 indexed zoneId,
        address indexed portal,
        address initialToken,
        address admin,
        address sequencer,
        address verifier,
        bytes32 genesisBlockHash,
        bytes32 genesisTempoBlockHash,
        uint64 genesisTempoBlockNumber
    );

    error InvalidToken();
    error InvalidOwner();
    error NotOwner();
    error InvalidAdmin();
    error InvalidSequencer();
    error InsufficientGas();
    error ZoneIdOverflow();

    function owner() external view returns (address);

    function transferOwnership(address newOwner) external;

    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal);

    function nextZoneId() external view returns (uint32);

    function zones(uint32 zoneId) external view returns (ZoneInfo memory);

    function isZonePortal(address portal) external view returns (bool);

}
