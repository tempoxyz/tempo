// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @notice Zone metadata recorded by the native factory.
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

/// @notice Minimal initializer interface required by the native factory.
interface IZonePortalInitializer {

    function initialize(
        uint32 zoneId,
        address initialToken,
        address messenger,
        address admin,
        address[] calldata sequencers,
        uint8 threshold,
        address verifier,
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
