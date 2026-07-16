// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IZoneFactory, IZonePortalInitializer, ZoneInfo } from "../interfaces/IZone.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";

/// @title ZoneFactory
/// @notice Reference registry logic for the enshrined ZoneFactory precompile.
/// @dev This is not deployable EVM bytecode. Native host hooks below model the
///      protocol operations that install portal proxy bytecode at vanity addresses.
abstract contract ZoneFactory is IZoneFactory {

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum gas required for zone creation.
    /// @dev Prevents low-cost zone spam. The caller must supply at least this much gas.
    uint256 public constant ZONE_CREATION_GAS = 15_000_000;

    /// @notice 12-byte prefix reserved for zone portal vanity addresses.
    bytes12 public constant ZONE_PORTAL_PREFIX = 0x5AD000000000000000000000;

    /// @notice Protocol-managed account that stores the central ZonePortal implementation.
    address public constant ZONE_PORTAL_IMPL_ADDRESS = 0x5AD1000000000000000000000000000000000000;

    /// @notice Protocol-managed verifier account (0x56 is ASCII "V").
    address public constant ZONE_VERIFIER_ADDRESS = 0x5a56000000000000000000000000000000000000;

    /// @notice Protocol-managed shared messenger account (0x4d is ASCII "M").
    address public constant ZONE_MESSENGER_ADDRESS = 0x5A4d000000000000000000000000000000000000;

    /// @notice Runtime prefix for an EIP-1167-style delegatecall proxy.
    bytes10 internal constant PORTAL_PROXY_PREFIX = 0x363d3d373d3d3d363d73;

    /// @notice Runtime suffix for an EIP-1167-style delegatecall proxy.
    bytes15 internal constant PORTAL_PROXY_SUFFIX = 0x5af43d82803e903d91602b57fd5bf3;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Next zone ID to be assigned.
    /// @dev Starts at 1, reserving zone ID 0 for potential future use.
    uint32 public override nextZoneId = 1;

    mapping(uint32 => ZoneInfo) internal _zones;

    /// @notice Initial value is configured by the T9 activation; exact address TBD.
    address public owner;

    /*//////////////////////////////////////////////////////////////
                            ZONE CREATION
    //////////////////////////////////////////////////////////////*/

    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal)
    {
        if (msg.sender != owner) revert NotOwner();

        if (!ITIP20Factory(StdPrecompiles.TIP20_FACTORY_ADDRESS).isTIP20(params.initialToken)) {
            revert InvalidToken();
        }
        if (params.admin == address(0)) revert InvalidAdmin();
        if (params.sequencer == address(0)) revert InvalidSequencer();
        if (gasleft() < ZONE_CREATION_GAS) revert InsufficientGas();

        zoneId = nextZoneId;
        if (zoneId == type(uint32).max) revert ZoneIdOverflow();
        nextZoneId = zoneId + 1;

        portal = portalAddress(zoneId);

        // Native precompile operation, not EVM CREATE or CREATE2:
        //
        // 1. The protocol etches minimal portal proxy/caller bytecode directly into
        //    the reserved `portal` account. The runtime delegatecalls into
        //    ZONE_PORTAL_IMPL_ADDRESS, the single protocol-managed ZonePortal logic
        //    implementation.
        // 2. This factory calls the portal's one-time initializer with the zone ID,
        //    initial token, shared messenger, admin, sequencer, verifier, genesis block
        //    hash, genesis Tempo block number, and RPC URL.
        //
        // The exact host operations are implementation details of the Tempo
        // precompile, represented by abstract hooks here so this artifact documents
        // the required behavior without pretending it is ordinary Solidity.
        _nativeEtchPortalProxy(portal, portalProxyRuntime());
        IZonePortalInitializer(portal)
            .initialize(
                zoneId,
                params.initialToken,
                ZONE_MESSENGER_ADDRESS,
                params.admin,
                params.sequencer,
                ZONE_VERIFIER_ADDRESS,
                params.zoneParams.genesisBlockHash,
                params.zoneParams.genesisTempoBlockNumber,
                params.rpcUrl
            );

        _zones[zoneId] = ZoneInfo({
            zoneId: zoneId,
            portal: portal,
            initialToken: params.initialToken,
            admin: params.admin,
            sequencer: params.sequencer,
            genesisBlockHash: params.zoneParams.genesisBlockHash,
            genesisTempoBlockHash: params.zoneParams.genesisTempoBlockHash,
            genesisTempoBlockNumber: params.zoneParams.genesisTempoBlockNumber,
            rpcUrl: params.rpcUrl
        });

        emit ZoneCreated(
            zoneId,
            portal,
            params.initialToken,
            params.admin,
            params.sequencer,
            ZONE_VERIFIER_ADDRESS,
            params.zoneParams.genesisBlockHash,
            params.zoneParams.genesisTempoBlockHash,
            params.zoneParams.genesisTempoBlockNumber
        );
    }

    /// @inheritdoc IZoneFactory
    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert InvalidOwner();

        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Returns the deterministic portal vanity address for a zone ID.
    function portalAddress(uint32 zoneId) public pure returns (address) {
        uint160 prefix = uint160(bytes20(ZONE_PORTAL_PREFIX));
        return address(prefix | uint160(uint64(zoneId)));
    }

    /// @notice Returns the exact runtime bytecode etched into each portal account.
    function portalProxyRuntime() public pure returns (bytes memory) {
        return abi.encodePacked(PORTAL_PROXY_PREFIX, ZONE_PORTAL_IMPL_ADDRESS, PORTAL_PROXY_SUFFIX);
    }

    /// @dev Native host hook: etch proxy/caller runtime bytecode at `portal`.
    function _nativeEtchPortalProxy(address portal, bytes memory runtime) internal virtual;

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    function zones(uint32 zoneId) external view returns (ZoneInfo memory) {
        return _zones[zoneId];
    }

    function isZonePortal(address portal) external view returns (bool) {
        uint64 zoneId = uint64(uint160(portal));
        return bytes12(bytes20(portal)) == ZONE_PORTAL_PREFIX && zoneId != 0 && zoneId < nextZoneId;
    }

}
