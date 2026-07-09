// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IZoneFactory, ZoneInfo } from "../interfaces/IZone.sol";
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
    bytes12 public constant ZONE_PORTAL_PREFIX = 0x20D000000000000000000000;

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Next zone ID to be assigned.
    /// @dev Starts at 1, reserving zone ID 0 for potential future use.
    uint32 internal _nextZoneId = 1;

    mapping(uint32 => ZoneInfo) internal _zones;
    mapping(address => bool) internal _isZonePortal;
    mapping(address => bool) internal _validVerifiers;
    address internal _verifier;
    address internal _messenger;
    address internal _portalLogic;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address initialVerifier, address sharedMessenger, address portalLogic) {
        if (initialVerifier == address(0)) revert InvalidVerifier();
        require(sharedMessenger != address(0), "invalid messenger");
        require(portalLogic != address(0), "invalid portal logic");

        _validVerifiers[initialVerifier] = true;
        _verifier = initialVerifier;
        _messenger = sharedMessenger;
        _portalLogic = portalLogic;
    }

    /*//////////////////////////////////////////////////////////////
                            ZONE CREATION
    //////////////////////////////////////////////////////////////*/

    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal)
    {
        if (!ITIP20Factory(StdPrecompiles.TIP20_FACTORY_ADDRESS).isTIP20(params.initialToken)) {
            revert InvalidToken();
        }
        if (params.admin == address(0)) revert InvalidAdmin();
        if (params.sequencer == address(0)) revert InvalidSequencer();
        if (!_validVerifiers[params.verifier]) revert InvalidVerifier();
        if (gasleft() < ZONE_CREATION_GAS) revert InsufficientGas();

        zoneId = _nextZoneId;
        if (zoneId == type(uint32).max) revert ZoneIdOverflow();
        _nextZoneId = zoneId + 1;

        portal = portalAddress(zoneId);

        // Native precompile operation, not EVM CREATE or CREATE2:
        //
        // 1. The protocol asserts that `portal` has no code, storage, or EIP-7702
        //    delegation and that no non-protocol deployment path can target it.
        // 2. The protocol etches minimal portal proxy/caller bytecode directly into
        //    the `portal` account. The runtime delegates/calls into `_portalLogic`,
        //    the single protocol-managed ZonePortal logic implementation.
        // 3. The protocol initializes the portal account's storage/immutable
        //    equivalents with the same values the ZonePortal constructor would have
        //    received: zone ID, initial token, shared messenger, admin, sequencer,
        //    verifier, genesis block hash, genesis Tempo block number, and RPC URL.
        //
        // The exact host operations are implementation details of the Tempo
        // precompile, represented by abstract hooks here so this artifact documents
        // the required behavior without pretending it is ordinary Solidity.
        _nativeInstallPortalProxy(portal, _portalLogic);
        _nativeInitializePortal(portal, zoneId, params);

        _zones[zoneId] = ZoneInfo({
            zoneId: zoneId,
            portal: portal,
            initialToken: params.initialToken,
            admin: params.admin,
            sequencer: params.sequencer,
            verifier: params.verifier,
            genesisBlockHash: params.zoneParams.genesisBlockHash,
            genesisTempoBlockHash: params.zoneParams.genesisTempoBlockHash,
            genesisTempoBlockNumber: params.zoneParams.genesisTempoBlockNumber,
            rpcUrl: params.rpcUrl
        });

        _isZonePortal[portal] = true;

        emit ZoneCreated(
            zoneId,
            portal,
            params.initialToken,
            params.admin,
            params.sequencer,
            params.verifier,
            params.zoneParams.genesisBlockHash,
            params.zoneParams.genesisTempoBlockHash,
            params.zoneParams.genesisTempoBlockNumber
        );
    }

    /// @notice Returns the deterministic portal vanity address for a zone ID.
    function portalAddress(uint32 zoneId) public pure returns (address) {
        uint160 prefix = uint160(bytes20(ZONE_PORTAL_PREFIX));
        return address(prefix | uint160(uint64(zoneId)));
    }

    /// @dev Native host hook: etch proxy/caller bytecode at `portal`.
    function _nativeInstallPortalProxy(address portal, address portalLogic) internal virtual;

    /// @dev Native host hook: initialize state equivalent to the ZonePortal constructor.
    function _nativeInitializePortal(
        address portal,
        uint32 zoneId,
        CreateZoneParams calldata params
    )
        internal
        virtual;

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the number of zones created, excluding reserved zone 0.
    function zoneCount() external view returns (uint32) {
        return _nextZoneId - 1;
    }

    function zones(uint32 zoneId) external view returns (ZoneInfo memory) {
        return _zones[zoneId];
    }

    function isZonePortal(address portal) external view returns (bool) {
        return _isZonePortal[portal];
    }

    function isValidVerifier(address v) external view returns (bool) {
        return _validVerifiers[v];
    }

    function verifier() external view returns (address) {
        return _verifier;
    }

    function messenger() external view returns (address) {
        return _messenger;
    }

}
