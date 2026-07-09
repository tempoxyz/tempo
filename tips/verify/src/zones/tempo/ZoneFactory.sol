// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { IZoneFactory, ZoneInfo } from "../interfaces/IZone.sol";
import { Verifier } from "./Verifier.sol";
import { ZoneMessenger } from "./ZoneMessenger.sol";
import { ZonePortal } from "./ZonePortal.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";

/// @title ZoneFactory
/// @notice Creates zones and registers parameters
contract ZoneFactory is IZoneFactory {

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Minimum gas required for zone creation.
    /// @dev Prevents low-cost zone spam. The caller must supply at least this much gas.
    uint256 public constant ZONE_CREATION_GAS = 15_000_000;

    /// @notice Next zone ID to be assigned
    /// @dev Starts at 1, reserving zone ID 0 for potential future use (e.g., mainnet as zone 0)
    uint32 internal _nextZoneId = 1;

    mapping(uint32 => ZoneInfo) internal _zones;
    mapping(address => bool) internal _isZonePortal;
    mapping(address => bool) internal _isZoneMessenger;
    mapping(address => bool) internal _validVerifiers;
    address internal _verifier;

    /// @notice Tracks deployment count for CREATE address prediction
    /// @dev Contracts start with nonce 1, not 0. Nonce 1 is used by the Verifier deployment
    ///      in the constructor, so zone deployments start at nonce 2.
    uint256 internal _deploymentNonce = 2;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        address v = address(new Verifier());
        _validVerifiers[v] = true;
        _verifier = v;
    }

    /*//////////////////////////////////////////////////////////////
                            ZONE CREATION
    //////////////////////////////////////////////////////////////*/

    function createZone(CreateZoneParams calldata params)
        external
        returns (uint32 zoneId, address portal)
    {
        // Validate initial token is a TIP-20
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

        // We deploy messenger first, then portal.
        // Messenger needs portal's address at construction (immutable).
        // Solution: predict portal's address based on CREATE address formula.
        //
        // CREATE addresses: address = keccak256(rlp([sender, nonce]))[12:]
        // - messenger will be at nonce N
        // - portal will be at nonce N+1
        //
        // We track our own nonce since contract nonce isn't accessible.

        uint256 currentNonce = _deploymentNonce;
        _deploymentNonce += 2; // We'll deploy 2 contracts

        // Compute portal's address (will be deployed at nonce+1)
        address predictedPortal = _computeCreateAddress(address(this), currentNonce + 1);

        // Deploy messenger with predicted portal address (no token needed -- portal grants approval per-token)
        ZoneMessenger messengerContract = new ZoneMessenger(predictedPortal);
        address messengerAddress = address(messengerContract);

        // Deploy portal with messenger address and initial token
        // The portal constructor enables the initial token automatically
        ZonePortal portalContract = new ZonePortal(
            zoneId,
            params.initialToken,
            messengerAddress,
            params.admin,
            params.sequencer,
            params.verifier,
            params.zoneParams.genesisBlockHash,
            params.zoneParams.genesisTempoBlockNumber,
            params.rpcUrl
        );
        portal = address(portalContract);

        // Verify our prediction was correct
        require(portal == predictedPortal, "Portal address mismatch - nonce tracking error");

        // Store zone info
        _zones[zoneId] = ZoneInfo({
            zoneId: zoneId,
            portal: portal,
            messenger: messengerAddress,
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
        _isZoneMessenger[messengerAddress] = true;

        emit ZoneCreated(
            zoneId,
            portal,
            messengerAddress,
            params.initialToken,
            params.admin,
            params.sequencer,
            params.verifier,
            params.zoneParams.genesisBlockHash,
            params.zoneParams.genesisTempoBlockHash,
            params.zoneParams.genesisTempoBlockNumber
        );
    }

    /// @notice Compute the address of a contract deployed with CREATE
    /// @dev address = keccak256(rlp([sender, nonce]))[12:]
    function _computeCreateAddress(address deployer, uint256 nonce)
        internal
        pure
        returns (address)
    {
        bytes memory data;
        if (nonce == 0x00) {
            data = abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, bytes1(0x80));
        } else if (nonce <= 0x7f) {
            data = abi.encodePacked(bytes1(0xd6), bytes1(0x94), deployer, uint8(nonce));
        } else if (nonce <= 0xff) {
            data =
                abi.encodePacked(bytes1(0xd7), bytes1(0x94), deployer, bytes1(0x81), uint8(nonce));
        } else if (nonce <= 0xffff) {
            data =
                abi.encodePacked(bytes1(0xd8), bytes1(0x94), deployer, bytes1(0x82), uint16(nonce));
        } else if (nonce <= 0xffffff) {
            data =
                abi.encodePacked(bytes1(0xd9), bytes1(0x94), deployer, bytes1(0x83), uint24(nonce));
        } else {
            data =
                abi.encodePacked(bytes1(0xda), bytes1(0x94), deployer, bytes1(0x84), uint32(nonce));
        }
        return address(uint160(uint256(keccak256(data))));
    }

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the number of zones created (not including reserved zone 0)
    function zoneCount() external view returns (uint32) {
        return _nextZoneId - 1;
    }

    function zones(uint32 zoneId) external view returns (ZoneInfo memory) {
        return _zones[zoneId];
    }

    function isZonePortal(address portal) external view returns (bool) {
        return _isZonePortal[portal];
    }

    function isZoneMessenger(address messenger) external view returns (bool) {
        return _isZoneMessenger[messenger];
    }

    function isValidVerifier(address v) external view returns (bool) {
        return _validVerifiers[v];
    }

    function verifier() external view returns (address) {
        return _verifier;
    }

}
