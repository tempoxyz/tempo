// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    PORTAL_MAX_TEMPO_GAS_RATE_SLOT,
    PORTAL_ROLE_SLOT,
    PORTAL_TOKEN_CONFIGS_SLOT,
    Role
} from "../../src/runtime/interfaces/IZone.sol";

/// @title MockTempoState
/// @notice Mock TempoState for testing ZoneInbox
/// @dev Allows setting storage slot values and simulates finalizeTempo
contract MockTempoState {

    address public immutable sequencer;

    // Core fields (matching real TempoState)
    bytes32 public tempoBlockHash;
    uint64 public tempoBlockNumber;

    /// @notice Mock storage values for readTempoStorageSlot
    mapping(address => mapping(bytes32 => bytes32)) public mockStorageValues;

    error OnlySequencer();

    constructor(
        address _sequencer,
        bytes32 _genesisTempoBlockHash,
        uint64 _genesisTempoBlockNumber
    ) {
        sequencer = _sequencer;
        tempoBlockHash = _genesisTempoBlockHash;
        tempoBlockNumber = _genesisTempoBlockNumber;
    }

    /// @notice Set a mock storage value for readTempoStorageSlot
    function setMockStorageValue(address account, bytes32 slot, bytes32 value) external {
        mockStorageValues[account][slot] = value;
    }

    function setMockMaxTempoGasRate(address portal, uint128 rate) external {
        mockStorageValues[portal][PORTAL_MAX_TEMPO_GAS_RATE_SLOT] = bytes32(uint256(rate));
    }

    /// @notice Set the mocked ZonePortal TokenConfig.enabled field.
    function setMockTokenEnabled(address portal, address token, bool enabled) external {
        bytes32 configSlot = keccak256(abi.encode(token, PORTAL_TOKEN_CONFIGS_SLOT));
        uint256 raw = uint256(mockStorageValues[portal][configSlot]);
        raw = (raw & ~uint256(0xff)) | (enabled ? 1 : 0);
        mockStorageValues[portal][configSlot] = bytes32(raw);
    }

    function setMockAccountAllowed(address portal, address account, bool allowed) external {
        bytes32 slot = keccak256(abi.encode(account, PORTAL_ROLE_SLOT));
        mockStorageValues[portal][slot] = allowed ? bytes32(uint256(Role.Account)) : bytes32(0);
    }

    function setMockZoneGateway(address portal, address gateway, bool enabled) external {
        bytes32 gatewaySlot = keccak256(abi.encode(gateway, PORTAL_ROLE_SLOT));
        mockStorageValues[portal][gatewaySlot] =
            enabled ? bytes32(uint256(Role.CallbackGateway)) : bytes32(0);
    }

    /// @notice Mock finalizeTempo - just advances block number
    /// @dev No sequencer check here - ZoneInbox already validates the caller
    function finalizeTempo(bytes[] calldata headers) external {
        tempoBlockNumber += uint64(headers.length);
        tempoBlockHash = keccak256(abi.encode(tempoBlockHash, tempoBlockNumber));
    }

    /// @notice Mock readTempoStorageSlot - returns preset values
    function readTempoStorageSlot(address account, bytes32 slot) external view returns (bytes32) {
        return mockStorageValues[account][slot];
    }

}
