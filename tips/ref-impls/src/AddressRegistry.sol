// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { TempoUtilities } from "./TempoUtilities.sol";
import { IAddressRegistry } from "./interfaces/IAddressRegistry.sol";

/// @title TIP-1022 virtual address registry
/// @notice Registers virtual masters and resolves virtual TIP-20 recipients to their masters
contract AddressRegistry is IAddressRegistry {

    mapping(bytes4 => address) internal _masters;

    function registerVirtualMaster(bytes32 salt) external returns (bytes4 masterId) {
        if (!TempoUtilities.isValidVirtualMaster(msg.sender)) {
            revert InvalidMasterAddress();
        }

        bytes32 registrationHash = keccak256(abi.encodePacked(msg.sender, salt));
        if (bytes4(registrationHash) != bytes4(0)) {
            revert ProofOfWorkFailed();
        }

        masterId = bytes4(uint32(uint256(registrationHash) >> 192));

        address existingMaster = _masters[masterId];
        if (existingMaster != address(0)) {
            revert MasterIdCollision(existingMaster);
        }

        _masters[masterId] = msg.sender;
        emit MasterRegistered(masterId, msg.sender);
    }

    function getMaster(bytes4 masterId) external view returns (address) {
        return _masters[masterId];
    }

    function resolveRecipient(address to) external view returns (address effectiveRecipient) {
        effectiveRecipient = resolveVirtualAddress(to);
        if (effectiveRecipient != address(0)) {
            return effectiveRecipient;
        }

        if (TempoUtilities.isVirtualAddress(to)) {
            revert VirtualAddressUnregistered();
        }

        return to;
    }

    function resolveVirtualAddress(address virtualAddr) public view returns (address master) {
        (bool isVirtual, bytes4 masterId,) = TempoUtilities.decodeVirtualAddress(virtualAddr);
        if (!isVirtual) {
            return address(0);
        }

        return _masters[masterId];
    }

    function isVirtualAddress(address addr) external pure returns (bool) {
        return TempoUtilities.isVirtualAddress(addr);
    }

    function decodeVirtualAddress(address addr)
        external
        pure
        returns (bool isVirtual, bytes4 masterId, bytes6 userTag)
    {
        return TempoUtilities.decodeVirtualAddress(addr);
    }

}
