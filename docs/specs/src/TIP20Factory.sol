// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { TIP20 } from "./TIP20.sol";
import { TempoUtilities } from "./TempoUtilities.sol";
import { ITIP20 } from "./interfaces/ITIP20.sol";
import { ITIP20Factory } from "./interfaces/ITIP20Factory.sol";
import { Vm } from "forge-std/Vm.sol";

contract TIP20Factory is ITIP20Factory {

    // Foundry cheatcode VM for deployCodeTo
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal immutable reservedSize = 1024;

    function createToken(
        string memory name,
        string memory symbol,
        string memory currency,
        ITIP20 quoteToken,
        address admin,
        bytes32 salt
    ) external returns (address) {
        // Validate that quoteToken is a valid TIP20
        if (!TempoUtilities.isTIP20(address(quoteToken))) {
            revert InvalidQuoteToken();
        }

        // If token is USD, its quote token must also be USD
        if (keccak256(bytes(currency)) == keccak256(bytes("USD"))) {
            if (keccak256(bytes(quoteToken.currency())) != keccak256(bytes("USD"))) {
                revert InvalidQuoteToken();
            }
        }

        uint80 lowerBytes = uint80(bytes10(keccak256(abi.encode(msg.sender, salt))));
        if (lowerBytes < reservedSize) {
            revert AddressReserved();
        }

        // Calculate the deterministic address for this token
        address tokenAddr =
            address(uint160(0x20C0000000000000000000000000000000000000) | uint160(lowerBytes));

        // Deploy TIP20 contract to the deterministic address using Foundry cheatcodes
        bytes memory creationCode = vm.getCode("TIP20.sol");
        vm.etch(
            tokenAddr,
            abi.encodePacked(creationCode, abi.encode(name, symbol, currency, quoteToken, admin))
        );
        (bool success, bytes memory runtimeBytecode) = tokenAddr.call("");
        require(success, "TIP20Factory: Failed to deploy TIP20");
        vm.etch(tokenAddr, runtimeBytecode);

        emit TokenCreated(tokenAddr, name, symbol, currency, quoteToken, admin, salt);

        return tokenAddr;
    }

    function isTIP20(address token) external view returns (bool) {
        return TempoUtilities.isTIP20(token);
    }

    function getTokenAddress(address sender, bytes32 salt) external pure returns (address) {
        uint80 lowerBytes = uint80(bytes10(keccak256(abi.encode(sender, salt))));
        return address(uint160(0x20C0000000000000000000000000000000000000) | uint160(lowerBytes));
    }

}
