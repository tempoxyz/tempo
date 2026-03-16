// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { IValidatorConfig } from "../src/interfaces/IValidatorConfig.sol";
import { Script, console } from "forge-std/Script.sol";

/// @title CheckV1Migration
/// @notice Pre-flight check: reads all V1 validators and reports which ones would be
///         skipped or cause a revert during `ValidatorConfigV2.migrateValidator`.
///
/// Migration heuristics (from ValidatorConfigV2.migrateValidator):
///   SKIP  1. publicKey == 0  OR  validatorAddress == address(0)
///   SKIP  2. Duplicate publicKey (already seen earlier in the array)
///   SKIP  3. Active validator whose ingress hash (full ip:port) collides with an earlier active validator
///   REVERT 4. Duplicate active validatorAddress (AddressAlreadyHasValidator)
contract CheckV1Migration is Script {

    address internal constant _VALIDATOR_CONFIG = 0xCccCcCCC00000000000000000000000000000000;

    mapping(bytes32 => bool) internal seenPubkeys;
    mapping(address => bool) internal activeAddresses;
    mapping(bytes32 => bool) internal activeIngressHashes;

    function run() external {
        IValidatorConfig v1 = IValidatorConfig(_VALIDATOR_CONFIG);
        IValidatorConfig.Validator[] memory vals = v1.getValidators();

        console.log("=== V1 Validator Migration Pre-Flight ===");
        console.log("Total V1 validators:", vals.length);
        console.log("");

        uint256 skipCount;
        uint256 revertCount;
        uint256 okCount;

        // Process in reverse order (migration iterates N-1 down to 0)
        for (uint256 ri = 0; ri < vals.length; ri++) {
            uint256 i = vals.length - 1 - ri;
            IValidatorConfig.Validator memory v = vals[i];

            // --- Check 1: zero pubkey or zero address ---
            if (v.publicKey == bytes32(0) || v.validatorAddress == address(0)) {
                console.log("SKIP  [idx %d] zero pubkey or zero address", i);
                console.log("        addr=%s", _toHex(v.validatorAddress));
                console.log("        pubkey=%s", _toHex32(v.publicKey));
                skipCount++;
                continue;
            }

            // --- Check 2: duplicate pubkey ---
            if (seenPubkeys[v.publicKey]) {
                console.log("SKIP  [idx %d] duplicate publicKey", i);
                console.log("        addr=%s", _toHex(v.validatorAddress));
                console.log("        pubkey=%s", _toHex32(v.publicKey));
                skipCount++;
                continue;
            }
            seenPubkeys[v.publicKey] = true;

            // --- Check 4 (before 3): duplicate active address → REVERT ---
            // The actual migration reverts (AddressAlreadyHasValidator) when
            // addressToIndex maps to an active validator.
            if (activeAddresses[v.validatorAddress]) {
                console.log("REVERT [idx %d] AddressAlreadyHasValidator (dup active address)", i);
                console.log("        addr=%s", _toHex(v.validatorAddress));
                revertCount++;
                continue;
            }

            // --- Check 3: active validator with duplicate ingress hash ---
            if (v.active) {
                bytes32 ingressHash = keccak256(bytes(v.inboundAddress));
                if (activeIngressHashes[ingressHash]) {
                    console.log("SKIP  [idx %d] duplicate active ingress", i);
                    console.log("        addr=%s", _toHex(v.validatorAddress));
                    console.log("        ingress=%s", v.inboundAddress);
                    skipCount++;
                    continue;
                }
                activeIngressHashes[ingressHash] = true;
                activeAddresses[v.validatorAddress] = true;
            }

            console.log("OK    [idx %d] %s", i, _toHex(v.validatorAddress));
            console.log("        active=%s  ingress=%s", v.active ? "true" : "false", v.inboundAddress);
            okCount++;
        }

        console.log("");
        console.log("=== Summary ===");
        console.log("  OK    : %d", okCount);
        console.log("  SKIP  : %d", skipCount);
        console.log("  REVERT: %d", revertCount);

        if (revertCount > 0) {
            console.log("");
            console.log("WARNING: %d validator(s) would cause migration to REVERT.", revertCount);
            console.log("These must be resolved in V1 before migration can proceed.");
        }
    }

    // ---- hex helpers (no Strings lib needed) ----

    function _toHex(address a) internal pure returns (string memory) {
        return _toHex(uint256(uint160(a)), 20);
    }

    function _toHex32(bytes32 b) internal pure returns (string memory) {
        return _toHex(uint256(b), 32);
    }

    function _toHex(uint256 value, uint256 byteLen) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(2 + byteLen * 2);
        result[0] = "0";
        result[1] = "x";
        for (uint256 i = 0; i < byteLen; i++) {
            uint256 byteVal = (value >> (8 * (byteLen - 1 - i))) & 0xff;
            result[2 + i * 2] = hexChars[byteVal >> 4];
            result[2 + i * 2 + 1] = hexChars[byteVal & 0xf];
        }
        return string(result);
    }
}
