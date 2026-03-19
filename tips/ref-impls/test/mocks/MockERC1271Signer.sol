// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";

/// @notice Mock ERC-1271 smart contract signer.
///         Delegates signature validation to an EOA key.
///         Simulates a vault or smart wallet that signs vouchers.
contract MockERC1271Signer {
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    /// @dev ERC-1271: validate signature by checking the delegated EOA.
    function isValidSignature(
        bytes32 hash,
        bytes memory signature
    ) external view returns (bytes4) {
        address recovered = ECDSA.recover(hash, signature);
        if (recovered == signer) {
            return 0x1626ba7e; // ERC-1271 magic value
        }
        return 0xffffffff;
    }

    /// @dev Allow this contract to approve token spending.
    function approveToken(
        address token,
        address spender,
        uint256 amount
    ) external {
        ITIP20(token).approve(spender, amount);
    }
}
