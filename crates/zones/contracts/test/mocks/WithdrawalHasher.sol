// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Withdrawal } from "../../src/runtime/interfaces/IZone.sol";
import { WithdrawalQueueLib } from "../../src/runtime/libraries/WithdrawalQueueLib.sol";

/// @notice Hashes withdrawals with the portal's calldata path, for tests that build them in memory.
contract WithdrawalHasher {

    function hashWithTail(
        Withdrawal calldata withdrawal,
        bytes32 tail
    )
        external
        pure
        returns (bytes32)
    {
        return WithdrawalQueueLib.hashWithTail(withdrawal, tail);
    }

}
