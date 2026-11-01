// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { getBlockHash } from "../../src/runtime/libraries/BlockHashHistory.sol";
import { BaseTest } from "../BaseTest.t.sol";

contract BlockHashHistoryTest is BaseTest {

    /// @notice Verifies recent in-window blocks return the same hash as the BLOCKHASH opcode.
    function test_getBlockHash_returnsInWindowHash() public {
        vm.roll(10_000);
        uint256 blockNumber = block.number - 1;

        bytes32 hash = getBlockHash(blockNumber);

        assertEq(hash, blockhash(blockNumber));
        assertTrue(hash != bytes32(0));
    }

    /// @notice Verifies blocks older than the history window return zero.
    function test_getBlockHash_returnsZeroForOutOfWindowBlock() public {
        vm.roll(20_000);
        uint256 blockNumber = block.number - BLOCKHASH_HISTORY_WINDOW - 1;

        assertEq(getBlockHash(blockNumber), bytes32(0));
    }

    /// @notice Verifies genesis, current, and future unknown blocks return zero.
    function test_getBlockHash_returnsZeroForUnknownBlocks() public {
        vm.roll(10_000);

        assertEq(getBlockHash(0), bytes32(0));
        assertEq(getBlockHash(block.number), bytes32(0));
        assertEq(getBlockHash(block.number + 1), bytes32(0));
    }

}
