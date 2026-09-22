// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Adversarial state-read workload for payload prewarming benchmarks.
contract StateAccessBenchmark {
    uint256 public constant READS_PER_TX = 4096;
    uint256 private constant CURSOR_SLOT = type(uint256).max;

    error NoPages();

    /// @notice Selects a page using state changed by preceding transactions.
    function touchStateDependent(bytes32 salt, uint256 pageCount)
        external
        returns (bytes32 accumulator)
    {
        uint256 sequence;
        uint256 cursorSlot = CURSOR_SLOT;
        assembly {
            sequence := sload(cursorSlot)
            sstore(cursorSlot, add(sequence, 1))
        }
        return _touch(salt, sequence, pageCount);
    }

    /// @notice Control workload whose page is fully determined by calldata.
    function touchPredictable(bytes32 salt, uint256 pageCount)
        external
        returns (bytes32 accumulator)
    {
        uint256 cursorSlot = CURSOR_SLOT;
        assembly {
            let sequence := sload(cursorSlot)
            sstore(cursorSlot, add(sequence, 1))
        }
        return _touch(salt, 0, pageCount);
    }

    function _touch(bytes32 salt, uint256 selector, uint256 pageCount)
        private
        view
        returns (bytes32 accumulator)
    {
        if (pageCount == 0) revert NoPages();

        uint256 start = (uint256(keccak256(abi.encode(salt, selector))) % pageCount)
            * READS_PER_TX;
        assembly {
            for { let i := 0 } lt(i, READS_PER_TX) { i := add(i, 1) } {
                accumulator := xor(accumulator, sload(add(start, i)))
            }
        }
    }
}
