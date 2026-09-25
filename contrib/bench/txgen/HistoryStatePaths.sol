// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "./StateAccessBenchmark.sol";

/// Local fixture installed over the original populated SLOAD benchmark account.
contract HistoryStatePaths is StateAccessBenchmark {
    uint256 private constant CURSOR = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    uint256 public constant ACCESSES = 1024;
    uint256 public constant CODE_ACCESSES = 128;
    uint256 public constant READ_ACCESSES = 128;
    uint256 public constant MAX_READ_ACCESSES = 13800;
    uint256 public constant MAX_CODE_ACCESSES = 10800;
    uint256 private constant CODE_BASE = 0x006000000000000000000000000000000000000000;

    function sequence() external view returns (uint256 value) {
        assembly { value := sload(CURSOR) }
    }

    function _select(bytes32 salt, bool dependent) private returns (uint256 seed) {
        uint256 cursor;
        assembly {
            cursor := sload(CURSOR)
            sstore(CURSOR, add(cursor, 1))
        }
        return uint256(keccak256(abi.encode(salt, dependent ? cursor : 0)));
    }

    /// EXTCODECOPY forces code retrieval, unlike a code-hash-only account lookup.
    function touchCode(bytes32 salt, uint256 count, bool dependent)
        external returns (bytes32 accumulator)
    {
        require(count >= ACCESSES, "small corpus");
        uint256 seed = _select(salt, dependent);
        assembly {
            for { let i := 0 } lt(i, CODE_ACCESSES) { i := add(i, 1) } {
                mstore(0, seed)
                mstore(32, i)
                let target := add(CODE_BASE, mod(keccak256(0, 64), count))
                extcodecopy(target, 0, 1, 32)
                accumulator := xor(accumulator, mload(0))
            }
        }
    }

    /// Small transactions retain the entire original 4096-slot-page working set.
    function touchReads(bytes32 salt, uint256 pageCount, bool dependent)
        external returns (bytes32 accumulator)
    {
        require(pageCount > 0 && pageCount <= type(uint256).max / 4096, "bad pages");
        uint256 chunks = pageCount * (4096 / READ_ACCESSES);
        uint256 start = (_select(salt, dependent) % chunks) * READ_ACCESSES;
        assembly {
            for { let i := 0 } lt(i, READ_ACCESSES) { i := add(i, 1) } {
                accumulator := xor(accumulator, sload(add(start, i)))
            }
        }
    }

    /// Near the 30M gas cap, without shrinking or extending the populated domain.
    function touchMaxReads(bytes32 salt, uint256 pageCount, bool dependent)
        external returns (bytes32 accumulator)
    {
        require(pageCount >= 4 && pageCount <= type(uint256).max / 4096, "bad pages");
        uint256 start = _select(salt, dependent) % (pageCount * 4096 - MAX_READ_ACCESSES + 1);
        assembly {
            for { let i := 0 } lt(i, MAX_READ_ACCESSES) { i := add(i, 1) } {
                accumulator := xor(accumulator, sload(add(start, i)))
            }
        }
    }

    /// Same 32-byte copy as the small case: fetched code, not copy gas, is the load.
    function touchMaxCode(bytes32 salt, uint256 count, bool dependent)
        external returns (bytes32 accumulator)
    {
        require(count >= MAX_CODE_ACCESSES, "small corpus");
        uint256 seed = _select(salt, dependent);
        assembly {
            for { let i := 0 } lt(i, MAX_CODE_ACCESSES) { i := add(i, 1) } {
                mstore(0, seed)
                mstore(32, i)
                let target := add(CODE_BASE, mod(keccak256(0, 64), count))
                extcodecopy(target, 0, 1, 32)
                accumulator := xor(accumulator, mload(0))
            }
        }
    }

    /// Calibrate latency by changing work per transaction, not the corpus size.
    function touchSizedReads(bytes32 salt, uint256 pageCount, bool dependent, uint256 accesses)
        external returns (bytes32 accumulator)
    {
        require(accesses > 0 && accesses <= MAX_READ_ACCESSES, "bad accesses");
        require(pageCount > 0 && pageCount <= type(uint256).max / 4096, "bad pages");
        require(pageCount * 4096 >= accesses, "small corpus");
        uint256 start = _select(salt, dependent) % (pageCount * 4096 - accesses + 1);
        assembly {
            for { let i := 0 } lt(i, accesses) { i := add(i, 1) } {
                accumulator := xor(accumulator, sload(add(start, i)))
            }
        }
    }

    function touchSizedCode(bytes32 salt, uint256 count, bool dependent, uint256 accesses)
        external returns (bytes32 accumulator)
    {
        require(accesses > 0 && accesses <= MAX_CODE_ACCESSES, "bad accesses");
        require(count >= accesses, "small corpus");
        uint256 seed = _select(salt, dependent);
        assembly {
            for { let i := 0 } lt(i, accesses) { i := add(i, 1) } {
                mstore(0, seed)
                mstore(32, i)
                let target := add(CODE_BASE, mod(keccak256(0, 64), count))
                extcodecopy(target, 0, 1, 32)
                accumulator := xor(accumulator, mload(0))
            }
        }
    }

    /// The transaction access list declares exactly [start, start + accesses).
    /// No history cursor: targets are known before execution and can be prewarmed.
    function touchDeclaredReads(uint256 start, uint256 accesses)
        external view returns (bytes32 accumulator)
    {
        // Native Tempo transactions currently allow 256 keys per account.
        require(accesses > 0 && accesses <= 256, "bad accesses");
        require(start <= type(uint256).max - accesses, "bad range");
        assembly {
            for { let i := 0 } lt(i, accesses) { i := add(i, 1) } {
                accumulator := xor(accumulator, sload(add(start, i)))
            }
        }
    }

    /// One read and one nonzero-to-different-nonzero write per declared slot.
    function touchDeclaredWrites(uint256 start, uint256 accesses)
        external returns (bytes32 accumulator)
    {
        require(accesses > 0 && accesses <= 256, "bad accesses");
        require(start <= type(uint256).max - accesses, "bad range");
        assembly {
            for { let i := 0 } lt(i, accesses) { i := add(i, 1) } {
                let slot := add(start, i)
                let before := sload(slot)
                if iszero(before) { revert(0, 0) }
                let afterValue := xor(before, shl(255, 1))
                if iszero(afterValue) { revert(0, 0) }
                sstore(slot, afterValue)
                accumulator := xor(accumulator, afterValue)
            }
        }
    }

    /// Existing nonzero storage is updated, not newly allocated or cleared.
    /// The 4096-slot logical pages match the original SLOAD fixture exactly.
    function touchWrites(bytes32 salt, uint256 pageCount, bool dependent)
        external returns (bytes32 accumulator)
    {
        require(pageCount > 0 && pageCount <= type(uint256).max / 4096, "bad pages");
        uint256 start = (_select(salt, dependent) % pageCount) * 4096;
        assembly {
            for { let i := 0 } lt(i, ACCESSES) { i := add(i, 1) } {
                let slot := add(start, i)
                let before := sload(slot)
                // Initial values are slot+1. The high-bit toggle stays nonzero
                // and guarantees a changed value even on repeated visits.
                if iszero(before) { revert(0, 0) }
                let afterValue := xor(before, shl(255, 1))
                if iszero(afterValue) { revert(0, 0) }
                sstore(slot, afterValue)
                accumulator := xor(accumulator, afterValue)
            }
        }
    }
}
