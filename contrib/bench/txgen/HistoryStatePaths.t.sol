// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "./HistoryStatePaths.sol";

interface VmHistory {
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external view returns (bytes32);
    function etch(address, bytes calldata) external;
    function cool(address) external;
    function coolSlot(address, bytes32) external;
}

contract HistoryStatePathsTest {
    event MeasuredGas(string workload, uint256 gasUsed);
    VmHistory private constant vm = VmHistory(address(uint160(uint256(keccak256("hevm cheat code")))));
    HistoryStatePaths private router;
    bytes32 private constant SALT = bytes32(uint256(19));
    bytes32 private maxCodeExpected;

    function setUp() public {
        router = new HistoryStatePaths();
        uint256 seed = uint256(keccak256(abi.encode(SALT, uint256(0))));
        // Install code in a separate transaction: etch in the measured test
        // leaves accounts warm despite cool(), unlike the restored fixture.
        for (uint256 i; i < router.MAX_CODE_ACCESSES(); ++i) {
            uint256 index = uint256(keccak256(abi.encode(seed, i))) % 4266667;
            address target = address(uint160(0x6000000000000000000000000000000000000000) + uint160(index));
            vm.etch(target, abi.encodePacked(bytes1(0), bytes32(index + 1)));
            maxCodeExpected ^= bytes32(index + 1);
        }
    }

    function testDeclaredReadsAndWritesTouchOnlySpecifiedRange() public {
        uint256 start = 1638399744;
        uint256 count = 256;
        bytes32 expected;
        for (uint256 i; i < count; ++i) {
            vm.store(address(router), bytes32(start + i), bytes32(start + i + 1));
            expected ^= bytes32(start + i + 1);
        }
        vm.store(address(router), bytes32(start - 1), bytes32(uint256(17)));
        vm.store(address(router), bytes32(start + count), bytes32(uint256(19)));
        require(router.touchDeclaredReads(start, count) == expected);
        for (uint256 i; i < count; ++i)
            require(vm.load(address(router), bytes32(start + i)) == bytes32(start + i + 1));
        // Even count makes the high-bit XOR cancel in the returned accumulator.
        require(router.touchDeclaredWrites(start, count) == expected);
        for (uint256 i; i < count; ++i)
            require(vm.load(address(router), bytes32(start + i)) == bytes32((start + i + 1) ^ (1 << 255)));
        require(router.touchDeclaredWrites(start, count) == expected);
        for (uint256 i; i < count; ++i)
            require(vm.load(address(router), bytes32(start + i)) == bytes32(start + i + 1));
        require(router.sequence() == 0);
        require(vm.load(address(router), bytes32(start - 1)) == bytes32(uint256(17)));
        require(vm.load(address(router), bytes32(start + count)) == bytes32(uint256(19)));
    }

    function testDeclaredSingleSlotReturnAndMissingWriteRevert() public {
        vm.store(address(router), bytes32(uint256(42)), bytes32(uint256(43)));
        require(router.touchDeclaredReads(42, 1) == bytes32(uint256(43)));
        require(router.touchDeclaredWrites(42, 1) == bytes32(uint256(43) ^ (1 << 255)));
        (bool empty,) = address(router).call(abi.encodeCall(router.touchDeclaredWrites, (43, 1)));
        require(!empty && router.sequence() == 0);
    }

    function testDeclaredRejectsEmptyOversizedAndCursorRanges() public {
        uint256[4] memory starts = [uint256(0), 0, type(uint256).max, type(uint256).max - 1];
        uint256[4] memory counts = [uint256(0), 257, 1, 2];
        for (uint256 i; i < starts.length; ++i) {
            (bool readOk,) = address(router).call(abi.encodeCall(router.touchDeclaredReads, (starts[i], counts[i])));
            (bool writeOk,) = address(router).call(abi.encodeCall(router.touchDeclaredWrites, (starts[i], counts[i])));
            require(!readOk && !writeOk && router.sequence() == 0);
        }
    }

    function testSizedReadsFollowHistoryAcrossFullDomain() public {
        for (uint256 sequence; sequence < 2; ++sequence) {
            uint256 count = 12500;
            uint256 start = uint256(keccak256(abi.encode(SALT, sequence))) % (399999 * 4096 - count + 1);
            bytes32 expected;
            for (uint256 i; i < count; ++i) {
                vm.store(address(router), bytes32(start + i), bytes32(start + i + 1));
                expected ^= bytes32(start + i + 1);
            }
            require(router.touchSizedReads(SALT, 399999, true, count) == expected);
            require(router.sequence() == sequence + 1);
        }
    }

    function testSizedCodeMatchesMaxAccessPrefixAndControl() public {
        uint256 seed = uint256(keccak256(abi.encode(SALT, uint256(0))));
        bytes32 expected;
        for (uint256 i; i < 3000; ++i) {
            uint256 index = uint256(keccak256(abi.encode(seed, i))) % 4266667;
            expected ^= bytes32(index + 1);
        }
        require(router.touchSizedCode(SALT, 4266667, true, 3000) == expected);
        require(router.touchSizedCode(SALT, 4266667, false, 3000) == expected);
        require(router.sequence() == 2);
    }

    function testSizedRejectsInvalidBoundsBeforeCursorChange() public {
        (bool zero,) = address(router).call(abi.encodeCall(router.touchSizedReads, (SALT, 399999, true, 0)));
        (bool high,) = address(router).call(abi.encodeCall(router.touchSizedReads, (SALT, 399999, true, 13801)));
        (bool small,) = address(router).call(abi.encodeCall(router.touchSizedReads, (SALT, 1, true, 12500)));
        (bool codeZero,) = address(router).call(abi.encodeCall(router.touchSizedCode, (SALT, 4266667, true, 0)));
        (bool codeHigh,) = address(router).call(abi.encodeCall(router.touchSizedCode, (SALT, 4266667, true, 10801)));
        (bool codeSmall,) = address(router).call(abi.encodeCall(router.touchSizedCode, (SALT, 1000, true, 3000)));
        require(!zero && !high && !small && !codeZero && !codeHigh && !codeSmall && router.sequence() == 0);
    }

    function testMaxReadsAreColdPopulatedAndBelowGasCap() public {
        checkMaxReads(false);
    }

    function testSizedMaxReadsAreColdPopulatedAndBelowGasCap() public {
        checkMaxReads(true);
    }

    function checkMaxReads(bool sized) private {
        uint256 count = router.MAX_READ_ACCESSES();
        uint256 start = uint256(keccak256(abi.encode(SALT, uint256(0)))) % (399999 * 4096 - count + 1);
        bytes32 expected;
        for (uint256 i; i < count; ++i) {
            bytes32 slot = bytes32(start + i);
            bytes32 value = bytes32(start + i + 1);
            vm.store(address(router), slot, value);
            vm.coolSlot(address(router), slot);
            expected ^= value;
        }
        uint256 before = gasleft();
        bytes32 actual = sized ? router.touchSizedReads(SALT, 399999, true, count) : router.touchMaxReads(SALT, 399999, true);
        uint256 used = before - gasleft();
        emit MeasuredGas("sload", used);
        require(actual == expected && router.sequence() == 1, "read/cursor mismatch");
        require(used > 29_800_000 && used < 29_960_000, "near-cap SLOAD gas budget");
    }

    function testMaxCodeIsColdPopulatedAndBelowGasCap() public {
        checkMaxCode(false);
    }

    function testSizedMaxCodeIsColdPopulatedAndBelowGasCap() public {
        checkMaxCode(true);
    }

    function checkMaxCode(bool sized) private {
        uint256 accesses = router.MAX_CODE_ACCESSES();
        uint256 count = 4266667;
        uint256 seed = uint256(keccak256(abi.encode(SALT, uint256(0))));
        for (uint256 i; i < accesses; ++i) {
            uint256 index = uint256(keccak256(abi.encode(seed, i))) % count;
            address target = address(uint160(0x6000000000000000000000000000000000000000) + uint160(index));
            vm.cool(target);
        }
        uint256 before = gasleft();
        bytes32 actual = sized ? router.touchSizedCode(SALT, count, true, accesses) : router.touchMaxCode(SALT, count, true);
        uint256 used = before - gasleft();
        emit MeasuredGas("bytecode", used);
        require(actual == maxCodeExpected && router.sequence() == 1, "code/cursor mismatch");
        require(used > 29_700_000 && used < 29_960_000, "near-cap bytecode gas budget");
    }

    function testMaxReadsRejectUnpopulatedRange() public {
        (bool small,) = address(router).call(abi.encodeCall(router.touchMaxReads, (SALT, 3, true)));
        (bool overflow,) = address(router).call(abi.encodeCall(router.touchMaxReads, (SALT, type(uint256).max, true)));
        require(!small && !overflow && router.sequence() == 0);
    }

    function testOriginalSloadImplementationIsPreserved() public {
        StateAccessBenchmark original = new StateAccessBenchmark();
        for (uint256 sequence; sequence < 2; ++sequence) {
            uint256 start = (uint256(keccak256(abi.encode(SALT, sequence))) % 399999) * 4096;
            for (uint256 i; i < 4096; ++i) {
                vm.store(address(router), bytes32(start + i), bytes32(start + i + 1));
                vm.store(address(original), bytes32(start + i), bytes32(start + i + 1));
            }
            require(router.touchStateDependent(SALT, 399999) == original.touchStateDependent(SALT, 399999));
            require(router.sequence() == sequence + 1);
            for (uint256 i; i < 4096; ++i) {
                require(uint256(vm.load(address(router), bytes32(start + i))) == start + i + 1);
            }
        }
    }

    function testSmallReadsCoverAllChunksAndFollowHistory() public {
        uint256 chunksSeen;
        for (uint256 sequence; sequence < 256; ++sequence) {
            uint256 chunk = uint256(keccak256(abi.encode(SALT, sequence))) % 32;
            uint256 start = chunk * 128;
            chunksSeen |= 1 << chunk;
            bytes32 expected;
            for (uint256 i; i < 128; ++i) {
                bytes32 value = keccak256(abi.encode(start + i));
                vm.store(address(router), bytes32(start + i), value);
                expected ^= value;
            }
            require(router.touchReads(SALT, 1, true) == expected);
            require(router.sequence() == sequence + 1);
            for (uint256 i; i < 128; ++i) {
                require(vm.load(address(router), bytes32(start + i)) == keccak256(abi.encode(start + i)));
            }
        }
        require(chunksSeen == type(uint32).max, "must reach all 32 chunks, not only the first");
    }

    function testSmallReadControlIgnoresHistoryAndRejectsBadPages() public {
        uint256 pages = 399999;
        uint256 start = (uint256(keccak256(abi.encode(SALT, uint256(0))))) % (pages * 32) * 128;
        bytes32 expected;
        for (uint256 i; i < 128; ++i) {
            bytes32 value = keccak256(abi.encode(start + i));
            vm.store(address(router), bytes32(start + i), value);
            expected ^= value;
        }
        require(router.touchReads(SALT, pages, false) == expected);
        require(router.touchReads(SALT, pages, false) == expected);
        require(router.sequence() == 2);
        (bool empty,) = address(router).call(abi.encodeCall(router.touchReads, (SALT, 0, true)));
        (bool overflow,) = address(router).call(abi.encodeCall(router.touchReads, (SALT, type(uint256).max, true)));
        require(!empty && !overflow && router.sequence() == 2);
    }

    function codeExpected(uint256 sequence, uint256 count) private pure returns (bytes32 result) {
        uint256 seed = uint256(keccak256(abi.encode(SALT, sequence)));
        for (uint256 i; i < 128; ++i) {
            uint256 index = uint256(keccak256(abi.encode(seed, i))) % count;
            result ^= bytes32(index + 1);
        }
    }

    function testCodeSelectionFollowsHistoryAndControlIgnoresIt() public {
        for (uint256 i; i < 2048; ++i) {
            vm.etch(address(uint160(0x6000000000000000000000000000000000000000) + uint160(i)), abi.encodePacked(bytes1(0), bytes32(i + 1)));
        }
        require(router.touchCode(SALT, 2048, true) == codeExpected(0, 2048));
        require(router.touchCode(SALT, 2048, true) == codeExpected(1, 2048));
        require(router.touchCode(SALT, 2048, false) == codeExpected(0, 2048));
        require(router.sequence() == 3);
    }

    function testWritesSelectPopulatedNonzeroSlotsFromHistory() public {
        for (uint256 sequence; sequence < 2; ++sequence) {
            uint256 start = (uint256(keccak256(abi.encode(SALT, sequence))) % 399999) * 4096;
            for (uint256 i; i < 1024; ++i) vm.store(address(router), bytes32(start + i), bytes32(start + i + 1));
            router.touchWrites(SALT, 399999, true);
            for (uint256 i; i < 1024; ++i) {
                require(uint256(vm.load(address(router), bytes32(start + i))) == (start + i + 1) ^ (1 << 255));
            }
        }
        require(router.sequence() == 2);
    }

    function testPredictableWriteControlStillMutatesCursorAndData() public {
        uint256 start = (uint256(keccak256(abi.encode(SALT, uint256(0)))) % 399999) * 4096;
        for (uint256 i; i < 1024; ++i) vm.store(address(router), bytes32(start + i), bytes32(start + i + 1));
        router.touchWrites(SALT, 399999, false);
        router.touchWrites(SALT, 399999, false);
        for (uint256 i; i < 1024; ++i) require(uint256(vm.load(address(router), bytes32(start + i))) == start + i + 1);
        require(router.sequence() == 2);
    }

    function testRejectsUnpopulatedWritesAndSmallCodeCorpus() public {
        (bool writes,) = address(router).call(abi.encodeCall(router.touchWrites, (SALT, 399999, true)));
        require(!writes && router.sequence() == 0);
        (bool code,) = address(router).call(abi.encodeCall(router.touchCode, (SALT, 10, true)));
        require(!code && router.sequence() == 0);
    }
}
