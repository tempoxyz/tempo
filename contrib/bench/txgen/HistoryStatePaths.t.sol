// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import "./HistoryStatePaths.sol";

interface VmHistory {
    function store(address, bytes32, bytes32) external;
    function load(address, bytes32) external view returns (bytes32);
    function etch(address, bytes calldata) external;
}

contract HistoryStatePathsTest {
    VmHistory private constant vm = VmHistory(address(uint160(uint256(keccak256("hevm cheat code")))));
    HistoryStatePaths private router;
    bytes32 private constant SALT = bytes32(uint256(19));

    function setUp() public { router = new HistoryStatePaths(); }

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
