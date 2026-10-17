// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    DepositPayload,
    DepositType,
    ForcedExit,
    ForcedExitAuthorization,
    ForcedExitReason,
    Withdrawal
} from "../../src/runtime/interfaces/IZone.sol";
import { DepositQueueLib } from "../../src/runtime/libraries/DepositQueueLib.sol";
import { Test } from "forge-std/Test.sol";

/// The same committed fixture is checked by exithatch's Rust tests.
contract ForcedExitVectorsTest is Test {

    function repeated(uint256 length, bytes1 value) internal pure returns (bytes memory data) {
        data = new bytes(length);
        for (uint256 i; i < length; ++i) {
            data[i] = value;
        }
    }

    function test_solidityRustCommitments() public view {
        string memory fixture = vm.readFile("test/fixtures/forcedExit.json");
        address portal = 0x5ad0000000000000000000000000000000000001;
        address token = 0x20C0000000000000000000000000000000000000;
        address recipient = 0x2222222222222222222222222222222222222222;
        ForcedExitAuthorization memory auth = ForcedExitAuthorization(
            0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf, 1234, token, recipient, 42, 100
        );
        bytes32 typeHash = keccak256(
            "ForcedExitAuthorization(address account,uint256 zoneChainId,address token,address recipient,uint256 nonce,uint64 admitBefore)"
        );
        assertEq(typeHash, vm.parseJsonBytes32(fixture, ".typeHash"));
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("TempoZoneForcedExit"),
                keccak256("1"),
                uint256(42_431),
                portal
            )
        );
        bytes32 digest =
            keccak256(abi.encodePacked(hex"1901", domain, keccak256(abi.encode(typeHash, auth))));
        assertEq(digest, vm.parseJsonBytes32(fixture, ".digest"));
        bytes memory signature = vm.parseJsonBytes(fixture, ".signature");
        bytes32 r;
        bytes32 s;
        assembly ("memory-safe") {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
        }
        assertEq(ecrecover(digest, uint8(signature[64]) + 27, r, s), auth.account);
        assertEq(
            abi.encode(uint8(1), auth, repeated(65, 0x33)), vm.parseJsonBytes(fixture, ".payload")
        );
        ForcedExit memory entry = ForcedExit(
            1,
            token,
            3,
            DepositPayload(
                0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                2,
                repeated(384, 0x44),
                bytes12(hex"555555555555555555555555"),
                bytes16(hex"66666666666666666666666666666666")
            ),
            0x7777777777777777777777777777777777777777,
            80,
            90
        );
        assertEq(
            DepositQueueLib.enqueueForcedExit(bytes32(repeated(32, 0x88)), entry),
            vm.parseJsonBytes32(fixture, ".queueHash")
        );
        bytes32 privateRequestHash = keccak256(abi.encode(uint8(1), auth, signature));
        assertEq(privateRequestHash, vm.parseJsonBytes32(fixture, ".privateRequestHash"));
        bytes32 tag = keccak256(abi.encodePacked(auth.account, privateRequestHash, uint64(9)));
        assertEq(tag, vm.parseJsonBytes32(fixture, ".senderTag"));
        Withdrawal memory withdrawal = Withdrawal(token, tag, recipient, 123_456, 0, 0, 9, "", "");
        bytes32 withdrawalHash = keccak256(abi.encode(withdrawal));
        assertEq(withdrawalHash, vm.parseJsonBytes32(fixture, ".withdrawalHash"));
        assertEq(
            keccak256(abi.encode(withdrawal, bytes32(repeated(32, 0x99)))),
            vm.parseJsonBytes32(fixture, ".withdrawalQueueHash")
        );
        assertEq(uint8(DepositType.WithdrawalBounceBack), 0);
        assertEq(uint8(DepositType.Deposit), 1);
        assertEq(uint8(DepositType.ForcedExit), 2);
        assertEq(uint8(ForcedExitReason.None), 0);
        assertEq(uint8(ForcedExitReason.InvalidPayload), 1);
        assertEq(uint8(ForcedExitReason.InvalidAuthorization), 2);
        assertEq(uint8(ForcedExitReason.NonceAlreadyConsumed), 3);
        assertEq(uint8(ForcedExitReason.BalanceOverflow), 4);
        assertEq(uint8(ForcedExitReason.PolicyRejected), 5);
    }

}
