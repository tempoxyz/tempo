// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Deposit, DepositPayload, DepositType } from "../../src/runtime/interfaces/IZone.sol";
import {
    ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE,
    EncryptedDepositLib
} from "../../src/runtime/libraries/EncryptedDeposit.sol";
import { Test } from "forge-std/Test.sol";

contract EncryptedDepositHarness {

    function encodePlaintext(address to, bytes32 memo) external pure returns (bytes memory) {
        return EncryptedDepositLib.encodePlaintext(to, memo);
    }

    function decodePlaintext(bytes memory plaintext)
        external
        pure
        returns (address to, bytes32 memo)
    {
        return EncryptedDepositLib.decodePlaintext(plaintext);
    }

    function queueHash(Deposit memory deposit, bytes32 prevHash) external pure returns (bytes32) {
        return EncryptedDepositLib.queueHash(deposit, prevHash);
    }

}

contract EncryptedDepositLibTest is Test {

    EncryptedDepositHarness internal harness;

    function setUp() public {
        harness = new EncryptedDepositHarness();
    }

    /// @notice Verifies plaintext encoding round-trips a recipient and memo.
    function test_encodeDecode_roundtrip() public view {
        address to = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        bytes32 memo = bytes32("memo");

        bytes memory plaintext = harness.encodePlaintext(to, memo);
        (address decodedTo, bytes32 decodedMemo) = harness.decodePlaintext(plaintext);

        assertEq(plaintext.length, ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE);
        assertEq(decodedTo, to);
        assertEq(decodedMemo, memo);
    }

    /// @notice Verifies decoding rejects plaintext with the wrong byte length.
    function test_decodePlaintext_revertsOnWrongLength() public {
        bytes memory plaintext = new bytes(63);

        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                uint256(63),
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        harness.decodePlaintext(plaintext);
    }

    /// @notice Verifies deposit queue hashing matches the typed ABI encoding.
    function test_queueHash_matchesTypedEncoding() public view {
        Deposit memory deposit = _makeEncryptedDeposit(100e6, bytes32("ciphertext"));
        bytes32 prevHash = keccak256("previous");

        bytes32 actual = harness.queueHash(deposit, prevHash);
        bytes32 expected = keccak256(abi.encode(DepositType.Deposit, deposit, prevHash));

        assertEq(actual, expected);
    }

    /// @notice Verifies plaintext encoding round-trips any recipient and memo.
    function testFuzz_encodeDecode_roundtrip(address to, bytes32 memo) public view {
        bytes memory plaintext = harness.encodePlaintext(to, memo);
        (address decodedTo, bytes32 decodedMemo) = harness.decodePlaintext(plaintext);

        assertEq(plaintext.length, ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE);
        assertEq(decodedTo, to);
        assertEq(decodedMemo, memo);
    }

    function _makeEncryptedDeposit(
        uint128 amount,
        bytes32 seed
    )
        internal
        pure
        returns (Deposit memory)
    {
        bytes memory ciphertext = new bytes(64);
        for (uint256 i = 0; i < ciphertext.length; i++) {
            ciphertext[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        }

        return Deposit({
            token: address(0x1000),
            sender: address(0x200),
            amount: amount,
            tempoRefundRecipient: address(0x300),
            keyIndex: 1,
            encrypted: DepositPayload({
                ephemeralPubkeyX: seed,
                ephemeralPubkeyYParity: 0x02,
                ciphertext: ciphertext,
                nonce: bytes12(seed),
                tag: bytes16(seed)
            })
        });
    }

}
