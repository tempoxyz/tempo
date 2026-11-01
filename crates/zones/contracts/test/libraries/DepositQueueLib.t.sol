// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    Deposit,
    DepositPayload,
    DepositType,
    WithdrawalBounceBackDeposit
} from "../../src/runtime/interfaces/IZone.sol";
import { DepositQueueLib } from "../../src/runtime/libraries/DepositQueueLib.sol";
import {
    ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE,
    EncryptedDepositLib
} from "../../src/runtime/libraries/EncryptedDeposit.sol";
import { Test, stdJson } from "forge-std/Test.sol";

/// @notice External wrapper to test EncryptedDepositLib.decodePlaintext (which is internal)
contract PlaintextDecoder {

    function decode(bytes memory plaintext) external pure returns (address to, bytes32 memo) {
        return EncryptedDepositLib.decodePlaintext(plaintext);
    }

}

/// @title DepositQueueLibTest
/// @notice Direct tests for DepositQueueLib functionality
contract DepositQueueLibTest is Test {

    using stdJson for string;

    string internal constant DEPOSIT_HASH_FIXTURE_PATH = "/test/fixtures/depositHashChain.json";

    address public alice = address(0x200);
    address public bob = address(0x300);

    /*//////////////////////////////////////////////////////////////
                            ENQUEUE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_enqueue_singleDeposit() public pure {
        WithdrawalBounceBackDeposit memory d = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });

        bytes32 newHash = DepositQueueLib.enqueue(bytes32(0), d);

        bytes32 expectedHash =
            keccak256(abi.encode(DepositType.WithdrawalBounceBack, d, bytes32(0)));
        assertEq(newHash, expectedHash);
    }

    function test_enqueue_multipleDeposits() public pure {
        WithdrawalBounceBackDeposit memory d1 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });
        WithdrawalBounceBackDeposit memory d2 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x200), amount: 200e6
        });
        WithdrawalBounceBackDeposit memory d3 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x200), amount: 300e6
        });

        bytes32 h1 = DepositQueueLib.enqueue(bytes32(0), d1);
        bytes32 h2 = DepositQueueLib.enqueue(h1, d2);
        bytes32 h3 = DepositQueueLib.enqueue(h2, d3);

        // Verify hash chain structure
        bytes32 expected1 = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d1, bytes32(0)));
        bytes32 expected2 = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d2, expected1));
        bytes32 expected3 = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d3, expected2));

        assertEq(h1, expected1);
        assertEq(h2, expected2);
        assertEq(h3, expected3);
    }

    function test_enqueue_hashChainStructure() public pure {
        // Verify that newer deposits wrap older ones
        WithdrawalBounceBackDeposit memory d1 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });
        WithdrawalBounceBackDeposit memory d2 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x200), amount: 200e6
        });

        bytes32 h1 = DepositQueueLib.enqueue(bytes32(0), d1);
        bytes32 h2 = DepositQueueLib.enqueue(h1, d2);

        // h2 should wrap h1
        assertEq(h2, keccak256(abi.encode(DepositType.WithdrawalBounceBack, d2, h1)));
    }

    function test_enqueue_emptyToEmpty() public pure {
        // An empty deposit struct should still produce a valid hash
        WithdrawalBounceBackDeposit memory d =
            WithdrawalBounceBackDeposit({ token: address(0x1000), to: address(0), amount: 0 });

        bytes32 h = DepositQueueLib.enqueue(bytes32(0), d);
        bytes32 expected = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d, bytes32(0)));
        assertEq(h, expected);
        assertTrue(h != bytes32(0)); // Hash of something is non-zero
    }

    function test_enqueue_differentInputsProduceDifferentHashes() public pure {
        WithdrawalBounceBackDeposit memory d1 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });
        WithdrawalBounceBackDeposit memory d2 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 101e6
        });

        bytes32 h1 = DepositQueueLib.enqueue(bytes32(0), d1);
        bytes32 h2 = DepositQueueLib.enqueue(bytes32(0), d2);

        assertTrue(h1 != h2);
    }

    function test_enqueue_sameDepositDifferentPrevHashProducesDifferentResult() public pure {
        WithdrawalBounceBackDeposit memory d = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });

        bytes32 h1 = DepositQueueLib.enqueue(bytes32(0), d);
        bytes32 h2 = DepositQueueLib.enqueue(bytes32(uint256(1)), d);

        assertTrue(h1 != h2);
    }

    /*//////////////////////////////////////////////////////////////
                    ENQUEUE ENCRYPTED TESTS
    //////////////////////////////////////////////////////////////*/

    function test_enqueueDeposit_singleDeposit() public pure {
        Deposit memory ed = Deposit({
            token: address(0x1000),
            sender: address(0x200),
            amount: 100e6,
            tempoRefundRecipient: address(0x200),
            keyIndex: 0,
            encrypted: DepositPayload({
                ephemeralPubkeyX: bytes32(uint256(1)),
                ephemeralPubkeyYParity: 0x02,
                ciphertext: new bytes(64),
                nonce: bytes12(0),
                tag: bytes16(0)
            })
        });

        bytes32 newHash = DepositQueueLib.enqueueDeposit(bytes32(0), ed);
        bytes32 expectedHash = keccak256(abi.encode(DepositType.Deposit, ed, bytes32(0)));
        assertEq(newHash, expectedHash);
    }

    function test_enqueueDeposit_matchesRegressionFixture() public view {
        string memory json = _depositHashFixtureJson();
        string memory depositRoot = ".deposit";
        string memory encryptedRoot = string.concat(depositRoot, ".encrypted");

        Deposit memory ed = Deposit({
            token: json.readAddress(string.concat(depositRoot, ".token")),
            sender: json.readAddress(string.concat(depositRoot, ".sender")),
            amount: uint128(json.readUint(string.concat(depositRoot, ".amount"))),
            tempoRefundRecipient: json.readAddress(
                string.concat(depositRoot, ".tempoRefundRecipient")
            ),
            keyIndex: json.readUint(string.concat(depositRoot, ".keyIndex")),
            encrypted: DepositPayload({
                ephemeralPubkeyX: json.readBytes32(
                    string.concat(encryptedRoot, ".ephemeralPubkeyX")
                ),
                ephemeralPubkeyYParity: uint8(
                    json.readUint(string.concat(encryptedRoot, ".ephemeralPubkeyYParity"))
                ),
                ciphertext: json.readBytes(string.concat(encryptedRoot, ".ciphertext")),
                nonce: _readBytes12(json, string.concat(encryptedRoot, ".nonce")),
                tag: _readBytes16(json, string.concat(encryptedRoot, ".tag"))
            })
        });

        bytes32 previousHash = json.readBytes32(".previousHash");
        bytes32 expectedHash = json.readBytes32(".expectedHash");
        bytes32 newHash = DepositQueueLib.enqueueDeposit(previousHash, ed);

        assertEq(newHash, expectedHash);
    }

    function test_enqueueDeposit_mixedQueue() public pure {
        WithdrawalBounceBackDeposit memory d1 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });

        Deposit memory ed = Deposit({
            token: address(0x1000),
            sender: address(0x300),
            amount: 200e6,
            tempoRefundRecipient: address(0x300),
            keyIndex: 0,
            encrypted: DepositPayload({
                ephemeralPubkeyX: bytes32(uint256(1)),
                ephemeralPubkeyYParity: 0x02,
                ciphertext: new bytes(64),
                nonce: bytes12(0),
                tag: bytes16(0)
            })
        });

        WithdrawalBounceBackDeposit memory d2 = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x200), amount: 300e6
        });

        bytes32 h1 = DepositQueueLib.enqueue(bytes32(0), d1);
        bytes32 h2 = DepositQueueLib.enqueueDeposit(h1, ed);
        bytes32 h3 = DepositQueueLib.enqueue(h2, d2);

        bytes32 expected1 = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d1, bytes32(0)));
        bytes32 expected2 = keccak256(abi.encode(DepositType.Deposit, ed, expected1));
        bytes32 expected3 = keccak256(abi.encode(DepositType.WithdrawalBounceBack, d2, expected2));

        assertEq(h1, expected1);
        assertEq(h2, expected2);
        assertEq(h3, expected3);
    }

    function test_enqueue_typeDiscriminatorPreventsCollision() public pure {
        // Same sender/amount but different type discriminators produce different hashes
        WithdrawalBounceBackDeposit memory d = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(0x300), amount: 100e6
        });

        Deposit memory ed = Deposit({
            token: address(0x1000),
            sender: address(0x200),
            amount: 100e6,
            tempoRefundRecipient: address(0x200),
            keyIndex: 0,
            encrypted: DepositPayload({
                ephemeralPubkeyX: bytes32(0),
                ephemeralPubkeyYParity: 0,
                ciphertext: "",
                nonce: bytes12(0),
                tag: bytes16(0)
            })
        });

        bytes32 regularHash = DepositQueueLib.enqueue(bytes32(0), d);
        bytes32 encryptedHash = DepositQueueLib.enqueueDeposit(bytes32(0), ed);

        assertTrue(regularHash != encryptedHash);
    }

    /// @notice Withdrawal bounce-back hash chains are deterministic across replays.
    function testFuzz_enqueue_hashChainDeterminism(uint8 rawCount, bytes32 seed) public pure {
        uint256 count = (uint256(rawCount) % 32) + 1;
        bytes32 firstRun = bytes32(0);
        bytes32 secondRun = bytes32(0);

        for (uint256 i = 0; i < count; i++) {
            WithdrawalBounceBackDeposit memory d = _makeDeposit(seed, i);
            bytes32 prevHash = firstRun;
            firstRun = DepositQueueLib.enqueue(firstRun, d);
            secondRun = DepositQueueLib.enqueue(secondRun, d);

            assertEq(firstRun, secondRun);
            assertEq(firstRun, keccak256(abi.encode(DepositType.WithdrawalBounceBack, d, prevHash)));
        }

        bytes32 replay = bytes32(0);
        for (uint256 i = 0; i < count; i++) {
            replay = DepositQueueLib.enqueue(replay, _makeDeposit(seed, i));
        }

        assertEq(firstRun, replay);
    }

    /// @notice WithdrawalBounceBack and Deposit discriminators produce distinct queue hashes.
    function testFuzz_enqueue_discriminatorsSeparateWithdrawalBounceBackAndDeposit(
        bytes32 prevHash,
        bytes32 seed,
        uint128 amount
    )
        public
        pure
    {
        WithdrawalBounceBackDeposit memory d = WithdrawalBounceBackDeposit({
            token: address(0x1000), to: address(uint160(uint256(seed))), amount: amount
        });
        Deposit memory ed = Deposit({
            token: d.token,
            sender: address(0x200),
            amount: d.amount,
            tempoRefundRecipient: address(0x300),
            keyIndex: uint256(seed),
            encrypted: DepositPayload({
                ephemeralPubkeyX: seed,
                ephemeralPubkeyYParity: 0x02,
                ciphertext: abi.encodePacked(seed, seed),
                nonce: bytes12(seed),
                tag: bytes16(seed)
            })
        });

        bytes32 regularHash = DepositQueueLib.enqueue(prevHash, d);
        bytes32 encryptedHash = DepositQueueLib.enqueueDeposit(prevHash, ed);

        assertEq(regularHash, keccak256(abi.encode(DepositType.WithdrawalBounceBack, d, prevHash)));
        assertEq(encryptedHash, keccak256(abi.encode(DepositType.Deposit, ed, prevHash)));
        assertTrue(regularHash != encryptedHash);
    }

    /*//////////////////////////////////////////////////////////////
                    PLAINTEXT ENCODE / DECODE TESTS
    //////////////////////////////////////////////////////////////*/

    PlaintextDecoder internal decoder;

    function _ensureDecoder() internal {
        if (address(decoder) == address(0)) {
            decoder = new PlaintextDecoder();
        }
    }

    /// @notice Round-trip: encodePlaintext → decodePlaintext recovers original values
    function test_plaintext_roundTrip() public {
        _ensureDecoder();
        address to = address(0x1234567890AbcdEF1234567890aBcdef12345678);
        bytes32 memo = bytes32("hello world");

        bytes memory encoded = EncryptedDepositLib.encodePlaintext(to, memo);
        assertEq(encoded.length, ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE, "encoded should be 64 bytes");

        (address decodedTo, bytes32 decodedMemo) = decoder.decode(encoded);
        assertEq(decodedTo, to, "decoded address mismatch");
        assertEq(decodedMemo, memo, "decoded memo mismatch");
    }

    /// @notice decodePlaintext rejects plaintext shorter than 64 bytes (e.g. 52 bytes)
    /// @dev Previously the check was >= 52, allowing out-of-bounds assembly reads
    function test_plaintext_rejectsTooShort() public {
        _ensureDecoder();
        bytes memory short = new bytes(52);
        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                uint256(52),
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        decoder.decode(short);
    }

    /// @notice decodePlaintext rejects empty plaintext
    function test_plaintext_rejectsEmpty() public {
        _ensureDecoder();
        bytes memory empty = new bytes(0);
        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                uint256(0),
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        decoder.decode(empty);
    }

    /// @notice decodePlaintext rejects plaintext longer than 64 bytes
    /// @dev Trailing bytes beyond 64 were previously silently ignored
    function test_plaintext_rejectsTooLong() public {
        _ensureDecoder();
        bytes memory long = new bytes(65);
        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                uint256(65),
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        decoder.decode(long);
    }

    /// @notice decodePlaintext rejects 63-byte plaintext (off-by-one boundary)
    function test_plaintext_rejects63Bytes() public {
        _ensureDecoder();
        bytes memory almostRight = new bytes(63);
        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                uint256(63),
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        decoder.decode(almostRight);
    }

    /// @notice decodePlaintext accepts exactly 64 bytes (boundary test)
    function test_plaintext_acceptsExact64Bytes() public {
        _ensureDecoder();
        bytes memory exact = new bytes(64);
        (address to, bytes32 memo) = decoder.decode(exact);
        assertEq(to, address(0), "zero-filled plaintext should decode to zero address");
        assertEq(memo, bytes32(0), "zero-filled plaintext should decode to zero memo");
    }

    /// @notice Fuzz test: decodePlaintext always reverts for length != 64
    function testFuzz_plaintext_rejectsWrongLength(uint256 len) public {
        _ensureDecoder();
        vm.assume(len != ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE);
        vm.assume(len <= 256); // keep allocation reasonable
        bytes memory data = new bytes(len);
        vm.expectRevert(
            abi.encodeWithSelector(
                EncryptedDepositLib.InvalidPlaintextLength.selector,
                len,
                ENCRYPTED_PAYLOAD_PLAINTEXT_SIZE
            )
        );
        decoder.decode(data);
    }

    function _depositHashFixtureJson() internal view returns (string memory) {
        return vm.readFile(string.concat(vm.projectRoot(), DEPOSIT_HASH_FIXTURE_PATH));
    }

    function _readBytes12(
        string memory json,
        string memory key
    )
        internal
        pure
        returns (bytes12 value)
    {
        bytes memory raw = json.readBytes(key);
        assertEq(raw.length, 12, "fixture bytes12 length");
        assembly {
            value := mload(add(raw, 32))
        }
    }

    function _readBytes16(
        string memory json,
        string memory key
    )
        internal
        pure
        returns (bytes16 value)
    {
        bytes memory raw = json.readBytes(key);
        assertEq(raw.length, 16, "fixture bytes16 length");
        assembly {
            value := mload(add(raw, 32))
        }
    }

    function _makeDeposit(
        bytes32 seed,
        uint256 index
    )
        internal
        pure
        returns (WithdrawalBounceBackDeposit memory)
    {
        return WithdrawalBounceBackDeposit({
            token: address(uint160(uint256(keccak256(abi.encode(seed, "token", index))))),
            to: address(uint160(uint256(keccak256(abi.encode(seed, "to", index))))),
            amount: uint128(uint256(keccak256(abi.encode(seed, "amount", index))))
        });
    }

}
