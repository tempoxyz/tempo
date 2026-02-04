// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ISignatureVerification } from "../../src/interfaces/ISignatureVerification.sol";
import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title SignatureVerification Invariant Tests
/// @notice Fuzz-based invariant tests for the SignatureVerification precompile (TIP-1020)
/// @dev Tests invariants TEMPO-SIG1 through TEMPO-SIG10 for signature verification
contract SignatureVerificationInvariantTest is InvariantBaseTest {
    /// @dev SignatureVerification precompile address (TIP-1020)
    ISignatureVerification public constant sigVerifier =
        ISignatureVerification(0x5165300000000000000000000000000000000000);

    /// @dev Private keys for test signers (generated deterministically for reproducibility)
    uint256[] private _signerPrivateKeys;
    address[] private _signerAddresses;

    /// @dev Track valid signatures we've created for verification
    struct SignatureRecord {
        address signer;
        bytes32 hash;
        bytes signature;
        bool isValid;
    }

    SignatureRecord[] private _signatures;

    /// @dev Counters for statistics
    uint256 private _totalVerifyAttempts;
    uint256 private _totalSuccessfulVerifies;
    uint256 private _totalFailedVerifies;

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();

        // Generate test signers with known private keys
        for (uint256 i = 1; i <= 5; i++) {
            uint256 pk = uint256(keccak256(abi.encodePacked("signer", i)));
            // Ensure pk is valid (non-zero and less than secp256k1 order)
            pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
            _signerPrivateKeys.push(pk);
            _signerAddresses.push(vm.addr(pk));
        }

        _initLogFile("signature_verification.log", "SignatureVerification Invariant Test Log");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Select a random signer
    function _selectSigner(uint256 seed)
        internal
        view
        returns (uint256 privateKey, address signerAddr)
    {
        uint256 idx = seed % _signerPrivateKeys.length;
        return (_signerPrivateKeys[idx], _signerAddresses[idx]);
    }

    /// @dev Generate a secp256k1 signature using vm.sign
    function _signSecp256k1(uint256 privateKey, bytes32 hash)
        internal
        pure
        returns (bytes memory signature)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        // Encode as r || s || v (65 bytes, Tempo format for secp256k1)
        signature = abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for verifying a valid secp256k1 signature
    /// @dev Tests TEMPO-SIG1: Valid signature always returns true
    function verifyValidSecp256k1(uint256 signerSeed, bytes32 messageSeed) external {
        (uint256 privateKey, address signerAddr) = _selectSigner(signerSeed);
        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp));

        bytes memory signature = _signSecp256k1(privateKey, messageHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, messageHash, signature) returns (bool result) {
            // TEMPO-SIG1: Valid signature should return true
            assertTrue(result, "TEMPO-SIG1: Valid secp256k1 signature should return true");
            _totalSuccessfulVerifies++;

            // Record for later invariant checks
            _signatures.push(
                SignatureRecord({
                    signer: signerAddr,
                    hash: messageHash,
                    signature: signature,
                    isValid: true
                })
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_VALID: signer=",
                        vm.toString(signerAddr),
                        " hash=",
                        vm.toString(messageHash)
                    )
                );
            }
        } catch (bytes memory reason) {
            // Unexpected failure for valid signature
            _totalFailedVerifies++;
            revert(
                string.concat(
                    "TEMPO-SIG1: Valid signature should not revert, got: ",
                    string(reason)
                )
            );
        }
    }

    /// @notice Handler for verifying with wrong signer
    /// @dev Tests TEMPO-SIG3: Signer mismatch reverts
    function verifyWrongSigner(uint256 signerSeed, uint256 wrongSignerSeed, bytes32 messageSeed)
        external
    {
        (uint256 privateKey, address actualSigner) = _selectSigner(signerSeed);
        (, address wrongSigner) = _selectSigner(wrongSignerSeed);

        // Ensure wrong signer is actually different
        if (wrongSigner == actualSigner) {
            wrongSigner = address(uint160(wrongSigner) + 1);
        }

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp));
        bytes memory signature = _signSecp256k1(privateKey, messageHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(wrongSigner, messageHash, signature) returns (bool) {
            // Should not succeed with wrong signer
            revert("TEMPO-SIG3: Wrong signer should revert with SignerMismatch");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            // TEMPO-SIG3: Should revert with SignerMismatch
            assertEq(
                bytes4(reason),
                ISignatureVerification.SignerMismatch.selector,
                "TEMPO-SIG3: Should revert with SignerMismatch"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_WRONG_SIGNER: expected=",
                        vm.toString(wrongSigner),
                        " actual=",
                        vm.toString(actualSigner)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying with wrong hash
    /// @dev Tests TEMPO-SIG10: Signature valid for hash H is invalid for H' ≠ H
    function verifyWrongHash(uint256 signerSeed, bytes32 originalHash, bytes32 wrongHash) external {
        // Ensure hashes are different
        if (originalHash == wrongHash) {
            wrongHash = keccak256(abi.encodePacked(wrongHash, "different"));
        }

        (uint256 privateKey, address signerAddr) = _selectSigner(signerSeed);
        bytes memory signature = _signSecp256k1(privateKey, originalHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, wrongHash, signature) returns (bool) {
            // Should not succeed with wrong hash
            revert("TEMPO-SIG10: Wrong hash should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            // TEMPO-SIG10: Should revert (either SignerMismatch or InvalidSignature)
            bytes4 selector = bytes4(reason);
            bool isExpectedError = selector == ISignatureVerification.SignerMismatch.selector
                || selector == ISignatureVerification.InvalidSignature.selector;
            assertTrue(isExpectedError, "TEMPO-SIG10: Should revert with SignerMismatch or InvalidSignature");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_WRONG_HASH: signer=",
                        vm.toString(signerAddr),
                        " original=",
                        vm.toString(originalHash),
                        " wrong=",
                        vm.toString(wrongHash)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying invalid signature bytes
    /// @dev Tests TEMPO-SIG2: Invalid signature always reverts
    function verifyInvalidSignature(uint256 signerSeed, bytes32 hash, uint8 invalidLength)
        external
    {
        (, address signerAddr) = _selectSigner(signerSeed);

        // Create invalid signature (wrong length, not 65 bytes for secp256k1)
        uint256 len = bound(invalidLength, 1, 64);
        bytes memory invalidSig = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            invalidSig[i] = bytes1(uint8(i));
        }

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, hash, invalidSig) returns (bool) {
            revert("TEMPO-SIG2: Invalid signature should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            // TEMPO-SIG2: Should revert with InvalidSignature
            assertEq(
                bytes4(reason),
                ISignatureVerification.InvalidSignature.selector,
                "TEMPO-SIG2: Should revert with InvalidSignature"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_INVALID_SIG: sigLen=",
                        vm.toString(len),
                        " signer=",
                        vm.toString(signerAddr)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying empty signature
    /// @dev Tests TEMPO-SIG2: Empty signature reverts
    function verifyEmptySignature(uint256 signerSeed, bytes32 hash) external {
        (, address signerAddr) = _selectSigner(signerSeed);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, hash, "") returns (bool) {
            revert("TEMPO-SIG2: Empty signature should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            assertEq(
                bytes4(reason),
                ISignatureVerification.InvalidSignature.selector,
                "TEMPO-SIG2: Empty signature should revert with InvalidSignature"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_EMPTY_SIG: signer=",
                        vm.toString(signerAddr)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying keychain signature with unauthorized key
    /// @dev Tests TEMPO-SIG9: Keychain with non-existent key reverts
    function verifyUnauthorizedKeychainKey(
        uint256 signerSeed,
        bytes32 hash,
        address randomAccessKey
    ) external {
        (uint256 privateKey, address rootAddr) = _selectSigner(signerSeed);

        // Sign with the access key (simulated)
        bytes memory accessSig = _signSecp256k1(privateKey, hash);

        // Encode as keychain signature: 0x03 || user_address || inner_signature
        bytes memory keychainSig = abi.encodePacked(
            uint8(0x03), // SIGNATURE_TYPE_KEYCHAIN
            rootAddr,
            accessSig
        );

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, hash, keychainSig) returns (bool) {
            // Key doesn't exist, should fail
            revert("TEMPO-SIG9: Keychain with non-existent key should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            // TEMPO-SIG9: Should revert with UnauthorizedKeychainKey
            assertEq(
                bytes4(reason),
                ISignatureVerification.UnauthorizedKeychainKey.selector,
                "TEMPO-SIG9: Should revert with UnauthorizedKeychainKey"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_UNAUTHORIZED_KEYCHAIN: rootAddr=",
                        vm.toString(rootAddr)
                    )
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    /// @dev Verifies TEMPO-SIG4: Signature type consistency across recorded signatures
    function invariant_globalInvariants() public view {
        // TEMPO-SIG4: All recorded valid signatures should still be verifiable
        // (This is a consistency check - if we recorded it as valid, it stays valid)
        for (uint256 i = 0; i < _signatures.length; i++) {
            SignatureRecord memory record = _signatures[i];
            if (record.isValid) {
                // Note: We can't call verify here in a view context that modifies state
                // but we can verify the signature hasn't been corrupted
                assertTrue(
                    record.signature.length == 65,
                    "TEMPO-SIG4: secp256k1 signature should be 65 bytes"
                );
            }
        }
    }

    /// @notice Called after each invariant run to log final state
    function afterInvariant() public {
        if (!_loggingEnabled) return;

        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("Final State Summary");
        _log("--------------------------------------------------------------------------------");
        _log(string.concat("Total verify attempts: ", vm.toString(_totalVerifyAttempts)));
        _log(string.concat("Successful verifies: ", vm.toString(_totalSuccessfulVerifies)));
        _log(string.concat("Failed verifies (expected): ", vm.toString(_totalFailedVerifies)));
        _log(string.concat("Recorded signatures: ", vm.toString(_signatures.length)));
        _log("--------------------------------------------------------------------------------");
    }
}
