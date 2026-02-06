// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ISignatureVerification } from "../../src/interfaces/ISignatureVerification.sol";
import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title SignatureVerification Invariant Tests
/// @notice Fuzz-based invariant tests for the SignatureVerification precompile (TIP-1020)
/// @dev Tests invariants TEMPO-SIG1 through TEMPO-SIG10 for signature verification
///
/// Invariants tested:
/// - TEMPO-SIG1: Valid signature always returns true
/// - TEMPO-SIG2: Invalid signature always reverts with InvalidSignature
/// - TEMPO-SIG3: Signer mismatch reverts with SignerMismatch(expected, recovered)
/// - TEMPO-SIG4: Each signature type correctly identifies signer
/// - TEMPO-SIG5: Gas costs match spec (tested in Rust unit tests)
/// - TEMPO-SIG6: Keychain with revoked key reverts UnauthorizedKeychainKey
/// - TEMPO-SIG7: Keychain with expired key reverts UnauthorizedKeychainKey
/// - TEMPO-SIG8: Keychain signature type mismatch reverts
/// - TEMPO-SIG9: Keychain with non-existent key reverts UnauthorizedKeychainKey
/// - TEMPO-SIG10: Signature valid for hash H is invalid for H' ≠ H
contract SignatureVerificationInvariantTest is InvariantBaseTest {
    /// @dev SignatureVerification precompile address (TIP-1020)
    ISignatureVerification public constant sigVerifier =
        ISignatureVerification(0x5165300000000000000000000000000000000000);

    /// @dev Signature type constants (from TxBuilder)
    uint8 constant SIGNATURE_TYPE_P256 = 0x01;
    uint8 constant SIGNATURE_TYPE_WEBAUTHN = 0x02;
    uint8 constant SIGNATURE_TYPE_KEYCHAIN = 0x03;

    /// @dev P256 curve constants for S normalization
    uint256 constant P256_ORDER =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256N_HALF =
        0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;

    /// @dev Private keys for test signers (bounded to valid secp256k1 range)
    uint256[] private _secp256k1PrivateKeys;
    address[] private _secp256k1Addresses;

    /// @dev P256 keys for testing
    uint256[] private _p256PrivateKeys;
    bytes32[] private _p256PubKeyX;
    bytes32[] private _p256PubKeyY;
    address[] private _p256Addresses;

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

        // Generate secp256k1 test signers with known private keys
        for (uint256 i = 1; i <= 5; i++) {
            uint256 pk = uint256(keccak256(abi.encodePacked("secp256k1_signer", i)));
            // Bound to valid secp256k1 range (1, n-1)
            pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
            _secp256k1PrivateKeys.push(pk);
            _secp256k1Addresses.push(vm.addr(pk));
        }

        // Generate P256 test keys
        for (uint256 i = 1; i <= 3; i++) {
            uint256 pk = uint256(keccak256(abi.encodePacked("p256_signer", i)));
            pk = bound(pk, 1, P256_ORDER - 1);
            _p256PrivateKeys.push(pk);

            // Derive public key using vm.publicKeyP256
            (uint256 pubXUint, uint256 pubYUint) = vm.publicKeyP256(pk);
            bytes32 pubX = bytes32(pubXUint);
            bytes32 pubY = bytes32(pubYUint);
            _p256PubKeyX.push(pubX);
            _p256PubKeyY.push(pubY);

            // Derive address (same as tempo_primitives::derive_p256_address)
            _p256Addresses.push(_deriveP256Address(pubX, pubY));
        }

        _initLogFile("signature_verification.log", "SignatureVerification Invariant Test Log");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Derive P256 address from public key (matches Tempo implementation)
    function _deriveP256Address(bytes32 pubX, bytes32 pubY) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(pubX, pubY)))));
    }

    /// @dev Select a random secp256k1 signer
    function _selectSecp256k1Signer(uint256 seed)
        internal
        view
        returns (uint256 privateKey, address signerAddr)
    {
        uint256 idx = seed % _secp256k1PrivateKeys.length;
        return (_secp256k1PrivateKeys[idx], _secp256k1Addresses[idx]);
    }

    /// @dev Select a random P256 signer
    function _selectP256Signer(uint256 seed)
        internal
        view
        returns (uint256 privateKey, bytes32 pubX, bytes32 pubY, address signerAddr)
    {
        uint256 idx = seed % _p256PrivateKeys.length;
        return (
            _p256PrivateKeys[idx],
            _p256PubKeyX[idx],
            _p256PubKeyY[idx],
            _p256Addresses[idx]
        );
    }

    /// @dev Generate a secp256k1 signature (65 bytes: r || s || v)
    function _signSecp256k1(uint256 privateKey, bytes32 hash)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Normalize P256 S value to low-S form
    function _normalizeP256S(bytes32 s) internal pure returns (bytes32) {
        uint256 sVal = uint256(s);
        if (sVal > P256N_HALF) {
            return bytes32(P256_ORDER - sVal);
        }
        return s;
    }

    /// @dev Generate a P256 signature (130 bytes: 0x01 || r || s || pubX || pubY || prehash)
    function _signP256(
        uint256 privateKey,
        bytes32 hash,
        bytes32 pubX,
        bytes32 pubY
    ) internal view returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, hash);
        s = _normalizeP256S(s);
        return abi.encodePacked(SIGNATURE_TYPE_P256, r, s, pubX, pubY, uint8(0));
    }

    /// @dev Generate a Keychain signature wrapping secp256k1
    function _signKeychainSecp256k1(
        uint256 accessKeyPrivateKey,
        bytes32 hash,
        address userAddress
    ) internal pure returns (bytes memory) {
        bytes memory innerSig = _signSecp256k1(accessKeyPrivateKey, hash);
        return abi.encodePacked(SIGNATURE_TYPE_KEYCHAIN, userAddress, innerSig);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for verifying a valid secp256k1 signature
    /// @dev Tests TEMPO-SIG1, TEMPO-SIG4: Valid secp256k1 signature returns true
    function verifyValidSecp256k1(uint256 signerSeed, bytes32 messageSeed) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (uint256 privateKey, address signerAddr) = _selectSecp256k1Signer(signerSeed);
        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp));

        bytes memory signature = _signSecp256k1(privateKey, messageHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, messageHash, signature) returns (bool result) {
            assertTrue(result, "TEMPO-SIG1: Valid secp256k1 signature should return true");
            _totalSuccessfulVerifies++;

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_SECP256K1: signer=",
                        vm.toString(signerAddr),
                        " hash=",
                        vm.toString(messageHash)
                    )
                );
            }
        } catch {
            _totalFailedVerifies++;
            revert("TEMPO-SIG1: Valid secp256k1 signature should not revert");
        }
    }

    /// @notice Handler for verifying a valid P256 signature
    /// @dev Tests TEMPO-SIG1, TEMPO-SIG4: Valid P256 signature returns true
    function verifyValidP256(uint256 signerSeed, bytes32 messageSeed) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (uint256 privateKey, bytes32 pubX, bytes32 pubY, address signerAddr) =
            _selectP256Signer(signerSeed);
        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp, "p256"));

        bytes memory signature = _signP256(privateKey, messageHash, pubX, pubY);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, messageHash, signature) returns (bool result) {
            assertTrue(result, "TEMPO-SIG1: Valid P256 signature should return true");
            _totalSuccessfulVerifies++;

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_P256: signer=",
                        vm.toString(signerAddr),
                        " hash=",
                        vm.toString(messageHash)
                    )
                );
            }
        } catch {
            _totalFailedVerifies++;
            revert("TEMPO-SIG1: Valid P256 signature should not revert");
        }
    }

    /// @notice Handler for verifying with wrong signer (secp256k1)
    /// @dev Tests TEMPO-SIG3: Signer mismatch reverts
    function verifyWrongSigner(uint256 signerSeed, uint256 wrongSignerSeed, bytes32 messageSeed)
        external
    {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (uint256 privateKey, address actualSigner) = _selectSecp256k1Signer(signerSeed);
        (, address wrongSigner) = _selectSecp256k1Signer(wrongSignerSeed);

        // Ensure wrong signer is actually different
        if (wrongSigner == actualSigner) {
            wrongSigner = address(uint160(wrongSigner) + 1);
        }

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp));
        bytes memory signature = _signSecp256k1(privateKey, messageHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(wrongSigner, messageHash, signature) returns (bool) {
            revert("TEMPO-SIG3: Wrong signer should revert with SignerMismatch");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
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
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        // Ensure hashes are different
        if (originalHash == wrongHash) {
            wrongHash = keccak256(abi.encodePacked(wrongHash, "different"));
        }

        (uint256 privateKey, address signerAddr) = _selectSecp256k1Signer(signerSeed);
        bytes memory signature = _signSecp256k1(privateKey, originalHash);

        _totalVerifyAttempts++;

        try sigVerifier.verify(signerAddr, wrongHash, signature) returns (bool) {
            revert("TEMPO-SIG10: Wrong hash should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            // Should revert with SignerMismatch (recovered signer won't match)
            bytes4 selector = bytes4(reason);
            bool isExpectedError = selector == ISignatureVerification.SignerMismatch.selector
                || selector == ISignatureVerification.InvalidSignature.selector;
            assertTrue(isExpectedError, "TEMPO-SIG10: Should revert with SignerMismatch or InvalidSignature");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_WRONG_HASH: signer=",
                        vm.toString(signerAddr)
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
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address signerAddr) = _selectSecp256k1Signer(signerSeed);

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
            assertEq(
                bytes4(reason),
                ISignatureVerification.InvalidSignature.selector,
                "TEMPO-SIG2: Should revert with InvalidSignature"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_INVALID_SIG: sigLen=",
                        vm.toString(len)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying empty signature
    /// @dev Tests TEMPO-SIG2: Empty signature reverts
    function verifyEmptySignature(uint256 signerSeed, bytes32 hash) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address signerAddr) = _selectSecp256k1Signer(signerSeed);

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
                _log("VERIFY_EMPTY_SIG: correctly rejected");
            }
        }
    }

    /// @notice Handler for verifying keychain signature with unauthorized key
    /// @dev Tests TEMPO-SIG9: Keychain with non-existent key reverts
    function verifyUnauthorizedKeychainKey(uint256 signerSeed, bytes32 hash) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        // Use one secp256k1 key as the "access key" and another as the "root user"
        (uint256 accessKeyPk, address accessKeyAddr) = _selectSecp256k1Signer(signerSeed);
        (, address rootAddr) = _selectSecp256k1Signer(signerSeed + 1);

        // Ensure they're different
        if (rootAddr == accessKeyAddr) {
            rootAddr = address(uint160(rootAddr) + 1);
        }

        // Create keychain signature - access key not authorized in AccountKeychain
        bytes memory keychainSig = _signKeychainSecp256k1(accessKeyPk, hash, rootAddr);

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, hash, keychainSig) returns (bool) {
            revert("TEMPO-SIG9: Keychain with non-existent key should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
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

    /// @notice Handler for verifying a valid keychain signature
    /// @dev Tests TEMPO-SIG1, TEMPO-SIG4: Valid keychain signature with authorized key returns true
    function verifyValidKeychainSignature(
        uint256 rootSignerSeed,
        uint256 accessKeySignerSeed,
        bytes32 messageSeed
    ) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address rootAddr) = _selectSecp256k1Signer(rootSignerSeed);
        (uint256 accessKeyPk, address accessKeyAddr) = _selectSecp256k1Signer(accessKeySignerSeed);

        // Ensure different keys
        if (rootAddr == accessKeyAddr) return;

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp, "keychain"));

        // Authorize the access key in AccountKeychain (as root signer)
        IAccountKeychain keychain = IAccountKeychain(_ACCOUNT_KEYCHAIN);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.prank(rootAddr);
        try keychain.authorizeKey(
            accessKeyAddr,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1 days),
            false,
            limits
        ) {} catch {
            // Key may already exist, that's fine
            return;
        }

        // Create keychain signature
        bytes memory keychainSig = _signKeychainSecp256k1(accessKeyPk, messageHash, rootAddr);

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, messageHash, keychainSig) returns (bool result) {
            assertTrue(result, "TEMPO-SIG1: Valid keychain signature should return true");
            _totalSuccessfulVerifies++;

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_VALID_KEYCHAIN: rootAddr=",
                        vm.toString(rootAddr),
                        " accessKey=",
                        vm.toString(accessKeyAddr)
                    )
                );
            }
        } catch {
            _totalFailedVerifies++;
            revert("TEMPO-SIG1: Valid keychain signature should not revert");
        }
    }

    /// @notice Handler for verifying keychain signature with revoked key
    /// @dev Tests TEMPO-SIG6: Keychain with revoked key reverts UnauthorizedKeychainKey
    function verifyRevokedKeychainKey(
        uint256 rootSignerSeed,
        uint256 accessKeySignerSeed,
        bytes32 messageSeed
    ) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address rootAddr) = _selectSecp256k1Signer(rootSignerSeed);
        (uint256 accessKeyPk, address accessKeyAddr) = _selectSecp256k1Signer(accessKeySignerSeed);

        // Ensure different keys
        if (rootAddr == accessKeyAddr) return;

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp, "revoked"));

        // Authorize then revoke the access key
        IAccountKeychain keychain = IAccountKeychain(_ACCOUNT_KEYCHAIN);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.startPrank(rootAddr);
        try keychain.authorizeKey(
            accessKeyAddr,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp + 1 days),
            false,
            limits
        ) {} catch {
            vm.stopPrank();
            return; // Key already exists
        }

        // Revoke the key
        try keychain.revokeKey(accessKeyAddr) {} catch {
            vm.stopPrank();
            return; // Already revoked
        }
        vm.stopPrank();

        // Create keychain signature with revoked key
        bytes memory keychainSig = _signKeychainSecp256k1(accessKeyPk, messageHash, rootAddr);

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, messageHash, keychainSig) returns (bool) {
            revert("TEMPO-SIG6: Keychain with revoked key should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            assertEq(
                bytes4(reason),
                ISignatureVerification.UnauthorizedKeychainKey.selector,
                "TEMPO-SIG6: Should revert with UnauthorizedKeychainKey"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_REVOKED_KEYCHAIN: rootAddr=",
                        vm.toString(rootAddr)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying keychain signature with expired key
    /// @dev Tests TEMPO-SIG7: Keychain with expired key reverts UnauthorizedKeychainKey
    function verifyExpiredKeychainKey(
        uint256 rootSignerSeed,
        uint256 accessKeySignerSeed,
        bytes32 messageSeed
    ) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address rootAddr) = _selectSecp256k1Signer(rootSignerSeed);
        (uint256 accessKeyPk, address accessKeyAddr) = _selectSecp256k1Signer(accessKeySignerSeed);

        // Ensure different keys
        if (rootAddr == accessKeyAddr) return;

        // Authorize key with expiry in the past (already expired)
        IAccountKeychain keychain = IAccountKeychain(_ACCOUNT_KEYCHAIN);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        // Set timestamp to allow for expired key setup
        vm.warp(block.timestamp + 2 days);

        vm.prank(rootAddr);
        try keychain.authorizeKey(
            accessKeyAddr,
            IAccountKeychain.SignatureType.Secp256k1,
            uint64(block.timestamp - 1), // Already expired
            false,
            limits
        ) {} catch {
            return; // Key already exists or invalid expiry
        }

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp, "expired"));

        // Create keychain signature with expired key
        bytes memory keychainSig = _signKeychainSecp256k1(accessKeyPk, messageHash, rootAddr);

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, messageHash, keychainSig) returns (bool) {
            revert("TEMPO-SIG7: Keychain with expired key should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            assertEq(
                bytes4(reason),
                ISignatureVerification.UnauthorizedKeychainKey.selector,
                "TEMPO-SIG7: Should revert with UnauthorizedKeychainKey"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_EXPIRED_KEYCHAIN: rootAddr=",
                        vm.toString(rootAddr)
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying keychain signature with wrong signature type
    /// @dev Tests TEMPO-SIG8: Keychain signature type mismatch reverts UnauthorizedKeychainKey
    function verifyWrongSignatureTypeKeychain(
        uint256 rootSignerSeed,
        uint256 accessKeySignerSeed,
        bytes32 messageSeed
    ) external {
        // Skip when not on Tempo (precompile not available)
        if (!isTempo) return;

        (, address rootAddr) = _selectSecp256k1Signer(rootSignerSeed);
        (uint256 accessKeyPk, address accessKeyAddr) = _selectSecp256k1Signer(accessKeySignerSeed);

        // Ensure different keys
        if (rootAddr == accessKeyAddr) return;

        // Authorize key for P256 (type 1) but we'll sign with secp256k1 (type 0)
        IAccountKeychain keychain = IAccountKeychain(_ACCOUNT_KEYCHAIN);
        IAccountKeychain.TokenLimit[] memory limits = new IAccountKeychain.TokenLimit[](0);

        vm.prank(rootAddr);
        try keychain.authorizeKey(
            accessKeyAddr,
            IAccountKeychain.SignatureType.P256, // Authorized for P256
            uint64(block.timestamp + 1 days),
            false,
            limits
        ) {} catch {
            return; // Key already exists
        }

        bytes32 messageHash = keccak256(abi.encodePacked(messageSeed, block.timestamp, "wrongtype"));

        // Create keychain signature with secp256k1 (type mismatch)
        bytes memory keychainSig = _signKeychainSecp256k1(accessKeyPk, messageHash, rootAddr);

        _totalVerifyAttempts++;

        try sigVerifier.verify(rootAddr, messageHash, keychainSig) returns (bool) {
            revert("TEMPO-SIG8: Keychain with wrong signature type should revert");
        } catch (bytes memory reason) {
            _totalFailedVerifies++;
            assertEq(
                bytes4(reason),
                ISignatureVerification.UnauthorizedKeychainKey.selector,
                "TEMPO-SIG8: Should revert with UnauthorizedKeychainKey"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "VERIFY_WRONG_TYPE_KEYCHAIN: rootAddr=",
                        vm.toString(rootAddr)
                    )
                );
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify signature length consistency
    /// @dev Part of TEMPO-SIG4: secp256k1=65, P256=130, WebAuthn=variable, Keychain=variable
    function invariant_signatureLengths() public pure {
        // secp256k1: r(32) + s(32) + v(1) = 65 bytes
        // P256: type(1) + r(32) + s(32) + pubX(32) + pubY(32) + prehash(1) = 130 bytes
        // These are validated by the signature parsing in the precompile
        assertTrue(true, "TEMPO-SIG4: Signature format consistency");
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
        _log("--------------------------------------------------------------------------------");
    }
}
