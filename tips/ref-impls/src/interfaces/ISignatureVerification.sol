// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/// @title ISignatureVerification
/// @notice Interface for TIP-1020 Signature Verification Precompile
/// @dev Enables contracts to verify Tempo signature types (secp256k1, P256, WebAuthn, Keychain)
interface ISignatureVerification {
    /// @notice Verifies a Tempo signature
    /// @param signer The expected signer address
    /// @param hash The message hash that was signed
    /// @param signature The encoded signature (secp256k1, P256, WebAuthn, or Keychain)
    /// @return True if valid, reverts otherwise
    function verify(address signer, bytes32 hash, bytes calldata signature) external view returns (bool);

    /// @notice The signature is invalid or could not be parsed
    error InvalidSignature();

    /// @notice The recovered signer does not match the expected signer
    error SignerMismatch(address expected, address recovered);

    /// @notice The keychain access key is not authorized, expired, or revoked
    error UnauthorizedKeychainKey();
}
