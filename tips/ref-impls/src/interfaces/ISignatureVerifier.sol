// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title ISignatureVerifier
/// @notice Interface for the TIP-1020 Signature Verification Precompile
/// @dev Deployed at 0x5165300000000000000000000000000000000000
interface ISignatureVerifier {

    error InvalidFormat();
    error InvalidSignature();

    /// @notice Recovers the signer of a Tempo signature (secp256k1, P256, WebAuthn).
    /// @param hash The message hash that was signed
    /// @param signature The encoded signature (see Tempo Transaction spec for formats)
    /// @return signer Address of the signer if valid, reverts otherwise
    function recover(bytes32 hash, bytes calldata signature) external view returns (address signer);

    /// @notice Verifies a signer against a Tempo signature (secp256k1, P256, WebAuthn).
    /// @param signer The input address verified against the recovered signer
    /// @param hash The message hash that was signed
    /// @param signature The encoded signature (see Tempo Transaction spec for formats)
    /// @return True if the input address signed, false otherwise. Reverts on invalid signatures.
    function verify(
        address signer,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);

}
