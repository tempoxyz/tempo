// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title ISignatureVerifier
/// @notice Interface for the TIP-1020 Signature Verification Precompile
/// @dev Deployed at 0x5165300000000000000000000000000000000000
interface ISignatureVerifier {

    error InvalidFormat();
    error InvalidSignature();

    /// @notice Recovers the signer of a Tempo signature (secp256k1, P256, P384, WebAuthn).
    /// @param hash The message hash that was signed
    /// @param signature The encoded signature (see Tempo Transaction spec for formats)
    /// @return signer Address of the signer if valid, reverts otherwise
    function recover(bytes32 hash, bytes calldata signature) external view returns (address signer);

    /// @notice Verifies a signer against a Tempo signature (secp256k1, P256, P384, WebAuthn).
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

    /// @notice Verifies an ES384 signature over a SHA-384 digest.
    /// @param digest The 48-byte SHA-384 digest that was signed.
    /// @param signature The raw ES384 signature encoded as `r || s`.
    /// @param publicKey The P-384 public key encoded as `x || y` or `0x04 || x || y`.
    /// @return True if the signature is valid for the digest and public key, false otherwise.
    function verifyES384(
        bytes calldata digest,
        bytes calldata signature,
        bytes calldata publicKey
    )
        external
        view
        returns (bool);

    /// @notice Computes the SHA-384 digest of the input data.
    /// @param data The input bytes to hash.
    /// @return digest The 48-byte SHA-384 digest.
    function sha384(bytes calldata data) external view returns (bytes memory digest);

}
