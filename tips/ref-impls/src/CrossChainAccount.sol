// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.28 <0.9.0;

import { ECDSA } from "solady/utils/ECDSA.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { P256 } from "solady/utils/P256.sol";
import { WebAuthn } from "solady/utils/WebAuthn.sol";

/// @title CrossChainAccount
/// @notice A passkey-authenticated smart wallet with cross-chain deterministic addresses.
/// @dev Deployed via CREATE2 by CrossChainAccountFactory. No constructor args to ensure
///      identical initCode (and thus identical address) across all chains.
///
/// Key design decisions:
/// 1. No constructor args - keeps creationCode identical across chains
/// 2. One-time initialization guarded by initialized flag
/// 3. Supports multiple key types: P-256, WebAuthn (passkeys), and secp256k1
/// 4. Pure Solidity signature verification via Solady - NO chain-specific precompiles
///    This ensures the contract works on ANY EVM chain, not just Tempo.
/// 5. Supports adding/removing keys for rotation without changing address
/// 6. ERC-1271 compliant via isValidSignature
///
/// ## Cross-Chain Compatibility
/// This contract deliberately avoids Tempo-specific precompiles (like AccountKeychain)
/// to ensure identical behavior across all EVM chains. Signature verification uses
/// Solady's battle-tested P256 and WebAuthn libraries which work on any EVM.
contract CrossChainAccount is EIP712 {

    // ============ Constants ============

    /// @notice ERC-1271 magic value for valid signatures
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @notice Typehash for execute operations
    bytes32 internal constant EXECUTE_TYPEHASH =
        keccak256("Execute(address target,uint256 value,bytes data,uint256 nonce)");

    // ============ Enums ============

    /// @notice Supported key types for signature verification
    /// @dev Inspired by ithacaxyz/account's KeyType enum
    enum KeyType {
        Secp256k1, // Standard Ethereum EOA signatures
        P256, // Raw P-256 ECDSA signatures
        WebAuthnP256 // WebAuthn/passkey signatures with P-256
    }

    // ============ Structs ============

    /// @notice Key information for authorized signers
    struct Key {
        KeyType keyType;
        uint40 expiry; // 0 = never expires
        bytes publicKey; // Encoded public key (format depends on keyType)
    }

    // ============ Storage ============

    /// @notice Primary owner passkey coordinates
    bytes32 public ownerX;
    bytes32 public ownerY;

    /// @notice Mapping from key hash to key info
    mapping(bytes32 => Key) public keys;

    /// @notice Nonce for replay protection
    uint256 public nonce;

    /// @notice Initialization flag
    bool private _initialized;

    // ============ Events ============

    event Initialized(bytes32 indexed ownerX, bytes32 indexed ownerY);
    event KeyAdded(bytes32 indexed keyHash, KeyType keyType);
    event KeyRemoved(bytes32 indexed keyHash);
    event Executed(address indexed target, uint256 value, bytes data);

    // ============ Errors ============

    error AlreadyInitialized();
    error NotAuthorized();
    error InvalidSignature();
    error ExecutionFailed();
    error InvalidKey();
    error KeyAlreadyExists();
    error CannotRemovePrimaryKey();
    error KeyExpired();

    // ============ Constructor ============

    /// @dev No constructor args to ensure identical creationCode across chains
    constructor() { }

    // ============ EIP712 ============

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("CrossChainAccount", "1");
    }

    // ============ Initialization ============

    /// @notice Initialize the account with owner passkey
    /// @dev Called atomically by factory after CREATE2 deployment
    /// @param _ownerX The x-coordinate of the owner's passkey public key
    /// @param _ownerY The y-coordinate of the owner's passkey public key
    function initialize(bytes32 _ownerX, bytes32 _ownerY) external {
        if (_initialized) {
            revert AlreadyInitialized();
        }
        if (_ownerX == bytes32(0) || _ownerY == bytes32(0)) {
            revert InvalidKey();
        }

        _initialized = true;
        ownerX = _ownerX;
        ownerY = _ownerY;

        // Register owner key as WebAuthnP256 (default for passkeys)
        bytes32 keyHash = keccak256(abi.encodePacked(_ownerX, _ownerY));
        keys[keyHash] = Key({
            keyType: KeyType.WebAuthnP256,
            expiry: 0, // Never expires
            publicKey: abi.encode(_ownerX, _ownerY)
        });

        emit Initialized(_ownerX, _ownerY);
        emit KeyAdded(keyHash, KeyType.WebAuthnP256);
    }

    // ============ ERC-1271 ============

    /// @notice Validates a signature per ERC-1271
    /// @param digest The hash that was signed
    /// @param signature The signature to validate (format: keyHash ++ innerSignature)
    /// @return magicValue ERC1271_MAGIC_VALUE if valid, 0xffffffff otherwise
    function isValidSignature(
        bytes32 digest,
        bytes calldata signature
    )
        external
        view
        returns (bytes4)
    {
        (bool isValid,) = _validateSignature(digest, signature);
        return isValid ? ERC1271_MAGIC_VALUE : bytes4(0xffffffff);
    }

    // ============ Execution Functions ============

    /// @notice Execute a call from this account with signature verification
    /// @param target The target address
    /// @param value The ETH value to send
    /// @param data The calldata
    /// @param signature The signature authorizing this execution
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    )
        external
        returns (bytes memory)
    {
        // Build digest for this execution
        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_TYPEHASH, target, value, keccak256(data), nonce));
        bytes32 digest = _hashTypedData(structHash);

        // Validate signature
        (bool isValid,) = _validateSignature(digest, signature);
        if (!isValid) {
            revert InvalidSignature();
        }

        // Increment nonce
        nonce++;

        // Execute call
        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            revert ExecutionFailed();
        }
        emit Executed(target, value, data);
        return result;
    }

    /// @notice Execute a call from this account (self-call only)
    /// @dev For internal calls after signature validation
    function executeTrusted(
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        returns (bytes memory)
    {
        if (msg.sender != address(this)) {
            revert NotAuthorized();
        }

        (bool success, bytes memory result) = target.call{ value: value }(data);
        if (!success) {
            revert ExecutionFailed();
        }
        emit Executed(target, value, data);
        return result;
    }

    // ============ Key Management ============

    /// @notice Add an additional authorized key
    /// @dev Can only be called via execute with valid signature
    /// @param keyHash The hash identifying this key
    /// @param keyType The type of key being added
    /// @param expiry Expiration timestamp (0 = never)
    /// @param publicKey The encoded public key
    function addKey(
        bytes32 keyHash,
        KeyType keyType,
        uint40 expiry,
        bytes calldata publicKey
    )
        external
    {
        if (msg.sender != address(this)) {
            revert NotAuthorized();
        }
        if (keyHash == bytes32(0)) {
            revert InvalidKey();
        }
        if (keys[keyHash].publicKey.length > 0) {
            revert KeyAlreadyExists();
        }

        keys[keyHash] = Key({ keyType: keyType, expiry: expiry, publicKey: publicKey });

        emit KeyAdded(keyHash, keyType);
    }

    /// @notice Remove an authorized key
    /// @dev Cannot remove the primary owner key
    /// @param keyHash The hash of the key to remove
    function removeKey(bytes32 keyHash) external {
        if (msg.sender != address(this)) {
            revert NotAuthorized();
        }

        bytes32 ownerKeyHash = keccak256(abi.encodePacked(ownerX, ownerY));
        if (keyHash == ownerKeyHash) {
            revert CannotRemovePrimaryKey();
        }

        delete keys[keyHash];
        emit KeyRemoved(keyHash);
    }

    // ============ View Functions ============

    /// @notice Check if a key is authorized
    function isAuthorizedKey(bytes32 keyHash) external view returns (bool) {
        Key storage key = keys[keyHash];
        if (key.publicKey.length == 0) return false;
        if (key.expiry != 0 && block.timestamp > key.expiry) return false;
        return true;
    }

    /// @notice Check if the account is initialized
    function initialized() external view returns (bool) {
        return _initialized;
    }

    /// @notice Get the owner key hash
    function ownerKeyHash() external view returns (bytes32) {
        return keccak256(abi.encodePacked(ownerX, ownerY));
    }

    // ============ Receive Functions ============

    receive() external payable { }
    fallback() external payable { }

    // ============ Internal Functions ============

    /// @dev Validates a signature and returns the key hash if valid
    /// @param digest The message digest to verify
    /// @param signature Format: keyHash (32 bytes) ++ innerSignature (variable)
    function _validateSignature(
        bytes32 digest,
        bytes calldata signature
    )
        internal
        view
        returns (bool isValid, bytes32 keyHash)
    {
        if (signature.length < 32) return (false, bytes32(0));

        // Extract key hash from signature prefix
        keyHash = bytes32(signature[:32]);
        bytes calldata innerSig = signature[32:];

        // Get key info
        Key storage key = keys[keyHash];
        if (key.publicKey.length == 0) return (false, keyHash);

        // Check expiry
        if (key.expiry != 0 && block.timestamp > key.expiry) {
            return (false, keyHash);
        }

        // Validate based on key type
        if (key.keyType == KeyType.Secp256k1) {
            isValid = _validateSecp256k1(digest, innerSig, key.publicKey);
        } else if (key.keyType == KeyType.P256) {
            isValid = _validateP256(digest, innerSig, key.publicKey);
        } else if (key.keyType == KeyType.WebAuthnP256) {
            isValid = _validateWebAuthn(digest, innerSig, key.publicKey);
        }
    }

    /// @dev Validates a secp256k1 signature
    function _validateSecp256k1(
        bytes32 digest,
        bytes calldata signature,
        bytes storage publicKey
    )
        internal
        view
        returns (bool)
    {
        address recovered = ECDSA.recoverCalldata(digest, signature);
        address expected = abi.decode(publicKey, (address));
        return recovered == expected && recovered != address(0);
    }

    /// @dev Validates a raw P-256 signature
    function _validateP256(
        bytes32 digest,
        bytes calldata signature,
        bytes storage publicKey
    )
        internal
        view
        returns (bool)
    {
        if (signature.length < 64) return false;

        (bytes32 x, bytes32 y) = abi.decode(publicKey, (bytes32, bytes32));
        bytes32 r = bytes32(signature[:32]);
        bytes32 s = bytes32(signature[32:64]);

        return P256.verifySignature(digest, r, s, x, y);
    }

    /// @dev Validates a WebAuthn signature (passkey)
    function _validateWebAuthn(
        bytes32 digest,
        bytes calldata signature,
        bytes storage publicKey
    )
        internal
        view
        returns (bool)
    {
        (bytes32 x, bytes32 y) = abi.decode(publicKey, (bytes32, bytes32));

        // Decode WebAuthn auth data from signature
        WebAuthn.WebAuthnAuth memory auth = abi.decode(signature, (WebAuthn.WebAuthnAuth));

        // Verify using Solady's WebAuthn library
        // Challenge is the digest we're verifying
        return WebAuthn.verify(
            abi.encode(digest), // challenge
            false, // requireUserVerification
            auth,
            x,
            y
        );
    }

}
