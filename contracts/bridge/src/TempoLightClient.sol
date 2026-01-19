// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "solady/auth/Ownable.sol";
import "solady/utils/ECDSA.sol";
import "./libraries/BLS12381.sol";

/// @title TempoLightClient
/// @notice Maintains finalized Tempo headers and validator BLS public key
/// @dev Supports both BLS12-381 (production) and ECDSA (testing) signature verification
///
/// ## Finality Semantics
///
/// A header is considered "finalized" on Ethereum once it has been successfully submitted
/// via `submitHeader()` with valid cryptographic proof:
///
/// - **BLS Mode (Production)**: The aggregated BLS signature from threshold validators
///   proves that ≥2/3 of the Tempo validator set has attested to this header. This mirrors
///   Tempo's on-chain consensus finality - if validators have signed, the block is final
///   on Tempo and cannot be reverted without ≥1/3 Byzantine stake.
///
/// - **ECDSA Mode (Testing)**: Requires threshold (2/3) of registered validator ECDSA
///   signatures. Used for testing environments where BLS precompiles are unavailable.
///
/// Once a header hash is stored in `headerHashes[height]`, it is immutable - no mechanism
/// exists to overwrite or remove it. The `finalizedAt` timestamp records when finality
/// was established on Ethereum for audit trail purposes.
///
/// @custom:security-contact security@tempo.xyz
contract TempoLightClient is Ownable {
    /// @notice Domain separator for header signatures
    bytes32 public constant HEADER_DOMAIN = keccak256("TEMPO_HEADER_V1");

    /// @notice Domain separator for key rotation
    bytes32 public constant ROTATION_DOMAIN = keccak256("TEMPO_KEY_ROTATION_V1");

    /// @notice Tempo chain ID
    uint64 public immutable tempoChainId;

    /// @notice Current validator set epoch
    uint64 public currentEpoch;

    /// @notice Aggregated BLS public key (G2 point, 256 bytes uncompressed)
    /// @dev For BLS mode, this stores the aggregated validator public key
    bytes public blsPublicKey;

    /// @notice Latest finalized Tempo block height
    uint64 public latestFinalizedHeight;

    /// @notice Mapping of height to header hash
    mapping(uint64 => bytes32) public headerHashes;

    /// @notice Mapping of height to receipts root
    mapping(uint64 => bytes32) public receiptsRoots;

    /// @notice Timestamp when each header was finalized on Ethereum (for audit trail)
    /// @dev Records block.timestamp when submitHeader() succeeds, enabling off-chain
    ///      systems to verify when finality was established and detect any delays
    mapping(uint64 => uint256) public finalizedAt;

    /// @notice Whether to use ECDSA mode (for testing) instead of BLS
    bool public useEcdsaMode;

    /// @notice Threshold for ECDSA signatures (2/3 of validators)
    uint256 public threshold;

    /// @notice Active validators for ECDSA mode
    mapping(address => bool) public isValidator;
    address[] public validators;

    /// @notice Legacy currentPublicKey getter for backwards compatibility
    bytes public currentPublicKey;

    /// @notice Pending owner for 2-step ownership transfer
    address public pendingOwner;

    event HeaderSubmitted(uint64 indexed height, bytes32 headerHash, bytes32 receiptsRoot);
    event KeyRotated(uint64 indexed newEpoch, bytes newPublicKey);
    event BLSPublicKeyUpdated(uint64 indexed epoch, bytes blsKey);
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);
    event SignatureModeChanged(bool useEcdsa);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    error InvalidSignatureCount();
    error InvalidSignature();
    error HeightNotMonotonic();
    error InvalidParentHash();
    error ThresholdNotMet();
    error ValidatorExists();
    error ValidatorNotFound();
    error BLSVerificationFailed();
    error InvalidBLSPublicKeyLength();
    error InvalidBLSSignatureLength();
    error BLSPrecompilesNotAvailable();

    constructor(uint64 _tempoChainId, uint64 _initialEpoch) {
        _initializeOwner(msg.sender);
        tempoChainId = _tempoChainId;
        currentEpoch = _initialEpoch;
        useEcdsaMode = true;
        threshold = 1;
    }

    /// @notice Transfer ownership in 2 steps (start)
    function transferOwnership(address newOwner) public payable override onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /// @notice Accept ownership (complete 2-step transfer)
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        _setOwner(msg.sender);
        pendingOwner = address(0);
    }

    /// @notice Set the signature verification mode
    /// @param _useEcdsaMode True for ECDSA mode (testing), false for BLS mode (production)
    function setSignatureMode(bool _useEcdsaMode) external onlyOwner {
        if (!_useEcdsaMode && !BLS12381.precompilesAvailable()) {
            revert BLSPrecompilesNotAvailable();
        }
        useEcdsaMode = _useEcdsaMode;
        emit SignatureModeChanged(_useEcdsaMode);
    }

    /// @notice Set the aggregated BLS public key
    /// @param _blsPublicKey The aggregated BLS public key (G2 point, 256 bytes uncompressed)
    function setBLSPublicKey(bytes calldata _blsPublicKey) external onlyOwner {
        if (_blsPublicKey.length != BLS12381.G2_POINT_SIZE) {
            revert InvalidBLSPublicKeyLength();
        }
        blsPublicKey = _blsPublicKey;
        emit BLSPublicKeyUpdated(currentEpoch, _blsPublicKey);
    }

    /// @notice Add a validator (owner only, for ECDSA mode)
    function addValidator(address validator) external onlyOwner {
        if (isValidator[validator]) revert ValidatorExists();
        isValidator[validator] = true;
        validators.push(validator);
        _updateThreshold();
        emit ValidatorAdded(validator);
    }

    /// @notice Remove a validator (owner only, for ECDSA mode)
    function removeValidator(address validator) external onlyOwner {
        if (!isValidator[validator]) revert ValidatorNotFound();
        isValidator[validator] = false;

        for (uint256 i = 0; i < validators.length; i++) {
            if (validators[i] == validator) {
                validators[i] = validators[validators.length - 1];
                validators.pop();
                break;
            }
        }
        _updateThreshold();
        emit ValidatorRemoved(validator);
    }

    /// @notice Submit a finalized Tempo header with validator signatures
    /// @dev In BLS mode, the aggregated signature proves that ≥2/3 of Tempo validators
    ///      have attested to this header, establishing consensus finality. Once stored,
    ///      the header cannot be overwritten - finality is permanent on this contract.
    /// @param height Block height (must be contiguous with latestFinalizedHeight)
    /// @param parentHash Parent block hash (must match stored hash at height-1)
    /// @param stateRoot State root
    /// @param receiptsRoot Receipts root (used for cross-chain message verification)
    /// @param epoch Validator set epoch
    /// @param signature For BLS mode: single aggregated signature (128 bytes G1 point)
    ///                  For ECDSA mode: encoded array of individual signatures
    function submitHeader(
        uint64 height,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 receiptsRoot,
        uint64 epoch,
        bytes calldata signature
    ) external {
        require(height == latestFinalizedHeight + 1 || latestFinalizedHeight == 0, "non-contiguous");
        if (height <= latestFinalizedHeight && latestFinalizedHeight > 0) {
            revert HeightNotMonotonic();
        }

        if (latestFinalizedHeight > 0) {
            if (parentHash != headerHashes[latestFinalizedHeight]) {
                revert InvalidParentHash();
            }
        }

        bytes32 headerDigest = keccak256(
            abi.encodePacked(HEADER_DOMAIN, tempoChainId, height, parentHash, stateRoot, receiptsRoot, epoch)
        );

        if (useEcdsaMode) {
            bytes[] memory signatures = abi.decode(signature, (bytes[]));
            _verifyThresholdSignatures(headerDigest, signatures);
        } else {
            _verifyBLSSignature(headerDigest, signature);
        }

        bytes32 headerHash = keccak256(abi.encodePacked(height, parentHash, stateRoot, receiptsRoot, epoch));
        headerHashes[height] = headerHash;
        receiptsRoots[height] = receiptsRoot;
        finalizedAt[height] = block.timestamp;
        latestFinalizedHeight = height;

        emit HeaderSubmitted(height, headerHash, receiptsRoot);
    }

    /// @notice Submit a finalized header with ECDSA signatures array (backwards compatible)
    /// @dev This function maintains the original interface for ECDSA mode
    function submitHeader(
        uint64 height,
        bytes32 parentHash,
        bytes32 stateRoot,
        bytes32 receiptsRoot,
        uint64 epoch,
        bytes[] calldata signatures
    ) external {
        require(height == latestFinalizedHeight + 1 || latestFinalizedHeight == 0, "non-contiguous");
        if (height <= latestFinalizedHeight && latestFinalizedHeight > 0) {
            revert HeightNotMonotonic();
        }

        if (latestFinalizedHeight > 0) {
            if (parentHash != headerHashes[latestFinalizedHeight]) {
                revert InvalidParentHash();
            }
        }

        bytes32 headerDigest = keccak256(
            abi.encodePacked(HEADER_DOMAIN, tempoChainId, height, parentHash, stateRoot, receiptsRoot, epoch)
        );

        if (useEcdsaMode) {
            bytes[] memory sigs = new bytes[](signatures.length);
            for (uint256 i = 0; i < signatures.length; i++) {
                sigs[i] = signatures[i];
            }
            _verifyThresholdSignatures(headerDigest, sigs);
        } else {
            require(signatures.length == 1, "BLS mode expects single aggregated signature");
            _verifyBLSSignature(headerDigest, signatures[0]);
        }

        bytes32 headerHash = keccak256(abi.encodePacked(height, parentHash, stateRoot, receiptsRoot, epoch));
        headerHashes[height] = headerHash;
        receiptsRoots[height] = receiptsRoot;
        finalizedAt[height] = block.timestamp;
        latestFinalizedHeight = height;

        emit HeaderSubmitted(height, headerHash, receiptsRoot);
    }

    /// @notice Submit a key rotation signed by the old validator set
    function submitKeyRotation(uint64 newEpoch, bytes calldata newPublicKey, bytes[] calldata signatures) external {
        require(newEpoch > currentEpoch, "Epoch must increase");

        bytes32 rotationDigest = keccak256(abi.encodePacked(ROTATION_DOMAIN, tempoChainId, newEpoch, newPublicKey));

        if (useEcdsaMode) {
            bytes[] memory sigs = new bytes[](signatures.length);
            for (uint256 i = 0; i < signatures.length; i++) {
                sigs[i] = signatures[i];
            }
            _verifyThresholdSignatures(rotationDigest, sigs);
        } else {
            require(signatures.length == 1, "BLS mode expects single aggregated signature");
            _verifyBLSSignature(rotationDigest, signatures[0]);
        }

        currentEpoch = newEpoch;
        currentPublicKey = newPublicKey;

        if (newPublicKey.length == BLS12381.G2_POINT_SIZE) {
            blsPublicKey = newPublicKey;
            emit BLSPublicKeyUpdated(newEpoch, newPublicKey);
        }

        emit KeyRotated(newEpoch, newPublicKey);
    }

    /// @notice Submit a BLS key rotation with BLS signature
    function submitBLSKeyRotation(
        uint64 newEpoch,
        bytes calldata newBLSPublicKey,
        bytes calldata blsSignature
    ) external {
        require(newEpoch > currentEpoch, "Epoch must increase");
        if (newBLSPublicKey.length != BLS12381.G2_POINT_SIZE) {
            revert InvalidBLSPublicKeyLength();
        }

        bytes32 rotationDigest = keccak256(
            abi.encodePacked(ROTATION_DOMAIN, tempoChainId, newEpoch, newBLSPublicKey)
        );

        _verifyBLSSignature(rotationDigest, blsSignature);

        currentEpoch = newEpoch;
        blsPublicKey = newBLSPublicKey;
        currentPublicKey = newBLSPublicKey;

        emit BLSPublicKeyUpdated(newEpoch, newBLSPublicKey);
        emit KeyRotated(newEpoch, newBLSPublicKey);
    }

    /// @notice Get the receipts root for a height
    function getReceiptsRoot(uint64 height) external view returns (bytes32) {
        return receiptsRoots[height];
    }

    /// @notice Check if a header is finalized
    /// @dev A header is finalized once it has been stored via submitHeader() with valid
    ///      cryptographic proof (BLS aggregated signature or ECDSA threshold signatures).
    ///      In BLS mode, finalization implies ≥2/3 of Tempo validators attested to this
    ///      header, which mirrors Tempo's consensus finality guarantees.
    ///      Use `finalizedAt[height]` to retrieve the Ethereum timestamp when finality
    ///      was established for audit or timing verification purposes.
    /// @param height The Tempo block height to check
    /// @return True if the header has been finalized and stored, false otherwise
    function isHeaderFinalized(uint64 height) external view returns (bool) {
        return headerHashes[height] != bytes32(0);
    }

    /// @notice Get validator count
    function validatorCount() external view returns (uint256) {
        return validators.length;
    }

    /// @notice Check if BLS precompiles are available
    function isBLSAvailable() external view returns (bool) {
        return BLS12381.precompilesAvailable();
    }

    /// @notice Verify a BLS signature against the stored public key
    function _verifyBLSSignature(bytes32 digest, bytes calldata signature) internal view {
        if (signature.length != BLS12381.G1_POINT_SIZE) {
            revert InvalidBLSSignatureLength();
        }
        if (blsPublicKey.length != BLS12381.G2_POINT_SIZE) {
            revert InvalidBLSPublicKeyLength();
        }

        bool valid = BLS12381.verify(
            signature,
            blsPublicKey,
            digest
        );

        if (!valid) {
            revert BLSVerificationFailed();
        }
    }

    function _verifyThresholdSignatures(bytes32 digest, bytes[] memory signatures) internal view {
        if (signatures.length < threshold) revert ThresholdNotMet();

        uint256 validCount = 0;
        address lastSigner = address(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(digest, signatures[i]);

            require(signer > lastSigner, "Signatures not sorted");
            lastSigner = signer;

            if (isValidator[signer]) {
                validCount++;
            }
        }

        if (validCount < threshold) revert ThresholdNotMet();
    }

    function _updateThreshold() internal {
        if (validators.length == 0) {
            threshold = 1;
        } else {
            threshold = (validators.length * 2 + 2) / 3;
        }
    }
}
