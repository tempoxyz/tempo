// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "solady/tokens/ERC20.sol";
import "solady/utils/SafeTransferLib.sol";
import "solady/auth/Ownable.sol";
import "solady/utils/ReentrancyGuard.sol";
import "solady/utils/ECDSA.sol";

/// @title StablecoinEscrow
/// @notice Escrows stablecoins for bridging to Tempo
/// @dev Uses validator attestations to verify burns. The original binary Merkle proof
///      verification was incompatible with Ethereum's MPT receipt trie structure.
///      Instead of complex on-chain MPT verification, burns are attested by the same
///      threshold validator set that finalizes headers in the light client.
contract StablecoinEscrow is Ownable, ReentrancyGuard {
    /// @notice The Tempo light client for header verification
    address public immutable lightClient;

    /// @notice Tempo chain ID
    uint64 public immutable tempoChainId;

    /// @notice Mapping of supported tokens (for new deposits)
    mapping(address => bool) public supportedTokens;

    /// @notice Mapping of tokens that were ever supported (for unlocking existing burns)
    mapping(address => bool) public everSupportedTokens;

    /// @notice Mapping of deposit nonces per user
    mapping(address => uint64) public depositNonces;

    /// @notice Mapping of spent burn IDs (prevents replay)
    mapping(bytes32 => bool) public spentBurnIds;

    /// @notice Bridge precompile address on Tempo
    address public constant TEMPO_BRIDGE = 0xBBBB000000000000000000000000000000000000;

    /// @notice Burn event signature from Tempo bridge
    bytes32 public constant BURN_EVENT_SIGNATURE =
        keccak256("BurnInitiated(bytes32,uint64,address,address,uint64,uint64,uint64)");

    /// @notice Domain separator for burn attestations
    bytes32 public constant BURN_ATTESTATION_DOMAIN = keccak256("TEMPO_BURN_ATTESTATION_V1");

    /// @notice Pending owner for 2-step ownership transfer
    address public pendingOwner;

    event Deposited(
        bytes32 indexed depositId,
        address indexed token,
        address indexed depositor,
        uint64 amount,
        address tempoRecipient,
        uint64 nonce
    );

    event Unlocked(bytes32 indexed burnId, address indexed token, address indexed recipient, uint64 amount);

    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    error TokenNotSupported();
    error ZeroAmount();
    error InvalidRecipient();
    error BurnAlreadySpent();
    error HeaderNotFinalized();
    error InvalidReceiptProof();
    error InvalidBurnEvent();
    error InvalidProofFormat();
    error AmountTooLarge();
    error ThresholdNotMet();

    constructor(address _lightClient, uint64 _tempoChainId) {
        _initializeOwner(msg.sender);
        lightClient = _lightClient;
        tempoChainId = _tempoChainId;
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

    /// @notice Add a supported token
    function addToken(address token) external onlyOwner {
        supportedTokens[token] = true;
        everSupportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /// @notice Remove a supported token
    function removeToken(address token) external onlyOwner {
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /// @notice Deposit tokens to bridge to Tempo
    /// @param token The ERC20 token to deposit
    /// @param amount Amount in token's native decimals (will be normalized to 6)
    /// @param tempoRecipient Recipient address on Tempo
    function deposit(address token, uint256 amount, address tempoRecipient)
        external
        nonReentrant
        returns (bytes32 depositId)
    {
        if (!supportedTokens[token]) revert TokenNotSupported();
        if (amount == 0) revert ZeroAmount();
        if (tempoRecipient == address(0)) revert InvalidRecipient();

        uint64 nonce = depositNonces[msg.sender]++;

        uint64 normalizedAmount = _normalizeAmount(token, amount);
        
        if (normalizedAmount == 0) revert ZeroAmount();

        SafeTransferLib.safeTransferFrom(token, msg.sender, address(this), amount);

        depositId = keccak256(
            abi.encodePacked(block.chainid, address(this), token, tempoRecipient, normalizedAmount, msg.sender, nonce)
        );

        emit Deposited(depositId, token, msg.sender, normalizedAmount, tempoRecipient, nonce);
    }

    /// @notice Unlock tokens based on validator-attested burn
    /// @dev Validators attest to burns by signing a digest that includes the burn details.
    ///      This replaces the previous binary Merkle proof which was incompatible with
    ///      Ethereum's MPT receipt trie structure (F-03 audit finding).
    /// @param burnId The unique burn ID from the Tempo burn event
    /// @param tempoHeight The Tempo block height containing the burn
    /// @param originToken The token address on this chain
    /// @param recipient The recipient address on this chain
    /// @param amount The amount to unlock (in 6-decimal normalized form)
    /// @param signatures Array of validator signatures attesting to the burn
    function unlock(
        bytes32 burnId,
        uint64 tempoHeight,
        address originToken,
        address recipient,
        uint64 amount,
        bytes[] calldata signatures
    ) external nonReentrant {
        ITempoLightClient lc = ITempoLightClient(lightClient);
        if (!lc.isHeaderFinalized(tempoHeight)) revert HeaderNotFinalized();

        if (spentBurnIds[burnId]) revert BurnAlreadySpent();

        if (!everSupportedTokens[originToken]) revert TokenNotSupported();

        bytes32 attestationDigest = _computeAttestationDigest(
            burnId, tempoHeight, originToken, recipient, amount
        );

        _verifyValidatorSignatures(lc, attestationDigest, signatures);

        spentBurnIds[burnId] = true;

        uint256 denormalizedAmount = _denormalizeAmount(originToken, amount);
        SafeTransferLib.safeTransfer(originToken, recipient, denormalizedAmount);

        emit Unlocked(burnId, originToken, recipient, amount);
    }

    /// @notice Unlock tokens with ABI-encoded attestation (called by bridge relayer)
    /// @dev Proof format: ABI-encoded (bytes32 burnId, uint64 tempoHeight, address originToken, 
    ///      address recipient, uint64 amount, bytes[] signatures)
    /// @param burnId The burn ID (used only for duplicate check before decoding)
    /// @param recipient Expected recipient (verified against decoded burn event)
    /// @param amount Expected amount (verified against decoded burn event)  
    /// @param proof ABI-encoded attestation data
    function unlockWithProof(bytes32 burnId, address recipient, uint256 amount, bytes calldata proof)
        external
        nonReentrant
    {
        if (spentBurnIds[burnId]) revert BurnAlreadySpent();

        _processAttestedUnlock(burnId, recipient, uint64(amount), proof);
    }

    /// @dev Internal helper to process attested unlock (reduces stack depth)
    function _processAttestedUnlock(
        bytes32 burnId,
        address recipient,
        uint64 expectedAmount,
        bytes calldata proof
    ) internal {
        (
            bytes32 decodedBurnId,
            uint64 tempoHeight,
            address originToken,
            address decodedRecipient,
            uint64 decodedAmount,
            bytes[] memory signatures
        ) = abi.decode(proof, (bytes32, uint64, address, address, uint64, bytes[]));

        if (decodedBurnId != burnId) revert InvalidBurnEvent();
        if (decodedRecipient != recipient) revert InvalidBurnEvent();
        if (decodedAmount != expectedAmount) revert InvalidBurnEvent();

        ITempoLightClient lc = ITempoLightClient(lightClient);
        if (!lc.isHeaderFinalized(tempoHeight)) revert HeaderNotFinalized();

        if (!everSupportedTokens[originToken]) revert TokenNotSupported();

        bytes32 attestationDigest = _computeAttestationDigest(
            burnId, tempoHeight, originToken, recipient, decodedAmount
        );

        _verifyValidatorSignatures(lc, attestationDigest, signatures);

        spentBurnIds[burnId] = true;

        uint256 denormalizedAmount = _denormalizeAmount(originToken, decodedAmount);
        SafeTransferLib.safeTransfer(originToken, recipient, denormalizedAmount);

        emit Unlocked(burnId, originToken, recipient, decodedAmount);
    }

    /// @dev Compute attestation digest for signature verification
    function _computeAttestationDigest(
        bytes32 burnId,
        uint64 tempoHeight,
        address originToken,
        address recipient,
        uint64 amount
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                BURN_ATTESTATION_DOMAIN,
                tempoChainId,
                burnId,
                tempoHeight,
                uint64(block.chainid),
                originToken,
                recipient,
                amount
            )
        );
    }

    /// @notice Check if a burn has been unlocked (alias for isBurnSpent)
    function isUnlocked(bytes32 burnId) external view returns (bool) {
        return spentBurnIds[burnId];
    }

    /// @notice Check if a burn ID has been spent
    function isBurnSpent(bytes32 burnId) external view returns (bool) {
        return spentBurnIds[burnId];
    }

    function _normalizeAmount(address token, uint256 amount) internal view returns (uint64) {
        uint8 decimals = _getDecimals(token);
        uint256 normalized;
        if (decimals > 6) {
            normalized = amount / (10 ** (decimals - 6));
        } else if (decimals < 6) {
            normalized = amount * (10 ** (6 - decimals));
        } else {
            normalized = amount;
        }
        if (normalized > type(uint64).max) revert AmountTooLarge();
        return uint64(normalized);
    }

    function _denormalizeAmount(address token, uint64 amount) internal view returns (uint256) {
        uint8 decimals = _getDecimals(token);
        if (decimals > 6) {
            return uint256(amount) * (10 ** (decimals - 6));
        } else if (decimals < 6) {
            return uint256(amount) / (10 ** (6 - decimals));
        }
        return uint256(amount);
    }

    function _getDecimals(address token) internal view returns (uint8) {
        try IERC20Metadata(token).decimals() returns (uint8 decimals) {
            return decimals;
        } catch {
            return 18;
        }
    }

    /// @dev Verify threshold validator signatures for burn attestation
    /// @param lc The light client to get validator info from
    /// @param digest The attestation digest to verify
    /// @param signatures Array of ECDSA signatures from validators
    function _verifyValidatorSignatures(
        ITempoLightClient lc,
        bytes32 digest,
        bytes[] memory signatures
    ) internal view {
        uint256 requiredThreshold = lc.threshold();
        if (signatures.length < requiredThreshold) revert ThresholdNotMet();

        uint256 validCount = 0;
        address lastSigner = address(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            address signer = ECDSA.recover(digest, signatures[i]);

            require(signer > lastSigner, "Signatures not sorted");
            lastSigner = signer;

            if (lc.isValidator(signer)) {
                validCount++;
            }
        }

        if (validCount < requiredThreshold) revert ThresholdNotMet();
    }
}

/// @notice Interface for the Tempo Light Client
/// @dev Extended to include validator set access for burn attestation verification
interface ITempoLightClient {
    function isHeaderFinalized(uint64 height) external view returns (bool);
    function getReceiptsRoot(uint64 height) external view returns (bytes32);
    function threshold() external view returns (uint256);
    function isValidator(address validator) external view returns (bool);
}

interface IERC20Metadata {
    function decimals() external view returns (uint8);
}
