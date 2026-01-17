// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/RLP.sol";
import "@openzeppelin/contracts/utils/Memory.sol";

/// @title StablecoinEscrow
/// @notice Escrows stablecoins for bridging to Tempo
contract StablecoinEscrow is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;
    using RLP for bytes;
    using Memory for bytes;

    /// @notice The Tempo light client for header verification
    address public immutable lightClient;

    /// @notice Tempo chain ID
    uint64 public immutable tempoChainId;

    /// @notice Mapping of supported tokens
    mapping(address => bool) public supportedTokens;

    /// @notice Mapping of deposit nonces per user
    mapping(address => uint64) public depositNonces;

    /// @notice Mapping of spent burn IDs (prevents replay)
    mapping(bytes32 => bool) public spentBurnIds;

    /// @notice Bridge precompile address on Tempo
    address public constant TEMPO_BRIDGE = 0xBBBB000000000000000000000000000000000000;

    /// @notice Burn event signature from Tempo bridge
    bytes32 public constant BURN_EVENT_SIGNATURE =
        keccak256("BurnInitiated(bytes32,uint64,address,address,uint64,uint64,uint64)");

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

    error TokenNotSupported();
    error ZeroAmount();
    error InvalidRecipient();
    error BurnAlreadySpent();
    error HeaderNotFinalized();
    error InvalidReceiptProof();
    error InvalidBurnEvent();
    error InvalidProofFormat();
    error AmountTooLarge();

    constructor(address _lightClient, uint64 _tempoChainId) Ownable(msg.sender) {
        lightClient = _lightClient;
        tempoChainId = _tempoChainId;
    }

    /// @notice Add a supported token
    function addToken(address token) external onlyOwner {
        supportedTokens[token] = true;
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
        
        // Ensure normalized amount is not zero (prevents dust deposits that can't be minted)
        if (normalizedAmount == 0) revert ZeroAmount();

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        depositId = keccak256(
            abi.encodePacked(block.chainid, address(this), token, msg.sender, normalizedAmount, tempoRecipient, nonce)
        );

        emit Deposited(depositId, token, msg.sender, normalizedAmount, tempoRecipient, nonce);
    }

    /// @notice Unlock tokens based on Tempo burn proof
    /// @param tempoHeight The Tempo block height containing the burn
    /// @param receiptRlp RLP-encoded receipt
    /// @param receiptProof MPT proof for receipt inclusion (each element is 33 bytes: 32 sibling hash + 1 position flag)
    /// @param logIndex Index of the burn event in the receipt
    function unlock(uint64 tempoHeight, bytes calldata receiptRlp, bytes[] calldata receiptProof, uint256 logIndex)
        external
        nonReentrant
    {
        _unlockInternal(tempoHeight, receiptRlp, receiptProof, logIndex);
    }

    /// @notice Unlock tokens with ABI-encoded proof (called by bridge relayer)
    /// @dev Proof format: ABI-encoded (uint64 tempoHeight, bytes receiptRlp, bytes[] receiptProof, uint256 logIndex)
    /// @param burnId The burn ID (used only for duplicate check before decoding)
    /// @param recipient Expected recipient (verified against decoded burn event)
    /// @param amount Expected amount (verified against decoded burn event)
    /// @param proof ABI-encoded proof data
    function unlockWithProof(bytes32 burnId, address recipient, uint256 amount, bytes calldata proof)
        external
        nonReentrant
    {
        // Early duplicate check to avoid wasting gas on decode
        if (spentBurnIds[burnId]) revert BurnAlreadySpent();

        // Decode the ABI-encoded proof
        (uint64 tempoHeight, bytes memory receiptRlp, bytes[] memory receiptProof, uint256 logIndex) =
            abi.decode(proof, (uint64, bytes, bytes[], uint256));

        // Perform the unlock
        _unlockInternalMemory(tempoHeight, receiptRlp, receiptProof, logIndex, burnId, recipient, amount);
    }

    /// @notice Check if a burn has been unlocked (alias for isBurnSpent)
    function isUnlocked(bytes32 burnId) external view returns (bool) {
        return spentBurnIds[burnId];
    }

    function _unlockInternal(
        uint64 tempoHeight,
        bytes calldata receiptRlp,
        bytes[] calldata receiptProof,
        uint256 logIndex
    ) internal {
        ITempoLightClient lc = ITempoLightClient(lightClient);
        if (!lc.isHeaderFinalized(tempoHeight)) revert HeaderNotFinalized();

        bytes32 receiptsRoot = lc.getReceiptsRoot(tempoHeight);

        bytes32 receiptHash = keccak256(receiptRlp);
        if (!_verifyReceiptProofCalldata(receiptHash, receiptsRoot, receiptProof)) {
            revert InvalidReceiptProof();
        }

        (bytes32 burnId, uint64 originChainId, address originToken, address originRecipient, uint64 amount) =
            _decodeBurnEvent(receiptRlp, logIndex);

        if (originChainId != uint64(block.chainid)) revert InvalidBurnEvent();
        
        // Security: only allow unlocking tokens that are/were supported
        if (!supportedTokens[originToken]) revert TokenNotSupported();

        if (spentBurnIds[burnId]) revert BurnAlreadySpent();
        spentBurnIds[burnId] = true;

        uint256 denormalizedAmount = _denormalizeAmount(originToken, amount);

        IERC20(originToken).safeTransfer(originRecipient, denormalizedAmount);

        emit Unlocked(burnId, originToken, originRecipient, amount);
    }

    function _unlockInternalMemory(
        uint64 tempoHeight,
        bytes memory receiptRlp,
        bytes[] memory receiptProof,
        uint256 logIndex,
        bytes32 expectedBurnId,
        address expectedRecipient,
        uint256 expectedAmount
    ) internal {
        ITempoLightClient lc = ITempoLightClient(lightClient);
        if (!lc.isHeaderFinalized(tempoHeight)) revert HeaderNotFinalized();

        bytes32 receiptsRoot = lc.getReceiptsRoot(tempoHeight);

        bytes32 receiptHash = keccak256(receiptRlp);
        if (!_verifyReceiptProofMemory(receiptHash, receiptsRoot, receiptProof)) {
            revert InvalidReceiptProof();
        }

        (bytes32 burnId, uint64 originChainId, address originToken, address originRecipient, uint64 amount) =
            _decodeBurnEventMemory(receiptRlp, logIndex);

        // Verify the decoded values match the expected values from the relayer
        if (burnId != expectedBurnId) revert InvalidBurnEvent();
        if (originRecipient != expectedRecipient) revert InvalidBurnEvent();
        if (amount != uint64(expectedAmount)) revert InvalidBurnEvent();
        if (originChainId != uint64(block.chainid)) revert InvalidBurnEvent();
        
        // Security: only allow unlocking tokens that are/were supported
        if (!supportedTokens[originToken]) revert TokenNotSupported();

        // Already checked at the start of unlockWithProof, but double-check after decode
        if (spentBurnIds[burnId]) revert BurnAlreadySpent();
        spentBurnIds[burnId] = true;

        uint256 denormalizedAmount = _denormalizeAmount(originToken, amount);

        IERC20(originToken).safeTransfer(originRecipient, denormalizedAmount);

        emit Unlocked(burnId, originToken, originRecipient, amount);
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

    /// @dev Verify receipt proof with 33-byte elements (calldata version)
    /// Each proof element is 32 bytes sibling hash + 1 byte position flag
    /// Position flag: 0x01 = current is left (sibling on right), 0x00 = current is right (sibling on left)
    function _verifyReceiptProofCalldata(bytes32 receiptHash, bytes32 receiptsRoot, bytes[] calldata proof)
        internal
        pure
        returns (bool)
    {
        bytes32 computedRoot = receiptHash;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes calldata proofElement = proof[i];
            if (proofElement.length != 33) return false;
            
            bytes32 sibling = bytes32(proofElement[:32]);
            bool isLeft = proofElement[32] == 0x01;
            
            if (isLeft) {
                // Current is on left, sibling is on right
                computedRoot = keccak256(abi.encodePacked(computedRoot, sibling));
            } else {
                // Current is on right, sibling is on left
                computedRoot = keccak256(abi.encodePacked(sibling, computedRoot));
            }
        }
        return computedRoot == receiptsRoot;
    }

    /// @dev Verify receipt proof with 33-byte elements (memory version)
    function _verifyReceiptProofMemory(bytes32 receiptHash, bytes32 receiptsRoot, bytes[] memory proof)
        internal
        pure
        returns (bool)
    {
        bytes32 computedRoot = receiptHash;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes memory proofElement = proof[i];
            if (proofElement.length != 33) return false;
            
            bytes32 sibling;
            uint8 positionFlag;
            assembly {
                // Memory layout: [32 bytes length][32 bytes sibling][1 byte flag]
                // Load sibling from offset 32 (after length prefix)
                sibling := mload(add(proofElement, 32))
                // Load byte at index 32 (the position flag)
                // mload at offset 33 loads 32 bytes starting at byte 33, flag is in high byte
                positionFlag := byte(0, mload(add(proofElement, 65)))
            }
            
            if (positionFlag == 0x01) {
                // Current is on left, sibling is on right
                computedRoot = keccak256(abi.encodePacked(computedRoot, sibling));
            } else {
                // Current is on right, sibling is on left
                computedRoot = keccak256(abi.encodePacked(sibling, computedRoot));
            }
        }
        return computedRoot == receiptsRoot;
    }

    function _decodeBurnEvent(bytes calldata receiptRlp, uint256 logIndex)
        internal
        pure
        returns (bytes32 burnId, uint64 originChainId, address originToken, address originRecipient, uint64 amount)
    {
        bytes memory receiptBytes;
        
        // Handle typed transactions (EIP-2718): strip the transaction type prefix byte
        // Type 0x01 = EIP-2930, Type 0x02 = EIP-1559, Type 0x03 = EIP-4844
        if (receiptRlp.length > 0 && uint8(receiptRlp[0]) < 0x80) {
            // Safe slicing: create new array without type prefix
            receiptBytes = receiptRlp[1:];
        } else {
            receiptBytes = receiptRlp;
        }
        
        // Receipt structure: [status, cumulativeGasUsed, logsBloom, logs[]]
        Memory.Slice[] memory receiptFields = receiptBytes.decodeList();
        require(receiptFields.length >= 4, "Invalid receipt");
        
        // logs is at index 3
        Memory.Slice[] memory logs = RLP.readList(receiptFields[3]);
        require(logIndex < logs.length, "Log index out of bounds");
        
        // Log structure: [address, topics[], data]
        Memory.Slice[] memory logFields = RLP.readList(logs[logIndex]);
        require(logFields.length == 3, "Invalid log");
        
        // Verify emitter is the Tempo bridge precompile
        address logAddress = RLP.readAddress(logFields[0]);
        require(logAddress == TEMPO_BRIDGE, "Invalid emitter");
        
        // Decode topics: [eventSig, burnId, originChainId]
        Memory.Slice[] memory topics = RLP.readList(logFields[1]);
        require(topics.length == 3, "Invalid topics count");
        
        bytes32 eventSig = RLP.readBytes32(topics[0]);
        require(eventSig == BURN_EVENT_SIGNATURE, "Invalid event signature");
        
        burnId = RLP.readBytes32(topics[1]);
        originChainId = uint64(RLP.readUint256(topics[2]));
        
        // Decode data: ABI-encoded (address originToken, address originRecipient, uint64 amount, uint64 nonce, uint64 tempoBlockNumber)
        // Each field is 32 bytes: 5 fields = 160 bytes total
        bytes memory logData = RLP.readBytes(logFields[2]);
        require(logData.length >= 160, "Invalid log data length");
        
        // ABI decoding: addresses are right-aligned in 32-byte slots
        // offset +32 for bytes length prefix, then:
        // - originToken at bytes [0:32] -> load at offset 32, mask lower 20 bytes
        // - originRecipient at bytes [32:64] -> load at offset 64
        // - amount at bytes [64:96] -> load at offset 96
        assembly {
            originToken := mload(add(logData, 32))
            originRecipient := mload(add(logData, 64))
            amount := mload(add(logData, 96))
        }
    }

    /// @dev Decode burn event from RLP receipt (memory version for unlockWithProof)
    function _decodeBurnEventMemory(bytes memory receiptRlp, uint256 logIndex)
        internal
        pure
        returns (bytes32 burnId, uint64 originChainId, address originToken, address originRecipient, uint64 amount)
    {
        bytes memory receiptBytes;
        
        // Handle typed transactions (EIP-2718): strip the transaction type prefix byte
        // Type 0x01 = EIP-2930, Type 0x02 = EIP-1559, Type 0x03 = EIP-4844
        if (receiptRlp.length > 0 && uint8(receiptRlp[0]) < 0x80) {
            // Safe slicing: create new array without type prefix
            uint256 newLen = receiptRlp.length - 1;
            receiptBytes = new bytes(newLen);
            for (uint256 i = 0; i < newLen; i++) {
                receiptBytes[i] = receiptRlp[i + 1];
            }
        } else {
            receiptBytes = receiptRlp;
        }
        
        // Receipt structure: [status, cumulativeGasUsed, logsBloom, logs[]]
        Memory.Slice[] memory receiptFields = receiptBytes.decodeList();
        require(receiptFields.length >= 4, "Invalid receipt");
        
        // logs is at index 3
        Memory.Slice[] memory logs = RLP.readList(receiptFields[3]);
        require(logIndex < logs.length, "Log index out of bounds");
        
        // Log structure: [address, topics[], data]
        Memory.Slice[] memory logFields = RLP.readList(logs[logIndex]);
        require(logFields.length == 3, "Invalid log");
        
        // Verify emitter is the Tempo bridge precompile
        address logAddress = RLP.readAddress(logFields[0]);
        require(logAddress == TEMPO_BRIDGE, "Invalid emitter");
        
        // Decode topics: [eventSig, burnId, originChainId]
        Memory.Slice[] memory topics = RLP.readList(logFields[1]);
        require(topics.length == 3, "Invalid topics count");
        
        bytes32 eventSig = RLP.readBytes32(topics[0]);
        require(eventSig == BURN_EVENT_SIGNATURE, "Invalid event signature");
        
        burnId = RLP.readBytes32(topics[1]);
        originChainId = uint64(RLP.readUint256(topics[2]));
        
        // Decode data: ABI-encoded (address originToken, address originRecipient, uint64 amount, uint64 nonce, uint64 tempoBlockNumber)
        bytes memory logData = RLP.readBytes(logFields[2]);
        require(logData.length >= 160, "Invalid log data length");
        
        assembly {
            originToken := mload(add(logData, 32))
            originRecipient := mload(add(logData, 64))
            amount := mload(add(logData, 96))
        }
    }
}

interface ITempoLightClient {
    function isHeaderFinalized(uint64 height) external view returns (bool);
    function getReceiptsRoot(uint64 height) external view returns (bytes32);
}

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
}
