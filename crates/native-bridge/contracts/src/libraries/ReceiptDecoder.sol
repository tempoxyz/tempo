// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RLPReader} from "solidity-merkle-trees/trie/ethereum/RLPReader.sol";

/// @title ReceiptDecoder
/// @notice Decodes Ethereum transaction receipts and extracts MessageSent logs
/// @dev Handles both legacy and EIP-2718 typed receipts
library ReceiptDecoder {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    /// @notice MessageSent event signature
    /// @dev keccak256("MessageSent(address,bytes32,uint64)")
    bytes32 internal constant MESSAGE_SENT_SIGNATURE = 0x461908389c48b18509635356200579f524bd58d0bf841361ffd8964b2fd41273;

    /// @notice Receipt field indices
    uint256 internal constant LOGS_INDEX = 3;

    /// @notice Log field indices
    uint256 internal constant LOG_ADDRESS_INDEX = 0;
    uint256 internal constant LOG_TOPICS_INDEX = 1;
    uint256 internal constant LOG_DATA_INDEX = 2;

    error InvalidReceiptFormat();
    error InvalidLogFormat();
    error LogIndexOutOfBounds(uint256 requested, uint256 available);
    error NotMessageSentEvent();
    error InvalidTopicsLength();

    /// @notice Decoded MessageSent event
    struct MessageSentLog {
        address emitter;
        address sender;
        bytes32 messageHash;
        uint64 destinationChainId;
    }

    /// @notice Decode a receipt and extract a MessageSent log at the given index
    /// @param rlpReceipt RLP-encoded receipt (may be typed or legacy)
    /// @param logIndex Index of the log within the receipt
    /// @return log The decoded MessageSent event
    function decodeMessageSentLog(
        bytes memory rlpReceipt,
        uint256 logIndex
    ) internal pure returns (MessageSentLog memory log) {
        bytes memory receiptData = rlpReceipt;

        // Handle typed transactions (EIP-2718): first byte < 0x80 means it's a type prefix
        if (receiptData.length > 0 && uint8(receiptData[0]) < 0x80) {
            // Skip the type byte
            bytes memory stripped = new bytes(receiptData.length - 1);
            for (uint256 i = 0; i < stripped.length; i++) {
                stripped[i] = receiptData[i + 1];
            }
            receiptData = stripped;
        }

        RLPReader.RLPItem memory item = receiptData.toRlpItem();
        if (!item.isList()) revert InvalidReceiptFormat();

        RLPReader.RLPItem[] memory fields = item.toList();
        if (fields.length <= LOGS_INDEX) revert InvalidReceiptFormat();

        // Get logs array
        RLPReader.RLPItem[] memory logs = fields[LOGS_INDEX].toList();
        if (logIndex >= logs.length) {
            revert LogIndexOutOfBounds(logIndex, logs.length);
        }

        // Decode the specific log
        RLPReader.RLPItem[] memory logFields = logs[logIndex].toList();
        if (logFields.length < 3) revert InvalidLogFormat();

        // Extract emitter address
        log.emitter = logFields[LOG_ADDRESS_INDEX].toAddress();

        // Extract topics
        RLPReader.RLPItem[] memory topics = logFields[LOG_TOPICS_INDEX].toList();

        // MessageSent has 4 topics: signature + 3 indexed params
        if (topics.length != 4) revert InvalidTopicsLength();

        // Verify event signature
        bytes32 eventSig = bytes32(topics[0].toUint());
        if (eventSig != MESSAGE_SENT_SIGNATURE) revert NotMessageSentEvent();

        // topics[1] = indexed sender (address padded to 32 bytes)
        log.sender = address(uint160(topics[1].toUint()));

        // topics[2] = indexed messageHash
        log.messageHash = bytes32(topics[2].toUint());

        // topics[3] = indexed destinationChainId (uint64 padded to 32 bytes)
        log.destinationChainId = uint64(topics[3].toUint());
    }

    /// @notice Get the number of logs in a receipt
    /// @param rlpReceipt RLP-encoded receipt
    /// @return count Number of logs
    function getLogCount(bytes memory rlpReceipt) internal pure returns (uint256 count) {
        bytes memory receiptData = rlpReceipt;

        // Handle typed transactions
        if (receiptData.length > 0 && uint8(receiptData[0]) < 0x80) {
            bytes memory stripped = new bytes(receiptData.length - 1);
            for (uint256 i = 0; i < stripped.length; i++) {
                stripped[i] = receiptData[i + 1];
            }
            receiptData = stripped;
        }

        RLPReader.RLPItem memory item = receiptData.toRlpItem();
        RLPReader.RLPItem[] memory fields = item.toList();

        if (fields.length <= LOGS_INDEX) return 0;

        RLPReader.RLPItem[] memory logs = fields[LOGS_INDEX].toList();
        return logs.length;
    }
}
