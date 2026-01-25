// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RLPReader} from "solidity-merkle-trees/trie/ethereum/RLPReader.sol";

/// @title BlockHeaderDecoder
/// @notice Decodes Ethereum-compatible block headers to extract the receiptsRoot
/// @dev Tempo uses Ethereum-compatible RLP-encoded block headers
library BlockHeaderDecoder {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;

    /// @notice Block header field indices (Ethereum format)
    /// @dev Header fields: [parentHash, unclesHash, coinbase, stateRoot, txRoot, receiptsRoot, ...]
    uint256 internal constant RECEIPTS_ROOT_INDEX = 5;

    error InvalidBlockHeaderFormat();
    error NotEnoughHeaderFields();

    /// @notice Decode a block header and extract key fields
    /// @param rlpHeader RLP-encoded block header
    /// @return blockHash keccak256 hash of the RLP-encoded header
    /// @return receiptsRoot The receipts trie root from the header
    function decode(bytes calldata rlpHeader) internal pure returns (bytes32 blockHash, bytes32 receiptsRoot) {
        blockHash = keccak256(rlpHeader);

        RLPReader.RLPItem memory item = rlpHeader.toRlpItem();
        if (!item.isList()) revert InvalidBlockHeaderFormat();

        RLPReader.RLPItem[] memory fields = item.toList();
        if (fields.length <= RECEIPTS_ROOT_INDEX) revert NotEnoughHeaderFields();

        receiptsRoot = bytes32(fields[RECEIPTS_ROOT_INDEX].toUint());
    }

    /// @notice Decode and return just the block hash
    /// @param rlpHeader RLP-encoded block header
    /// @return blockHash keccak256 hash of the header
    function hashHeader(bytes calldata rlpHeader) internal pure returns (bytes32 blockHash) {
        blockHash = keccak256(rlpHeader);
    }

    /// @notice Extract receiptsRoot from a block header
    /// @param rlpHeader RLP-encoded block header
    /// @return receiptsRoot The receipts trie root
    function extractReceiptsRoot(bytes calldata rlpHeader) internal pure returns (bytes32 receiptsRoot) {
        RLPReader.RLPItem memory item = rlpHeader.toRlpItem();
        if (!item.isList()) revert InvalidBlockHeaderFormat();

        RLPReader.RLPItem[] memory fields = item.toList();
        if (fields.length <= RECEIPTS_ROOT_INDEX) revert NotEnoughHeaderFields();

        receiptsRoot = bytes32(fields[RECEIPTS_ROOT_INDEX].toUint());
    }
}
