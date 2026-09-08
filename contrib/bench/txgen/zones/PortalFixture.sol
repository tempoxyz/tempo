// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IPortal {
    struct BlockTransition {
        bytes32 prevBlockHash;
        bytes32 nextBlockHash;
    }

    struct DepositQueueTransition {
        bytes32 prevProcessedHash;
        bytes32 nextProcessedHash;
        uint64 prevDepositNumber;
        uint64 nextDepositNumber;
    }

    struct TokenEnablementTransition {
        uint64 prevProcessedTokenCount;
        uint64 nextProcessedTokenCount;
    }
    function blockHash() external view returns (bytes32);
    function zoneHeight() external view returns (uint256);
    function depositCount() external view returns (uint64);
    function lastProcessedDepositNumber() external view returns (uint64);
    function currentDepositQueueHash() external view returns (bytes32);
    function lastProcessedEnabledTokenCount() external view returns (uint64);
    function submitBatch(
        uint64,
        uint64,
        BlockTransition calldata,
        DepositQueueTransition calldata,
        bytes32,
        bytes calldata,
        bytes calldata,
        uint256,
        bytes[] calldata
    ) external;
    function submitBatch(
        uint64,
        uint64,
        BlockTransition calldata,
        DepositQueueTransition calldata,
        TokenEnablementTransition calldata,
        bytes32,
        bytes calldata,
        bytes calldata,
        uint256,
        bytes[] calldata
    ) external;

    struct DepositPayload {
        bytes32 ephemeralPubkeyX;
        uint8 ephemeralPubkeyYParity;
        bytes ciphertext;
        bytes12 nonce;
        bytes16 tag;
    }

    struct Withdrawal {
        address token;
        bytes32 senderTag;
        address to;
        uint128 amount;
        bytes32 memo;
        uint64 gasLimit;
        uint64 fallbackNonce;
        bytes callbackData;
        bytes encryptedSender;
    }
    function deposit(
        address token,
        uint128 amount,
        uint256 keyIndex,
        DepositPayload calldata encrypted,
        address tempoRefundRecipient
    ) external returns (bytes32);
    function processWithdrawals(Withdrawal[] calldata withdrawals, bytes32 remainingQueue) external;
}

/// @notice Local execution benchmark only: constructor-seeded portal state with dummy settlement verification.
/// @dev Returns the exact production ERC-1167 proxy runtime. There are no fixture methods
/// in the deployed contract. Storage layout: crates/precompiles/src/zone_factory/portal.rs.
contract PortalFixture {
    constructor(address account, address token, address settlement) {
        require(block.chainid == 1337, "local benchmark chain only");
        require(
            address(0x5AD1000000000000000000000000000000000000).code.length != 0,
            "ZonePortal runtime missing; enable T10 or later"
        );

        bytes32 tokenSlot = keccak256(abi.encode(token, uint256(6)));
        bytes32 tokensSlot = keccak256(abi.encode(uint256(7)));
        bytes32 roleSlot = keccak256(abi.encode(settlement, uint256(20)));
        bytes32 userRoleSlot = keccak256(abi.encode(account, uint256(20)));
        bytes32 sequencersSlot = keccak256(abi.encode(uint256(18)));
        bytes32 keysSlot = keccak256(abi.encode(uint256(5)));
        // Public, deterministic benchmark encryption key (private scalar 1).
        assembly {
            sstore(0, account)
            sstore(tokenSlot, 0x0101)
            sstore(7, 1)
            sstore(tokensSlot, token)
            sstore(roleSlot, 1)
            sstore(userRoleSlot, 1)
            sstore(18, 2)
            sstore(sequencersSlot, settlement)
            sstore(add(sequencersSlot, 1), account)
            sstore(5, 1)
            sstore(keysSlot, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
            sstore(add(keysSlot, 1), or(2, shl(8, number())))
            // Dummy verifier and zero attestation threshold are local fixture settings only.
            // The real portal still checks transitions and manages both queues.
            sstore(15, or(1, shl(32, 0x5a4d000000000000000000000000000000000000)))
            sstore(16, or(settlement, shl(160, 1)))
            sstore(23, or(settlement, shl(160, 1)))
            sstore(24, number())
        }
        bytes memory proxy =
            hex"363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3";
        assembly { return(add(proxy, 32), mload(proxy)) }
    }
}

/// @notice Local-only dummy verifier and synthetic batch submitter. No zone or prover runs.
contract SettlementFixture {
    mapping(address => bytes32) private processedHash;

    constructor() {
        require(block.chainid == 1337, "local benchmark chain only");
    }

    // Accept either verifier ABI (before or after TIP-1096). No proof is checked.
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }

    /// @notice Settle all pending deposits and optionally enqueue one user withdrawal.
    function settle(IPortal portal, address token, address recipient, bool withdraw) external {
        bytes32 withdrawalRoot;
        if (withdraw) {
            IPortal.Withdrawal memory item =
                IPortal.Withdrawal(token, bytes32(0), recipient, 1, bytes32(0), 0, 1, "", "");
            withdrawalRoot = keccak256(abi.encode(item, bytes32(0)));
        }
        uint256 height = portal.zoneHeight() + 1;
        IPortal.BlockTransition memory blocks =
            IPortal.BlockTransition(portal.blockHash(), keccak256(abi.encode(address(portal), height)));
        IPortal.DepositQueueTransition memory deposits = IPortal.DepositQueueTransition(
            processedHash[address(portal)],
            portal.currentDepositQueueHash(),
            portal.lastProcessedDepositNumber(),
            portal.depositCount()
        );
        // The real portal authenticates a recent Tempo anchor even with a dummy verifier.
        uint64 anchor = uint64(block.number - 1);
        bytes[] memory signatures = new bytes[](0);
        // TIP-1096 adds the enabled-token cursor to the settlement ABI.
        try portal.lastProcessedEnabledTokenCount() returns (uint64 tokens) {
            portal.submitBatch(
                anchor,
                0,
                blocks,
                deposits,
                IPortal.TokenEnablementTransition(tokens, 1),
                withdrawalRoot,
                "",
                "",
                height,
                signatures
            );
        } catch {
            portal.submitBatch(anchor, 0, blocks, deposits, withdrawalRoot, "", "", height, signatures);
        }
        processedHash[address(portal)] = deposits.nextProcessedHash;
    }
}
