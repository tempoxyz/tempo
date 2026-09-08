// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IPortal {
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
    function deposit(address token, uint128 amount, uint256 keyIndex, DepositPayload calldata encrypted,
        address tempoRefundRecipient) external returns (bytes32);
    function processWithdrawals(Withdrawal[] calldata withdrawals, bytes32 remainingQueue) external;
}

/// @notice Local execution benchmark only: constructor-seeded portal state, no settlement.
/// @dev Returns the exact production ERC-1167 proxy runtime. There are no fixture methods
/// in the deployed contract. Storage layout: crates/precompiles/src/zone_factory/portal.rs.
contract PortalFixture {
    constructor(address account, address token, bytes32 withdrawalRoot) {
        require(block.chainid == 1337, "local benchmark chain only");
        require(address(0x5AD1000000000000000000000000000000000000).code.length != 0,
            "ZonePortal runtime missing; enable T10 or later");

        bytes32 tokenSlot = keccak256(abi.encode(token, uint256(6)));
        bytes32 tokensSlot = keccak256(abi.encode(uint256(7)));
        bytes32 roleSlot = keccak256(abi.encode(account, uint256(20)));
        bytes32 sequencersSlot = keccak256(abi.encode(uint256(18)));
        bytes32 keysSlot = keccak256(abi.encode(uint256(5)));
        bytes32 queueSlot = keccak256(abi.encode(uint256(0), uint256(11)));
        // Public, deterministic benchmark encryption key (private scalar 1).
        assembly {
            sstore(0, account)
            sstore(tokenSlot, 0x0101)
            sstore(7, 1)
            sstore(tokensSlot, token)
            sstore(roleSlot, 1)
            sstore(18, 1)
            sstore(sequencersSlot, account)
            sstore(5, 1)
            sstore(keysSlot, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)
            sstore(add(keysSlot, 1), or(2, shl(8, number())))
            // zoneId=1, canonical messenger; initialized=true, threshold=1.
            sstore(15, or(1, shl(32, 0x5a4d000000000000000000000000000000000000)))
            sstore(16, or(or(0x5a56000000000000000000000000000000000000, shl(160, 1)), shl(232, 1)))
            sstore(23, or(account, shl(160, 1)))
            sstore(24, number())
            if withdrawalRoot {
                sstore(10, 1)
                sstore(queueSlot, withdrawalRoot)
            }
        }
        bytes memory proxy = hex"363d3d373d3d3d363d735ad10000000000000000000000000000000000005af43d82803e903d91602b57fd5bf3";
        assembly { return(add(proxy, 32), mload(proxy)) }
    }
}
