// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import "./TempoTest.t.sol";
import {ITIP20Token} from "tempo-std/interfaces/ITIP20.sol";

interface ITIP403Registry1028 {
    enum PolicyType {
        WHITELIST,
        BLACKLIST,
        COMPOUND
    }

    enum BlockedReason {
        NONE,
        TOKEN_FILTER,
        RECEIVE_POLICY
    }

    function setReceivePolicy(uint64 senderPolicyId, uint64 tokenFilterId, address recoveryContract) external;
    function validateReceivePolicy(address token, address sender, address receiver)
        external
        view
        returns (bool authorized, BlockedReason blockedReason);
    function createTokenFilter(address admin, PolicyType filterType) external returns (uint64 newTokenFilterId);
    function modifyTokenFilterWhitelist(uint64 tokenFilterId, address token, bool allowed) external;
    function isTokenAllowed(uint64 tokenFilterId, address token) external view returns (bool);
}

interface ITIP1028Escrow {
    enum BlockedReason {
        NONE,
        TOKEN_FILTER,
        RECEIVE_POLICY
    }

    enum InboundKind {
        TRANSFER,
        MINT
    }

    struct ClaimReceiptV1 {
        address originator;
        address recipient;
        uint64 blockedAt;
        uint64 blockedNonce;
        BlockedReason blockedReason;
        InboundKind kind;
        bytes32 memo;
    }

    function blockedReceiptBalance(
        address token,
        address recoveryContract,
        uint8 receiptVersion,
        bytes calldata receipt
    ) external view returns (uint256 amount);
    function claimBlocked(
        address token,
        address recoveryContract,
        uint8 receiptVersion,
        bytes calldata receipt,
        address to
    ) external;
}

/// forge-config: default.hardfork = "tempo:T5"
/// forge-config: fuzz500.hardfork = "tempo:T5"
contract TIP1028Test is TempoTest {
    address internal constant ESCROW = 0xE5c0000000000000000000000000000000000000;
    uint64 internal constant REJECT_ALL_POLICY = 0;
    uint64 internal constant ALLOW_ALL_POLICY = 1;
    uint64 internal constant REJECT_ALL_TOKEN_FILTER = 0;
    uint64 internal constant ALLOW_ALL_TOKEN_FILTER = 1;
    uint8 internal constant RECEIPT_VERSION = 1;

    ITIP403Registry1028 internal registry1028 = ITIP403Registry1028(TIP403_REGISTRY);
    ITIP1028Escrow internal escrow = ITIP1028Escrow(ESCROW);

    function setUp() public override {
        super.setUp();
        _requirePrecompile("TIP1028Escrow", ESCROW);
    }

    function test_BlockedTransferCanBeClaimedByReceiver() public {
        uint256 amount = 100e6;
        vm.startPrank(admin);
        token1.grantRole(_ISSUER_ROLE, admin);
        token1.mint(alice, amount);
        vm.stopPrank();

        vm.prank(bob);
        registry1028.setReceivePolicy(REJECT_ALL_POLICY, ALLOW_ALL_TOKEN_FILTER, address(0));

        uint64 blockedAt = uint64(block.timestamp);
        vm.prank(alice);
        assertTrue(token1.transfer(bob, amount));

        assertEq(token1.balanceOf(alice), 0);
        assertEq(token1.balanceOf(bob), 0);
        assertEq(token1.balanceOf(ESCROW), amount);

        bytes memory receipt = abi.encode(
            ITIP1028Escrow.ClaimReceiptV1({
                originator: alice,
                recipient: bob,
                blockedAt: blockedAt,
                blockedNonce: 1,
                blockedReason: ITIP1028Escrow.BlockedReason.RECEIVE_POLICY,
                kind: ITIP1028Escrow.InboundKind.TRANSFER,
                memo: bytes32(0)
            })
        );
        assertEq(escrow.blockedReceiptBalance(address(token1), address(0), RECEIPT_VERSION, receipt), amount);

        vm.prank(bob);
        escrow.claimBlocked(address(token1), address(0), RECEIPT_VERSION, receipt, bob);

        assertEq(token1.balanceOf(ESCROW), 0);
        assertEq(token1.balanceOf(bob), amount);
        assertEq(escrow.blockedReceiptBalance(address(token1), address(0), RECEIPT_VERSION, receipt), 0);
    }

    function test_TokenFilterBlocksBeforeSenderPolicy() public {
        uint64 filterId = registry1028.createTokenFilter(admin, ITIP403Registry1028.PolicyType.WHITELIST);
        registry1028.modifyTokenFilterWhitelist(filterId, address(token1), false);

        vm.prank(bob);
        registry1028.setReceivePolicy(REJECT_ALL_POLICY, filterId, address(0));

        (bool authorized, ITIP403Registry1028.BlockedReason reason) =
            registry1028.validateReceivePolicy(address(token1), alice, bob);
        assertFalse(authorized);
        assertEq(uint8(reason), uint8(ITIP403Registry1028.BlockedReason.TOKEN_FILTER));

        registry1028.modifyTokenFilterWhitelist(filterId, address(token1), true);
        (authorized, reason) = registry1028.validateReceivePolicy(address(token1), alice, bob);
        assertFalse(authorized);
        assertEq(uint8(reason), uint8(ITIP403Registry1028.BlockedReason.RECEIVE_POLICY));
    }

    function testFuzz_BlockedTransferClaimRoundTrip(uint96 rawAmount, address receiver) public {
        vm.assume(receiver != address(0));
        vm.assume(receiver != ESCROW);
        vm.assume(!_isTIP20Address(receiver));

        uint256 amount = bound(uint256(rawAmount), 1, 1_000_000e6);
        vm.startPrank(admin);
        token1.grantRole(_ISSUER_ROLE, admin);
        token1.mint(alice, amount);
        vm.stopPrank();

        vm.prank(receiver);
        registry1028.setReceivePolicy(REJECT_ALL_POLICY, ALLOW_ALL_TOKEN_FILTER, address(0));

        uint64 blockedAt = uint64(block.timestamp);
        vm.prank(alice);
        assertTrue(token1.transfer(receiver, amount));

        bytes memory receipt = abi.encode(
            ITIP1028Escrow.ClaimReceiptV1({
                originator: alice,
                recipient: receiver,
                blockedAt: blockedAt,
                blockedNonce: 1,
                blockedReason: ITIP1028Escrow.BlockedReason.RECEIVE_POLICY,
                kind: ITIP1028Escrow.InboundKind.TRANSFER,
                memo: bytes32(0)
            })
        );
        assertEq(token1.balanceOf(ESCROW), amount);
        assertEq(escrow.blockedReceiptBalance(address(token1), address(0), RECEIPT_VERSION, receipt), amount);

        vm.prank(receiver);
        escrow.claimBlocked(address(token1), address(0), RECEIPT_VERSION, receipt, receiver);

        assertEq(token1.balanceOf(ESCROW), 0);
        assertEq(token1.balanceOf(receiver), amount);
    }

    function _isTIP20Address(address account) internal pure returns (bool) {
        return uint16(uint160(account) >> 144) == 0x20c0;
    }
}
