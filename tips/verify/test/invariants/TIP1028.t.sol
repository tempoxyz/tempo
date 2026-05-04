// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {InvariantBaseTest} from "./InvariantBaseTest.t.sol";
import {ITIP20Token} from "tempo-std/interfaces/ITIP20.sol";

interface ITIP403Registry1028Invariant {
    function setReceivePolicy(uint64 senderPolicyId, uint64 tokenFilterId, address recoveryContract) external;
}

/// forge-config: default.hardfork = "tempo:T5"
/// forge-config: fuzz500.hardfork = "tempo:T5"
contract TIP1028InvariantTest is InvariantBaseTest {
    address internal constant ESCROW = 0xE5c0000000000000000000000000000000000000;
    uint64 internal constant REJECT_ALL_POLICY = 0;
    uint64 internal constant ALLOW_ALL_TOKEN_FILTER = 1;

    ITIP403Registry1028Invariant internal registry1028 = ITIP403Registry1028Invariant(TIP403_REGISTRY);

    mapping(address => uint256) internal openReceiptAmount;

    function setUp() public override {
        super.setUp();
        _requirePrecompile("TIP1028Escrow", ESCROW);

        targetContract(address(this));
        _setupInvariantBase();
        (_actors,) = _buildActors(12);
    }

    function blockInboundTransfer(uint256 actorSeed, uint256 tokenSeed, uint256 receiverSeed, uint256 amountSeed)
        external
    {
        ITIP20Token token = _selectBaseToken(tokenSeed);
        address sender = _selectAuthorizedActor(actorSeed, address(token));
        address receiver = _selectActorExcluding(receiverSeed, sender);
        uint256 balance = token.balanceOf(sender);
        vm.assume(balance > 0);

        uint256 amount = bound(amountSeed, 1, balance);

        vm.prank(receiver);
        registry1028.setReceivePolicy(REJECT_ALL_POLICY, ALLOW_ALL_TOKEN_FILTER, address(0));

        uint256 escrowBefore = token.balanceOf(ESCROW);
        vm.prank(sender);
        bool success = token.transfer(receiver, amount);
        assertTrue(success);

        openReceiptAmount[address(token)] += amount;
        assertEq(token.balanceOf(ESCROW), escrowBefore + amount);
    }

    function invariant_escrowBalancesEqualOpenReceiptGhostSums() public view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            address token = address(_tokens[i]);
            assertEq(
                _tokens[i].balanceOf(ESCROW),
                openReceiptAmount[token],
                "TIP1028: escrow balance must equal open receipts"
            );
        }
    }
}
