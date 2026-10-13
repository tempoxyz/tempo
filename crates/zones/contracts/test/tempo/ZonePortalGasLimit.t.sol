// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    IZonePortal,
    Withdrawal,
    ZONE_FACTORY_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { PortalRuntimeTest } from "../PortalRuntimeTest.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

contract MockPortalToken {

    string public name = "Mock USD";
    string public symbol = "mUSD";
    string public currency = "USD";

    mapping(address => uint256) public balanceOf;
    mapping(address => bool) public blockedRecipient;

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setBlockedRecipient(address recipient, bool blocked) external {
        blockedRecipient[recipient] = blocked;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (blockedRecipient[to]) revert("blocked");
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

}

contract ZonePortalGasLimitTest is PortalRuntimeTest {

    uint256 internal constant WITHDRAWAL_QUEUE_TAIL_SLOT = 10;
    uint256 internal constant WITHDRAWAL_QUEUE_SLOTS_MAPPING_SLOT = 11;

    ZonePortal public portal;
    MockPortalToken public token;

    address public admin = address(0x500);
    address public zoneFallbackRecipient = address(0x200);
    address public recipient = address(0x300);

    function setUp() public {
        token = new MockPortalToken();
        portal = _newPortalProxy(1);
        address[] memory sequencers = new address[](1);
        sequencers[0] = address(this);

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        vm.mockCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.migrateTransferPolicyIds, (tokens)),
            abi.encode(uint256(1))
        );
        vm.mockCall(
            StdPrecompiles.TIP403_REGISTRY_ADDRESS,
            abi.encodeCall(ITIP403Registry.tokenTransferPolicyId, (address(token))),
            abi.encode(true, uint64(1))
        );

        vm.prank(ZONE_FACTORY_ADDRESS);
        address[] memory allowedAccounts = new address[](1);
        allowedAccounts[0] = recipient;
        address[] memory noGateways = new address[](0);
        portal.initialize(
            1,
            address(token),
            true,
            true,
            allowedAccounts,
            noGateways,
            address(0x400),
            admin,
            sequencers,
            1,
            address(0),
            ""
        );
    }

    function test_bouncebackGas_defaultsToZero() public view {
        assertEq(portal.bouncebackGas(), 0);
        assertEq(portal.calculateBouncebackFee(), 0);
    }

    function test_setBouncebackGas_onlyAdmin() public {
        vm.expectRevert(IZonePortal.NotAdmin.selector);
        portal.setBouncebackGas(300_000);
    }

    function test_setBouncebackGas_updatesGasAndFee() public {
        vm.expectEmit(false, false, false, true, address(portal));
        emit IZonePortal.BouncebackGasUpdated(300_000);
        vm.prank(admin);
        portal.setBouncebackGas(300_000);
        vm.fee(1e12);

        assertEq(portal.bouncebackGas(), 300_000);
        assertEq(portal.calculateBouncebackFee(), 300_000);
    }

    function test_processWithdrawal_overMaxGasLimit_bouncesBackAndClearsQueue() public {
        Withdrawal memory w = Withdrawal({
            token: address(token),
            senderTag: keccak256("sender"),
            to: recipient,
            amount: 500e6,
            memo: bytes32(0),
            gasLimit: portal.MAX_WITHDRAWAL_GAS_LIMIT() + 1,
            fallbackNonce: 1,
            callbackData: "test",
            encryptedSender: ""
        });
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        vm.store(address(portal), bytes32(WITHDRAWAL_QUEUE_TAIL_SLOT), bytes32(uint256(1)));
        vm.store(address(portal), _withdrawalQueueSlot(0), wHash);

        vm.expectEmit(false, true, false, true, address(portal));
        emit IZonePortal.WithdrawalBounceBack(bytes32(0), 1, address(token), 500e6, 1);
        vm.expectEmit(true, true, false, true, address(portal));
        emit IZonePortal.WithdrawalProcessed(recipient, w.senderTag, address(token), 500e6, false);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
        assertTrue(portal.currentDepositQueueHash() != bytes32(0));
    }

    function test_processWithdrawal_simpleTransferFailureBouncesBackWithinPlannerLimit() public {
        token.mint(address(portal), 500e6);
        token.setBlockedRecipient(recipient, true);

        Withdrawal memory w = Withdrawal({
            token: address(token),
            senderTag: keccak256("sender"),
            to: recipient,
            amount: 500e6,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: 1,
            callbackData: "",
            encryptedSender: ""
        });
        _storeSingleWithdrawal(w);

        (bool success,) = address(portal).call{ gas: 1_500_000 }(
            abi.encodeCall(IZonePortal.processWithdrawals, (_singleWithdrawal(w), bytes32(0)))
        );

        assertTrue(success);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertTrue(portal.currentDepositQueueHash() != bytes32(0));
    }

    function test_processWithdrawal_depositBounceBack_paysFeeAndRefundsNetAmount() public {
        _configureBouncebackFee();
        token.mint(address(portal), 1000e6);
        uint128 bouncebackFee = portal.calculateBouncebackFee();
        uint128 refundAmount = 1000e6 - bouncebackFee;

        Withdrawal memory w = _depositBounceBackWithdrawal(1000e6);
        _storeSingleWithdrawal(w);

        vm.expectEmit(true, false, false, true, address(portal));
        emit IZonePortal.DepositBounceBack(recipient, address(token), refundAmount, bouncebackFee);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(token.balanceOf(admin), bouncebackFee);
        assertEq(token.balanceOf(recipient), refundAmount);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
    }

    function test_processWithdrawal_depositBounceBack_feeTransferFailureRefundsFullAmount() public {
        _configureBouncebackFee();
        token.mint(address(portal), 1000e6);
        token.setBlockedRecipient(admin, true);

        Withdrawal memory w = _depositBounceBackWithdrawal(1000e6);
        _storeSingleWithdrawal(w);

        vm.expectEmit(true, false, false, true, address(portal));
        emit IZonePortal.DepositBounceBack(recipient, address(token), 1000e6, 0);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(token.balanceOf(admin), 0);
        assertEq(token.balanceOf(recipient), 1000e6);
        assertEq(token.balanceOf(address(portal)), 0);
        assertEq(portal.withdrawalQueueHead(), 1);
        assertEq(portal.withdrawalQueueSlot(0), bytes32(0));
    }

    function test_processWithdrawal_depositBounceBack_feeAndRefundFailureParksFullAmount() public {
        _configureBouncebackFee();
        token.mint(address(portal), 1000e6);
        token.setBlockedRecipient(admin, true);
        token.setBlockedRecipient(recipient, true);

        Withdrawal memory w = _depositBounceBackWithdrawal(1000e6);
        _storeSingleWithdrawal(w);

        vm.expectEmit(true, false, false, true, address(portal));
        emit IZonePortal.DepositBounceBackPending(recipient, address(token), 1000e6, 0);
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(token.balanceOf(admin), 0);
        assertEq(token.balanceOf(recipient), 0);
        assertEq(token.balanceOf(address(portal)), 1000e6);
        assertEq(portal.refunds(address(token), recipient), 1000e6);

        token.setBlockedRecipient(recipient, false);
        vm.prank(recipient);
        assertEq(portal.claimRefund(address(token)), 1000e6);
        assertEq(token.balanceOf(recipient), 1000e6);
        assertEq(portal.refunds(address(token), recipient), 0);
    }

    function test_processWithdrawal_depositBounceBack_parksRefundWhenTransferFails() public {
        _configureBouncebackFee();
        token.mint(address(portal), 1000e6);
        token.setBlockedRecipient(recipient, true);
        uint128 bouncebackFee = portal.calculateBouncebackFee();
        uint128 refundAmount = 1000e6 - bouncebackFee;

        Withdrawal memory w = _depositBounceBackWithdrawal(1000e6);
        _storeSingleWithdrawal(w);

        vm.expectEmit(true, false, false, true, address(portal));
        emit IZonePortal.DepositBounceBackPending(
            recipient, address(token), refundAmount, bouncebackFee
        );
        portal.processWithdrawals(_singleWithdrawal(w), bytes32(0));

        assertEq(token.balanceOf(admin), bouncebackFee);
        assertEq(token.balanceOf(recipient), 0);
        assertEq(portal.refunds(address(token), recipient), refundAmount);

        token.setBlockedRecipient(recipient, false);
        vm.prank(recipient);
        assertEq(portal.claimRefund(address(token)), refundAmount);
        assertEq(token.balanceOf(recipient), refundAmount);
        assertEq(portal.refunds(address(token), recipient), 0);
    }

    function _withdrawalQueueSlot(uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(slot, WITHDRAWAL_QUEUE_SLOTS_MAPPING_SLOT));
    }

    function _configureBouncebackFee() internal {
        vm.prank(admin);
        portal.setBouncebackGas(300_000);
        vm.fee(1e12);
    }

    function _depositBounceBackWithdrawal(uint128 amount)
        internal
        view
        returns (Withdrawal memory)
    {
        return Withdrawal({
            token: address(token),
            senderTag: keccak256(abi.encodePacked(address(0), bytes32(0))),
            to: recipient,
            amount: amount,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: 0,
            callbackData: "",
            encryptedSender: ""
        });
    }

    function _storeSingleWithdrawal(Withdrawal memory w) internal {
        vm.store(address(portal), bytes32(WITHDRAWAL_QUEUE_TAIL_SLOT), bytes32(uint256(1)));
        vm.store(address(portal), _withdrawalQueueSlot(0), keccak256(abi.encode(w, bytes32(0))));
    }

    function _singleWithdrawal(Withdrawal memory withdrawal)
        internal
        pure
        returns (Withdrawal[] memory withdrawals)
    {
        withdrawals = new Withdrawal[](1);
        withdrawals[0] = withdrawal;
    }

}
