// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { TIP20 } from "../src/TIP20.sol";
import { TempoStreamChannel } from "../src/TempoStreamChannel.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract TempoStreamChannelTest is BaseTest {

    TempoStreamChannel public channel;
    TIP20 public token;

    address public payer;
    uint256 public payerKey;
    address public payee;

    uint128 constant DEPOSIT = 1_000_000;
    bytes32 constant SALT = bytes32(uint256(1));

    function setUp() public override {
        super.setUp();

        channel = new TempoStreamChannel();
        token = TIP20(
            factory.createToken("Stream Token", "STR", "USD", pathUSD, admin, bytes32("stream"))
        );

        (payer, payerKey) = makeAddrAndKey("payer");
        payee = makeAddr("payee");

        vm.startPrank(admin);
        token.grantRole(_ISSUER_ROLE, admin);
        token.mint(payer, 10_000_000);
        vm.stopPrank();

        vm.prank(payer);
        token.approve(address(channel), type(uint256).max);
    }

    function _openChannel() internal returns (bytes32) {
        vm.prank(payer);
        return channel.open(payee, address(token), DEPOSIT, SALT, address(0));
    }

    function _signVoucher(bytes32 channelId, uint128 amount) internal view returns (bytes memory) {
        bytes32 digest = channel.getVoucherDigest(channelId, amount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    // --- Open Tests ---

    function test_open_success() public {
        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), DEPOSIT, SALT, address(0));

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertEq(ch.payer, payer);
        assertEq(ch.payee, payee);
        assertEq(ch.token, address(token));
        assertEq(ch.deposit, DEPOSIT);
        assertEq(ch.settled, 0);
        assertFalse(ch.finalized);

        assertEq(token.balanceOf(address(channel)), DEPOSIT);
    }

    function test_open_revert_duplicate() public {
        _openChannel();

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.ChannelAlreadyExists.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0));
    }

    // --- Settle Tests ---

    function test_settle_success() public {
        bytes32 channelId = _openChannel();

        uint128 amount = 500_000;
        bytes memory sig = _signVoucher(channelId, amount);

        vm.prank(payee);
        channel.settle(channelId, amount, sig);

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertEq(ch.settled, amount);
        assertEq(token.balanceOf(payee), amount);
    }

    function test_settle_multiple() public {
        bytes32 channelId = _openChannel();

        bytes memory sig1 = _signVoucher(channelId, 200_000);
        vm.prank(payee);
        channel.settle(channelId, 200_000, sig1);

        bytes memory sig2 = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig2);

        assertEq(token.balanceOf(payee), 500_000);
        assertEq(channel.getChannel(channelId).settled, 500_000);
    }

    function test_settle_revert_notIncreasing() public {
        bytes32 channelId = _openChannel();

        bytes memory sig1 = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig1);

        bytes memory sig2 = _signVoucher(channelId, 400_000);
        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.AmountNotIncreasing.selector);
        channel.settle(channelId, 400_000, sig2);
    }

    function test_settle_revert_exceedsDeposit() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, DEPOSIT + 1);
        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.AmountExceedsDeposit.selector);
        channel.settle(channelId, DEPOSIT + 1, sig);
    }

    function test_settle_revert_invalidSignature() public {
        bytes32 channelId = _openChannel();

        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes32 digest = channel.getVoucherDigest(channelId, 500_000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.InvalidSignature.selector);
        channel.settle(channelId, 500_000, sig);
    }

    // --- TopUp Tests ---

    function test_topUp_addDeposit() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.topUp(channelId, 500_000);

        assertEq(channel.getChannel(channelId).deposit, DEPOSIT + 500_000);
        assertEq(token.balanceOf(address(channel)), DEPOSIT + 500_000);
    }

    function test_topUp_revert_notPayer() public {
        bytes32 channelId = _openChannel();

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.NotPayer.selector);
        channel.topUp(channelId, 500_000);
    }

    // --- RequestClose Tests ---

    function test_requestClose_setsTimestamp() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        assertEq(channel.getChannel(channelId).closeRequestedAt, block.timestamp);
    }

    function test_requestClose_revert_notPayer() public {
        bytes32 channelId = _openChannel();

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.NotPayer.selector);
        channel.requestClose(channelId);
    }

    // --- Close Tests (Server-initiated) ---

    function test_close_withVoucher() public {
        bytes32 channelId = _openChannel();

        uint128 amount = 600_000;
        bytes memory sig = _signVoucher(channelId, amount);

        uint256 payeeBalanceBefore = token.balanceOf(payee);
        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, amount, sig);

        assertEq(token.balanceOf(payee), payeeBalanceBefore + amount);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - amount));
        assertTrue(channel.getChannel(channelId).finalized);
    }

    function test_close_withoutVoucher() public {
        bytes32 channelId = _openChannel();

        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 0, "");

        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
        assertEq(token.balanceOf(payee), 0);
        assertTrue(channel.getChannel(channelId).finalized);
    }

    function test_close_revert_notPayee() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.NotPayee.selector);
        channel.close(channelId, 0, "");
    }

    // --- Withdraw Tests ---

    function test_withdraw_afterGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);
        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payer);
        channel.withdraw(channelId);

        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
        assertTrue(channel.getChannel(channelId).finalized);
    }

    function test_withdraw_revert_beforeGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.CloseNotReady.selector);
        channel.withdraw(channelId);
    }

    function test_withdraw_revert_noCloseRequest() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.CloseNotReady.selector);
        channel.withdraw(channelId);
    }

    function test_withdraw_revert_doubleWithdraw() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);
        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        vm.prank(payer);
        channel.withdraw(channelId);

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.ChannelFinalized.selector);
        channel.withdraw(channelId);
    }

    // --- Batch Read Test ---

    function test_getChannelsBatch_success() public {
        bytes32 channelId1 = _openChannel();

        vm.prank(payer);
        bytes32 channelId2 =
            channel.open(payee, address(token), DEPOSIT, bytes32(uint256(2)), address(0));

        bytes memory sig = _signVoucher(channelId1, 500_000);
        vm.prank(payee);
        channel.settle(channelId1, 500_000, sig);

        bytes32[] memory channelIds = new bytes32[](2);
        channelIds[0] = channelId1;
        channelIds[1] = channelId2;

        TempoStreamChannel.Channel[] memory states = channel.getChannelsBatch(channelIds);

        assertEq(states.length, 2);
        assertEq(states[0].settled, 500_000);
        assertEq(states[1].settled, 0);
    }

    // --- AuthorizedSigner Tests ---

    function test_authorizedSigner_settleSuccess() public {
        (address delegateSigner, uint256 delegateKey) = makeAddrAndKey("delegate");

        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), DEPOSIT, SALT, delegateSigner);

        bytes32 digest = channel.getVoucherDigest(channelId, 500_000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(delegateKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        assertEq(channel.getChannel(channelId).settled, 500_000);
        assertEq(token.balanceOf(payee), 500_000);
    }

    function test_authorizedSigner_payerSignatureRejected() public {
        (address delegateSigner,) = makeAddrAndKey("delegate");

        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), DEPOSIT, SALT, delegateSigner);

        bytes32 digest = channel.getVoucherDigest(channelId, 500_000);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(payerKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.InvalidSignature.selector);
        channel.settle(channelId, 500_000, sig);
    }

    function test_authorizedSigner_closeWithDelegateVoucher() public {
        (address delegateSigner, uint256 delegateKey) = makeAddrAndKey("delegate");

        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), DEPOSIT, SALT, delegateSigner);

        uint128 amount = 400_000;
        bytes32 digest = channel.getVoucherDigest(channelId, amount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(delegateKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(payee);
        channel.close(channelId, amount, sig);

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payee), amount);
        assertEq(token.balanceOf(payer), 10_000_000 - DEPOSIT + (DEPOSIT - amount));
    }

    function test_authorizedSigner_equalsPayer() public {
        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), DEPOSIT, SALT, payer);

        bytes memory sig = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        assertEq(channel.getChannel(channelId).settled, 500_000);
    }

    // --- TopUp + Settle Beyond Initial Deposit ---

    function test_topUp_thenSettleBeyondInitialDeposit() public {
        bytes32 channelId = _openChannel();

        bytes memory sig1 = _signVoucher(channelId, 900_000);
        vm.prank(payee);
        channel.settle(channelId, 900_000, sig1);
        assertEq(channel.getChannel(channelId).settled, 900_000);

        vm.prank(payer);
        channel.topUp(channelId, 500_000);
        assertEq(channel.getChannel(channelId).deposit, DEPOSIT + 500_000);

        uint128 beyondInitial = DEPOSIT + 200_000;
        bytes memory sig2 = _signVoucher(channelId, beyondInitial);
        vm.prank(payee);
        channel.settle(channelId, beyondInitial, sig2);

        assertEq(channel.getChannel(channelId).settled, beyondInitial);
        assertEq(token.balanceOf(payee), beyondInitial);
    }

    function test_topUp_zeroAmount() public {
        bytes32 channelId = _openChannel();

        uint256 balanceBefore = token.balanceOf(address(channel));
        vm.prank(payer);
        channel.topUp(channelId, 0);

        assertEq(channel.getChannel(channelId).deposit, DEPOSIT);
        assertEq(token.balanceOf(address(channel)), balanceBefore);
    }

    function test_topUp_cancelsCloseRequest() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);
        assertEq(channel.getChannel(channelId).closeRequestedAt, block.timestamp);

        vm.prank(payer);
        channel.topUp(channelId, 100_000);

        assertEq(channel.getChannel(channelId).closeRequestedAt, 0);
    }

    function test_topUp_revert_finalized() public {
        bytes32 channelId = _openChannel();

        vm.prank(payee);
        channel.close(channelId, 0, "");

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.ChannelFinalized.selector);
        channel.topUp(channelId, 100_000);
    }

    // --- Grace Period Boundary Tests ---

    function test_payeeCanSettleDuringGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() - 1);

        bytes memory sig = _signVoucher(channelId, 600_000);
        vm.prank(payee);
        channel.settle(channelId, 600_000, sig);

        assertEq(channel.getChannel(channelId).settled, 600_000);
        assertEq(token.balanceOf(payee), 600_000);
    }

    function test_payeeCanCloseDuringGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() - 1);

        uint128 amount = 700_000;
        bytes memory sig = _signVoucher(channelId, amount);

        vm.prank(payee);
        channel.close(channelId, amount, sig);

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payee), amount);
    }

    function test_withdraw_exactGraceBoundary() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD());

        vm.prank(payer);
        channel.withdraw(channelId);

        assertTrue(channel.getChannel(channelId).finalized);
    }

    function test_withdraw_afterPartialSettle() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, 300_000);
        vm.prank(payee);
        channel.settle(channelId, 300_000, sig);

        vm.prank(payer);
        channel.requestClose(channelId);
        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(channelId);

        uint128 expectedRefund = DEPOSIT - 300_000;
        assertEq(token.balanceOf(payer), payerBalanceBefore + expectedRefund);
        assertTrue(channel.getChannel(channelId).finalized);
    }

    // --- Close Edge Cases ---

    function test_close_cumulativeEqualToSettled() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 500_000, "");

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 500_000));
    }

    function test_close_cumulativeLessThanSettled() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(channelId, 200_000, "");

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 500_000));
        assertEq(token.balanceOf(payee), payeeBalanceBefore);
    }

    function test_close_zeroAfterPartialSettle() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, 300_000);
        vm.prank(payee);
        channel.settle(channelId, 300_000, sig);

        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 0, "");

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 300_000));
    }

    function test_close_fullDeposit() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, DEPOSIT);

        vm.prank(payee);
        channel.close(channelId, DEPOSIT, sig);

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payee), DEPOSIT);
        assertEq(token.balanceOf(address(channel)), 0);
    }

    // --- RequestClose Edge Cases ---

    function test_requestClose_idempotent() public {
        bytes32 channelId = _openChannel();

        vm.warp(1000);
        vm.prank(payer);
        channel.requestClose(channelId);

        uint64 firstTimestamp = channel.getChannel(channelId).closeRequestedAt;

        vm.warp(2000);
        vm.prank(payer);
        channel.requestClose(channelId);

        assertEq(channel.getChannel(channelId).closeRequestedAt, firstTimestamp);
    }

    function test_requestClose_revert_finalized() public {
        bytes32 channelId = _openChannel();

        vm.prank(payee);
        channel.close(channelId, 0, "");

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.ChannelFinalized.selector);
        channel.requestClose(channelId);
    }

    // --- Settle Edge Cases ---

    function test_settle_revert_finalized() public {
        bytes32 channelId = _openChannel();

        vm.prank(payee);
        channel.close(channelId, 0, "");

        bytes memory sig = _signVoucher(channelId, 100_000);
        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.ChannelFinalized.selector);
        channel.settle(channelId, 100_000, sig);
    }

    function test_settle_revert_nonExistentChannel() public {
        bytes32 fakeId = bytes32(uint256(999));
        bytes memory sig = _signVoucher(fakeId, 100_000);

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.ChannelNotFound.selector);
        channel.settle(fakeId, 100_000, sig);
    }

    function test_settle_revert_sameAmount() public {
        bytes32 channelId = _openChannel();

        bytes memory sig1 = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        channel.settle(channelId, 500_000, sig1);

        bytes memory sig2 = _signVoucher(channelId, 500_000);
        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.AmountNotIncreasing.selector);
        channel.settle(channelId, 500_000, sig2);
    }

    function test_settle_revert_notPayee() public {
        bytes32 channelId = _openChannel();

        address randomCaller = makeAddr("random");
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(randomCaller);
        vm.expectRevert(TempoStreamChannel.NotPayee.selector);
        channel.settle(channelId, 500_000, sig);
    }

    // --- View Function Tests ---

    function test_computeChannelId_deterministic() public view {
        bytes32 id1 = channel.computeChannelId(payer, payee, address(token), SALT, address(0));
        bytes32 id2 = channel.computeChannelId(payer, payee, address(token), SALT, address(0));
        assertEq(id1, id2);
    }

    function test_computeChannelId_differentSaltDifferentId() public view {
        bytes32 id1 = channel.computeChannelId(payer, payee, address(token), SALT, address(0));
        bytes32 id2 =
            channel.computeChannelId(payer, payee, address(token), bytes32(uint256(2)), address(0));
        assertTrue(id1 != id2);
    }

    function test_domainSeparator_nonZero() public view {
        assertTrue(channel.domainSeparator() != bytes32(0));
    }

    // --- Settle Access Control Tests ---

    function test_settle_revert_payerCannotSettle() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.NotPayee.selector);
        channel.settle(channelId, 500_000, sig);
    }

    function test_settle_revert_thirdParty() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        address stranger = makeAddr("stranger");
        vm.prank(stranger);
        vm.expectRevert(TempoStreamChannel.NotPayee.selector);
        channel.settle(channelId, 500_000, sig);
    }

    // --- Cross-Contract / Cross-Chain Replay Tests ---

    function test_settle_revert_crossContractReplay() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        TempoStreamChannel channel2 = new TempoStreamChannel();
        TIP20 token2 = TIP20(
            factory.createToken("Stream Token 2", "ST2", "USD", pathUSD, admin, bytes32("stream2"))
        );

        vm.startPrank(admin);
        token2.grantRole(_ISSUER_ROLE, admin);
        token2.mint(payer, 10_000_000);
        vm.stopPrank();

        vm.prank(payer);
        token2.approve(address(channel2), type(uint256).max);

        vm.prank(payer);
        bytes32 channelId2 = channel2.open(payee, address(token2), DEPOSIT, SALT, address(0));

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.InvalidSignature.selector);
        channel2.settle(channelId2, 500_000, sig);
    }

    function test_settle_revert_crossChainReplay() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        uint256 originalChainId = block.chainid;
        vm.chainId(originalChainId + 1);

        TempoStreamChannel channel2 = new TempoStreamChannel();
        TIP20 token2 = TIP20(
            factory.createToken("Stream Token 3", "ST3", "USD", pathUSD, admin, bytes32("stream3"))
        );

        vm.startPrank(admin);
        token2.grantRole(_ISSUER_ROLE, admin);
        token2.mint(payer, 10_000_000);
        vm.stopPrank();

        vm.prank(payer);
        token2.approve(address(channel2), type(uint256).max);

        vm.prank(payer);
        bytes32 channelId2 = channel2.open(payee, address(token2), DEPOSIT, SALT, address(0));

        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.InvalidSignature.selector);
        channel2.settle(channelId2, 500_000, sig);

        vm.chainId(originalChainId);
    }

    // --- Zero Deposit Edge Case ---

    function test_open_zeroDeposit() public {
        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), 0, bytes32(uint256(99)), address(0));

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertEq(ch.deposit, 0);
        assertEq(ch.settled, 0);
        assertFalse(ch.finalized);

        bytes memory sig = _signVoucher(channelId, 1);
        vm.prank(payee);
        vm.expectRevert(TempoStreamChannel.AmountExceedsDeposit.selector);
        channel.settle(channelId, 1, sig);

        vm.prank(payee);
        channel.close(channelId, 0, "");
        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), 10_000_000);
    }

    // --- Close No-Op Settlement Path ---

    function test_close_noopWhenCumulativeEqualsSettled() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, 600_000);
        vm.prank(payee);
        channel.settle(channelId, 600_000, sig);

        uint256 payeeBalanceBefore = token.balanceOf(payee);
        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 600_000, "");

        assertEq(token.balanceOf(payee), payeeBalanceBefore);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 600_000));
        assertTrue(channel.getChannel(channelId).finalized);
    }

    function test_close_noopZeroCumulativeZeroSettled() public {
        bytes32 channelId = _openChannel();

        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 0, "");

        assertEq(token.balanceOf(payee), 0);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
        assertTrue(channel.getChannel(channelId).finalized);
    }

    // --- Fuzz Tests ---

    function testFuzz_settle_monotonic(uint128 amount1, uint128 amount2) public {
        vm.assume(amount1 > 0 && amount1 < DEPOSIT);
        vm.assume(amount2 > amount1 && amount2 <= DEPOSIT);

        bytes32 channelId = _openChannel();

        bytes memory sig1 = _signVoucher(channelId, amount1);
        vm.prank(payee);
        channel.settle(channelId, amount1, sig1);
        assertEq(channel.getChannel(channelId).settled, amount1);

        bytes memory sig2 = _signVoucher(channelId, amount2);
        vm.prank(payee);
        channel.settle(channelId, amount2, sig2);
        assertEq(channel.getChannel(channelId).settled, amount2);
    }

    function testFuzz_conservation(uint128 depositAmt, uint128 settleAmt) public {
        vm.assume(depositAmt > 0 && depositAmt <= 5_000_000);
        vm.assume(settleAmt > 0 && settleAmt <= depositAmt);

        vm.startPrank(admin);
        token.mint(payer, depositAmt);
        vm.stopPrank();

        bytes32 salt = bytes32(uint256(block.timestamp));

        uint256 totalBefore =
            token.balanceOf(payer) + token.balanceOf(payee) + token.balanceOf(address(channel));

        vm.prank(payer);
        bytes32 channelId = channel.open(payee, address(token), depositAmt, salt, address(0));

        bytes memory sig = _signVoucher(channelId, settleAmt);
        vm.prank(payee);
        channel.close(channelId, settleAmt, sig);

        uint256 totalAfter =
            token.balanceOf(payer) + token.balanceOf(payee) + token.balanceOf(address(channel));

        assertEq(totalAfter, totalBefore);
    }

    // --- TopUp Overflow Tests ---

    function test_topUp_revert_overflowUint128() public {
        bytes32 channelId = _openChannel();

        uint256 tooLarge = uint256(type(uint128).max);
        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.DepositOverflow.selector);
        channel.topUp(channelId, tooLarge);
    }

    function test_topUp_revert_overflowExact() public {
        bytes32 channelId = _openChannel();

        uint256 maxAdditional = uint256(type(uint128).max) - DEPOSIT;
        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.DepositOverflow.selector);
        channel.topUp(channelId, maxAdditional + 1);
    }

    // --- Settle Exact Deposit ---

    function test_settle_exactDeposit() public {
        bytes32 channelId = _openChannel();

        bytes memory sig = _signVoucher(channelId, DEPOSIT);
        vm.prank(payee);
        channel.settle(channelId, DEPOSIT, sig);

        assertEq(channel.getChannel(channelId).settled, DEPOSIT);
        assertEq(token.balanceOf(payee), DEPOSIT);
        assertEq(token.balanceOf(address(channel)), 0);
    }

    // --- InvalidPayee Tests ---

    function test_open_revert_zeroPayee() public {
        vm.prank(payer);
        vm.expectRevert(TempoStreamChannel.InvalidPayee.selector);
        channel.open(address(0), address(token), DEPOSIT, SALT, address(0));
    }

}
