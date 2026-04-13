// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { TIP20 } from "../src/TIP20.sol";
import { TempoStreamChannel } from "../src/TempoStreamChannel.sol";
import { ITempoStreamChannel } from "../src/interfaces/ITempoStreamChannel.sol";
import { BaseTest } from "./BaseTest.t.sol";

contract MockSignatureVerifier {

    error InvalidFormat();
    error InvalidSignature();

    function recover(bytes32 hash, bytes calldata signature)
        external
        pure
        returns (address signer)
    {
        return _recover(hash, signature);
    }

    function verify(
        address signer,
        bytes32 hash,
        bytes calldata signature
    )
        external
        pure
        returns (bool)
    {
        return _recover(hash, signature) == signer;
    }

    function _recover(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        pure
        returns (address signer)
    {
        if (signature.length != 65) revert InvalidSignature();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();

        signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
    }

}

contract TempoStreamChannelTest is BaseTest {

    TempoStreamChannel public channel;
    TIP20 public token;

    address public payer;
    uint256 public payerKey;
    address public payee;

    uint128 internal constant DEPOSIT = 1_000_000;
    bytes32 internal constant SALT = bytes32(uint256(1));

    function setUp() public override {
        super.setUp();

        channel = new TempoStreamChannel();
        MockSignatureVerifier verifier = new MockSignatureVerifier();
        vm.etch(channel.SIGNATURE_VERIFIER_PRECOMPILE(), address(verifier).code);
        token = TIP20(
            factory.createToken("Stream Token", "STR", "USD", pathUSD, admin, bytes32("stream"))
        );

        (payer, payerKey) = makeAddrAndKey("payer");
        payee = makeAddr("payee");

        vm.startPrank(admin);
        token.grantRole(_ISSUER_ROLE, admin);
        token.mint(payer, 20_000_000);
        vm.stopPrank();

        vm.prank(payer);
        token.approve(address(channel), type(uint256).max);
    }

    function _defaultExpiry() internal view returns (uint64) {
        return uint64(block.timestamp + 1 days);
    }

    function _openChannel() internal returns (bytes32) {
        vm.prank(payer);
        return channel.open(payee, address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function _openChannelWithExpiry(uint64 expiresAt) internal returns (bytes32) {
        vm.prank(payer);
        return channel.open(payee, address(token), DEPOSIT, SALT, address(0), expiresAt);
    }

    function _signVoucher(bytes32 channelId, uint128 amount) internal view returns (bytes memory) {
        return _signVoucher(channelId, amount, payerKey);
    }

    function _signVoucher(
        bytes32 channelId,
        uint128 amount,
        uint256 signerKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = channel.getVoucherDigest(channelId, amount);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_open_success() public {
        uint64 expiresAt = _defaultExpiry();

        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(token), DEPOSIT, SALT, address(0), expiresAt);

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertFalse(ch.finalized);
        assertEq(ch.closeRequestedAt, 0);
        assertEq(ch.payer, payer);
        assertEq(ch.payee, payee);
        assertEq(ch.expiresAt, expiresAt);
        assertEq(ch.token, address(token));
        assertEq(ch.authorizedSigner, address(0));
        assertEq(ch.deposit, DEPOSIT);
        assertEq(ch.settled, 0);
    }

    function test_open_revert_zeroPayee() public {
        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.InvalidPayee.selector);
        channel.open(address(0), address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_zeroToken() public {
        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.InvalidToken.selector);
        channel.open(payee, address(0), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_zeroDeposit() public {
        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.ZeroDeposit.selector);
        channel.open(payee, address(token), 0, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_invalidExpiry() public {
        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.InvalidExpiry.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0), uint64(block.timestamp));
    }

    function test_open_revert_duplicate() public {
        _openChannel();

        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.ChannelAlreadyExists.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_settle_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        assertEq(channel.getChannel(channelId).settled, 500_000);
        assertEq(token.balanceOf(payee), 500_000);
    }

    function test_settle_revert_afterExpiry() public {
        bytes32 channelId = _openChannelWithExpiry(uint64(block.timestamp + 10));
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.warp(block.timestamp + 10);
        vm.prank(payee);
        vm.expectRevert(ITempoStreamChannel.ChannelExpiredError.selector);
        channel.settle(channelId, 500_000, sig);
    }

    function test_settle_revert_invalidSignature() public {
        bytes32 channelId = _openChannel();
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes memory sig = _signVoucher(channelId, 500_000, wrongKey);

        vm.prank(payee);
        vm.expectRevert(ITempoStreamChannel.InvalidSignature.selector);
        channel.settle(channelId, 500_000, sig);
    }

    function test_authorizedSigner_settleSuccess() public {
        (address delegateSigner, uint256 delegateKey) = makeAddrAndKey("delegate");

        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(token), DEPOSIT, SALT, delegateSigner, _defaultExpiry());

        bytes memory sig = _signVoucher(channelId, 500_000, delegateKey);

        vm.prank(payee);
        channel.settle(channelId, 500_000, sig);

        assertEq(channel.getChannel(channelId).settled, 500_000);
    }

    function test_topUp_updatesDepositAndExpiry() public {
        bytes32 channelId = _openChannel();
        uint64 nextExpiry = uint64(block.timestamp + 2 days);

        vm.prank(payer);
        channel.topUp(channelId, 250_000, nextExpiry);

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertEq(ch.deposit, DEPOSIT + 250_000);
        assertEq(ch.expiresAt, nextExpiry);
    }

    function test_topUp_revert_nonIncreasingExpiry() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        vm.expectRevert(ITempoStreamChannel.InvalidExpiry.selector);
        channel.topUp(channelId, 0, _defaultExpiry());
    }

    function test_topUp_cancelsCloseRequest() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.prank(payer);
        channel.topUp(channelId, 100_000, 0);

        assertEq(channel.getChannel(channelId).closeRequestedAt, 0);
    }

    function test_close_partialCapture_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 900_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);
        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(channelId, 900_000, 600_000, sig);

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertTrue(ch.finalized);
        assertEq(ch.settled, 600_000);
        assertEq(token.balanceOf(payee), payeeBalanceBefore + 600_000);
        assertEq(token.balanceOf(payer), payerBalanceBefore + 400_000);
    }

    function test_close_usesPreviousSettledForDelta() public {
        bytes32 channelId = _openChannel();
        bytes memory settleSig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(channelId, 300_000, settleSig);

        bytes memory closeSig = _signVoucher(channelId, 800_000);
        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(channelId, 800_000, 500_000, closeSig);

        assertEq(token.balanceOf(payee), payeeBalanceBefore + 200_000);
        assertEq(channel.getChannel(channelId).settled, 500_000);
    }

    function test_close_allowsVoucherAmountAboveDepositWhenCaptureWithinDeposit() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, DEPOSIT + 250_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(channelId, DEPOSIT + 250_000, DEPOSIT, sig);

        TempoStreamChannel.Channel memory ch = channel.getChannel(channelId);
        assertTrue(ch.finalized);
        assertEq(ch.settled, DEPOSIT);
        assertEq(token.balanceOf(payee), payeeBalanceBefore + DEPOSIT);
    }

    function test_close_revert_invalidCaptureAmount() public {
        bytes32 channelId = _openChannel();
        bytes memory settleSig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(channelId, 300_000, settleSig);

        vm.prank(payee);
        vm.expectRevert(ITempoStreamChannel.CaptureAmountInvalid.selector);
        channel.close(channelId, 300_000, 200_000, "");
    }

    function test_close_afterExpiry_allowsNoAdditionalCapture() public {
        bytes32 channelId = _openChannelWithExpiry(uint64(block.timestamp + 10));
        bytes memory sig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(channelId, 300_000, sig);

        vm.warp(block.timestamp + 10);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payee);
        channel.close(channelId, 300_000, 300_000, "");

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 300_000));
    }

    function test_withdraw_afterGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(channelId);

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(channelId);

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
    }

    function test_withdraw_afterExpiryWithoutCloseRequest() public {
        bytes32 channelId = _openChannelWithExpiry(uint64(block.timestamp + 10));

        vm.warp(block.timestamp + 10);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(channelId);

        assertTrue(channel.getChannel(channelId).finalized);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
    }

    function test_getChannelsBatch_success() public {
        bytes32 channelId1 = _openChannel();

        vm.prank(payer);
        bytes32 channelId2 = channel.open(
            payee, address(token), DEPOSIT, bytes32(uint256(2)), address(0), _defaultExpiry()
        );

        bytes memory sig = _signVoucher(channelId1, 400_000);
        vm.prank(payee);
        channel.settle(channelId1, 400_000, sig);

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = channelId1;
        ids[1] = channelId2;

        TempoStreamChannel.Channel[] memory states = channel.getChannelsBatch(ids);
        assertEq(states.length, 2);
        assertEq(states[0].settled, 400_000);
        assertEq(states[1].settled, 0);
    }

    function test_computeChannelId_usesFixedPrecompileAddress() public {
        TempoStreamChannel other = new TempoStreamChannel();

        bytes32 id1 = channel.computeChannelId(payer, payee, address(token), SALT, address(0));
        bytes32 id2 = other.computeChannelId(payer, payee, address(token), SALT, address(0));

        assertEq(id1, id2);
        assertEq(channel.domainSeparator(), other.domainSeparator());
    }

}
