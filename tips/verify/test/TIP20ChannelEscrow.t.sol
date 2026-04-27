// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { TIP20 } from "../src/TIP20.sol";
import { TIP20ChannelEscrow } from "../src/TIP20ChannelEscrow.sol";
import { ITIP20ChannelEscrow } from "../src/interfaces/ITIP20ChannelEscrow.sol";
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

contract TIP20ChannelEscrowTest is BaseTest {

    TIP20ChannelEscrow public channel;
    TIP20 public token;

    address public payer;
    uint256 public payerKey;
    address public payee;

    uint96 internal constant DEPOSIT = 1_000_000;
    bytes32 internal constant SALT = bytes32(uint256(1));

    function setUp() public override {
        super.setUp();

        channel = new TIP20ChannelEscrow();
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

    function _defaultExpiry() internal view returns (uint32) {
        return uint32(block.timestamp + 1 days);
    }

    function _openChannel() internal returns (bytes32) {
        vm.prank(payer);
        return channel.open(payee, address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function _openChannelWithExpiry(uint32 expiresAt) internal returns (bytes32) {
        vm.prank(payer);
        return channel.open(payee, address(token), DEPOSIT, SALT, address(0), expiresAt);
    }

    function _descriptor() internal view returns (ITIP20ChannelEscrow.ChannelDescriptor memory) {
        return _descriptor(SALT, address(0));
    }

    function _descriptor(
        bytes32 salt,
        address authorizedSigner
    )
        internal
        view
        returns (ITIP20ChannelEscrow.ChannelDescriptor memory)
    {
        return ITIP20ChannelEscrow.ChannelDescriptor({
            payer: payer,
            payee: payee,
            token: address(token),
            salt: salt,
            authorizedSigner: authorizedSigner
        });
    }

    function _channelStateSlot(bytes32 channelId) internal pure returns (bytes32) {
        return keccak256(abi.encode(channelId, uint256(0)));
    }

    function _signVoucher(bytes32 channelId, uint96 amount) internal view returns (bytes memory) {
        return _signVoucher(channelId, amount, payerKey);
    }

    function _signVoucher(
        bytes32 channelId,
        uint96 amount,
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
        uint32 expiresAt = _defaultExpiry();

        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(token), DEPOSIT, SALT, address(0), expiresAt);

        ITIP20ChannelEscrow.Channel memory ch = channel.getChannel(_descriptor());
        assertEq(ch.descriptor.payer, payer);
        assertEq(ch.descriptor.payee, payee);
        assertEq(ch.descriptor.token, address(token));
        assertEq(ch.descriptor.authorizedSigner, address(0));
        assertEq(ch.state.settled, 0);
        assertEq(ch.state.deposit, DEPOSIT);
        assertEq(ch.state.expiresAt, expiresAt);
        assertEq(ch.state.closeData, 0);
        assertEq(channel.getChannelState(channelId).deposit, DEPOSIT);
    }

    function test_open_revert_zeroPayee() public {
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.InvalidPayee.selector);
        channel.open(address(0), address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_zeroToken() public {
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.InvalidToken.selector);
        channel.open(payee, address(0), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_zeroDeposit() public {
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.ZeroDeposit.selector);
        channel.open(payee, address(token), 0, SALT, address(0), _defaultExpiry());
    }

    function test_open_revert_invalidExpiry() public {
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.InvalidExpiry.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0), uint32(block.timestamp));
    }

    function test_open_revert_duplicate() public {
        _openChannel();

        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.ChannelAlreadyExists.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_settle_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 500_000, sig);

        assertEq(channel.getChannelState(channelId).settled, 500_000);
        assertEq(token.balanceOf(payee), 500_000);
    }

    function test_settle_revert_afterExpiry() public {
        bytes32 channelId = _openChannelWithExpiry(uint32(block.timestamp + 10));
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.warp(block.timestamp + 10);
        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelEscrow.ChannelExpiredError.selector);
        channel.settle(_descriptor(), 500_000, sig);
    }

    function test_settle_revert_invalidSignature() public {
        bytes32 channelId = _openChannel();
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes memory sig = _signVoucher(channelId, 500_000, wrongKey);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelEscrow.InvalidSignature.selector);
        channel.settle(_descriptor(), 500_000, sig);
    }

    function test_settle_revert_wrongDescriptor() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelEscrow.ChannelNotFound.selector);
        channel.settle(_descriptor(bytes32(uint256(2)), address(0)), 500_000, sig);
    }

    function test_authorizedSigner_settleSuccess() public {
        (address delegateSigner, uint256 delegateKey) = makeAddrAndKey("delegate");

        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(token), DEPOSIT, SALT, delegateSigner, _defaultExpiry());

        bytes memory sig = _signVoucher(channelId, 500_000, delegateKey);

        vm.prank(payee);
        channel.settle(_descriptor(SALT, delegateSigner), 500_000, sig);

        assertEq(channel.getChannelState(channelId).settled, 500_000);
    }

    function test_topUp_updatesDepositAndExpiry() public {
        bytes32 channelId = _openChannel();
        uint32 nextExpiry = uint32(block.timestamp + 2 days);

        vm.prank(payer);
        channel.topUp(_descriptor(), 250_000, nextExpiry);

        ITIP20ChannelEscrow.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.deposit, DEPOSIT + 250_000);
        assertEq(ch.expiresAt, nextExpiry);
    }

    function test_topUp_revert_nonIncreasingExpiry() public {
        _openChannel();

        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.InvalidExpiry.selector);
        channel.topUp(_descriptor(), 0, _defaultExpiry());
    }

    function test_topUp_cancelsCloseRequest() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(_descriptor());

        vm.prank(payer);
        channel.topUp(_descriptor(), 100_000, 0);

        assertEq(channel.getChannelState(channelId).closeData, 0);
    }

    function test_requestClose_storesTimestampInCloseData() public {
        bytes32 channelId = _openChannel();
        uint32 closeRequestedAt = uint32(block.timestamp);

        vm.prank(payer);
        channel.requestClose(_descriptor());

        ITIP20ChannelEscrow.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.closeData, closeRequestedAt);

        uint256 raw = uint256(vm.load(address(channel), _channelStateSlot(channelId)));
        assertEq(uint32(raw >> 224), closeRequestedAt);
    }

    function test_close_partialCapture_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 900_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);
        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(_descriptor(), 900_000, 600_000, sig);

        ITIP20ChannelEscrow.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.settled, 600_000);
        assertEq(ch.closeData, 1);
        assertEq(token.balanceOf(payee), payeeBalanceBefore + 600_000);
        assertEq(token.balanceOf(payer), payerBalanceBefore + 400_000);
    }

    function test_close_usesPreviousSettledForDelta() public {
        bytes32 channelId = _openChannel();
        bytes memory settleSig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 300_000, settleSig);

        bytes memory closeSig = _signVoucher(channelId, 800_000);
        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(_descriptor(), 800_000, 500_000, closeSig);

        assertEq(token.balanceOf(payee), payeeBalanceBefore + 200_000);
        assertEq(channel.getChannelState(channelId).settled, 500_000);
    }

    function test_close_allowsVoucherAmountAboveDepositWhenCaptureWithinDeposit() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, DEPOSIT + 250_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(_descriptor(), DEPOSIT + 250_000, DEPOSIT, sig);

        ITIP20ChannelEscrow.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.settled, DEPOSIT);
        assertEq(ch.closeData, 1);
        assertEq(token.balanceOf(payee), payeeBalanceBefore + DEPOSIT);
    }

    function test_close_revert_invalidCaptureAmount() public {
        bytes32 channelId = _openChannel();
        bytes memory settleSig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 300_000, settleSig);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelEscrow.CaptureAmountInvalid.selector);
        channel.close(_descriptor(), 300_000, 200_000, "");
    }

    function test_close_afterExpiry_allowsNoAdditionalCapture() public {
        bytes32 channelId = _openChannelWithExpiry(uint32(block.timestamp + 10));
        bytes memory sig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 300_000, sig);

        vm.warp(block.timestamp + 10);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payee);
        channel.close(_descriptor(), 300_000, 300_000, "");

        assertEq(channel.getChannelState(channelId).closeData, 1);
        assertEq(token.balanceOf(payer), payerBalanceBefore + (DEPOSIT - 300_000));
    }

    function test_close_keepsTombstoneAndBlocksReopen() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 600_000);

        vm.prank(payee);
        channel.close(_descriptor(), 600_000, 600_000, sig);

        assertEq(channel.getChannelState(channelId).closeData, 1);

        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelEscrow.ChannelAlreadyExists.selector);
        channel.open(payee, address(token), DEPOSIT, SALT, address(0), _defaultExpiry());
    }

    function test_withdraw_afterGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(_descriptor());

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(_descriptor());

        assertEq(channel.getChannelState(channelId).closeData, 1);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
    }

    function test_withdraw_afterExpiryWithoutCloseRequest() public {
        bytes32 channelId = _openChannelWithExpiry(uint32(block.timestamp + 10));

        vm.warp(block.timestamp + 10);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(_descriptor());

        assertEq(channel.getChannelState(channelId).closeData, 1);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
    }

    function test_getChannelStatesBatch_success() public {
        bytes32 channelId1 = _openChannel();

        vm.prank(payer);
        bytes32 channelId2 = channel.open(
            payee, address(token), DEPOSIT, bytes32(uint256(2)), address(0), _defaultExpiry()
        );

        bytes memory sig = _signVoucher(channelId1, 400_000);
        vm.prank(payee);
        channel.settle(_descriptor(), 400_000, sig);

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = channelId1;
        ids[1] = channelId2;

        ITIP20ChannelEscrow.ChannelState[] memory states = channel.getChannelStatesBatch(ids);
        assertEq(states.length, 2);
        assertEq(states[0].settled, 400_000);
        assertEq(states[1].settled, 0);
    }

    function test_computeChannelId_usesFixedPrecompileAddress() public {
        TIP20ChannelEscrow other = new TIP20ChannelEscrow();

        bytes32 id1 = channel.computeChannelId(payer, payee, address(token), SALT, address(0));
        bytes32 id2 = other.computeChannelId(payer, payee, address(token), SALT, address(0));

        assertEq(id1, id2);
        assertEq(channel.domainSeparator(), other.domainSeparator());
    }

}
