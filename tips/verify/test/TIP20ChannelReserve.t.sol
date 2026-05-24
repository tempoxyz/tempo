// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { TIP20ChannelReserve } from "../src/TIP20ChannelReserve.sol";
import { ITIP20ChannelReserve } from "../src/interfaces/ITIP20ChannelReserve.sol";
import { MockTIP20 } from "./mocks/MockTIP20.sol";
import { Test } from "forge-std/Test.sol";

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

contract TIP20ChannelReserveTest is Test {

    TIP20ChannelReserve public channel;
    MockTIP20 public token;

    address public payer;
    uint256 public payerKey;
    address public payee;
    bytes32 internal lastExpiringNonceHash;
    uint256 internal expiringNonceCounter;

    uint96 internal constant DEPOSIT = 1_000_000;
    bytes32 internal constant SALT = bytes32(uint256(1));

    function setUp() public {
        channel = new TIP20ChannelReserve();
        MockSignatureVerifier verifier = new MockSignatureVerifier();
        vm.etch(channel.SIGNATURE_VERIFIER_PRECOMPILE(), address(verifier).code);
        token = new MockTIP20("Stream Token", "STR", 20_000_000);

        (payer, payerKey) = makeAddrAndKey("payer");
        payee = makeAddr("payee");

        token.transfer(payer, 20_000_000);

        vm.prank(payer);
        token.approve(address(channel), type(uint256).max);
    }

    function _openChannel() internal returns (bytes32) {
        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        return channel.open(payee, address(0), address(token), DEPOSIT, SALT, address(0));
    }

    function _descriptor() internal view returns (ITIP20ChannelReserve.ChannelDescriptor memory) {
        return _descriptor(SALT, address(0), lastExpiringNonceHash);
    }

    function _descriptor(
        bytes32 salt,
        address authorizedSigner
    )
        internal
        view
        returns (ITIP20ChannelReserve.ChannelDescriptor memory)
    {
        return _descriptor(salt, authorizedSigner, lastExpiringNonceHash);
    }

    function _descriptor(
        bytes32 salt,
        address authorizedSigner,
        bytes32 expiringNonceHash
    )
        internal
        view
        returns (ITIP20ChannelReserve.ChannelDescriptor memory)
    {
        return _descriptorWithOperator(salt, address(0), authorizedSigner, expiringNonceHash);
    }

    function _descriptorWithOperator(
        bytes32 salt,
        address operator,
        address authorizedSigner,
        bytes32 expiringNonceHash
    )
        internal
        view
        returns (ITIP20ChannelReserve.ChannelDescriptor memory)
    {
        return ITIP20ChannelReserve.ChannelDescriptor({
            payer: payer,
            payee: payee,
            operator: operator,
            token: address(token),
            salt: salt,
            authorizedSigner: authorizedSigner,
            expiringNonceHash: expiringNonceHash
        });
    }

    function _prepareNextExpiringNonceHash() internal returns (bytes32 expiringNonceHash) {
        expiringNonceHash = keccak256(abi.encodePacked("open", ++expiringNonceCounter));
        channel.setExpiringNonceHashForTest(expiringNonceHash);
        lastExpiringNonceHash = expiringNonceHash;
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
        bytes32 expiringNonceHash = _prepareNextExpiringNonceHash();

        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(0), address(token), DEPOSIT, SALT, address(0));

        ITIP20ChannelReserve.Channel memory ch = channel.getChannel(_descriptor());
        assertEq(ch.descriptor.payer, payer);
        assertEq(ch.descriptor.payee, payee);
        assertEq(ch.descriptor.operator, address(0));
        assertEq(ch.descriptor.token, address(token));
        assertEq(ch.descriptor.authorizedSigner, address(0));
        assertEq(ch.descriptor.expiringNonceHash, expiringNonceHash);
        assertEq(ch.state.settled, 0);
        assertEq(ch.state.deposit, DEPOSIT);
        assertEq(ch.state.closeRequestedAt, 0);
        assertEq(channel.getChannelState(channelId).deposit, DEPOSIT);
    }

    function test_open_revert_zeroPayee() public {
        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelReserve.InvalidPayee.selector);
        channel.open(address(0), address(0), address(token), DEPOSIT, SALT, address(0));
    }

    function test_open_revert_tip20PrefixPayee() public {
        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelReserve.InvalidPayee.selector);
        channel.open(
            address(0x20C0000000000000000000000000000000000001),
            address(0),
            address(token),
            DEPOSIT,
            SALT,
            address(0)
        );
    }

    function test_open_revert_zeroToken() public {
        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelReserve.InvalidToken.selector);
        channel.open(payee, address(0), address(0), DEPOSIT, SALT, address(0));
    }

    function test_open_revert_zeroDeposit() public {
        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelReserve.ZeroDeposit.selector);
        channel.open(payee, address(0), address(token), 0, SALT, address(0));
    }

    function test_open_same_descriptor_uses_distinct_expiring_nonce_hashes() public {
        bytes32 channelId1 = _openChannel();
        bytes32 expiringNonceHash1 = lastExpiringNonceHash;

        bytes32 channelId2 = _openChannel();
        bytes32 expiringNonceHash2 = lastExpiringNonceHash;

        assertNotEq(expiringNonceHash1, expiringNonceHash2);
        assertNotEq(channelId1, channelId2);
    }

    function test_open_allows_distinct_channel_ids_with_same_expiring_nonce_hash() public {
        bytes32 sharedExpiringNonceHash = keccak256("same top-level tx");

        channel.setExpiringNonceHashForTest(sharedExpiringNonceHash);
        vm.prank(payer);
        bytes32 channelId1 =
            channel.open(payee, address(0), address(token), DEPOSIT, SALT, address(0));

        channel.setExpiringNonceHashForTest(sharedExpiringNonceHash);
        vm.prank(payer);
        bytes32 channelId2 = channel.open(
            payee, address(0), address(token), DEPOSIT, bytes32(uint256(2)), address(0)
        );

        // Same top-level transaction means the same expiringNonceHash, but distinct descriptors
        // still derive independent channel IDs and are safe to open atomically in one AA batch.
        assertNotEq(channelId1, channelId2);
        assertEq(channel.getChannelState(channelId1).deposit, DEPOSIT);
        assertEq(channel.getChannelState(channelId2).deposit, DEPOSIT);
    }

    function test_settle_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 500_000, sig);

        assertEq(channel.getChannelState(channelId).settled, 500_000);
        assertEq(token.balanceOf(payee), 500_000);
    }

    function test_settle_revert_invalidSignature() public {
        bytes32 channelId = _openChannel();
        (, uint256 wrongKey) = makeAddrAndKey("wrong");
        bytes memory sig = _signVoucher(channelId, 500_000, wrongKey);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelReserve.InvalidSignature.selector);
        channel.settle(_descriptor(), 500_000, sig);
    }

    function test_settle_revert_wrongDescriptor() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelReserve.ChannelNotFound.selector);
        channel.settle(_descriptor(bytes32(uint256(2)), address(0)), 500_000, sig);
    }

    function test_authorizedSigner_settleSuccess() public {
        (address delegateSigner, uint256 delegateKey) = makeAddrAndKey("delegate");

        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        bytes32 channelId =
            channel.open(payee, address(0), address(token), DEPOSIT, SALT, delegateSigner);

        bytes memory sig = _signVoucher(channelId, 500_000, delegateKey);

        vm.prank(payee);
        channel.settle(_descriptor(SALT, delegateSigner), 500_000, sig);

        assertEq(channel.getChannelState(channelId).settled, 500_000);
    }

    function test_operator_settleSuccess() public {
        address operator = makeAddr("operator");

        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        bytes32 channelId = channel.open(payee, operator, address(token), DEPOSIT, SALT, address(0));

        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(operator);
        channel.settle(
            _descriptorWithOperator(SALT, operator, address(0), lastExpiringNonceHash), 500_000, sig
        );

        assertEq(channel.getChannelState(channelId).settled, 500_000);
        assertEq(token.balanceOf(payee), 500_000);
    }

    function test_operator_zeroDoesNotAuthorizeArbitrarySettler() public {
        address operator = makeAddr("operator");
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 500_000);

        vm.prank(operator);
        vm.expectRevert(ITIP20ChannelReserve.NotPayeeOrOperator.selector);
        channel.settle(_descriptor(), 500_000, sig);
    }

    function test_topUp_updatesDeposit() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.topUp(_descriptor(), 250_000);

        ITIP20ChannelReserve.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.deposit, DEPOSIT + 250_000);
    }

    function test_topUp_cancelsCloseRequest() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(_descriptor());

        vm.prank(payer);
        channel.topUp(_descriptor(), 100_000);

        assertEq(channel.getChannelState(channelId).closeRequestedAt, 0);
    }

    function test_requestClose_storesTimestampInCloseRequestedAt() public {
        bytes32 channelId = _openChannel();
        uint32 closeRequestedAt = uint32(block.timestamp);

        vm.prank(payer);
        channel.requestClose(_descriptor());

        ITIP20ChannelReserve.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.closeRequestedAt, closeRequestedAt);

        uint256 raw = uint256(vm.load(address(channel), _channelStateSlot(channelId)));
        assertEq(uint32(raw >> 192), closeRequestedAt);
    }

    function test_close_partialCapture_success() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 900_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);
        uint256 payerBalanceBefore = token.balanceOf(payer);

        vm.prank(payee);
        channel.close(_descriptor(), 900_000, 600_000, sig);

        ITIP20ChannelReserve.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.settled, 0);
        assertEq(ch.closeRequestedAt, 0);
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
        assertEq(channel.getChannelState(channelId).settled, 0);
    }

    function test_close_allowsVoucherAmountAboveDepositWhenCaptureWithinDeposit() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, DEPOSIT + 250_000);

        uint256 payeeBalanceBefore = token.balanceOf(payee);

        vm.prank(payee);
        channel.close(_descriptor(), DEPOSIT + 250_000, DEPOSIT, sig);

        ITIP20ChannelReserve.ChannelState memory ch = channel.getChannelState(channelId);
        assertEq(ch.settled, 0);
        assertEq(ch.closeRequestedAt, 0);
        assertEq(token.balanceOf(payee), payeeBalanceBefore + DEPOSIT);
    }

    function test_close_revert_invalidCaptureAmount() public {
        bytes32 channelId = _openChannel();
        bytes memory settleSig = _signVoucher(channelId, 300_000);

        vm.prank(payee);
        channel.settle(_descriptor(), 300_000, settleSig);

        vm.prank(payee);
        vm.expectRevert(ITIP20ChannelReserve.CaptureAmountInvalid.selector);
        channel.close(_descriptor(), 300_000, 200_000, "");
    }

    function test_close_clears_state_and_allows_reopen_with_new_expiring_nonce_hash() public {
        bytes32 channelId = _openChannel();
        bytes memory sig = _signVoucher(channelId, 600_000);
        bytes32 originalExpiringNonceHash = lastExpiringNonceHash;

        vm.prank(payee);
        channel.close(_descriptor(), 600_000, 600_000, sig);

        assertEq(channel.getChannelState(channelId).closeRequestedAt, 0);

        // Reusing the original expiringNonceHash approximates a later call in the same top-level AA batch.
        // The persistent channel slot has been deleted by close, so the per-transaction opened-ID
        // guard is what prevents reopening the same channel ID before the transaction ends.
        channel.setExpiringNonceHashForTest(originalExpiringNonceHash);
        vm.prank(payer);
        vm.expectRevert(ITIP20ChannelReserve.ChannelAlreadyExists.selector);
        channel.open(payee, address(0), address(token), DEPOSIT, SALT, address(0));

        // A later transaction has a fresh expiringNonceHash, so the same logical descriptor derives
        // a new channel ID and may be opened after the previous channel terminally closed.
        bytes32 reopenedChannelId = _openChannel();
        assertNotEq(reopenedChannelId, channelId);
    }

    function test_withdraw_afterGracePeriod() public {
        bytes32 channelId = _openChannel();

        vm.prank(payer);
        channel.requestClose(_descriptor());

        vm.warp(block.timestamp + channel.CLOSE_GRACE_PERIOD() + 1);

        uint256 payerBalanceBefore = token.balanceOf(payer);
        vm.prank(payer);
        channel.withdraw(_descriptor());

        assertEq(channel.getChannelState(channelId).closeRequestedAt, 0);
        assertEq(token.balanceOf(payer), payerBalanceBefore + DEPOSIT);
    }

    function test_getChannelStatesBatch_success() public {
        bytes32 channelId1 = _openChannel();
        bytes32 channel1ExpiringNonceHash = lastExpiringNonceHash;

        _prepareNextExpiringNonceHash();
        vm.prank(payer);
        bytes32 channelId2 = channel.open(
            payee, address(0), address(token), DEPOSIT, bytes32(uint256(2)), address(0)
        );

        bytes memory sig = _signVoucher(channelId1, 400_000);
        vm.prank(payee);
        channel.settle(_descriptor(SALT, address(0), channel1ExpiringNonceHash), 400_000, sig);

        bytes32[] memory ids = new bytes32[](2);
        ids[0] = channelId1;
        ids[1] = channelId2;

        ITIP20ChannelReserve.ChannelState[] memory states = channel.getChannelStatesBatch(ids);
        assertEq(states.length, 2);
        assertEq(states[0].settled, 400_000);
        assertEq(states[1].settled, 0);
    }

    function test_computeChannelId_usesFixedPrecompileAddress() public {
        TIP20ChannelReserve other = new TIP20ChannelReserve();
        bytes32 expiringNonceHash = keccak256("expiringNonceHash");

        bytes32 id1 = channel.computeChannelId(
            payer, payee, address(0), address(token), SALT, address(0), expiringNonceHash
        );
        bytes32 id2 = other.computeChannelId(
            payer, payee, address(0), address(token), SALT, address(0), expiringNonceHash
        );

        assertEq(id1, id2);
        assertEq(channel.domainSeparator(), other.domainSeparator());
    }

}
