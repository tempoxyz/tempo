// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    Capability,
    DepositQueueTransition,
    IWithdrawalReceiver,
    IZoneFactory,
    IZonePortal,
    QueuedWithdrawal,
    Withdrawal,
    WithdrawalBounceBackDeposit,
    ZONE_FACTORY_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { DepositQueueLib } from "../../src/runtime/libraries/DepositQueueLib.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { StdPrecompiles } from "tempo-std/StdPrecompiles.sol";

/// @notice Callback receiver that rejects any delivery that arrives with less than its gasLimit.
contract GasCheckingReceiver is IWithdrawalReceiver {

    uint256 public immutable minimumGas;
    /// @dev Starts at 1 so counting a call never creates a storage slot.
    uint256 internal _calls = 1;

    constructor(uint256 _minimumGas) {
        minimumGas = _minimumGas;
    }

    function calls() external view returns (uint256) {
        return _calls - 1;
    }

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        returns (bytes4)
    {
        require(gasleft() >= minimumGas, "underfunded callback");
        ++_calls;
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

/// @notice Callback receiver that claims its own parked refund while its callback runs.
contract RefundClaimingReceiver is IWithdrawalReceiver {

    IZonePortal public immutable portal;
    address public immutable token;
    /// @dev Starts nonzero so recording a claim never creates a storage slot.
    uint256 public claimed = type(uint256).max;

    constructor(IZonePortal _portal, address _token) {
        portal = _portal;
        token = _token;
    }

    function onWithdrawalReceived(
        uint32,
        address,
        bytes32,
        address,
        uint128,
        bytes calldata
    )
        external
        returns (bytes4)
    {
        claimed = portal.claimRefund(token);
        return IWithdrawalReceiver.onWithdrawalReceived.selector;
    }

}

/// @notice TIP-1150 per-token withdrawal limits and per-token withdrawal queues.
contract ZonePortalWithdrawalLimitTest is BaseTest {

    bytes32 internal constant TOKEN_CURSOR_SLOT = bytes32(uint256(28));
    bytes32 internal constant DEPOSIT_COUNTERS_SLOT = bytes32(uint256(4));
    uint256 internal constant WITHDRAWAL_LIMITS_SLOT = 32;
    uint256 internal constant QUEUED_WITHDRAWALS_SLOT = 33;
    uint128 internal constant MAX = 1000e6;
    uint64 internal constant PERIOD = 1000; // refills 1e6 units per second
    uint64 internal constant CALLBACK_GAS = 200_000;

    ZonePortal internal portal;
    address internal limitAuthority = address(0xA11CE);
    address internal anyone = address(0xBEEF);
    GasCheckingReceiver internal receiver;

    function setUp() public override {
        super.setUp();

        address[] memory sequencers = new address[](1);
        sequencers[0] = sequencer;
        portal = _createZonePortal(1, address(pathUSD), admin, sequencers, 1, "https://rpc.example");

        vm.mockCall(
            ZONE_FACTORY_ADDRESS, abi.encodeCall(IZoneFactory.owner, ()), abi.encode(limitAuthority)
        );

        // Authenticate the enabled-token cursor so a second token can be enabled.
        vm.store(address(portal), TOKEN_CURSOR_SLOT, bytes32(uint256(1) | (uint256(1) << 64)));
        _mockTokenPolicyMigration(address(token1), true);
        vm.prank(admin);
        portal.enableToken(address(token1));

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(address(portal), 100_000e6);
        vm.stopPrank();
        token1.grantRole(_ISSUER_ROLE, address(this));
        token1.mint(address(portal), 100_000e6);

        receiver = new GasCheckingReceiver(CALLBACK_GAS - 5000);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _plain(
        address token,
        address to,
        uint128 amount
    )
        internal
        view
        returns (Withdrawal memory)
    {
        return Withdrawal({
            token: token,
            senderTag: keccak256(abi.encode(amount, to, token)),
            to: to,
            amount: amount,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: uint64(uint160(alice)),
            callbackData: "",
            encryptedSender: ""
        });
    }

    function _callback(uint128 amount) internal view returns (Withdrawal memory w) {
        w = _plain(address(pathUSD), address(receiver), amount);
        w.gasLimit = CALLBACK_GAS;
        w.callbackData = "cb";
    }

    function _depositBounceBack(uint128 amount) internal view returns (Withdrawal memory w) {
        w = _plain(address(pathUSD), alice, amount);
        w.fallbackNonce = 0;
    }

    function _one(Withdrawal memory w) internal pure returns (Withdrawal[] memory ws) {
        ws = new Withdrawal[](1);
        ws[0] = w;
    }

    function _two(
        Withdrawal memory a,
        Withdrawal memory b
    )
        internal
        pure
        returns (Withdrawal[] memory ws)
    {
        ws = new Withdrawal[](2);
        ws[0] = a;
        ws[1] = b;
    }

    /// @dev Settles one batch carrying ws and processes it through the main queue.
    function _withdraw(Withdrawal[] memory ws) internal {
        _settle(ws);
        portal.processWithdrawals(ws, bytes32(0));
    }

    /// @dev Settles one batch carrying ws into the main withdrawal queue.
    function _settle(Withdrawal[] memory ws) internal {
        bytes32 queueHash;
        for (uint256 i = ws.length; i > 0; --i) {
            queueHash = keccak256(abi.encode(ws[i - 1], queueHash));
        }
        vm.roll(block.number + 1);
        uint64 processed = portal.lastProcessedDepositNumber();
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(),
                nextBlockHash: keccak256(abi.encode("limit-batch", block.number))
            }),
            DepositQueueTransition({
                prevProcessedHash: bytes32(0),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: processed,
                nextDepositNumber: processed
            }),
            queueHash,
            "",
            ""
        );
    }

    function _setLimit(address token, uint128 maxAmount, uint64 period) internal {
        vm.prank(limitAuthority);
        portal.setWithdrawalLimit(token, maxAmount, period);
    }

    function _available(address token) internal view returns (uint128 available) {
        (,, available) = portal.withdrawalLimit(token);
    }

    function _queue(address token) internal view returns (uint64 head, uint64 tail) {
        return portal.queuedWithdrawals(token);
    }

    function _record(address token, uint256 index) internal view returns (QueuedWithdrawal memory) {
        return portal.queuedWithdrawalAt(token, index);
    }

    function _remaining(address token, uint256 index) internal view returns (uint128) {
        return portal.queuedWithdrawalAt(token, index).remaining;
    }

    /// @dev Asserts the record holds what the payout of w reads.
    function _assertRecord(
        address token,
        uint256 index,
        Withdrawal memory w,
        uint128 remaining
    )
        internal
        view
    {
        QueuedWithdrawal memory record = _record(token, index);
        assertEq(record.to, w.to, "record.to");
        assertEq(record.fallbackNonce, w.fallbackNonce, "record.fallbackNonce");
        assertEq(record.senderTag, w.fallbackNonce == 0 ? bytes32(0) : w.senderTag, "senderTag");
        assertEq(record.remaining, remaining, "record.remaining");
    }

    /// @dev Asserts every storage slot of the record at index is zero.
    function _assertRecordDeleted(address token, uint256 index) internal view {
        bytes32 queue = keccak256(abi.encode(token, QUEUED_WITHDRAWALS_SLOT));
        bytes32 entries = bytes32(uint256(queue) + 1);
        uint256 slot = uint256(keccak256(abi.encode(index, entries)));
        for (uint256 i; i < 3; ++i) {
            assertEq(vm.load(address(portal), bytes32(slot + i)), bytes32(0), "record slot");
        }
    }

    /// @dev Processes a token queue as a caller that is not a sequencer, without an entry bound.
    function _processQueued(address token) internal returns (uint256) {
        return _processQueued(token, type(uint256).max);
    }

    function _processQueued(address token, uint256 maxEntries) internal returns (uint256) {
        vm.prank(anyone);
        return portal.processQueuedWithdrawals(token, maxEntries);
    }

    /// @dev Expects the WithdrawalQueued event of w, whose senderTag matches its record's.
    function _expectQueued(address token, uint64 queueIndex, Withdrawal memory w) internal {
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalQueued(
            token,
            queueIndex,
            w.to,
            w.amount,
            w.fallbackNonce == 0 ? bytes32(0) : w.senderTag,
            w.fallbackNonce
        );
    }

    /// @dev Advances time from the current block timestamp, which forge does not cache.
    function _skip(uint256 seconds_) internal {
        vm.warp(vm.getBlockTimestamp() + seconds_);
    }

    function _openModes() internal {
        vm.startPrank(admin);
        portal.setAccessMode(false);
        portal.setGatewayMode(false);
        vm.stopPrank();
    }

    /// @dev Sets the unprocessed deposit count to n by moving depositCount, keeping the rest of
    ///      the packed slot.
    function _setUnprocessedDeposits(uint64 n) internal {
        uint256 word = uint256(vm.load(address(portal), DEPOSIT_COUNTERS_SLOT));
        uint64 processed = uint64(word >> 64);
        word = (word & ~uint256(type(uint64).max)) | uint256(processed + n);
        vm.store(address(portal), DEPOSIT_COUNTERS_SLOT, bytes32(word));
    }

    /*//////////////////////////////////////////////////////////////
                           LIMIT AUTHORITY
    //////////////////////////////////////////////////////////////*/

    function test_setWithdrawalLimit_onlyFactoryOwner() public {
        address[3] memory callers = [admin, sequencer, anyone];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            vm.expectRevert(IZonePortal.NotWithdrawalLimitAuthority.selector);
            portal.setWithdrawalLimit(address(pathUSD), MAX, PERIOD);
        }

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalLimitSet(address(pathUSD), MAX, PERIOD);
        _setLimit(address(pathUSD), MAX, PERIOD);
        (uint128 maxAmount, uint64 period, uint128 available) =
            portal.withdrawalLimit(address(pathUSD));
        assertEq(maxAmount, MAX);
        assertEq(period, PERIOD);
        assertEq(available, MAX, "a new limit starts full");
    }

    function test_setWithdrawalLimit_followsFactoryOwnerChange() public {
        vm.mockCall(
            ZONE_FACTORY_ADDRESS, abi.encodeCall(IZoneFactory.owner, ()), abi.encode(anyone)
        );
        vm.prank(limitAuthority);
        vm.expectRevert(IZonePortal.NotWithdrawalLimitAuthority.selector);
        portal.setWithdrawalLimit(address(pathUSD), MAX, PERIOD);
        vm.prank(anyone);
        portal.setWithdrawalLimit(address(pathUSD), MAX, PERIOD);
    }

    function test_setWithdrawalLimit_validation() public {
        vm.startPrank(limitAuthority);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 0, 1);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 1, 0);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 99, 100);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 1000, 3);

        portal.setWithdrawalLimit(address(pathUSD), 100, 100);
        portal.setWithdrawalLimit(address(pathUSD), 1, 1);
        portal.setWithdrawalLimit(address(pathUSD), 365 days, 365 days);
        portal.setWithdrawalLimit(address(pathUSD), 0, 0);
        vm.stopPrank();
        (uint128 maxAmount, uint64 period, uint128 available) =
            portal.withdrawalLimit(address(pathUSD));
        assertEq(maxAmount, 0);
        assertEq(period, 0);
        assertEq(available, 0);
    }

    function test_setWithdrawalLimit_beforeTokenIsEnabled() public {
        address token2 = address(0xDEAD);
        assertFalse(portal.isTokenEnabled(token2));
        _setLimit(token2, MAX, PERIOD);
        (uint128 maxAmount, uint64 period, uint128 available) = portal.withdrawalLimit(token2);
        assertEq(maxAmount, MAX);
        assertEq(period, PERIOD);
        assertEq(available, MAX);
    }

    function test_setWithdrawalLimit_storesTwoWords() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 600e6)));
        bytes32 base = keccak256(abi.encode(address(pathUSD), WITHDRAWAL_LIMITS_SLOT));
        assertEq(
            vm.load(address(portal), base),
            bytes32(uint256(MAX) | (uint256(PERIOD) << 128)),
            "word 0: maxAmount, period"
        );
        assertEq(
            vm.load(address(portal), bytes32(uint256(base) + 1)),
            bytes32(uint256(400e6) | (uint256(vm.getBlockTimestamp()) << 128)),
            "word 1: available, updatedAt"
        );
        assertEq(vm.load(address(portal), bytes32(uint256(base) + 2)), bytes32(0));
    }

    function test_setWithdrawalLimit_unaffectedByPauseAndAbdication() public {
        vm.prank(admin);
        portal.pause();
        assertTrue(portal.paused());
        _setLimit(address(pathUSD), MAX, PERIOD);

        vm.startPrank(admin);
        portal.resume();
        portal.abdicate(Capability.PausePortal);
        portal.abdicate(Capability.AccessPolicy);
        vm.stopPrank();
        _skip(400 days);
        vm.prank(admin);
        vm.expectRevert(
            abi.encodeWithSelector(
                IZonePortal.CapabilityAbdicated.selector, Capability.AccessPolicy
            )
        );
        portal.setTransfersEnabled(true);

        _setLimit(address(pathUSD), 2 * MAX, PERIOD);
        (uint128 maxAmount,,) = portal.withdrawalLimit(address(pathUSD));
        assertEq(maxAmount, 2 * MAX);
    }

    /*//////////////////////////////////////////////////////////////
                              REFILL
    //////////////////////////////////////////////////////////////*/

    function test_refill_linearAndCapped() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 600e6)));
        assertEq(pathUSD.balanceOf(bob), 600e6);
        assertEq(_available(address(pathUSD)), 400e6);

        _skip(100);
        assertEq(_available(address(pathUSD)), 500e6);
        _skip(10_000);
        assertEq(_available(address(pathUSD)), MAX, "capacity never exceeds maxAmount");
    }

    function test_refill_slowestRate() public {
        // (1, 1) refills one raw unit per second.
        _setLimit(address(pathUSD), 1, 1);
        _withdraw(_one(_plain(address(pathUSD), bob, 1)));
        assertEq(_available(address(pathUSD)), 0);
        _skip(1);
        assertEq(_available(address(pathUSD)), 1);
        _skip(100);
        assertEq(_available(address(pathUSD)), 1);
    }

    function test_changeLimit_keepsRefilledCapacityCapped() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 800e6)));
        _skip(100); // 300e6 under the old limit

        _setLimit(address(pathUSD), 2 * MAX, PERIOD);
        assertEq(_available(address(pathUSD)), 300e6);
        _skip(100); // refills 2e6 per second now
        assertEq(_available(address(pathUSD)), 500e6);

        _setLimit(address(pathUSD), 100e6, PERIOD);
        assertEq(_available(address(pathUSD)), 100e6, "capped at the new maxAmount");
    }

    function test_unlimitedToken_unchanged() public {
        _withdraw(_one(_plain(address(pathUSD), bob, 50_000e6)));
        assertEq(pathUSD.balanceOf(bob), 50_000e6);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, tail);
    }

    /*//////////////////////////////////////////////////////////////
                           MAIN QUEUE RULES
    //////////////////////////////////////////////////////////////*/

    function test_overLimit_queuesRecordsInOrderPerToken() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _setLimit(address(token1), MAX, PERIOD);

        Withdrawal memory big = _plain(address(pathUSD), bob, 1500e6);
        Withdrawal memory other = _plain(address(token1), bob, 200e6);
        Withdrawal memory small = _plain(address(pathUSD), charlie, 1);
        Withdrawal[] memory ws = new Withdrawal[](3);
        ws[0] = big;
        ws[1] = other;
        ws[2] = small;

        _settle(ws);
        _expectQueued(address(pathUSD), 0, big);
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(bob, other.senderTag, address(token1), 200e6, true);
        _expectQueued(address(pathUSD), 1, small);
        portal.processWithdrawals(ws, bytes32(0));

        // The over-limit entry holds back the later small one of the same token, not the other.
        assertEq(token1.balanceOf(bob), 200e6);
        assertEq(pathUSD.balanceOf(bob), 0);
        assertEq(pathUSD.balanceOf(charlie), 0);
        assertEq(_available(address(pathUSD)), MAX, "queued entries take no capacity");

        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 0);
        assertEq(tail, 2);
        _assertRecord(address(pathUSD), 0, big, 1500e6);
        _assertRecord(address(pathUSD), 1, small, 1);
        assertEq(_record(address(pathUSD), 2).to, address(0), "no record past the tail");
        (, uint64 tail1) = _queue(address(token1));
        assertEq(tail1, 0);
    }

    function test_backlog_queuesLaterEntriesAcrossCalls() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory big = _plain(address(pathUSD), bob, 1500e6);
        _withdraw(_one(big));

        // Capacity is full, but the token queue is non-empty, so the next entry queues too.
        Withdrawal memory small = _plain(address(pathUSD), charlie, 1e6);
        _settle(_one(small));
        _expectQueued(address(pathUSD), 1, small);
        portal.processWithdrawals(_one(small), bytes32(0));
        assertEq(pathUSD.balanceOf(charlie), 0);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 0);
        assertEq(tail, 2);
        _assertRecord(address(pathUSD), 1, small, 1e6);
    }

    function test_oversizedCallback_bounces() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        uint64 depositsBefore = portal.depositCount();
        Withdrawal memory cb = _callback(MAX + 1);

        _settle(_one(cb));
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(
            address(receiver), cb.senderTag, address(pathUSD), MAX + 1, false
        );
        portal.processWithdrawals(_one(cb), bytes32(0));
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(receiver.calls(), 0);
        (, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail, 0);
        assertEq(_available(address(pathUSD)), MAX);
    }

    function test_overGasCapWithdrawal_bouncesWithoutCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 5000e6);
        w.gasLimit = portal.MAX_WITHDRAWAL_GAS_LIMIT() + 1;
        uint64 depositsBefore = portal.depositCount();
        _withdraw(_one(w));
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(_available(address(pathUSD)), MAX);
        (, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail, 0);
    }

    function test_depositBounceBack_limitedDespiteLargeGasLimit() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _depositBounceBack(5000e6);
        w.gasLimit = type(uint64).max;
        uint64 depositsBefore = portal.depositCount();

        _settle(_one(w));
        _expectQueued(address(pathUSD), 0, w);
        portal.processWithdrawals(_one(w), bytes32(0));
        assertEq(pathUSD.balanceOf(alice), 0);
        assertEq(portal.depositCount(), depositsBefore, "not bounced to the zone");
        _assertRecord(address(pathUSD), 0, w, 5000e6);

        // Paid in parts like a plain withdrawal.
        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(pathUSD.balanceOf(alice), MAX);
        assertEq(_remaining(address(pathUSD), 0), 4000e6);
        assertTrue(_record(address(pathUSD), 0).partlyPaid);
    }

    function test_depositBounceBack_queuedWithoutSenderTag() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _depositBounceBack(5000e6);
        assertTrue(w.senderTag != bytes32(0));

        _settle(_one(w));
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalQueued(address(pathUSD), 0, alice, 5000e6, bytes32(0), 0);
        portal.processWithdrawals(_one(w), bytes32(0));
        assertEq(_record(address(pathUSD), 0).senderTag, bytes32(0));
    }

    function test_depositBounceBack_withinCapacityTakesCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_depositBounceBack(400e6)));
        assertEq(pathUSD.balanceOf(alice), 400e6);
        assertEq(_available(address(pathUSD)), 600e6);
    }

    function test_failedDelivery_restoresCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        address outsider = address(0xD00D);
        uint64 depositsBefore = portal.depositCount();

        _withdraw(_one(_plain(address(pathUSD), outsider, 400e6)));

        assertEq(pathUSD.balanceOf(outsider), 0);
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(_available(address(pathUSD)), MAX);
    }

    /*//////////////////////////////////////////////////////////////
                         QUEUED PROCESSING
    //////////////////////////////////////////////////////////////*/

    /// @dev The TIP's example: A waits, B pays, a later small A waits behind, an A callback
    ///      bounces, and a drainer later pays A in parts.
    function test_queueOrder_acrossTwoTokens() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        _setLimit(address(token1), MAX, PERIOD);
        Withdrawal memory a1 = _plain(address(pathUSD), bob, 1500e6);
        Withdrawal memory b = _plain(address(token1), bob, 200e6);
        Withdrawal memory a2 = _plain(address(pathUSD), charlie, 1e6);
        Withdrawal memory a3 = _callback(1e6);
        Withdrawal[] memory ws = new Withdrawal[](4);
        ws[0] = a1;
        ws[1] = b;
        ws[2] = a2;
        ws[3] = a3;
        uint64 depositsBefore = portal.depositCount();
        _withdraw(ws);

        assertEq(token1.balanceOf(bob), 200e6, "B pays");
        assertEq(pathUSD.balanceOf(bob) + pathUSD.balanceOf(charlie), 0, "A waits");
        assertEq(portal.depositCount(), depositsBefore + 1, "the A callback bounces");
        assertEq(receiver.calls(), 0);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail - head, 2);

        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(pathUSD.balanceOf(bob), MAX, "first part");
        assertEq(pathUSD.balanceOf(charlie), 0, "behind the head");

        _skip(501);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 500e6, 0);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 1, 1e6, 0);
        assertEq(_processQueued(address(pathUSD)), 2);
        assertEq(pathUSD.balanceOf(bob), 1500e6);
        assertEq(pathUSD.balanceOf(charlie), 1e6);
        (head, tail) = _queue(address(pathUSD));
        assertEq(head, 2);
        assertEq(tail, 2);
    }

    function test_partialPayment_acrossRefills() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(bob, w.senderTag, address(pathUSD), MAX, true);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, MAX, 1500e6);
        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(pathUSD.balanceOf(bob), MAX);
        (uint64 head,) = _queue(address(pathUSD));
        assertEq(head, 0);
        _assertRecord(address(pathUSD), 0, w, 1500e6);

        // No capacity: stops without reverting or paying.
        vm.recordLogs();
        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(pathUSD.balanceOf(bob), MAX);

        _skip(1000);
        _processQueued(address(pathUSD));
        assertEq(_remaining(address(pathUSD), 0), 500e6);
        _skip(1000);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 500e6, 0);
        assertEq(_processQueued(address(pathUSD)), 1);
        assertEq(pathUSD.balanceOf(bob), 2500e6);
        assertEq(_available(address(pathUSD)), 500e6);
        (head,) = _queue(address(pathUSD));
        assertEq(head, 1);
        _assertRecordDeleted(address(pathUSD), 0);
    }

    function test_maxEntries_boundsWork() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal[] memory ws = new Withdrawal[](4);
        ws[0] = _plain(address(pathUSD), bob, MAX);
        ws[1] = _plain(address(pathUSD), bob, 100e6);
        ws[2] = _plain(address(pathUSD), charlie, 200e6);
        ws[3] = _plain(address(pathUSD), admin, 900e6);
        _withdraw(ws);
        _skip(PERIOD);

        assertEq(_processQueued(address(pathUSD), 0), 0, "zero entries does nothing");
        assertEq(_available(address(pathUSD)), MAX);
        assertEq(_processQueued(address(pathUSD), 2), 2);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 2);
        assertEq(tail, 3);
        assertEq(_available(address(pathUSD)), 700e6);

        // A record at or below maxAmount waits until capacity covers all of it.
        vm.recordLogs();
        assertEq(_processQueued(address(pathUSD), 1), 0);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(_remaining(address(pathUSD), 2), 900e6);
        assertEq(_available(address(pathUSD)), 700e6);
        _skip(199);
        assertEq(_processQueued(address(pathUSD), 1), 0);
        _skip(1);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 2, 900e6, 0);
        assertEq(_processQueued(address(pathUSD), 1), 1);
        assertEq(pathUSD.balanceOf(admin), 900e6);
        assertEq(_available(address(pathUSD)), 0);
    }

    function test_queuedTransferFailure_bouncesRemainderWithoutCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        _processQueued(address(pathUSD));
        uint256 bobPaid = pathUSD.balanceOf(bob);

        vm.prank(admin);
        portal.setAllowedAccount(bob, false);
        _skip(PERIOD);
        uint64 depositsBefore = portal.depositCount();

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(bob, w.senderTag, address(pathUSD), 1500e6, false);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 0, 0);
        assertEq(_processQueued(address(pathUSD)), 1);

        assertEq(pathUSD.balanceOf(bob), bobPaid);
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(_available(address(pathUSD)), MAX, "a bounce-back takes no capacity");
        (uint64 head,) = _queue(address(pathUSD));
        assertEq(head, 1);
        _assertRecordDeleted(address(pathUSD), 0);
    }

    function test_paused_blocksQueuedProcessing() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 1500e6)));
        vm.prank(admin);
        portal.pause();

        vm.prank(anyone);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.processQueuedWithdrawals(address(pathUSD), 1);

        // The limit authority still acts while paused.
        _setLimit(address(pathUSD), 0, 0);
        vm.prank(admin);
        portal.resume();
        assertEq(_processQueued(address(pathUSD)), 1);
        assertEq(pathUSD.balanceOf(bob), 1500e6);
    }

    function test_removedLimit_drainsEverything() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory big = _plain(address(pathUSD), bob, 5000e6);
        _withdraw(_one(big));
        _setLimit(address(pathUSD), 0, 0);

        Withdrawal memory small = _plain(address(pathUSD), charlie, 1e6);
        Withdrawal memory refund = _depositBounceBack(3000e6);
        _withdraw(_two(small, refund));
        assertEq(pathUSD.balanceOf(charlie), 0, "still behind the backlog");

        assertEq(_processQueued(address(pathUSD)), 3);
        assertEq(pathUSD.balanceOf(bob), 5000e6);
        assertEq(pathUSD.balanceOf(charlie), 1e6);
        assertEq(pathUSD.balanceOf(alice), 3000e6);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 3);
        assertEq(tail, 3);

        // With the queue drained, the unlimited token is paid directly again.
        _withdraw(_one(_plain(address(pathUSD), charlie, 7e6)));
        assertEq(pathUSD.balanceOf(charlie), 8e6);
    }

    function test_loweredLimit_belowPartlyPaidHead() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 2500e6)));
        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(_remaining(address(pathUSD), 0), 1500e6);

        // Each later payment is the new maxAmount, and the last one completes the record.
        uint128 lowered = 400e6;
        _setLimit(address(pathUSD), lowered, PERIOD);
        uint128[4] memory remainders = [uint128(1100e6), 700e6, 300e6, 0];
        for (uint256 i; i < remainders.length; ++i) {
            _skip(PERIOD);
            uint128 pay = _remaining(address(pathUSD), 0) - remainders[i];
            vm.expectEmit(address(portal));
            emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, pay, remainders[i]);
            assertEq(_processQueued(address(pathUSD)), remainders[i] == 0 ? 1 : 0);
            assertLe(pay, lowered);
        }
        assertEq(pathUSD.balanceOf(bob), 2500e6);
        assertEq(_available(address(pathUSD)), lowered - 300e6);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 1);
        assertEq(tail, 1);
        _assertRecordDeleted(address(pathUSD), 0);
    }

    function test_completedRecords_deletedForStorageCredits() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal[] memory ws = new Withdrawal[](3);
        ws[0] = _plain(address(pathUSD), bob, 1500e6);
        ws[1] = _depositBounceBack(300e6);
        ws[2] = _plain(address(pathUSD), charlie, 200e6);
        _withdraw(ws);
        assertEq(_record(address(pathUSD), 0).to, bob);
        _processQueued(address(pathUSD));
        _skip(PERIOD);

        // Three slots for a plain withdrawal, two for a deposit bounce-back. Capacity is zero
        // before and after, so only the records change the credit balance.
        uint64 creditsBefore = StdPrecompiles.STORAGE_CREDITS.balanceOf(address(portal));
        assertEq(_processQueued(address(pathUSD)), 3);
        for (uint256 i; i < 3; ++i) {
            _assertRecordDeleted(address(pathUSD), i);
        }
        assertEq(StdPrecompiles.STORAGE_CREDITS.balanceOf(address(portal)) - creditsBefore, 8);
    }

    /*//////////////////////////////////////////////////////////////
                           SEQUENCER GAS RESERVATIONS
        //////////////////////////////////////////////////////////////*/

    // Copies of the sequencer's planner reservations: crates/zones/sequencer/src/withdrawals.rs
    // (PROCESS_WITHDRAWAL_TX_OVERHEAD_GAS, T15_PROCESS_SIMPLE_WITHDRAWAL_ITEM_OVERHEAD_GAS,
    // PROCESS_DEPOSIT_BOUNCEBACK_ITEM_OVERHEAD_GAS) and withdrawals/token_queues.rs
    // (QUEUED_ENTRY_GAS). Change them together.
    uint256 internal constant TX_OVERHEAD_GAS = 1_250_000;
    uint256 internal constant SIMPLE_ITEM_GAS = 1_100_000;
    uint256 internal constant BOUNCEBACK_ITEM_GAS = 1_250_000;
    uint256 internal constant QUEUED_ENTRY_GAS = 400_000;
    /// @dev Intrinsic gas, and calldata per withdrawal or per drain, as the planner tests count it.
    uint256 internal constant INTRINSIC_GAS = 21_000;
    uint256 internal constant ITEM_CALLDATA_GAS = 2800;
    uint256 internal constant DRAIN_CALLDATA_GAS = 400;
    bytes32 internal constant DEPOSIT_QUEUE_HASH_SLOT = bytes32(uint256(3));
    bytes32 internal constant DEPOSIT_BUCKETS_SLOT = bytes32(uint256(29));

    /// @dev Ways a drained record can be paid, each creating storage the drain pays for.
    enum DrainedRecord {
        // A plain withdrawal paid to a recipient holding no tokens.
        Paid,
        // A deposit bounce-back paying a fee to the admin and the rest to a recipient holding no
        // tokens.
        RefundPaid,
        // A deposit bounce-back paying a fee to the admin and parking the rest in refunds.
        RefundParked,
        // A plain withdrawal whose payout fails and bounces back to the zone.
        Bounced
    }

    /// @dev Cools every account a payout of ws touches, so each call is charged as its own
    ///      transaction would be.
    function _coolPayoutAccounts(Withdrawal[] memory ws) internal {
        vm.cool(address(portal));
        vm.cool(address(pathUSD));
        vm.cool(address(token1));
        vm.cool(admin);
        vm.cool(StdPrecompiles.STORAGE_CREDITS_ADDRESS);
        vm.cool(StdPrecompiles.TIP403_REGISTRY_ADDRESS);
        for (uint256 i; i < ws.length; ++i) {
            vm.cool(ws[i].to);
        }
    }

    function _processWithdrawalsGas(Withdrawal[] memory ws) internal returns (uint256 gasUsed) {
        _settle(ws);
        _coolPayoutAccounts(ws);
        gasUsed = gasleft();
        portal.processWithdrawals(ws, bytes32(0));
        gasUsed -= gasleft();
    }

    /// @dev Leaves the deposit checkpoints as a runtime without them did: deposits processed,
    ///      no checkpoint stored, so the next deposit-queue append creates them.
    function _clearDepositCheckpoints() internal {
        uint256 word = uint256(vm.load(address(portal), DEPOSIT_COUNTERS_SLOT));
        word = (word >> 128 << 128) | (uint256(1000) << 64) | 1000;
        vm.store(address(portal), DEPOSIT_COUNTERS_SLOT, bytes32(word));
        vm.store(address(portal), DEPOSIT_QUEUE_HASH_SLOT, keccak256("deposit queue"));
        assertEq(_depositBucketCount(), 0);
    }

    function _depositBucketCount() internal view returns (uint256) {
        return uint256(vm.load(address(portal), DEPOSIT_BUCKETS_SLOT));
    }

    /// @dev Queues one token1 record per entry of kinds behind an empty limit, then returns the
    ///      gas of one drain that completes them all, with cold accounts.
    function _drainGas(DrainedRecord[] memory kinds) internal returns (uint256 gasUsed) {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 100);
        _setLimit(address(token1), MAX, PERIOD);
        address sink = address(0x5111);
        _allow(sink);
        _withdraw(_one(_plain(address(token1), sink, MAX)));

        Withdrawal[] memory ws = new Withdrawal[](kinds.length);
        for (uint256 i; i < kinds.length; ++i) {
            ws[i] = _plain(address(token1), address(uint160(0x6000 + i)), MAX / 10);
            if (kinds[i] == DrainedRecord.RefundPaid || kinds[i] == DrainedRecord.RefundParked) {
                ws[i].fallbackNonce = 0;
            }
        }
        _withdraw(ws);
        for (uint256 i; i < kinds.length; ++i) {
            if (kinds[i] == DrainedRecord.Paid || kinds[i] == DrainedRecord.RefundPaid) {
                _allow(ws[i].to);
            } else {
                _disallow(ws[i].to);
            }
            assertEq(token1.balanceOf(ws[i].to), 0);
        }
        assertEq(token1.balanceOf(admin), 0);
        assertEq(StdPrecompiles.STORAGE_CREDITS.balanceOf(address(portal)), 0);
        _skip(PERIOD);

        _coolPayoutAccounts(ws);
        vm.prank(anyone);
        gasUsed = gasleft();
        uint256 completed = portal.processQueuedWithdrawals(address(token1), kinds.length);
        gasUsed -= gasleft();
        assertEq(completed, kinds.length);
    }

    function _assertDrainFits(DrainedRecord[] memory kinds, bool clearCheckpoints) internal {
        uint256 snapshot = vm.snapshotState();
        if (clearCheckpoints) _clearDepositCheckpoints();
        uint256 gasUsed = _drainGas(kinds);
        if (clearCheckpoints) assertEq(_depositBucketCount(), 1);
        assertLe(
            INTRINSIC_GAS + DRAIN_CALLDATA_GAS + gasUsed,
            TX_OVERHEAD_GAS + kinds.length * QUEUED_ENTRY_GAS,
            "drain exceeds its reservation"
        );
        vm.revertToState(snapshot);
    }

    function _kinds(DrainedRecord a) internal pure returns (DrainedRecord[] memory kinds) {
        kinds = new DrainedRecord[](1);
        kinds[0] = a;
    }

    function _kinds(
        DrainedRecord a,
        DrainedRecord b
    )
        internal
        pure
        returns (DrainedRecord[] memory kinds)
    {
        kinds = new DrainedRecord[](2);
        kinds[0] = a;
        kinds[1] = b;
    }

    /// @notice Queuing an entry as the first record of its token queue, with cold accounts and no
    ///         storage credits, fits what the sequencer reserves for it in processWithdrawals.
    function test_gas_queuedEntriesFitProcessWithdrawalsReservations() public {
        assertEq(StdPrecompiles.STORAGE_CREDITS.balanceOf(address(portal)), 0);
        _setLimit(address(pathUSD), MAX, PERIOD);
        _setLimit(address(token1), MAX, PERIOD);
        Withdrawal memory first = _plain(address(pathUSD), bob, 2 * MAX);
        Withdrawal memory plain = _plain(address(token1), charlie, 2 * MAX);
        Withdrawal memory bounceBack = _plain(address(token1), charlie, 2 * MAX);
        bounceBack.fallbackNonce = 0;

        uint256 snapshot = vm.snapshotState();
        uint256 firstAlone = _processWithdrawalsGas(_one(first));
        vm.revertToState(snapshot);
        uint256 bounceBackAlone = _processWithdrawalsGas(_one(bounceBack));
        vm.revertToState(snapshot);
        uint256 withPlain = _processWithdrawalsGas(_two(first, plain));
        vm.revertToState(snapshot);
        uint256 withBounceBack = _processWithdrawalsGas(_two(first, bounceBack));
        (, uint64 tail) = _queue(address(token1));
        assertEq(tail, 1);

        assertLe(INTRINSIC_GAS + ITEM_CALLDATA_GAS + firstAlone, TX_OVERHEAD_GAS + SIMPLE_ITEM_GAS);
        assertLe(
            INTRINSIC_GAS + ITEM_CALLDATA_GAS + bounceBackAlone,
            TX_OVERHEAD_GAS + BOUNCEBACK_ITEM_GAS
        );
        assertLe(ITEM_CALLDATA_GAS + withPlain - firstAlone, SIMPLE_ITEM_GAS);
        assertLe(ITEM_CALLDATA_GAS + withBounceBack - firstAlone, BOUNCEBACK_ITEM_GAS);
    }

    /// @notice Drains fit what the sequencer reserves for them, with cold accounts, no storage
    ///         credits and the storage each record can create: recipient balances, the admin's fee
    ///         balance, a parked refund, and the deposit checkpoints a bounce-back starts.
    function test_gas_drainsFitQueuedEntryReservation() public {
        _assertDrainFits(_kinds(DrainedRecord.Paid), false);
        _assertDrainFits(_kinds(DrainedRecord.RefundPaid), false);
        _assertDrainFits(_kinds(DrainedRecord.RefundParked), false);
        _assertDrainFits(_kinds(DrainedRecord.Bounced), true);
        _assertDrainFits(_kinds(DrainedRecord.Paid, DrainedRecord.RefundPaid), false);
        _assertDrainFits(_kinds(DrainedRecord.Paid, DrainedRecord.RefundParked), false);
        _assertDrainFits(_kinds(DrainedRecord.Bounced, DrainedRecord.RefundPaid), true);
        _assertDrainFits(_kinds(DrainedRecord.Paid, DrainedRecord.Bounced), true);

        DrainedRecord[] memory many = new DrainedRecord[](10);
        for (uint256 i; i < many.length; ++i) {
            many[i] = DrainedRecord(i % 4);
        }
        _assertDrainFits(many, true);
    }

    /*//////////////////////////////////////////////////////////////
                       DEPOSIT BOUNCE-BACK FEES
    //////////////////////////////////////////////////////////////*/

    function test_queuedDepositBounceBack_feeOnFirstPartOnly() public {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 100); // fee = 100_000 * 100 = 10e6
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_depositBounceBack(2500e6)));
        uint256 adminBefore = pathUSD.balanceOf(admin);

        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), MAX - 10e6, 10e6);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, MAX, 1500e6);
        _processQueued(address(pathUSD));

        _skip(10_000);
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), MAX, 0);
        _processQueued(address(pathUSD));
        _skip(10_000);
        assertEq(_processQueued(address(pathUSD)), 1);

        assertEq(pathUSD.balanceOf(admin) - adminBefore, 10e6);
        assertEq(pathUSD.balanceOf(alice), 2500e6 - 10e6);
    }

    function test_queuedDepositBounceBack_feeCappedAtMaxAmount() public {
        vm.prank(admin);
        portal.setBouncebackGas(1_000_000);
        vm.fee(1e12 * 2000); // fee = 2000e6 > MAX
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_depositBounceBack(5000e6)));
        uint256 adminBefore = pathUSD.balanceOf(admin);

        // The fee is capped at the first payment, which a full capacity always covers.
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), 0, MAX);
        _processQueued(address(pathUSD));
        for (uint256 i; i < 4; ++i) {
            _skip(PERIOD);
            _processQueued(address(pathUSD));
        }
        (uint64 head,) = _queue(address(pathUSD));
        assertEq(head, 1);
        assertEq(pathUSD.balanceOf(admin) - adminBefore, MAX);
        assertEq(pathUSD.balanceOf(alice), 4000e6);
    }

    function test_queuedDepositBounceBack_waitsForFullPayment() public {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 1000); // fee = 100e6
        _setLimit(address(pathUSD), MAX, PERIOD);
        // Use up capacity, then queue a bounce-back behind it.
        _withdraw(_two(_plain(address(pathUSD), bob, MAX), _depositBounceBack(2000e6)));
        _skip(500); // covers the fee, not a full payment

        assertEq(_processQueued(address(pathUSD)), 0);
        assertEq(_remaining(address(pathUSD), 0), 2000e6);
        assertFalse(_record(address(pathUSD), 0).partlyPaid);
        assertEq(_available(address(pathUSD)), 500e6, "a waiting record takes nothing");

        _skip(500);
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), MAX - 100e6, 100e6);
        _processQueued(address(pathUSD));
        assertEq(_remaining(address(pathUSD), 0), 1000e6);
        assertTrue(_record(address(pathUSD), 0).partlyPaid);
    }

    function test_queuedDepositBounceBack_feeAttemptedOnceWhenAdminTransferFails() public {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 100); // fee = 10e6
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_depositBounceBack(1500e6)));
        uint256 adminBefore = pathUSD.balanceOf(admin);

        // The admin cannot receive the fee: the first payment refunds all of it.
        vm.mockCallRevert(
            address(pathUSD), abi.encodeCall(pathUSD.transfer, (admin, 10e6)), "blocked"
        );
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), MAX, 0);
        _processQueued(address(pathUSD));
        vm.clearMockedCalls();
        vm.mockCall(
            ZONE_FACTORY_ADDRESS, abi.encodeCall(IZoneFactory.owner, ()), abi.encode(limitAuthority)
        );
        assertTrue(_record(address(pathUSD), 0).partlyPaid);

        // The fee is not retried on a later payment.
        _skip(PERIOD);
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBack(alice, address(pathUSD), 500e6, 0);
        assertEq(_processQueued(address(pathUSD)), 1);
        assertEq(pathUSD.balanceOf(admin), adminBefore);
        assertEq(pathUSD.balanceOf(alice), 1500e6);
    }

    function test_mainQueueDepositBounceBack_feeUnchanged() public {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 100); // fee = 10e6
        uint256 adminBefore = pathUSD.balanceOf(admin);
        _withdraw(_one(_depositBounceBack(5e6)));
        assertEq(pathUSD.balanceOf(alice), 0, "fee capped at amount");
        assertEq(pathUSD.balanceOf(admin) - adminBefore, 5e6);
    }

    /*//////////////////////////////////////////////////////////////
                              CALLBACKS
    //////////////////////////////////////////////////////////////*/

    function test_callback_fitsWithoutBacklog_deliveredAndCharged() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_callback(500e6)));
        assertEq(receiver.calls(), 1);
        assertEq(_available(address(pathUSD)), 500e6);
        (, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail, 0);
    }

    function test_callback_overCapacityBounces() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 600e6)));
        uint64 depositsBefore = portal.depositCount();
        Withdrawal memory cb = _callback(500e6);

        _settle(_one(cb));
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(
            address(receiver), cb.senderTag, address(pathUSD), 500e6, false
        );
        portal.processWithdrawals(_one(cb), bytes32(0));

        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(receiver.calls(), 0);
        assertEq(_available(address(pathUSD)), 400e6, "a bounced callback takes no capacity");
        (, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail, 0, "callbacks never enter a token queue");
    }

    function test_callback_behindBacklogBounces() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory big = _plain(address(pathUSD), bob, 1500e6);
        // Queued earlier in the same call: the callback bounces although capacity covers it.
        Withdrawal memory cb = _callback(1e6);
        _withdraw(_one(_plain(address(pathUSD), charlie, 100e6)));
        uint64 depositsBefore = portal.depositCount();
        _withdraw(_two(big, cb));
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(receiver.calls(), 0);
        _assertRecord(address(pathUSD), 0, big, 1500e6);

        // Queued in an earlier call: capacity is full, yet the callback still bounces.
        _skip(PERIOD);
        _withdraw(_one(cb));
        assertEq(portal.depositCount(), depositsBefore + 2);
        assertEq(receiver.calls(), 0);
        assertEq(_available(address(pathUSD)), MAX);

        // So does a callback behind the backlog of a token whose limit was removed.
        _setLimit(address(pathUSD), 0, 0);
        _withdraw(_one(cb));
        assertEq(portal.depositCount(), depositsBefore + 3);
        assertEq(receiver.calls(), 0);
        (, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail, 1);

        // Once the backlog drains, the same callback is delivered.
        assertEq(_processQueued(address(pathUSD)), 1);
        _withdraw(_one(cb));
        assertEq(receiver.calls(), 1);
    }

    /*//////////////////////////////////////////////////////////////
                         PERMISSIONLESS DRAIN
    //////////////////////////////////////////////////////////////*/

    function test_queue_drainedByAnyCallerWithIdenticalResult() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, MAX)));
        _withdraw(_two(_plain(address(pathUSD), bob, 1500e6), _depositBounceBack(700e6)));
        _withdraw(_one(_plain(address(pathUSD), charlie, 300e6)));
        _skip(600);

        uint256 snapshot = vm.snapshotState();
        vm.prank(sequencer);
        uint256 bySequencer = portal.processQueuedWithdrawals(address(pathUSD), 10);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        uint128 remaining = _remaining(address(pathUSD), head);
        uint256 bobBalance = pathUSD.balanceOf(bob);
        vm.revertToState(snapshot);

        assertEq(_processQueued(address(pathUSD), 10), bySequencer);
        (uint64 head2, uint64 tail2) = _queue(address(pathUSD));
        assertEq(head2, head);
        assertEq(tail2, tail);
        assertEq(_remaining(address(pathUSD), head2), remaining);
        assertEq(pathUSD.balanceOf(bob), bobBalance);

        // With no sequencer acting, a caller outside the set drains the queue as capacity refills.
        assertFalse(portal.isSequencer(anyone));
        for (uint256 i; i < 3; ++i) {
            _skip(PERIOD);
            _processQueued(address(pathUSD));
        }
        (head, tail) = _queue(address(pathUSD));
        assertEq(head, 3);
        assertEq(tail, 3);
        assertEq(pathUSD.balanceOf(bob), MAX + 1500e6);
        assertEq(pathUSD.balanceOf(alice), 700e6);
        assertEq(pathUSD.balanceOf(charlie), 300e6);
    }

    /*//////////////////////////////////////////////////////////////
                            DEPOSIT BACKLOG
    //////////////////////////////////////////////////////////////*/

    function test_depositBacklog_doesNotBlockQueuedPayouts() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        address outsider = address(0xD00D);
        Withdrawal memory c = _plain(address(pathUSD), outsider, 100e6);
        _withdraw(_one(_plain(address(pathUSD), charlie, MAX)));
        _withdraw(_two(_plain(address(pathUSD), bob, 1500e6), _depositBounceBack(200e6)));
        _withdraw(_one(c));
        // Far more unsettled entries than one Zone block processes.
        _setUnprocessedDeposits(1000);
        uint64 depositsBefore = portal.depositCount();

        _skip(PERIOD);
        assertEq(_processQueued(address(pathUSD)), 0);
        _skip(PERIOD);
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(outsider, c.senderTag, address(pathUSD), 100e6, false);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 2, 0, 0);
        assertEq(_processQueued(address(pathUSD)), 3);

        assertEq(pathUSD.balanceOf(bob), 1500e6);
        assertEq(pathUSD.balanceOf(alice), 200e6);
        assertEq(portal.depositCount(), depositsBefore + 1, "only the failed transfer bounces back");
        assertEq(_available(address(pathUSD)), MAX - 700e6, "the bounce-back takes no capacity");
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, 3);
        assertEq(tail, 3);
    }

    /// @dev A queued transfer that bounces appends to the TIP-1171 deposit queue like any other
    ///      bounce-back: it lands on a real checkpoint, counts toward congestion, and pays no
    ///      premium.
    function test_queuedTransferBounce_crossesDepositCheckpoint() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        address outsider = address(0xD00D);
        Withdrawal memory w = _plain(address(pathUSD), outsider, 1500e6);
        _withdraw(_two(_plain(address(pathUSD), bob, MAX), w));

        // Failed transfers of the unlimited token bounce from the main queue, one entry each,
        // until the next append is a checkpoint entry.
        _withdraw(_one(_plain(address(token1), outsider, 1)));
        uint64 base = portal.depositBucketBase();
        uint64 perBucket = portal.DEPOSITS_PER_BUCKET();
        uint256 fill = perBucket - 1 - (portal.depositCount() - base) % perBucket;
        Withdrawal[] memory bounces = new Withdrawal[](fill);
        for (uint256 i; i < fill; ++i) {
            bounces[i] = _plain(address(token1), outsider, uint128(i + 2));
        }
        if (fill != 0) _withdraw(bounces);
        uint64 thisDeposit = portal.depositCount() + 1;
        assertEq((thisDeposit - base) % perBucket, 0);
        uint256 checkpoint = (thisDeposit - base) / perBucket;
        vm.expectRevert();
        portal.depositBuckets(checkpoint);
        uint128 feeBefore = portal.calculateDepositFee();

        bytes32 expectedHash = DepositQueueLib.enqueue(
            portal.currentDepositQueueHash(),
            WithdrawalBounceBackDeposit({
                token: address(pathUSD), to: address(uint160(w.fallbackNonce)), amount: 1500e6
            })
        );
        uint256 escrowBefore = pathUSD.balanceOf(address(portal));
        uint256 adminBefore = pathUSD.balanceOf(admin);

        _skip(PERIOD);
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalBounceBack(
            expectedHash, w.fallbackNonce, address(pathUSD), 1500e6, thisDeposit
        );
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 0, 0);
        assertEq(_processQueued(address(pathUSD)), 1);

        assertEq(portal.currentDepositQueueHash(), expectedHash);
        assertEq(portal.depositCount(), thisDeposit);
        (bytes32 bucketHash,) = portal.depositBuckets(checkpoint);
        assertEq(bucketHash, expectedHash);
        assertEq(pathUSD.balanceOf(address(portal)), escrowBefore, "the whole amount stays");
        assertEq(pathUSD.balanceOf(admin), adminBefore, "no premium or fee");
        assertEq(_available(address(pathUSD)), MAX, "no capacity used");
        // It crosses a congestion tier, so the next deposit pays a premium this one did not.
        assertGt(portal.calculateDepositFee(), feeBefore, "premium for the next deposit");
    }

    /*//////////////////////////////////////////////////////////////
                               REFUNDS
    //////////////////////////////////////////////////////////////*/

    function _disallow(address account) internal {
        vm.prank(admin);
        portal.setAllowedAccount(account, false);
    }

    function _allow(address account) internal {
        vm.prank(admin);
        portal.setAllowedAccount(account, true);
    }

    function test_parkedRefund_mainQueueUsesNoCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(400e6)));
        assertEq(portal.refunds(address(pathUSD), alice), 400e6);
        assertEq(_available(address(pathUSD)), MAX);
    }

    function test_parkedRefund_tokenQueueUsesNoCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_depositBounceBack(2500e6)));
        _processQueued(address(pathUSD));
        assertEq(pathUSD.balanceOf(alice), MAX);

        // The refund now fails: the whole remainder is parked at once, consuming no capacity.
        _disallow(alice);
        _skip(PERIOD);
        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBackPending(alice, address(pathUSD), 1500e6, 0);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 0, 0);
        assertEq(_processQueued(address(pathUSD)), 1);

        assertEq(portal.refunds(address(pathUSD), alice), 1500e6);
        assertEq(_available(address(pathUSD)), MAX);
        (uint64 head,) = _queue(address(pathUSD));
        assertEq(head, 1);
        _assertRecordDeleted(address(pathUSD), 0);
    }

    function test_parkedRefund_feeTakesCapacity() public {
        vm.prank(admin);
        portal.setBouncebackGas(100_000);
        vm.fee(1e12 * 100); // fee = 10e6
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_two(_plain(address(pathUSD), bob, MAX), _depositBounceBack(2500e6)));
        _disallow(alice);
        _skip(PERIOD);

        vm.expectEmit(address(portal));
        emit IZonePortal.DepositBounceBackPending(alice, address(pathUSD), 2490e6, 10e6);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 10e6, 0);
        assertEq(_processQueued(address(pathUSD)), 1);
        assertEq(portal.refunds(address(pathUSD), alice), 2490e6);
        assertEq(_available(address(pathUSD)), MAX - 10e6);
    }

    function test_claimRefund_limitedByCapacityAcrossPeriods() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        uint256 start = vm.getBlockTimestamp();
        uint256 escrowBefore = pathUSD.balanceOf(address(portal));
        _disallow(alice);
        // Refunds parked over several periods, from the token queue and the main queue.
        _withdraw(_one(_depositBounceBack(3000e6)));
        _processQueued(address(pathUSD));
        for (uint256 i; i < 3; ++i) {
            _skip(PERIOD);
            _withdraw(_one(_depositBounceBack(200e6)));
        }
        assertEq(portal.refunds(address(pathUSD), alice), 3600e6);
        assertEq(_available(address(pathUSD)), MAX);
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, tail, "claims need an empty token queue");

        _allow(alice);
        vm.prank(alice);
        vm.expectEmit(address(portal));
        emit IZonePortal.RefundClaimed(alice, address(pathUSD), MAX);
        assertEq(portal.claimRefund(address(pathUSD)), MAX);
        assertEq(portal.refunds(address(pathUSD), alice), 2600e6);
        assertEq(_available(address(pathUSD)), 0);

        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 0);
        _skip(250);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 250e6);
        assertEq(portal.refunds(address(pathUSD), alice), 2350e6);

        // Every outflow since the limit was set stays within maxAmount + elapsed * rate.
        uint256 elapsed = vm.getBlockTimestamp() - start;
        uint256 outflow = escrowBefore - pathUSD.balanceOf(address(portal));
        assertEq(outflow, 1250e6);
        assertLe(outflow, MAX + elapsed * MAX / PERIOD);

        // A claimed refund takes capacity a later withdrawal would have used.
        _withdraw(_one(_plain(address(pathUSD), bob, 1e6)));
        assertEq(pathUSD.balanceOf(bob), 0);
    }

    /// @dev A callback reserves its amount before delivery, so a claimRefund it reenters gets only
    ///      the capacity left after that reservation.
    function test_claimRefund_reenteredFromCallbackGetsCapacityLeft() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        RefundClaimingReceiver claimer = new RefundClaimingReceiver(portal, address(pathUSD));
        Withdrawal memory parked = _depositBounceBack(500e6);
        parked.to = address(claimer);
        _withdraw(_one(parked));
        assertEq(portal.refunds(address(pathUSD), address(claimer)), 500e6);
        assertEq(_available(address(pathUSD)), MAX, "parking takes no capacity");
        _openModes();
        uint256 escrowBefore = pathUSD.balanceOf(address(portal));

        Withdrawal memory cb = _plain(address(pathUSD), address(claimer), 600e6);
        cb.gasLimit = CALLBACK_GAS;
        cb.callbackData = "cb";
        _settle(_one(cb));
        vm.expectEmit(address(portal));
        emit IZonePortal.RefundClaimed(address(claimer), address(pathUSD), 400e6);
        portal.processWithdrawals(_one(cb), bytes32(0));

        assertEq(claimer.claimed(), 400e6);
        assertEq(portal.refunds(address(pathUSD), address(claimer)), 100e6);
        assertEq(_available(address(pathUSD)), 0);
        assertEq(escrowBefore - pathUSD.balanceOf(address(portal)), MAX, "outflow is maxAmount");
    }

    function test_claimRefund_unlimitedTokenPaysAll() public {
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(5000e6)));
        _allow(alice);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 5000e6);
        assertEq(portal.refunds(address(pathUSD), alice), 0);
        assertEq(pathUSD.balanceOf(alice), 5000e6);
    }

    function test_claimRefund_paysNothingWhileLimitedTokenHasBacklog() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(400e6)));
        _allow(alice);
        _withdraw(_one(_plain(address(pathUSD), bob, 1500e6)));
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(tail - head, 1, "backlog");

        // Capacity covers the claim, but the token has a backlog.
        assertEq(_available(address(pathUSD)), MAX);
        vm.prank(alice);
        vm.expectEmit(address(portal));
        emit IZonePortal.RefundClaimed(alice, address(pathUSD), 0);
        assertEq(portal.claimRefund(address(pathUSD)), 0);
        assertEq(portal.refunds(address(pathUSD), alice), 400e6);
        assertEq(_available(address(pathUSD)), MAX, "a blocked claim takes no capacity");
        assertEq(pathUSD.balanceOf(alice), 0);

        // The first installment leaves the record partly paid, still a backlog.
        _processQueued(address(pathUSD));
        _skip(PERIOD);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 0);

        // Once the queue is empty, the claim takes what the last installment left.
        _processQueued(address(pathUSD));
        assertEq(pathUSD.balanceOf(bob), 1500e6);
        assertEq(_available(address(pathUSD)), 500e6);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 400e6);
        assertEq(portal.refunds(address(pathUSD), alice), 0);
        assertEq(_available(address(pathUSD)), 100e6);
        assertEq(pathUSD.balanceOf(alice), 400e6);
    }

    function test_claimRefund_paysNothingWhileUnlimitedTokenHasBacklog() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(400e6)));
        _allow(alice);
        _withdraw(_one(_plain(address(pathUSD), bob, 1500e6)));
        // Removing the limit leaves the backlog in place.
        _setLimit(address(pathUSD), 0, 0);

        vm.prank(alice);
        vm.expectEmit(address(portal));
        emit IZonePortal.RefundClaimed(alice, address(pathUSD), 0);
        assertEq(portal.claimRefund(address(pathUSD)), 0);
        assertEq(portal.refunds(address(pathUSD), alice), 400e6);

        assertEq(_processQueued(address(pathUSD)), 1);
        assertEq(pathUSD.balanceOf(bob), 1500e6);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 400e6);
        assertEq(portal.refunds(address(pathUSD), alice), 0);
        assertEq(pathUSD.balanceOf(alice), 400e6);
    }

    /// @dev A record larger than maxAmount waits for full capacity for each installment. A refund
    ///      recipient claiming every block would otherwise keep capacity below maxAmount forever.
    function test_claimRefund_everyBlockCannotStallInstallment() public {
        uint128 maxAmount = 1000;
        uint64 period = 10; // refills 100 units per second
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(5000)));
        _allow(alice);
        assertEq(portal.refunds(address(pathUSD), alice), 5000);

        _setLimit(address(pathUSD), maxAmount, period);
        // The first payout empties capacity, and the 1500 record waits at the head.
        _withdraw(_two(_plain(address(pathUSD), bob, 1000), _plain(address(pathUSD), bob, 1500)));
        assertEq(_available(address(pathUSD)), 0);
        assertEq(_remaining(address(pathUSD), 0), 1500);

        // Each block, the refund recipient claims before anyone pays the queue.
        for (uint256 i; i < 15; ++i) {
            vm.roll(block.number + 1);
            _skip(1);
            vm.prank(alice);
            assertEq(portal.claimRefund(address(pathUSD)), 0);
            _processQueued(address(pathUSD));
        }

        // A full installment after 10 seconds, the last 500 five seconds later.
        (uint64 head, uint64 tail) = _queue(address(pathUSD));
        assertEq(head, tail, "queue drained");
        assertEq(pathUSD.balanceOf(bob), 2500);
        assertEq(pathUSD.balanceOf(alice), 0);
        assertEq(portal.refunds(address(pathUSD), alice), 5000);

        vm.roll(block.number + 1);
        _skip(1);
        vm.prank(alice);
        assertEq(portal.claimRefund(address(pathUSD)), 100);
    }

    function test_claimRefund_blockedWhilePaused() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _disallow(alice);
        _withdraw(_one(_depositBounceBack(100e6)));
        _allow(alice);
        vm.prank(admin);
        portal.pause();
        vm.prank(alice);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.claimRefund(address(pathUSD));
    }

}
