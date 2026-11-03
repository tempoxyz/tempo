// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    IWithdrawalReceiver,
    IZoneFactory,
    IZonePortal,
    Withdrawal,
    ZONE_FACTORY_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { WithdrawalQueueLib } from "../../src/runtime/libraries/WithdrawalQueueLib.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @notice Callback receiver that rejects any delivery that arrives with less than its gasLimit.
contract GasCheckingReceiver is IWithdrawalReceiver {

    uint256 public immutable minimumGas;
    /// @dev Starts at 1 so counting a call never creates a storage slot (250,000 gas on Tempo).
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

/// @notice TIP-1150 per-token withdrawal limits and the per-token withdrawal queue.
contract ZonePortalWithdrawalLimitTest is BaseTest {

    bytes32 internal constant TOKEN_CURSOR_SLOT = bytes32(uint256(28));
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
            senderTag: keccak256(abi.encode(amount, to)),
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

    /// @dev Settles one batch carrying ws and processes it through the main FIFO.
    function _withdraw(Withdrawal[] memory ws) internal {
        _settle(ws);
        portal.processWithdrawals(ws, bytes32(0));
    }

    /// @dev Settles one batch carrying ws into the main withdrawal FIFO.
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

    function _queue(address token)
        internal
        view
        returns (uint64 head, uint64 tail, uint128 headPaid)
    {
        return portal.queuedWithdrawals(token);
    }

    function _processQueued(address token, Withdrawal[] memory ws) internal returns (uint256) {
        vm.prank(anyone);
        return portal.processQueuedWithdrawals(token, ws);
    }

    function _openModes() internal {
        vm.startPrank(admin);
        portal.setAccessMode(false);
        portal.setGatewayMode(false);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                             MAIN FIFO PATH
    //////////////////////////////////////////////////////////////*/

    function test_unlimitedToken_deliversImmediately() public {
        uint256 before = pathUSD.balanceOf(bob);
        _withdraw(_one(_plain(address(pathUSD), bob, 50_000e6)));

        assertEq(pathUSD.balanceOf(bob), before + 50_000e6);
        (uint64 head, uint64 tail,) = _queue(address(pathUSD));
        assertEq(head, 0);
        assertEq(tail, 0);
        (uint128 maxAmount, uint64 period, uint128 available) =
            portal.withdrawalLimit(address(pathUSD));
        assertEq(maxAmount, 0);
        assertEq(period, 0);
        assertEq(available, 0);
    }

    function test_limit_exactFitDeliversAndConsumesCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        uint256 before = pathUSD.balanceOf(bob);

        _withdraw(_one(_plain(address(pathUSD), bob, MAX)));

        assertEq(pathUSD.balanceOf(bob), before + MAX);
        assertEq(_available(address(pathUSD)), 0);
        vm.warp(block.timestamp + 10);
        assertEq(_available(address(pathUSD)), 10e6);
    }

    function test_limit_oneUnitOverIsQueued() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, MAX + 1);
        uint256 before = pathUSD.balanceOf(bob);

        _settle(_one(w));
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalQueued(address(pathUSD), 0, keccak256(abi.encode(w)), MAX + 1);
        portal.processWithdrawals(_one(w), bytes32(0));

        assertEq(pathUSD.balanceOf(bob), before);
        (uint64 head, uint64 tail, uint128 headPaid) = _queue(address(pathUSD));
        assertEq(head, 0);
        assertEq(tail, 1);
        assertEq(headPaid, 0);
        assertEq(portal.queuedWithdrawalAt(address(pathUSD), 0), keccak256(abi.encode(w)));
        assertEq(_available(address(pathUSD)), MAX);
    }

    function test_queuedPlainWithdrawal_isPaidInPartsByAnyone() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        uint256 before = pathUSD.balanceOf(bob);

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(bob, w.senderTag, address(pathUSD), MAX, true);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, MAX, 1500e6);
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        assertEq(pathUSD.balanceOf(bob), before + MAX);
        (,, uint128 headPaid) = _queue(address(pathUSD));
        assertEq(headPaid, MAX);

        // Nothing has refilled yet: the call stops without reverting.
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        assertEq(pathUSD.balanceOf(bob), before + MAX);

        vm.warp(block.timestamp + 500);
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        assertEq(pathUSD.balanceOf(bob), before + 1500e6);

        vm.warp(block.timestamp + PERIOD);
        assertEq(_processQueued(address(pathUSD), _one(w)), 1);
        assertEq(pathUSD.balanceOf(bob), before + 2500e6);
        (uint64 head, uint64 tail, uint128 paid) = _queue(address(pathUSD));
        assertEq(head, 1);
        assertEq(tail, 1);
        assertEq(paid, 0);
        assertEq(portal.queuedWithdrawalAt(address(pathUSD), 0), bytes32(0));
        assertEq(_available(address(pathUSD)), 0);
    }

    function test_queue_keepsOrderWithinTokenWhileOtherTokenFlows() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory big = _plain(address(pathUSD), bob, 1500e6);
        Withdrawal memory other = _plain(address(token1), bob, 100e6);
        Withdrawal memory small = _plain(address(pathUSD), charlie, 10e6);
        Withdrawal[] memory ws = new Withdrawal[](3);
        ws[0] = big;
        ws[1] = other;
        ws[2] = small;
        uint256 bobBefore = pathUSD.balanceOf(bob);
        uint256 charlieBefore = pathUSD.balanceOf(charlie);

        _withdraw(ws);

        // The other token flows; the small pathUSD withdrawal waits behind the backlog even
        // though it fits the remaining capacity.
        assertEq(token1.balanceOf(bob), 100e6);
        assertEq(pathUSD.balanceOf(charlie), charlieBefore);
        (uint64 head, uint64 tail,) = _queue(address(pathUSD));
        assertEq(head, 0);
        assertEq(tail, 2);
        assertEq(_available(address(pathUSD)), MAX);

        Withdrawal[] memory queued = _two(big, small);
        assertEq(_processQueued(address(pathUSD), queued), 0);
        assertEq(pathUSD.balanceOf(bob), bobBefore + MAX);
        assertEq(pathUSD.balanceOf(charlie), charlieBefore);

        vm.warp(block.timestamp + 500);
        assertEq(_processQueued(address(pathUSD), queued), 1);
        assertEq(pathUSD.balanceOf(bob), bobBefore + 1500e6);
        assertEq(pathUSD.balanceOf(charlie), charlieBefore);

        vm.warp(block.timestamp + 10);
        assertEq(_processQueued(address(pathUSD), _one(small)), 1);
        assertEq(pathUSD.balanceOf(charlie), charlieBefore + 10e6);
        (head, tail,) = _queue(address(pathUSD));
        assertEq(head, 2);
        assertEq(tail, 2);
    }

    function test_callbackOverMaxAmount_bouncesBackToZone() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _callback(MAX + 1);
        uint64 depositsBefore = portal.depositCount();

        _settle(_one(w));
        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(
            address(receiver), w.senderTag, address(pathUSD), MAX + 1, false
        );
        portal.processWithdrawals(_one(w), bytes32(0));

        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(receiver.calls(), 0);
        (, uint64 tail,) = _queue(address(pathUSD));
        assertEq(tail, 0);
        assertEq(_available(address(pathUSD)), MAX);
    }

    function test_queuedCallback_waitsUntilItFitsAndRequiresGas() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory first = _plain(address(pathUSD), bob, 600e6);
        Withdrawal memory cb = _callback(500e6);
        _withdraw(_two(first, cb));
        assertEq(_available(address(pathUSD)), 400e6);

        // Callbacks are never split: it waits for the whole amount.
        assertEq(_processQueued(address(pathUSD), _one(cb)), 0);
        assertEq(receiver.calls(), 0);

        vm.warp(block.timestamp + 100);
        // Only sequencers deliver callbacks: anyone else stops at the entry and nothing changes.
        assertEq(_processQueued(address(pathUSD), _one(cb)), 0);
        assertEq(receiver.calls(), 0);
        assertEq(_available(address(pathUSD)), 500e6);

        vm.expectRevert(IZonePortal.InsufficientCallbackGas.selector);
        portal.processQueuedWithdrawals{ gas: 450_000 }(address(pathUSD), _one(cb));

        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 500e6, 0);
        assertEq(portal.processQueuedWithdrawals(address(pathUSD), _one(cb)), 1);
        assertEq(receiver.calls(), 1);
        assertEq(pathUSD.balanceOf(address(receiver)), 500e6);
        assertEq(_available(address(pathUSD)), 0);
    }

    /// @notice At every gas amount the portal accepts, the callback receives its full gasLimit:
    ///         a permissionless caller can make the call revert, never force a bounce.
    function test_queuedCallback_acceptedGasAlwaysFundsCallback() public {
        _openModes();
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory cb = _callback(MAX);
        // The over-limit callback bounces first, so the deposit queue's slots already exist and a
        // later bounce is cheap enough to succeed in the gas the portal keeps back.
        Withdrawal[] memory ws = new Withdrawal[](3);
        ws[0] = _plain(address(pathUSD), bob, 1);
        ws[1] = _callback(MAX + 1);
        ws[2] = cb;
        _withdraw(ws);
        assertEq(portal.depositCount(), 1);
        vm.warp(block.timestamp + 1);
        bytes memory data =
            abi.encodeCall(IZonePortal.processQueuedWithdrawals, (address(pathUSD), _one(cb)));

        // Find the least gas that passes the portal's check.
        uint256 lo = CALLBACK_GAS;
        uint256 hi = 20_000_000;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            uint256 snapshot = vm.snapshotState();
            (bool ok, bytes memory ret) = address(portal).call{ gas: mid }(data);
            vm.revertToState(snapshot);
            if (
                !ok && ret.length == 4
                    && bytes4(ret) == IZonePortal.InsufficientCallbackGas.selector
            ) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }

        uint256 depositsBefore = portal.depositCount();
        bool anyAccepted;
        for (uint256 extra; extra <= 1_000_000; extra += 10_000) {
            uint256 snapshot = vm.snapshotState();
            (bool ok,) = address(portal).call{ gas: lo + extra }(data);
            if (ok) {
                anyAccepted = true;
                assertEq(receiver.calls(), 1, "accepted call bounced the callback");
                assertEq(portal.depositCount(), depositsBefore, "callback bounced back");
            }
            vm.revertToState(snapshot);
        }
        assertTrue(anyAccepted);
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

    function test_queuedPartFailure_bouncesRemainderAndRestoresCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        _processQueued(address(pathUSD), _one(w));
        uint256 bobPaid = pathUSD.balanceOf(bob);

        vm.prank(admin);
        portal.setAllowedAccount(bob, false);
        vm.warp(block.timestamp + 300);
        uint64 depositsBefore = portal.depositCount();

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalProcessed(bob, w.senderTag, address(pathUSD), 1500e6, false);
        vm.expectEmit(address(portal));
        emit IZonePortal.QueuedWithdrawalPaid(address(pathUSD), 0, 0, 0);
        assertEq(_processQueued(address(pathUSD), _one(w)), 1);

        assertEq(pathUSD.balanceOf(bob), bobPaid);
        assertEq(portal.depositCount(), depositsBefore + 1);
        assertEq(_available(address(pathUSD)), 300e6);
        (uint64 head,, uint128 headPaid) = _queue(address(pathUSD));
        assertEq(head, 1);
        assertEq(headPaid, 0);
    }

    function test_depositBounceBack_countsAndIsPaidInPartsWithFeeOnce() public {
        vm.prank(admin);
        portal.setBouncebackGas(1_000_000);
        vm.fee(1e9); // fee = 1e6 * 1e9 / 1e12 = 1000 units
        uint128 fee = portal.calculateBouncebackFee();
        assertEq(fee, 1000);
        _setLimit(address(pathUSD), MAX, PERIOD);

        Withdrawal memory w = _depositBounceBack(2500e6);
        _withdraw(_one(w));
        (, uint64 tail,) = _queue(address(pathUSD));
        assertEq(tail, 1);

        uint256 aliceBefore = pathUSD.balanceOf(alice);
        uint256 adminBefore = pathUSD.balanceOf(admin);
        _processQueued(address(pathUSD), _one(w));
        assertEq(pathUSD.balanceOf(admin), adminBefore + fee);
        assertEq(pathUSD.balanceOf(alice), aliceBefore + MAX - fee);

        vm.warp(block.timestamp + PERIOD);
        _processQueued(address(pathUSD), _one(w));
        assertEq(pathUSD.balanceOf(admin), adminBefore + fee);
        assertEq(pathUSD.balanceOf(alice), aliceBefore + 2 * MAX - fee);

        vm.warp(block.timestamp + PERIOD);
        assertEq(_processQueued(address(pathUSD), _one(w)), 1);
        assertEq(pathUSD.balanceOf(admin), adminBefore + fee);
        assertEq(pathUSD.balanceOf(alice), aliceBefore + 2500e6 - fee);
        assertEq(_available(address(pathUSD)), 500e6);
    }

    /// @notice A deposit bounce-back's first part waits until it covers the whole fee, so a caller
    ///         cannot shrink the fee by paying a tiny first part.
    function test_depositBounceBack_firstPartWaitsForFullFee() public {
        vm.prank(admin);
        portal.setBouncebackGas(1_000_000);
        vm.fee(1e9);
        uint128 fee = portal.calculateBouncebackFee();
        assertEq(fee, 1000);
        _setLimit(address(pathUSD), 10_000, PERIOD); // refills 10 units per second

        Withdrawal memory w = _depositBounceBack(50_000);
        _withdraw(_two(_plain(address(pathUSD), bob, 9500), w));
        assertEq(_available(address(pathUSD)), 500);

        uint256 adminBefore = pathUSD.balanceOf(admin);
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        (,, uint128 headPaid) = _queue(address(pathUSD));
        assertEq(headPaid, 0);
        assertEq(pathUSD.balanceOf(admin), adminBefore);
        assertEq(_available(address(pathUSD)), 500);

        vm.warp(block.timestamp + 50);
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        (,, headPaid) = _queue(address(pathUSD));
        assertEq(headPaid, 1000);
        assertEq(pathUSD.balanceOf(admin), adminBefore + fee);
    }

    function test_depositBounceBack_fitConsumesCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        uint256 aliceBefore = pathUSD.balanceOf(alice);
        _withdraw(_one(_depositBounceBack(400e6)));
        assertEq(pathUSD.balanceOf(alice), aliceBefore + 400e6);
        assertEq(_available(address(pathUSD)), 600e6);
    }

    /*//////////////////////////////////////////////////////////////
                            CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    function test_setWithdrawalLimit_onlyFactoryOwner() public {
        vm.prank(admin);
        vm.expectRevert(IZonePortal.NotWithdrawalLimitAuthority.selector);
        portal.setWithdrawalLimit(address(pathUSD), MAX, PERIOD);

        vm.expectRevert(IZonePortal.NotWithdrawalLimitAuthority.selector);
        portal.setWithdrawalLimit(address(pathUSD), MAX, PERIOD);

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalLimitSet(address(pathUSD), MAX, PERIOD);
        _setLimit(address(pathUSD), MAX, PERIOD);
        (uint128 maxAmount, uint64 period, uint128 available) =
            portal.withdrawalLimit(address(pathUSD));
        assertEq(maxAmount, MAX);
        assertEq(period, PERIOD);
        assertEq(available, MAX);
    }

    function test_setWithdrawalLimit_rejectsInvalidConfigurations() public {
        uint64 maxPeriod = portal.MAX_WITHDRAWAL_LIMIT_PERIOD();
        assertEq(maxPeriod, 7 days);
        vm.startPrank(limitAuthority);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 0, 1);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), MAX, 0);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), 99, 100);
        vm.expectRevert(IZonePortal.InvalidWithdrawalLimit.selector);
        portal.setWithdrawalLimit(address(pathUSD), MAX, maxPeriod + 1);
        vm.expectRevert(IZonePortal.TokenNotEnabled.selector);
        portal.setWithdrawalLimit(address(token2), MAX, PERIOD);

        portal.setWithdrawalLimit(address(pathUSD), maxPeriod, maxPeriod);
        portal.setWithdrawalLimit(address(pathUSD), 0, 0);
        vm.stopPrank();
    }

    function test_setWithdrawalLimit_lowersCapAndRaisesWithoutAddingCapacity() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        _withdraw(_one(_plain(address(pathUSD), bob, 800e6)));
        assertEq(_available(address(pathUSD)), 200e6);

        // Refill under the old limit first, then keep that capacity.
        vm.warp(block.timestamp + 100);
        _setLimit(address(pathUSD), 5 * MAX, PERIOD);
        assertEq(_available(address(pathUSD)), 300e6);
        vm.warp(block.timestamp + 10);
        assertEq(_available(address(pathUSD)), 350e6);

        _setLimit(address(pathUSD), 100e6, 100);
        assertEq(_available(address(pathUSD)), 100e6);
    }

    function test_removingLimit_drainsBacklogInFullAndKeepsOrder() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        uint256 before = pathUSD.balanceOf(bob);
        _processQueued(address(pathUSD), _one(w));

        vm.expectEmit(address(portal));
        emit IZonePortal.WithdrawalLimitSet(address(pathUSD), 0, 0);
        _setLimit(address(pathUSD), 0, 0);

        // A later withdrawal of the token still waits behind the backlog.
        Withdrawal memory later = _plain(address(pathUSD), charlie, 5e6);
        uint256 charlieBefore = pathUSD.balanceOf(charlie);
        _withdraw(_one(later));
        assertEq(pathUSD.balanceOf(charlie), charlieBefore);

        assertEq(_processQueued(address(pathUSD), _two(w, later)), 2);
        assertEq(pathUSD.balanceOf(bob), before + 2500e6);
        assertEq(pathUSD.balanceOf(charlie), charlieBefore + 5e6);

        // With the backlog drained, the token flows directly again.
        _withdraw(_one(_plain(address(pathUSD), charlie, 7e6)));
        assertEq(pathUSD.balanceOf(charlie), charlieBefore + 12e6);
    }

    function test_pause_blocksBothPathsWhileCapacityRefillsToMax() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        _processQueued(address(pathUSD), _one(w));
        assertEq(_available(address(pathUSD)), 0);

        vm.prank(admin);
        portal.pause();
        vm.prank(anyone);
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.processQueuedWithdrawals(address(pathUSD), _one(w));
        vm.expectRevert(IZonePortal.PortalIsPaused.selector);
        portal.processWithdrawals(new Withdrawal[](0), bytes32(0));

        // Limits stay configurable while paused.
        _setLimit(address(pathUSD), MAX, PERIOD);

        vm.warp(block.timestamp + 10 days);
        assertEq(_available(address(pathUSD)), MAX);

        vm.prank(admin);
        portal.resume();
        uint256 before = pathUSD.balanceOf(bob);
        assertEq(_processQueued(address(pathUSD), _one(w)), 0);
        assertEq(pathUSD.balanceOf(bob), before + MAX);
    }

    /// @notice Outside callers leave the deposit slots reserved for withdrawal processing to the
    ///         sequencer, so they cannot block processWithdrawals.
    function test_processQueuedWithdrawals_keepsSequencerDepositReserve() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));
        vm.warp(block.timestamp + PERIOD);

        // depositCount and lastProcessedDepositNumber share slot 4: leave 210 deposits unprocessed.
        uint64 publicMaximum = portal.MAX_UNPROCESSED_DEPOSITS() - 20;
        uint256 word = uint256(vm.load(address(portal), bytes32(uint256(4))));
        uint64 processed = uint64(word >> 64);
        word = (word & ~uint256(type(uint64).max)) | uint256(processed + publicMaximum);
        vm.store(address(portal), bytes32(uint256(4)), bytes32(word));

        vm.prank(anyone);
        vm.expectRevert(
            abi.encodeWithSelector(IZonePortal.DepositBlockCapacityExceeded.selector, publicMaximum)
        );
        portal.processQueuedWithdrawals(address(pathUSD), _one(w));

        assertEq(portal.processQueuedWithdrawals(address(pathUSD), _one(w)), 0);
        (,, uint128 headPaid) = _queue(address(pathUSD));
        assertEq(headPaid, MAX);
    }

    function test_processQueuedWithdrawals_rejectsWrongWithdrawal() public {
        _setLimit(address(pathUSD), MAX, PERIOD);
        Withdrawal memory w = _plain(address(pathUSD), bob, 2500e6);
        _withdraw(_one(w));

        Withdrawal memory forged = w;
        forged.amount = 2400e6;
        vm.prank(anyone);
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processQueuedWithdrawals(address(pathUSD), _one(forged));

        // Entries past the tail are empty.
        vm.warp(block.timestamp + 10 * PERIOD);
        vm.prank(anyone);
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processQueuedWithdrawals(address(pathUSD), _two(w, w));

        // Another token's queue does not hold it.
        vm.prank(anyone);
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processQueuedWithdrawals(address(token1), _one(w));
    }

}
