// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    IZonePortal,
    Role,
    Withdrawal,
    ZONE_FACTORY_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { ZonePortal } from "../../src/runtime/tempo/ZonePortal.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { WithdrawalHasher } from "../mocks/WithdrawalHasher.sol";
import { GasCheckingReceiver } from "./ZonePortalWithdrawalLimit.t.sol";
import { Vm } from "forge-std/Vm.sol";
import { ITIP20 } from "tempo-std/interfaces/ITIP20.sol";

/// @notice Bounds fuzzed inputs and forwards each action to the test contract, which holds the
///         sequencer role.
contract WithdrawalLimitHandler {

    ZonePortalWithdrawalLimitInvariantTest internal immutable host;

    constructor(ZonePortalWithdrawalLimitInvariantTest _host) {
        host = _host;
    }

    function withdraw(uint8 kindA, uint128 amountA, uint8 kindB, uint128 amountB) external {
        host.actWithdraw(kindA, amountA, kindB, amountB);
    }

    function drain(uint8 token, uint8 maxEntries) external {
        host.actDrain(token, maxEntries);
    }

    function warp(uint32 seconds_) external {
        host.actWarp(seconds_);
    }

    function claim(uint8 token) external {
        host.actClaim(token);
    }

    function toggleAllowed(uint8 who) external {
        host.actToggleAllowed(who);
    }

    function setFee(uint64 bouncebackGas, uint64 baseFee) external {
        host.actSetFee(bouncebackGas, baseFee);
    }

    function togglePause() external {
        host.actTogglePause();
    }

    function setLimit(uint8 token, uint8 change, uint128 maxAmount, uint64 period) external {
        host.actSetLimit(token, change, maxAmount, period);
    }

}

/// @notice Stateful fuzzing of TIP-1150 limits on two tokens: main-queue payouts, queued partial
///         payouts, failed deliveries, deposit bounce-back fees, refund claims, pauses, time and
///         limit changes by the factory owner. Checks the outflow bound over every window with an
///         unchanged limit (WL1), that refund claims pay nothing during a backlog (WL5), the
///         installment pattern (WL7), capacity against maxAmount, and that every withdrawn unit
///         is paid, bounced back, parked or still queued (WL6).
contract ZonePortalWithdrawalLimitInvariantTest is BaseTest {

    uint128 internal constant MAX = 1000e6;
    uint64 internal constant PERIOD = 1000;
    uint64 internal constant CALLBACK_GAS = 200_000;
    address internal constant OUTSIDER = address(0xD00D);
    bytes32 internal constant TOKEN_CURSOR_SLOT = bytes32(uint256(28));

    /// @dev A token's outflow at one point in time, under its limit epoch.
    struct Checkpoint {
        uint256 time;
        uint256 outflow;
        uint256 epoch;
    }

    /// @dev A limit, in force from one setWithdrawalLimit call to the next.
    struct Limit {
        uint128 maxAmount;
        uint64 period;
    }

    /// @dev The reference ledger of one token.
    struct Ledger {
        uint256 escrowStart;
        uint256 withdrawn;
        uint256 bouncedToZone;
        uint256 shortInstallments;
        uint256 claimsPaidDuringBacklog;
    }

    ZonePortal internal portal;
    WithdrawalHasher internal hasher = new WithdrawalHasher();
    WithdrawalLimitHandler internal handler;
    GasCheckingReceiver internal receiver;
    address internal anyone = address(0xBEEF);

    address[2] internal tokens;
    address[] internal payees;
    mapping(address token => Ledger) internal ledgers;
    mapping(address token => Checkpoint[]) internal checkpoints;
    mapping(address token => Limit[]) internal epochs;
    mapping(address token => uint256[]) internal payeeStart;

    function setUp() public override {
        super.setUp();
        address[] memory sequencers = new address[](1);
        sequencers[0] = sequencer;
        portal = _createZonePortal(1, address(pathUSD), admin, sequencers, 1, "https://rpc.example");
        receiver = new GasCheckingReceiver(CALLBACK_GAS - 5000);

        // Authenticate the enabled-token cursor so a second token can be enabled.
        vm.store(address(portal), TOKEN_CURSOR_SLOT, bytes32(uint256(1) | (uint256(1) << 64)));
        _mockTokenPolicyMigration(address(token1), true);
        vm.startPrank(admin);
        portal.enableToken(address(token1));
        portal.setGatewayMode(false);
        portal.setAllowedAccount(address(receiver), true);
        vm.stopPrank();

        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.mint(address(portal), 10_000_000e6);
        vm.stopPrank();
        token1.grantRole(_ISSUER_ROLE, address(this));
        token1.mint(address(portal), 10_000_000e6);

        tokens = [address(pathUSD), address(token1)];
        payees = [alice, bob, charlie, admin, address(receiver), portal.messenger(), OUTSIDER];
        for (uint256 t; t < tokens.length; ++t) {
            address token = tokens[t];
            vm.prank(admin);
            portal.setWithdrawalLimit(token, MAX, PERIOD);
            epochs[token].push(Limit(MAX, PERIOD));
            for (uint256 i; i < payees.length; ++i) {
                payeeStart[token].push(_balance(token, payees[i]));
            }
            ledgers[token].escrowStart = _balance(token, address(portal));
        }
        _checkpoint();

        handler = new WithdrawalLimitHandler(this);
        targetContract(address(handler));
    }

    modifier onlyHandler() {
        require(msg.sender == address(handler));
        _;
        _checkpoint();
    }

    /*//////////////////////////////////////////////////////////////
                                ACTIONS
    //////////////////////////////////////////////////////////////*/

    function actWithdraw(
        uint8 kindA,
        uint128 amountA,
        uint8 kindB,
        uint128 amountB
    )
        external
        onlyHandler
    {
        if (portal.paused()) return;
        Withdrawal[] memory ws = new Withdrawal[](2);
        ws[0] = _withdrawal(kindA, amountA);
        ws[1] = _withdrawal(kindB, amountB);

        bytes32 queueHash;
        for (uint256 i = ws.length; i > 0; --i) {
            queueHash = hasher.hashWithTail(ws[i - 1], queueHash);
        }
        vm.roll(block.number + 1);
        uint64 processed = portal.lastProcessedDepositNumber();
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(),
                nextBlockHash: keccak256(abi.encode("invariant-batch", block.number))
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
        vm.recordLogs();
        portal.processWithdrawals(ws, bytes32(0));
        for (uint256 i; i < ws.length; ++i) {
            ledgers[ws[i].token].withdrawn += ws[i].amount;
        }
        _countLogs();
    }

    function actDrain(uint8 token, uint8 maxEntries) external onlyHandler {
        address drained = tokens[token % tokens.length];
        if (portal.paused()) {
            vm.prank(anyone);
            vm.expectRevert(IZonePortal.PortalIsPaused.selector);
            portal.processQueuedWithdrawals(drained, maxEntries);
            return;
        }
        vm.recordLogs();
        vm.prank(anyone);
        portal.processQueuedWithdrawals(drained, maxEntries);
        _countLogs();
    }

    function actWarp(uint32 seconds_) external onlyHandler {
        vm.warp(vm.getBlockTimestamp() + seconds_ % (2 * PERIOD));
    }

    function actClaim(uint8 token) external onlyHandler {
        if (portal.paused() || !portal.hasRole(alice, Role.Account)) return;
        address claimed = tokens[token % tokens.length];
        (uint64 head, uint64 tail) = portal.queuedWithdrawals(claimed);
        vm.prank(alice);
        uint128 amount = portal.claimRefund(claimed);
        if (head != tail && amount != 0) ++ledgers[claimed].claimsPaidDuringBacklog;
    }

    function actToggleAllowed(uint8 who) external onlyHandler {
        address account = [alice, bob, charlie][who % 3];
        bool allowed = portal.hasRole(account, Role.Account);
        vm.prank(admin);
        portal.setAllowedAccount(account, !allowed);
    }

    function actSetFee(uint64 bouncebackGas, uint64 baseFee) external onlyHandler {
        vm.prank(admin);
        portal.setBouncebackGas(bouncebackGas % 1_000_001);
        vm.fee(1e12 * (uint256(baseFee) % 3000));
    }

    function actTogglePause() external onlyHandler {
        bool paused = portal.paused();
        vm.prank(admin);
        if (paused) portal.resume();
        else portal.pause();
    }

    /// @dev Raises, lowers or removes a token's limit, or changes its period, as the factory
    ///      owner. maxAmount stays a nonzero multiple of period, or (0, 0) to remove it.
    function actSetLimit(
        uint8 token,
        uint8 change,
        uint128 maxAmount,
        uint64 period
    )
        external
        onlyHandler
    {
        address limited = tokens[token % tokens.length];
        Limit memory current = epochs[limited][epochs[limited].length - 1];
        Limit memory next;
        change %= 4;
        if (change == 3) {
            // Remove the limit.
        } else if (change == 2 || current.maxAmount == 0) {
            // Change the period, keeping maxAmount where it divides evenly.
            next.period = uint64(bound(period, 1, 2 * PERIOD));
            next.maxAmount = current.maxAmount == 0 ? MAX : current.maxAmount;
            next.maxAmount -= next.maxAmount % next.period;
            if (next.maxAmount == 0) next.maxAmount = next.period;
        } else {
            // Raise or lower maxAmount, as a multiple of the current period.
            next.period = current.period;
            uint128 bounded = change == 0
                ? uint128(bound(maxAmount, current.maxAmount, 3 * MAX))
                : uint128(bound(maxAmount, 1, current.maxAmount));
            next.maxAmount = bounded - bounded % next.period;
            if (next.maxAmount == 0) next.maxAmount = next.period;
        }
        vm.prank(admin);
        portal.setWithdrawalLimit(limited, next.maxAmount, next.period);
        epochs[limited].push(next);
    }

    /*//////////////////////////////////////////////////////////////
                              INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @dev WL1: outflow over any window under one unchanged limit is at most
    ///      maxAmount + window * maxAmount / period.
    function invariant_outflowWithinWindowBound() public view {
        for (uint256 t; t < tokens.length; ++t) {
            Checkpoint[] storage points = checkpoints[tokens[t]];
            for (uint256 i; i < points.length; ++i) {
                Limit memory limit = epochs[tokens[t]][points[i].epoch];
                if (limit.maxAmount == 0) continue;
                for (
                    uint256 j = i + 1;
                    j < points.length && points[j].epoch == points[i].epoch;
                    ++j
                ) {
                    uint256 window = points[j].time - points[i].time;
                    uint256 outflow = points[j].outflow - points[i].outflow;
                    assertLe(
                        outflow,
                        limit.maxAmount + window * limit.maxAmount / limit.period,
                        "window outflow"
                    );
                }
            }
        }
    }

    /// @dev Escrow outflow lands with the payees, and every withdrawn unit is paid out, bounced
    ///      back to the Zone, parked in refunds or still queued.
    function invariant_ledgerReconciles() public view {
        for (uint256 t; t < tokens.length; ++t) {
            address token = tokens[t];
            Ledger storage ledger = ledgers[token];
            uint256 outflow = ledger.escrowStart - _balance(token, address(portal));
            uint256 received;
            for (uint256 i; i < payees.length; ++i) {
                received += _balance(token, payees[i]) - payeeStart[token][i];
            }
            assertEq(received, outflow, "escrow outflow reaches payees");

            (uint64 head, uint64 tail) = portal.queuedWithdrawals(token);
            uint256 queued;
            for (uint256 i = head; i < tail; ++i) {
                uint128 remaining = portal.queuedWithdrawalAt(token, i).remaining;
                assertGt(remaining, 0, "unpaid entry");
                queued += remaining;
            }
            for (uint256 i; i < head; ++i) {
                assertEq(portal.queuedWithdrawalAt(token, i).to, address(0), "deleted");
            }
            uint256 parked = portal.refunds(token, alice);
            assertEq(
                ledger.withdrawn,
                outflow + ledger.bouncedToZone + parked + queued,
                "reference ledger"
            );
        }
    }

    /// @dev WL7: every payment that leaves a remainder is exactly the token's maxAmount at that
    ///      time, so a record is paid in one payment unless it is larger than maxAmount.
    function invariant_installmentsAreFullCapacity() public view {
        for (uint256 t; t < tokens.length; ++t) {
            assertEq(ledgers[tokens[t]].shortInstallments, 0, "short installment");
        }
    }

    /// @dev WL5: a refund claim pays nothing while its token has a backlog.
    function invariant_noRefundPaidDuringBacklog() public view {
        for (uint256 t; t < tokens.length; ++t) {
            assertEq(ledgers[tokens[t]].claimsPaidDuringBacklog, 0, "claim during backlog");
        }
    }

    /// @dev The portal holds the limit last set, and capacity never exceeds maxAmount.
    function invariant_capacityBounded() public view {
        for (uint256 t; t < tokens.length; ++t) {
            address token = tokens[t];
            Limit memory current = epochs[token][epochs[token].length - 1];
            (uint128 maxAmount, uint64 period, uint128 available) = portal.withdrawalLimit(token);
            assertEq(maxAmount, current.maxAmount);
            assertEq(period, current.period);
            assertLe(available, maxAmount);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _balance(address token, address account) internal view returns (uint256) {
        return ITIP20(token).balanceOf(account);
    }

    function _withdrawal(uint8 kind, uint128 amount) internal view returns (Withdrawal memory w) {
        amount = uint128(bound(amount, 1, 2500e6));
        address[5] memory recipients = [bob, charlie, OUTSIDER, alice, address(receiver)];
        uint256 k = kind % recipients.length;
        w = Withdrawal({
            token: tokens[(kind / recipients.length) % tokens.length],
            senderTag: keccak256(abi.encode(amount, kind, block.number)),
            to: recipients[k],
            amount: amount,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: uint64(uint160(alice)),
            callbackData: "",
            encryptedSender: "",
            senderOrg: 0
        });
        // alice receives deposit bounce-backs; the receiver takes callbacks.
        if (k == 3) w.fallbackNonce = 0;
        if (k == 4) {
            w.gasLimit = CALLBACK_GAS;
            w.callbackData = "cb";
        }
    }

    function _countLogs() internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter != address(portal)) continue;
            if (logs[i].topics[0] == IZonePortal.WithdrawalBounceBack.selector) {
                (address token, uint128 amount,) =
                    abi.decode(logs[i].data, (address, uint128, uint64));
                ledgers[token].bouncedToZone += amount;
            }
            if (logs[i].topics[0] == IZonePortal.QueuedWithdrawalPaid.selector) {
                address token = address(uint160(uint256(logs[i].topics[1])));
                (uint128 paid, uint128 remaining) = abi.decode(logs[i].data, (uint128, uint128));
                uint128 maxAmount = epochs[token][epochs[token].length - 1].maxAmount;
                if (remaining != 0 && paid != maxAmount) ++ledgers[token].shortInstallments;
            }
        }
    }

    function _checkpoint() internal {
        for (uint256 t; t < tokens.length; ++t) {
            address token = tokens[t];
            checkpoints[token].push(
                Checkpoint({
                    time: vm.getBlockTimestamp(),
                    outflow: ledgers[token].escrowStart - _balance(token, address(portal)),
                    epoch: epochs[token].length - 1
                })
            );
        }
    }

}
