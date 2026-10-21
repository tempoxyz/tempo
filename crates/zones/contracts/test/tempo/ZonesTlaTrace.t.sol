// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    IZonePortal,
    Withdrawal
} from "../../src/runtime/interfaces/IZone.sol";
import { WithdrawalQueueLib } from "../../src/runtime/libraries/WithdrawalQueueLib.sol";
import { ZonePortalTest } from "./ZonePortal.t.sol";
import { console2 } from "forge-std/console2.sol";

/// @dev Emits measured portal state for zones/formal/Replay.tla. Zone actions are fixtures:
///      the proof verifier and certificate recovery are mocked by the existing BaseTest.
contract ZonesTlaTraceTest is ZonePortalTest {

    function test_tla_successfulWithdrawal() public {
        string memory scenario = "portal-success";
        _trace(scenario, "init");
        vm.fee(0);
        _fundCallbackWithdrawal(1);
        _trace(scenario, "fund");
        _trace(scenario, "advance_ok");
        _trace(scenario, "request");
        _trace(scenario, "finalize");
        Withdrawal memory withdrawal = _traceWithdrawal(1);
        _traceSubmit(withdrawal);
        _trace(scenario, "submit");
        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));
        _trace(scenario, "deliver_ok");
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));
        _trace(scenario, "retry");
        _trace(scenario, "finalize"); // Empty zone batch fixture.
        _traceSubmitHash(bytes32(0));
        _trace(scenario, "submit");
        _trace(scenario, "complete");
    }

    function test_tla_failedWithdrawalBounces() public {
        string memory scenario = "portal-bounce";
        _trace(scenario, "init");
        vm.fee(0);
        _fundCallbackWithdrawal(1);
        _trace(scenario, "fund");
        _trace(scenario, "advance_ok");
        _trace(scenario, "request");
        _trace(scenario, "finalize");
        Withdrawal memory withdrawal = _traceWithdrawal(1);
        _traceSubmit(withdrawal);
        _trace(scenario, "submit");
        vm.prank(admin);
        portal.setAllowedAccount(alice, false);
        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));
        _trace(scenario, "deliver_fail");
        _trace(scenario, "complete");
    }

    function test_tla_failedDepositRefundIsTerminal() public {
        string memory scenario = "portal-refund";
        _trace(scenario, "init");
        vm.fee(0);
        _fundCallbackWithdrawal(1);
        _trace(scenario, "fund");
        _trace(scenario, "advance_fail");
        _trace(scenario, "finalize");
        Withdrawal memory withdrawal = _traceWithdrawal(0);
        _traceSubmit(withdrawal);
        _trace(scenario, "submit");
        vm.prank(admin);
        portal.setAllowedAccount(alice, false);
        portal.processWithdrawals(_singleWithdrawal(withdrawal), bytes32(0));
        _trace(scenario, "deliver_fail");
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(IZonePortal.AccountNotAllowed.selector, alice));
        portal.claimRefund(address(pathUSD));
        _trace(scenario, "retry");
        vm.prank(admin);
        portal.setAllowedAccount(alice, true);
        vm.prank(alice);
        portal.claimRefund(address(pathUSD));
        _trace(scenario, "claim_portal");
        vm.prank(alice);
        portal.claimRefund(address(pathUSD));
        _trace(scenario, "retry");
        _trace(scenario, "complete");
    }

    function test_tla_fifoAndPartialBatch() public {
        string memory scenario = "portal-fifo";
        _trace(scenario, "init");
        vm.fee(0);
        _fundCallbackWithdrawal(1);
        _trace(scenario, "fund");
        _fundCallbackWithdrawal(1);
        _trace(scenario, "fund");
        _trace(scenario, "advance_ok");
        _trace(scenario, "request");
        _trace(scenario, "request");
        _trace(scenario, "finalize");
        Withdrawal memory first = _traceWithdrawal(1);
        Withdrawal memory second = _traceWithdrawal(2);
        bytes32 suffix = keccak256(abi.encode(second, bytes32(0)));
        _traceSubmitHash(keccak256(abi.encode(first, suffix)));
        _trace(scenario, "submit");
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        portal.processWithdrawals(_singleWithdrawal(second), bytes32(0));
        _trace(scenario, "retry");
        portal.processWithdrawals(_singleWithdrawal(first), suffix);
        _trace(scenario, "deliver_ok");
        portal.processWithdrawals(_singleWithdrawal(second), bytes32(0));
        _trace(scenario, "deliver_ok");
        _trace(scenario, "complete");
    }

    function _traceWithdrawal(uint64 nonce) internal view returns (Withdrawal memory) {
        return Withdrawal({
            token: address(pathUSD),
            senderTag: bytes32(0),
            to: alice,
            amount: 1,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: nonce,
            callbackData: "",
            encryptedSender: ""
        });
    }

    function _traceSubmit(Withdrawal memory withdrawal) internal {
        _traceSubmitHash(keccak256(abi.encode(withdrawal, bytes32(0))));
    }

    function _traceSubmitHash(bytes32 withdrawalHash) internal {
        vm.roll(block.number + 1);
        _submitBatch(
            portal,
            uint64(block.number - 1),
            0,
            BlockTransition({
                prevBlockHash: portal.blockHash(), nextBlockHash: keccak256("tla state")
            }),
            DepositQueueTransition({
                prevProcessedHash: portal.lastProcessedDepositNumber() == 0
                    ? bytes32(0)
                    : portal.currentDepositQueueHash(),
                nextProcessedHash: portal.currentDepositQueueHash(),
                prevDepositNumber: portal.lastProcessedDepositNumber(),
                nextDepositNumber: portal.depositCount()
            }),
            withdrawalHash,
            "",
            ""
        );
    }

    function _trace(string memory scenario, string memory action) internal view {
        console2.log(
            string.concat(
                'ZONES_TLA {"scenario":"',
                scenario,
                '","action":"',
                action,
                '","state":{"escrow":',
                vm.toString(pathUSD.balanceOf(address(portal))),
                ',"portalRefund":',
                vm.toString(portal.refunds(address(pathUSD), alice)),
                ',"depositCount":',
                vm.toString(portal.depositCount()),
                ',"acceptedCursor":',
                vm.toString(portal.lastProcessedDepositNumber()),
                ',"acceptedBatches":',
                vm.toString(portal.withdrawalBatchIndex()),
                ',"head":',
                vm.toString(portal.withdrawalQueueHead()),
                ',"tail":',
                vm.toString(portal.withdrawalQueueTail()),
                "}}"
            )
        );
    }

}
