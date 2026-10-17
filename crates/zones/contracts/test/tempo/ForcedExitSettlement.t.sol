// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {
    BlockTransition,
    DepositQueueTransition,
    IZonePortal,
    TokenEnablementTransition,
    Withdrawal,
    ZONE_VERIFIER_ADDRESS
} from "../../src/runtime/interfaces/IZone.sol";
import { getBlockHash } from "../../src/runtime/libraries/BlockHashHistory.sol";
import { Verifier } from "../../src/runtime/tempo/Verifier.sol";
import { ForcedExitTest } from "./ForcedExit.t.sol";
import { Vm } from "forge-std/Vm.sol";

contract ForcedExitSettlementTest is ForcedExitTest {

    uint256 constant SIGNER_KEY = 0xabc123;
    string constant TYPE =
        "SettlementAttestation(uint32 zoneId,uint64 sequencerSetVersion,uint256 zoneHeight,uint256 withdrawalBatchIndex,address verifier,uint64 tempoBlockNumber,uint64 anchorBlockNumber,bytes32 anchorBlockHash,bytes32 blockTransitionHash,bytes32 depositQueueTransitionHash,bytes32 tokenEnablementTransitionHash,bytes32 withdrawalQueueHash,bytes32 verifierConfigHash)";

    function setUp() public override {
        sequencer = vm.addr(SIGNER_KEY);
        super.setUp();
        vm.etch(ZONE_VERIFIER_ADDRESS, address(new Verifier()).code);
    }

    function transitions(uint64 processed)
        internal
        view
        returns (BlockTransition memory b, DepositQueueTransition memory d)
    {
        b = BlockTransition(
            portal.blockHash(), keccak256(abi.encode("tip", portal.zoneHeight() + 1))
        );
        d = DepositQueueTransition(
            bytes32(0),
            portal.currentDepositQueueHash(),
            portal.lastProcessedDepositNumber(),
            processed
        );
    }

    function certificate(
        uint64 tempo,
        uint64 processed,
        bytes32 queue
    )
        internal
        view
        returns (bytes32)
    {
        (BlockTransition memory b, DepositQueueTransition memory d) = transitions(processed);
        bytes32 domain = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("ZonePortal"),
                keccak256("1"),
                block.chainid,
                address(portal)
            )
        );
        bytes32 statement = keccak256(
            abi.encode(
                keccak256(bytes(TYPE)),
                portal.zoneId(),
                portal.sequencerSetVersion(),
                portal.zoneHeight() + 1,
                uint256(portal.withdrawalBatchIndex() + 1),
                portal.verifier(),
                tempo,
                tempo,
                getBlockHash(tempo),
                keccak256(abi.encode(b)),
                keccak256(abi.encode(d)),
                keccak256(
                    abi.encode(
                        TokenEnablementTransition(
                            portal.lastProcessedEnabledTokenCount(),
                            uint64(portal.enabledTokenCount())
                        )
                    )
                ),
                queue,
                keccak256("")
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domain, statement));
    }

    function submit(uint64 tempo, uint64 processed, bytes32 queue, bytes32 digest) external {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        (BlockTransition memory b, DepositQueueTransition memory d) = transitions(processed);
        uint256 height = portal.zoneHeight() + 1;
        TokenEnablementTransition memory tokens = TokenEnablementTransition(
            portal.lastProcessedEnabledTokenCount(), uint64(portal.enabledTokenCount())
        );
        vm.prank(sequencer);
        portal.submitBatch(tempo, 0, b, d, tokens, queue, "", "", height, signatures);
    }

    function test_activated_forced_requests_use_existing_selector_statement_and_event() public {
        uint64 count =
            (portal.MAX_UNPROCESSED_DEPOSITS() - 20) / portal.FORCED_EXIT_ADMISSION_WEIGHT();
        for (uint64 i; i < count; ++i) {
            request(384);
        }
        uint64 tempo = uint64(vm.getBlockNumber());
        vm.roll(vm.getBlockNumber() + 1);
        bytes32 digest = certificate(tempo, count, bytes32(0));
        vm.expectRevert(IZonePortal.InvalidQuorumCertificate.selector);
        this.submit(tempo, count, bytes32("tampered"), digest);
        vm.recordLogs();
        uint256 beforeGas = gasleft();
        this.submit(tempo, count, bytes32(0), digest);
        uint256 used = beforeGas - gasleft();
        emit log_named_uint("forced inbox cursor settlement gas", used);
        assertLt(used + 1_000_000, 30_000_000);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 portalEvents;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(portal)) {
                ++portalEvents;
                assertEq(logs[i].topics[0], IZonePortal.BatchSubmitted.selector);
            }
        }
        assertEq(portalEvents, 1);
        assertEq(portal.lastProcessedDepositNumber(), count);
        assertEq(
            IZonePortal.submitBatch.selector,
            bytes4(
                keccak256(
                    "submitBatch(uint64,uint64,(bytes32,bytes32),(bytes32,bytes32,uint64,uint64),(uint64,uint64),bytes32,bytes,bytes,uint256,bytes[])"
                )
            )
        );
    }

    function test_forced_withdrawals_use_ordinary_delivery_and_bounceback() public {
        request(384);
        request(384);
        vm.prank(pathUSDAdmin);
        pathUSD.mint(address(portal), 100);
        Withdrawal[] memory withdrawals = new Withdrawal[](2);
        // Private hashes stand in for canonical authorized plaintext, checked by Zone execution.
        withdrawals[0] = Withdrawal(
            address(pathUSD),
            keccak256(abi.encodePacked(alice, bytes32("private1"), uint64(1))),
            bob,
            40,
            0,
            0,
            1,
            "",
            ""
        );
        withdrawals[1] = Withdrawal(
            address(pathUSD),
            keccak256(abi.encodePacked(alice, bytes32("private2"), uint64(2))),
            address(0x12345),
            60,
            0,
            0,
            2,
            "",
            ""
        );
        bytes32 queue = keccak256(abi.encode(withdrawals[1], bytes32(0)));
        queue = keccak256(abi.encode(withdrawals[0], queue));
        uint64 tempo = uint64(vm.getBlockNumber());
        vm.roll(vm.getBlockNumber() + 1);
        this.submit(tempo, 2, queue, certificate(tempo, 2, queue));
        uint256 beforeBalance = pathUSD.balanceOf(bob);
        vm.prank(sequencer);
        portal.processWithdrawals(withdrawals, bytes32(0));
        assertEq(pathUSD.balanceOf(bob), beforeBalance + 40);
        assertEq(pathUSD.balanceOf(address(portal)), 60);
        assertEq(portal.depositCount(), 3);
        assertEq(portal.lastProcessedDepositNumber(), 2);
    }

}
