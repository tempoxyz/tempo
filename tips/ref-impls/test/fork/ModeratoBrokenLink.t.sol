// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";

/// @title Pinpoint the tx that corrupted order 7122508's linked list pointer
/// @dev Fork at block 5271468 (one before corruption block 5271469).
///      Replays each DEX tx in order and checks if 7122508.next becomes 7305967.
///      Run with: --fork-url <moderato> --fork-block-number 5271468
contract ModeratoBrokenLinkTest is Test {

    IStablecoinDEX constant DEX = IStablecoinDEX(0xDEc0000000000000000000000000000000000000);
    uint128 constant VICTIM = 7122508;
    uint128 constant GHOST = 7305967;

    function test_verifyCleanState() public view {
        IStablecoinDEX.Order memory o = DEX.getOrder(VICTIM);
        console.log("Before block 5271469:");
        console.log("  order 7122508.next =", o.next);
        console.log("  nextOrderId =", DEX.nextOrderId());
        assertEq(o.next, 0, "next should be 0 before corruption");
    }

    function test_replayToFindCorruption() public {
        IStablecoinDEX.Order memory before = DEX.getOrder(VICTIM);
        assertEq(before.next, 0, "precondition failed");

        // Replay all 8 DEX txs from block 5271469 in order

        _replay(0xF42CF45b8278f7524AfcDAA10E3630df4771A00F, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000300000000000000000000000020c0000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000ad91980000000000000000000000000000000000000000000000000000000000ab5332a", "idx=27");

        _replay(0x4805FC80A5Cb327FCAf96BF25002c3a7Bba90017, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000100000000000000000000000020c0000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000003567e0000000000000000000000000000000000000000000000000000000000035376efc", "idx=31");

        _replay(0x09aE41BbD2954b32D39019f74cC0223967adeE26, hex"f0122b7500000000000000000000000020c000000000000000000000000000000000000200000000000000000000000020c0000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000001ad27480000000000000000000000000000000000000000000000000000000001afef01b", "idx=35");

        _replay(0x8B95686216E8CCCD7A6F92712Bd57C8fC07d13d6, hex"ce5c53e500000000000000000000000020c0000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000036fca300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "idx=41");

        _replay(0xECc45b852095929d07485936CBEC8D883d043462, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000000000000000000000000000020c0000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000001cab7a40000000000000000000000000000000000000000000000000000000001c621530", "idx=48");

        _replay(0x462587170c825BF27Cc1dc079af7f043C4cf4c68, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000100000000000000000000000020c0000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000206cc800000000000000000000000000000000000000000000000000000000002058c06", "idx=58");

        _replay(0x2c5bB2Cf2F51E0215eE1f69D6Dc23B16b3567db5, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000100000000000000000000000020c0000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000001f5a1f80000000000000000000000000000000000000000000000000000000001f3f382c", "idx=61");

        _replay(0xB8C361EA407B4e2569724cD306eD0A609937DCb9, hex"f8856c0f00000000000000000000000020c000000000000000000000000000000000000200000000000000000000000020c000000000000000000000000000000000000300000000000000000000000000000000000000000000000000000000069db9c000000000000000000000000000000000000000000000000000000000068cc9d0", "idx=78");

        // Final state
        IStablecoinDEX.Order memory final_ = DEX.getOrder(VICTIM);
        console.log("Final state:");
        console.log("  order 7122508.next =", final_.next);
        console.log("  nextOrderId =", DEX.nextOrderId());
    }

    function _replay(address from, bytes memory data, string memory label) internal {
        uint128 nextBefore = DEX.nextOrderId();

        vm.prank(from);
        (bool ok,) = address(DEX).call(data);

        IStablecoinDEX.Order memory o = DEX.getOrder(VICTIM);
        uint128 nextAfter = DEX.nextOrderId();

        if (o.next == GHOST) {
            console.log("=== CORRUPTION BY", label, "===");
            console.log("  from:", from);
            console.log("  success:", ok);
            console.log("  nextOrderId:", nextBefore, "->", nextAfter);

            try DEX.getOrder(GHOST) returns (IStablecoinDEX.Order memory g) {
                console.log("  ghost order EXISTS, remaining:", g.remaining);
                console.log("  ghost maker:", g.maker);
            } catch {
                console.log("  ghost order 7305967 DOES NOT EXIST");
            }
        } else if (o.next != 0) {
            console.log(label, ": next changed to", o.next);
        }

        if (nextAfter > nextBefore) {
            console.log(label, "nextOrderId changed:", nextBefore);
            console.log("  ->", nextAfter);
        }
    }
}
