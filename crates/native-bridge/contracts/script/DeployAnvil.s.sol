// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MessageBridge.sol";

contract DeployAnvil is Script {
    function run() external {
        bytes memory g2Pubkey = hex"0000000000000000000000000000000018c6e82fdf8990fa8b78df3788c45d4a36d83dd6c4e619b7b746abe12891427dd93ccd2d00596b8a87a5b084578fd2cf000000000000000000000000000000000a1f3a02672f4b370b2601e6425f873eafeb10a62adaa093b503a8630b89994c5f1401e62001896d2bd4f858be2cb9410000000000000000000000000000000007ae7a62574cb9c8f67245c58a039c52e3ad03a869943cc20b5eb8c25eda43f6c7255aa25799fc64bdfddc9a45237f63000000000000000000000000000000000c614769f1f69fb979b3193bf920e3e036ead2e3bcf2e994506115f613bd3367600800a6c290f24b9066a73ecead97d4";
        
        vm.startBroadcast();
        MessageBridge bridge = new MessageBridge(
            0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266,
            1,
            g2Pubkey
        );
        vm.stopBroadcast();
        
        console.log("MessageBridge deployed at:", address(bridge));
    }
}
