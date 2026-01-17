// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Script.sol";
import "../src/TempoLightClient.sol";
import "../src/StablecoinEscrow.sol";
import "../test/Bridge.t.sol";

contract DeployBridge is Script {
    uint64 constant TEMPO_CHAIN_ID = 62049;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        bytes memory blsPublicKey = vm.envBytes("BLS_PUBLIC_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        console.log("Deploying from:", deployer);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy MockUSDC
        MockUSDC usdc = new MockUSDC();
        console.log("MockUSDC deployed at:", address(usdc));

        // Deploy TempoLightClient
        TempoLightClient lightClient = new TempoLightClient(TEMPO_CHAIN_ID, 1);
        console.log("TempoLightClient deployed at:", address(lightClient));

        // Set BLS public key if provided
        if (blsPublicKey.length > 0) {
            lightClient.setBLSPublicKey(blsPublicKey);
            console.log("BLS public key set");
        }

        // Deploy StablecoinEscrow
        StablecoinEscrow escrow = new StablecoinEscrow(address(lightClient), TEMPO_CHAIN_ID);
        console.log("StablecoinEscrow deployed at:", address(escrow));

        // Configure escrow
        escrow.addToken(address(usdc));
        console.log("USDC added to escrow");

        // Mint some USDC to deployer for testing
        usdc.mint(deployer, 1_000_000 * 1e6); // 1M USDC
        console.log("Minted 1M USDC to deployer");

        vm.stopBroadcast();

        console.log("\n=== Deployment Summary ===");
        console.log("MockUSDC:", address(usdc));
        console.log("TempoLightClient:", address(lightClient));
        console.log("StablecoinEscrow:", address(escrow));
    }
}
