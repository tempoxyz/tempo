// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

interface ITIP20 {
    function ISSUER_ROLE() external view returns (bytes32);
    function grantRole(bytes32 role, address account) external;
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

interface ITIP20Factory {
    function createToken(
        string calldata name,
        string calldata symbol,
        string calldata currency,
        ITIP20 quoteToken,
        address admin,
        bytes32 salt
    ) external returns (address);
}

contract DeployTip20Example is Script {
    ITIP20Factory internal constant TIP20_FACTORY = ITIP20Factory(0x20Fc000000000000000000000000000000000000);

    ITIP20 internal constant PATH_USD = ITIP20(0x20C0000000000000000000000000000000000000);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.addr(deployerPrivateKey);

        bytes32 salt = keccak256(abi.encodePacked(admin, block.timestamp));
        uint256 initialSupply = 1_000_000 * 1e6; // TIP-20 tokens use 6 decimals.

        vm.startBroadcast(deployerPrivateKey);

        address tokenAddress = TIP20_FACTORY.createToken("My Tempo Stable Token", "MTST", "USD", PATH_USD, admin, salt);

        ITIP20 token = ITIP20(tokenAddress);
        token.grantRole(token.ISSUER_ROLE(), admin);
        token.mint(admin, initialSupply);

        vm.stopBroadcast();

        console2.log("TIP-20 deployed at:", tokenAddress);
        console2.log("Admin address:", admin);
        console2.log("Minted amount (base units):", token.balanceOf(admin));
        console2.log("Explorer URL:", string.concat("https://explore.tempo.xyz/address/", vm.toString(tokenAddress)));
    }
}
