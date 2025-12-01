// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../src/FeeManager.sol";
import "../src/LinkingUSD.sol";
import "../src/Nonce.sol";
import "../src/StablecoinExchange.sol";
import "../src/TIP20.sol";
import "../src/TIP20Factory.sol";
import "../src/TIP20RewardRegistry.sol";
import "../src/TIP403Registry.sol";
import { INonce } from "../src/interfaces/INonce.sol";
import { Test, console } from "forge-std/Test.sol";

// Base test framework - all tests should import this
contract BaseTest is Test {

    // Registry precompiles
    address internal constant _TIP403REGISTRY = 0x403c000000000000000000000000000000000000;
    address internal constant _TIP20REWARDS_REGISTRY = 0x3000000000000000000000000000000000000000;
    address internal constant _TIP20FACTORY = 0x20Fc000000000000000000000000000000000000;
    address internal constant _LINKING_USD = 0x20C0000000000000000000000000000000000000;
    address internal constant _STABLECOIN_DEX = 0xDEc0000000000000000000000000000000000000;
    address internal constant _FEE_AMM = 0xfeEC000000000000000000000000000000000000;
    address internal constant _NONCE = 0x4e4F4E4345000000000000000000000000000000;

    // Role constants
    bytes32 internal constant _ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 internal constant _PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 internal constant _UNPAUSE_ROLE = keccak256("UNPAUSE_ROLE");
    bytes32 internal constant _TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    bytes32 internal constant _RECEIVE_WITH_MEMO_ROLE = keccak256("RECEIVE_WITH_MEMO_ROLE");

    // Common test addresses
    address public admin = address(this);
    address public alice = address(0x200);
    address public bob = address(0x300);
    address public charlie = address(0x400);
    // Use the same admin address for both Tempo and local testing
    address public linkingUSDAdmin = address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84);

    // Common test contracts
    TIP20Factory public factory = TIP20Factory(_TIP20FACTORY);
    LinkingUSD public linkingUSD = LinkingUSD(_LINKING_USD);
    StablecoinExchange public exchange = StablecoinExchange(_STABLECOIN_DEX);
    FeeManager public amm = FeeManager(_FEE_AMM);
    TIP403Registry public registry = TIP403Registry(_TIP403REGISTRY);
    INonce public nonce = INonce(_NONCE);
    TIP20 public token1;
    TIP20 public token2;
    bool isTempo;

    error MissingPrecompile(string name, address addr);
    error CallShouldHaveReverted();

    function setUp() public virtual {
        // Is this tempo chain?
        isTempo = _TIP403REGISTRY.code.length + _TIP20REWARDS_REGISTRY.code.length
                + _TIP20FACTORY.code.length + _LINKING_USD.code.length + _STABLECOIN_DEX.code.length
                + _NONCE.code.length > 0;

        console.log("Tests running with isTempo =", isTempo);

        // Deploy contracts if not tempo
        if (!isTempo) {
            deployCodeTo("TIP403Registry", _TIP403REGISTRY);
            vm.etch(_TIP20REWARDS_REGISTRY, type(TIP20RewardsRegistry).runtimeCode);
            vm.etch(_STABLECOIN_DEX, type(StablecoinExchange).runtimeCode);
            deployCodeTo("FeeManager", _FEE_AMM);
            deployCodeTo("TIP20Factory", _TIP20FACTORY);
            // Deploy LinkingUSD with the same admin used on Tempo
            deployCodeTo("LinkingUSD.sol", abi.encode(linkingUSDAdmin), _LINKING_USD);
            deployCodeTo("Nonce", _NONCE);
        }

        if (isTempo) {
            if (_TIP403REGISTRY.code.length == 0) {
                revert MissingPrecompile("TIP403Registry", _TIP403REGISTRY);
            }
            if (_TIP20REWARDS_REGISTRY.code.length == 0) {
                revert MissingPrecompile("TIP20RewardsRegistry", _TIP20REWARDS_REGISTRY);
            }
            if (_TIP20FACTORY.code.length == 0) {
                revert MissingPrecompile("TIP20Factory", _TIP20FACTORY);
            }
            if (_LINKING_USD.code.length == 0) {
                revert MissingPrecompile("LinkingUSD", _LINKING_USD);
            }
            if (_STABLECOIN_DEX.code.length == 0) {
                revert MissingPrecompile("StablecoinDEX", _STABLECOIN_DEX);
            }
            if (_FEE_AMM.code.length == 0) {
                revert MissingPrecompile("FeeManager", _STABLECOIN_DEX);
            }
            if (_NONCE.code.length == 0) {
                revert MissingPrecompile("Nonce", _NONCE);
            }

            // Grant DEFAULT_ADMIN_ROLE (bytes32(0)) to admin for linkingUSD via direct storage write
            // hasRole is: mapping(address account => mapping(bytes32 role => bool))
            // Storage slot = keccak256(abi.encode(role, keccak256(abi.encode(account, baseSlot))))
            // Assuming hasRole is at slot 0 in TIP20RolesAuth (first state variable)
            bytes32 adminRoleSlot = keccak256(
                abi.encode(
                    bytes32(0), // DEFAULT_ADMIN_ROLE
                    keccak256(abi.encode(admin, uint256(0))) // account and base slot
                )
            );
            vm.store(_LINKING_USD, adminRoleSlot, bytes32(uint256(1)));

            // Also grant DEFAULT_ADMIN_ROLE to tempoAdmin (0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84)
            bytes32 tempoAdminRoleSlot = keccak256(
                abi.encode(
                    bytes32(0), // DEFAULT_ADMIN_ROLE
                    keccak256(abi.encode(linkingUSDAdmin, uint256(0)))
                )
            );
            vm.store(_LINKING_USD, tempoAdminRoleSlot, bytes32(uint256(1)));
        }

        token1 = TIP20(factory.createToken("TOKEN1", "T1", "USD", linkingUSD, admin));
        token2 = TIP20(factory.createToken("TOKEN2", "T2", "USD", linkingUSD, admin));
    }

}
