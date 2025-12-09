// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { FeeManager } from "../src/FeeManager.sol";
import { Nonce } from "../src/Nonce.sol";
import { StablecoinExchange } from "../src/StablecoinExchange.sol";
import { TIP20 } from "../src/TIP20.sol";
import { TIP20Factory } from "../src/TIP20Factory.sol";
import { TIP403Registry } from "../src/TIP403Registry.sol";
import { INonce } from "../src/interfaces/INonce.sol";
import { ITIP20 } from "../src/interfaces/ITIP20.sol";
import { IValidatorConfig } from "../src/interfaces/IValidatorConfig.sol";
import { Test, console } from "forge-std/Test.sol";

/// @notice Base test framework for all spec tests
/// PathUSD is just a TIP20 at a special address (0x20C0...) with token_id=0
contract BaseTest is Test {

    // Registry precompiles
    address internal constant _TIP403REGISTRY = 0x403c000000000000000000000000000000000000;
    address internal constant _TIP20FACTORY = 0x20Fc000000000000000000000000000000000000;
    address internal constant _PATH_USD = 0x20C0000000000000000000000000000000000000;
    address internal constant _STABLECOIN_DEX = 0xDEc0000000000000000000000000000000000000;
    address internal constant _FEE_AMM = 0xfeEC000000000000000000000000000000000000;
    address internal constant _NONCE = 0x4e4F4E4345000000000000000000000000000000;
    address internal constant _VALIDATOR_CONFIG = 0xCccCcCCC00000000000000000000000000000000;

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
    address public pathUSDAdmin = address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84);

    // Common test contracts
    TIP20Factory public factory = TIP20Factory(_TIP20FACTORY);
    TIP20 public pathUSD = TIP20(_PATH_USD); // PathUSD is just a TIP20 at token_id=0
    StablecoinExchange public exchange = StablecoinExchange(_STABLECOIN_DEX);
    FeeManager public amm = FeeManager(_FEE_AMM);
    TIP403Registry public registry = TIP403Registry(_TIP403REGISTRY);
    INonce public nonce = INonce(_NONCE);
    IValidatorConfig public validatorConfig = IValidatorConfig(_VALIDATOR_CONFIG);
    TIP20 public token1;
    TIP20 public token2;
    bool isTempo;

    error MissingPrecompile(string name, address addr);
    error CallShouldHaveReverted();

    function setUp() public virtual {
        // Is this tempo chain?
        isTempo = _TIP403REGISTRY.code.length + _TIP20FACTORY.code.length + _PATH_USD.code.length
            + _STABLECOIN_DEX.code.length + _NONCE.code.length > 0;

        console.log("Tests running with isTempo =", isTempo);

        // Deploy contracts if not tempo
        if (!isTempo) {
            deployCodeTo("TIP403Registry", _TIP403REGISTRY);
            vm.etch(_STABLECOIN_DEX, type(StablecoinExchange).runtimeCode);
            deployCodeTo("FeeManager", _FEE_AMM);
            deployCodeTo("TIP20Factory", _TIP20FACTORY);
            // Deploy PathUSD as a TIP20 at the special address
            deployCodeTo(
                "TIP20.sol",
                abi.encode("pathUSD", "pathUSD", "USD", address(0), pathUSDAdmin),
                _PATH_USD
            );
            // Set TIP20Factory's token_id_counter to 1 since PathUSD is at token_id=0
            vm.store(_TIP20FACTORY, bytes32(uint256(0)), bytes32(uint256(1)));
            deployCodeTo("Nonce", _NONCE);
            // Deploy ValidatorConfig with admin as owner
            deployCodeTo("ValidatorConfig.sol", abi.encode(admin), _VALIDATOR_CONFIG);
        }

        if (isTempo) {
            if (_TIP403REGISTRY.code.length == 0) {
                revert MissingPrecompile("TIP403Registry", _TIP403REGISTRY);
            }
            if (_TIP20FACTORY.code.length == 0) {
                revert MissingPrecompile("TIP20Factory", _TIP20FACTORY);
            }
            if (_PATH_USD.code.length == 0) {
                revert MissingPrecompile("PathUSD", _PATH_USD);
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
            if (_VALIDATOR_CONFIG.code.length == 0) {
                revert MissingPrecompile("ValidatorConfig", _VALIDATOR_CONFIG);
            }

            // Set ValidatorConfig owner to admin via direct storage write
            // owner is at slot 0 in ValidatorConfig
            vm.store(_VALIDATOR_CONFIG, bytes32(uint256(0)), bytes32(uint256(uint160(admin))));

            // Grant DEFAULT_ADMIN_ROLE to admin for pathUSD via direct storage write
            bytes32 adminRoleSlot = keccak256(
                abi.encode(
                    bytes32(0), // DEFAULT_ADMIN_ROLE
                    keccak256(abi.encode(admin, uint256(0)))
                )
            );
            vm.store(_PATH_USD, adminRoleSlot, bytes32(uint256(1)));

            // Grant DEFAULT_ADMIN_ROLE to pathUSDAdmin
            bytes32 tempoAdminRoleSlot = keccak256(
                abi.encode(
                    bytes32(0), // DEFAULT_ADMIN_ROLE
                    keccak256(abi.encode(pathUSDAdmin, uint256(0)))
                )
            );
            vm.store(_PATH_USD, tempoAdminRoleSlot, bytes32(uint256(1)));

            // Set TIP20Factory's token_id_counter to 1 since PathUSD is at token_id=0
            vm.store(_TIP20FACTORY, bytes32(uint256(0)), bytes32(uint256(1)));
        }

        token1 = TIP20(factory.createToken("TOKEN1", "T1", "USD", pathUSD, admin));
        token2 = TIP20(factory.createToken("TOKEN2", "T2", "USD", pathUSD, admin));
    }

}
