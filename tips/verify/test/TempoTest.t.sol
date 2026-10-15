// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Test } from "forge-std/Test.sol";
import { Tempo } from "tempo-std/Tempo.sol";
import { IFeeManager } from "tempo-std/interfaces/IFeeManager.sol";
import { IStablecoinDEX } from "tempo-std/interfaces/IStablecoinDEX.sol";
import { ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

/// @notice Tempo test framework for all spec verification tests
contract TempoTest is Tempo, Test {

    /// @notice Thrown when a precompile is not initialized at the active hardfork.
    error MissingPrecompile(string name, address addr);
    /// @notice Thrown when a call was expected to revert.
    error CallShouldHaveReverted();

    // Precompiles aliases (for succinctness)
    ITIP403Registry registry = tip403Registry;
    ITIP20Factory factory = tip20Factory;
    IStablecoinDEX exchange = stableDEX;
    IFeeManager amm = feeAMM;

    // Regular TIP20 tokens deployed using the factory
    ITIP20Token public token1;
    ITIP20Token public token2;

    // Role constants
    bytes32 internal constant _ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 internal constant _PAUSE_ROLE = keccak256("PAUSE_ROLE");
    bytes32 internal constant _UNPAUSE_ROLE = keccak256("UNPAUSE_ROLE");
    bytes32 internal constant _TRANSFER_ROLE = keccak256("TRANSFER_ROLE");
    bytes32 internal constant _RECEIVE_WITH_MEMO_ROLE = keccak256("RECEIVE_WITH_MEMO_ROLE");
    bytes32 internal constant _BURN_BLOCKED_ROLE = keccak256("BURN_BLOCKED_ROLE");

    // Common test addresses
    address public admin = address(this);
    address public alice = address(0x200);
    address public bob = address(0x300);
    address public charlie = address(0x400);
    address public pathUSDAdmin = address(0xb4c79daB8f259C7Aee6E5b2Aa729821864227e84);

    /// @notice Ensures that a precompile is initialized at the active hardfork.
    function _requirePrecompile(string memory name, address precompile) internal view {
        if (precompile.code.length == 0) {
            revert MissingPrecompile(name, precompile);
        }
    }

    /// @dev Seeds legacy settled rewards and their reserve using the TIP-20 storage layout.
    function _seedSettledRewards(
        ITIP20Token rewardToken,
        address holder,
        uint256 amount,
        uint256 funding
    )
        internal
    {
        // userRewardInfo is at slot 17; rewardBalance is its third field.
        uint256 rewardSlot = uint256(keccak256(abi.encode(holder, uint256(17)))) + 2;
        vm.store(
            address(rewardToken),
            bytes32(rewardSlot),
            bytes32(rewardToken.getPendingRewards(holder) + amount)
        );
        // balances and totalSupply are at slots 9 and 8 respectively.
        vm.store(
            address(rewardToken),
            keccak256(abi.encode(address(rewardToken), uint256(9))),
            bytes32(rewardToken.balanceOf(address(rewardToken)) + funding)
        );
        vm.store(
            address(rewardToken), bytes32(uint256(8)), bytes32(rewardToken.totalSupply() + funding)
        );
    }

    function setUp() public virtual {
        _requirePrecompile("AccountKeychain", KEYCHAIN);
        _requirePrecompile("TIP403Registry", TIP403_REGISTRY);
        _requirePrecompile("AddressRegistry", ADDRESS_REGISTRY);
        _requirePrecompile("TIP20Factory", TIP20_FACTORY);
        _requirePrecompile("pathUSD", PATH_USD);
        _requirePrecompile("StablecoinDEX", STABLE_DEX);
        _requirePrecompile("FeeManager", FEE_AMM);
        _requirePrecompile("Nonce", NONCE);
        _requirePrecompile("ValidatorConfig", VALIDATOR_CONFIG);
        _requirePrecompile("ValidatorConfigV2", VALIDATOR_CONFIG_V2);

        // Set ValidatorConfig owner to admin via direct storage write
        // owner is at slot 0 in ValidatorConfig
        vm.store(VALIDATOR_CONFIG, bytes32(uint256(0)), bytes32(uint256(uint160(admin))));

        // Grant DEFAULT_ADMIN_ROLE to admin for pathUSD via direct storage write
        bytes32 adminRoleSlot = keccak256(
            abi.encode(
                bytes32(0), // DEFAULT_ADMIN_ROLE
                keccak256(abi.encode(admin, uint256(0)))
            )
        );
        vm.store(PATH_USD, adminRoleSlot, bytes32(uint256(1)));

        // Grant DEFAULT_ADMIN_ROLE to pathUSDAdmin
        bytes32 tempoAdminRoleSlot = keccak256(
            abi.encode(
                bytes32(0), // DEFAULT_ADMIN_ROLE
                keccak256(abi.encode(pathUSDAdmin, uint256(0)))
            )
        );
        vm.store(PATH_USD, tempoAdminRoleSlot, bytes32(uint256(1)));

        // Deploy tokens
        token1 = ITIP20Token(
            factory.createToken("TOKEN1", "T1", "USD", pathUSD, admin, bytes32("token1"))
        );
        token2 = ITIP20Token(
            factory.createToken("TOKEN2", "T2", "USD", pathUSD, admin, bytes32("token2"))
        );
    }

}
