// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

contract FeeAMMInvariantTest is BaseTest {
    /// @dev Array of test actors that interact with the DEX
    address[] private _actors;

    /// @dev Array of fee tokens (token1, token2, token3, token4)
    TIP20[] private _tokens;

    /// @dev Blacklist policy IDs for each token
    mapping(address => uint64) private _tokenPolicyIds;

    /// @dev Blacklist policy ID for pathUSD
    uint64 private _pathUsdPolicyId;

    /// @dev Additional tokens (token3, token4) - token1/token2 from BaseTest
    TIP20 public token3;
    TIP20 public token4;

    /// @dev Log file path for recording amm actions
    string private constant LOG_FILE = "amm.log";

    /// @notice Sets up the test environment
    /// @dev Initializes BaseTest, creates trading pair, builds actors, and sets initial state
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        // Create additional tokens (token1, token2 already created in BaseTest)
        token3 =
            TIP20(factory.createToken("TOKEN3", "T3", "USD", pathUSD, admin, bytes32("token3")));
        token4 =
            TIP20(factory.createToken("TOKEN4", "T4", "USD", pathUSD, admin, bytes32("token4")));

        // Setup pathUSD with issuer role (pathUSDAdmin is the pathUSD admin from BaseTest)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup all tokens with issuer role and create trading pairs
        vm.startPrank(admin);
        TIP20[4] memory tokens = [token1, token2, token3, token4];
        for (uint256 i = 0; i < tokens.length; i++) {
            tokens[i].grantRole(_ISSUER_ROLE, admin);
            _tokens.push(tokens[i]);

            // Create blacklist policy for each token
            uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
            tokens[i].changeTransferPolicyId(policyId);
            _tokenPolicyIds[address(tokens[i])] = policyId;
        }
        vm.stopPrank();

        // Create blacklist policy for pathUSD
        vm.startPrank(pathUSDAdmin);
        _pathUsdPolicyId = registry.createPolicy(pathUSDAdmin, ITIP403Registry.PolicyType.BLACKLIST);
        pathUSD.changeTransferPolicyId(_pathUsdPolicyId);
        vm.stopPrank();

        _actors = _buildActors(20);

        // Initialize log file
        try vm.removeFile(LOG_FILE) { } catch { }
        _log("=== FeeAMM Invariant Test Log ===");
        _log(
            string.concat(
                "Tokens: T1=",
                token1.symbol(),
                ", T2=",
                token2.symbol(),
                ", T3=",
                token3.symbol(),
                ", T4=",
                token4.symbol()
            )
        );
        _log(string.concat("Actors: ", vm.toString(_actors.length)));
        _log("");
        _logBalances();
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    // function mint() {}

    // function burn() {}

    // function rebalanceSwap() {}

    // function simulateFeeSwap() {}

    // function addLiquidity() {}

    // function removeLiquidity() {}

    // function rebalancePool() {}

    // function distributeFees() {}

    /*//////////////////////////////////////////////////////////////
                            INVARIANT HOOKS
    //////////////////////////////////////////////////////////////*/

    /// @notice Called after invariant testing completes to clean up state
    function afterInvariant() public {}

    /*//////////////////////////////////////////////////////////////
                          INVARIANT ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Main invariant function called after each fuzz sequence
    function invariantFeeAMM() public view {}

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Verifies a revert is due to a known/expected error
    /// @dev Fails if the error selector doesn't match any known error
    /// @param reason The revert reason bytes from the failed
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnownError = selector == IFeeAMM.IdenticalAddresses.selector
            || selector == IFeeAMM.InvalidToken.selector
            || selector == IFeeAMM.InsufficientLiquidity.selector
            || selector == IFeeAMM.InsufficientReserves.selector
            || selector == IFeeAMM.InvalidAmount.selector
            || selector == IFeeAMM.DivisionByZero.selector
            || selector == IFeeAMM.InvalidSwapCalculation.selector
            || selector == IFeeAMM.InvalidCurrency.selector
            || selector == ITIP20.InsufficientBalance.selector
            || selector == ITIP20.PolicyForbids.selector;
        assertTrue(isKnownError, "Failed with unknown error");
    }

    /// @notice Creates test actors with initial balances and approvals
    /// @dev Each actor gets funded and approves the FeeAMM for both tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = makeAddr(string(abi.encodePacked("Actor", vm.toString(i))));
            actorsAddress[i] = actor;

            // initial actor balance for all tokens
            _ensureFundsAll(actor, 1_000_000_000_000);

            vm.startPrank(actor);
            // Approve all base tokens and pathUSD for the FeeAMM
            for (uint256 j = 0; j < _tokens.length; j++) {
                _tokens[j].approve(address(amm), type(uint256).max);
            }
            pathUSD.approve(address(amm), type(uint256).max);
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /// @dev Selects a token from all available tokens (base tokens + pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token address
    function _selectToken(uint256 rnd) internal view returns (address) {
        // Pool of tokens: pathUSD + all base tokens
        uint256 totalTokens = _tokens.length + 1;
        uint256 index = rnd % totalTokens;
        if (index == 0) {
            return address(pathUSD);
        }
        return address(_tokens[index - 1]);
    }

    /// @notice Ensures an actor has sufficient token balances for testing
    /// @dev Mints tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param token The token to mint (base token for asks, pathUSD for bids)
    /// @param amount The minimum balance required
    function _ensureFunds(address actor, TIP20 token, uint256 amount) internal {
        vm.startPrank(admin);
        if (token.balanceOf(address(actor)) < amount) {
            token.mint(actor, amount + 100_000_000);
        }
        vm.stopPrank();
    }

    /// @notice Ensures an actor has sufficient balances for all tokens (used in setUp)
    /// @dev Mints pathUSD and all base tokens if actor's balance is below the required amount
    /// @param actor The actor address to fund
    /// @param amount The minimum balance required
    function _ensureFundsAll(address actor, uint256 amount) internal {
        vm.startPrank(admin);
        if (pathUSD.balanceOf(address(actor)) < amount) {
            pathUSD.mint(actor, amount + 100_000_000);
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (_tokens[i].balanceOf(address(actor)) < amount) {
                _tokens[i].mint(actor, amount + 100_000_000);
            }
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                              LOGGING
    //////////////////////////////////////////////////////////////*/

    /// @dev Logs an action message to the amm.log file
    function _log(string memory message) internal {
        vm.writeLine(LOG_FILE, message);
    }

    /// @dev Logs AMM balances for all tokens
    function _logBalances() internal {
        string memory balanceStr = string.concat(
            "AMM balances: pathUSD=", vm.toString(pathUSD.balanceOf(address(amm)))
        );
        for (uint256 t = 0; t < _tokens.length; t++) {
            balanceStr = string.concat(
                balanceStr,
                ", ",
                _tokens[t].symbol(),
                "=",
                vm.toString(_tokens[t].balanceOf(address(amm)))
            );
        }
        _log(balanceStr);
    }


    /// @dev Gets actor index from address for logging
    function _getActorIndex(address actor) internal view returns (string memory) {
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == actor) {
                return string.concat("Actor", vm.toString(i));
            }
        }
        return vm.toString(actor);
    }
}