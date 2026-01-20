// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP20RolesAuth } from "../../src/interfaces/ITIP20RolesAuth.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title Invariant Base Test
/// @notice Shared test infrastructure for invariant testing of Tempo precompiles
/// @dev Provides common actor management, token selection, funding, and logging utilities
abstract contract InvariantBaseTest is BaseTest {

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Array of test actors that interact with the contracts
    address[] internal _actors;

    /// @dev Array of test tokens (token1, token2, token3, token4)
    TIP20[] internal _tokens;

    /// @dev Blacklist policy IDs for each token
    mapping(address => uint64) internal _tokenPolicyIds;

    /// @dev Blacklist policy ID for pathUSD
    uint64 internal _pathUsdPolicyId;

    /// @dev Additional tokens (token3, token4) - token1/token2 from BaseTest
    TIP20 public token3;
    TIP20 public token4;

    /// @dev Log file path - must be set by child contract
    string internal _logFile;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    /// @notice Common setup for invariant tests
    /// @dev Creates tokens, sets up roles, creates blacklist policies
    function _setupInvariantBase() internal {
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

        // Setup all tokens with issuer role
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
    }

    /// @notice Initialize log file with header
    /// @param logFile The log file path
    /// @param title The title for the log header
    function _initLogFile(string memory logFile, string memory title) internal {
        _logFile = logFile;
        try vm.removeFile(_logFile) { } catch { }
        _log("================================================================================");
        _log(string.concat("                         ", title));
        _log("================================================================================");
        _log(string.concat("Actors: ", vm.toString(_actors.length), " | Tokens: T1, T2, T3, T4"));
        _log("--------------------------------------------------------------------------------");
        _log("");
    }

    /*//////////////////////////////////////////////////////////////
                          ACTOR MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Selects an actor based on seed
    /// @param seed Random seed
    /// @return Selected actor address
    function _selectActor(uint256 seed) internal view returns (address) {
        return _actors[seed % _actors.length];
    }

    /// @notice Creates test actors with initial balances
    /// @dev Each actor gets funded with all tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal virtual returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);
        uint256 initialBalance = 1_000_000_000_000;

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = makeAddr(string(abi.encodePacked("Actor", vm.toString(i))));
            actorsAddress[i] = actor;

            // Initial actor balance for all tokens
            vm.startPrank(admin);
            if (pathUSD.balanceOf(actor) < initialBalance) {
                pathUSD.mint(actor, initialBalance + 100_000_000);
            }
            for (uint256 j = 0; j < _tokens.length; j++) {
                if (_tokens[j].balanceOf(actor) < initialBalance) {
                    _tokens[j].mint(actor, initialBalance + 100_000_000);
                }
            }
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /// @notice Creates test actors with approvals for a specific contract
    /// @param noOfActors_ Number of actors to create
    /// @param spender Contract to approve for token spending
    /// @return actorsAddress Array of created actor addresses
    function _buildActorsWithApprovals(uint256 noOfActors_, address spender)
        internal
        returns (address[] memory)
    {
        address[] memory actorsAddress = _buildActors(noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            vm.startPrank(actorsAddress[i]);
            for (uint256 j = 0; j < _tokens.length; j++) {
                _tokens[j].approve(spender, type(uint256).max);
            }
            pathUSD.approve(spender, type(uint256).max);
            vm.stopPrank();
        }

        return actorsAddress;
    }

    /*//////////////////////////////////////////////////////////////
                          TOKEN SELECTION
    //////////////////////////////////////////////////////////////*/

    /// @dev Selects a token from all available tokens (base tokens + pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token address
    function _selectToken(uint256 rnd) internal view returns (address) {
        uint256 totalTokens = _tokens.length + 1;
        uint256 index = rnd % totalTokens;
        if (index == 0) {
            return address(pathUSD);
        }
        return address(_tokens[index - 1]);
    }

    /// @dev Selects a base token only (excludes pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token
    function _selectBaseToken(uint256 rnd) internal view returns (TIP20) {
        return _tokens[rnd % _tokens.length];
    }

    /// @dev Gets token symbol for logging
    /// @param token Token address
    /// @return Symbol string
    function _getTokenSymbol(address token) internal view returns (string memory) {
        if (token == address(pathUSD)) {
            return "pathUSD";
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (address(_tokens[i]) == token) {
                return _tokens[i].symbol();
            }
        }
        return vm.toString(token);
    }

    /*//////////////////////////////////////////////////////////////
                          FUNDING HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Ensures an actor has sufficient token balance
    /// @param actor The actor address to fund
    /// @param token The token to mint
    /// @param amount The minimum balance required
    function _ensureFunds(address actor, TIP20 token, uint256 amount) internal {
        if (token.balanceOf(actor) < amount) {
            vm.startPrank(admin);
            token.mint(actor, amount + 100_000_000);
            vm.stopPrank();
        }
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Gets the policy ID for a token
    /// @param token Token address
    /// @return policyId The policy ID
    function _getPolicyId(address token) internal view returns (uint64) {
        if (token == address(pathUSD)) {
            return _pathUsdPolicyId;
        }
        return _tokenPolicyIds[token];
    }

    /// @dev Gets the policy admin for a token
    /// @param token Token address
    /// @return The policy admin address
    function _getPolicyAdmin(address token) internal view returns (address) {
        if (token == address(pathUSD)) {
            return pathUSDAdmin;
        }
        return admin;
    }

    /// @dev Checks if an actor is authorized for a token
    /// @param token Token address
    /// @param actor Actor address
    /// @return True if authorized
    function _isAuthorized(address token, address actor) internal view returns (bool) {
        return registry.isAuthorized(_getPolicyId(token), actor);
    }

    /// @dev Toggles blacklist status for an actor on a token
    /// @param token Token address
    /// @param actor Actor address
    /// @param blacklist True to blacklist, false to whitelist
    function _setBlacklist(address token, address actor, bool blacklist) internal {
        vm.prank(_getPolicyAdmin(token));
        registry.modifyPolicyBlacklist(_getPolicyId(token), actor, blacklist);
    }

    /*//////////////////////////////////////////////////////////////
                              LOGGING
    //////////////////////////////////////////////////////////////*/

    /// @dev Logs a message to the log file
    function _log(string memory message) internal {
        vm.writeLine(_logFile, message);
    }

    /// @dev Gets actor index from address for logging
    function _getActorIndex(address actor) internal view returns (string memory) {
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == actor) {
                return string.concat("Actor", vm.toString(i));
            }
        }
        if (actor == admin) return "Admin";
        if (actor == address(0)) return "ZERO";
        return vm.toString(actor);
    }

    /// @dev Logs contract balances for all tokens
    /// @param contractAddr Contract address to check
    /// @param contractName Name for logging
    function _logContractBalances(address contractAddr, string memory contractName) internal {
        string memory balanceStr = string.concat(
            contractName, " balances: pathUSD=", vm.toString(pathUSD.balanceOf(contractAddr))
        );
        for (uint256 t = 0; t < _tokens.length; t++) {
            balanceStr = string.concat(
                balanceStr,
                ", ",
                _tokens[t].symbol(),
                "=",
                vm.toString(_tokens[t].balanceOf(contractAddr))
            );
        }
        _log(balanceStr);
    }

    /*//////////////////////////////////////////////////////////////
                          ERROR HANDLING
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks if an error is a known TIP20 error
    /// @param selector Error selector
    /// @return True if known TIP20 error
    function _isKnownTIP20Error(bytes4 selector) internal pure returns (bool) {
        return selector == ITIP20.ContractPaused.selector
            || selector == ITIP20.InsufficientAllowance.selector
            || selector == ITIP20.InsufficientBalance.selector
            || selector == ITIP20.InvalidRecipient.selector
            || selector == ITIP20.InvalidAmount.selector
            || selector == ITIP20.PolicyForbids.selector
            || selector == ITIP20.SupplyCapExceeded.selector
            || selector == ITIP20.NoOptedInSupply.selector
            || selector == ITIP20.InvalidTransferPolicyId.selector
            || selector == ITIP20.InvalidQuoteToken.selector
            || selector == ITIP20.InvalidCurrency.selector
            || selector == ITIP20.InvalidSupplyCap.selector
            || selector == ITIP20.ProtectedAddress.selector
            || selector == ITIP20RolesAuth.Unauthorized.selector;
    }

    /// @dev Checks if an error is a known TIP403Registry error
    /// @param selector Error selector
    /// @return True if known TIP403Registry error
    function _isKnownRegistryError(bytes4 selector) internal pure returns (bool) {
        return selector == ITIP403Registry.Unauthorized.selector
            || selector == ITIP403Registry.IncompatiblePolicyType.selector
            || selector == ITIP403Registry.PolicyNotFound.selector;
    }

    /// @dev Checks if an error is a known FeeAMM/FeeManager error
    /// @param selector Error selector
    /// @return True if known FeeAMM error
    function _isKnownFeeAMMError(bytes4 selector) internal pure returns (bool) {
        return selector == IFeeAMM.IdenticalAddresses.selector
            || selector == IFeeAMM.InvalidAmount.selector
            || selector == IFeeAMM.InsufficientLiquidity.selector
            || selector == IFeeAMM.InsufficientReserves.selector
            || selector == IFeeAMM.DivisionByZero.selector
            || selector == IFeeAMM.InvalidSwapCalculation.selector
            || selector == IFeeAMM.InvalidCurrency.selector
            || selector == IFeeAMM.InvalidToken.selector || _isKnownTIP20Error(selector);
    }

    /// @dev Checks if an error is a known StablecoinDEX error
    /// @param selector Error selector
    /// @return True if known StablecoinDEX error
    function _isKnownDEXError(bytes4 selector) internal pure returns (bool) {
        return selector == IStablecoinDEX.InsufficientLiquidity.selector
            || selector == IStablecoinDEX.InsufficientOutput.selector
            || selector == IStablecoinDEX.MaxInputExceeded.selector
            || selector == IStablecoinDEX.InsufficientBalance.selector
            || selector == IStablecoinDEX.PairDoesNotExist.selector
            || selector == IStablecoinDEX.IdenticalTokens.selector
            || selector == IStablecoinDEX.InvalidToken.selector
            || selector == IStablecoinDEX.OrderDoesNotExist.selector
            || selector == IStablecoinDEX.BelowMinimumOrderSize.selector
            || selector == IStablecoinDEX.InvalidTick.selector || _isKnownTIP20Error(selector);
    }

    /// @dev Asserts a revert is a known TIP20 error
    function _assertKnownTIP20Revert(bytes memory reason) internal pure {
        assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown TIP20 error");
    }

    /// @dev Asserts a revert is a known TIP403Registry error
    function _assertKnownRegistryRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownRegistryError(bytes4(reason)), "Unknown Registry error");
    }

    /// @dev Asserts a revert is a known FeeAMM error
    function _assertKnownFeeAMMRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownFeeAMMError(bytes4(reason)), "Unknown FeeAMM error");
    }

    /// @dev Asserts a revert is a known StablecoinDEX error
    function _assertKnownDEXRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownDEXError(bytes4(reason)), "Unknown DEX error");
    }

    /*//////////////////////////////////////////////////////////////
                        SYSTEM ADDRESS TRACKING
    //////////////////////////////////////////////////////////////*/

    /// @dev Returns array of system addresses that may hold token balances
    /// @return Array of system contract addresses
    function _getSystemAddresses() internal view returns (address[] memory) {
        address[] memory sysAddrs = new address[](4);
        sysAddrs[0] = address(amm);
        sysAddrs[1] = address(exchange);
        sysAddrs[2] = address(pathUSD);
        sysAddrs[3] = address(factory);
        return sysAddrs;
    }

    /// @dev Computes sum of balances for a token across all actors and system addresses
    /// @param token The token to sum balances for
    /// @return total The sum of all balances
    function _sumAllBalances(TIP20 token) internal view returns (uint256 total) {
        for (uint256 i = 0; i < _actors.length; i++) {
            total += token.balanceOf(_actors[i]);
        }

        total += token.balanceOf(address(token));
        total += token.balanceOf(address(amm));
        total += token.balanceOf(address(exchange));
        total += token.balanceOf(admin);
        total += token.balanceOf(alice);
        total += token.balanceOf(bob);
        total += token.balanceOf(charlie);
        total += token.balanceOf(pathUSDAdmin);
    }

}
