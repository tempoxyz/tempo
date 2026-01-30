// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { IFeeAMM } from "../../src/interfaces/IFeeAMM.sol";
import { INonce } from "../../src/interfaces/INonce.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../../src/interfaces/ITIP20Factory.sol";
import { ITIP20RolesAuth } from "../../src/interfaces/ITIP20RolesAuth.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { IValidatorConfig } from "../../src/interfaces/IValidatorConfig.sol";
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

    /// @dev Whether logging is enabled (opt-in via LOG_INVARIANTS=true for local debugging)
    bool internal _loggingEnabled;

    /// @dev All addresses that may hold token balances (for invariant checks)
    address[] internal _balanceHolders;

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

        // Register known balance holders for invariant checks
        _registerBalanceHolder(address(amm));
        _registerBalanceHolder(address(exchange));
        _registerBalanceHolder(admin);
        _registerBalanceHolder(alice);
        _registerBalanceHolder(bob);
        _registerBalanceHolder(charlie);
        _registerBalanceHolder(pathUSDAdmin);
    }

    /// @dev Registers an address as a potential balance holder
    function _registerBalanceHolder(address holder) internal {
        _balanceHolders.push(holder);
    }

    /// @notice Initialize log file with header
    /// @dev Logging is opt-in via LOG_INVARIANTS=true env var (disabled by default for CI performance)
    /// @param logFile The log file path
    /// @param title The title for the log header
    function _initLogFile(string memory logFile, string memory title) internal {
        // Logging is opt-in for local debugging (default off for CI performance)
        try vm.envBool("LOG_INVARIANTS") returns (bool logEnabled) {
            _loggingEnabled = logEnabled;
        } catch {
            _loggingEnabled = false; // Default to disabled for CI
        }

        if (!_loggingEnabled) {
            return;
        }

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

    /// @notice Selects an actor that is NOT the excluded address, using bound to avoid discards
    /// @param seed Random seed
    /// @param excluded Address to exclude from selection
    /// @return Selected actor address (guaranteed != excluded if excluded is in the pool)
    function _selectActorExcluding(uint256 seed, address excluded) internal view returns (address) {
        uint256 excludedIdx = _actors.length;
        for (uint256 i = 0; i < _actors.length; i++) {
            if (_actors[i] == excluded) {
                excludedIdx = i;
                break;
            }
        }

        if (excludedIdx == _actors.length) {
            return _selectActor(seed);
        }

        uint256 idx = bound(seed, 0, _actors.length - 2);
        if (idx >= excludedIdx) idx++;
        return _actors[idx];
    }

    /// @notice Creates test actors with initial balances
    /// @dev Each actor gets funded with all tokens
    /// @param noOfActors_ Number of actors to create
    /// @return actorsAddress Array of created actor addresses
    function _buildActors(uint256 noOfActors_) internal virtual returns (address[] memory) {
        address[] memory actorsAddress = new address[](noOfActors_);

        for (uint256 i = 0; i < noOfActors_; i++) {
            address actor = makeAddr(string(abi.encodePacked("Actor", vm.toString(i))));
            actorsAddress[i] = actor;

            // Register actor as balance holder for invariant checks
            _registerBalanceHolder(actor);

            // Initial actor balance for all tokens
            _ensureFundsAll(actor, 1_000_000_000_000);
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

    /// @dev Selects a pair of distinct tokens using a single seed
    /// @param pairSeed Random seed - lower bits for first token, upper bits for offset
    /// @return userToken First token
    /// @return validatorToken Second token (guaranteed different from first)
    function _selectTokenPair(uint256 pairSeed)
        internal
        view
        returns (address userToken, address validatorToken)
    {
        uint256 totalTokens = _tokens.length + 1;
        uint256 idx1 = bound(pairSeed, 0, totalTokens - 1);

        // Pick from [0, N-2] then skip over idx1 to guarantee idx2 != idx1
        uint256 idx2 = bound(pairSeed >> 128, 0, totalTokens - 2);
        if (idx2 >= idx1) idx2++;

        userToken = idx1 == 0 ? address(pathUSD) : address(_tokens[idx1 - 1]);
        validatorToken = idx2 == 0 ? address(pathUSD) : address(_tokens[idx2 - 1]);
    }

    /// @dev Selects a base token only (excludes pathUSD)
    /// @param rnd Random seed for selection
    /// @return The selected token
    function _selectBaseToken(uint256 rnd) internal view returns (TIP20) {
        return _tokens[rnd % _tokens.length];
    }

    /// @dev Selects an actor authorized for the given token's policy
    /// @param seed Random seed for selection
    /// @param token Token to check authorization for
    /// @return The selected authorized actor
    function _selectAuthorizedActor(uint256 seed, address token) internal view returns (address) {
        uint64 policyId = token == address(pathUSD) ? _pathUsdPolicyId : _tokenPolicyIds[token];

        address[] memory authorized = new address[](_actors.length);
        uint256 count = 0;
        for (uint256 i = 0; i < _actors.length; i++) {
            if (registry.isAuthorized(policyId, _actors[i])) {
                authorized[count++] = _actors[i];
            }
        }

        vm.assume(count > 0);
        return authorized[bound(seed, 0, count - 1)];
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

    /// @notice Ensures an actor has sufficient balances for all tokens
    /// @param actor The actor address to fund
    /// @param amount The minimum balance required
    function _ensureFundsAll(address actor, uint256 amount) internal {
        vm.startPrank(admin);
        if (pathUSD.balanceOf(actor) < amount) {
            pathUSD.mint(actor, amount + 100_000_000);
        }
        for (uint256 i = 0; i < _tokens.length; i++) {
            if (_tokens[i].balanceOf(actor) < amount) {
                _tokens[i].mint(actor, amount + 100_000_000);
            }
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          POLICY HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Gets the policy ID for a token by reading from the token contract
    /// @param token Token address
    /// @return policyId The policy ID
    function _getPolicyId(address token) internal view returns (uint64) {
        return TIP20(token).transferPolicyId();
    }

    /// @dev Gets the policy admin for a token by querying the registry
    /// @param token Token address
    /// @return The policy admin address
    function _getPolicyAdmin(address token) internal view returns (address) {
        uint64 policyId = _getPolicyId(token);
        (, address policyAdmin) = registry.policyData(policyId);
        return policyAdmin;
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

    /// @dev Logs a message to the log file (no-op if logging disabled)
    function _log(string memory message) internal {
        if (!_loggingEnabled) {
            return;
        }
        vm.writeLine(_logFile, message);
    }

    /// @dev Logs a handler entry to the log file
    function _logHandlerEntry(string memory handler) internal {
        vm.writeLine(_logFile, string.concat("CALL: ", handler));
    }

    /// @dev Logs a skip reason to the log file
    function _logSkip(string memory reason) internal {
        vm.writeLine(_logFile, string.concat("SKIP: ", reason));
    }

    /// @dev Logs a successful handler completion
    function _logHandlerSuccess(string memory handler) internal {
        vm.writeLine(_logFile, string.concat("SUCCESS: ", handler));
    }

    /// @dev Logs a handler revert
    function _logHandlerRevert(string memory handler, bytes4 selector) internal {
        vm.writeLine(
            _logFile, string.concat("REVERT: ", handler, " selector=", vm.toString(selector))
        );
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
                        CONSOLIDATED HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Consolidated setup helper for invariant tests
    /// @param actorCount Number of actors to create
    /// @param spender Address to approve for spending (0 for no approvals)
    /// @param logFile Log file path
    /// @param title Log file title
    function _setupInvariantTest(
        uint256 actorCount,
        address spender,
        string memory logFile,
        string memory title
    ) internal {
        _setupInvariantBase();
        _actors = spender == address(0)
            ? _buildActors(actorCount)
            : _buildActorsWithApprovals(actorCount, spender);
        _initLogFile(logFile, title);
    }

    /// @dev Helper to assert error selector is in allowed list
    /// @param reason The revert reason bytes
    /// @param allowed Array of allowed error selectors
    function _assertSelectorIn(bytes memory reason, bytes4[] memory allowed) internal pure {
        bytes4 selector = bytes4(reason);
        for (uint256 i = 0; i < allowed.length; i++) {
            if (selector == allowed[i]) return;
        }
        revert("Unknown error encountered");
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

    /// @dev Checks if an error is a known TIP20Factory error
    /// @param selector Error selector
    /// @return True if known TIP20Factory error
    function _isKnownFactoryError(bytes4 selector) internal pure returns (bool) {
        return selector == ITIP20Factory.AddressReserved.selector
            || selector == ITIP20Factory.InvalidQuoteToken.selector
            || selector == ITIP20Factory.TokenAlreadyExists.selector || _isKnownTIP20Error(selector);
    }

    /*//////////////////////////////////////////////////////////////
                       FACTORY ADDRESS HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Checks if a salt would produce a usable token address
    /// @param actor The actor creating the token
    /// @param salt The salt to check
    /// @return available True if address is available for creation
    /// @return existing Non-zero if token already exists at this address (for collision checks)
    function _checkTokenAddress(address actor, bytes32 salt)
        internal
        view
        returns (bool available, address existing)
    {
        try factory.getTokenAddress(actor, salt) returns (address predicted) {
            if (predicted.code.length != 0) {
                return (false, predicted); // Collision - return existing token
            }
            return (true, address(0)); // Available
        } catch {
            return (false, address(0)); // Reserved
        }
    }

    /// @dev Checks if an address is in the reserved TIP20 range
    /// @param addr The address to check
    /// @return True if address is reserved (prefix 0x20C0... with lower 64 bits < 1024)
    function _isReservedTIP20Address(address addr) internal pure returns (bool) {
        bytes12 prefix = bytes12(bytes20(addr));
        uint64 lowerBytes = uint64(uint160(addr));
        return prefix == bytes12(0x20c000000000000000000000) && lowerBytes < 1024;
    }

    /// @dev Checks if an error is a known Nonce precompile error
    /// @param selector Error selector
    /// @return True if known Nonce error
    function _isKnownNonceError(bytes4 selector) internal pure returns (bool) {
        return selector == INonce.ProtocolNonceNotSupported.selector
            || selector == INonce.InvalidNonceKey.selector
            || selector == INonce.NonceOverflow.selector;
    }

    /// @dev Checks if an error is a known AccountKeychain error
    /// @param selector Error selector
    /// @return True if known AccountKeychain error
    function _isKnownKeychainError(bytes4 selector) internal pure returns (bool) {
        return selector == IAccountKeychain.KeyAlreadyExists.selector
            || selector == IAccountKeychain.KeyNotFound.selector
            || selector == IAccountKeychain.KeyInactive.selector
            || selector == IAccountKeychain.KeyExpired.selector
            || selector == IAccountKeychain.KeyAlreadyRevoked.selector
            || selector == IAccountKeychain.SpendingLimitExceeded.selector
            || selector == IAccountKeychain.InvalidSignatureType.selector
            || selector == IAccountKeychain.ZeroPublicKey.selector
            || selector == IAccountKeychain.UnauthorizedCaller.selector;
    }

    /// @dev Checks if an error is a known ValidatorConfig error
    /// @param selector Error selector
    /// @return True if known ValidatorConfig error
    function _isKnownValidatorError(bytes4 selector) internal pure returns (bool) {
        return selector == IValidatorConfig.Unauthorized.selector
            || selector == IValidatorConfig.ValidatorAlreadyExists.selector
            || selector == IValidatorConfig.ValidatorNotFound.selector
            || selector == IValidatorConfig.InvalidPublicKey.selector
            || selector == IValidatorConfig.NotHostPort.selector
            || selector == IValidatorConfig.NotIpPort.selector;
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

    /// @dev Asserts a revert is a known TIP20Factory error
    function _assertKnownFactoryRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownFactoryError(bytes4(reason)), "Unknown Factory error");
    }

    /// @dev Asserts a revert is a known Nonce error
    function _assertKnownNonceRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownNonceError(bytes4(reason)), "Unknown Nonce error");
    }

    /// @dev Asserts a revert is a known AccountKeychain error
    function _assertKnownKeychainRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownKeychainError(bytes4(reason)), "Unknown Keychain error");
    }

    /// @dev Asserts a revert is a known ValidatorConfig error
    function _assertKnownValidatorRevert(bytes memory reason) internal pure {
        assertTrue(_isKnownValidatorError(bytes4(reason)), "Unknown Validator error");
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
                          ADDRESS POOL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Builds an array of sequential addresses for use as a selection pool
    /// @param count Number of addresses to generate
    /// @param startOffset Starting offset for address generation (e.g., 0x1001, 0x2000)
    /// @return addresses Array of generated addresses
    function _buildAddressPool(uint256 count, uint256 startOffset)
        internal
        pure
        returns (address[] memory)
    {
        address[] memory addresses = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            addresses[i] = address(uint160(startOffset + i));
        }
        return addresses;
    }

    /// @dev Selects an address from a pool using a seed
    /// @param pool The address pool to select from
    /// @param seed Random seed for selection
    /// @return Selected address
    function _selectFromPool(address[] memory pool, uint256 seed) internal pure returns (address) {
        return pool[seed % pool.length];
    }

    /*//////////////////////////////////////////////////////////////
                          STRING UTILITIES
    //////////////////////////////////////////////////////////////*/

    /// @dev Converts uint8 to string
    /// @param value The uint8 value to convert
    /// @return The string representation
    function _uint8ToString(uint8 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0";
        }

        uint8 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }

        return string(buffer);
    }

    /*//////////////////////////////////////////////////////////////
                        BOUNDED FUZZING HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Bounds a value to [min, max] with overflow protection
    /// @param x The value to bound
    /// @param min Minimum allowed value
    /// @param max Maximum allowed value
    /// @return The bounded value
    function _boundSafe(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        require(min <= max, "min > max");
        if (max == min) return min;
        return min + (x % (max - min + 1));
    }

    /// @dev Bounds a value to [1, max] - useful for non-zero amounts
    /// @param x The value to bound
    /// @param max Maximum allowed value
    /// @return The bounded non-zero value
    function _boundNonZero(uint256 x, uint256 max) internal pure returns (uint256) {
        return _boundSafe(x, 1, max);
    }

    /// @dev Bounds a value to a percentage of another value
    /// @param x Random seed
    /// @param total The total to take a percentage of
    /// @param minPct Minimum percentage (0-100)
    /// @param maxPct Maximum percentage (0-100)
    /// @return The bounded value as a percentage of total
    function _boundPct(uint256 x, uint256 total, uint256 minPct, uint256 maxPct)
        internal
        pure
        returns (uint256)
    {
        uint256 pct = _boundSafe(x, minPct, maxPct);
        return (total * pct) / 100;
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

    /// @dev Computes sum of balances for a token across all tracked balance holders
    /// @param token The token to sum balances for
    /// @return total The sum of all balances
    function _sumAllBalances(TIP20 token) internal view returns (uint256 total) {
        for (uint256 i = 0; i < _balanceHolders.length; i++) {
            total += token.balanceOf(_balanceHolders[i]);
        }
        // Also include the token contract itself (for locked/burned tokens)
        total += token.balanceOf(address(token));
    }

    /*//////////////////////////////////////////////////////////////
                       VALID INPUT GENERATORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Generates a valid IP:port address string for validator config
    /// @param seed Random seed for variation
    /// @return Valid IP:port string
    function _generateValidIpPort(uint256 seed) internal pure returns (string memory) {
        uint8 lastOctet = uint8((seed % 254) + 1);
        uint16 port = uint16((seed % 9000) + 1000);
        return string(
            abi.encodePacked("192.168.1.", _uint8ToString(lastOctet), ":", _uint16ToString(port))
        );
    }

    /// @dev Converts uint16 to string
    /// @param value The uint16 value to convert
    /// @return The string representation
    function _uint16ToString(uint16 value) internal pure returns (string memory) {
        if (value == 0) return "0";

        uint16 temp = value;
        uint8 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits--;
            buffer[digits] = bytes1(uint8(48 + value % 10));
            value /= 10;
        }

        return string(buffer);
    }

    /// @dev Generates a non-zero bytes32 for use as public key
    /// @param seed Random seed
    /// @return Non-zero bytes32
    function _generateNonZeroBytes32(uint256 seed) internal pure returns (bytes32) {
        bytes32 result = keccak256(abi.encode(seed));
        if (result == bytes32(0)) {
            return bytes32(uint256(1));
        }
        return result;
    }

    /// @dev Generates a valid expiry timestamp in the future
    /// @param seed Random seed for variation
    /// @return Future timestamp
    function _generateFutureExpiry(uint256 seed) internal view returns (uint64) {
        return uint64(block.timestamp + 1 days + (seed % 365 days));
    }

    /// @dev Generates a past or current timestamp (for expired key testing)
    /// @param seed Random seed for variation
    /// @return Past or current timestamp
    function _generatePastExpiry(uint256 seed) internal view returns (uint64) {
        uint256 offset = seed % (block.timestamp > 1 days ? 1 days : block.timestamp);
        return uint64(block.timestamp - offset);
    }

    /*//////////////////////////////////////////////////////////////
                          EXACT SELECTOR ASSERTIONS
    //////////////////////////////////////////////////////////////*/

    /// @dev Asserts that a revert has a specific expected selector
    /// @param reason The revert reason bytes
    /// @param expected The expected error selector
    /// @param message Assertion message on failure
    function _assertExactSelector(bytes memory reason, bytes4 expected, string memory message)
        internal
        pure
    {
        assertEq(bytes4(reason), expected, message);
    }

}
