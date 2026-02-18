// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP20RolesAuth } from "../../src/interfaces/ITIP20RolesAuth.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title Invariant Base Test
/// @notice Shared test infrastructure for invariant testing of Tempo precompiles
/// @dev Provides common actor management, token selection, funding, and policy utilities
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
    function _buildActorsWithApprovals(
        uint256 noOfActors_,
        address spender
    )
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

    /*//////////////////////////////////////////////////////////////
                          ADDRESS POOL HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Builds an array of sequential addresses for use as a selection pool
    /// @param count Number of addresses to generate
    /// @param startOffset Starting offset for address generation (e.g., 0x1001, 0x2000)
    /// @return addresses Array of generated addresses
    function _buildAddressPool(
        uint256 count,
        uint256 startOffset
    )
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

}
