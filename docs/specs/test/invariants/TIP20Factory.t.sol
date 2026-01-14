// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { TIP20Factory } from "../../src/TIP20Factory.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../../src/interfaces/ITIP20Factory.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP20Factory Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP20Factory implementation
/// @dev Tests invariants TEMPO-FAC1 through TEMPO-FAC10 as documented in README.md
contract TIP20FactoryInvariantTest is InvariantBaseTest {

    /// @dev Log file path for recording actions
    string private constant LOG_FILE = "factory.log";

    /// @dev Ghost variables for tracking operations
    uint256 private _totalTokensCreated;
    uint256 private _totalReservedAttempts;
    uint256 private _totalDuplicateAttempts;
    uint256 private _totalInvalidQuoteAttempts;

    /// @dev Track created tokens and their properties
    address[] private _createdTokens;
    mapping(address => bool) private _isCreatedToken;
    mapping(bytes32 => address) private _saltToToken;
    mapping(address => bytes32) private _tokenToSalt;

    /// @dev Track salts used by each sender
    mapping(address => bytes32[]) private _senderSalts;

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(10);

        _initLogFile(LOG_FILE, "TIP20Factory Invariant Test Log");
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for creating tokens
    /// @dev Tests TEMPO-FAC1 (deterministic addresses), TEMPO-FAC2 (address uniqueness)
    function createToken(
        uint256 actorSeed,
        bytes32 salt,
        uint256 nameIdx,
        uint256 symbolIdx
    ) external {
        address actor = _selectActor(actorSeed);

        // Generate varied names and symbols
        string memory name = _generateName(nameIdx);
        string memory symbol = _generateSymbol(symbolIdx);

        // Predict the address before creation
        address predictedAddr;
        try factory.getTokenAddress(actor, salt) returns (address addr) {
            predictedAddr = addr;
        } catch (bytes memory reason) {
            // TEMPO-FAC5: Reserved address range is enforced
            if (bytes4(reason) == ITIP20Factory.AddressReserved.selector) {
                _totalReservedAttempts++;
                _log(
                    string.concat(
                        "CREATE_TOKEN_RESERVED: ",
                        _getActorIndex(actor),
                        " salt=",
                        vm.toString(salt)
                    )
                );
                return;
            }
            revert("Unknown error in getTokenAddress");
        }

        // Check if token already exists at this address
        if (predictedAddr.code.length != 0) {
            vm.startPrank(actor);
            try factory.createToken(name, symbol, "USD", pathUSD, admin, salt) {
                vm.stopPrank();
                revert("TEMPO-FAC3: Should revert for existing token");
            } catch (bytes memory reason) {
                vm.stopPrank();
                if (bytes4(reason) == ITIP20Factory.TokenAlreadyExists.selector) {
                    _totalDuplicateAttempts++;
                    _log(
                        string.concat(
                            "CREATE_TOKEN_EXISTS: ",
                            _getActorIndex(actor),
                            " at ",
                            vm.toString(predictedAddr)
                        )
                    );
                    return;
                }
            }
            return;
        }

        vm.startPrank(actor);
        try factory.createToken(name, symbol, "USD", pathUSD, admin, salt) returns (address tokenAddr) {
            vm.stopPrank();

            _totalTokensCreated++;
            _createdTokens.push(tokenAddr);
            _isCreatedToken[tokenAddr] = true;

            bytes32 uniqueKey = keccak256(abi.encode(actor, salt));
            _saltToToken[uniqueKey] = tokenAddr;
            _tokenToSalt[tokenAddr] = salt;
            _senderSalts[actor].push(salt);

            // TEMPO-FAC1: Created address matches predicted address
            assertEq(
                tokenAddr,
                predictedAddr,
                "TEMPO-FAC1: Created address does not match predicted address"
            );

            // TEMPO-FAC2: Token is recognized as TIP20
            assertTrue(
                factory.isTIP20(tokenAddr),
                "TEMPO-FAC2: Created token not recognized as TIP20"
            );

            // TEMPO-FAC6: Token has correct properties
            TIP20 newToken = TIP20(tokenAddr);
            assertEq(
                keccak256(bytes(newToken.name())),
                keccak256(bytes(name)),
                "TEMPO-FAC6: Token name mismatch"
            );
            assertEq(
                keccak256(bytes(newToken.symbol())),
                keccak256(bytes(symbol)),
                "TEMPO-FAC6: Token symbol mismatch"
            );
            assertEq(
                keccak256(bytes(newToken.currency())),
                keccak256(bytes("USD")),
                "TEMPO-FAC6: Token currency mismatch"
            );

            _log(
                string.concat(
                    "CREATE_TOKEN: ",
                    _getActorIndex(actor),
                    " created ",
                    symbol,
                    " at ",
                    vm.toString(tokenAddr)
                )
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for creating tokens with invalid quote token
    /// @dev Tests TEMPO-FAC4 (quote token validation)
    function createTokenInvalidQuote(uint256 actorSeed, bytes32 salt) external {
        address actor = _selectActor(actorSeed);

        // Use a non-TIP20 address as quote token
        address invalidQuote = makeAddr("InvalidQuote");

        vm.startPrank(actor);
        try factory.createToken("Test", "TST", "USD", ITIP20(invalidQuote), admin, salt) {
            vm.stopPrank();
            revert("TEMPO-FAC4: Should revert for invalid quote token");
        } catch (bytes memory reason) {
            vm.stopPrank();
            if (bytes4(reason) == ITIP20Factory.InvalidQuoteToken.selector) {
                _totalInvalidQuoteAttempts++;
                _log(
                    string.concat(
                        "CREATE_TOKEN_INVALID_QUOTE: ",
                        _getActorIndex(actor),
                        " with invalid quote"
                    )
                );
            } else {
                _assertKnownError(reason);
            }
        }
    }

    /// @notice Handler for creating tokens with mismatched currency
    /// @dev Tests TEMPO-FAC7 (currency/quote token consistency)
    function createTokenMismatchedCurrency(
        uint256 actorSeed,
        bytes32 salt,
        uint256 currencyIdx
    ) external {
        address actor = _selectActor(actorSeed);

        // Use a non-USD currency with a USD quote token
        string memory currency = _generateNonUsdCurrency(currencyIdx);

        // This should succeed - non-USD tokens can have USD quote tokens
        // But USD tokens must have USD quote tokens
        vm.startPrank(actor);
        try factory.createToken("Test", "TST", currency, pathUSD, admin, salt) returns (address tokenAddr) {
            vm.stopPrank();

            if (tokenAddr != address(0)) {
                _createdTokens.push(tokenAddr);
                _isCreatedToken[tokenAddr] = true;

                TIP20 newToken = TIP20(tokenAddr);
                assertEq(
                    keccak256(bytes(newToken.currency())),
                    keccak256(bytes(currency)),
                    "TEMPO-FAC7: Currency mismatch"
                );

                _log(
                    string.concat(
                        "CREATE_TOKEN_NON_USD: ",
                        _getActorIndex(actor),
                        " currency=",
                        currency
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for verifying isTIP20 on random addresses
    /// @dev Tests TEMPO-FAC8 (isTIP20 consistency)
    function checkIsTIP20(uint256 addrSeed) external view {
        address checkAddr;

        if (addrSeed % 3 == 0 && _createdTokens.length > 0) {
            // Check a created token
            checkAddr = _createdTokens[addrSeed % _createdTokens.length];
            assertTrue(
                factory.isTIP20(checkAddr),
                "TEMPO-FAC8: Created token should be TIP20"
            );
        } else if (addrSeed % 3 == 1) {
            // Check pathUSD (known TIP20)
            assertTrue(
                factory.isTIP20(address(pathUSD)),
                "TEMPO-FAC8: pathUSD should be TIP20"
            );
        } else {
            // Check a random non-TIP20 address
            checkAddr = address(uint160(addrSeed));
            // Skip addresses in TIP20 range
            if ((uint160(checkAddr) >> 64) != 0x20C000000000000000000000) {
                assertFalse(
                    factory.isTIP20(checkAddr),
                    "TEMPO-FAC8: Random address should not be TIP20"
                );
            }
        }
    }

    /// @notice Handler for verifying getTokenAddress determinism
    /// @dev Tests TEMPO-FAC9 (address prediction is deterministic)
    function verifyAddressDeterminism(uint256 actorSeed, bytes32 salt) external view {
        address actor = _selectActor(actorSeed);

        try factory.getTokenAddress(actor, salt) returns (address addr1) {
            address addr2 = factory.getTokenAddress(actor, salt);

            // TEMPO-FAC9: Same inputs always produce same output
            assertEq(
                addr1,
                addr2,
                "TEMPO-FAC9: getTokenAddress not deterministic"
            );

            // TEMPO-FAC10: Different senders produce different addresses
            address otherActor = _selectActor(actorSeed + 1);
            if (actor != otherActor) {
                try factory.getTokenAddress(otherActor, salt) returns (address otherAddr) {
                    assertTrue(
                        addr1 != otherAddr,
                        "TEMPO-FAC10: Different senders should produce different addresses"
                    );
                } catch {}
            }
        } catch {}
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks
    function invariant_globalInvariants() public view {
        _invariantAllCreatedTokensAreTIP20();
        _invariantAddressUniqueness();
        _invariantAddressFormat();
    }

    /// @notice TEMPO-FAC2: All created tokens are recognized as TIP20
    function _invariantAllCreatedTokensAreTIP20() internal view {
        for (uint256 i = 0; i < _createdTokens.length; i++) {
            assertTrue(
                factory.isTIP20(_createdTokens[i]),
                "TEMPO-FAC2: Created token not recognized as TIP20"
            );
        }
    }

    /// @notice TEMPO-FAC3: All created token addresses are unique
    function _invariantAddressUniqueness() internal view {
        for (uint256 i = 0; i < _createdTokens.length; i++) {
            for (uint256 j = i + 1; j < _createdTokens.length; j++) {
                assertTrue(
                    _createdTokens[i] != _createdTokens[j],
                    "TEMPO-FAC3: Duplicate token addresses found"
                );
            }
        }
    }

    /// @notice TEMPO-FAC11: All created tokens have correct address format
    function _invariantAddressFormat() internal view {
        for (uint256 i = 0; i < _createdTokens.length; i++) {
            address token = _createdTokens[i];
            uint160 addrValue = uint160(token);
            uint96 prefix = uint96(addrValue >> 64);

            assertEq(
                prefix,
                0x20C000000000000000000000,
                "TEMPO-FAC11: Token address has incorrect prefix"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Generates a token name based on index
    function _generateName(uint256 idx) internal pure returns (string memory) {
        string[5] memory names = ["Token Alpha", "Token Beta", "Token Gamma", "Token Delta", "Token Epsilon"];
        return names[idx % names.length];
    }

    /// @dev Generates a token symbol based on index
    function _generateSymbol(uint256 idx) internal pure returns (string memory) {
        string[5] memory symbols = ["TALP", "TBET", "TGAM", "TDEL", "TEPS"];
        return symbols[idx % symbols.length];
    }

    /// @dev Generates a non-USD currency based on index
    function _generateNonUsdCurrency(uint256 idx) internal pure returns (string memory) {
        string[4] memory currencies = ["EUR", "GBP", "JPY", "CHF"];
        return currencies[idx % currencies.length];
    }

    /// @dev Checks if an error is known/expected
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == ITIP20Factory.AddressReserved.selector
            || selector == ITIP20Factory.InvalidQuoteToken.selector
            || selector == ITIP20Factory.TokenAlreadyExists.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
