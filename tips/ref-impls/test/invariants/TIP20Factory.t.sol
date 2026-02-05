// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { TIP20Factory } from "../../src/TIP20Factory.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP20Factory } from "../../src/interfaces/ITIP20Factory.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP20Factory Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP20Factory implementation
/// @dev Tests invariants TEMPO-FAC1 through TEMPO-FAC12 as documented in README.md
contract TIP20FactoryInvariantTest is InvariantBaseTest {

    /// @dev Log file path for recording actions
    string private constant LOG_FILE = "tip20_factory.log";

    /// @dev Ghost variables for tracking operations
    uint256 private _totalTokensCreated;
    uint256 private _totalReservedAttempts;
    uint256 private _totalDuplicateAttempts;
    uint256 private _totalInvalidQuoteAttempts;
    uint256 private _totalNonUsdCurrencyCreated;
    uint256 private _totalUsdWithNonUsdQuoteRejected;
    uint256 private _totalReservedCreateAttempts;
    uint256 private _totalIsTIP20Checks;

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

        // One-time constant checks (immutable after deployment)
        // TEMPO-FAC8: isTIP20 consistency for system contracts
        assertTrue(factory.isTIP20(address(pathUSD)), "TEMPO-FAC8: pathUSD should be TIP20");
        assertFalse(factory.isTIP20(address(factory)), "TEMPO-FAC8: Factory should not be TIP20");
        assertFalse(factory.isTIP20(address(amm)), "TEMPO-FAC8: AMM should not be TIP20");
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
    )
        external
    {
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
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "CREATE_TOKEN_RESERVED: ",
                            _getActorIndex(actor),
                            " salt=",
                            vm.toString(salt)
                        )
                    );
                }
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
                    if (_loggingEnabled) {
                        _log(
                            string.concat(
                                "CREATE_TOKEN_EXISTS: ",
                                _getActorIndex(actor),
                                " at ",
                                vm.toString(predictedAddr)
                            )
                        );
                    }
                    return;
                }
                _assertKnownError(reason);
            }
            return;
        }

        vm.startPrank(actor);
        try factory.createToken(name, symbol, "USD", pathUSD, admin, salt) returns (
            address tokenAddr
        ) {
            vm.stopPrank();

            _totalTokensCreated++;
            _recordCreatedToken(actor, salt, tokenAddr);

            // TEMPO-FAC1: Created address matches predicted address
            assertEq(
                tokenAddr,
                predictedAddr,
                "TEMPO-FAC1: Created address does not match predicted address"
            );

            // TEMPO-FAC2: Token is recognized as TIP20
            assertTrue(
                factory.isTIP20(tokenAddr), "TEMPO-FAC2: Created token not recognized as TIP20"
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

            if (_loggingEnabled) {
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
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for creating tokens with invalid quote token
    /// @dev Tests TEMPO-FAC4 (quote token validation)
    function createTokenInvalidQuote(uint256 actorSeed, bytes32 salt) external {
        address actor = _selectActor(actorSeed);

        // Skip if salt is reserved or token already exists
        try factory.getTokenAddress(actor, salt) returns (address predictedAddr) {
            if (predictedAddr.code.length != 0) {
                return;
            }
        } catch (bytes memory reason) {
            if (bytes4(reason) == ITIP20Factory.AddressReserved.selector) {
                return;
            }
            revert("Unknown error in getTokenAddress");
        }

        // Use a non-TIP20 address as quote token
        address invalidQuote = makeAddr("InvalidQuote");

        vm.startPrank(actor);
        try factory.createToken("Test", "TST", "USD", ITIP20(invalidQuote), admin, salt) {
            vm.stopPrank();
            revert("TEMPO-FAC4: Should revert for invalid quote token");
        } catch (bytes memory reason) {
            vm.stopPrank();
            // Must be InvalidQuoteToken since we filtered out reserved addresses and existing tokens
            assertEq(
                bytes4(reason),
                ITIP20Factory.InvalidQuoteToken.selector,
                "TEMPO-FAC4: Expected InvalidQuoteToken error"
            );
            _totalInvalidQuoteAttempts++;
            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "CREATE_TOKEN_INVALID_QUOTE: ", _getActorIndex(actor), " with invalid quote"
                    )
                );
            }
        }
    }

    /// @notice Handler for creating tokens with mismatched currency
    /// @dev Tests TEMPO-FAC7 (currency/quote token consistency)
    function createTokenMismatchedCurrency(
        uint256 actorSeed,
        bytes32 salt,
        uint256 currencyIdx
    )
        external
    {
        address actor = _selectActor(actorSeed);

        // Skip if salt is reserved or token already exists
        try factory.getTokenAddress(actor, salt) returns (address predictedAddr) {
            if (predictedAddr.code.length != 0) {
                return;
            }
        } catch (bytes memory reason) {
            if (bytes4(reason) == ITIP20Factory.AddressReserved.selector) {
                return;
            }
            revert("Unknown error in getTokenAddress");
        }

        string memory currency = _generateNonUsdCurrency(currencyIdx);

        vm.startPrank(actor);
        try factory.createToken("Test", "TST", currency, pathUSD, admin, salt) returns (
            address tokenAddr
        ) {
            vm.stopPrank();

            if (tokenAddr != address(0)) {
                _totalNonUsdCurrencyCreated++;
                _recordCreatedToken(actor, salt, tokenAddr);

                TIP20 newToken = TIP20(tokenAddr);
                assertEq(
                    keccak256(bytes(newToken.currency())),
                    keccak256(bytes(currency)),
                    "TEMPO-FAC7: Currency mismatch"
                );

                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "CREATE_TOKEN_NON_USD: ", _getActorIndex(actor), " currency=", currency
                        )
                    );
                }
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownError(reason);
        }
    }

    /// @notice Handler for attempting to create USD token with non-USD quote
    /// @dev Tests TEMPO-FAC7 (USD tokens must have USD quote tokens)
    function createUsdTokenWithNonUsdQuote(uint256 actorSeed, bytes32 salt) external {
        address actor = _selectActor(actorSeed);

        bytes32 eurSalt = keccak256(abi.encode(salt, "EUR"));
        address eurToken;

        // Get or create a EUR token to use as quote
        try factory.getTokenAddress(actor, eurSalt) returns (address predictedEurAddr) {
            if (predictedEurAddr.code.length != 0) {
                // Verify the existing token is actually a EUR token (not some other token
                // that happened to be created at this address by another handler)
                if (keccak256(bytes(TIP20(predictedEurAddr).currency())) != keccak256(bytes("EUR")))
                {
                    // Token exists but is not EUR - skip this test case
                    return;
                }
                eurToken = predictedEurAddr;
            } else {
                vm.startPrank(actor);
                try factory.createToken(
                    "EUR Token", "EUR", "EUR", pathUSD, admin, eurSalt
                ) returns (
                    address addr
                ) {
                    eurToken = addr;
                    _recordCreatedToken(actor, eurSalt, addr);
                } catch (bytes memory reason) {
                    vm.stopPrank();
                    _assertKnownError(reason);
                    return;
                }
                vm.stopPrank();
            }
        } catch (bytes memory reason) {
            if (bytes4(reason) == ITIP20Factory.AddressReserved.selector) {
                return;
            }
            revert("Unknown error in getTokenAddress");
        }

        // Try to create a USD token with EUR quote - should fail
        bytes32 usdSalt = keccak256(abi.encode(salt, "USD_WITH_EUR"));

        try factory.getTokenAddress(actor, usdSalt) returns (address) { }
        catch (bytes memory reason) {
            if (bytes4(reason) == ITIP20Factory.AddressReserved.selector) {
                return;
            }
            revert("Unknown error in getTokenAddress");
        }

        vm.startPrank(actor);
        try factory.createToken("Bad USD", "BUSD", "USD", ITIP20(eurToken), admin, usdSalt) {
            vm.stopPrank();
            revert("TEMPO-FAC7: USD token with non-USD quote should fail");
        } catch (bytes memory reason) {
            vm.stopPrank();
            // Accept either InvalidQuoteToken or TokenAlreadyExists since validation order
            // may vary between Solidity spec and Rust precompile. The precompile checks
            // TokenAlreadyExists before InvalidQuoteToken, so if the computed address
            // collides with an existing token, we get TokenAlreadyExists instead.
            bytes4 selector = bytes4(reason);
            bool isExpectedError = selector == ITIP20Factory.InvalidQuoteToken.selector
                || selector == ITIP20Factory.TokenAlreadyExists.selector;
            assertTrue(
                isExpectedError,
                "TEMPO-FAC7: Should revert with InvalidQuoteToken or TokenAlreadyExists"
            );
            _totalUsdWithNonUsdQuoteRejected++;
            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "CREATE_USD_WITH_NON_USD_QUOTE: ",
                        _getActorIndex(actor),
                        " correctly rejected"
                    )
                );
            }
        }
    }

    /// @notice Handler for testing reserved address enforcement on createToken
    /// @dev Tests TEMPO-FAC5 (reserved address enforcement on createToken, not just getTokenAddress)
    function createTokenReservedAddress(uint256 actorSeed, bytes32 salt) external {
        address actor = _selectActor(actorSeed);

        // Only proceed if salt produces a reserved address
        try factory.getTokenAddress(actor, salt) returns (address) {
            return;
        } catch (bytes memory reason) {
            if (bytes4(reason) != ITIP20Factory.AddressReserved.selector) {
                revert("Unknown error in getTokenAddress");
            }
        }

        vm.startPrank(actor);
        try factory.createToken("Reserved", "RES", "USD", pathUSD, admin, salt) {
            vm.stopPrank();
            revert("TEMPO-FAC5: Should revert for reserved address on createToken");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                ITIP20Factory.AddressReserved.selector,
                "TEMPO-FAC5: createToken should revert with AddressReserved"
            );
            _totalReservedCreateAttempts++;
            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "CREATE_TOKEN_RESERVED_CREATE: ",
                        _getActorIndex(actor),
                        " correctly rejected"
                    )
                );
            }
        }
    }

    /// @notice Handler for verifying isTIP20 on controlled addresses
    /// @dev Tests TEMPO-FAC8 (isTIP20 consistency)
    function checkIsTIP20(uint256 addrSeed) external {
        _totalIsTIP20Checks++;

        if (addrSeed % 4 == 0 && _createdTokens.length > 0) {
            // Check a created token - must be TIP20
            address checkAddr = _createdTokens[addrSeed % _createdTokens.length];
            assertTrue(factory.isTIP20(checkAddr), "TEMPO-FAC8: Created token should be TIP20");
        } else if (addrSeed % 4 == 1) {
            // Check pathUSD (known TIP20)
            assertTrue(factory.isTIP20(address(pathUSD)), "TEMPO-FAC8: pathUSD should be TIP20");
        } else if (addrSeed % 4 == 2) {
            // Check factory address - should NOT be TIP20
            assertFalse(
                factory.isTIP20(address(factory)), "TEMPO-FAC8: Factory should not be TIP20"
            );
            // Check AMM address - should NOT be TIP20
            assertFalse(factory.isTIP20(address(amm)), "TEMPO-FAC8: AMM should not be TIP20");
        } else {
            // Check a random address - exclude known TIP20s and reserved range
            address checkAddr = address(uint160(addrSeed));

            // Skip addresses in the reserved TIP20 range (prefix 0x20C0... with lower 64 bits < 1024)
            // These addresses may have code from genesis/hardfork deployments
            bool hasPrefix = bytes12(bytes20(checkAddr)) == bytes12(0x20c000000000000000000000);
            uint64 lowerBytes = uint64(uint160(checkAddr));
            bool isReserved = hasPrefix && lowerBytes < 1024;

            if (
                !_isCreatedToken[checkAddr] && checkAddr != address(pathUSD)
                    && checkAddr != address(token1) && checkAddr != address(token2)
                    && checkAddr != address(token3) && checkAddr != address(token4) && !isReserved
            ) {
                assertFalse(
                    factory.isTIP20(checkAddr), "TEMPO-FAC8: Random address should not be TIP20"
                );
            }
        }
    }

    /// @notice Handler for verifying getTokenAddress determinism
    /// @dev Tests TEMPO-FAC9 (address prediction is deterministic), TEMPO-FAC10 (sender differentiation)
    function verifyAddressDeterminism(uint256 actorSeed, bytes32 salt) external view {
        address actor = _selectActor(actorSeed);
        address otherActor = _selectActorExcluding(actorSeed, actor);

        try factory.getTokenAddress(actor, salt) returns (address addr1) {
            // TEMPO-FAC9: Same inputs always produce same output
            address addr2 = factory.getTokenAddress(actor, salt);
            assertEq(addr1, addr2, "TEMPO-FAC9: getTokenAddress not deterministic");

            // TEMPO-FAC10: Different senders produce different addresses
            try factory.getTokenAddress(otherActor, salt) returns (address otherAddr) {
                assertTrue(
                    addr1 != otherAddr,
                    "TEMPO-FAC10: Different senders should produce different addresses"
                );
            } catch (bytes memory reason) {
                // Other actor's salt might be reserved - that's OK
                if (bytes4(reason) != ITIP20Factory.AddressReserved.selector) {
                    _assertKnownError(reason);
                }
            }
        } catch (bytes memory reason) {
            // Actor's salt might be reserved - that's OK
            if (bytes4(reason) != ITIP20Factory.AddressReserved.selector) {
                _assertKnownError(reason);
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Lightweight global invariant - most checks done inline in handlers
    /// @dev FAC1 verified at creation time, FAC2/FAC11/FAC12 verified inline
    ///      FAC8 system contract checks in setUp() as they're immutable
    ///      This function uses sampling to avoid O(n) on every call
    function invariant_globalInvariants() public view {
        // Only sample-check if we have created tokens
        if (_createdTokens.length == 0) return;

        // Sample up to 3 tokens per call using block.number for variation
        uint256 sampleCount = _createdTokens.length < 3 ? _createdTokens.length : 3;
        bytes32 usdHash = keccak256(bytes("USD"));

        for (uint256 i = 0; i < sampleCount; i++) {
            uint256 idx = (block.number + i) % _createdTokens.length;
            address tokenAddr = _createdTokens[idx];
            TIP20 token = TIP20(tokenAddr);

            // TEMPO-FAC2: Created token is recognized as TIP20
            assertTrue(
                factory.isTIP20(tokenAddr), "TEMPO-FAC2: Created token not recognized as TIP20"
            );

            // TEMPO-FAC11: Token address has correct prefix
            uint160 addrValue = uint160(tokenAddr);
            uint96 prefix = uint96(addrValue >> 64);
            assertEq(
                prefix,
                0x20C000000000000000000000,
                "TEMPO-FAC11: Token address has incorrect prefix"
            );

            // TEMPO-FAC12: USD tokens must have USD quote tokens
            if (keccak256(bytes(token.currency())) == usdHash) {
                ITIP20 quote = token.quoteToken();
                if (address(quote) != address(0)) {
                    assertEq(
                        keccak256(bytes(TIP20(address(quote)).currency())),
                        usdHash,
                        "TEMPO-FAC12: USD token has non-USD quote token"
                    );
                }
            }
        }
    }

    /// @notice Called after each invariant run to log final state
    function afterInvariant() public {
        if (!_loggingEnabled) return;

        _log("");
        _log("--------------------------------------------------------------------------------");
        _log("                              Final State Summary");
        _log("--------------------------------------------------------------------------------");
        _log(string.concat("Tokens created: ", vm.toString(_totalTokensCreated)));
        _log(
            string.concat(
                "Reserved attempts (getTokenAddress): ", vm.toString(_totalReservedAttempts)
            )
        );
        _log(
            string.concat(
                "Reserved attempts (createToken): ", vm.toString(_totalReservedCreateAttempts)
            )
        );
        _log(string.concat("Duplicate attempts: ", vm.toString(_totalDuplicateAttempts)));
        _log(string.concat("Invalid quote attempts: ", vm.toString(_totalInvalidQuoteAttempts)));
        _log(string.concat("Non-USD currency created: ", vm.toString(_totalNonUsdCurrencyCreated)));
        _log(
            string.concat(
                "USD with non-USD quote rejected: ", vm.toString(_totalUsdWithNonUsdQuoteRejected)
            )
        );
        _log(string.concat("isTIP20 checks: ", vm.toString(_totalIsTIP20Checks)));
        _log("--------------------------------------------------------------------------------");
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Records a newly created token in ghost state and verifies invariants inline
    /// @param actor The actor who created the token
    /// @param salt The salt used for creation
    /// @param tokenAddr The address of the created token
    function _recordCreatedToken(address actor, bytes32 salt, address tokenAddr) internal {
        // Defensive: ensure we're not recording duplicates
        assertFalse(_isCreatedToken[tokenAddr], "TEMPO-FAC3: Duplicate token address detected");

        bytes32 uniqueKey = keccak256(abi.encode(actor, salt));
        assertEq(
            _saltToToken[uniqueKey], address(0), "Ghost state: salt already used for this actor"
        );

        // TEMPO-FAC1: Verify salt-to-token mapping consistency immediately
        address factoryAddr = factory.getTokenAddress(actor, salt);
        assertEq(tokenAddr, factoryAddr, "TEMPO-FAC1: Created address inconsistent with factory");

        // TEMPO-FAC11: Verify token address has correct prefix
        uint160 addrValue = uint160(tokenAddr);
        uint96 prefix = uint96(addrValue >> 64);
        assertEq(
            prefix, 0x20C000000000000000000000, "TEMPO-FAC11: Token address has incorrect prefix"
        );

        _createdTokens.push(tokenAddr);
        _isCreatedToken[tokenAddr] = true;
        _saltToToken[uniqueKey] = tokenAddr;
        _tokenToSalt[tokenAddr] = salt;
        _senderSalts[actor].push(salt);
    }

    /// @dev Generates a token name based on index
    function _generateName(uint256 idx) internal pure returns (string memory) {
        string[5] memory names =
            ["Token Alpha", "Token Beta", "Token Gamma", "Token Delta", "Token Epsilon"];
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
    /// @dev Only accepts known custom error selectors - Panic and Error(string) should fail
    ///      the test as they may indicate bugs in the factory implementation
    function _assertKnownError(bytes memory reason) internal pure {
        bytes4 selector = bytes4(reason);
        bool isKnown = selector == ITIP20Factory.AddressReserved.selector
            || selector == ITIP20Factory.InvalidQuoteToken.selector
            || selector == ITIP20Factory.TokenAlreadyExists.selector;
        assertTrue(isKnown, "Unknown error encountered");
    }

}
