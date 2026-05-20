// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { ITIP20, ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20Factory } from "tempo-std/interfaces/ITIP20Factory.sol";
import { ITIP20RolesAuthErr } from "tempo-std/interfaces/ITIP20RolesAuth.sol";

/// @title TIP-1026 Token Logo URI Invariant Tests
/// @notice Handler-based invariant tests for the TIP-1026 logoURI / setLogoURI / factory
///         overload as defined in `tips/tip-1026.md`.
/// @dev Covers the two normative invariants from the spec:
///      TEMPO-1026-1: `bytes(logoURI()).length <= 256` must always hold.
///      TEMPO-1026-2: The legacy 6-argument `createToken` selector and the
///                    `TokenCreated` event signature are unchanged by this TIP.
contract TIP1026InvariantTest is InvariantBaseTest {

    /*//////////////////////////////////////////////////////////////
                              CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 private constant MAX_LOGO_URI_BYTES = 256;
    uint256 private constant NUM_ACTORS = 4;
    uint256 private constant MAX_LOGO_TOKENS = 4;

    /// @dev Pre-image of the legacy 6-arg createToken selector. Must remain
    ///      `0x68130445` per TEMPO-1026-2.
    bytes4 private constant LEGACY_CREATE_TOKEN_SELECTOR =
        bytes4(keccak256("createToken(string,string,string,address,address,bytes32)"));

    /// @dev Pre-image of the TokenCreated event topic0. Must remain
    ///      `0x44f7b801...` per TEMPO-1026-2 (the event signature does NOT
    ///      include `logoURI`).
    bytes32 private constant TOKEN_CREATED_TOPIC0 =
        keccak256("TokenCreated(address,string,string,string,address,address,bytes32)");

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    /// @dev Tokens whose logoURI is exercised by the fuzz handlers; the global
    ///      invariant scans this list after every run.
    ITIP20Token[] private _logoTokens;

    /// @dev Counter used to derive unique salts for createToken handlers.
    uint256 private _saltNonce;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));
        _setupInvariantBase();
        (_actors,) = _buildActors(NUM_ACTORS);

        // Make the token admin one of the fuzz actors so the success path of
        // `setLogoURI` (and the LogoURITooLong / InvalidLogoURI validation
        // branches that only fire when `msg.sender == admin`) is reachable.
        // Without this, `_selectActor` only ever returns one of the
        // `_buildActors`-generated EOAs and every `setLogoURI` call goes down
        // the `Unauthorized` path, leaving the admin-side invariants
        // unexercised.
        _actors.push(admin);

        // TEMPO-1026-2: assert constants up-front. These are immutable after
        // deployment, so a one-shot check in setUp is sufficient — any
        // regression (e.g. the legacy selector being rewritten or the event
        // being extended with `logoURI`) will fail the suite immediately.
        assertEq(
            LEGACY_CREATE_TOKEN_SELECTOR,
            bytes4(0x68130445),
            "TEMPO-1026-2: legacy createToken selector must remain 0x68130445"
        );
        assertEq(
            TOKEN_CREATED_TOPIC0,
            bytes32(0x44f7b8011db3e3647a530b4ff635726de5fafc8fa8ad10f0f31c0eb9dd52fc65),
            "TEMPO-1026-2: TokenCreated topic0 must remain unchanged"
        );

        // Track existing factory-deployed tokens so the global invariant has
        // something to scan even before any handler runs.
        _logoTokens.push(token1);
        _logoTokens.push(token2);
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Calls `setLogoURI` from a random actor with a fuzz-generated URI.
    /// @dev Per-handler assertions:
    ///        - calls from non-admins revert with `Unauthorized`
    ///        - calls with `len > 256` revert with `LogoURITooLong`
    ///        - calls with a non-empty disallowed scheme revert with `InvalidLogoURI`
    ///        - successful calls leave `bytes(logoURI()).length <= 256`
    function fuzzSetLogoURI(
        uint256 tokenSeed,
        uint256 actorSeed,
        uint256 schemeSeed,
        uint16 len
    )
        external
    {
        if (_logoTokens.length == 0) return;

        ITIP20Token token = _logoTokens[tokenSeed % _logoTokens.length];
        address actor = _selectActor(actorSeed);

        // Generate a URI of fuzzed length (0..512) with a fuzzed scheme.
        // The 0..512 window covers both sides of the 256-byte cap so the
        // fuzzer exercises both LogoURITooLong and accepted lengths.
        uint256 boundedLen = bound(uint256(len), 0, 512);
        (string memory uri, bool wellFormedAllowed) = _buildUri(schemeSeed, boundedLen);
        bool tooLong = bytes(uri).length > MAX_LOGO_URI_BYTES;
        bool isEmpty = bytes(uri).length == 0;
        bool acceptable = isEmpty || wellFormedAllowed;

        vm.prank(actor);
        try token.setLogoURI(uri) {
            // Success path — must be admin, length within cap, and either
            // empty or a well-formed URI with an allowed scheme.
            assertEq(actor, admin, "TEMPO-1026: non-admin setLogoURI must revert");
            assertFalse(tooLong, "TEMPO-1026-1: oversized setLogoURI must revert");
            assertTrue(acceptable, "TEMPO-1026: setLogoURI with bad URI must revert");
            assertEq(token.logoURI(), uri, "TEMPO-1026: logoURI not persisted on success");
        } catch (bytes memory reason) {
            bytes4 sel = bytes4(reason);
            if (actor != admin) {
                assertEq(
                    sel,
                    ITIP20RolesAuthErr.Unauthorized.selector,
                    "TEMPO-1026: non-admin must revert with Unauthorized"
                );
            } else if (tooLong) {
                assertEq(
                    sel,
                    ITIP20.LogoURITooLong.selector,
                    "TEMPO-1026-1: oversized URI must revert with LogoURITooLong"
                );
            } else {
                // Admin, length OK → only legitimate failure is a malformed
                // URI or a non-allowlisted scheme.
                assertFalse(acceptable, "TEMPO-1026: acceptable URI must succeed for admin");
                assertEq(
                    sel,
                    ITIP20.InvalidLogoURI.selector,
                    "TEMPO-1026: bad URI must revert with InvalidLogoURI"
                );
            }
        }

        // TEMPO-1026-1: the global invariant — checked here per-handler too
        // for fast feedback on the offending call.
        assertLe(
            bytes(token.logoURI()).length,
            MAX_LOGO_URI_BYTES,
            "TEMPO-1026-1: logoURI length must always be <= 256 bytes"
        );
    }

    /// @notice Creates a token via the 7-arg `createToken` overload and tracks it.
    /// @dev Successful creation must satisfy TEMPO-1026-1 immediately on the
    ///      newly-deployed token. Bad URIs must revert atomically; the would-be
    ///      address must remain undeployed (TEMPO-FAC1 derives that address
    ///      deterministically from `(sender, salt)`).
    function fuzzCreateTokenWithLogo(uint256 schemeSeed, uint16 len) external {
        if (_logoTokens.length >= MAX_LOGO_TOKENS) return;

        bytes32 salt = keccak256(abi.encode("TIP1026", _saltNonce++));
        uint256 boundedLen = bound(uint256(len), 0, 512);
        (string memory uri, bool wellFormedAllowed) = _buildUri(schemeSeed, boundedLen);
        bool tooLong = bytes(uri).length > MAX_LOGO_URI_BYTES;
        bool isEmpty = bytes(uri).length == 0;
        bool acceptable = isEmpty || wellFormedAllowed;

        address predicted = factory.getTokenAddress(admin, salt);

        vm.prank(admin);
        try factory.createToken("LOGO", "LG", "USD", pathUSD, admin, salt, uri) returns (
            address tokenAddr
        ) {
            assertFalse(tooLong, "TEMPO-1026-1: oversized URI must revert createToken");
            assertTrue(acceptable, "TEMPO-1026: bad URI must revert createToken");
            assertEq(tokenAddr, predicted, "TEMPO-FAC1: deployed at predicted address");

            ITIP20Token created = ITIP20Token(tokenAddr);
            assertEq(created.logoURI(), uri, "TEMPO-1026: factory must persist logoURI");
            assertLe(
                bytes(created.logoURI()).length,
                MAX_LOGO_URI_BYTES,
                "TEMPO-1026-1: logoURI length must always be <= 256 bytes"
            );

            _logoTokens.push(created);
        } catch (bytes memory reason) {
            bytes4 sel = bytes4(reason);
            if (tooLong) {
                assertEq(
                    sel,
                    ITIP20.LogoURITooLong.selector,
                    "TEMPO-1026-1: oversized URI must revert with LogoURITooLong"
                );
            } else if (!acceptable) {
                assertEq(
                    sel,
                    ITIP20.InvalidLogoURI.selector,
                    "TEMPO-1026: bad URI must revert with InvalidLogoURI"
                );
            } else {
                revert("TEMPO-1026: valid createToken+logoURI must not revert");
            }
            // Atomicity: bad URI must NOT leave a deployed token at the
            // predicted address (validation runs before deployment).
            assertEq(predicted.code.length, 0, "TEMPO-1026: rejected URI left a partial token");
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice TEMPO-1026-1: `bytes(logoURI()).length <= 256` for every tracked token.
    function invariant_logoURILengthBounded() public view {
        for (uint256 i = 0; i < _logoTokens.length; i++) {
            assertLe(
                bytes(_logoTokens[i].logoURI()).length,
                MAX_LOGO_URI_BYTES,
                "TEMPO-1026-1: logoURI length must always be <= 256 bytes"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Builds a URI of exactly `len` bytes whose scheme is selected by
    ///      `schemeSeed % schemes.length`, and reports whether the result is
    ///      a well-formed URI with an allowlisted scheme (i.e. the protocol
    ///      should accept it, ignoring the length cap).
    ///
    ///      If the requested length is shorter than the scheme prefix's `:`
    ///      separator, the produced slice has no parseable scheme and
    ///      `wellFormedAllowed` is `false` (the protocol rejects it as
    ///      `InvalidLogoURI`). Once the slice includes the `:`, however, the
    ///      protocol parses the full scheme name and accepts the URI iff that
    ///      scheme is allowlisted — so e.g. `"https:"`, `"https:/"`, `"http:"`,
    ///      `"ipfs:"`, `"data:"` are all accepted (`split_once(':')` yields
    ///      the allowlisted scheme name and an empty / partial path is fine
    ///      per RFC 3986 §3.1). `len == 0` returns `("", false)` — callers
    ///      handle empty as a separate accepted case.
    function _buildUri(
        uint256 schemeSeed,
        uint256 len
    )
        internal
        pure
        returns (string memory uri, bool wellFormedAllowed)
    {
        if (len == 0) return ("", false);

        // Mix of allowed, disallowed, and malformed schemes so the fuzzer
        // exercises every revert/accept path. The first four are in the
        // TIP-1026 allowlist; the rest are not. `colonPos[i]` is the byte
        // offset of `:` inside `schemes[i]` and is used to decide whether a
        // truncated slice still contains the scheme separator.
        string[8] memory schemes =
            ["https://", "http://", "ipfs://", "data:", "javascript:", "ftp://", "file://", "://"];
        uint256[8] memory colonPos = [uint256(5), 4, 4, 4, 10, 3, 4, 0];
        uint256 idx = schemeSeed % schemes.length;
        bytes memory prefix = bytes(schemes[idx]);

        bytes memory out = new bytes(len);
        uint256 copyLen = prefix.length < len ? prefix.length : len;
        for (uint256 i = 0; i < copyLen; i++) {
            out[i] = prefix[i];
        }
        for (uint256 i = copyLen; i < len; i++) {
            out[i] = "a";
        }

        // Accepted iff the slice contains the scheme's `:` AND the scheme is
        // allowlisted. The protocol parses the scheme as everything before
        // the first `:` (RFC 3986 §3.1), so e.g. `"https:"` is acceptable
        // even though the trailing `//` was truncated.
        wellFormedAllowed = (idx < 4) && (len > colonPos[idx]);
        return (string(out), wellFormedAllowed);
    }

}
