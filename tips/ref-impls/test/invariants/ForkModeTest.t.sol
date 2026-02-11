// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { TIP20 } from "../../src/TIP20.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title Fork Mode Unit Tests
/// @notice Tests for the fork mode actor collection logic in StablecoinDEXInvariantTest
/// @dev Tests properties derived from the implementation to ensure correctness
/// @dev SKIPPED BY DEFAULT - run locally with: RUN_FORK_TESTS=true forge test --match-contract ForkModeTest
contract ForkModeTest is BaseTest {

    /// @dev Skip modifier - tests only run when RUN_FORK_TESTS=true
    modifier onlyLocal() {
        if (!vm.envOr("RUN_FORK_TESTS", false)) {
            vm.skip(true);
        }
        _;
    }

    /// @dev Array of test tokens
    TIP20[] internal _tokens;

    /// @dev Book keys for path finding tests
    bytes32[] internal _bookKeys;

    /// @dev Set for O(1) lookup of existing book keys
    mapping(bytes32 => bool) internal _bookKeySet;

    /// @dev Set for O(1) lookup of actors
    mapping(address => bool) internal _actorSet;

    /// @dev Role constant from BaseTest
    bytes32 internal constant ISSUER_ROLE = keccak256("ISSUER_ROLE");

    function setUp() public override {
        super.setUp();

        // Setup pathUSD with issuer role (pathUSDAdmin from BaseTest)
        vm.startPrank(pathUSDAdmin);
        pathUSD.grantRole(ISSUER_ROLE, pathUSDAdmin);
        pathUSD.grantRole(ISSUER_ROLE, admin);
        vm.stopPrank();

        // Setup tokens with issuer role
        vm.startPrank(admin);
        token1.grantRole(ISSUER_ROLE, admin);
        token2.grantRole(ISSUER_ROLE, admin);
        _tokens.push(token1);
        _tokens.push(token2);
        vm.stopPrank();

        // Create trading pairs
        vm.startPrank(admin);
        exchange.createPair(address(token1));
        exchange.createPair(address(token2));
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    PATH FINDING TESTS (Properties 1-3)
    //////////////////////////////////////////////////////////////*/

    /// @notice Property 1: LCA algorithm finds valid paths between all token pairs
    function test_findPathToRoot_DirectQuote() public onlyLocal {
        // token1 quotes pathUSD directly
        address[] memory path = _findPathToRoot(address(token1));
        assertEq(path.length, 2, "Path should have 2 elements for direct quote");
        assertEq(path[0], address(token1), "First element should be token1");
        assertEq(path[1], address(pathUSD), "Second element should be pathUSD");
    }

    /// @notice Property 1: Path to root works for pathUSD itself
    function test_findPathToRoot_PathUSD() public onlyLocal {
        address[] memory path = _findPathToRoot(address(pathUSD));
        assertEq(path.length, 1, "Path should have 1 element for pathUSD");
        assertEq(path[0], address(pathUSD), "Element should be pathUSD");
    }

    /// @notice Property 2: Direct pairs detected correctly (tokenIn.quoteToken == tokenOut)
    function test_directPair_InQuotesOut() public onlyLocal {
        // token1 quotes pathUSD, so token1 -> pathUSD is direct
        _findTradePathAndCollectKeys(address(token1), address(pathUSD));
        assertEq(_bookKeys.length, 1, "Should find exactly 1 book key");

        bytes32 expectedKey = exchange.pairKey(address(token1), address(pathUSD));
        assertEq(_bookKeys[0], expectedKey, "Book key should be token1/pathUSD");
    }

    /// @notice Property 2: Direct pairs detected correctly (tokenOut.quoteToken == tokenIn)
    function test_directPair_OutQuotesIn() public onlyLocal {
        // pathUSD -> token1: token1 quotes pathUSD, so it's outQuote == tokenIn
        _findTradePathAndCollectKeys(address(pathUSD), address(token1));
        assertEq(_bookKeys.length, 1, "Should find exactly 1 book key");

        bytes32 expectedKey = exchange.pairKey(address(token1), address(pathUSD));
        assertEq(_bookKeys[0], expectedKey, "Book key should be token1/pathUSD");
    }

    /// @notice Property 1: Multi-hop path via LCA (both tokens quote pathUSD)
    function test_multiHopPath_BothQuotePathUSD() public onlyLocal {
        // token1 and token2 both quote pathUSD, so LCA is pathUSD
        _findTradePathAndCollectKeys(address(token1), address(token2));

        // Should collect both book keys: token1/pathUSD and token2/pathUSD
        assertEq(_bookKeys.length, 2, "Should find 2 book keys");
        assertTrue(
            _bookKeySet[exchange.pairKey(address(token1), address(pathUSD))],
            "Should have token1/pathUSD"
        );
        assertTrue(
            _bookKeySet[exchange.pairKey(address(token2), address(pathUSD))],
            "Should have token2/pathUSD"
        );
    }

    /// @notice Property 1 (negative): Identical tokens returns early
    function test_findPath_IdenticalTokens() public onlyLocal {
        _findTradePathAndCollectKeys(address(token1), address(token1));
        assertEq(_bookKeys.length, 0, "Should not collect any keys for identical tokens");
    }

    /// @notice Property 3: No duplicate book keys collected
    function test_noDuplicateBookKeys() public onlyLocal {
        // Call the same path multiple times
        _findTradePathAndCollectKeys(address(token1), address(pathUSD));
        _findTradePathAndCollectKeys(address(token1), address(pathUSD));
        _findTradePathAndCollectKeys(address(pathUSD), address(token1));

        assertEq(_bookKeys.length, 1, "Should only have 1 unique key despite multiple calls");
    }

    /// @notice Verify our path finding collects books that enable swaps
    /// @dev This implicitly tests equivalence with StablecoinDEX.findTradePath
    function test_collectedBooksEnableSwaps() public onlyLocal {
        // Collect all paths
        _findTradePathAndCollectKeys(address(token1), address(pathUSD));
        _findTradePathAndCollectKeys(address(pathUSD), address(token1));
        _findTradePathAndCollectKeys(address(token1), address(token2));

        // Fund an actor and place liquidity so swaps can work
        address actor = makeAddr("SwapActor");
        _fundAndApprove(actor, address(pathUSD), 10_000_000_000);
        _fundAndApprove(actor, address(token1), 10_000_000_000);
        _fundAndApprove(actor, address(token2), 10_000_000_000);

        // Place ask orders (sells token for pathUSD) to provide liquidity
        vm.startPrank(actor);
        exchange.place(address(token1), 1_000_000_000, false, 10); // ask
        exchange.place(address(token2), 1_000_000_000, false, 10); // ask
        // Place bid orders (buys token with pathUSD) for reverse direction
        exchange.place(address(token1), 1_000_000_000, true, -10); // bid
        exchange.place(address(token2), 1_000_000_000, true, -10); // bid
        vm.stopPrank();

        // Try swaps - if our path finding is wrong, these would revert with PairDoesNotExist
        vm.startPrank(actor);

        // token1 -> pathUSD (direct)
        uint128 out1 = exchange.swapExactAmountIn(address(token1), address(pathUSD), 100_000_000, 1);
        assertTrue(out1 > 0, "token1->pathUSD swap should work");

        // pathUSD -> token1 (direct)
        uint128 out2 = exchange.swapExactAmountIn(address(pathUSD), address(token1), 100_000_000, 1);
        assertTrue(out2 > 0, "pathUSD->token1 swap should work");

        // token1 -> token2 (multi-hop via pathUSD)
        uint128 out3 = exchange.swapExactAmountIn(address(token1), address(token2), 100_000_000, 1);
        assertTrue(out3 > 0, "token1->token2 multi-hop swap should work");

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                ACTOR COLLECTION TESTS (Properties 4-9)
    //////////////////////////////////////////////////////////////*/

    /// @notice Property 4-5: Order iteration and remaining > 0 filter
    function test_collectOrderMakers_OnlyActiveOrders() public onlyLocal {
        // Place orders with different actors
        address actor1 = makeAddr("Actor1");
        address actor2 = makeAddr("Actor2");
        address actor3 = makeAddr("Actor3");

        _fundAndApprove(actor1, address(pathUSD), 1_000_000_000);
        _fundAndApprove(actor2, address(pathUSD), 1_000_000_000);
        _fundAndApprove(actor3, address(token1), 1_000_000_000);

        // Place orders
        vm.prank(actor1);
        uint128 orderId1 = exchange.place(address(token1), 100_000_000, true, 10);

        vm.prank(actor2);
        exchange.place(address(token1), 100_000_000, true, 10);

        vm.prank(actor3);
        exchange.place(address(token1), 100_000_000, false, 10);

        // Cancel one order (remaining becomes 0 after cancel)
        vm.prank(actor1);
        exchange.cancel(orderId1);

        // Collect from book
        bytes32 bookKey = exchange.pairKey(address(token1), address(pathUSD));
        address[] memory makers = _collectOrderMakers(bookKey, 10);

        // Should only get actor2 and actor3 (actor1's order was cancelled)
        assertEq(makers.length, 2, "Should find 2 active makers");

        bool foundActor2 = false;
        bool foundActor3 = false;
        for (uint256 i = 0; i < makers.length; i++) {
            if (makers[i] == actor2) foundActor2 = true;
            if (makers[i] == actor3) foundActor3 = true;
        }
        assertTrue(foundActor2, "Should find actor2");
        assertTrue(foundActor3, "Should find actor3");
    }

    /// @notice Property 6: Only includes orders matching the book
    function test_collectOrderMakers_OnlyMatchingBook() public onlyLocal {
        address actor1 = makeAddr("Actor1");
        address actor2 = makeAddr("Actor2");

        _fundAndApprove(actor1, address(pathUSD), 1_000_000_000);
        _fundAndApprove(actor2, address(pathUSD), 1_000_000_000);

        // Place order on token1
        vm.prank(actor1);
        exchange.place(address(token1), 100_000_000, true, 10);

        // Place order on token2
        vm.prank(actor2);
        exchange.place(address(token2), 100_000_000, true, 10);

        // Collect from token1 book only
        bytes32 bookKey1 = exchange.pairKey(address(token1), address(pathUSD));
        address[] memory makers = _collectOrderMakers(bookKey1, 10);

        assertEq(makers.length, 1, "Should only find 1 maker");
        assertEq(makers[0], actor1, "Should be actor1 who placed on token1");
    }

    /// @notice Property 7: Deduplicates actors within same book
    function test_collectOrderMakers_DeduplicatesWithinBook() public onlyLocal {
        address actor1 = makeAddr("Actor1");

        _fundAndApprove(actor1, address(pathUSD), 2_000_000_000);
        _fundAndApprove(actor1, address(token1), 1_000_000_000);

        // Same actor places multiple orders
        vm.startPrank(actor1);
        exchange.place(address(token1), 100_000_000, true, 10);
        exchange.place(address(token1), 100_000_000, true, 20);
        exchange.place(address(token1), 100_000_000, false, 30);
        vm.stopPrank();

        bytes32 bookKey = exchange.pairKey(address(token1), address(pathUSD));
        address[] memory makers = _collectOrderMakers(bookKey, 10);

        assertEq(makers.length, 1, "Should deduplicate to 1 maker");
        assertEq(makers[0], actor1, "Should be actor1");
    }

    /// @notice Property 4: Iterates newest to oldest (last placed order's maker should be first if unique)
    function test_collectOrderMakers_NewestFirst() public onlyLocal {
        address actor1 = makeAddr("Actor1");
        address actor2 = makeAddr("Actor2");
        address actor3 = makeAddr("Actor3");

        _fundAndApprove(actor1, address(pathUSD), 1_000_000_000);
        _fundAndApprove(actor2, address(pathUSD), 1_000_000_000);
        _fundAndApprove(actor3, address(pathUSD), 1_000_000_000);

        // Place orders in sequence: actor1, actor2, actor3
        vm.prank(actor1);
        exchange.place(address(token1), 100_000_000, true, 10);

        vm.prank(actor2);
        exchange.place(address(token1), 100_000_000, true, 10);

        vm.prank(actor3);
        exchange.place(address(token1), 100_000_000, true, 10);

        bytes32 bookKey = exchange.pairKey(address(token1), address(pathUSD));
        address[] memory makers = _collectOrderMakers(bookKey, 10);

        // Should find all 3, with actor3 (newest) first
        assertEq(makers.length, 3, "Should find 3 makers");
        assertEq(makers[0], actor3, "Newest order maker (actor3) should be first");
        assertEq(makers[1], actor2, "Second newest (actor2) should be second");
        assertEq(makers[2], actor1, "Oldest (actor1) should be last");
    }

    /// @notice Property 8: Round-robin across books for diversity
    function test_roundRobin_Diversity() public onlyLocal {
        // Create actors for each book
        address[] memory token1Actors = new address[](3);
        address[] memory token2Actors = new address[](3);

        for (uint256 i = 0; i < 3; i++) {
            token1Actors[i] = makeAddr(string.concat("T1Actor", vm.toString(i)));
            token2Actors[i] = makeAddr(string.concat("T2Actor", vm.toString(i)));

            _fundAndApprove(token1Actors[i], address(pathUSD), 1_000_000_000);
            _fundAndApprove(token2Actors[i], address(pathUSD), 1_000_000_000);

            vm.prank(token1Actors[i]);
            exchange.place(address(token1), 100_000_000, true, 10);

            vm.prank(token2Actors[i]);
            exchange.place(address(token2), 100_000_000, true, 10);
        }

        // Collect book keys
        bytes32 book1Key = exchange.pairKey(address(token1), address(pathUSD));
        bytes32 book2Key = exchange.pairKey(address(token2), address(pathUSD));
        _addUniqueBookKey(book1Key);
        _addUniqueBookKey(book2Key);

        // Simulate round-robin
        address[] memory actors = _roundRobinCollect(4);

        // Should interleave: T2Actor2, T1Actor2, T2Actor1, T1Actor1 (newest first from each book)
        // First 4 should come from both books
        uint256 book1Count = 0;
        uint256 book2Count = 0;
        for (uint256 i = 0; i < 4; i++) {
            for (uint256 j = 0; j < 3; j++) {
                if (actors[i] == token1Actors[j]) book1Count++;
                if (actors[i] == token2Actors[j]) book2Count++;
            }
        }

        assertEq(book1Count, 2, "Should have 2 actors from book1");
        assertEq(book2Count, 2, "Should have 2 actors from book2");
    }

    /// @notice Property 9: Reverts if fewer than required actors found
    function test_revertOnInsufficientActors() public onlyLocal {
        // Only place 1 order
        address actor1 = makeAddr("Actor1");
        _fundAndApprove(actor1, address(pathUSD), 1_000_000_000);

        vm.prank(actor1);
        exchange.place(address(token1), 100_000_000, true, 10);

        bytes32 bookKey = exchange.pairKey(address(token1), address(pathUSD));
        _addUniqueBookKey(bookKey);

        // Try to collect 5 actors when only 1 exists - should fail with our custom message
        bool reverted = false;
        try this.externalRoundRobinCollect(5) {
        // Should not reach here
        }
        catch {
            reverted = true;
        }
        assertTrue(reverted, "Should revert when insufficient actors");
    }

    /// @dev External wrapper for testing revert behavior
    function externalRoundRobinCollect(uint256 noOfActors) external returns (address[] memory) {
        return _roundRobinCollect(noOfActors);
    }

    /*//////////////////////////////////////////////////////////////
                    INTEGRATION TESTS (Properties 10-11)
    //////////////////////////////////////////////////////////////*/

    /// @notice Property 10: Fork setup validates FORK_TOKEN_1 is required
    /// @dev This is tested implicitly by the require in _setupInvariantBaseFork

    /// @notice Property 11: Optional tokens work correctly
    /// @dev This is validated in the main invariant test setup

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _fundAndApprove(address actor, address token, uint256 amount) internal {
        vm.startPrank(admin);
        TIP20(token).mint(actor, amount);
        vm.stopPrank();

        vm.prank(actor);
        TIP20(token).approve(address(exchange), type(uint256).max);
    }

    function _findPathToRoot(address token) internal view returns (address[] memory path) {
        uint256 length = 1;
        address current = token;

        while (current != address(pathUSD)) {
            current = address(ITIP20(current).quoteToken());
            length++;
        }

        path = new address[](length);
        current = token;
        for (uint256 i = 0; i < length; i++) {
            path[i] = current;
            if (current == address(pathUSD)) break;
            current = address(ITIP20(current).quoteToken());
        }

        return path;
    }

    function _findTradePathAndCollectKeys(address tokenIn, address tokenOut) internal {
        if (tokenIn == tokenOut) return;

        // Handle pathUSD as endpoint specially - it has no quoteToken
        if (tokenIn == address(pathUSD)) {
            address[] memory pathOut = _findPathToRoot(tokenOut);
            for (uint256 i = 0; i < pathOut.length - 1; i++) {
                _addUniqueBookKey(exchange.pairKey(pathOut[i], pathOut[i + 1]));
            }
            return;
        }
        if (tokenOut == address(pathUSD)) {
            address[] memory pathIn = _findPathToRoot(tokenIn);
            for (uint256 i = 0; i < pathIn.length - 1; i++) {
                _addUniqueBookKey(exchange.pairKey(pathIn[i], pathIn[i + 1]));
            }
            return;
        }

        // Check if direct pair exists (neither is pathUSD)
        address inQuote = address(ITIP20(tokenIn).quoteToken());
        address outQuote = address(ITIP20(tokenOut).quoteToken());

        if (inQuote == tokenOut) {
            _addUniqueBookKey(exchange.pairKey(tokenIn, tokenOut));
            return;
        }
        if (outQuote == tokenIn) {
            _addUniqueBookKey(exchange.pairKey(tokenOut, tokenIn));
            return;
        }

        address[] memory pathIn = _findPathToRoot(tokenIn);
        address[] memory pathOut = _findPathToRoot(tokenOut);

        address lca = address(0);
        for (uint256 i = 0; i < pathIn.length; i++) {
            for (uint256 j = 0; j < pathOut.length; j++) {
                if (pathIn[i] == pathOut[j]) {
                    lca = pathIn[i];
                    break;
                }
            }
            if (lca != address(0)) break;
        }

        require(lca != address(0), "No trading path found between tokens");

        for (uint256 i = 0; i < pathIn.length; i++) {
            if (pathIn[i] == lca) break;
            _addUniqueBookKey(exchange.pairKey(pathIn[i], pathIn[i + 1]));
        }

        for (uint256 i = 0; i < pathOut.length; i++) {
            if (pathOut[i] == lca) break;
            _addUniqueBookKey(exchange.pairKey(pathOut[i], pathOut[i + 1]));
        }
    }

    function _addUniqueBookKey(bytes32 key) internal {
        if (_bookKeySet[key]) return;

        (address base,,,) = exchange.books(key);
        if (base == address(0)) return;

        _bookKeySet[key] = true;
        _bookKeys.push(key);
    }

    function _collectOrderMakers(
        bytes32 bookKey,
        uint256 maxCandidates
    )
        internal
        view
        returns (address[] memory)
    {
        (address base,,,) = exchange.books(bookKey);
        if (base == address(0)) return new address[](0);

        address[] memory temp = new address[](maxCandidates * 2);
        uint256 count = 0;

        uint128 nextId = exchange.nextOrderId();
        uint256 ordersChecked = 0;
        uint256 maxOrders = 500;

        for (
            uint128 orderId = nextId - 1;
            orderId >= 1 && count < maxCandidates && ordersChecked < maxOrders;
            orderId--
        ) {
            ordersChecked++;

            try exchange.getOrder(orderId) returns (IStablecoinDEX.Order memory order) {
                if (order.bookKey != bookKey) continue;
                if (order.remaining == 0) continue;

                bool isDuplicate = false;
                for (uint256 i = 0; i < count; i++) {
                    if (temp[i] == order.maker) {
                        isDuplicate = true;
                        break;
                    }
                }

                if (!isDuplicate) {
                    temp[count] = order.maker;
                    count++;
                }
            } catch {
                continue;
            }
        }

        address[] memory result = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = temp[i];
        }
        return result;
    }

    function _roundRobinCollect(uint256 noOfActors) internal returns (address[] memory) {
        address[][] memory bookCandidates = new address[][](_bookKeys.length);
        for (uint256 b = 0; b < _bookKeys.length; b++) {
            bookCandidates[b] = _collectOrderMakers(_bookKeys[b], noOfActors);
        }

        address[] memory actorsAddress = new address[](noOfActors);
        uint256 actorCount = 0;
        uint256[] memory candidateIdx = new uint256[](_bookKeys.length);

        bool madeProgress = true;
        while (actorCount < noOfActors && madeProgress) {
            madeProgress = false;

            for (uint256 b = 0; b < _bookKeys.length && actorCount < noOfActors; b++) {
                while (candidateIdx[b] < bookCandidates[b].length) {
                    address candidate = bookCandidates[b][candidateIdx[b]];
                    candidateIdx[b]++;

                    if (!_actorSet[candidate]) {
                        _actorSet[candidate] = true;
                        actorsAddress[actorCount] = candidate;
                        actorCount++;
                        madeProgress = true;
                        break;
                    }
                }
            }
        }

        require(
            actorCount >= noOfActors,
            string.concat(
                "Insufficient actors found: need ",
                vm.toString(noOfActors),
                ", found ",
                vm.toString(actorCount)
            )
        );

        return actorsAddress;
    }

}
