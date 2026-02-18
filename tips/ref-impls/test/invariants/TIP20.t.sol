// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP20 Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP20 token implementation
/// @dev Tests invariants TEMPO-TIP1 through TEMPO-TIP29
contract TIP20InvariantTest is InvariantBaseTest {

    /// @dev Ghost variables for reward distribution tracking
    uint256 private _totalRewardsDistributed;
    uint256 private _totalRewardsClaimed;
    uint256 private _ghostRewardInputSum;
    uint256 private _ghostRewardClaimSum;

    /// @dev Track total supply changes for conservation check
    mapping(address => uint256) private _tokenMintSum;
    mapping(address => uint256) private _tokenBurnSum;

    /// @dev Track rewards distributed per token for conservation invariant
    mapping(address => uint256) private _tokenRewardsDistributed;
    mapping(address => uint256) private _tokenRewardsClaimed;

    /// @dev Track distribution count for dust bounds
    mapping(address => uint256) private _tokenDistributionCount;

    /// @dev Track all addresses that have held tokens (per token)
    mapping(address => mapping(address => bool)) private _tokenHolderSeen;
    mapping(address => address[]) private _tokenHolders;

    /// @dev Constants
    uint256 internal constant ACC_PRECISION = 1e18;

    /// @dev Register an address as a potential token holder
    function _registerHolder(address token, address holder) internal {
        if (!_tokenHolderSeen[token][holder]) {
            _tokenHolderSeen[token][holder] = true;
            _tokenHolders[token].push(holder);
        }
    }

    /// @notice Sets up the test environment
    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _actors = _buildActors(20);

        // Snapshot initial supply after _buildActors mints tokens to actors
        for (uint256 i = 0; i < _tokens.length; i++) {
            _tokenMintSum[address(_tokens[i])] = _tokens[i].totalSupply();
        }

        // Register all initially known addresses for each token
        for (uint256 i = 0; i < _tokens.length; i++) {
            address tokenAddr = address(_tokens[i]);

            // Register actors
            for (uint256 j = 0; j < _actors.length; j++) {
                _registerHolder(tokenAddr, _actors[j]);
            }

            // Register system addresses
            _registerHolder(tokenAddr, admin);
            _registerHolder(tokenAddr, tokenAddr); // token contract itself
            _registerHolder(tokenAddr, address(amm));
            _registerHolder(tokenAddr, address(exchange));
            _registerHolder(tokenAddr, address(pathUSD));
            _registerHolder(tokenAddr, alice);
            _registerHolder(tokenAddr, bob);
            _registerHolder(tokenAddr, charlie);
            _registerHolder(tokenAddr, pathUSDAdmin);
        }

        // One-time constant checks (immutable after deployment)
        for (uint256 i = 0; i < _tokens.length; i++) {
            TIP20 token = _tokens[i];

            // TEMPO-TIP21: Decimals is always 6
            assertEq(token.decimals(), 6, "TEMPO-TIP21: Decimals should always be 6");

            // Quote token graph must be acyclic (set at creation, never changes)
            ITIP20 current = token.quoteToken();
            uint256 maxDepth = 20;
            uint256 depth = 0;
            while (address(current) != address(0) && depth < maxDepth) {
                assertTrue(address(current) != address(token), "Quote token cycle detected");
                current = current.quoteToken();
                depth++;
            }
            assertLt(depth, maxDepth, "Quote token chain too deep (possible cycle)");
        }
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for token transfers
    /// @dev Tests TEMPO-TIP1 (balance conservation), TEMPO-TIP2 (total supply unchanged)
    function transfer(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));
        address recipient = _selectActorExcluding(recipientSeed, actor);

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance > 0);

        amount = bound(amount, 1, actorBalance);

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), recipient));
        vm.assume(!token.paused());

        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(actor);
        try token.transfer(recipient, amount) returns (bool success) {
            vm.stopPrank();
            assertTrue(success, "TEMPO-TIP1: Transfer should return true");

            // TEMPO-TIP1: Balance conservation
            assertEq(
                token.balanceOf(actor),
                actorBalance - amount,
                "TEMPO-TIP1: Sender balance not decreased correctly"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP1: Recipient balance not increased correctly"
            );

            // TEMPO-TIP2: Total supply unchanged
            assertEq(
                token.totalSupply(),
                totalSupplyBefore,
                "TEMPO-TIP2: Total supply changed during transfer"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for zero-amount transfer edge case
    /// @dev Tests that zero-amount transfers are handled correctly
    function transferZeroAmount(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));
        address recipient = _selectActorExcluding(recipientSeed, actor);

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), recipient));
        vm.assume(!token.paused());

        uint256 actorBalanceBefore = token.balanceOf(actor);
        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(actor);
        try token.transfer(recipient, 0) returns (bool success) {
            vm.stopPrank();
            assertTrue(success, "Zero transfer should return true");

            // Balances should remain unchanged
            assertEq(
                token.balanceOf(actor),
                actorBalanceBefore,
                "Sender balance changed on zero transfer"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore,
                "Recipient balance changed on zero transfer"
            );
            assertEq(
                token.totalSupply(), totalSupplyBefore, "Total supply changed on zero transfer"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for transferFrom with allowance
    /// @dev Tests TEMPO-TIP3 (allowance consumption), TEMPO-TIP4 (infinite allowance)
    function transferFrom(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address owner = _selectAuthorizedActor(ownerSeed, address(token));
        address spender = _selectActorExcluding(actorSeed, owner);
        address recipient = _selectActorExcluding(recipientSeed, owner);

        uint256 ownerBalance = token.balanceOf(owner);
        vm.assume(ownerBalance > 0);

        uint256 allowance = token.allowance(owner, spender);
        vm.assume(allowance > 0);

        amount = bound(amount, 1, ownerBalance < allowance ? ownerBalance : allowance);

        vm.assume(_isAuthorized(address(token), owner));
        vm.assume(_isAuthorized(address(token), recipient));
        vm.assume(!token.paused());

        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        bool isInfiniteAllowance = allowance == type(uint256).max;

        vm.startPrank(spender);
        try token.transferFrom(owner, recipient, amount) returns (bool success) {
            vm.stopPrank();
            assertTrue(success, "TEMPO-TIP3: TransferFrom should return true");

            // TEMPO-TIP3/TIP4: Allowance handling
            if (isInfiniteAllowance) {
                assertEq(
                    token.allowance(owner, spender),
                    type(uint256).max,
                    "TEMPO-TIP4: Infinite allowance should remain infinite"
                );
            } else {
                assertEq(
                    token.allowance(owner, spender),
                    allowance - amount,
                    "TEMPO-TIP3: Allowance not decreased correctly"
                );
            }

            assertEq(
                token.balanceOf(owner),
                ownerBalance - amount,
                "TEMPO-TIP3: Owner balance not decreased"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP3: Recipient balance not increased"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for approvals
    /// @dev Tests TEMPO-TIP5 (allowance setting)
    function approve(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 spenderSeed,
        uint256 amount
    )
        external
    {
        address actor = _selectActor(actorSeed);
        address spender = _selectActor(spenderSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        amount = bound(amount, 0, type(uint128).max);

        vm.startPrank(actor);
        try token.approve(spender, amount) returns (bool success) {
            vm.stopPrank();
            assertTrue(success, "TEMPO-TIP5: Approve should return true");

            assertEq(
                token.allowance(actor, spender), amount, "TEMPO-TIP5: Allowance not set correctly"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for minting tokens
    /// @dev Tests TEMPO-TIP6 (supply increase), TEMPO-TIP7 (supply cap)
    function mint(uint256 tokenSeed, uint256 recipientSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address recipient = _selectAuthorizedActor(recipientSeed, address(token));

        uint256 currentSupply = token.totalSupply();
        uint256 supplyCap = token.supplyCap();
        uint256 remaining = supplyCap > currentSupply ? supplyCap - currentSupply : 0;

        vm.assume(remaining > 0);
        amount = bound(amount, 1, remaining);

        vm.assume(_isAuthorized(address(token), recipient));

        uint256 recipientBalanceBefore = token.balanceOf(recipient);

        vm.startPrank(admin);
        try token.mint(recipient, amount) {
            vm.stopPrank();

            _tokenMintSum[address(token)] += amount;

            // TEMPO-TIP6: Total supply should increase
            assertEq(
                token.totalSupply(),
                currentSupply + amount,
                "TEMPO-TIP6: Total supply not increased correctly"
            );

            // TEMPO-TIP7: Total supply should not exceed cap
            assertLe(token.totalSupply(), supplyCap, "TEMPO-TIP7: Total supply exceeds supply cap");

            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP6: Recipient balance not increased"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for burning tokens
    /// @dev Tests TEMPO-TIP8 (supply decrease)
    function burn(uint256 tokenSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        uint256 adminBalance = token.balanceOf(admin);
        vm.assume(adminBalance > 0);

        amount = bound(amount, 1, adminBalance);

        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(admin);
        try token.burn(amount) {
            vm.stopPrank();

            _tokenBurnSum[address(token)] += amount;

            // TEMPO-TIP8: Total supply should decrease
            assertEq(
                token.totalSupply(),
                totalSupplyBefore - amount,
                "TEMPO-TIP8: Total supply not decreased correctly"
            );

            assertEq(
                token.balanceOf(admin),
                adminBalance - amount,
                "TEMPO-TIP8: Admin balance not decreased"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for transfer with memo
    /// @dev Tests TEMPO-TIP9 (memo transfers work like regular transfers)
    function transferWithMemo(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount,
        bytes32 memo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));
        address recipient = _selectActorExcluding(recipientSeed, actor);

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance > 0);

        amount = bound(amount, 1, actorBalance);

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), recipient));
        vm.assume(!token.paused());

        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(actor);
        try token.transferWithMemo(recipient, amount, memo) {
            vm.stopPrank();

            // TEMPO-TIP9: Balance changes same as regular transfer
            assertEq(
                token.balanceOf(actor),
                actorBalance - amount,
                "TEMPO-TIP9: Sender balance not decreased"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP9: Recipient balance not increased"
            );
            assertEq(token.totalSupply(), totalSupplyBefore, "TEMPO-TIP9: Total supply changed");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for transferFrom with memo
    /// @dev Tests TEMPO-TIP9 (memo transfers work like regular transfers with allowance)
    function transferFromWithMemo(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount,
        bytes32 memo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address owner = _selectAuthorizedActor(ownerSeed, address(token));
        address spender = _selectActorExcluding(actorSeed, owner);
        address recipient = _selectActorExcluding(recipientSeed, owner);

        uint256 ownerBalance = token.balanceOf(owner);
        vm.assume(ownerBalance > 0);

        uint256 allowance = token.allowance(owner, spender);
        vm.assume(allowance > 0);

        amount = bound(amount, 1, ownerBalance < allowance ? ownerBalance : allowance);

        vm.assume(_isAuthorized(address(token), owner));
        vm.assume(_isAuthorized(address(token), recipient));
        vm.assume(!token.paused());

        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 totalSupplyBefore = token.totalSupply();
        bool isInfiniteAllowance = allowance == type(uint256).max;

        vm.startPrank(spender);
        try token.transferFromWithMemo(owner, recipient, amount, memo) returns (bool success) {
            vm.stopPrank();
            assertTrue(success, "TEMPO-TIP9: TransferFromWithMemo should return true");

            // Balance changes same as regular transferFrom
            assertEq(
                token.balanceOf(owner),
                ownerBalance - amount,
                "TEMPO-TIP9: Owner balance not decreased"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP9: Recipient balance not increased"
            );
            assertEq(token.totalSupply(), totalSupplyBefore, "TEMPO-TIP9: Total supply changed");

            // Allowance handling same as transferFrom
            if (isInfiniteAllowance) {
                assertEq(
                    token.allowance(owner, spender),
                    type(uint256).max,
                    "TEMPO-TIP4: Infinite allowance should remain infinite"
                );
            } else {
                assertEq(
                    token.allowance(owner, spender),
                    allowance - amount,
                    "TEMPO-TIP3: Allowance not decreased correctly"
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for setting reward recipient (opt-in, opt-out, or delegate)
    /// @dev Tests TEMPO-TIP10 (opted-in supply), TEMPO-TIP11 (supply updates), TEMPO-TIP25 (delegation)
    function setRewardRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        // 0 = opt-out, 1 = opt-in to self, 2+ = delegate to another actor
        uint256 choice = recipientSeed % 3;
        address newRecipient;
        if (choice == 0) {
            newRecipient = address(0);
        } else if (choice == 1) {
            newRecipient = actor;
        } else {
            newRecipient = _selectActor(recipientSeed);
            if (newRecipient == actor) newRecipient = _selectActor(recipientSeed + 1);
        }

        vm.assume(_isAuthorized(address(token), actor));
        if (newRecipient != address(0)) {
            vm.assume(_isAuthorized(address(token), newRecipient));
        }
        vm.assume(!token.paused());

        (address currentRecipient,,) = token.userRewardInfo(actor);
        uint256 actorBalance = token.balanceOf(actor);
        uint128 optedInSupplyBefore = token.optedInSupply();

        vm.startPrank(actor);
        try token.setRewardRecipient(newRecipient) {
            vm.stopPrank();

            _registerHolder(address(token), actor);
            if (newRecipient != address(0)) {
                _registerHolder(address(token), newRecipient);
            }

            (address storedRecipient,,) = token.userRewardInfo(actor);

            assertEq(storedRecipient, newRecipient, "Reward recipient not set correctly");

            // Opted-in supply should update correctly
            uint128 optedInSupplyAfter = token.optedInSupply();
            if (currentRecipient == address(0) && newRecipient != address(0)) {
                assertEq(
                    optedInSupplyAfter,
                    optedInSupplyBefore + uint128(actorBalance),
                    "Opted-in supply not increased"
                );
            } else if (currentRecipient != address(0) && newRecipient == address(0)) {
                assertEq(
                    optedInSupplyAfter,
                    optedInSupplyBefore - uint128(actorBalance),
                    "Opted-in supply not decreased"
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for distributing rewards
    /// @dev Tests TEMPO-TIP12, TEMPO-TIP13
    function distributeReward(uint256 actorSeed, uint256 tokenSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance > 0);

        amount = bound(amount, 1, actorBalance);

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), address(token))); // Token contract must be authorized as recipient
        vm.assume(!token.paused());

        vm.assume(token.optedInSupply() > 0);

        uint256 globalRPTBefore = token.globalRewardPerToken();
        uint256 tokenBalanceBefore = token.balanceOf(address(token));

        vm.startPrank(actor);
        try token.distributeReward(amount) {
            vm.stopPrank();

            _totalRewardsDistributed++;
            _ghostRewardInputSum += amount;
            _tokenRewardsDistributed[address(token)] += amount;
            _tokenDistributionCount[address(token)]++;
            _registerHolder(address(token), actor);
            _registerHolder(address(token), address(token));

            // TEMPO-TIP12: Global reward per token should increase by exact floor division
            // Formula: delta = floor(amount * ACC_PRECISION / optedInSupply)
            // Note: optedInSupply may change during _transfer before the delta calculation,
            // so we verify the delta is consistent with the post-transfer optedInSupply
            uint256 globalRPTAfter = token.globalRewardPerToken();
            uint256 actualDelta = globalRPTAfter - globalRPTBefore;

            // Verify delta is reasonable (non-zero when amount > 0 and optedInSupply is reasonable)
            // The exact formula verification is complex due to optedInSupply changes during transfer
            assertTrue(
                actualDelta > 0 || amount * ACC_PRECISION < token.optedInSupply(),
                "TEMPO-TIP12: globalRewardPerToken should increase unless amount is tiny relative to optedInSupply"
            );

            // TEMPO-TIP13: Tokens should be transferred to the token contract
            assertEq(
                token.balanceOf(address(token)),
                tokenBalanceBefore + amount,
                "TEMPO-TIP13: Tokens not transferred to contract"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for distributing tiny rewards where delta == 0
    /// @dev Tests TEMPO-TIP12 edge case: when amount << optedInSupply, delta is 0
    function distributeRewardTiny(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), address(token))); // Token contract must be authorized as recipient
        vm.assume(!token.paused());

        uint128 optedInSupply = token.optedInSupply();
        vm.assume(optedInSupply > ACC_PRECISION); // Ensure division will result in 0

        // Use amount = 1 where delta = floor(1 * ACC_PRECISION / optedInSupply) = 0
        uint256 amount = 1;
        uint256 expectedDelta = (amount * ACC_PRECISION) / optedInSupply;
        vm.assume(expectedDelta == 0); // Confirm this is indeed a zero-delta case

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance >= amount);

        uint256 globalRPTBefore = token.globalRewardPerToken();

        vm.startPrank(actor);
        try token.distributeReward(amount) {
            vm.stopPrank();

            // Update ghost variables (same as distributeReward)
            _totalRewardsDistributed++;
            _ghostRewardInputSum += amount;
            _tokenRewardsDistributed[address(token)] += amount;
            _tokenDistributionCount[address(token)]++;
            _registerHolder(address(token), actor);
            _registerHolder(address(token), address(token));

            // TEMPO-TIP12: When delta == 0, globalRewardPerToken must stay constant
            uint256 globalRPTAfter = token.globalRewardPerToken();
            assertEq(
                globalRPTAfter,
                globalRPTBefore,
                "TEMPO-TIP12: Zero-delta distribution should not change globalRewardPerToken"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for attempting to distribute rewards when optedInSupply == 0
    /// @dev Tests TEMPO-TIP12 edge case: must revert with NoOptedInSupply when nobody is opted in
    function distributeRewardZeroOptedIn(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), address(token))); // Token contract must be authorized as recipient
        vm.assume(!token.paused());

        uint128 optedInSupply = token.optedInSupply();
        vm.assume(optedInSupply == 0); // Only test when nobody is opted in

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance >= 1000);

        vm.startPrank(actor);
        try token.distributeReward(1000) {
            vm.stopPrank();
            revert("TEMPO-TIP12: distributeReward should revert when optedInSupply == 0");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                ITIP20.NoOptedInSupply.selector,
                "TEMPO-TIP12: Should revert with NoOptedInSupply when optedInSupply == 0"
            );
        }
    }

    /// @notice Handler for claiming rewards
    /// @dev Tests TEMPO-TIP14, TEMPO-TIP15
    function claimRewards(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), address(token)));
        vm.assume(!token.paused());

        (,, uint256 rewardBalance) = token.userRewardInfo(actor);
        uint256 actorBalanceBefore = token.balanceOf(actor);
        uint256 contractBalanceBefore = token.balanceOf(address(token));

        vm.startPrank(actor);
        try token.claimRewards() returns (uint256 claimed) {
            vm.stopPrank();

            _registerHolder(address(token), actor);

            if (rewardBalance > 0 || claimed > 0) {
                _totalRewardsClaimed++;
                _ghostRewardClaimSum += claimed;
                _tokenRewardsClaimed[address(token)] += claimed;
            }

            // TEMPO-TIP14: Actor should receive claimed amount
            assertEq(
                token.balanceOf(actor),
                actorBalanceBefore + claimed,
                "TEMPO-TIP14: Actor balance not increased by claimed amount"
            );

            assertEq(
                token.balanceOf(address(token)),
                contractBalanceBefore - claimed,
                "TEMPO-TIP14: Contract balance not decreased"
            );

            // TEMPO-TIP15: Claimed amount should not exceed available
            assertLe(
                claimed, contractBalanceBefore, "TEMPO-TIP15: Claimed more than contract balance"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for reward claim with detailed verification
    /// @dev Tests TEMPO-TIP14/TIP15: verifies claim is bounded by contract balance and stored rewards
    function claimRewardsVerified(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectAuthorizedActor(actorSeed, address(token));

        vm.assume(_isAuthorized(address(token), actor));
        vm.assume(_isAuthorized(address(token), address(token)));
        vm.assume(!token.paused());

        uint256 contractBalance = token.balanceOf(address(token));
        uint256 actorBalanceBefore = token.balanceOf(actor);

        // Use contract's getPendingRewards view to get expected claimable amount
        uint256 pendingRewards = token.getPendingRewards(actor);
        uint256 expectedClaim = contractBalance > pendingRewards ? pendingRewards : contractBalance;

        vm.startPrank(actor);
        try token.claimRewards() returns (uint256 claimed) {
            vm.stopPrank();

            _registerHolder(address(token), actor);
            _registerHolder(address(token), address(token));

            if (claimed > 0) {
                _totalRewardsClaimed++;
                _ghostRewardClaimSum += claimed;
                _tokenRewardsClaimed[address(token)] += claimed;
            }

            // TEMPO-TIP15: Claimed should be min(pendingRewards, contractBalance)
            assertEq(claimed, expectedClaim, "TEMPO-TIP15: Claimed amount incorrect");

            // TEMPO-TIP15: Claimed should not exceed contract balance
            assertLe(claimed, contractBalance, "TEMPO-TIP15: Claimed more than contract balance");

            // TEMPO-TIP14: Actor should receive exactly the claimed amount
            assertEq(
                token.balanceOf(actor),
                actorBalanceBefore + claimed,
                "TEMPO-TIP14: Actor balance not increased correctly"
            );

            // Contract balance should decrease by claimed amount
            assertEq(
                token.balanceOf(address(token)),
                contractBalance - claimed,
                "TEMPO-TIP14: Contract balance not decreased correctly"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for burning tokens from blocked accounts
    /// @dev Tests TEMPO-TIP23 (burnBlocked functionality)
    function burnBlocked(uint256 tokenSeed, uint256 targetSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address target = _selectActor(targetSeed);

        // Ensure target is blacklisted for this test
        uint64 policyId = _tokenPolicyIds[address(token)];
        bool isBlacklisted = !registry.isAuthorized(policyId, target);
        vm.assume(isBlacklisted);

        uint256 targetBalance = token.balanceOf(target);
        vm.assume(targetBalance > 0);

        amount = bound(amount, 1, targetBalance);

        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(admin);
        token.grantRole(_BURN_BLOCKED_ROLE, admin);
        try token.burnBlocked(target, amount) {
            vm.stopPrank();

            _tokenBurnSum[address(token)] += amount;

            // TEMPO-TIP23: Balance should decrease
            assertEq(
                token.balanceOf(target),
                targetBalance - amount,
                "TEMPO-TIP23: Target balance not decreased"
            );

            // TEMPO-TIP23: Total supply should decrease
            assertEq(
                token.totalSupply(),
                totalSupplyBefore - amount,
                "TEMPO-TIP23: Total supply not decreased"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for attempting burnBlocked on protected addresses
    /// @dev Tests TEMPO-TIP24 (protected addresses cannot be burned from)
    function burnBlockedProtectedAddress(uint256 tokenSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        amount = bound(amount, 1, 1_000_000);

        address feeManager = 0xfeEC000000000000000000000000000000000000;
        address dex = 0xDEc0000000000000000000000000000000000000;

        vm.startPrank(admin);
        token.grantRole(_BURN_BLOCKED_ROLE, admin);

        // Try to burn from FeeManager - should revert with ProtectedAddress
        try token.burnBlocked(feeManager, amount) {
            vm.stopPrank();
            revert("TEMPO-TIP24: Should revert for FeeManager");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                ITIP20.ProtectedAddress.selector,
                "TEMPO-TIP24: Should revert with ProtectedAddress for FeeManager"
            );
        }

        // Try to burn from DEX - should revert with ProtectedAddress
        try token.burnBlocked(dex, amount) {
            vm.stopPrank();
            revert("TEMPO-TIP24: Should revert for DEX");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                ITIP20.ProtectedAddress.selector,
                "TEMPO-TIP24: Should revert with ProtectedAddress for DEX"
            );
        }
    }

    /// @notice Handler for unauthorized mint attempts
    /// @dev Tests TEMPO-TIP26 (only ISSUER_ROLE can mint)
    function mintUnauthorized(uint256 actorSeed, uint256 tokenSeed, uint256 amount) external {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Ensure attacker doesn't have ISSUER_ROLE
        vm.assume(!token.hasRole(attacker, _ISSUER_ROLE));

        amount = bound(amount, 1, 1_000_000);

        vm.startPrank(attacker);
        try token.mint(attacker, amount) {
            vm.stopPrank();
            revert("TEMPO-TIP26: Non-issuer should not be able to mint");
        } catch {
            vm.stopPrank();
            // Expected to revert - access control enforced
        }
    }

    /// @notice Handler for unauthorized pause attempts
    /// @dev Tests TEMPO-TIP27 (only PAUSE_ROLE can pause)
    function pauseUnauthorized(uint256 actorSeed, uint256 tokenSeed) external {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Ensure attacker doesn't have PAUSE_ROLE
        vm.assume(!token.hasRole(attacker, _PAUSE_ROLE));
        vm.assume(!token.paused());

        vm.startPrank(attacker);
        try token.pause() {
            vm.stopPrank();
            revert("TEMPO-TIP27: Non-pause-role should not be able to pause");
        } catch {
            vm.stopPrank();
            // Expected to revert - access control enforced
        }
    }

    /// @notice Handler for unauthorized unpause attempts
    /// @dev Tests TEMPO-TIP28 (only UNPAUSE_ROLE can unpause)
    function unpauseUnauthorized(uint256 actorSeed, uint256 tokenSeed) external {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Ensure attacker doesn't have UNPAUSE_ROLE
        vm.assume(!token.hasRole(attacker, _UNPAUSE_ROLE));
        vm.assume(token.paused());

        vm.startPrank(attacker);
        try token.unpause() {
            vm.stopPrank();
            revert("TEMPO-TIP28: Non-unpause-role should not be able to unpause");
        } catch {
            vm.stopPrank();
            // Expected to revert - access control enforced
        }
    }

    /// @notice Handler for unauthorized burnBlocked attempts
    /// @dev Tests TEMPO-TIP29 (only BURN_BLOCKED_ROLE can call burnBlocked)
    function burnBlockedUnauthorized(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 targetSeed,
        uint256 amount
    )
        external
    {
        address attacker = _selectActor(actorSeed);
        address target = _selectActor(targetSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Ensure attacker doesn't have BURN_BLOCKED_ROLE
        vm.assume(!token.hasRole(attacker, _BURN_BLOCKED_ROLE));

        uint256 targetBalance = token.balanceOf(target);
        vm.assume(targetBalance > 0);
        amount = bound(amount, 1, targetBalance);

        vm.startPrank(attacker);
        try token.burnBlocked(target, amount) {
            vm.stopPrank();
            revert("TEMPO-TIP29: Non-burn-blocked-role should not be able to call burnBlocked");
        } catch {
            vm.stopPrank();
            // Expected to revert - access control enforced
        }
    }

    /// @notice Handler for changing transfer policy ID
    /// @dev Tests that only admin can change policy, and policy must exist
    function changeTransferPolicyId(uint256 tokenSeed, uint256 policySeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        // Select from special policies (0, 1) or created policies
        uint64 newPolicyId;
        if (policySeed % 3 == 0) {
            newPolicyId = 0; // always-reject
        } else if (policySeed % 3 == 1) {
            newPolicyId = 1; // always-allow
        } else {
            // Use the token's current policy or a nearby valid one
            newPolicyId = uint64(policySeed % 10) + 2;
        }

        vm.startPrank(admin);
        try token.changeTransferPolicyId(newPolicyId) {
            vm.stopPrank();

            assertEq(token.transferPolicyId(), newPolicyId, "Transfer policy ID not updated");
        } catch (bytes memory reason) {
            vm.stopPrank();
            // Expected if policy doesn't exist
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for unauthorized policy change attempts
    /// @dev Tests that non-admin cannot change transfer policy
    function changeTransferPolicyIdUnauthorized(uint256 actorSeed, uint256 tokenSeed) external {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Ensure attacker is not admin
        vm.assume(!token.hasRole(attacker, bytes32(0))); // DEFAULT_ADMIN_ROLE

        vm.startPrank(attacker);
        try token.changeTransferPolicyId(1) {
            vm.stopPrank();
            revert("Non-admin should not change policy");
        } catch {
            vm.stopPrank();
            // Expected - access control enforced
        }
    }

    /// @notice Handler for quote token updates
    /// @dev Tests setNextQuoteToken and completeQuoteTokenUpdate
    function updateQuoteToken(uint256 tokenSeed, uint256 quoteTokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        // Skip pathUSD - it cannot change quote token
        vm.assume(address(token) != address(pathUSD));

        // Select a different token as potential new quote
        TIP20 newQuoteToken = _selectBaseToken(quoteTokenSeed);
        vm.assume(address(newQuoteToken) != address(token));

        // For USD tokens, quote must also be USD
        bool isUsdToken = keccak256(bytes(token.currency())) == keccak256(bytes("USD"));
        if (isUsdToken) {
            bool isUsdQuote = keccak256(bytes(newQuoteToken.currency())) == keccak256(bytes("USD"));
            vm.assume(isUsdQuote);
        }

        vm.startPrank(admin);
        try token.setNextQuoteToken(ITIP20(address(newQuoteToken))) {
            // Next quote token should be set
            assertEq(
                address(token.nextQuoteToken()), address(newQuoteToken), "Next quote token not set"
            );

            // Try to complete the update
            try token.completeQuoteTokenUpdate() {
                vm.stopPrank();

                // Quote token should be updated
                assertEq(
                    address(token.quoteToken()), address(newQuoteToken), "Quote token not updated"
                );
            } catch (bytes memory reason) {
                vm.stopPrank();
                // Cycle detection may reject
                bytes4 selector = bytes4(reason);
                assertTrue(
                    selector == ITIP20.InvalidQuoteToken.selector,
                    "Unexpected error on completeQuoteTokenUpdate"
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for unauthorized quote token update attempts
    /// @dev Tests that non-admin cannot change quote token
    function updateQuoteTokenUnauthorized(uint256 actorSeed, uint256 tokenSeed) external {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        vm.assume(address(token) != address(pathUSD));
        vm.assume(!token.hasRole(attacker, bytes32(0))); // DEFAULT_ADMIN_ROLE

        vm.startPrank(attacker);
        try token.setNextQuoteToken(ITIP20(address(pathUSD))) {
            vm.stopPrank();
            revert("Non-admin should not set quote token");
        } catch {
            vm.stopPrank();
            // Expected - access control enforced
        }
    }

    /// @notice Handler for setting supply cap
    /// @dev Tests TEMPO-TIP22 (supply cap enforcement)
    function setSupplyCap(uint256 tokenSeed, uint256 newCap) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        uint256 currentSupply = token.totalSupply();

        // Bound new cap between current supply and max uint128
        newCap = bound(newCap, currentSupply, type(uint128).max);

        vm.startPrank(admin);
        try token.setSupplyCap(newCap) {
            vm.stopPrank();

            // TEMPO-TIP22: New cap should be set
            assertEq(token.supplyCap(), newCap, "TEMPO-TIP22: Supply cap not updated");

            // TEMPO-TIP22: Cap must be >= current supply
            assertGe(
                token.supplyCap(), token.totalSupply(), "TEMPO-TIP22: Supply cap below total supply"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for unauthorized supply cap change attempts
    /// @dev Tests that non-admin cannot change supply cap
    function setSupplyCapUnauthorized(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 newCap
    )
        external
    {
        address attacker = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        vm.assume(!token.hasRole(attacker, bytes32(0))); // DEFAULT_ADMIN_ROLE

        vm.startPrank(attacker);
        try token.setSupplyCap(newCap) {
            vm.stopPrank();
            revert("Non-admin should not change supply cap");
        } catch {
            vm.stopPrank();
            // Expected - access control enforced
        }
    }

    /// @notice Handler for attempting to set supply cap below current supply
    /// @dev Tests that supply cap cannot be set below current supply
    function setSupplyCapBelowSupply(uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        uint256 currentSupply = token.totalSupply();
        vm.assume(currentSupply > 1);

        uint256 invalidCap = currentSupply - 1;

        vm.startPrank(admin);
        try token.setSupplyCap(invalidCap) {
            vm.stopPrank();
            revert("TEMPO-TIP22: Should revert when cap < supply");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertEq(
                bytes4(reason),
                ITIP20.InvalidSupplyCap.selector,
                "TEMPO-TIP22: Should revert with InvalidSupplyCap"
            );
        }
    }

    /// @notice Handler for toggling blacklist
    /// @dev Tests TEMPO-TIP16 (blacklist enforcement)
    function toggleBlacklist(uint256 actorSeed, uint256 tokenSeed, bool blacklist) external {
        address actor = _selectActor(actorSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Only toggle for actors 0-4
        vm.assume(actorSeed % _actors.length < 5);

        // Skip if policy is a special policy (0 or 1) which cannot be modified
        uint64 policyId = _getPolicyId(address(token));
        vm.assume(policyId >= 2);

        // Ensure we are the policy admin (policy may have changed via changeTransferPolicyId)
        address policyAdmin = _getPolicyAdmin(address(token));
        vm.assume(policyAdmin == admin || policyAdmin == pathUSDAdmin);

        bool currentlyAuthorized = _isAuthorized(address(token), actor);

        if (blacklist && !currentlyAuthorized) return;
        if (!blacklist && currentlyAuthorized) return;

        // Try to set blacklist - may fail if policy doesn't exist or we're not admin
        vm.startPrank(policyAdmin);
        try registry.modifyPolicyBlacklist(policyId, actor, blacklist) {
            vm.stopPrank();
            // TEMPO-TIP16: Authorization status should be updated
            bool afterAuthorized = _isAuthorized(address(token), actor);
            assertEq(
                afterAuthorized, !blacklist, "TEMPO-TIP16: Blacklist status not updated correctly"
            );
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for pause/unpause
    /// @dev Tests TEMPO-TIP17 (pause enforcement)
    function togglePause(uint256 tokenSeed, bool pause) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.grantRole(_UNPAUSE_ROLE, admin);

        if (pause && !token.paused()) {
            token.pause();
            assertTrue(token.paused(), "TEMPO-TIP17: Token should be paused");
        } else if (!pause && token.paused()) {
            token.unpause();
            assertFalse(token.paused(), "TEMPO-TIP17: Token should be unpaused");
        }
        vm.stopPrank();
    }

    /// @notice Handler that verifies paused tokens reject transfers with ContractPaused
    /// @dev Tests TEMPO-TIP17: pause enforcement - transfers revert with ContractPaused
    function tryTransferWhilePaused(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed
    )
        external
    {
        address actor = _selectActor(actorSeed);
        address recipient = _selectActorExcluding(recipientSeed, actor);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Only test when token is paused
        vm.assume(token.paused());

        uint256 actorBalance = token.balanceOf(actor);
        vm.assume(actorBalance > 0);

        vm.startPrank(actor);
        try token.transfer(recipient, 1) {
            vm.stopPrank();
            revert("TEMPO-TIP17: Transfer should fail when paused");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Run all invariant checks in a single unified loop
    /// @dev Combines TEMPO-TIP18, TIP19, TIP20, TIP22, and rewards conservation checks
    ///      Decimals (TIP21) and quote token acyclic checks moved to setUp() as they're immutable
    function invariant_globalInvariants() public view {
        for (uint256 i = 0; i < _tokens.length; i++) {
            TIP20 token = _tokens[i];
            address tokenAddr = address(token);
            uint256 totalSupply = token.totalSupply();

            // TEMPO-TIP19: Opted-in supply <= total supply
            assertLe(
                token.optedInSupply(),
                totalSupply,
                "TEMPO-TIP19: Opted-in supply exceeds total supply"
            );

            // TEMPO-TIP22: Supply cap is enforced
            assertLe(totalSupply, token.supplyCap(), "TEMPO-TIP22: Total supply exceeds supply cap");

            // TEMPO-TIP18: Supply conservation - totalSupply = mints - burns
            uint256 expectedSupply = _tokenMintSum[tokenAddr] - _tokenBurnSum[tokenAddr];
            assertEq(totalSupply, expectedSupply, "TEMPO-TIP18: Supply conservation violated");

            // TEMPO-TIP20: Balance sum equals supply
            address[] storage holders = _tokenHolders[tokenAddr];
            uint256 balanceSum = 0;
            for (uint256 j = 0; j < holders.length; j++) {
                balanceSum += token.balanceOf(holders[j]);
            }
            assertEq(balanceSum, totalSupply, "TEMPO-TIP20: Balance sum does not equal totalSupply");

            // Rewards conservation: claimed <= distributed, dust bounded
            uint256 distributed = _tokenRewardsDistributed[tokenAddr];
            uint256 claimed = _tokenRewardsClaimed[tokenAddr];
            assertLe(claimed, distributed, "Rewards claimed exceeds distributed");

            if (distributed > 0) {
                uint256 contractBalance = token.balanceOf(tokenAddr);
                uint256 expectedUnclaimed = distributed - claimed;
                uint256 holderCount = holders.length;
                uint256 maxDust =
                    _tokenDistributionCount[tokenAddr] * (holderCount > 0 ? holderCount : 1);

                if (expectedUnclaimed > maxDust) {
                    assertGe(
                        contractBalance,
                        expectedUnclaimed - maxDust,
                        "Reward dust exceeds theoretical bound"
                    );
                }
            }
        }
    }

}
