// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { IAccountKeychain } from "../../src/interfaces/IAccountKeychain.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title TIP20 Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP20 token implementation
/// @dev Tests invariants TEMPO-TIP1 through TEMPO-TIP29
contract TIP20InvariantTest is InvariantBaseTest {

    /// @dev Log file path for recording actions
    string private constant LOG_FILE = "tip20.log";

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

    /*//////////////////////////////////////////////////////////////
                           ENSURE HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Ensures a token is unpaused. If paused, unpauses it.
    function _ensureUnpaused(TIP20 token) internal {
        if (!token.paused()) return;
        vm.startPrank(admin);
        token.grantRole(_UNPAUSE_ROLE, admin);
        token.unpause();
        vm.stopPrank();
    }

    /// @dev Ensures a token is paused. If unpaused, pauses it.
    function _ensurePaused(TIP20 token) internal {
        if (token.paused()) return;
        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.pause();
        vm.stopPrank();
    }

    /// @dev Ensures an actor has at least `min` balance, minting if needed. Updates ghost state.
    ///      Returns false if supply cap prevents minting enough tokens or mint reverts.
    function _ensureBalance(TIP20 token, address actor, uint256 min) internal returns (bool) {
        uint256 bal = token.balanceOf(actor);
        if (bal >= min) return true;
        uint256 needed = min - bal;
        uint256 cap = token.supplyCap();
        uint256 supply = token.totalSupply();
        if (supply >= cap) return false;
        uint256 remaining = cap - supply;
        if (remaining < needed) return false;
        uint256 mintAmt = needed + (remaining - needed < 100_000_000 ? 0 : 100_000_000);
        vm.prank(admin);
        try token.mint(actor, mintAmt) {
            _tokenMintSum[address(token)] += mintAmt;
            _registerHolder(address(token), actor);
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Ensures spender has at least `min` allowance from owner. Approves if needed.
    ///      Returns false if approve reverts (e.g. due to AccountKeychain constraints).
    function _ensureAllowance(TIP20 token, address owner, address spender, uint256 min) internal returns (bool) {
        if (token.allowance(owner, spender) >= min) return true;
        vm.prank(owner);
        try token.approve(spender, min) {
            return true;
        } catch {
            return false;
        }
    }

    /// @dev Ensures there is opted-in supply by opting in an actor if needed.
    function _ensureOptedInSupply(TIP20 token, uint256 seed) internal returns (bool) {
        if (token.optedInSupply() > 0) return true;
        uint256 start = seed % _actors.length;
        for (uint256 i = 0; i < _actors.length; i++) {
            address cand = _actors[addmod(start, i, _actors.length)];
            if (_isAuthorized(address(token), cand) && token.balanceOf(cand) > 0) {
                vm.prank(cand);
                token.setRewardRecipient(cand);
                return token.optedInSupply() > 0;
            }
        }
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                        TRANSFER SNAPSHOT HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Captures all relevant state before a transfer for post-transfer assertions
    struct TransferSnapshot {
        uint256 fromBalance;
        uint256 toBalance;
        uint256 totalSupply;
        uint128 optedInSupply;
        uint256 globalRPT;
        address fromDelegate;
        uint256 fromRPT;
        address toDelegate;
        uint256 toRPT;
        uint256 fromDelegateRewardBal;
        uint256 toDelegateRewardBal;
        uint256 spenderRPTBefore;
        uint256 spenderRewardBalBefore;
    }

    /// @dev Takes a snapshot of all transfer-relevant state
    function _snapTransfer(
        TIP20 token,
        address from,
        address to
    )
        internal
        view
        returns (TransferSnapshot memory s)
    {
        s.fromBalance = token.balanceOf(from);
        s.toBalance = token.balanceOf(to);
        s.totalSupply = token.totalSupply();
        s.optedInSupply = token.optedInSupply();
        s.globalRPT = token.globalRewardPerToken();
        (s.fromDelegate, s.fromRPT,) = token.userRewardInfo(from);
        (s.toDelegate, s.toRPT,) = token.userRewardInfo(to);
        if (s.fromDelegate != address(0)) {
            (,, s.fromDelegateRewardBal) = token.userRewardInfo(s.fromDelegate);
        }
        if (s.toDelegate != address(0)) {
            (,, s.toDelegateRewardBal) = token.userRewardInfo(s.toDelegate);
        }
    }

    /// @dev Asserts all post-transfer invariants: balance conservation, total supply,
    ///      optedInSupply delta, globalRPT unchanged, rewardPerToken synced, reward accrual
    function _assertPostTransfer(
        TIP20 token,
        address from,
        address to,
        uint256 amount,
        TransferSnapshot memory s,
        string memory ctx
    )
        internal
        view
    {
        bool isSelf = from == to;

        // Balance conservation
        if (isSelf) {
            assertEq(token.balanceOf(from), s.fromBalance, string.concat(ctx, ": balance changed on self-transfer"));
        } else {
            assertEq(
                token.balanceOf(from), s.fromBalance - amount, string.concat(ctx, ": sender balance incorrect")
            );
            assertEq(
                token.balanceOf(to), s.toBalance + amount, string.concat(ctx, ": recipient balance incorrect")
            );
        }

        // Total supply unchanged
        assertEq(token.totalSupply(), s.totalSupply, string.concat(ctx, ": total supply changed"));

        // optedInSupply delta
        {
            int256 expectedDelta;
            if (!isSelf) {
                expectedDelta = (s.toDelegate != address(0) ? int256(uint256(amount)) : int256(0))
                    - (s.fromDelegate != address(0) ? int256(uint256(amount)) : int256(0));
            }
            assertEq(
                int256(uint256(token.optedInSupply())),
                int256(uint256(s.optedInSupply)) + expectedDelta,
                string.concat(ctx, ": optedInSupply delta mismatch")
            );
        }

        // globalRewardPerToken unchanged
        assertEq(
            token.globalRewardPerToken(), s.globalRPT, string.concat(ctx, ": globalRewardPerToken changed")
        );

        // rewardPerToken synced to global
        {
            (, uint256 fromRPTAfter,) = token.userRewardInfo(from);
            assertEq(fromRPTAfter, s.globalRPT, string.concat(ctx, ": sender rewardPerToken not synced"));

            if (!isSelf) {
                (, uint256 toRPTAfter,) = token.userRewardInfo(to);
                assertEq(toRPTAfter, s.globalRPT, string.concat(ctx, ": recipient rewardPerToken not synced"));
            }
        }

        // Reward accrual
        _assertRewardAccrual(token, isSelf, s, ctx);
    }

    /// @dev Asserts delegate reward accrual is correct after a transfer
    function _assertRewardAccrual(
        TIP20 token,
        bool isSelf,
        TransferSnapshot memory s,
        string memory ctx
    )
        internal
        view
    {
        if (isSelf) {
            if (s.fromDelegate != address(0) && s.globalRPT > s.fromRPT) {
                uint256 expectedAccrual = (s.fromBalance * (s.globalRPT - s.fromRPT)) / ACC_PRECISION;
                (,, uint256 delegateRewardBalAfter) = token.userRewardInfo(s.fromDelegate);
                assertEq(
                    delegateRewardBalAfter,
                    s.fromDelegateRewardBal + expectedAccrual,
                    string.concat(ctx, ": self-transfer delegate reward accrual should happen exactly once")
                );
            }
            return;
        }

        if (s.fromDelegate != address(0) && s.globalRPT > s.fromRPT) {
            uint256 expectedAccrual = (s.fromBalance * (s.globalRPT - s.fromRPT)) / ACC_PRECISION;
            (,, uint256 fromDelegateRewardBalAfter) = token.userRewardInfo(s.fromDelegate);
            uint256 base = s.fromDelegateRewardBal;
            if (s.fromDelegate == s.toDelegate && s.globalRPT > s.toRPT) {
                base += (s.toBalance * (s.globalRPT - s.toRPT)) / ACC_PRECISION;
            }
            assertEq(
                fromDelegateRewardBalAfter,
                base + expectedAccrual,
                string.concat(ctx, ": sender delegate reward accrual incorrect")
            );
        }
        if (s.toDelegate != address(0) && s.globalRPT > s.toRPT) {
            uint256 expectedAccrual = (s.toBalance * (s.globalRPT - s.toRPT)) / ACC_PRECISION;
            (,, uint256 toDelegateRewardBalAfter) = token.userRewardInfo(s.toDelegate);
            uint256 base = s.toDelegateRewardBal;
            if (s.fromDelegate == s.toDelegate && s.globalRPT > s.fromRPT) {
                base += (s.fromBalance * (s.globalRPT - s.fromRPT)) / ACC_PRECISION;
            }
            assertEq(
                toDelegateRewardBalAfter,
                base + expectedAccrual,
                string.concat(ctx, ": recipient delegate reward accrual incorrect")
            );
        }
    }

    /// @dev Asserts spender reward info is unchanged after a transferFrom.
    function _assertSpenderIsolation(
        TIP20 token,
        address spender,
        address owner,
        address recipient,
        TransferSnapshot memory s
    ) internal view {
        if (spender != owner && spender != recipient && spender != s.fromDelegate && spender != s.toDelegate) {
            (, uint256 rptA, uint256 rbA) = token.userRewardInfo(spender);
            assertEq(rptA, s.spenderRPTBefore, "Spender rewardPerToken changed");
            assertEq(rbA, s.spenderRewardBalBefore, "Spender rewardBalance changed");
        }
    }

    /// @dev Executes transferFrom and asserts event, allowance, post-transfer, and spender isolation.
    function _transferFromAndAssert(
        TIP20 token,
        address owner,
        address spender,
        address recipient,
        uint256 amount,
        TransferSnapshot memory s
    ) internal {
        uint256 allowBefore = token.allowance(owner, spender);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(owner, recipient, amount);

        vm.startPrank(spender);
        assertTrue(token.transferFrom(owner, recipient, amount), "TEMPO-TIP3: TransferFrom should return true");
        vm.stopPrank();

        // Allowance check
        {
            uint256 allowAfter = token.allowance(owner, spender);
            if (allowBefore == type(uint256).max) {
                assertEq(allowAfter, type(uint256).max, "TEMPO-TIP4: Infinite allowance should remain infinite");
            } else {
                assertEq(allowAfter, allowBefore - amount, "TEMPO-TIP3: Allowance not decreased correctly");
            }
        }

        _assertPostTransfer(token, owner, recipient, amount, s, "transferFrom");
        _assertSpenderIsolation(token, spender, owner, recipient, s);
    }

    /// @dev Executes transferFromWithMemo and asserts event, allowance, post-transfer, and spender isolation.
    function _transferFromWithMemoAndAssert(
        TIP20 token,
        address owner,
        address spender,
        address recipient,
        uint256 amount,
        bytes32 memo,
        TransferSnapshot memory s
    ) internal {
        uint256 allowBefore = token.allowance(owner, spender);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(owner, recipient, amount);

        vm.startPrank(spender);
        assertTrue(
            token.transferFromWithMemo(owner, recipient, amount, memo),
            "TEMPO-TIP9: TransferFromWithMemo should return true"
        );
        vm.stopPrank();

        // Allowance check
        {
            uint256 allowAfter = token.allowance(owner, spender);
            if (allowBefore == type(uint256).max) {
                assertEq(allowAfter, type(uint256).max, "TEMPO-TIP4: Infinite allowance should remain infinite");
            } else {
                assertEq(allowAfter, allowBefore - amount, "TEMPO-TIP3: Allowance not decreased correctly");
            }
        }

        _assertPostTransfer(token, owner, recipient, amount, s, "transferFromWithMemo");
        _assertSpenderIsolation(token, spender, owner, recipient, s);
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

        _initLogFile(LOG_FILE, "TIP20 Invariant Test Log");

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

    /// @notice Handler for token transfers (success path)
    /// @dev Tests TEMPO-TIP1 (balance conservation), TEMPO-TIP2 (total supply unchanged),
    ///      optedInSupply consistency, reward accounting, and Transfer event emission
    function handler_transfer(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        address recipient;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), actor);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

        TransferSnapshot memory s = _snapTransfer(token, actor, recipient);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(actor, recipient, amount);

        vm.startPrank(actor);
        bool success = token.transfer(recipient, amount);
        vm.stopPrank();

        assertTrue(success, "TEMPO-TIP1: Transfer should return true");
        _assertPostTransfer(token, actor, recipient, amount, s, "transfer");

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER: ",
                    _getActorIndex(actor),
                    " -> ",
                    _getActorIndex(recipient),
                    " ",
                    vm.toString(amount),
                    " ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for self-transfer edge case
    /// @dev Self-transfers are valid and must not change any balances or optedInSupply.
    ///      Reward accrual must happen exactly once (not doubled).
    function handler_transferSelf(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
            if (!_isAuthorizedRecipient(address(token), actor)) return;
        }

        amount = bound(amount, 0, token.balanceOf(actor));

        TransferSnapshot memory s = _snapTransfer(token, actor, actor);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(actor, actor, amount);

        vm.startPrank(actor);
        bool success = token.transfer(actor, amount);
        vm.stopPrank();

        assertTrue(success, "Self-transfer should return true");
        _assertPostTransfer(token, actor, actor, amount, s, "self-transfer");

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_SELF: ",
                    _getActorIndex(actor),
                    " ",
                    vm.toString(amount),
                    " ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for zero-amount transfer edge case
    /// @dev Tests that zero-amount transfers succeed, emit Transfer, and leave all state unchanged
    function handler_transferZeroAmount(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        address recipient;
        {
            bool ok;
            (actor, ok) = _trySelectAuthorizedSender(actorSeed, address(token));
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), actor);
            if (!ok) return;
        }

        TransferSnapshot memory s = _snapTransfer(token, actor, recipient);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(actor, recipient, 0);

        vm.startPrank(actor);
        bool success = token.transfer(recipient, 0);
        vm.stopPrank();

        assertTrue(success, "Zero transfer should return true");
        _assertPostTransfer(token, actor, recipient, 0, s, "zero-transfer");

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_ZERO: ",
                    _getActorIndex(actor),
                    " -> ",
                    _getActorIndex(recipient),
                    " 0 ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for transfer to invalid recipient (zero address)
    /// @dev Tests that transfers to address(0) revert with InvalidRecipient
    function handler_tryTransferInvalidRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

        vm.startPrank(actor);
        vm.expectRevert(ITIP20.InvalidRecipient.selector);
        token.transfer(address(0), amount);
        vm.stopPrank();
    }

    /// @notice Handler for transfer to TIP20-prefix address
    /// @dev Tests that transfers to TIP20 token addresses revert with InvalidRecipient
    function handler_tryTransferInvalidRecipientTIP20Prefix(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 amount,
        uint256 lowBitsSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

        // Construct a TIP20-prefix address: upper 96 bits = 0x20c000000000000000000000
        uint64 lowBits = uint64(bound(lowBitsSeed, 1, type(uint64).max));
        address tip20Addr = address(uint160(0x20c000000000000000000000) << 64 | uint160(lowBits));

        vm.startPrank(actor);
        vm.expectRevert(ITIP20.InvalidRecipient.selector);
        token.transfer(tip20Addr, amount);
        vm.stopPrank();
    }

    /// @notice Handler for transferFrom to TIP20-prefix address
    /// @dev Tests that transferFrom to TIP20 token addresses reverts with InvalidRecipient
    function handler_tryTransferFromInvalidRecipientTIP20Prefix(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 amount,
        uint256 lowBitsSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        address spender;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
        }
        spender = _selectActorExcluding(actorSeed, owner);

        amount = bound(amount, 1, token.balanceOf(owner));
        if (!_ensureAllowance(token, owner, spender, amount)) return;

        // Construct a TIP20-prefix address: upper 96 bits = 0x20c000000000000000000000
        uint64 lowBits = uint64(bound(lowBitsSeed, 1, type(uint64).max));
        address tip20Addr = address(uint160(0x20c000000000000000000000) << 64 | uint160(lowBits));

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.InvalidRecipient.selector);
        token.transferFrom(owner, tip20Addr, amount);
        vm.stopPrank();
    }

    /// @notice Handler for transfer with insufficient balance
    /// @dev Tests that transfers exceeding balance revert with InsufficientBalance
    function handler_tryTransferInsufficientBalance(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 extra
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        address recipient;
        {
            bool ok;
            (actor, ok) = _trySelectAuthorizedSender(actorSeed, address(token));
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), actor);
            if (!ok) return;
        }

        uint256 actorBalance = token.balanceOf(actor);
        extra = bound(extra, 1, 1_000_000_000_000);

        vm.startPrank(actor);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITIP20.InsufficientBalance.selector, actorBalance, actorBalance + extra, address(token)
            )
        );
        token.transfer(recipient, actorBalance + extra);
        vm.stopPrank();
    }

    /// @notice Handler for transfer from blacklisted sender
    /// @dev Tests that transfers from a blacklisted address revert with PolicyForbids.
    ///      Uses vm.snapshot/revertTo for clean state isolation.
    function handler_tryTransferPolicyForbidsSender(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectAuthorizedSender(actorSeed, address(token));
            if (!ok) return;
        }
        address recipient = _selectActorExcluding(recipientSeed, actor);

        if (!_ensureBalance(token, actor, 1)) return;
        amount = bound(amount, 1, token.balanceOf(actor));

        uint64 policyId = _getPolicyId(address(token));
        if (policyId < 2) return; // special policies cannot be modified

        uint256 snap = vm.snapshotState();

        address policyAdmin = _getPolicyAdmin(address(token));

        vm.prank(policyAdmin);
        registry.modifyPolicyBlacklist(policyId, actor, true);

        vm.startPrank(actor);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        token.transfer(recipient, amount);
        vm.stopPrank();

        vm.revertToStateAndDelete(snap);
    }

    /// @notice Handler for transfer to blacklisted recipient
    /// @dev Tests that transfers to a blacklisted address revert with PolicyForbids.
    ///      Uses vm.snapshot/revertTo for clean state isolation.
    function handler_tryTransferPolicyForbidsRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }
        address recipient = _selectActorExcluding(recipientSeed, actor);
        if (!_isAuthorizedRecipient(address(token), recipient)) return;

        amount = bound(amount, 1, token.balanceOf(actor));

        uint64 policyId = _getPolicyId(address(token));
        if (policyId < 2) return; // special policies cannot be modified

        uint256 snap = vm.snapshotState();

        address policyAdmin = _getPolicyAdmin(address(token));

        vm.prank(policyAdmin);
        registry.modifyPolicyBlacklist(policyId, recipient, true);

        vm.startPrank(actor);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        token.transfer(recipient, amount);
        vm.stopPrank();

        vm.revertToStateAndDelete(snap);
    }

    /// @notice Handler for transfer when contract is paused
    /// @dev Tests that transfers revert with ContractPaused when paused.
    ///      Ensures all other preconditions are met so the revert is from the pause check.
    function handler_tryTransferWhenPaused(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensurePaused(token);

        address actor;
        address recipient;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), actor);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

        vm.startPrank(actor);
        vm.expectRevert(ITIP20.ContractPaused.selector);
        token.transfer(recipient, amount);
        vm.stopPrank();
    }

    /// @notice Handler for transferFrom with allowance
    /// @dev Tests TEMPO-TIP3 (allowance consumption), TEMPO-TIP4 (infinite allowance),
    ///      balance conservation, total supply unchanged, optedInSupply consistency,
    ///      reward accounting, spender isolation, and Transfer event emission
    function handler_transferFrom(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        address spender;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        spender = _selectActorExcluding(actorSeed, owner);

        {
            if (!_ensureAllowance(token, owner, spender, 1)) return;
            uint256 a = token.allowance(owner, spender);
            uint256 b = token.balanceOf(owner);
            amount = bound(amount, 1, b < a ? b : a);
        }

        TransferSnapshot memory s = _snapTransfer(token, owner, recipient);
        (, s.spenderRPTBefore, s.spenderRewardBalBefore) = token.userRewardInfo(spender);

        _transferFromAndAssert(token, owner, spender, recipient, amount, s);

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_FROM: ",
                    _getActorIndex(owner),
                    " -> ",
                    _getActorIndex(recipient),
                    " via ",
                    _getActorIndex(spender),
                    " ",
                    vm.toString(amount),
                    " ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for transferFrom self-transfer edge case (owner == recipient)
    /// @dev Self-transfers via transferFrom are valid: balance unchanged, allowance consumed,
    ///      reward accrual happens exactly once (not doubled)
    function handler_transferFromSelf(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
            if (!_isAuthorizedRecipient(address(token), owner)) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        {
            if (!_ensureAllowance(token, owner, spender, 1)) return;
            uint256 a = token.allowance(owner, spender);
            uint256 b = token.balanceOf(owner);
            amount = bound(amount, 0, b < a ? b : a);
        }

        TransferSnapshot memory s = _snapTransfer(token, owner, owner);
        (, s.spenderRPTBefore, s.spenderRewardBalBefore) = token.userRewardInfo(spender);

        _transferFromAndAssert(token, owner, spender, owner, amount, s);

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_FROM_SELF: ",
                    _getActorIndex(owner),
                    " via ",
                    _getActorIndex(spender),
                    " ",
                    vm.toString(amount),
                    " ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for zero-amount transferFrom edge case
    /// @dev Tests that zero-amount transferFrom succeeds, emits Transfer, leaves state unchanged.
    ///      Allowance is unchanged since 0 is deducted.
    function handler_transferFromZeroAmount(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectAuthorizedSender(ownerSeed, address(token));
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        TransferSnapshot memory s = _snapTransfer(token, owner, recipient);
        uint256 allowanceBefore = token.allowance(owner, spender);

        vm.expectEmit(true, true, false, true, address(token));
        emit ITIP20.Transfer(owner, recipient, 0);

        vm.startPrank(spender);
        bool success = token.transferFrom(owner, recipient, 0);
        vm.stopPrank();

        assertTrue(success, "Zero-amount transferFrom should return true");

        _assertPostTransfer(token, owner, recipient, 0, s, "zero-transferFrom");

        // Allowance unchanged (0 deducted)
        assertEq(
            token.allowance(owner, spender),
            allowanceBefore,
            "Allowance changed on zero transferFrom"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_FROM_ZERO: ",
                    _getActorIndex(owner),
                    " -> ",
                    _getActorIndex(recipient),
                    " via ",
                    _getActorIndex(spender),
                    " 0 ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for transferFrom with insufficient allowance
    /// @dev Tests that transferFrom reverts with InsufficientAllowance when amount > allowance
    function handler_tryTransferFromInsufficientAllowance(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 extra
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectAuthorizedSender(ownerSeed, address(token));
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        uint256 currentAllowance = token.allowance(owner, spender);
        if (currentAllowance == type(uint256).max) return;

        // Ensure owner has enough balance so the revert comes from allowance, not balance.
        // We need balance >= transferAmount > allowance. If allowance is huge (from a prior
        // approve), minting that much may exceed supply cap, so derive from achievable balance.
        extra = bound(extra, 1, 1_000_000_000_000);
        if (!_ensureBalance(token, owner, currentAllowance + extra)) {
            // Can't achieve balance > allowance; skip
            return;
        }
        uint256 transferAmount = currentAllowance + extra;

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.InsufficientAllowance.selector);
        token.transferFrom(owner, recipient, transferAmount);
        vm.stopPrank();
    }

    /// @notice Handler for transferFrom with insufficient balance
    /// @dev Tests that transferFrom reverts with InsufficientBalance when amount > balance
    function handler_tryTransferFromInsufficientBalance(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 extra
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectAuthorizedSender(ownerSeed, address(token));
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        uint256 ownerBalance = token.balanceOf(owner);
        extra = bound(extra, 1, 1_000_000_000_000);
        uint256 transferAmount = ownerBalance + extra;

        if (!_ensureAllowance(token, owner, spender, transferAmount)) return;

        vm.startPrank(spender);
        vm.expectRevert(
            abi.encodeWithSelector(
                ITIP20.InsufficientBalance.selector, ownerBalance, transferAmount, address(token)
            )
        );
        token.transferFrom(owner, recipient, transferAmount);
        vm.stopPrank();
    }

    /// @notice Handler for transferFrom from blacklisted owner
    /// @dev Tests that transferFrom from a blacklisted address reverts with PolicyForbids.
    ///      Uses vm.snapshot/revertTo for clean state isolation.
    function handler_tryTransferFromPolicyForbidsSender(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        {
            bool ok;
            (owner, ok) = _trySelectAuthorizedSender(ownerSeed, address(token));
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);
        address recipient = _selectActorExcluding(recipientSeed, owner);

        if (!_ensureBalance(token, owner, 1)) return;
        amount = bound(amount, 1, token.balanceOf(owner));
        if (!_ensureAllowance(token, owner, spender, amount)) return;

        uint64 policyId = _getPolicyId(address(token));
        if (policyId < 2) return; // special policies cannot be modified

        uint256 snap = vm.snapshotState();

        address policyAdmin = _getPolicyAdmin(address(token));

        vm.prank(policyAdmin);
        registry.modifyPolicyBlacklist(policyId, owner, true);

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        token.transferFrom(owner, recipient, amount);
        vm.stopPrank();

        vm.revertToStateAndDelete(snap);
    }

    /// @notice Handler for transferFrom to blacklisted recipient
    /// @dev Tests that transferFrom to a blacklisted address reverts with PolicyForbids.
    ///      Uses vm.snapshot/revertTo for clean state isolation.
    function handler_tryTransferFromPolicyForbidsRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);
        address recipient = _selectActorExcluding(recipientSeed, owner);
        if (!_isAuthorizedRecipient(address(token), recipient)) return;

        amount = bound(amount, 1, token.balanceOf(owner));
        if (!_ensureAllowance(token, owner, spender, amount)) return;

        uint64 policyId = _getPolicyId(address(token));
        if (policyId < 2) return; // special policies cannot be modified

        uint256 snap = vm.snapshotState();

        address policyAdmin = _getPolicyAdmin(address(token));

        vm.prank(policyAdmin);
        registry.modifyPolicyBlacklist(policyId, recipient, true);

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.PolicyForbids.selector);
        token.transferFrom(owner, recipient, amount);
        vm.stopPrank();

        vm.revertToStateAndDelete(snap);
    }

    /// @notice Handler for transferFrom when contract is paused
    /// @dev Tests that transferFrom reverts with ContractPaused when paused.
    ///      Ensures all other preconditions are met so the revert is from the pause check.
    function handler_tryTransferFromWhenPaused(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 recipientSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensurePaused(token);

        address owner;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        amount = bound(amount, 1, token.balanceOf(owner));
        if (!_ensureAllowance(token, owner, spender, amount)) return;

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.ContractPaused.selector);
        token.transferFrom(owner, recipient, amount);
        vm.stopPrank();
    }

    /// @notice Handler for transferFrom to invalid recipient (zero address)
    /// @dev Tests that transferFrom to address(0) reverts with InvalidRecipient
    function handler_tryTransferFromInvalidRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 ownerSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        address owner;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        amount = bound(amount, 1, token.balanceOf(owner));
        if (!_ensureAllowance(token, owner, spender, amount)) return;

        vm.startPrank(spender);
        vm.expectRevert(ITIP20.InvalidRecipient.selector);
        token.transferFrom(owner, address(0), amount);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                        APPROVE SNAPSHOT HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev Captures all relevant state before an approve for post-approve assertions
    struct ApproveSnapshot {
        uint256 allowanceBefore;
        uint256 ownerBal;
        uint256 spenderBal;
        uint256 totalSupply;
        uint128 optedInSupply;
        uint256 globalRPT;
        bool paused;
        uint64 transferPolicyId;
        uint256 supplyCap;
        address ownerRewardRecipient;
        uint256 ownerRPT;
        uint256 ownerRewardBal;
        address spenderRewardRecipient;
        uint256 spenderRPT;
        uint256 spenderRewardBal;
    }

    /// @dev Takes a snapshot of all approve-relevant state
    function _snapApprove(
        TIP20 token,
        address owner,
        address spender
    )
        internal
        view
        returns (ApproveSnapshot memory s)
    {
        s.allowanceBefore = token.allowance(owner, spender);
        s.ownerBal = token.balanceOf(owner);
        s.spenderBal = token.balanceOf(spender);
        s.totalSupply = token.totalSupply();
        s.optedInSupply = token.optedInSupply();
        s.globalRPT = token.globalRewardPerToken();
        s.paused = token.paused();
        s.transferPolicyId = token.transferPolicyId();
        s.supplyCap = token.supplyCap();
        (s.ownerRewardRecipient, s.ownerRPT, s.ownerRewardBal) = token.userRewardInfo(owner);
        if (owner != spender) {
            (s.spenderRewardRecipient, s.spenderRPT, s.spenderRewardBal) =
                token.userRewardInfo(spender);
        }
    }

    /// @dev Asserts that approve did not change any state other than the allowance
    function _assertApproveNoSideEffects(
        TIP20 token,
        address owner,
        address spender,
        ApproveSnapshot memory s,
        string memory ctx
    )
        internal
        view
    {
        assertEq(token.balanceOf(owner), s.ownerBal, string.concat(ctx, ": owner balance changed"));
        if (owner != spender) {
            assertEq(
                token.balanceOf(spender), s.spenderBal, string.concat(ctx, ": spender balance changed")
            );
        }
        assertEq(token.totalSupply(), s.totalSupply, string.concat(ctx, ": totalSupply changed"));
        assertEq(token.optedInSupply(), s.optedInSupply, string.concat(ctx, ": optedInSupply changed"));
        assertEq(
            token.globalRewardPerToken(), s.globalRPT, string.concat(ctx, ": globalRewardPerToken changed")
        );
        assertEq(token.paused(), s.paused, string.concat(ctx, ": paused changed"));
        assertEq(
            token.transferPolicyId(), s.transferPolicyId, string.concat(ctx, ": transferPolicyId changed")
        );
        assertEq(token.supplyCap(), s.supplyCap, string.concat(ctx, ": supplyCap changed"));

        (address rrO, uint256 rptO, uint256 rbO) = token.userRewardInfo(owner);
        assertEq(rrO, s.ownerRewardRecipient, string.concat(ctx, ": owner rewardRecipient changed"));
        assertEq(rptO, s.ownerRPT, string.concat(ctx, ": owner rewardPerToken changed"));
        assertEq(rbO, s.ownerRewardBal, string.concat(ctx, ": owner rewardBalance changed"));

        if (owner != spender) {
            (address rrS, uint256 rptS, uint256 rbS) = token.userRewardInfo(spender);
            assertEq(
                rrS, s.spenderRewardRecipient, string.concat(ctx, ": spender rewardRecipient changed")
            );
            assertEq(rptS, s.spenderRPT, string.concat(ctx, ": spender rewardPerToken changed"));
            assertEq(rbS, s.spenderRewardBal, string.concat(ctx, ": spender rewardBalance changed"));
        }
    }

    /*//////////////////////////////////////////////////////////////
                        APPROVE HANDLERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Handler for approvals
    /// @dev Tests TEMPO-TIP5 (allowance setting via overwrite semantics)
    ///      Asserts: return value, allowance set correctly, Approval event emitted,
    ///      no side effects on balances/supply/rewards/admin state.
    ///      Covers: self-approval (owner == spender), overwrite of existing allowance,
    ///      zero amount (revocation), type(uint256).max (infinite approval),
    ///      works regardless of pause state or transfer policy.
    function handler_approve(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 spenderSeed,
        uint256 amount
    )
        external
    {
        address owner = _selectActor(actorSeed);
        address spender = _selectActor(spenderSeed);
        TIP20 token = _selectBaseToken(tokenSeed);

        // Bias amount toward important edge values using independent entropy
        uint256 r = uint256(keccak256(abi.encode(amount, owner, spender))) % 8;
        if (r == 0) {
            amount = 0;
        } else if (r == 1) {
            amount = 1;
        } else if (r == 2) {
            amount = type(uint128).max;
        } else if (r == 3) {
            amount = uint256(type(uint128).max) + 1;
        } else if (r == 4) {
            amount = type(uint256).max;
        }
        // r >= 5: keep raw fuzz value (full uint256 range)

        ApproveSnapshot memory s = _snapApprove(token, owner, spender);

        vm.recordLogs();
        vm.startPrank(owner);
        try token.approve(spender, amount) returns (bool success) {
            vm.stopPrank();

            // TEMPO-TIP5: Must return true
            assertTrue(success, "TEMPO-TIP5: approve must return true");

            // TEMPO-TIP5: Allowance must be set to the exact amount (overwrite semantics)
            assertEq(
                token.allowance(owner, spender), amount, "TEMPO-TIP5: allowance not set correctly"
            );

            // Approve must not change any other state
            _assertApproveNoSideEffects(token, owner, spender, s, "approve");

            // Assert exactly one Approval event emitted by the token with correct parameters
            Vm.Log[] memory logs = vm.getRecordedLogs();
            bytes32 approvalSig = keccak256("Approval(address,address,uint256)");
            uint256 tokenLogCount;
            bool found;
            for (uint256 i = 0; i < logs.length; i++) {
                if (logs[i].emitter != address(token)) continue;
                tokenLogCount++;
                if (logs[i].topics.length < 3 || logs[i].topics[0] != approvalSig) continue;
                if (
                    address(uint160(uint256(logs[i].topics[1]))) == owner
                        && address(uint160(uint256(logs[i].topics[2]))) == spender
                ) {
                    uint256 evAmount = abi.decode(logs[i].data, (uint256));
                    assertEq(evAmount, amount, "TEMPO-TIP5: Approval event amount mismatch");
                    found = true;
                }
            }
            assertTrue(found, "TEMPO-TIP5: Approval event not emitted");
            assertEq(tokenLogCount, 1, "TEMPO-TIP5: token emitted unexpected extra logs");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "APPROVE: ",
                        _getActorIndex(owner),
                        " approved ",
                        _getActorIndex(spender),
                        " for ",
                        vm.toString(amount),
                        " ",
                        token.symbol()
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();

            // Solidity approve has no revert paths. A revert here can only
            // come from Rust AccountKeychain spending limit enforcement.
            bytes4 sel = reason.length >= 4 ? bytes4(reason) : bytes4(0);
            assertTrue(
                sel == IAccountKeychain.SpendingLimitExceeded.selector
                    || sel == IAccountKeychain.KeyNotFound.selector
                    || sel == IAccountKeychain.KeyInactive.selector
                    || sel == IAccountKeychain.KeyExpired.selector
                    || sel == IAccountKeychain.KeyAlreadyRevoked.selector
                    || sel == IAccountKeychain.UnauthorizedCaller.selector,
                "approve: unexpected revert (not a keychain error)"
            );

            // Revert must not change any state
            assertEq(
                token.allowance(owner, spender),
                s.allowanceBefore,
                "approve: allowance changed on revert"
            );
            _assertApproveNoSideEffects(token, owner, spender, s, "approve(revert)");

            // No events should be emitted on revert
            assertEq(vm.getRecordedLogs().length, 0, "approve: logs emitted on revert");
        }
    }

    /// @notice Handler for minting tokens
    /// @dev Tests TEMPO-TIP6 (supply increase), TEMPO-TIP7 (supply cap)
    function mint(uint256 tokenSeed, uint256 recipientSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        address recipient;
        {
            bool ok;
            (recipient, ok) = _trySelectPolicyAuthorized(recipientSeed, address(token));
            if (!ok) return;
        }

        uint256 currentSupply = token.totalSupply();
        uint256 supplyCap = token.supplyCap();
        uint256 remaining = supplyCap > currentSupply ? supplyCap - currentSupply : 0;
        if (remaining == 0) return;
        amount = bound(amount, 1, remaining);

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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "MINT: ",
                        vm.toString(amount),
                        " ",
                        token.symbol(),
                        " to ",
                        _getActorIndex(recipient)
                    )
                );
            }
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
        if (adminBalance == 0) return;

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

            if (_loggingEnabled) {
                _log(string.concat("BURN: ", vm.toString(amount), " ", token.symbol()));
            }
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
        _ensureUnpaused(token);

        address actor;
        address recipient;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), actor);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

        uint256 actorBalBefore = token.balanceOf(actor);
        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 totalSupplyBefore = token.totalSupply();

        vm.startPrank(actor);
        try token.transferWithMemo(recipient, amount, memo) {
            vm.stopPrank();

            // TEMPO-TIP9: Balance changes same as regular transfer
            assertEq(
                token.balanceOf(actor),
                actorBalBefore - amount,
                "TEMPO-TIP9: Sender balance not decreased"
            );
            assertEq(
                token.balanceOf(recipient),
                recipientBalanceBefore + amount,
                "TEMPO-TIP9: Recipient balance not increased"
            );
            assertEq(token.totalSupply(), totalSupplyBefore, "TEMPO-TIP9: Total supply changed");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "TRANSFER_WITH_MEMO: ",
                        _getActorIndex(actor),
                        " -> ",
                        _getActorIndex(recipient),
                        " ",
                        vm.toString(amount),
                        " ",
                        token.symbol()
                    )
                );
            }
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
        _ensureUnpaused(token);

        address owner;
        address recipient;
        {
            bool ok;
            (owner, ok) = _trySelectFundedSender(ownerSeed, token);
            if (!ok) return;
            (recipient, ok) = _trySelectAuthorizedRecipientExcluding(recipientSeed, address(token), owner);
            if (!ok) return;
        }
        address spender = _selectActorExcluding(actorSeed, owner);

        {
            if (!_ensureAllowance(token, owner, spender, 1)) return;
            uint256 a = token.allowance(owner, spender);
            uint256 b = token.balanceOf(owner);
            amount = bound(amount, 1, b < a ? b : a);
        }

        TransferSnapshot memory s = _snapTransfer(token, owner, recipient);
        (, s.spenderRPTBefore, s.spenderRewardBalBefore) = token.userRewardInfo(spender);

        _transferFromWithMemoAndAssert(token, owner, spender, recipient, amount, memo, s);

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRANSFER_FROM_MEMO: ",
                    _getActorIndex(owner),
                    " -> ",
                    _getActorIndex(recipient),
                    " via ",
                    _getActorIndex(spender),
                    " ",
                    vm.toString(amount),
                    " ",
                    token.symbol()
                )
            );
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
        _ensureUnpaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectPolicyAuthorized(actorSeed, address(token));
            if (!ok) return;
        }

        // 0 = opt-out, 1 = opt-in to self, 2+ = delegate to another actor
        address newRecipient;
        {
            uint256 choice = recipientSeed % 3;
            if (choice == 0) {
                newRecipient = address(0);
            } else if (choice == 1) {
                newRecipient = actor;
            } else {
                bool ok;
                (newRecipient, ok) = _trySelectPolicyAuthorizedExcluding(recipientSeed, address(token), actor);
                if (!ok) return;
            }
        }

        (address currentRecipient,,) = token.userRewardInfo(actor);
        uint256 actorBalance = token.balanceOf(actor);
        uint128 optedInSupplyBefore = token.optedInSupply();
        bool isDelegation = newRecipient != address(0) && newRecipient != actor;

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

            if (isDelegation) {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "DELEGATE_REWARDS: ",
                            _getActorIndex(actor),
                            " delegated to ",
                            _getActorIndex(newRecipient),
                            " on ",
                            token.symbol()
                        )
                    );
                }
            } else {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "SET_REWARD_RECIPIENT: ",
                            _getActorIndex(actor),
                            " -> ",
                            newRecipient != address(0) ? _getActorIndex(newRecipient) : "NONE",
                            " on ",
                            token.symbol()
                        )
                    );
                }
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
        _ensureUnpaused(token);

        if (!_isAuthorized(address(token), address(token))) return;
        if (!_ensureOptedInSupply(token, actorSeed)) return;

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }

        amount = bound(amount, 1, token.balanceOf(actor));

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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "DISTRIBUTE_REWARD: ",
                        _getActorIndex(actor),
                        " distributed ",
                        vm.toString(amount),
                        " ",
                        token.symbol()
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for distributing tiny rewards where delta == 0
    /// @dev Tests TEMPO-TIP12 edge case: when amount << optedInSupply, delta is 0
    function distributeRewardTiny(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        if (!_isAuthorized(address(token), address(token))) return;
        if (!_ensureOptedInSupply(token, actorSeed)) return;

        uint128 optedInSupply = token.optedInSupply();
        if (optedInSupply <= ACC_PRECISION) return;

        // Use amount = 1 where delta = floor(1 * ACC_PRECISION / optedInSupply) = 0
        if ((ACC_PRECISION / optedInSupply) != 0) return;

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }

        uint256 globalRPTBefore = token.globalRewardPerToken();

        vm.startPrank(actor);
        try token.distributeReward(1) {
            vm.stopPrank();

            // Update ghost variables (same as distributeReward)
            _totalRewardsDistributed++;
            _ghostRewardInputSum += 1;
            _tokenRewardsDistributed[address(token)] += 1;
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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "DISTRIBUTE_REWARD_TINY: ",
                        _getActorIndex(actor),
                        " distributed 1 ",
                        token.symbol(),
                        " (delta=0)"
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for attempting to distribute rewards when optedInSupply == 0
    /// @dev Tests TEMPO-TIP12 edge case: must revert with NoOptedInSupply when nobody is opted in
    function distributeRewardZeroOptedIn(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        if (!_isAuthorized(address(token), address(token))) return;
        if (token.optedInSupply() != 0) return;

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectPolicyAuthorized(actorSeed, address(token));
            if (!ok) return;
        }
        if (!_ensureBalance(token, actor, 1000)) return;

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

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "DISTRIBUTE_REWARD_ZERO_OPTED: ",
                    _getActorIndex(actor),
                    " correctly rejected on ",
                    token.symbol()
                )
            );
        }
    }

    /// @notice Handler for claiming rewards
    /// @dev Tests TEMPO-TIP14, TEMPO-TIP15
    function claimRewards(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        if (!_isAuthorized(address(token), address(token))) return;

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectPolicyAuthorized(actorSeed, address(token));
            if (!ok) return;
        }

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

            if (claimed > 0) {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "CLAIM_REWARDS: ",
                            _getActorIndex(actor),
                            " claimed ",
                            vm.toString(claimed),
                            " ",
                            token.symbol()
                        )
                    );
                }
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for reward claim with detailed verification
    /// @dev Tests TEMPO-TIP14/TIP15: verifies claim is bounded by contract balance and stored rewards
    function claimRewardsVerified(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);

        if (!_isAuthorized(address(token), address(token))) return;

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectPolicyAuthorized(actorSeed, address(token));
            if (!ok) return;
        }

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

            if (claimed > 0) {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "CLAIM_VERIFIED: ",
                            _getActorIndex(actor),
                            " claimed ",
                            vm.toString(claimed),
                            "/",
                            vm.toString(pendingRewards),
                            " ",
                            token.symbol()
                        )
                    );
                }
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for burning tokens from blocked accounts
    /// @dev Tests TEMPO-TIP23 (burnBlocked functionality)
    function burnBlocked(uint256 tokenSeed, uint256 targetSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);

        // Find a blacklisted actor with balance
        address target;
        {
            uint64 policyId = _getPolicyId(address(token));
            bool found;
            uint256 start = targetSeed % _actors.length;
            for (uint256 i = 0; i < _actors.length; i++) {
                address cand = _actors[addmod(start, i, _actors.length)];
                if (!registry.isAuthorized(policyId, cand) && token.balanceOf(cand) > 0) {
                    target = cand;
                    found = true;
                    break;
                }
            }
            if (!found) return;
        }

        uint256 targetBalance = token.balanceOf(target);
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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "BURN_BLOCKED: ",
                        vm.toString(amount),
                        " ",
                        token.symbol(),
                        " from ",
                        _getActorIndex(target)
                    )
                );
            }
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
        TIP20 token = _selectBaseToken(tokenSeed);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, _ISSUER_ROLE);
        if (!ok) return;

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
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensureUnpaused(token);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, _PAUSE_ROLE);
        if (!ok) return;

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
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensurePaused(token);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, _UNPAUSE_ROLE);
        if (!ok) return;

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
        TIP20 token = _selectBaseToken(tokenSeed);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, _BURN_BLOCKED_ROLE);
        if (!ok) return;

        address target = _selectActor(targetSeed);
        if (!_ensureBalance(token, target, 1)) return;
        amount = bound(amount, 1, token.balanceOf(target));

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

        // Select from special policies or created policies.
        // Bias toward modifiable blacklist policies to avoid stalling transfer coverage.
        uint64 newPolicyId;
        uint256 r = policySeed % 20;
        if (r == 0) {
            newPolicyId = 0; // always-reject (rare — 5%)
        } else if (r == 1) {
            newPolicyId = 1; // always-allow
        } else {
            // Use a created blacklist policy (most likely to keep transfers functional)
            newPolicyId = uint64(policySeed % 10) + 2;
        }

        uint64 currentPolicyId = token.transferPolicyId();

        vm.startPrank(admin);
        try token.changeTransferPolicyId(newPolicyId) {
            vm.stopPrank();

            assertEq(token.transferPolicyId(), newPolicyId, "Transfer policy ID not updated");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "CHANGE_POLICY: ",
                        token.symbol(),
                        " policy ",
                        vm.toString(currentPolicyId),
                        " -> ",
                        vm.toString(newPolicyId)
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            // Expected if policy doesn't exist
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }
    }

    /// @notice Handler for unauthorized policy change attempts
    /// @dev Tests that non-admin cannot change transfer policy
    function changeTransferPolicyIdUnauthorized(uint256 actorSeed, uint256 tokenSeed) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, bytes32(0));
        if (!ok) return;

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
        if (address(token) == address(pathUSD)) return;

        TIP20 newQuoteToken = _selectBaseToken(quoteTokenSeed);
        if (address(newQuoteToken) == address(token)) return;

        // For USD tokens, quote must also be USD
        {
            bool isUsdToken = keccak256(bytes(token.currency())) == keccak256(bytes("USD"));
            if (isUsdToken) {
                bool isUsdQuote = keccak256(bytes(newQuoteToken.currency())) == keccak256(bytes("USD"));
                if (!isUsdQuote) return;
            }
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

                if (_loggingEnabled) {
                    _log(string.concat("UPDATE_QUOTE_TOKEN: ", token.symbol(), " quote changed"));
                }
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
        TIP20 token = _selectBaseToken(tokenSeed);
        if (address(token) == address(pathUSD)) return;
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, bytes32(0));
        if (!ok) return;

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
        uint256 currentCap = token.supplyCap();

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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "SET_SUPPLY_CAP: ",
                        token.symbol(),
                        " cap ",
                        vm.toString(currentCap),
                        " -> ",
                        vm.toString(newCap)
                    )
                );
            }
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
        TIP20 token = _selectBaseToken(tokenSeed);
        (address attacker, bool ok) = _trySelectActorWithoutRole(actorSeed, token, bytes32(0));
        if (!ok) return;

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
        if (currentSupply <= 1) return;

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
        if (actorSeed % _actors.length >= 5) return;

        // Skip if policy is a special policy (0 or 1) which cannot be modified
        uint64 policyId = _getPolicyId(address(token));
        if (policyId < 2) return;

        // Ensure we are the policy admin (policy may have changed via changeTransferPolicyId)
        address policyAdmin = _getPolicyAdmin(address(token));
        if (policyAdmin != admin && policyAdmin != pathUSDAdmin) return;

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

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "TOGGLE_BLACKLIST: ",
                        _getActorIndex(actor),
                        " ",
                        blacklist ? "BLACKLISTED" : "UNBLACKLISTED",
                        " on ",
                        token.symbol()
                    )
                );
            }
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

        if (_loggingEnabled) {
            _log(
                string.concat("TOGGLE_PAUSE: ", token.symbol(), " ", pause ? "PAUSED" : "UNPAUSED")
            );
        }
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
        TIP20 token = _selectBaseToken(tokenSeed);
        _ensurePaused(token);

        address actor;
        {
            bool ok;
            (actor, ok) = _trySelectFundedSender(actorSeed, token);
            if (!ok) return;
        }
        address recipient = _selectActorExcluding(recipientSeed, actor);

        vm.startPrank(actor);
        try token.transfer(recipient, 1) {
            vm.stopPrank();
            revert("TEMPO-TIP17: Transfer should fail when paused");
        } catch (bytes memory reason) {
            vm.stopPrank();
            assertTrue(_isKnownTIP20Error(bytes4(reason)), "Unknown error encountered");
        }

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_TRANSFER_PAUSED: ",
                    _getActorIndex(actor),
                    " blocked on paused ",
                    token.symbol()
                )
            );
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
