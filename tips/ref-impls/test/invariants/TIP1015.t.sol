// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { IStablecoinDEX } from "../../src/interfaces/IStablecoinDEX.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP-1015 Compound Policy Invariant Tests
/// @notice Handler-based invariant tests for compound transfer policies as specified in TIP-1015
/// @dev Tests 8 invariants using Foundry's stateful fuzzing:
///      TEMPO-1015-1: Simple Policy Constraint - compound policies only reference simple policies
///      TEMPO-1015-2: Immutability - compound policies have no admin and cannot be modified
///      TEMPO-1015-3: Existence Check - createCompoundPolicy reverts for non-existent policies
///      TEMPO-1015-4: Delegation Correctness - simple policies have equivalent directional auth
///      TEMPO-1015-5: isAuthorized Equivalence - isAuthorized = sender && recipient
///      TEMPO-1015-6: Built-in Policy Compatibility - compound policies can reference policies 0/1
///      TEMPO-1015-7: distributeReward requires both sender AND recipient authorization
///      TEMPO-1015-8: claimRewards uses correct directional authorization
contract TIP1015InvariantTest is InvariantBaseTest {

    /*//////////////////////////////////////////////////////////////
                              STATE
    //////////////////////////////////////////////////////////////*/

    string private constant LOG_FILE = "tip1015.log";

    uint64[] private _simplePolicies;
    uint64[] private _compoundPolicies;

    mapping(uint64 => ITIP403Registry.PolicyType) private _policyTypes;
    mapping(uint64 => uint64) private _compoundSenderPolicy;
    mapping(uint64 => uint64) private _compoundRecipientPolicy;
    mapping(uint64 => uint64) private _compoundMintPolicy;

    mapping(uint64 => mapping(address => bool)) private _ghostPolicySet;
    mapping(uint64 => address[]) private _policyAccounts;
    mapping(uint64 => mapping(address => bool)) private _policyAccountTracked;

    TIP20[] private _compoundTokens;
    mapping(address => uint64) private _tokenPolicy;

    uint256 private _totalCompoundPoliciesCreated;

    /*//////////////////////////////////////////////////////////////
                              SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();

        targetContract(address(this));
        _setupInvariantBase();

        _actors = _buildActors(10);

        vm.startPrank(admin);

        for (uint256 i = 0; i < 4; i++) {
            ITIP403Registry.PolicyType ptype = i % 2 == 0
                ? ITIP403Registry.PolicyType.WHITELIST
                : ITIP403Registry.PolicyType.BLACKLIST;
            uint64 pid = registry.createPolicy(admin, ptype);
            _simplePolicies.push(pid);
            _policyTypes[pid] = ptype;
        }

        vm.stopPrank();

        _initLogFile(LOG_FILE, "TIP-1015 Compound Policy Invariant Test Log");
    }

    /*//////////////////////////////////////////////////////////////
                            FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    function createSimplePolicy(uint256 actorSeed, bool isWhitelist) external {
        address actor = _selectActor(actorSeed);
        ITIP403Registry.PolicyType ptype = isWhitelist
            ? ITIP403Registry.PolicyType.WHITELIST
            : ITIP403Registry.PolicyType.BLACKLIST;

        vm.startPrank(actor);
        uint64 pid = registry.createPolicy(actor, ptype);
        vm.stopPrank();

        _simplePolicies.push(pid);
        _policyTypes[pid] = ptype;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "CREATE_SIMPLE_POLICY: ",
                    _getActorIndex(actor),
                    " created policy ",
                    vm.toString(pid),
                    " type=",
                    isWhitelist ? "WHITELIST" : "BLACKLIST"
                )
            );
        }
    }

    function createCompoundPolicy(uint256 senderSeed, uint256 recipientSeed, uint256 mintSeed)
        external
    {
        if (_simplePolicies.length < 3) return;

        uint64 sPid = _selectSimplePolicy(senderSeed);
        uint64 rPid = _selectSimplePolicy(recipientSeed);
        uint64 mPid = _selectSimplePolicy(mintSeed);

        vm.startPrank(admin);
        try registry.createCompoundPolicy(sPid, rPid, mPid) returns (uint64 compoundPid) {
            vm.stopPrank();

            _compoundPolicies.push(compoundPid);
            _policyTypes[compoundPid] = ITIP403Registry.PolicyType.COMPOUND;
            _compoundSenderPolicy[compoundPid] = sPid;
            _compoundRecipientPolicy[compoundPid] = rPid;
            _compoundMintPolicy[compoundPid] = mPid;
            _totalCompoundPoliciesCreated++;

            (ITIP403Registry.PolicyType ptype, address policyAdmin) =
                registry.policyData(compoundPid);
            assertEq(
                uint8(ptype),
                uint8(ITIP403Registry.PolicyType.COMPOUND),
                "TEMPO-1015-2: Type mismatch"
            );
            assertEq(policyAdmin, address(0), "TEMPO-1015-2: Compound must have no admin");

            (uint64 storedS, uint64 storedR, uint64 storedM) =
                registry.compoundPolicyData(compoundPid);
            assertEq(storedS, sPid, "Sender policy mismatch");
            assertEq(storedR, rPid, "Recipient policy mismatch");
            assertEq(storedM, mPid, "MintRecipient policy mismatch");

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "CREATE_COMPOUND_POLICY: compound=",
                        vm.toString(compoundPid),
                        " sender=",
                        vm.toString(sPid),
                        " recipient=",
                        vm.toString(rPid),
                        " mint=",
                        vm.toString(mPid)
                    )
                );
            }
        } catch (bytes memory reason) {
            vm.stopPrank();
            _assertKnownRegistryRevert(reason);
        }
    }

    function createCompoundWithBuiltins(uint256 seed) external {
        uint64 alwaysReject = 0;
        uint64 alwaysAllow = 1;

        uint64 sPid = seed % 2 == 0 ? alwaysAllow : alwaysReject;
        uint64 rPid = (seed >> 8) % 2 == 0 ? alwaysAllow : alwaysReject;
        uint64 mPid = (seed >> 16) % 2 == 0 ? alwaysAllow : alwaysReject;

        vm.startPrank(admin);
        uint64 compoundPid = registry.createCompoundPolicy(sPid, rPid, mPid);
        vm.stopPrank();

        _compoundPolicies.push(compoundPid);
        _policyTypes[compoundPid] = ITIP403Registry.PolicyType.COMPOUND;
        _compoundSenderPolicy[compoundPid] = sPid;
        _compoundRecipientPolicy[compoundPid] = rPid;
        _compoundMintPolicy[compoundPid] = mPid;
        _totalCompoundPoliciesCreated++;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "CREATE_COMPOUND_WITH_BUILTINS: compound=",
                    vm.toString(compoundPid),
                    " sender=",
                    vm.toString(sPid),
                    " recipient=",
                    vm.toString(rPid),
                    " mint=",
                    vm.toString(mPid)
                )
            );
        }
    }

    function tryCreateCompoundWithCompound(uint256 seed) external {
        if (_compoundPolicies.length == 0) return;

        uint64 compoundRef = _compoundPolicies[seed % _compoundPolicies.length];
        uint64 simplePid =
            _simplePolicies.length > 0 ? _simplePolicies[seed % _simplePolicies.length] : 1;

        uint256 position = seed % 3;

        vm.startPrank(admin);

        bool reverted;
        bytes4 errorSelector;

        if (position == 0) {
            try registry.createCompoundPolicy(compoundRef, simplePid, simplePid) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                errorSelector = bytes4(reason);
            }
        } else if (position == 1) {
            try registry.createCompoundPolicy(simplePid, compoundRef, simplePid) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                errorSelector = bytes4(reason);
            }
        } else {
            try registry.createCompoundPolicy(simplePid, simplePid, compoundRef) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                errorSelector = bytes4(reason);
            }
        }

        vm.stopPrank();

        assertTrue(reverted, "TEMPO-1015-1: Should revert with compound in compound");
        assertEq(
            errorSelector, ITIP403Registry.PolicyNotSimple.selector, "TEMPO-1015-1: Wrong error"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_CREATE_COMPOUND_WITH_COMPOUND: position=",
                    vm.toString(position),
                    " compoundRef=",
                    vm.toString(compoundRef),
                    " (correctly reverted)"
                )
            );
        }
    }

    function tryCreateCompoundWithNonExistent(uint256 seed) external {
        uint64 counter = registry.policyIdCounter();
        uint64 nonExistent = counter + uint64(bound(seed, 1, 1000));
        uint64 simplePid =
            _simplePolicies.length > 0 ? _simplePolicies[seed % _simplePolicies.length] : 1;

        uint256 position = seed % 3;

        vm.startPrank(admin);

        bool reverted;
        bytes memory revertReason;

        if (position == 0) {
            try registry.createCompoundPolicy(nonExistent, simplePid, simplePid) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                revertReason = reason;
            }
        } else if (position == 1) {
            try registry.createCompoundPolicy(simplePid, nonExistent, simplePid) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                revertReason = reason;
            }
        } else {
            try registry.createCompoundPolicy(simplePid, simplePid, nonExistent) returns (uint64) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                revertReason = reason;
            }
        }

        vm.stopPrank();

        assertTrue(reverted, "TEMPO-1015-3: Should revert for non-existent policy");
        assertEq(
            bytes4(revertReason),
            ITIP403Registry.PolicyNotFound.selector,
            "TEMPO-1015-3: Wrong error selector"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_CREATE_COMPOUND_WITH_NONEXISTENT: position=",
                    vm.toString(position),
                    " nonExistent=",
                    vm.toString(nonExistent),
                    " (correctly reverted)"
                )
            );
        }
    }

    function modifySimplePolicy(uint256 policySeed, uint256 accountSeed, bool add) external {
        if (_simplePolicies.length == 0) return;

        uint64 pid = _simplePolicies[policySeed % _simplePolicies.length];
        address account = _selectActor(accountSeed);

        (ITIP403Registry.PolicyType ptype, address policyAdmin) = registry.policyData(pid);

        vm.startPrank(policyAdmin);

        if (ptype == ITIP403Registry.PolicyType.WHITELIST) {
            registry.modifyPolicyWhitelist(pid, account, add);
        } else {
            registry.modifyPolicyBlacklist(pid, account, add);
        }

        vm.stopPrank();

        _ghostPolicySet[pid][account] = add;
        if (!_policyAccountTracked[pid][account]) {
            _policyAccountTracked[pid][account] = true;
            _policyAccounts[pid].push(account);
        }

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "MODIFY_SIMPLE_POLICY: policy=",
                    vm.toString(pid),
                    " account=",
                    _getActorIndex(account),
                    " add=",
                    add ? "true" : "false"
                )
            );
        }
    }

    function tryModifyCompoundPolicy(uint256 policySeed, uint256 accountSeed) external {
        if (_compoundPolicies.length == 0) return;

        uint64 pid = _compoundPolicies[policySeed % _compoundPolicies.length];
        address account = _selectActor(accountSeed);

        bool whitelistReverted;
        try registry.modifyPolicyWhitelist(pid, account, true) {
            whitelistReverted = false;
        } catch {
            whitelistReverted = true;
        }
        assertTrue(
            whitelistReverted, "TEMPO-1015-2: modifyPolicyWhitelist should revert for compound"
        );

        bool blacklistReverted;
        try registry.modifyPolicyBlacklist(pid, account, true) {
            blacklistReverted = false;
        } catch {
            blacklistReverted = true;
        }
        assertTrue(
            blacklistReverted, "TEMPO-1015-2: modifyPolicyBlacklist should revert for compound"
        );

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_MODIFY_COMPOUND_POLICY: policy=", vm.toString(pid), " (correctly reverted)"
                )
            );
        }
    }

    function checkSimplePolicyEquivalence(uint256 policySeed, uint256 accountSeed) external view {
        if (_simplePolicies.length == 0) return;

        uint64 pid = _simplePolicies[policySeed % _simplePolicies.length];
        address account = _selectActor(accountSeed);

        bool senderAuth = registry.isAuthorizedSender(pid, account);
        bool recipientAuth = registry.isAuthorizedRecipient(pid, account);
        bool mintAuth = registry.isAuthorizedMintRecipient(pid, account);

        assertEq(senderAuth, recipientAuth, "TEMPO-1015-4: Sender != Recipient for simple");
        assertEq(recipientAuth, mintAuth, "TEMPO-1015-4: Recipient != Mint for simple");
    }

    function checkCompoundIsAuthorizedEquivalence(uint256 policySeed, uint256 accountSeed)
        external
        view
    {
        if (_compoundPolicies.length == 0) return;

        uint64 pid = _compoundPolicies[policySeed % _compoundPolicies.length];
        address account = _selectActor(accountSeed);

        bool senderAuth = registry.isAuthorizedSender(pid, account);
        bool recipientAuth = registry.isAuthorizedRecipient(pid, account);
        bool isAuth = registry.isAuthorized(pid, account);

        assertEq(
            isAuth, senderAuth && recipientAuth, "TEMPO-1015-5: isAuthorized != sender && recipient"
        );
    }

    function checkCompoundDelegation(uint256 policySeed, uint256 accountSeed) external view {
        if (_compoundPolicies.length == 0) return;

        uint64 pid = _compoundPolicies[policySeed % _compoundPolicies.length];
        address account = _selectActor(accountSeed);

        uint64 senderPid = _compoundSenderPolicy[pid];
        uint64 recipientPid = _compoundRecipientPolicy[pid];
        uint64 mintPid = _compoundMintPolicy[pid];

        bool expectedSender = registry.isAuthorized(senderPid, account);
        bool expectedRecipient = registry.isAuthorized(recipientPid, account);
        bool expectedMint = registry.isAuthorized(mintPid, account);

        bool actualSender = registry.isAuthorizedSender(pid, account);
        bool actualRecipient = registry.isAuthorizedRecipient(pid, account);
        bool actualMint = registry.isAuthorizedMintRecipient(pid, account);

        assertEq(actualSender, expectedSender, "Compound sender delegation broken");
        assertEq(actualRecipient, expectedRecipient, "Compound recipient delegation broken");
        assertEq(actualMint, expectedMint, "Compound mint delegation broken");
    }

    function createTokenWithCompoundPolicy(uint256 policySeed) external {
        if (_compoundPolicies.length == 0) return;

        uint64 pid = _compoundPolicies[policySeed % _compoundPolicies.length];

        vm.startPrank(admin);

        TIP20 token = TIP20(
            factory.createToken(
                "CMPTKN",
                "CT",
                "USD",
                pathUSD,
                admin,
                keccak256(abi.encode(pid, _compoundTokens.length))
            )
        );
        token.grantRole(_ISSUER_ROLE, admin);
        token.grantRole(_BURN_BLOCKED_ROLE, admin);
        token.changeTransferPolicyId(pid);

        vm.stopPrank();

        _compoundTokens.push(token);
        _tokenPolicy[address(token)] = pid;

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "CREATE_TOKEN_WITH_COMPOUND: token=",
                    vm.toString(address(token)),
                    " policy=",
                    vm.toString(pid)
                )
            );
        }
    }

    /// @notice Opt an actor into rewards - critical for testing reward distribution/claim flows
    function optIntoRewards(uint256 tokenSeed, uint256 actorSeed) external {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address actor = _selectActor(actorSeed);

        // Need sender + recipient auth to opt in
        bool senderAuth = registry.isAuthorizedSender(pid, actor);
        bool recipientAuth = registry.isAuthorizedRecipient(pid, actor);
        if (!senderAuth || !recipientAuth) return;

        // Ensure actor has balance (required for opt-in to matter)
        if (token.balanceOf(actor) == 0) {
            if (!registry.isAuthorizedMintRecipient(pid, actor)) return;
            vm.prank(admin);
            try token.mint(actor, 10_000) { }
            catch {
                return;
            }
        }

        vm.prank(actor);
        try token.setRewardRecipient(actor) { } catch { }
    }

    function mintToAuthorizedRecipient(uint256 tokenSeed, uint256 recipientSeed, uint256 amount)
        public
    {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address recipient = _selectActor(recipientSeed);

        amount = bound(amount, 1, 1_000_000);

        bool authorized = registry.isAuthorizedMintRecipient(pid, recipient);

        vm.startPrank(admin);

        if (authorized) {
            token.mint(recipient, amount);
            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "MINT: recipient=",
                        _getActorIndex(recipient),
                        " amount=",
                        vm.toString(amount),
                        " (authorized)"
                    )
                );
            }
        } else {
            bool reverted;
            bytes4 errorSelector;
            try token.mint(recipient, amount) {
                reverted = false;
            } catch (bytes memory reason) {
                reverted = true;
                errorSelector = bytes4(reason);
            }
            assertTrue(reverted, "Mint should revert for unauthorized recipient");
            assertEq(
                errorSelector, ITIP20.PolicyForbids.selector, "Wrong error for unauthorized mint"
            );

            if (_loggingEnabled) {
                _log(
                    string.concat(
                        "MINT: recipient=",
                        _getActorIndex(recipient),
                        " (unauthorized, correctly reverted)"
                    )
                );
            }
        }

        vm.stopPrank();
    }

    /// @notice Transfer with compound policy uses senderPolicyId and recipientPolicyId
    function transferWithCompoundPolicy(
        uint256 tokenSeed,
        uint256 senderSeed,
        uint256 recipientSeed,
        uint256 amount
    ) external {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address sender = _selectActor(senderSeed);
        address recipient = _selectActorExcluding(recipientSeed, sender);

        amount = bound(amount, 1, 1_000_000);

        // Ensure sender has sufficient balance
        if (token.balanceOf(sender) < amount) {
            mintToAuthorizedRecipient(tokenSeed, senderSeed, amount);
        }
        if (token.balanceOf(sender) < amount) return;

        bool senderAuth = registry.isAuthorizedSender(pid, sender);
        bool recipientAuth = registry.isAuthorizedRecipient(pid, recipient);

        vm.prank(sender);
        if (senderAuth && recipientAuth) {
            token.transfer(recipient, amount);
        } else {
            try token.transfer(recipient, amount) {
                revert("Transfer should revert for unauthorized sender/recipient");
            } catch (bytes memory reason) {
                assertEq(bytes4(reason), ITIP20.PolicyForbids.selector, "Wrong error for transfer");
            }
        }
    }

    /// @notice burnBlocked uses senderPolicyId to check if address is blocked
    function burnBlockedWithCompoundPolicy(uint256 tokenSeed, uint256 targetSeed, uint256 amount)
        external
    {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address target = _selectActor(targetSeed);

        amount = bound(amount, 1, 1_000_000);

        // Ensure target has sufficient balance
        if (token.balanceOf(target) < amount) {
            mintToAuthorizedRecipient(tokenSeed, targetSeed, amount);
        }
        if (token.balanceOf(target) < amount) return;

        bool senderAuth = registry.isAuthorizedSender(pid, target);

        vm.startPrank(admin);
        token.grantRole(_BURN_BLOCKED_ROLE, admin);

        if (!senderAuth) {
            uint256 supplyBefore = token.totalSupply();
            token.burnBlocked(target, amount);
            assertEq(token.totalSupply(), supplyBefore - amount, "Supply not decreased");
        } else {
            try token.burnBlocked(target, amount) {
                revert("burnBlocked should revert for authorized sender");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason), ITIP20.PolicyForbids.selector, "Wrong error for burnBlocked"
                );
            }
        }
        vm.stopPrank();
    }

    /// @notice TEMPO-1015-7: distributeReward requires both sender AND recipient authorization
    /// @dev Sender must be authorized to send, contract must be authorized to receive
    function distributeRewardWithCompoundPolicy(
        uint256 tokenSeed,
        uint256 senderSeed,
        uint256 amount
    ) external {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address sender = _selectActor(senderSeed);

        amount = bound(amount, 1, 10_000);

        // Skip if sender is not authorized to receive mints (can't get balance)
        if (!registry.isAuthorizedMintRecipient(pid, sender)) return;

        // Ensure sender has sufficient balance - mint extra to avoid underflow
        uint256 senderBalance = token.balanceOf(sender);
        if (senderBalance < amount + 1000) {
            vm.startPrank(admin);
            try token.mint(sender, amount + 1000) { }
            catch {
                vm.stopPrank();
                return;
            }
            vm.stopPrank();
        }
        senderBalance = token.balanceOf(sender);
        if (senderBalance < amount) return;

        // Need at least one opted-in holder for distributeReward to work
        // Use a different actor to opt-in (use XOR to avoid overflow)
        address optedInHolder = _selectActorExcluding(senderSeed ^ 0x1234, sender);
        if (registry.isAuthorizedMintRecipient(pid, optedInHolder)) {
            if (token.balanceOf(optedInHolder) == 0) {
                vm.startPrank(admin);
                try token.mint(optedInHolder, 1000) { } catch { }
                vm.stopPrank();
            }
            if (token.balanceOf(optedInHolder) > 0) {
                // Check if can opt in (needs sender + recipient auth for setRewardRecipient)
                if (
                    registry.isAuthorizedSender(pid, optedInHolder)
                        && registry.isAuthorizedRecipient(pid, optedInHolder)
                ) {
                    vm.prank(optedInHolder);
                    try token.setRewardRecipient(optedInHolder) { } catch { }
                }
            }
        }

        // Skip if no opted-in supply
        if (token.optedInSupply() == 0) return;

        // Occasionally test with deauthorized sender to hit unauthorized branch (40% chance)
        uint64 senderPid = _compoundSenderPolicy[pid];
        bool shouldTestUnauthorized = (senderSeed % 5 < 2) && senderPid >= 2;
        bool wasAuthorized = false;

        if (shouldTestUnauthorized) {
            wasAuthorized = registry.isAuthorizedSender(pid, sender);
            if (wasAuthorized) {
                _authorize(senderPid, sender, false);
            }
        }

        bool senderAuth = registry.isAuthorizedSender(pid, sender);
        bool contractRecipientAuth = registry.isAuthorizedRecipient(pid, address(token));

        vm.prank(sender);
        if (senderAuth && contractRecipientAuth) {
            try token.distributeReward(amount) {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "DISTRIBUTE_REWARD: sender=",
                            _getActorIndex(sender),
                            " amount=",
                            vm.toString(amount),
                            " (authorized)"
                        )
                    );
                }
            } catch {
                // Can fail for other reasons (e.g., zero optedInSupply race)
            }
        } else {
            try token.distributeReward(amount) {
                revert("TEMPO-1015-7: distributeReward should revert for unauthorized");
            } catch (bytes memory reason) {
                // May revert for other reasons too, only check if it's PolicyForbids
                if (bytes4(reason) == ITIP20.PolicyForbids.selector) {
                    if (_loggingEnabled) {
                        _log(
                            string.concat(
                                "DISTRIBUTE_REWARD: sender=",
                                _getActorIndex(sender),
                                " senderAuth=",
                                senderAuth ? "true" : "false",
                                " contractRecipientAuth=",
                                contractRecipientAuth ? "true" : "false",
                                " (correctly reverted)"
                            )
                        );
                    }
                }
            }
        }

        // Restore authorization if we deauthorized for testing
        if (shouldTestUnauthorized && wasAuthorized) {
            _authorize(senderPid, sender, true);
        }
    }

    /// @notice TEMPO-1015-8: claimRewards uses correct directional authorization
    /// @dev Contract must be authorized to send, claimer must be authorized to receive
    function claimRewardsWithCompoundPolicy(uint256 tokenSeed, uint256 claimerSeed) external {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = _tokenPolicy[address(token)];
        address claimer = _selectActor(claimerSeed);

        // Skip if claimer can't receive mints
        if (!registry.isAuthorizedMintRecipient(pid, claimer)) return;

        // Claimer must opt-in first and have some rewards to claim
        // First ensure claimer has balance
        if (token.balanceOf(claimer) == 0) {
            vm.startPrank(admin);
            try token.mint(claimer, 1000) { }
            catch {
                vm.stopPrank();
                return;
            }
            vm.stopPrank();
        }
        if (token.balanceOf(claimer) == 0) return;

        // Check if claimer is opted in, if not try to opt in
        // setRewardRecipient requires sender + recipient auth
        (address rewardRecipient,,) = token.userRewardInfo(claimer);
        if (rewardRecipient == address(0)) {
            if (
                !registry.isAuthorizedSender(pid, claimer)
                    || !registry.isAuthorizedRecipient(pid, claimer)
            ) {
                return; // Can't opt in due to policy
            }
            vm.prank(claimer);
            try token.setRewardRecipient(claimer) { }
            catch {
                return; // Can't opt in, skip
            }
        }

        // Skip if no opted-in supply
        if (token.optedInSupply() == 0) return;

        // Occasionally test with deauthorized claimer to hit unauthorized branch (20% chance)
        uint64 recipientPid = _compoundRecipientPolicy[pid];
        bool shouldTestUnauthorized = (claimerSeed % 5 == 0) && recipientPid >= 2;
        bool wasAuthorized = false;

        if (shouldTestUnauthorized) {
            wasAuthorized = registry.isAuthorizedRecipient(pid, claimer);
            if (wasAuthorized) {
                _authorize(recipientPid, claimer, false);
            }
        }

        bool contractSenderAuth = registry.isAuthorizedSender(pid, address(token));
        bool claimerRecipientAuth = registry.isAuthorizedRecipient(pid, claimer);

        vm.prank(claimer);
        if (contractSenderAuth && claimerRecipientAuth) {
            try token.claimRewards() {
                if (_loggingEnabled) {
                    _log(
                        string.concat(
                            "CLAIM_REWARDS: claimer=", _getActorIndex(claimer), " (authorized)"
                        )
                    );
                }
            } catch {
                // Can fail for other reasons
            }
        } else {
            try token.claimRewards() {
                revert("TEMPO-1015-8: claimRewards should revert for unauthorized");
            } catch (bytes memory reason) {
                // May revert for other reasons too, only check if it's PolicyForbids
                if (bytes4(reason) == ITIP20.PolicyForbids.selector) {
                    if (_loggingEnabled) {
                        _log(
                            string.concat(
                                "CLAIM_REWARDS: claimer=",
                                _getActorIndex(claimer),
                                " contractSenderAuth=",
                                contractSenderAuth ? "true" : "false",
                                " claimerRecipientAuth=",
                                claimerRecipientAuth ? "true" : "false",
                                " (correctly reverted)"
                            )
                        );
                    }
                }
            }
        }

        // Restore authorization if we deauthorized for testing
        if (shouldTestUnauthorized && wasAuthorized) {
            _authorize(recipientPid, claimer, true);
        }
    }

    /// @notice DEX cancelStaleOrder uses senderPolicyId to check if maker is blocked
    /// @dev Only tests ask orders - for bids, DEX checks quote token (pathUSD) policy
    function cancelStaleOrderWithCompoundPolicy(
        uint256 tokenSeed,
        uint256 makerSeed,
        uint256 cancellerSeed
    ) external {
        if (_compoundTokens.length == 0) return;

        TIP20 token = _compoundTokens[tokenSeed % _compoundTokens.length];
        uint64 pid = token.transferPolicyId();
        (uint64 senderPid, uint64 recipientPid, uint64 mintPid) = registry.compoundPolicyData(pid);

        // Skip always-reject (0) - we need modifiable policies, but always-allow (1) is fine
        if (senderPid == 0 || recipientPid == 0 || mintPid == 0) return;

        address maker = _selectActor(makerSeed);
        address canceller = _selectActorExcluding(cancellerSeed, maker);
        uint128 amount = 102_000_000; // 1.02 * MIN_ORDER_AMOUNT for tick price buffer

        // Cache original policy states
        bool cachedMakerSender = registry.isAuthorizedSender(pid, maker);
        bool cachedMakerRecipient = registry.isAuthorizedRecipient(pid, maker);
        bool cachedMakerMint = registry.isAuthorizedMintRecipient(pid, maker);
        bool cachedDexSender = registry.isAuthorizedSender(pid, address(exchange));
        bool cachedDexRecipient = registry.isAuthorizedRecipient(pid, address(exchange));
        bool cachedMakerPathUsdMint = registry.isAuthorizedMintRecipient(_pathUsdPolicyId, maker);

        // Temporarily authorize in all policies to allow order placement
        if (!cachedMakerSender) _authorize(senderPid, maker, true);
        if (!cachedMakerRecipient) _authorize(recipientPid, maker, true);
        if (!cachedMakerMint) _authorize(mintPid, maker, true);
        if (!cachedMakerPathUsdMint) _authorize(_pathUsdPolicyId, maker, true);
        if (!cachedDexSender) _authorize(senderPid, address(exchange), true);
        if (!cachedDexRecipient) _authorize(recipientPid, address(exchange), true);

        // Create pair if needed
        vm.startPrank(admin);
        try exchange.createPair(address(token)) { } catch { }
        token.grantRole(_ISSUER_ROLE, admin);

        // Mint tokens to maker
        token.mint(maker, amount);
        pathUSD.mint(maker, amount);
        vm.stopPrank();

        // Place order
        // Place ask order (isBid=false) - DEX checks base token's senderPolicy for asks
        vm.startPrank(maker);
        token.approve(address(exchange), type(uint256).max);
        pathUSD.approve(address(exchange), type(uint256).max);
        uint128 orderId = exchange.place(address(token), amount, false, int16(20));
        vm.stopPrank();

        // Restore original policy states for maker only
        // Note: We don't restore DEX authorization - leaving DEX authorized doesn't break invariants
        // and avoids complex state tracking across shared sub-policies
        if (!cachedMakerSender) _authorize(senderPid, maker, false);
        if (!cachedMakerRecipient) _authorize(recipientPid, maker, false);
        if (!cachedMakerMint) _authorize(mintPid, maker, false);
        if (!cachedMakerPathUsdMint) _authorize(_pathUsdPolicyId, maker, false);

        // Occasionally deauthorize maker to hit blocked branch (40% chance)
        bool shouldTestBlocked = (makerSeed % 5 < 2) && senderPid >= 2;
        bool wasAuthorizedForBlock = false;

        if (shouldTestBlocked) {
            wasAuthorizedForBlock = registry.isAuthorizedSender(pid, maker);
            if (wasAuthorizedForBlock) {
                _authorize(senderPid, maker, false);
            }
        }

        // Now test cancelStaleOrder
        bool senderAuth = registry.isAuthorizedSender(pid, maker);

        vm.prank(canceller);
        if (!senderAuth) {
            exchange.cancelStaleOrder(orderId);
        } else {
            try exchange.cancelStaleOrder(orderId) {
                revert("cancelStaleOrder should revert for authorized maker");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IStablecoinDEX.OrderNotStale.selector,
                    "Wrong error for cancelStaleOrder"
                );
            }
        }

        // Restore authorization if we deauthorized for testing
        if (shouldTestBlocked && wasAuthorizedForBlock) {
            _authorize(senderPid, maker, true);
        }
    }

    /// @dev Helper to authorize/deauthorize account based on policy type
    function _authorize(uint64 policyId, address account, bool authorize) internal {
        if (policyId < 2) return; // Skip builtins
        (ITIP403Registry.PolicyType ptype, address policyAdmin) = registry.policyData(policyId);

        vm.startPrank(policyAdmin);
        if (ptype == ITIP403Registry.PolicyType.WHITELIST) {
            registry.modifyPolicyWhitelist(policyId, account, authorize);
        } else if (ptype == ITIP403Registry.PolicyType.BLACKLIST) {
            registry.modifyPolicyBlacklist(policyId, account, !authorize);
        }
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                         GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Combined invariant check - single loop through compound policies
    /// @dev Checks TEMPO-1015-2, TEMPO-1015-3, TEMPO-1015-5, TEMPO-1015-6 in one pass
    function invariant_globalInvariants() public view {
        _invariantSimplePolicyEquivalence();
        _invariantCompoundPoliciesCombined();
    }

    /// @dev TEMPO-1015-4: Simple policy equivalence - all directional auth functions return same value
    function _invariantSimplePolicyEquivalence() internal view {
        for (uint256 i = 0; i < _simplePolicies.length; i++) {
            uint64 pid = _simplePolicies[i];

            for (uint256 j = 0; j < _actors.length; j++) {
                address account = _actors[j];

                bool senderAuth = registry.isAuthorizedSender(pid, account);
                bool recipientAuth = registry.isAuthorizedRecipient(pid, account);
                bool mintAuth = registry.isAuthorizedMintRecipient(pid, account);

                assertEq(senderAuth, recipientAuth, "TEMPO-1015-4: Sender != Recipient");
                assertEq(recipientAuth, mintAuth, "TEMPO-1015-4: Recipient != Mint");
            }
        }
    }

    /// @dev Combined compound policy invariants - single loop checks:
    ///      TEMPO-1015-2: Immutability (type=COMPOUND, admin=0)
    ///      TEMPO-1015-3: Existence (policyExists returns true)
    ///      TEMPO-1015-5: isAuthorized = sender && recipient
    ///      TEMPO-1015-6: Delegation correctness
    function _invariantCompoundPoliciesCombined() internal view {
        for (uint256 i = 0; i < _compoundPolicies.length; i++) {
            uint64 pid = _compoundPolicies[i];

            // TEMPO-1015-3: Existence
            assertTrue(registry.policyExists(pid), "TEMPO-1015-3: Compound policy should exist");

            // TEMPO-1015-2: Immutability
            (ITIP403Registry.PolicyType ptype, address policyAdmin) = registry.policyData(pid);
            assertEq(
                uint8(ptype),
                uint8(ITIP403Registry.PolicyType.COMPOUND),
                "TEMPO-1015-2: Type should be COMPOUND"
            );
            assertEq(policyAdmin, address(0), "TEMPO-1015-2: Compound should have no admin");

            // Get sub-policies for delegation check
            uint64 senderPid = _compoundSenderPolicy[pid];
            uint64 recipientPid = _compoundRecipientPolicy[pid];
            uint64 mintPid = _compoundMintPolicy[pid];

            // Check all actors for TEMPO-1015-5 and TEMPO-1015-6
            for (uint256 j = 0; j < _actors.length; j++) {
                address account = _actors[j];

                bool actualSender = registry.isAuthorizedSender(pid, account);
                bool actualRecipient = registry.isAuthorizedRecipient(pid, account);
                bool actualMint = registry.isAuthorizedMintRecipient(pid, account);
                bool isAuth = registry.isAuthorized(pid, account);

                // TEMPO-1015-5: isAuthorized equivalence
                assertEq(
                    isAuth,
                    actualSender && actualRecipient,
                    "TEMPO-1015-5: isAuthorized != sender && recipient"
                );

                // TEMPO-1015-6: Delegation correctness
                bool expectedSender = registry.isAuthorized(senderPid, account);
                bool expectedRecipient = registry.isAuthorized(recipientPid, account);
                bool expectedMint = registry.isAuthorized(mintPid, account);

                assertEq(actualSender, expectedSender, "TEMPO-1015-6: Sender delegation mismatch");
                assertEq(
                    actualRecipient,
                    expectedRecipient,
                    "TEMPO-1015-6: Recipient delegation mismatch"
                );
                assertEq(actualMint, expectedMint, "TEMPO-1015-6: Mint delegation mismatch");
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                            HELPERS
    //////////////////////////////////////////////////////////////*/

    function _selectSimplePolicy(uint256 seed) internal view returns (uint64) {
        if (seed % 4 == 0) {
            return uint64(seed % 2);
        }
        return _simplePolicies[seed % _simplePolicies.length];
    }

    /*//////////////////////////////////////////////////////////////
                         DEBUG TEST
    //////////////////////////////////////////////////////////////*/

    /// @notice Reproduce exact failure case from invariant test
    function test_debugCancelStaleOrder() public {
        // Full sequence from failure
        this.createCompoundPolicy(
            40_146_768_666_470_591_288_466_911_002_501_495_605_974_772_490_515_831_968_758_688_164_918_013_896_771,
            1_881_666_673_669_373_799_574_385_455_517_466_765_151_316_784_746_389_933_119_316_841_213,
            183_494_902_547
        );
        this.createCompoundPolicy(
            23_588_147_900,
            37_600_582_443_196_186_754_263,
            177_289_021_393_573_700_694_057_871_859_357_188_285_772_652_827_948_214_985_572_261_305_846_255
        );
        this.createCompoundWithBuiltins(
            12_682_145_792_537_745_889_008_897_362_953_153_928_823_602_948_197_597_710_284_864_067_148_923_443_545
        );
        this.createCompoundWithBuiltins(8_204_912_707_026_222_929_993_648_814_990_631_487_527_516);
        this.createCompoundWithBuiltins(86_400);
        this.createCompoundWithBuiltins(15_806_843_813_925);
        this.createCompoundWithBuiltins(3_627_873);
        this.createCompoundPolicy(98_000, 1609, 128);
        this.createCompoundWithBuiltins(40_704);
        this.createCompoundWithBuiltins(76_540_973_584_718_233_635_329_213_503_135_674);
        this.createCompoundWithBuiltins(67_771_880_847);
        this.createCompoundWithBuiltins(29);
        this.createCompoundPolicy(
            44_172_541_173_081_406_189_036_225_624_124_066_257_091,
            115_792_089_237_316_195_423_570_985_008_687_907_853_269_984_665_640_564_039_457_584_007_913_129_639_933,
            1_274_785_353_851_877_832_320_239_800_422_796_560_778_225_101
        );
        this.createCompoundPolicy(
            6_050_371,
            2_866_076_699_040_129_585_745_194_515_303_195_934_739_708_415_431_910_362_438,
            2_026_154_340_968_570_463_286_171_109_674_026_194_671
        );
        this.createCompoundPolicy(3803, 4144, 9217);
        this.createCompoundPolicy(14_707, 1_000_000_000_000, 13_520);
        this.createSimplePolicy(1_814_478_140_341, true);
        this.createCompoundPolicy(
            4_829_602_596_148_722_693_864_290,
            863_406_761_782_549_020_671_270_317_021_783_900_374_275_151_710_601_687_344_864_082_439_363_934,
            5_900_857_876_373_900_092_548_860_506_117_377_883_276_434_917_390
        );
        this.createCompoundPolicy(16_538, 2787, 1024);
        this.createCompoundWithBuiltins(734_909_486_155_771_638);
        this.createCompoundPolicy(1000, 3, 102_000_000);
        this.createCompoundWithBuiltins(86_400);
        this.createSimplePolicy(3419, true);
        this.createCompoundWithBuiltins(441);
        this.createCompoundPolicy(
            9_928_368_277_730_969_577_776_484_779_711_653_591_287_188_860_223_700_328_444_723_565_047_526_986_159,
            606_983_657_455_066_788_779_915_939_933_531_225_919_187_657_378_407_792_306_311_029_088,
            559_566_233_903_447_733
        );
        this.createCompoundWithBuiltins(8_031_225_649_463_389_431_459_072_435_135_521);
        this.createCompoundPolicy(
            2_740_680_062_706_222_617_640_726_483_586_529_120_663_175_539_104_490_898_662_066_226,
            2,
            286_210_428_856_067_613_313_425_952_111
        );
        this.createTokenWithCompoundPolicy(
            1_442_795_299_312_553_038_441_356_441_254_559_307_351_227_213_265_778_295_552_262_787_923_449
        );
        this.cancelStaleOrderWithCompoundPolicy(
            176_330_312_160_789_598_509_252_851_577,
            63_222_939_885_621_963_159_082_200_988_494_049_364_061_294_388_899_558,
            3_783_560_614_102_001_382_765_846_522_756_205_262_344_865_442_837
        );

        // Run invariant check
        invariant_globalInvariants();
    }

}
