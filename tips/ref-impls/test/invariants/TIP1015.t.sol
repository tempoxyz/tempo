// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";

/// @title TIP-1015 Compound Policy Invariant Tests
/// @notice Handler-based invariant tests for compound transfer policies as specified in TIP-1015
/// @dev Tests 6 invariants using Foundry's stateful fuzzing:
///      TEMPO-1015-1: Simple Policy Constraint - compound policies only reference simple policies
///      TEMPO-1015-2: Immutability - compound policies have no admin and cannot be modified
///      TEMPO-1015-3: Existence Check - createCompoundPolicy reverts for non-existent policies
///      TEMPO-1015-4: Delegation Correctness - simple policies have equivalent directional auth
///      TEMPO-1015-5: isAuthorized Equivalence - isAuthorized = sender && recipient
///      TEMPO-1015-6: Built-in Policy Compatibility - compound policies can reference policies 0/1
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

    function createCompoundPolicy(
        uint256 senderSeed,
        uint256 recipientSeed,
        uint256 mintSeed
    ) external {
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

            (ITIP403Registry.PolicyType ptype, address policyAdmin) = registry.policyData(compoundPid);
            assertEq(uint8(ptype), uint8(ITIP403Registry.PolicyType.COMPOUND), "TEMPO-1015-2: Type mismatch");
            assertEq(policyAdmin, address(0), "TEMPO-1015-2: Compound must have no admin");

            (uint64 storedS, uint64 storedR, uint64 storedM) = registry.compoundPolicyData(compoundPid);
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
        uint64 simplePid = _simplePolicies.length > 0
            ? _simplePolicies[seed % _simplePolicies.length]
            : 1;

        uint256 position = seed % 3;

        vm.startPrank(admin);

        if (position == 0) {
            vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
            registry.createCompoundPolicy(compoundRef, simplePid, simplePid);
        } else if (position == 1) {
            vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
            registry.createCompoundPolicy(simplePid, compoundRef, simplePid);
        } else {
            vm.expectRevert(ITIP403Registry.PolicyNotSimple.selector);
            registry.createCompoundPolicy(simplePid, simplePid, compoundRef);
        }

        vm.stopPrank();

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
        uint64 simplePid = _simplePolicies.length > 0
            ? _simplePolicies[seed % _simplePolicies.length]
            : 1;

        uint256 position = seed % 3;

        vm.startPrank(admin);

        if (position == 0) {
            vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistent));
            registry.createCompoundPolicy(nonExistent, simplePid, simplePid);
        } else if (position == 1) {
            vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistent));
            registry.createCompoundPolicy(simplePid, nonExistent, simplePid);
        } else {
            vm.expectRevert(abi.encodeWithSelector(ITIP403Registry.PolicyNotFound.selector, nonExistent));
            registry.createCompoundPolicy(simplePid, simplePid, nonExistent);
        }

        vm.stopPrank();

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

    function modifySimplePolicy(uint256 policySeed, uint256 accountSeed, bool add)
        external
       
    {
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

    function tryModifyCompoundPolicy(uint256 policySeed, uint256 accountSeed)
        external
       
    {
        if (_compoundPolicies.length == 0) return;

        uint64 pid = _compoundPolicies[policySeed % _compoundPolicies.length];
        address account = _selectActor(accountSeed);

        vm.expectRevert();
        registry.modifyPolicyWhitelist(pid, account, true);

        vm.expectRevert();
        registry.modifyPolicyBlacklist(pid, account, true);

        if (_loggingEnabled) {
            _log(
                string.concat(
                    "TRY_MODIFY_COMPOUND_POLICY: policy=",
                    vm.toString(pid),
                    " (correctly reverted)"
                )
            );
        }
    }

    function checkSimplePolicyEquivalence(uint256 policySeed, uint256 accountSeed)
        external
        view
       
    {
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
            isAuth,
            senderAuth && recipientAuth,
            "TEMPO-1015-5: isAuthorized != sender && recipient"
        );
    }

    function checkCompoundDelegation(uint256 policySeed, uint256 accountSeed)
        external
        view
       
    {
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

    function mintToAuthorizedRecipient(uint256 tokenSeed, uint256 recipientSeed, uint256 amount)
        external
       
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
            vm.expectRevert(ITIP20.PolicyForbids.selector);
            token.mint(recipient, amount);
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
            assertEq(uint8(ptype), uint8(ITIP403Registry.PolicyType.COMPOUND), "TEMPO-1015-2: Type should be COMPOUND");
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
                assertEq(isAuth, actualSender && actualRecipient, "TEMPO-1015-5: isAuthorized != sender && recipient");

                // TEMPO-1015-6: Delegation correctness
                bool expectedSender = registry.isAuthorized(senderPid, account);
                bool expectedRecipient = registry.isAuthorized(recipientPid, account);
                bool expectedMint = registry.isAuthorized(mintPid, account);

                assertEq(actualSender, expectedSender, "TEMPO-1015-6: Sender delegation mismatch");
                assertEq(actualRecipient, expectedRecipient, "TEMPO-1015-6: Recipient delegation mismatch");
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

}
