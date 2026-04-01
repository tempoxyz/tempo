// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { TIP20 } from "../../src/TIP20.sol";
import { TempoUtilities as Tempo } from "../../src/TempoUtilities.sol";
import { IAddressRegistry } from "../../src/interfaces/IAddressRegistry.sol";
import { ITIP20 } from "../../src/interfaces/ITIP20.sol";
import { ITIP403Registry } from "../../src/interfaces/ITIP403Registry.sol";
import { InvariantBaseTest } from "./InvariantBaseTest.t.sol";
import { Vm } from "forge-std/Vm.sol";

/// @title TIP-1022 Virtual Address Invariant Tests
/// @notice Stateful invariant coverage for deterministic virtual-address forwarding fixtures
/// @dev Tests TEMPO-VA1 through TEMPO-VA16 using fixed anvil masters and pre-mined salts
/// forge-config: default.hardfork = "tempo:T3"
contract VirtualAddressesInvariantTest is InvariantBaseTest {

    struct MasterFixture {
        address master;
        uint256 pk;
        bytes32 salt;
        bytes4 masterId;
    }

    struct BalanceSnapshot {
        uint256 fromBalance;
        uint256 masterBalance;
        uint256 virtualBalance;
        uint256 totalSupply;
        uint256 allowance;
    }

    string internal constant ANVIL_MNEMONIC =
        "test test test test test test test test test test test junk";
    uint256 internal constant MASTER_COUNT = 8;
    uint256 internal constant TAG_COUNT = 16;
    uint256 internal constant INITIAL_MASTER_BALANCE = 1_000_000_000_000;
    uint256 internal constant MAX_HANDLER_AMOUNT = 1_000_000_000;
    uint80 internal constant VIRTUAL_MAGIC = 0xFDFDFDFDFDFDFDFDFDFD;

    bytes32[MASTER_COUNT] internal POW_SALTS = [
        bytes32(uint256(0xabf52baf)),
        bytes32(uint256(0x0213f67626)),
        bytes32(uint256(0x490a6a7e)),
        bytes32(uint256(0xe9380f73)),
        bytes32(uint256(0xbf34bdba)),
        bytes32(uint256(0x011e93c2f3)),
        bytes32(uint256(0x01bf66b590)),
        // Second salt for master index 0 (same address, different masterId 0x66937001).
        // Exercises the spec's many-to-one property: "The same address MAY register
        // multiple masterIds using different salts."
        bytes32(uint256(0x10e1ea97a))
    ];

    bytes6[TAG_COUNT] internal USER_TAGS = [
        bytes6(uint48(1)),
        bytes6(uint48(2)),
        bytes6(uint48(3)),
        bytes6(uint48(4)),
        bytes6(uint48(5)),
        bytes6(uint48(6)),
        bytes6(uint48(7)),
        bytes6(uint48(8)),
        bytes6(uint48(9)),
        bytes6(uint48(10)),
        bytes6(uint48(11)),
        bytes6(uint48(12)),
        bytes6(uint48(13)),
        bytes6(uint48(14)),
        bytes6(uint48(15)),
        bytes6(uint48(16))
    ];

    MasterFixture[] internal _masters;
    address[] internal _virtualPool;
    address[] internal _nonVirtualPool;

    mapping(bytes4 => address) internal _masterById;
    mapping(address => bytes4) internal _masterIdByVirtual;
    mapping(address => address) internal _virtualToMaster;
    mapping(address => bytes6) internal _virtualToTag;
    mapping(address => bool) internal _virtualTracked;
    mapping(address => uint64) internal _recipientPolicyIds;
    mapping(address => uint64) internal _mintPolicyIds;

    uint64 internal _policyRejectWhitelistId;
    uint64 internal _policyRejectBlacklistId;

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        _setupInvariantBase();
        _configureVirtualPolicies();
        (_actors,) = _buildActors(20);

        _registerVirtualMasters();
        _buildVirtualPool();
        _seedMasterBalances();
        _buildNonVirtualPool();
    }

    /*//////////////////////////////////////////////////////////////
                              FUZZ HANDLERS
    //////////////////////////////////////////////////////////////*/

    function transferToVirtual(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address sender = _selectActor(actorSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];

        _setTransferAllowed(token, master, true);
        _ensureFunds(sender, token, MAX_HANDLER_AMOUNT);

        uint256 senderBalanceBefore = token.balanceOf(sender);
        uint256 masterBalanceBefore = token.balanceOf(master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _boundedAmount(senderBalanceBefore));

        vm.recordLogs();
        vm.prank(sender);
        bool success = token.transfer(virtualAddr, amount);

        assertTrue(success, "TEMPO-VA7: transfer should succeed");
        assertEq(token.balanceOf(sender), senderBalanceBefore - amount, "TEMPO-VA7: sender debit");
        assertEq(token.balanceOf(master), masterBalanceBefore + amount, "TEMPO-VA7: master credit");
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance");
        assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA7: transfer supply change");

        _assertTransferSequence(token, sender, virtualAddr, master, amount);
    }

    function transferFromToVirtual(
        uint256 ownerSeed,
        uint256 spenderSeed,
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 approvalSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address owner = _selectActor(ownerSeed);
        address spender = _selectActorExcluding(spenderSeed, owner);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];
        BalanceSnapshot memory snapshot;

        _setTransferAllowed(token, master, true);
        _ensureFunds(owner, token, MAX_HANDLER_AMOUNT);

        snapshot = _snapshot(token, owner, master, virtualAddr);

        uint256 approvalAmount = approvalSeed % 2 == 0
            ? type(uint256).max
            : bound(approvalSeed, 1, _boundedAmount(snapshot.fromBalance));

        vm.prank(owner);
        token.approve(spender, approvalAmount);

        snapshot.allowance = token.allowance(owner, spender);
        amount = bound(amount, 1, _maxTransferFromAmount(snapshot));

        vm.recordLogs();
        vm.prank(spender);
        bool success = token.transferFrom(owner, virtualAddr, amount);

        assertTrue(success, "TEMPO-VA8: transferFrom should succeed");
        assertEq(token.balanceOf(owner), snapshot.fromBalance - amount, "TEMPO-VA8: owner debit");
        assertEq(
            token.balanceOf(master), snapshot.masterBalance + amount, "TEMPO-VA8: master credit"
        );
        assertEq(
            token.balanceOf(virtualAddr), snapshot.virtualBalance, "TEMPO-VA10: virtual balance"
        );
        assertEq(token.totalSupply(), snapshot.totalSupply, "TEMPO-VA8: transferFrom supply change");

        if (snapshot.allowance == type(uint256).max) {
            assertEq(
                token.allowance(owner, spender),
                type(uint256).max,
                "TEMPO-VA8: infinite allowance changed"
            );
        } else {
            assertEq(
                token.allowance(owner, spender),
                snapshot.allowance - amount,
                "TEMPO-VA8: allowance not reduced"
            );
        }

        _assertTransferSequence(token, owner, virtualAddr, master, amount);
    }

    function transferWithMemoToVirtual(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 amount,
        bytes32 memo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address sender = _selectActor(actorSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];

        _setTransferAllowed(token, master, true);
        _ensureFunds(sender, token, MAX_HANDLER_AMOUNT);

        uint256 senderBalanceBefore = token.balanceOf(sender);
        uint256 masterBalanceBefore = token.balanceOf(master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _boundedAmount(senderBalanceBefore));

        vm.recordLogs();
        vm.prank(sender);
        token.transferWithMemo(virtualAddr, amount, memo);

        assertEq(token.balanceOf(sender), senderBalanceBefore - amount, "TEMPO-VA7: sender debit");
        assertEq(token.balanceOf(master), masterBalanceBefore + amount, "TEMPO-VA7: master credit");
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance");
        assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA7: transferWithMemo supply change");

        _assertTransferWithMemoSequence(token, sender, virtualAddr, master, amount, memo);
    }

    function transferFromWithMemoToVirtual(
        uint256 ownerSeed,
        uint256 spenderSeed,
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 approvalSeed,
        uint256 amount,
        bytes32 memo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address owner = _selectActor(ownerSeed);
        address spender = _selectActorExcluding(spenderSeed, owner);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];
        BalanceSnapshot memory snapshot;

        _setTransferAllowed(token, master, true);
        _ensureFunds(owner, token, MAX_HANDLER_AMOUNT);

        snapshot = _snapshot(token, owner, master, virtualAddr);

        uint256 approvalAmount = approvalSeed % 2 == 0
            ? type(uint256).max
            : bound(approvalSeed, 1, _boundedAmount(snapshot.fromBalance));

        vm.prank(owner);
        token.approve(spender, approvalAmount);

        snapshot.allowance = token.allowance(owner, spender);
        amount = bound(amount, 1, _maxTransferFromAmount(snapshot));

        vm.recordLogs();
        vm.prank(spender);
        bool success = token.transferFromWithMemo(owner, virtualAddr, amount, memo);

        assertTrue(success, "TEMPO-VA8: transferFromWithMemo should succeed");
        assertEq(token.balanceOf(owner), snapshot.fromBalance - amount, "TEMPO-VA8: owner debit");
        assertEq(
            token.balanceOf(master), snapshot.masterBalance + amount, "TEMPO-VA8: master credit"
        );
        assertEq(
            token.balanceOf(virtualAddr), snapshot.virtualBalance, "TEMPO-VA10: virtual balance"
        );
        assertEq(
            token.totalSupply(), snapshot.totalSupply, "TEMPO-VA8: transferFromWithMemo supply"
        );

        if (snapshot.allowance == type(uint256).max) {
            assertEq(
                token.allowance(owner, spender),
                type(uint256).max,
                "TEMPO-VA8: infinite allowance changed"
            );
        } else {
            assertEq(
                token.allowance(owner, spender),
                snapshot.allowance - amount,
                "TEMPO-VA8: allowance not reduced"
            );
        }

        _assertTransferWithMemoSequence(token, owner, virtualAddr, master, amount, memo);
    }

    function mintToVirtual(uint256 tokenSeed, uint256 virtualSeed, uint256 amount) external {
        TIP20 token = _selectBaseToken(tokenSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];

        _setMintAllowed(token, master, true);

        uint256 masterBalanceBefore = token.balanceOf(master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _mintableAmount(token));

        vm.recordLogs();
        vm.prank(admin);
        token.mint(virtualAddr, amount);

        assertEq(token.balanceOf(master), masterBalanceBefore + amount, "TEMPO-VA9: master credit");
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance");
        assertEq(token.totalSupply(), supplyBefore + amount, "TEMPO-VA9: supply increase");

        _assertMintSequence(token, virtualAddr, master, amount);
    }

    function mintWithMemoToVirtual(
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 amount,
        bytes32 memo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];

        _setMintAllowed(token, master, true);

        uint256 masterBalanceBefore = token.balanceOf(master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _mintableAmount(token));

        vm.recordLogs();
        vm.prank(admin);
        token.mintWithMemo(virtualAddr, amount, memo);

        assertEq(token.balanceOf(master), masterBalanceBefore + amount, "TEMPO-VA9: master credit");
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance");
        assertEq(token.totalSupply(), supplyBefore + amount, "TEMPO-VA9: supply increase");

        _assertMintWithMemoSequence(token, virtualAddr, master, amount, memo);
    }

    function transferToUnregisteredVirtual(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 masterSeed,
        uint256 tagSeed,
        uint256 amount,
        bytes32 memo,
        bool useMemo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address sender = _selectActor(actorSeed);
        (address virtualAddr,) = _selectUnregisteredVirtual(masterSeed, tagSeed);

        _ensureFunds(sender, token, MAX_HANDLER_AMOUNT);

        uint256 senderBalanceBefore = token.balanceOf(sender);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _boundedAmount(senderBalanceBefore));

        vm.recordLogs();
        vm.prank(sender);
        if (useMemo) {
            try token.transferWithMemo(virtualAddr, amount, memo) {
                revert("TEMPO-VA6: unregistered transferWithMemo unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered transferWithMemo error"
                );
            }
        } else {
            try token.transfer(virtualAddr, amount) returns (bool) {
                revert("TEMPO-VA6: unregistered transfer unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered transfer error"
                );
            }
        }

        assertEq(token.balanceOf(sender), senderBalanceBefore, "TEMPO-VA6: sender changed");
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA6: alias changed");
        assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA6: supply changed");

        _assertNoRelevantTokenLogs(token, "TEMPO-VA6: transfer emitted token logs");
    }

    function transferFromToUnregisteredVirtual(
        uint256 ownerSeed,
        uint256 spenderSeed,
        uint256 tokenSeed,
        uint256 masterSeed,
        uint256 tagSeed,
        uint256 approvalSeed,
        uint256 amount,
        bytes32 memo,
        bool useMemo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address owner = _selectActor(ownerSeed);
        address spender = _selectActorExcluding(spenderSeed, owner);
        (address virtualAddr,) = _selectUnregisteredVirtual(masterSeed, tagSeed);
        BalanceSnapshot memory snapshot;

        _ensureFunds(owner, token, MAX_HANDLER_AMOUNT);

        snapshot.fromBalance = token.balanceOf(owner);
        snapshot.virtualBalance = token.balanceOf(virtualAddr);
        snapshot.totalSupply = token.totalSupply();
        uint256 approvalAmount = approvalSeed % 2 == 0
            ? type(uint256).max
            : bound(approvalSeed, 1, _boundedAmount(snapshot.fromBalance));

        vm.prank(owner);
        token.approve(spender, approvalAmount);

        snapshot.allowance = token.allowance(owner, spender);
        amount = bound(amount, 1, _maxTransferFromAmount(snapshot));

        vm.recordLogs();
        vm.prank(spender);
        if (useMemo) {
            try token.transferFromWithMemo(owner, virtualAddr, amount, memo) returns (bool) {
                revert("TEMPO-VA6: unregistered transferFromWithMemo unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered transferFromWithMemo error"
                );
            }
        } else {
            try token.transferFrom(owner, virtualAddr, amount) returns (bool) {
                revert("TEMPO-VA6: unregistered transferFrom unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered transferFrom error"
                );
            }
        }

        assertEq(token.balanceOf(owner), snapshot.fromBalance, "TEMPO-VA6: owner changed");
        assertEq(token.balanceOf(virtualAddr), snapshot.virtualBalance, "TEMPO-VA6: alias changed");
        assertEq(token.totalSupply(), snapshot.totalSupply, "TEMPO-VA6: supply changed");
        assertEq(
            token.allowance(owner, spender), snapshot.allowance, "TEMPO-VA6: allowance changed"
        );

        _assertNoRelevantTokenLogs(token, "TEMPO-VA6: transferFrom emitted token logs");
    }

    function mintToUnregisteredVirtual(
        uint256 tokenSeed,
        uint256 masterSeed,
        uint256 tagSeed,
        uint256 amount,
        bytes32 memo,
        bool useMemo
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        (address virtualAddr,) = _selectUnregisteredVirtual(masterSeed, tagSeed);

        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();
        amount = bound(amount, 1, _mintableAmount(token));

        vm.recordLogs();
        vm.prank(admin);
        if (useMemo) {
            try token.mintWithMemo(virtualAddr, amount, memo) {
                revert("TEMPO-VA6: unregistered mintWithMemo unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered mintWithMemo error"
                );
            }
        } else {
            try token.mint(virtualAddr, amount) {
                revert("TEMPO-VA6: unregistered mint unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    IAddressRegistry.VirtualAddressUnregistered.selector,
                    "TEMPO-VA6: wrong unregistered mint error"
                );
            }
        }

        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA6: alias changed");
        assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA6: supply changed");

        _assertNoRelevantTokenLogs(token, "TEMPO-VA6: mint emitted token logs");
    }

    function selfForward(
        uint256 tokenSeed,
        uint256 masterSeed,
        uint256 tagSeed,
        uint256 amount
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        uint256 masterIndex = masterSeed % MASTER_COUNT;
        MasterFixture memory fixture = _masters[masterIndex];
        address virtualAddr = _virtualForMaster(masterIndex, tagSeed);

        _setTransferAllowed(token, fixture.master, true);

        uint256 masterBalanceBefore = token.balanceOf(fixture.master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _boundedAmount(masterBalanceBefore));

        vm.recordLogs();
        vm.prank(fixture.master);
        bool success = token.transfer(virtualAddr, amount);

        assertTrue(success, "TEMPO-VA13: self-forward should succeed");
        assertEq(
            token.balanceOf(fixture.master), masterBalanceBefore, "TEMPO-VA13: net balance changed"
        );
        assertEq(token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance");
        assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA13: supply changed");

        _assertTransferSequence(token, fixture.master, virtualAddr, fixture.master, amount);
    }

    function policyOnMasterTransfer(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 amount,
        bool allowMaster
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address sender = _selectActor(actorSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];
        BalanceSnapshot memory snapshot;

        _setTransferAllowed(token, master, allowMaster);
        _setMintAllowed(token, master, true);
        _ensureFunds(sender, token, MAX_HANDLER_AMOUNT);

        snapshot = _snapshot(token, sender, master, virtualAddr);

        amount = bound(amount, 1, _boundedAmount(snapshot.fromBalance));

        vm.recordLogs();
        vm.prank(sender);
        if (allowMaster) {
            bool success = token.transfer(virtualAddr, amount);
            assertTrue(success, "TEMPO-VA14: transfer should succeed for allowed master");
            assertEq(
                token.balanceOf(sender), snapshot.fromBalance - amount, "TEMPO-VA14: sender debit"
            );
            assertEq(
                token.balanceOf(master),
                snapshot.masterBalance + amount,
                "TEMPO-VA14: master credit"
            );
            assertEq(
                token.balanceOf(virtualAddr), snapshot.virtualBalance, "TEMPO-VA10: virtual balance"
            );
            assertEq(token.totalSupply(), snapshot.totalSupply, "TEMPO-VA14: supply change");
            _assertTransferSequence(token, sender, virtualAddr, master, amount);
        } else {
            try token.transfer(virtualAddr, amount) returns (bool) {
                revert("TEMPO-VA14: blocked master transfer unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    ITIP20.PolicyForbids.selector,
                    "TEMPO-VA14: blocked transfer wrong error"
                );
            }

            assertEq(token.balanceOf(sender), snapshot.fromBalance, "TEMPO-VA14: sender changed");
            assertEq(token.balanceOf(master), snapshot.masterBalance, "TEMPO-VA14: master changed");
            assertEq(
                token.balanceOf(virtualAddr), snapshot.virtualBalance, "TEMPO-VA10: virtual balance"
            );
            assertEq(token.totalSupply(), snapshot.totalSupply, "TEMPO-VA14: supply changed");
            _assertNoRelevantTokenLogs(token, "TEMPO-VA14: blocked transfer emitted logs");
        }
    }

    function policyOnMasterMint(
        uint256 tokenSeed,
        uint256 virtualSeed,
        uint256 amount,
        bool allowMaster
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address virtualAddr = _selectVirtual(virtualSeed);
        address master = _virtualToMaster[virtualAddr];

        _setTransferAllowed(token, master, true);
        _setMintAllowed(token, master, allowMaster);

        uint256 masterBalanceBefore = token.balanceOf(master);
        uint256 virtualBalanceBefore = token.balanceOf(virtualAddr);
        uint256 supplyBefore = token.totalSupply();

        amount = bound(amount, 1, _mintableAmount(token));

        vm.recordLogs();
        vm.prank(admin);
        if (allowMaster) {
            token.mint(virtualAddr, amount);

            assertEq(
                token.balanceOf(master), masterBalanceBefore + amount, "TEMPO-VA14: master credit"
            );
            assertEq(
                token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance"
            );
            assertEq(token.totalSupply(), supplyBefore + amount, "TEMPO-VA14: supply increase");
            _assertMintSequence(token, virtualAddr, master, amount);
        } else {
            try token.mint(virtualAddr, amount) {
                revert("TEMPO-VA14: blocked master mint unexpectedly succeeded");
            } catch (bytes memory reason) {
                assertEq(
                    bytes4(reason),
                    ITIP20.PolicyForbids.selector,
                    "TEMPO-VA14: blocked mint wrong error"
                );
            }

            assertEq(token.balanceOf(master), masterBalanceBefore, "TEMPO-VA14: master changed");
            assertEq(
                token.balanceOf(virtualAddr), virtualBalanceBefore, "TEMPO-VA10: virtual balance"
            );
            assertEq(token.totalSupply(), supplyBefore, "TEMPO-VA14: supply changed");
            _assertNoRelevantTokenLogs(token, "TEMPO-VA14: blocked mint emitted logs");
        }
    }

    function rejectVirtualInPolicyOperations(
        uint256 virtualSeed,
        uint256 actorSeed,
        bool useBlacklist
    )
        external
    {
        address virtualAddr = _selectVirtual(virtualSeed);
        address actor = _selectActor(actorSeed);
        address[] memory accounts = new address[](2);
        accounts[0] = actor;
        accounts[1] = virtualAddr;

        uint64 counterBefore = registry.policyIdCounter();
        bool whitelistAuthBefore = registry.isAuthorized(_policyRejectWhitelistId, virtualAddr);
        bool blacklistAuthBefore = registry.isAuthorized(_policyRejectBlacklistId, virtualAddr);

        vm.recordLogs();
        vm.startPrank(admin);

        try registry.createPolicyWithAccounts(
            admin,
            useBlacklist
                ? ITIP403Registry.PolicyType.BLACKLIST
                : ITIP403Registry.PolicyType.WHITELIST,
            accounts
        ) returns (
            uint64
        ) {
            revert("TEMPO-VA15: createPolicyWithAccounts unexpectedly succeeded");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                ITIP403Registry.VirtualAddressNotAllowed.selector,
                "TEMPO-VA15: wrong createPolicyWithAccounts error"
            );
        }

        try registry.modifyPolicyWhitelist(_policyRejectWhitelistId, virtualAddr, true) {
            revert("TEMPO-VA15: modifyPolicyWhitelist unexpectedly succeeded");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                ITIP403Registry.VirtualAddressNotAllowed.selector,
                "TEMPO-VA15: wrong whitelist error"
            );
        }

        try registry.modifyPolicyBlacklist(_policyRejectBlacklistId, virtualAddr, true) {
            revert("TEMPO-VA15: modifyPolicyBlacklist unexpectedly succeeded");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                ITIP403Registry.VirtualAddressNotAllowed.selector,
                "TEMPO-VA15: wrong blacklist error"
            );
        }

        vm.stopPrank();

        assertEq(registry.policyIdCounter(), counterBefore, "TEMPO-VA15: policy counter changed");
        assertEq(
            registry.isAuthorized(_policyRejectWhitelistId, virtualAddr),
            whitelistAuthBefore,
            "TEMPO-VA15: whitelist membership changed"
        );
        assertEq(
            registry.isAuthorized(_policyRejectBlacklistId, virtualAddr),
            blacklistAuthBefore,
            "TEMPO-VA15: blacklist membership changed"
        );
        assertEq(vm.getRecordedLogs().length, 0, "TEMPO-VA15: policy rejection emitted logs");
    }

    function rejectVirtualRewardRecipient(
        uint256 actorSeed,
        uint256 tokenSeed,
        uint256 virtualSeed
    )
        external
    {
        TIP20 token = _selectBaseToken(tokenSeed);
        address actor = _selectActor(actorSeed);
        address virtualAddr = _selectVirtual(virtualSeed);

        (address rewardRecipientBefore,,) = token.userRewardInfo(actor);
        uint128 optedInSupplyBefore = token.optedInSupply();

        vm.recordLogs();
        vm.prank(actor);
        try token.setRewardRecipient(virtualAddr) {
            revert("TEMPO-VA16: setRewardRecipient unexpectedly succeeded");
        } catch (bytes memory reason) {
            assertEq(
                bytes4(reason),
                ITIP20.InvalidRecipient.selector,
                "TEMPO-VA16: wrong reward recipient error"
            );
        }

        (address rewardRecipientAfter,,) = token.userRewardInfo(actor);
        assertEq(
            rewardRecipientAfter, rewardRecipientBefore, "TEMPO-VA16: reward recipient changed"
        );
        assertEq(token.optedInSupply(), optedInSupplyBefore, "TEMPO-VA16: optedInSupply changed");
        assertEq(vm.getRecordedLogs().length, 0, "TEMPO-VA16: reward rejection emitted logs");
    }

    function registerWithInvalidInputs(uint256 callerTypeSeed, bytes32 salt) external {
        address caller;
        uint256 callerType = callerTypeSeed % 4;

        if (callerType == 0) {
            caller = address(0);
        } else if (callerType == 1) {
            caller = _selectVirtual(callerTypeSeed);
        } else if (callerType == 2) {
            caller = address(_selectBaseToken(callerTypeSeed));
        } else {
            caller = _selectActor(callerTypeSeed);
        }

        uint256 masterCountBefore = _masters.length;

        vm.recordLogs();
        vm.prank(caller);
        try tip20Registry.registerVirtualMaster(salt) returns (bytes4) {
            // Extremely unlikely for a random salt to pass PoW (~1 in 2^32),
            // but if it does and the caller is valid, that's fine — not an error.
            // For invalid callers (type 0/1/2) this should never happen.
            assertTrue(
                callerType == 3, "TEMPO-VA1: invalid caller registration unexpectedly succeeded"
            );
        } catch (bytes memory reason) {
            bytes4 selector = bytes4(reason);
            assertTrue(
                selector == IAddressRegistry.InvalidMasterAddress.selector
                    || selector == IAddressRegistry.ProofOfWorkFailed.selector
                    || selector == IAddressRegistry.MasterIdCollision.selector,
                "TEMPO-VA1: unexpected registration error"
            );
        }

        assertEq(_masters.length, masterCountBefore, "TEMPO-VA1: fixture array changed");
        _assertNoRelevantTokenLogs(
            _selectBaseToken(0), "TEMPO-VA1: registration failure emitted token logs"
        );
    }

    /*//////////////////////////////////////////////////////////////
                           GLOBAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    function invariant_globalInvariants() public view {
        for (uint256 i = 0; i < _masters.length; i++) {
            MasterFixture memory fixture = _masters[i];
            bytes32 registrationHash = keccak256(abi.encodePacked(fixture.master, fixture.salt));
            bytes4 derivedMasterId = bytes4(uint32(uint256(registrationHash) >> 192));

            assertEq(bytes4(registrationHash), bytes4(0), "TEMPO-VA1: fixture PoW invalid");
            assertEq(derivedMasterId, fixture.masterId, "TEMPO-VA1: masterId derivation mismatch");
            assertEq(
                tip20Registry.getMaster(fixture.masterId),
                fixture.master,
                "TEMPO-VA1: registry mismatch"
            );

            for (uint256 j = i + 1; j < _masters.length; j++) {
                assertTrue(
                    fixture.masterId != _masters[j].masterId,
                    "TEMPO-VA2: duplicate masterId detected"
                );
            }
        }

        for (uint256 i = 0; i < _virtualPool.length; i++) {
            address virtualAddr = _virtualPool[i];
            (bool isVirtual, bytes4 masterId, bytes6 userTag) =
                tip20Registry.decodeVirtualAddress(virtualAddr);

            assertTrue(isVirtual, "TEMPO-VA3: tracked alias not virtual");
            assertEq(masterId, _masterIdByVirtual[virtualAddr], "TEMPO-VA3: masterId mismatch");
            assertEq(userTag, _virtualToTag[virtualAddr], "TEMPO-VA3: userTag mismatch");
            assertEq(
                tip20Registry.resolveRecipient(virtualAddr),
                _virtualToMaster[virtualAddr],
                "TEMPO-VA4: resolveRecipient mismatch"
            );
            assertEq(
                tip20Registry.resolveVirtualAddress(virtualAddr),
                _virtualToMaster[virtualAddr],
                "TEMPO-VA4: resolveVirtualAddress mismatch"
            );

            for (uint256 j = 0; j < _tokens.length; j++) {
                assertEq(
                    _tokens[j].balanceOf(virtualAddr),
                    0,
                    "TEMPO-VA10: virtual alias accumulated balance"
                );
            }
        }

        for (uint256 i = 0; i < _nonVirtualPool.length; i++) {
            address account = _nonVirtualPool[i];
            assertFalse(
                tip20Registry.isVirtualAddress(account), "TEMPO-VA5: non-virtual pool polluted"
            );
            assertEq(
                tip20Registry.resolveRecipient(account),
                account,
                "TEMPO-VA5: non-virtual address changed"
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                                SETUP
    //////////////////////////////////////////////////////////////*/

    function _configureVirtualPolicies() internal {
        vm.startPrank(admin);
        for (uint256 i = 0; i < _tokens.length; i++) {
            TIP20 token = _tokens[i];
            uint64 recipientPolicyId =
                registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
            uint64 mintPolicyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
            uint64 compoundPolicyId =
                registry.createCompoundPolicy(1, recipientPolicyId, mintPolicyId);

            token.changeTransferPolicyId(compoundPolicyId);
            _recipientPolicyIds[address(token)] = recipientPolicyId;
            _mintPolicyIds[address(token)] = mintPolicyId;
        }

        _policyRejectWhitelistId =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        _policyRejectBlacklistId =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        vm.stopPrank();
    }

    function _registerVirtualMasters() internal {
        for (uint256 i = 0; i < MASTER_COUNT; i++) {
            // Index 7 reuses master index 0's address with a different salt,
            // exercising the many-to-one property (same master, different masterId).
            uint256 keyIndex = i < 7 ? i : 0;
            uint256 pk = vm.deriveKey(ANVIL_MNEMONIC, uint32(keyIndex));
            address master = vm.rememberKey(pk);
            bytes32 salt = POW_SALTS[i];
            bytes32 registrationHash = keccak256(abi.encodePacked(master, salt));
            bytes4 masterId = bytes4(uint32(uint256(registrationHash) >> 192));

            assertEq(bytes4(registrationHash), bytes4(0), "TEMPO-VA1: setup PoW invalid");
            assertEq(_masterById[masterId], address(0), "TEMPO-VA2: duplicate setup masterId");

            vm.prank(master);
            bytes4 registeredId = tip20Registry.registerVirtualMaster(salt);

            assertEq(registeredId, masterId, "TEMPO-VA1: registration returned wrong masterId");
            assertEq(
                tip20Registry.getMaster(masterId), master, "TEMPO-VA1: registry stored wrong master"
            );

            _masters.push(MasterFixture({ master: master, pk: pk, salt: salt, masterId: masterId }));
            _masterById[masterId] = master;
            _registerBalanceHolder(master);
        }
    }

    function _buildVirtualPool() internal {
        for (uint256 i = 0; i < _masters.length; i++) {
            MasterFixture memory fixture = _masters[i];
            for (uint256 j = 0; j < TAG_COUNT; j++) {
                bytes6 userTag = USER_TAGS[j];
                address virtualAddr = _makeVirtualAddress(fixture.masterId, userTag);

                _virtualPool.push(virtualAddr);
                _masterIdByVirtual[virtualAddr] = fixture.masterId;
                _virtualToMaster[virtualAddr] = fixture.master;
                _virtualToTag[virtualAddr] = userTag;
                _virtualTracked[virtualAddr] = true;
            }
        }
    }

    function _seedMasterBalances() internal {
        vm.startPrank(admin);
        for (uint256 i = 0; i < _tokens.length; i++) {
            TIP20 token = _tokens[i];
            for (uint256 j = 0; j < _masters.length; j++) {
                token.mint(_masters[j].master, INITIAL_MASTER_BALANCE);
            }
        }
        vm.stopPrank();
    }

    function _buildNonVirtualPool() internal {
        _pushNonVirtual(admin);
        _pushNonVirtual(alice);
        _pushNonVirtual(bob);
        _pushNonVirtual(charlie);

        for (uint256 i = 0; i < _actors.length; i++) {
            _pushNonVirtual(_actors[i]);
        }

        for (uint256 i = 0; i < _masters.length; i++) {
            _pushNonVirtual(_masters[i].master);
        }
    }

    function _pushNonVirtual(address account) internal {
        if (!tip20Registry.isVirtualAddress(account)) {
            _nonVirtualPool.push(account);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _selectVirtual(uint256 seed) internal view returns (address) {
        return _virtualPool[seed % _virtualPool.length];
    }

    function _virtualForMaster(
        uint256 masterIndex,
        uint256 tagSeed
    )
        internal
        view
        returns (address)
    {
        return _virtualPool[(masterIndex * TAG_COUNT) + (tagSeed % TAG_COUNT)];
    }

    function _selectUnregisteredVirtual(
        uint256 masterSeed,
        uint256 tagSeed
    )
        internal
        view
        returns (address virtualAddr, bytes4 masterId)
    {
        for (uint256 i = 0;; i++) {
            masterId = bytes4(keccak256(abi.encodePacked(masterSeed, i)));
            if (tip20Registry.getMaster(masterId) == address(0)) {
                return (_makeVirtualAddress(masterId, USER_TAGS[tagSeed % TAG_COUNT]), masterId);
            }
        }
    }

    function _makeVirtualAddress(bytes4 masterId, bytes6 userTag) internal pure returns (address) {
        uint160 raw = (uint160(uint32(masterId)) << 128) | (uint160(VIRTUAL_MAGIC) << 48)
            | uint160(uint48(userTag));
        return address(raw);
    }

    function _setTransferAllowed(TIP20 token, address master, bool allowed) internal {
        uint64 policyId = _recipientPolicyIds[address(token)];
        bool current = registry.isAuthorized(policyId, master);
        if (current == allowed) {
            return;
        }

        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, master, !allowed);
    }

    function _setMintAllowed(TIP20 token, address master, bool allowed) internal {
        uint64 policyId = _mintPolicyIds[address(token)];
        bool current = registry.isAuthorized(policyId, master);
        if (current == allowed) {
            return;
        }

        vm.prank(admin);
        registry.modifyPolicyBlacklist(policyId, master, !allowed);
    }

    function _mintableAmount(TIP20 token) internal view returns (uint256) {
        uint256 remaining = token.supplyCap() - token.totalSupply();
        return remaining > MAX_HANDLER_AMOUNT ? MAX_HANDLER_AMOUNT : remaining;
    }

    function _snapshot(
        TIP20 token,
        address from,
        address master,
        address virtualAddr
    )
        internal
        view
        returns (BalanceSnapshot memory snapshot)
    {
        snapshot.fromBalance = token.balanceOf(from);
        snapshot.masterBalance = token.balanceOf(master);
        snapshot.virtualBalance = token.balanceOf(virtualAddr);
        snapshot.totalSupply = token.totalSupply();
    }

    function _maxTransferFromAmount(BalanceSnapshot memory snapshot)
        internal
        pure
        returns (uint256)
    {
        return snapshot.allowance == type(uint256).max
            ? _boundedAmount(snapshot.fromBalance)
            : _min(_boundedAmount(snapshot.fromBalance), snapshot.allowance);
    }

    function _boundedAmount(uint256 available) internal pure returns (uint256) {
        return available > MAX_HANDLER_AMOUNT ? MAX_HANDLER_AMOUNT : available;
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function _assertTransferSequence(
        TIP20 token,
        address from,
        address virtualAddr,
        address master,
        uint256 amount
    )
        internal
    {
        Vm.Log[] memory logs = _relevantTokenLogs(token);
        assertEq(logs.length, 2, "TEMPO-VA11: expected two transfer logs");
        _assertTransferLog(logs[0], token, from, virtualAddr, amount);
        _assertTransferLog(logs[1], token, virtualAddr, master, amount);
    }

    function _assertTransferWithMemoSequence(
        TIP20 token,
        address from,
        address virtualAddr,
        address master,
        uint256 amount,
        bytes32 memo
    )
        internal
    {
        Vm.Log[] memory logs = _relevantTokenLogs(token);
        assertEq(logs.length, 3, "TEMPO-VA12: expected transfer/memo/forward logs");
        _assertTransferLog(logs[0], token, from, virtualAddr, amount);
        _assertTransferWithMemoLog(logs[1], token, from, virtualAddr, amount, memo);
        _assertTransferLog(logs[2], token, virtualAddr, master, amount);
    }

    function _assertMintSequence(
        TIP20 token,
        address virtualAddr,
        address master,
        uint256 amount
    )
        internal
    {
        Vm.Log[] memory logs = _relevantTokenLogs(token);
        assertEq(logs.length, 3, "TEMPO-VA12: expected transfer/mint/forward logs");
        _assertTransferLog(logs[0], token, address(0), virtualAddr, amount);
        _assertMintLog(logs[1], token, virtualAddr, amount);
        _assertTransferLog(logs[2], token, virtualAddr, master, amount);
    }

    function _assertMintWithMemoSequence(
        TIP20 token,
        address virtualAddr,
        address master,
        uint256 amount,
        bytes32 memo
    )
        internal
    {
        Vm.Log[] memory logs = _relevantTokenLogs(token);
        assertEq(logs.length, 4, "TEMPO-VA12: expected transfer/memo/mint/forward logs");
        _assertTransferLog(logs[0], token, address(0), virtualAddr, amount);
        _assertTransferWithMemoLog(logs[1], token, address(0), virtualAddr, amount, memo);
        _assertMintLog(logs[2], token, virtualAddr, amount);
        _assertTransferLog(logs[3], token, virtualAddr, master, amount);
    }

    function _assertNoRelevantTokenLogs(TIP20 token, string memory message) internal {
        assertEq(_relevantTokenLogs(token).length, 0, message);
    }

    function _relevantTokenLogs(TIP20 token) internal returns (Vm.Log[] memory relevant) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 count;

        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(token) && _isRelevantTokenEvent(logs[i].topics[0])) {
                count++;
            }
        }

        relevant = new Vm.Log[](count);
        uint256 index;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(token) && _isRelevantTokenEvent(logs[i].topics[0])) {
                relevant[index++] = logs[i];
            }
        }
    }

    function _isRelevantTokenEvent(bytes32 topic0) internal pure returns (bool) {
        return topic0 == Tempo.TRANSFER_EVENT || topic0 == Tempo.TRANSFER_WITH_MEMO_EVENT
            || topic0 == Tempo.MINT_EVENT;
    }

    function _assertTransferLog(
        Vm.Log memory log,
        TIP20 token,
        address from,
        address to,
        uint256 amount
    )
        internal
        pure
    {
        assertEq(log.emitter, address(token), "TEMPO-VA11: wrong transfer emitter");
        assertEq(log.topics.length, 3, "TEMPO-VA11: wrong transfer topic count");
        assertEq(log.topics[0], Tempo.TRANSFER_EVENT, "TEMPO-VA11: wrong transfer selector");
        assertEq(address(uint160(uint256(log.topics[1]))), from, "TEMPO-VA11: wrong transfer from");
        assertEq(address(uint160(uint256(log.topics[2]))), to, "TEMPO-VA11: wrong transfer to");
        assertEq(abi.decode(log.data, (uint256)), amount, "TEMPO-VA11: wrong transfer amount");
    }

    function _assertTransferWithMemoLog(
        Vm.Log memory log,
        TIP20 token,
        address from,
        address to,
        uint256 amount,
        bytes32 memo
    )
        internal
        pure
    {
        assertEq(log.emitter, address(token), "TEMPO-VA12: wrong memo emitter");
        assertEq(log.topics.length, 4, "TEMPO-VA12: wrong memo topic count");
        assertEq(log.topics[0], Tempo.TRANSFER_WITH_MEMO_EVENT, "TEMPO-VA12: wrong memo selector");
        assertEq(address(uint160(uint256(log.topics[1]))), from, "TEMPO-VA12: wrong memo from");
        assertEq(address(uint160(uint256(log.topics[2]))), to, "TEMPO-VA12: wrong memo to");
        assertEq(log.topics[3], memo, "TEMPO-VA12: wrong memo topic");
        assertEq(abi.decode(log.data, (uint256)), amount, "TEMPO-VA12: wrong memo amount");
    }

    function _assertMintLog(
        Vm.Log memory log,
        TIP20 token,
        address to,
        uint256 amount
    )
        internal
        pure
    {
        assertEq(log.emitter, address(token), "TEMPO-VA12: wrong mint emitter");
        assertEq(log.topics.length, 2, "TEMPO-VA12: wrong mint topic count");
        assertEq(log.topics[0], Tempo.MINT_EVENT, "TEMPO-VA12: wrong mint selector");
        assertEq(address(uint160(uint256(log.topics[1]))), to, "TEMPO-VA12: wrong mint recipient");
        assertEq(abi.decode(log.data, (uint256)), amount, "TEMPO-VA12: wrong mint amount");
    }

}
