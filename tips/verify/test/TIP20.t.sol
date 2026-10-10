// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import "./TempoTest.t.sol";
import { ITIP20, ITIP20Token } from "tempo-std/interfaces/ITIP20.sol";
import { ITIP20RolesAuth, ITIP20RolesAuthErr } from "tempo-std/interfaces/ITIP20RolesAuth.sol";
import { ITIP403Registry } from "tempo-std/interfaces/ITIP403Registry.sol";

interface ITIP20Protocol is ITIP20 {

    function systemTransferFrom(address from, address to, uint256 amount) external;
    function transferFeePreTx(address from, uint256 amount) external;

}

contract TIP20Test is TempoTest {

    ITIP20Token token;
    ITIP20Token linkedToken;
    ITIP20Token anotherToken;

    bytes32 constant TEST_MEMO = bytes32(uint256(0x1234567890abcdef));
    bytes32 constant ANOTHER_MEMO = bytes32("Hello World");

    // Signer key pair for permit tests
    uint256 internal constant SIGNER_KEY = 0xA11CE;
    uint256 internal constant WRONG_KEY = 0xB0B;

    event TransferWithMemo(
        address indexed from, address indexed to, uint256 amount, bytes32 indexed memo
    );
    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);
    event NextQuoteTokenSet(address indexed updater, ITIP20Token indexed nextQuoteToken);
    event QuoteTokenUpdate(address indexed updater, ITIP20Token indexed newQuoteToken);
    event RewardDistributed(address indexed funder, uint256 amount);
    event RewardRecipientSet(address indexed holder, address indexed recipient);

    function setUp() public override {
        super.setUp();

        linkedToken = ITIP20Token(
            factory.createToken("Linked Token", "LINK", "USD", pathUSD, admin, bytes32("linked"))
        );
        anotherToken = ITIP20Token(
            factory.createToken("Another Token", "OTHER", "USD", pathUSD, admin, bytes32("another"))
        );
        token = ITIP20Token(
            factory.createToken("Test Token", "TST", "USD", linkedToken, admin, bytes32("token"))
        );

        // Setup roles and mint tokens
        vm.startPrank(admin);
        token.grantRole(_ISSUER_ROLE, admin);
        token.mint(alice, 1000e18);
        token.mint(bob, 500e18);

        vm.stopPrank();
    }

    function testTransferWithMemo() public {
        uint256 amount = 100e18;

        vm.startPrank(alice);

        // Expect both Transfer and TransferWithMemo events
        vm.expectEmit(true, true, true, true);
        emit Transfer(alice, bob, amount);

        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(alice, bob, amount, TEST_MEMO);

        token.transferWithMemo(bob, amount, TEST_MEMO);

        vm.stopPrank();

        // Verify balances
        assertEq(token.balanceOf(alice), 900e18);
        assertEq(token.balanceOf(bob), 600e18);
    }

    function testTransferWithMemoDifferentMemos() public {
        uint256 amount1 = 50e18;
        uint256 amount2 = 75e18;

        vm.startPrank(alice);

        // First transfer with TEST_MEMO
        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(alice, bob, amount1, TEST_MEMO);

        token.transferWithMemo(bob, amount1, TEST_MEMO);

        // Second transfer with ANOTHER_MEMO
        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(alice, charlie, amount2, ANOTHER_MEMO);

        token.transferWithMemo(charlie, amount2, ANOTHER_MEMO);

        vm.stopPrank();

        // Verify balances
        assertEq(token.balanceOf(alice), 875e18);
        assertEq(token.balanceOf(bob), 550e18);
        assertEq(token.balanceOf(charlie), 75e18);
    }

    function testTransferFromWithMemo() public {
        uint256 amount = 150e18;

        // Alice approves bob to spend her tokens
        vm.prank(alice);
        token.approve(bob, 200e18);

        vm.startPrank(bob);

        // Expect both Transfer and TransferWithMemo events
        vm.expectEmit(true, true, true, true);
        emit Transfer(alice, charlie, amount);

        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(alice, charlie, amount, TEST_MEMO);

        bool success = token.transferFromWithMemo(alice, charlie, amount, TEST_MEMO);
        assertTrue(success);

        vm.stopPrank();

        // Verify balances
        assertEq(token.balanceOf(alice), 850e18);
        assertEq(token.balanceOf(charlie), 150e18);

        // Verify allowance was decreased
        assertEq(token.allowance(alice, bob), 50e18);
    }

    function testTransferFromWithMemoInsufficientAllowance() public {
        uint256 amount = 300e18;

        // Alice approves bob to spend less than he tries to transfer
        vm.prank(alice);
        token.approve(bob, 200e18);

        vm.startPrank(bob);
        try token.transferFromWithMemo(alice, charlie, amount, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InsufficientAllowance.selector));
        }
        vm.stopPrank();

        // Verify balances unchanged
        assertEq(token.balanceOf(alice), 1000e18);
        assertEq(token.balanceOf(charlie), 0);
    }

    function testTransferFromWithMemoInfiniteAllowance() public {
        uint256 amount = 150e18;

        // Alice gives bob infinite allowance
        vm.prank(alice);
        token.approve(bob, type(uint256).max);

        vm.startPrank(bob);

        // First transfer
        token.transferFromWithMemo(alice, charlie, amount, TEST_MEMO);

        // Verify infinite allowance is still infinite
        assertEq(token.allowance(alice, bob), type(uint256).max);

        // Second transfer should also work
        token.transferFromWithMemo(alice, charlie, amount, ANOTHER_MEMO);

        vm.stopPrank();

        // Verify balances
        assertEq(token.balanceOf(alice), 700e18);
        assertEq(token.balanceOf(charlie), 300e18);

        // Verify infinite allowance is still infinite
        assertEq(token.allowance(alice, bob), type(uint256).max);
    }

    function testTransferWithMemoWhenPaused() public {
        // Admin pauses the contract
        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.pause();
        vm.stopPrank();

        vm.startPrank(alice);
        try token.transferWithMemo(bob, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.ContractPaused.selector));
        }
        vm.stopPrank();
    }

    function testTransferFromWithMemoWhenPaused() public {
        // Alice approves bob
        vm.prank(alice);
        token.approve(bob, 200e18);

        // Admin pauses the contract
        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.pause();
        vm.stopPrank();

        vm.startPrank(bob);
        try token.transferFromWithMemo(alice, charlie, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.ContractPaused.selector));
        }
        vm.stopPrank();
    }

    function testTransferToInvalidRecipient() public {
        vm.startPrank(alice);

        // Try to transfer to the zero address
        try token.transfer(address(0), 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }

        // Try to transfer to a token precompile address
        address tokenAddress = address(0x20C0000000000000000000000000000000000001);
        try token.transfer(tokenAddress, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }
        vm.stopPrank();
    }

    function testTransferFromToInvalidRecipient() public {
        // Alice approves bob
        vm.prank(alice);
        token.approve(bob, 200e18);

        // Try to transfer to the zero address
        try token.transferFrom(alice, address(0), 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }

        // Try to transfer to a token precompile address
        address tokenAddress = address(0x20C0000000000000000000000000000000000001);

        vm.startPrank(bob);
        try token.transferFrom(alice, tokenAddress, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }
        vm.stopPrank();
    }

    function testTransferWithMemoToInvalidRecipient() public {
        vm.startPrank(alice);

        // Try to transfer to the zero address
        try token.transferWithMemo(address(0), 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }

        // Try to transfer to a token precompile address
        address tokenAddress = address(0x20C0000000000000000000000000000000000001);
        try token.transferWithMemo(tokenAddress, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }
        vm.stopPrank();
    }

    function testTransferFromWithMemoToInvalidRecipient() public {
        // Alice approves bob
        vm.prank(alice);
        token.approve(bob, 200e18);

        // Try to transfer to the zero address
        try token.transferFromWithMemo(alice, address(0), 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }

        // Try to transfer to a token precompile address
        address tokenAddress = address(0x20C0000000000000000000000000000000000001);

        vm.startPrank(bob);
        try token.transferFromWithMemo(alice, tokenAddress, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidRecipient.selector));
        }
        vm.stopPrank();
    }

    function testFuzzTransferWithMemo(address to, uint256 amount, bytes32 memo) public {
        // Avoid invalid recipients
        vm.assume(to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);

        // Bound amount to alice's balance
        amount = bound(amount, 0, 1000e18);

        // Get initial balance of recipient
        uint256 toInitialBalance = token.balanceOf(to);

        vm.prank(alice);
        token.transferWithMemo(to, amount, memo);

        // Check balances - handle self-transfer case
        if (alice == to) {
            assertEq(token.balanceOf(alice), 1000e18);
        } else {
            assertEq(token.balanceOf(alice), 1000e18 - amount);
            assertEq(token.balanceOf(to), toInitialBalance + amount);
        }
    }

    function testFuzzTransferFromWithMemo(
        address spender,
        address to,
        uint256 allowanceAmount,
        uint256 transferAmount,
        bytes32 memo
    )
        public
    {
        // Avoid invalid addresses
        vm.assume(spender != address(0) && to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);
        vm.assume(spender != 0x1559c00000000000000000000000000000000000); // Not FeeManager

        // Bound amounts
        allowanceAmount = bound(allowanceAmount, 0, 1000e18);
        transferAmount = bound(transferAmount, 0, allowanceAmount);

        // Alice approves spender
        vm.prank(alice);
        token.approve(spender, allowanceAmount);

        // Get initial balance of recipient (in case it's an existing address with balance)
        uint256 toInitialBalance = token.balanceOf(to);

        // Spender transfers from alice to to
        vm.prank(spender);
        bool success = token.transferFromWithMemo(alice, to, transferAmount, memo);
        assertTrue(success);

        // Check balances based on whether it's a self-transfer or not
        if (alice == to) {
            // Self-transfer: alice's balance remains unchanged
            assertEq(token.balanceOf(alice), 1000e18);
        } else {
            // Normal transfer: alice loses transferAmount, to gains transferAmount
            assertEq(token.balanceOf(alice), 1000e18 - transferAmount);
            assertEq(token.balanceOf(to), toInitialBalance + transferAmount);
        }

        // Check allowance
        if (allowanceAmount == type(uint256).max) {
            assertEq(token.allowance(alice, spender), type(uint256).max);
        } else {
            assertEq(token.allowance(alice, spender), allowanceAmount - transferAmount);
        }
    }

    function testMintWithMemo() public {
        uint256 amount = 200e18;
        address recipient = charlie;

        vm.startPrank(admin);

        // Expect Transfer, TransferWithMemo, and Mint events
        vm.expectEmit(true, true, true, true);
        emit Transfer(address(0), recipient, amount);

        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(address(0), recipient, amount, TEST_MEMO);

        vm.expectEmit(true, true, true, true);
        emit Mint(recipient, amount);

        token.mintWithMemo(recipient, amount, TEST_MEMO);

        vm.stopPrank();

        // Verify balance and total supply
        assertEq(token.balanceOf(recipient), amount);
        assertEq(token.totalSupply(), 1500e18 + amount);
    }

    function testBurnWithMemo() public {
        uint256 amount = 100e18;

        vm.startPrank(admin);

        // First mint some tokens to admin to burn
        token.mint(admin, amount);

        // Expect Transfer, TransferWithMemo, and Burn events
        vm.expectEmit(true, true, true, true);
        emit Transfer(admin, address(0), amount);

        vm.expectEmit(true, true, true, true);
        emit TransferWithMemo(admin, address(0), amount, TEST_MEMO);

        vm.expectEmit(true, true, true, true);
        emit Burn(admin, amount);

        token.burnWithMemo(amount, TEST_MEMO);

        vm.stopPrank();

        // Verify balance and total supply
        assertEq(token.balanceOf(admin), 0);
        assertEq(token.totalSupply(), 1500e18);
    }

    function testMintWithMemoSupplyCapExceeded() public {
        vm.startPrank(admin);

        // Set a supply cap
        token.setSupplyCap(1600e18);

        // Try to mint more than the cap allows
        try token.mintWithMemo(charlie, 200e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.SupplyCapExceeded.selector));
        }

        vm.stopPrank();
    }

    function testBurnWithMemoInsufficientBalance() public {
        vm.startPrank(admin);

        // Try to burn more than admin has
        try token.burnWithMemo(100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err,
                abi.encodeWithSelector(
                    ITIP20.InsufficientBalance.selector,
                    token.balanceOf(admin),
                    100e18,
                    address(token)
                )
            );
        }

        vm.stopPrank();
    }

    function testMintWithMemoRequiresIssuerRole() public {
        // Try to mint without _ISSUER_ROLE
        vm.startPrank(alice);
        try token.mintWithMemo(charlie, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
        vm.stopPrank();
    }

    function testPolicyForbidsAllCases() public {
        // Setup: approve bob to spend alice's tokens
        vm.prank(alice);
        token.approve(bob, 1000e18);

        // Create a policy that blocks alice
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 blockingPolicy = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        vm.prank(admin);
        token.changeTransferPolicyId(blockingPolicy);

        // 1. mint - blocked recipient
        vm.prank(admin);
        try token.mint(alice, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 2. transfer - blocked sender
        vm.prank(alice);
        try token.transfer(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 3. transferWithMemo - blocked sender
        vm.prank(alice);
        try token.transferWithMemo(bob, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 4. transferFrom - blocked from
        vm.prank(bob);
        try token.transferFrom(alice, charlie, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 5. transferFromWithMemo - blocked from
        vm.prank(bob);
        try token.transferFromWithMemo(alice, charlie, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 6. claimRewards - blocked recipient
        vm.prank(alice);
        try token.claimRewards() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        // 7. burnBlocked - reverts if from IS authorized (opposite logic)
        vm.startPrank(admin);
        token.grantRole(token.BURN_BLOCKED_ROLE(), admin);
        token.changeTransferPolicyId(1); // back to default where bob is authorized
        try token.burnBlocked(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }
        vm.stopPrank();
    }

    function testBurnWithMemoRequiresIssuerRole() public {
        // Try to burn without _ISSUER_ROLE
        vm.startPrank(alice);
        try token.burnWithMemo(100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
        vm.stopPrank();
    }

    function testFuzzMintWithMemo(address to, uint256 amount, bytes32 memo) public {
        // Avoid minting to address(0) or token addresses
        vm.assume(to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);

        // Bound amount to avoid supply cap overflow
        amount = bound(amount, 0, type(uint128).max - token.totalSupply());

        uint256 initialSupply = token.totalSupply();
        uint256 initialBalance = token.balanceOf(to);

        vm.prank(admin);
        token.mintWithMemo(to, amount, memo);

        assertEq(token.balanceOf(to), initialBalance + amount);
        assertEq(token.totalSupply(), initialSupply + amount);
    }

    function testFuzzBurnWithMemo(uint256 mintAmount, uint256 burnAmount, bytes32 memo) public {
        // Bound amounts
        mintAmount = bound(mintAmount, 1, type(uint128).max / 2);
        burnAmount = bound(burnAmount, 0, mintAmount);

        vm.startPrank(admin);

        // Mint tokens first
        token.mint(admin, mintAmount);

        uint256 balanceBeforeBurn = token.balanceOf(admin);
        uint256 supplyBeforeBurn = token.totalSupply();

        // Burn tokens with memo
        token.burnWithMemo(burnAmount, memo);

        assertEq(token.balanceOf(admin), balanceBeforeBurn - burnAmount);
        assertEq(token.totalSupply(), supplyBeforeBurn - burnAmount);

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          QUOTE TOKEN TESTS
    //////////////////////////////////////////////////////////////*/

    function testQuoteTokenSetInConstructor() public view {
        assertEq(address(token.quoteToken()), address(linkedToken));
    }

    function testChangeTransferPolicyId() public {
        // Create a policy first
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        vm.prank(admin);
        token.changeTransferPolicyId(policyId);
        assertEq(token.transferPolicyId(), policyId);
    }

    function testChangeTransferPolicyIdUnauthorized() public {
        // Create a policy first
        uint64 policyId = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        vm.prank(alice);
        try token.changeTransferPolicyId(policyId) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testFuzz_ChangeTransferPolicyId_RevertsIf_PolicyNotFound(uint64 policyId) public {
        vm.assume(policyId >= registry.policyIdCounter());
        vm.prank(admin);
        try token.changeTransferPolicyId(policyId) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidTransferPolicyId.selector));
        }
    }

    function testSetNextQuoteTokenAndComplete() public {
        vm.startPrank(admin);

        // Expect the NextQuoteTokenSet event
        vm.expectEmit(true, true, false, false);
        emit NextQuoteTokenSet(admin, anotherToken);

        token.setNextQuoteToken(anotherToken);

        // Verify nextQuoteToken is set but quoteToken is not changed yet
        assertEq(address(token.nextQuoteToken()), address(anotherToken));
        assertEq(address(token.quoteToken()), address(linkedToken));

        // Expect the QuoteTokenUpdate event
        vm.expectEmit(true, true, false, false);
        emit QuoteTokenUpdate(admin, anotherToken);

        token.completeQuoteTokenUpdate();

        vm.stopPrank();

        assertEq(address(token.quoteToken()), address(anotherToken));
    }

    function testSetNextQuoteTokenRequiresAdmin() public {
        vm.startPrank(alice);

        try token.setNextQuoteToken(anotherToken) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }

        vm.stopPrank();
    }

    function testCompleteQuoteTokenUpdateRequiresAdmin() public {
        vm.prank(admin);
        token.setNextQuoteToken(anotherToken);

        vm.startPrank(alice);

        try token.completeQuoteTokenUpdate() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }

        vm.stopPrank();
    }

    function testSetNextQuoteTokenToInvalidAddress() public {
        vm.startPrank(admin);

        // Should revert when trying to set to zero address (not registered in factory)
        try token.setNextQuoteToken(ITIP20(address(0))) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidQuoteToken.selector));
        }

        vm.stopPrank();
    }

    function testSetNextQuoteTokenUsdRequiresUsdQuote() public {
        ITIP20 usdToken = ITIP20(
            factory.createToken("USD Token", "USD", "USD", pathUSD, admin, bytes32("usdtoken"))
        );

        ITIP20 nonUsdToken = ITIP20(
            factory.createToken("Euro Token", "EUR", "EUR", pathUSD, admin, bytes32("eurotok"))
        );

        vm.prank(admin);
        try usdToken.setNextQuoteToken(nonUsdToken) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidQuoteToken.selector));
        }
    }

    function testSetSupplyCapUnauthorized() public {
        vm.prank(alice);
        try token.setSupplyCap(2000e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testSetSupplyCapBelowTotalSupply() public {
        vm.prank(admin);
        try token.setSupplyCap(1000e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidSupplyCap.selector));
        }
    }

    function testSetSupplyCapAboveUint128Max() public {
        vm.prank(admin);
        try token.setSupplyCap(uint256(type(uint128).max) + 1) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.SupplyCapExceeded.selector));
        }
    }

    function testUnpauseUnauthorized() public {
        vm.prank(alice);
        try token.unpause() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testMintUnauthorized() public {
        vm.prank(alice);
        try token.mint(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testBurnUnauthorized() public {
        vm.prank(alice);
        try token.burn(100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testBurnInsufficientBalance() public {
        vm.prank(admin);
        try token.burn(100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err,
                abi.encodeWithSelector(
                    ITIP20.InsufficientBalance.selector, 0, 100e18, address(token)
                )
            );
        }
    }

    function testBurnBlockedUnauthorized() public {
        vm.prank(alice);
        try token.burnBlocked(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20RolesAuthErr.Unauthorized.selector));
        }
    }

    function testBurnBlockedFromAuthorizedAddress() public {
        vm.startPrank(admin);
        token.grantRole(token.BURN_BLOCKED_ROLE(), admin);
        try token.burnBlocked(alice, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }
        vm.stopPrank();
    }

    function testBurnBlockedSuccess() public {
        // Create a policy that blocks alice
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 blockingPolicy = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        // Change to a policy where alice is blocked
        vm.startPrank(admin);
        token.grantRole(token.BURN_BLOCKED_ROLE(), admin);
        token.changeTransferPolicyId(blockingPolicy);

        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 totalSupplyBefore = token.totalSupply();

        token.burnBlocked(alice, 100e18);

        assertEq(token.balanceOf(alice), aliceBalanceBefore - 100e18);
        assertEq(token.totalSupply(), totalSupplyBefore - 100e18);
        vm.stopPrank();
    }

    function testTransferPolicyForbids() public {
        vm.prank(alice);
        token.approve(bob, 1000e18);

        // Create a policy that blocks alice
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 blockingPolicy = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        vm.prank(admin);
        token.changeTransferPolicyId(blockingPolicy);

        vm.prank(alice);
        try token.transfer(bob, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        vm.prank(alice);
        try token.transferWithMemo(bob, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        vm.prank(bob);
        try token.transferFrom(alice, charlie, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }

        vm.prank(bob);
        try token.transferFromWithMemo(alice, charlie, 100e18, TEST_MEMO) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }
    }

    function testTransferInsufficientBalance() public {
        vm.prank(alice);
        try token.transfer(bob, 2000e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(
                err,
                abi.encodeWithSelector(
                    ITIP20.InsufficientBalance.selector, 1000e18, 2000e18, address(token)
                )
            );
        }
    }

    /*//////////////////////////////////////////////////////////////
                        LOOP PREVENTION TESTS
    //////////////////////////////////////////////////////////////*/

    function testCompleteQuoteTokenUpdateCannotCreateDirectLoop() public {
        // Try to set token's quote token to itself
        vm.startPrank(admin);

        // setNextQuoteToken doesn't check for loops
        token.setNextQuoteToken(token);

        // completeQuoteTokenUpdate should detect the loop and revert
        try token.completeQuoteTokenUpdate() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidQuoteToken.selector));
        }

        vm.stopPrank();
    }

    function testCompleteQuoteTokenUpdateCannotCreateIndirectLoop() public {
        ITIP20 newToken = ITIP20(
            factory.createToken("New Token", "NEW", "USD", token, admin, bytes32("newtoken"))
        );

        // Try to set token's quote token to newToken (which would create a loop)
        vm.startPrank(admin);

        // setNextQuoteToken doesn't check for loops
        token.setNextQuoteToken(newToken);

        // completeQuoteTokenUpdate should detect the loop and revert
        try token.completeQuoteTokenUpdate() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidQuoteToken.selector));
        }

        vm.stopPrank();
    }

    function testCompleteQuoteTokenUpdateCannotCreateLongerLoop() public {
        // Create a longer chain: pathUSD -> linkedToken -> token -> token2 -> token3

        ITIP20 token3 =
            ITIP20(factory.createToken("Token 3", "TK2", "USD", token, admin, bytes32("token3")));

        // Try to set linkedToken's quote token to token3 (would create loop)
        vm.startPrank(admin);

        // setNextQuoteToken doesn't check for loops
        linkedToken.setNextQuoteToken(token3);

        // completeQuoteTokenUpdate should detect the loop and revert
        try linkedToken.completeQuoteTokenUpdate() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidQuoteToken.selector));
        }

        vm.stopPrank();
    }

    function testCompleteQuoteTokenUpdateValidChangeDoesNotRevert() public {
        // Verify that a valid change doesn't revert
        // token currently links to linkedToken, change it to anotherToken (both depth 1)
        vm.startPrank(admin);

        // This should succeed - no loop created
        token.setNextQuoteToken(anotherToken);
        token.completeQuoteTokenUpdate();

        vm.stopPrank();

        // Verify the change was successful
        assertEq(address(token.quoteToken()), address(anotherToken));
    }

    function testFuzz_DisabledRewardsPreserveSettledState(
        uint128 amount,
        address recipient
    )
        public
    {
        _seedSettledRewards(token, alice, amount, 0);
        uint256 supply = token.totalSupply();
        uint256 balance = token.balanceOf(alice);

        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.pause();
        token.changeTransferPolicyId(0);
        vm.stopPrank();

        vm.startPrank(alice);
        token.setRewardRecipient(recipient);
        token.distributeReward(amount);
        vm.stopPrank();

        (address storedRecipient, uint256 rewardPerToken, uint256 rewardBalance) =
            token.userRewardInfo(alice);
        assertEq(storedRecipient, address(0));
        assertEq(rewardPerToken, 0);
        assertEq(rewardBalance, amount);
        assertEq(token.getPendingRewards(alice), amount);
        assertEq(token.globalRewardPerToken(), 0);
        assertEq(token.optedInSupply(), 0);
        assertEq(token.totalSupply(), supply);
        assertEq(token.balanceOf(alice), balance);
        assertEq(token.balanceOf(address(token)), 0);
    }

    function testFuzz_ClaimSettledRewards(uint128 amount, uint128 funding) public {
        _seedSettledRewards(token, alice, amount, funding);
        uint256 balance = token.balanceOf(alice);
        uint256 supply = token.totalSupply();
        uint256 paid = funding < amount ? funding : amount;

        vm.prank(alice);
        assertEq(token.claimRewards(), paid);
        assertEq(token.balanceOf(alice), balance + paid);
        assertEq(token.balanceOf(address(token)), uint256(funding) - paid);
        assertEq(token.getPendingRewards(alice), uint256(amount) - paid);
        assertEq(token.totalSupply(), supply);

        vm.prank(alice);
        assertEq(token.claimRewards(), 0);
        assertEq(token.getPendingRewards(alice), uint256(amount) - paid);
    }

    function test_ClaimRewards_RevertsWhenPaused() public {
        _seedSettledRewards(token, alice, 100, 100);
        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.pause();
        vm.stopPrank();

        vm.expectRevert(ITIP20.ContractPaused.selector);
        vm.prank(alice);
        token.claimRewards();
        assertEq(token.getPendingRewards(alice), 100);
    }

    /*//////////////////////////////////////////////////////////////
                    SECTION: ADDITIONAL FUZZ TESTS
    //////////////////////////////////////////////////////////////*/

    function testFuzz_transfer(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 0, 1000e18);

        uint256 aliceBalanceBefore = token.balanceOf(alice);
        uint256 toBalanceBefore = token.balanceOf(to);
        uint256 totalSupplyBefore = token.totalSupply();

        vm.prank(alice);
        token.transfer(to, amount);

        if (alice == to) {
            assertEq(token.balanceOf(alice), aliceBalanceBefore);
        } else {
            assertEq(token.balanceOf(alice), aliceBalanceBefore - amount);
            assertEq(token.balanceOf(to), toBalanceBefore + amount);
        }

        // Invariant: total supply unchanged
        assertEq(token.totalSupply(), totalSupplyBefore);
    }

    function testFuzz_transferFrom(
        address spender,
        address to,
        uint256 allowanceAmount,
        uint256 transferAmount
    )
        public
    {
        vm.assume(spender != address(0) && to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);
        vm.assume(spender != 0x1559c00000000000000000000000000000000000);

        allowanceAmount = bound(allowanceAmount, 0, 1000e18);
        transferAmount = bound(transferAmount, 0, allowanceAmount);

        vm.prank(alice);
        token.approve(spender, allowanceAmount);

        uint256 totalSupplyBefore = token.totalSupply();

        vm.prank(spender);
        token.transferFrom(alice, to, transferAmount);

        // Invariant: total supply unchanged
        assertEq(token.totalSupply(), totalSupplyBefore);

        // Verify allowance decreased (unless infinite)
        if (allowanceAmount == type(uint256).max) {
            assertEq(token.allowance(alice, spender), type(uint256).max);
        } else {
            assertEq(token.allowance(alice, spender), allowanceAmount - transferAmount);
        }
    }

    function testFuzz_approve(address spender, uint256 amount) public {
        vm.assume(spender != address(0));
        amount = bound(amount, 0, type(uint256).max);

        vm.prank(alice);
        token.approve(spender, amount);

        assertEq(token.allowance(alice, spender), amount);

        // Balance should not change from approval
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function testFuzz_multipleApprovals(
        address spender,
        uint256 amount1,
        uint256 amount2,
        uint256 amount3
    )
        public
    {
        vm.assume(spender != address(0));
        amount1 = bound(amount1, 0, type(uint128).max);
        amount2 = bound(amount2, 0, type(uint128).max);
        amount3 = bound(amount3, 0, type(uint128).max);

        vm.startPrank(alice);

        token.approve(spender, amount1);
        assertEq(token.allowance(alice, spender), amount1);

        token.approve(spender, amount2);
        assertEq(token.allowance(alice, spender), amount2);

        token.approve(spender, amount3);
        assertEq(token.allowance(alice, spender), amount3);

        vm.stopPrank();

        // Balance unchanged throughout
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function testFuzz_mint(address to, uint256 amount) public {
        vm.assume(to != address(0));
        vm.assume((uint160(to) >> 64) != 0x20C000000000000000000000);
        amount = bound(amount, 0, type(uint128).max - token.totalSupply());

        uint256 supplyBefore = token.totalSupply();
        uint256 balanceBefore = token.balanceOf(to);

        vm.prank(admin);
        token.mint(to, amount);

        assertEq(token.balanceOf(to), balanceBefore + amount);
        assertEq(token.totalSupply(), supplyBefore + amount);
        assertLe(token.totalSupply(), token.supplyCap());
    }

    function testFuzz_burn(uint256 mintAmount, uint256 burnAmount) public {
        mintAmount = bound(mintAmount, 1, type(uint128).max / 2);
        burnAmount = bound(burnAmount, 0, mintAmount);

        vm.startPrank(admin);
        token.mint(admin, mintAmount);

        uint256 supplyBefore = token.totalSupply();
        uint256 balanceBefore = token.balanceOf(admin);

        token.burn(burnAmount);

        assertEq(token.balanceOf(admin), balanceBefore - burnAmount);
        assertEq(token.totalSupply(), supplyBefore - burnAmount);
        vm.stopPrank();
    }

    function testFuzz_mintBurnSequence(
        uint256 mint1,
        uint256 mint2,
        uint256 burn1,
        uint256 mint3
    )
        public
    {
        mint1 = bound(mint1, 1e18, type(uint128).max / 5);
        mint2 = bound(mint2, 1e18, type(uint128).max / 5);
        burn1 = bound(burn1, 0, mint1 + mint2);
        mint3 = bound(mint3, 1e18, type(uint128).max / 5);

        vm.startPrank(admin);

        uint256 supply0 = token.totalSupply();
        uint256 remaining = token.supplyCap() - supply0;

        // Ensure we don't exceed cap
        if (mint1 + mint2 + mint3 > remaining) {
            vm.stopPrank();
            return;
        }

        token.mint(alice, mint1);
        assertEq(token.totalSupply(), supply0 + mint1);

        token.mint(bob, mint2);
        assertEq(token.totalSupply(), supply0 + mint1 + mint2);

        token.mint(admin, burn1);
        token.burn(burn1);
        assertEq(token.totalSupply(), supply0 + mint1 + mint2);

        token.mint(charlie, mint3);
        assertEq(token.totalSupply(), supply0 + mint1 + mint2 + mint3);

        vm.stopPrank();
    }

    function testFuzz_supplyCap(uint256 cap, uint256 mintAmount) public {
        cap = bound(cap, 1500e18, type(uint128).max);
        mintAmount = bound(mintAmount, 0, cap - token.totalSupply());

        vm.startPrank(admin);
        token.setSupplyCap(cap);

        uint256 supplyBefore = token.totalSupply();
        token.mint(charlie, mintAmount);

        assertEq(token.totalSupply(), supplyBefore + mintAmount);
        assertLe(token.totalSupply(), cap);
        vm.stopPrank();
    }

    function testFuzz_pauseUnpause(uint8 cycles) public {
        cycles = uint8(bound(cycles, 1, 5));

        vm.startPrank(admin);
        token.grantRole(_PAUSE_ROLE, admin);
        token.grantRole(_UNPAUSE_ROLE, admin);
        vm.stopPrank();

        for (uint256 i = 0; i < cycles; i++) {
            vm.prank(admin);
            token.pause();
            assertTrue(token.paused());

            vm.prank(admin);
            token.unpause();
            assertFalse(token.paused());
        }
    }

    /*//////////////////////////////////////////////////////////////
                    SECTION: CRITICAL INVARIANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice INVARIANT: Sum of all balances equals totalSupply
    function test_INVARIANT_supplyConservation() public view {
        address[] memory actors = new address[](5);
        actors[0] = alice;
        actors[1] = bob;
        actors[2] = charlie;
        actors[3] = admin;
        actors[4] = address(token);

        uint256 sumBalances = 0;
        for (uint256 i = 0; i < actors.length; i++) {
            sumBalances += token.balanceOf(actors[i]);
        }

        assertEq(sumBalances, token.totalSupply(), "CRITICAL: Sum of balances != totalSupply");
    }

    /// @notice INVARIANT: Total supply never exceeds supply cap
    function test_INVARIANT_supplyCapRespected() public view {
        assertLe(token.totalSupply(), token.supplyCap(), "CRITICAL: Total supply > supply cap");
    }

    function testBurnBlocked_RevertsIf_ProtectedAddress() public {
        vm.startPrank(admin);
        token.grantRole(token.BURN_BLOCKED_ROLE(), admin);

        // Test burning from TIP_FEE_MANAGER_ADDRESS
        try token.burnBlocked(0xfeEC000000000000000000000000000000000000, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.ProtectedAddress.selector));
        }

        // Test burning from STABLECOIN_DEX_ADDRESS
        try token.burnBlocked(0xDEc0000000000000000000000000000000000000, 100e18) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.ProtectedAddress.selector));
        }

        vm.stopPrank();
    }

    function test_ClaimRewards_RevertsIf_UserUnauthorized() public {
        address[] memory accounts = new address[](1);
        accounts[0] = alice;
        uint64 blacklistPolicy = registry.createPolicyWithAccounts(
            admin, ITIP403Registry.PolicyType.BLACKLIST, accounts
        );

        vm.prank(admin);
        token.changeTransferPolicyId(blacklistPolicy);

        vm.prank(alice);
        try token.claimRewards() {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.PolicyForbids.selector));
        }
    }

    function test_Mint_Succeeds_AuthorizedMintRecipient_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 recipientWhitelist =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 mintWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        registry.modifyPolicyWhitelist(mintWhitelist, charlie, true);

        uint64 compound =
            registry.createCompoundPolicy(senderWhitelist, recipientWhitelist, mintWhitelist);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("COMPOUND", "CMP", "USD", pathUSD, admin, bytes32("compound"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(compound);

        compoundToken.mint(charlie, 1000);
        assertEq(compoundToken.balanceOf(charlie), 1000);

        vm.stopPrank();
    }

    function test_Mint_Fails_UnauthorizedMintRecipient_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 recipientWhitelist =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 mintWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        // charlie is NOT in mintWhitelist

        uint64 compound =
            registry.createCompoundPolicy(senderWhitelist, recipientWhitelist, mintWhitelist);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("COMPOUND2", "CMP2", "USD", pathUSD, admin, bytes32("compound2"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(compound);

        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.mint(charlie, 1000) {
            revert("mint should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }

        vm.stopPrank();
    }

    function test_Transfer_Succeeds_BothAuthorized_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        uint64 recipientWhitelist =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);

        registry.modifyPolicyWhitelist(senderWhitelist, alice, true);
        registry.modifyPolicyWhitelist(recipientWhitelist, bob, true);

        uint64 compound = registry.createCompoundPolicy(senderWhitelist, recipientWhitelist, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("COMPOUND3", "CMP3", "USD", pathUSD, admin, bytes32("compound3"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(alice, 1000);
        compoundToken.changeTransferPolicyId(compound);

        vm.stopPrank();

        vm.prank(alice);
        compoundToken.transfer(bob, 500);

        assertEq(compoundToken.balanceOf(alice), 500);
        assertEq(compoundToken.balanceOf(bob), 500);
    }

    function test_Transfer_Fails_SenderUnauthorized_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderWhitelist = registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        // alice is NOT in senderWhitelist

        uint64 compound = registry.createCompoundPolicy(senderWhitelist, 1, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("COMPOUND4", "CMP4", "USD", pathUSD, admin, bytes32("compound4"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(alice, 1000);
        compoundToken.changeTransferPolicyId(compound);

        vm.stopPrank();

        vm.prank(alice);
        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.transfer(bob, 500) {
            revert("transfer should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }
    }

    function test_Transfer_Fails_RecipientUnauthorized_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 recipientWhitelist =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.WHITELIST);
        // bob is NOT in recipientWhitelist

        uint64 compound = registry.createCompoundPolicy(1, recipientWhitelist, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("COMPOUND5", "CMP5", "USD", pathUSD, admin, bytes32("compound5"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(alice, 1000);
        compoundToken.changeTransferPolicyId(compound);

        vm.stopPrank();

        vm.prank(alice);
        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.transfer(bob, 500) {
            revert("transfer should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }
    }

    function test_Transfer_AsymmetricCompound_BlockedCanReceiveNotSend() public {
        vm.startPrank(admin);

        uint64 senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderBlacklist, charlie, true);

        // charlie blocked from sending, but anyone can receive
        uint64 asymmetricCompound = registry.createCompoundPolicy(senderBlacklist, 1, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("ASYM", "ASY", "USD", pathUSD, admin, bytes32("asym"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(alice, 1000);
        compoundToken.mint(charlie, 500);
        compoundToken.changeTransferPolicyId(asymmetricCompound);

        vm.stopPrank();

        // alice can send to charlie (charlie can receive)
        vm.prank(alice);
        compoundToken.transfer(charlie, 200);
        assertEq(compoundToken.balanceOf(charlie), 700);

        // charlie cannot send (blocked as sender)
        vm.prank(charlie);
        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.transfer(alice, 100) {
            revert("transfer should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }
    }

    function test_BurnBlocked_Succeeds_BlockedSender_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(senderBlacklist, charlie, true);

        uint64 asymmetricCompound = registry.createCompoundPolicy(senderBlacklist, 1, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("BURN1", "BRN1", "USD", pathUSD, admin, bytes32("burn1"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(charlie, 1000);
        compoundToken.changeTransferPolicyId(asymmetricCompound);

        compoundToken.burnBlocked(charlie, 500);
        assertEq(compoundToken.balanceOf(charlie), 500);

        vm.stopPrank();
    }

    function test_BurnBlocked_Fails_AuthorizedSender_CompoundPolicy() public {
        vm.startPrank(admin);

        uint64 senderBlacklist = registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        // alice is NOT blacklisted, so she's authorized as sender

        uint64 asymmetricCompound = registry.createCompoundPolicy(senderBlacklist, 1, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("BURN2", "BRN2", "USD", pathUSD, admin, bytes32("burn2"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(alice, 1000);
        compoundToken.changeTransferPolicyId(asymmetricCompound);

        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.burnBlocked(alice, 500) {
            revert("burnBlocked should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }

        vm.stopPrank();
    }

    function test_BurnBlocked_ChecksCorrectSubPolicy() public {
        vm.startPrank(admin);

        // Create compound where only recipient is blocked, sender is allowed
        uint64 recipientBlacklist =
            registry.createPolicy(admin, ITIP403Registry.PolicyType.BLACKLIST);
        registry.modifyPolicyBlacklist(recipientBlacklist, charlie, true);

        uint64 recipientBlockedCompound = registry.createCompoundPolicy(1, recipientBlacklist, 1);

        ITIP20Token compoundToken = ITIP20Token(
            factory.createToken("BURN3", "BRN3", "USD", pathUSD, admin, bytes32("burn3"))
        );
        compoundToken.grantRole(_ISSUER_ROLE, admin);
        compoundToken.grantRole(_BURN_BLOCKED_ROLE, admin);
        compoundToken.changeTransferPolicyId(1);
        compoundToken.mint(charlie, 1000);
        compoundToken.changeTransferPolicyId(recipientBlockedCompound);

        // charlie is blocked as recipient but NOT as sender, so burnBlocked should fail
        // Use try/catch instead of vm.expectRevert() due to precompile call depth issues
        try compoundToken.burnBlocked(charlie, 500) {
            revert("burnBlocked should have reverted");
        } catch (bytes memory err) {
            assertEq(bytes4(err), ITIP20.PolicyForbids.selector);
        }

        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                          EIP-2612 PERMIT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @dev Helper to build the EIP-712 digest for a permit call
    function _permitDigest(
        address owner_,
        address spender_,
        uint256 value_,
        uint256 nonce_,
        uint256 deadline_
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 permitTypeHash = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );
        bytes32 structHash =
            keccak256(abi.encode(permitTypeHash, owner_, spender_, value_, nonce_, deadline_));
        return keccak256(abi.encodePacked("\x19\x01", token.DOMAIN_SEPARATOR(), structHash));
    }

    function test_Permit() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        address signer = vm.addr(SIGNER_KEY);
        uint256 value = 500e18;
        uint256 deadline = block.timestamp + 1 hours;

        // Mint tokens so signer has a balance (not strictly required for approve, but realistic)
        vm.prank(admin);
        token.mint(signer, 1000e18);

        // Nonce starts at 0
        assertEq(token.nonces(signer), 0);

        bytes32 digest = _permitDigest(signer, bob, value, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);

        vm.expectEmit(true, true, true, true);
        emit Approval(signer, bob, value);

        token.permit(signer, bob, value, deadline, v, r, s);

        // Allowance reflects new value
        assertEq(token.allowance(signer, bob), value);
        // Nonce incremented
        assertEq(token.nonces(signer), 1);
    }

    function test_Permit_OverridesExistingAllowance() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        address signer = vm.addr(SIGNER_KEY);
        uint256 deadline = block.timestamp + 1 hours;

        // Set initial allowance via approve
        vm.prank(signer);
        token.approve(bob, 100e18);
        assertEq(token.allowance(signer, bob), 100e18);

        // Permit overrides to 50e18
        bytes32 digest = _permitDigest(signer, bob, 50e18, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);

        token.permit(signer, bob, 50e18, deadline, v, r, s);

        assertEq(token.allowance(signer, bob), 50e18);
    }

    function test_Permit_Replay() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        address signer = vm.addr(SIGNER_KEY);
        uint256 value = 500e18;
        uint256 deadline = block.timestamp + 1 hours;

        bytes32 digest = _permitDigest(signer, bob, value, 0, deadline);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);

        // First call succeeds
        token.permit(signer, bob, value, deadline, v, r, s);
        assertEq(token.nonces(signer), 1);

        // Replay fails — nonce already consumed
        try token.permit(signer, bob, value, deadline, v, r, s) {
            revert CallShouldHaveReverted();
        } catch (bytes memory err) {
            assertEq(err, abi.encodeWithSelector(ITIP20.InvalidSignature.selector));
        }

        // Nonce unchanged after failed replay
        assertEq(token.nonces(signer), 1);
    }

    function test_Permit_Fail() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        address signer = vm.addr(SIGNER_KEY);
        uint256 value = 500e18;

        // 1. Expired deadline
        {
            uint256 expiredDeadline = block.timestamp - 1;
            bytes32 digest = _permitDigest(signer, bob, value, 0, expiredDeadline);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);

            try token.permit(signer, bob, value, expiredDeadline, v, r, s) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(ITIP20.PermitExpired.selector));
            }
            assertEq(token.nonces(signer), 0);
        }

        // 2. Invalid signature (garbage bytes)
        {
            uint256 deadline = block.timestamp + 1 hours;

            try token.permit(signer, bob, value, deadline, 27, bytes32("bad_r"), bytes32("bad_s")) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(ITIP20.InvalidSignature.selector));
            }
            assertEq(token.nonces(signer), 0);
        }

        // 3. Wrong signer (bob signs a permit claiming owner = signer)
        {
            uint256 deadline = block.timestamp + 1 hours;
            bytes32 digest = _permitDigest(signer, bob, value, 0, deadline);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(WRONG_KEY, digest);

            try token.permit(signer, bob, value, deadline, v, r, s) {
                revert CallShouldHaveReverted();
            } catch (bytes memory err) {
                assertEq(err, abi.encodeWithSelector(ITIP20.InvalidSignature.selector));
            }
            assertEq(token.nonces(signer), 0);
        }
    }

    function test_Nonces() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        address signer = vm.addr(SIGNER_KEY);
        uint256 deadline = block.timestamp + 1 hours;

        assertEq(token.nonces(signer), 0);

        // First permit: nonce 0 → 1
        bytes32 digest0 = _permitDigest(signer, bob, 100e18, 0, deadline);
        (uint8 v0, bytes32 r0, bytes32 s0) = vm.sign(SIGNER_KEY, digest0);
        token.permit(signer, bob, 100e18, deadline, v0, r0, s0);
        assertEq(token.nonces(signer), 1);

        // Second permit: nonce 1 → 2
        bytes32 digest1 = _permitDigest(signer, charlie, 200e18, 1, deadline);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(SIGNER_KEY, digest1);
        token.permit(signer, charlie, 200e18, deadline, v1, r1, s1);
        assertEq(token.nonces(signer), 2);
    }

    function test_DomainSeparator() public {
        vm.skip(true); // TODO: skip for Tempo for now, reenable after tempo-foundry deps bumped
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(token.name())),
                keccak256(bytes("1")),
                block.chainid,
                address(token)
            )
        );
        assertEq(token.DOMAIN_SEPARATOR(), expected);
    }

}
