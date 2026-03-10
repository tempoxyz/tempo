// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { TIP20 } from "../../src/TIP20.sol";
import { BaseTest } from "../BaseTest.t.sol";
import { ActorManager } from "./ActorManager.sol";
import { GhostState } from "./GhostState.sol";
import { TxBuilder } from "./TxBuilder.sol";
import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";

/// @title InvariantBase - Combined Base Contract for Invariant Tests
/// @notice Combines all helper functionality into a single base contract
/// @dev Inherit from this contract to write invariant tests
abstract contract InvariantBase is BaseTest, ActorManager, GhostState {

    using TxBuilder for *;

    // ============ Tempo VM Extensions ============

    VmRlp internal vmRlp = VmRlp(address(vm));
    VmExecuteTransaction internal vmExec = VmExecuteTransaction(address(vm));

    // ============ Test State ============

    /// @dev Fee token for testing
    TIP20 public feeToken;

    /// @dev Validator address for fee collection
    address public validator;

    /// @dev Storage slot constants for Nonce precompile
    uint256 private constant NONCES_SLOT = 0;

    // ============ Setup ============

    function setUp() public virtual override {
        super.setUp();

        // Initialize fee token
        feeToken = TIP20(
            factory.createToken("Fee Token", "FEE", "USD", pathUSD, admin, bytes32("feetoken"))
        );

        // Initialize actors
        _initActors();

        // Fund actors with fee tokens
        vm.startPrank(admin);
        feeToken.grantRole(_ISSUER_ROLE, admin);
        for (uint256 i = 0; i < actors.length; i++) {
            feeToken.mint(actors[i], 100_000_000e6);
        }
        vm.stopPrank();

        // Setup validator
        validator = makeAddr("validator");

        // Setup AMM liquidity for fee swaps
        _setupAmmLiquidity();
    }

    function _setupAmmLiquidity() internal {
        // Grant ISSUER_ROLE to admin on pathUSD (requires pathUSDAdmin)
        vm.prank(pathUSDAdmin);
        pathUSD.grantRole(_ISSUER_ROLE, admin);

        vm.startPrank(admin);
        // Mint tokens to admin first, then provide liquidity
        feeToken.mint(admin, 100_000_000e6);
        pathUSD.mint(admin, 100_000_000e6);
        // Approve the AMM to spend tokens
        feeToken.approve(address(amm), type(uint256).max);
        pathUSD.approve(address(amm), type(uint256).max);
        // Provide liquidity - AMM will transfer from admin
        amm.mint(address(feeToken), address(pathUSD), 50_000_000e6, admin);
        vm.stopPrank();

        vm.prank(validator, validator);
        amm.setValidatorToken(address(feeToken));
    }

    // ============ Transaction Execution Helpers ============

    /// @notice Execute a signed transaction and track results
    /// @return success Whether execution succeeded
    function _executeAndTrack(
        address sender,
        bytes memory signedTx,
        bool isCreate,
        uint256 createNonce
    )
        internal
        returns (bool success)
    {
        vm.coinbase(validator);

        try vmExec.executeTransaction(signedTx) {
            _updateProtocolNonce(sender);
            _recordTxSuccess();

            if (isCreate) {
                address deployed = TxBuilder.computeCreateAddress(sender, createNonce);
                _recordCreateSuccess(sender, createNonce, deployed);
            } else {
                _recordCallSuccess();
            }

            return true;
        } catch {
            // CREATE failure still burns nonce (per protocol)
            if (isCreate) {
                _updateProtocolNonce(sender);
            }
            _recordTxRevert();
            return false;
        }
    }

    // ============ 2D Nonce Storage Helpers ============

    /// @notice Increment 2D nonce via direct storage manipulation
    /// @dev Simulates protocol behavior for 2D nonces since vm.executeTransaction
    ///      doesn't support Tempo transactions
    function _incrementNonceViaStorage(
        address account,
        uint256 nonceKey
    )
        internal
        returns (uint64 newNonce)
    {
        require(nonceKey > 0, "Cannot increment protocol nonce (key 0)");

        bytes32 nonceSlot =
            keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, NONCES_SLOT))));

        uint64 currentNonce = uint64(uint256(vm.load(_NONCE, nonceSlot)));
        require(currentNonce < type(uint64).max, "Nonce overflow");

        newNonce = currentNonce + 1;
        vm.store(_NONCE, nonceSlot, bytes32(uint256(newNonce)));

        _update2dNonce(account, nonceKey);

        return newNonce;
    }

    /// @notice Get 2D nonce from storage
    function _getNonceFromStorage(address account, uint256 nonceKey)
        internal
        view
        returns (uint64)
    {
        if (nonceKey == 0) {
            return uint64(vm.getNonce(account));
        }

        bytes32 nonceSlot =
            keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, NONCES_SLOT))));
        return uint64(uint256(vm.load(_NONCE, nonceSlot)));
    }

    // ============ Access Key Helpers ============

    /// @notice Set the transaction key in AccountKeychain transient storage
    /// @dev Simulates the protocol setting transactionKey before tx execution
    function _setTransactionKey(address keyId) internal {
        // transient storage slot for _transactionKey in AccountKeychain
        // Since it's a transient variable, we need to use vm.store with the proper slot
        // The transient storage is at the end of regular storage
        bytes32 slot = bytes32(uint256(2)); // After keys (slot 0) and spendingLimits (slot 1)
        vm.store(_ACCOUNT_KEYCHAIN, slot, bytes32(uint256(uint160(keyId))));
    }

    // ============ Revert Reason Helpers ============

    /// @notice Decode an Error(string) revert reason into its message
    /// @param reason The raw revert bytes
    /// @return isErrorString Whether the reason is a valid Error(string)
    /// @return errorMessage The decoded error message (empty if not Error(string))
    function _tryDecodeErrorMessage(bytes memory reason)
        internal
        pure
        returns (bool isErrorString, string memory errorMessage)
    {
        if (reason.length < 4) return (false, "");
        if (bytes4(reason) != bytes4(keccak256("Error(string)"))) return (false, "");

        bytes memory payload = new bytes(reason.length - 4);
        for (uint256 i = 0; i < payload.length; i++) {
            payload[i] = reason[i + 4];
        }
        errorMessage = abi.decode(payload, (string));
        return (true, errorMessage);
    }

    // ============ Balance Helpers ============

    /// @notice Get fee token balance for an account
    function _getFeeTokenBalance(address account) internal view returns (uint256) {
        return feeToken.balanceOf(account);
    }

    /// @notice Transfer fee tokens between actors (for testing)
    function _transferFeeTokens(address from, address to, uint256 amount) internal {
        vm.prank(from);
        feeToken.transfer(to, amount);
    }

}
