// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Vm } from "forge-std/Vm.sol";

import { TempoTransactionInvariantTest } from "./TempoTransactionInvariant.t.sol";
import { DelegatedWallet } from "./helpers/DelegatedWallet.sol";
import { TxBuilder } from "./helpers/TxBuilder.sol";

import { VmExecuteTransaction, VmRlp } from "tempo-std/StdVm.sol";
import {
    Eip7702Authorization,
    Eip7702Transaction,
    Eip7702TransactionLib
} from "tempo-std/tx/Eip7702TransactionLib.sol";

/// @title Tempo Transaction Invariant Tests (All Actors EIP-7702 Delegated)
/// @notice Runs the exact same ~70 handlers as TempoTransactionInvariantTest, but with
///         all secp256k1 actors delegated to a DelegatedWallet implementation via EIP-7702.
/// @dev This tests that having code at an EOA's address (via delegation) does not break
///      any existing invariants: nonce management, fee collection, access keys, CREATE
///      operations, replay protection, etc.
contract TempoTransactionInvariantDelegatedTest is TempoTransactionInvariantTest {

    using Eip7702TransactionLib for Eip7702Transaction;

    DelegatedWallet public walletImpl;

    function setUp() public override {
        super.setUp();

        // Deploy the wallet implementation
        walletImpl = new DelegatedWallet();

        // Delegate all secp256k1 actors to the wallet implementation via EIP-7702
        vm.coinbase(validator);
        for (uint256 i = 0; i < actors.length; i++) {
            _delegateActor(i);
        }
    }

    /// @notice Delegate a single actor to the wallet implementation using an EIP-7702 tx
    /// @dev The actor signs both the authorization (to set delegation) and the tx itself.
    ///      This consumes the actor's protocol nonce for the tx, and the authorization
    ///      consumes one nonce as well (same account, so net effect = +1 nonce for the tx).
    function _delegateActor(uint256 actorIdx) internal {
        address actor = actors[actorIdx];
        uint256 pk = actorKeys[actorIdx];

        uint64 currentNonce = uint64(ghost_protocolNonce[actor]);

        // Sign the authorization: actor authorizes delegation to walletImpl
        // When authority == sender, the tx nonce is validated and incremented first,
        // so the auth nonce must be currentNonce + 1 to match the authority's nonce
        // at authorization processing time.
        uint64 authNonce = currentNonce + 1;
        bytes32 authHash = Eip7702TransactionLib.computeAuthorizationHash(
            block.chainid, address(walletImpl), authNonce
        );
        (uint8 authV, bytes32 authR, bytes32 authS) = vm.sign(pk, authHash);
        uint8 authYParity = authV >= 27 ? authV - 27 : authV;

        Eip7702Authorization[] memory auths = new Eip7702Authorization[](1);
        auths[0] = Eip7702Authorization({
            chainId: block.chainid,
            codeAddress: address(walletImpl),
            nonce: authNonce,
            yParity: authYParity,
            r: authR,
            s: authS
        });

        // Build the EIP-7702 tx (self-signed, no-op call to self)
        // The authorization nonce consumption bumps the nonce before tx validation,
        // so the tx nonce must account for this. We use currentNonce and let the
        // protocol sort out ordering; if it fails, we sync from chain.
        Eip7702Transaction memory tx_ = Eip7702TransactionLib.create().withNonce(currentNonce)
            .withMaxPriorityFeePerGas(10).withMaxFeePerGas(100).withGasLimit(1_000_000)
            .withTo(actor).withAuthorizationList(auths);

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, txHash);
        bytes memory signedTx = tx_.encodeWithSignature(vmRlp, v, r, s);

        try vmExec.executeTransaction(signedTx) {
            // Sync ghost nonce from chain (delegation may consume auth nonce + tx nonce)
            uint256 actualNonce = vm.getNonce(actor);
            uint256 nonceDelta = actualNonce - ghost_protocolNonce[actor];
            ghost_protocolNonce[actor] = actualNonce;
            ghost_totalProtocolNonceTxs += nonceDelta;

            require(
                actor.code.length > 0,
                string(
                    abi.encodePacked(
                        "7702 delegation failed: no code at actor ", vm.toString(actorIdx)
                    )
                )
            );
        } catch (bytes memory reason) {
            // Sync nonce even on failure (protocol may have consumed it)
            uint256 actualNonce = vm.getNonce(actor);
            if (actualNonce > ghost_protocolNonce[actor]) {
                uint256 nonceDelta = actualNonce - ghost_protocolNonce[actor];
                ghost_protocolNonce[actor] = actualNonce;
                ghost_totalProtocolNonceTxs += nonceDelta;
            }

            revert(
                string(
                    abi.encodePacked(
                        "7702 delegation tx failed for actor ", vm.toString(actorIdx), ": ", reason
                    )
                )
            );
        }
    }

}
