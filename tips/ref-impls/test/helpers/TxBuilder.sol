// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

import { Vm } from "forge-std/Vm.sol";
import { VmRlp } from "tempo-std/StdVm.sol";
import { LegacyTransaction, LegacyTransactionLib } from "tempo-std/tx/LegacyTransactionLib.sol";
import {
    TempoAuthorization,
    TempoCall,
    TempoTransaction,
    TempoTransactionLib
} from "tempo-std/tx/TempoTransactionLib.sol";
import { TxRlp } from "tempo-std/tx/TxRlp.sol";

/// @title TxBuilder - Transaction Building Library
/// @dev Used by invariant tests to construct transactions for vm.executeTransaction
library TxBuilder {

    using LegacyTransactionLib for LegacyTransaction;
    using TempoTransactionLib for TempoTransaction;

    // ============ Default Transaction Parameters ============

    uint64 constant DEFAULT_GAS_LIMIT = 100_000;
    uint64 constant DEFAULT_CREATE_GAS_LIMIT = 1_500_000;
    uint256 constant DEFAULT_GAS_PRICE = 100;
    uint64 constant GAS_LIMIT_BUFFER = 100_000;

    // ============ EVM Gas Constants ============

    uint64 constant TX_BASE_COST = 21_000;
    uint64 constant COLD_ACCOUNT_ACCESS = 2600;
    uint64 constant CALLDATA_ZERO_BYTE = 4;
    uint64 constant CALLDATA_NONZERO_BYTE = 16;
    uint64 constant INITCODE_WORD_COST = 2;
    uint64 constant ACCESS_LIST_ADDR_COST = 2400;
    uint64 constant ACCESS_LIST_SLOT_COST = 1900;
    uint64 constant ECRECOVER_GAS = 3000;
    uint64 constant P256_EXTRA_GAS = 5000;
    uint64 constant KEY_AUTH_BASE_GAS = 27_000;
    uint64 constant KEY_AUTH_PER_LIMIT_GAS = 22_000;

    // ============ TIP-1000 Gas Constants (Hardfork: T1) ============

    uint64 constant ACCOUNT_CREATION_COST = 250_000; // nonce 0→1
    uint64 constant STATE_CREATION_COST = 250_000; // SSTORE zero→non-zero
    uint64 constant CREATE_BASE_COST = 500_000; // CREATE/CREATE2 base
    uint64 constant CODE_DEPOSIT_COST = 1000; // per byte
    uint64 constant CREATE_FIELDS_COST = 500_000; // keccak + codesize (2 × 250,000)

    // ============ Gas Calculation Helpers ============

    /// @notice Calculate calldata gas cost (4 per zero byte, 16 per non-zero)
    function calldataGas(bytes memory data) internal pure returns (uint64 gas) {
        for (uint256 i = 0; i < data.length; i++) {
            gas += data[i] == 0 ? CALLDATA_ZERO_BYTE : CALLDATA_NONZERO_BYTE;
        }
    }

    /// @notice Calculate initcode gas cost (2 gas per 32-byte word)
    function initcodeGas(bytes memory initcode) internal pure returns (uint64) {
        return uint64(((initcode.length + 31) / 32) * INITCODE_WORD_COST);
    }

    /// @notice Calculate CREATE intrinsic gas (TIP-1000)
    /// @param initcode The contract creation bytecode
    /// @param nonce The sender's current nonce (0 = first tx, account creation cost applies)
    function createGas(bytes memory initcode, uint64 nonce) internal pure returns (uint64) {
        uint64 gas = TX_BASE_COST + CREATE_BASE_COST;

        if (nonce == 0) {
            gas += ACCOUNT_CREATION_COST;
        }

        gas += calldataGas(initcode);
        gas += initcodeGas(initcode);

        return gas;
    }

    /// @notice Calculate CALL intrinsic gas (TIP-1000)
    /// @param data The calldata
    /// @param nonce The sender's current nonce (0 = first tx, account creation cost applies)
    function callGas(bytes memory data, uint64 nonce) internal pure returns (uint64) {
        uint64 gas = TX_BASE_COST;

        if (nonce == 0) {
            gas += ACCOUNT_CREATION_COST;
        }

        gas += calldataGas(data);

        return gas;
    }

    /// @notice Estimate gas for multicall (TIP-1000)
    /// @param calls The calls in the batch
    /// @param nonce The sender's current nonce (0 = first tx, account creation cost applies)
    function multicallGas(TempoCall[] memory calls, uint64 nonce) internal pure returns (uint64) {
        uint64 gas = TX_BASE_COST;

        if (nonce == 0) {
            gas += ACCOUNT_CREATION_COST;
        }

        for (uint256 i = 0; i < calls.length; i++) {
            gas += calldataGas(calls[i].data);
        }

        return gas;
    }

    uint8 constant SIGNATURE_TYPE_P256 = 0x01;
    uint8 constant SIGNATURE_TYPE_WEBAUTHN = 0x02;
    uint8 constant SIGNATURE_TYPE_KEYCHAIN = 0x03;

    uint256 constant P256_ORDER =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant P256N_HALF =
        0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;

    // ============ Signing Strategy ============

    enum SigningStrategy {
        Secp256k1,
        P256,
        WebAuthn,
        KeychainSecp256k1,
        KeychainP256
    }

    struct SigningParams {
        SigningStrategy strategy;
        uint256 privateKey;
        bytes32 pubKeyX; // For P256/WebAuthn
        bytes32 pubKeyY; // For P256/WebAuthn
        address userAddress; // For Keychain strategies
    }

    // ============ Legacy Transactions with Secp256k1 ============

    /// @notice Build and sign a legacy CALL transaction with secp256k1
    function buildLegacyCall(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        LegacyTransaction memory tx_ = LegacyTransactionLib.create().withNonce(nonce)
            .withGasPrice(DEFAULT_GAS_PRICE).withGasLimit(callGas(data, nonce) + GAS_LIMIT_BUFFER)
            .withTo(to).withData(data);

        return _signLegacy(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build and sign a legacy CALL transaction with custom gas limit
    function buildLegacyCallWithGas(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonce,
        uint64 gasLimit,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        LegacyTransaction memory tx_ = LegacyTransactionLib.create().withNonce(nonce)
            .withGasPrice(DEFAULT_GAS_PRICE).withGasLimit(gasLimit).withTo(to).withData(data);

        return _signLegacy(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build and sign a legacy CREATE transaction
    function buildLegacyCreate(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        uint64 nonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        LegacyTransaction memory tx_ = LegacyTransactionLib.create().withNonce(nonce)
            .withGasPrice(DEFAULT_GAS_PRICE)
            .withGasLimit(createGas(initcode, nonce) + GAS_LIMIT_BUFFER).withTo(address(0))
            .withData(initcode);

        return _signLegacy(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build and sign a legacy CREATE transaction with custom gas limit
    function buildLegacyCreateWithGas(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        uint64 nonce,
        uint64 gasLimit,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        LegacyTransaction memory tx_ = LegacyTransactionLib.create().withNonce(nonce)
            .withGasPrice(DEFAULT_GAS_PRICE).withGasLimit(gasLimit).withTo(address(0))
            .withData(initcode);

        return _signLegacy(vmRlp, vm, tx_, privateKey);
    }

    // ============ Tempo Transactions with Secp256k1 ============

    /// @notice Build and sign a Tempo single-call transaction with secp256k1
    function buildTempoCall(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: to, value: 0, data: data });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(callGas(data, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build and sign a Tempo multi-call transaction with secp256k1
    function buildTempoMultiCall(
        VmRlp vmRlp,
        Vm vm,
        TempoCall[] memory calls,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        uint64 gasLimit = multicallGas(calls, txNonce) + GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    // ============ Tempo Transactions with P256 ============

    /// @notice Build and sign a Tempo single-call transaction with P256 signature
    function buildTempoCallP256(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: to, value: 0, data: data });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(callGas(data, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoP256(vmRlp, vm, tx_, p256PrivateKey, pubKeyX, pubKeyY);
    }

    /// @notice Build and sign a Tempo multi-call transaction with P256 signature
    function buildTempoMultiCallP256(
        VmRlp vmRlp,
        Vm vm,
        TempoCall[] memory calls,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        uint64 gasLimit = multicallGas(calls, txNonce) + GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoP256(vmRlp, vm, tx_, p256PrivateKey, pubKeyX, pubKeyY);
    }

    // ============ Tempo Transactions with WebAuthn ============

    /// @notice Build and sign a Tempo single-call transaction with WebAuthn signature
    function buildTempoCallWebAuthn(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: to, value: 0, data: data });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(callGas(data, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoWebAuthn(vmRlp, vm, tx_, p256PrivateKey, pubKeyX, pubKeyY);
    }

    /// @notice Build and sign a Tempo multi-call transaction with WebAuthn signature
    function buildTempoMultiCallWebAuthn(
        VmRlp vmRlp,
        Vm vm,
        TempoCall[] memory calls,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        uint64 gasLimit = multicallGas(calls, txNonce) + GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoWebAuthn(vmRlp, vm, tx_, p256PrivateKey, pubKeyX, pubKeyY);
    }

    // ============ Tempo Transactions with Keychain ============

    /// @notice Build and sign a Tempo single-call transaction with Keychain signature (secp256k1 access key)
    function buildTempoCallKeychain(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 accessKeyPrivateKey,
        address userAddress
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: to, value: 0, data: data });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(callGas(data, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoKeychain(vmRlp, vm, tx_, accessKeyPrivateKey, userAddress);
    }

    /// @notice Build and sign a Tempo multi-call transaction with Keychain signature
    function buildTempoMultiCallKeychain(
        VmRlp vmRlp,
        Vm vm,
        TempoCall[] memory calls,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 accessKeyPrivateKey,
        address userAddress
    ) internal view returns (bytes memory) {
        uint64 gasLimit =
            multicallGas(calls, txNonce) + GAS_LIMIT_BUFFER;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoKeychain(vmRlp, vm, tx_, accessKeyPrivateKey, userAddress);
    }

    /// @notice Build and sign a Tempo single-call transaction with Keychain P256 signature
    function buildTempoCallKeychainP256(
        VmRlp vmRlp,
        Vm vm,
        address to,
        bytes memory data,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 accessKeyP256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        address userAddress
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: to, value: 0, data: data });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(callGas(data, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempoKeychainP256(
            vmRlp, vm, tx_, accessKeyP256PrivateKey, pubKeyX, pubKeyY, userAddress
        );
    }

    // ============ Tempo CREATE Transactions ============

    /// @notice Build and sign a Tempo CREATE transaction (CREATE as first call with to=0)
    function buildTempoCreate(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: address(0), value: 0, data: initcode });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(createGas(initcode, txNonce) + GAS_LIMIT_BUFFER).withCalls(calls)
            .withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build and sign a Tempo CREATE transaction with custom gas limit
    function buildTempoCreateWithGas(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        uint64 nonceKey,
        uint64 txNonce,
        uint64 gasLimit,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: address(0), value: 0, data: initcode });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build Tempo multicall with CREATE as second call (invalid - C1)
    function buildTempoCreateNotFirst(
        VmRlp vmRlp,
        Vm vm,
        address callTarget,
        bytes memory callData,
        bytes memory initcode,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({ to: callTarget, value: 0, data: callData });
        calls[1] = TempoCall({ to: address(0), value: 0, data: initcode }); // CREATE as second call

        // Mixed CALL + CREATE: use createGas for the CREATE + buffer for the CALL
        uint64 gasLimit = createGas(initcode, txNonce) + GAS_LIMIT_BUFFER + DEFAULT_GAS_LIMIT;

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(gasLimit).withCalls(calls).withNonceKey(nonceKey).withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build Tempo multicall with two CREATEs (invalid - C2)
    function buildTempoMultipleCreates(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode1,
        bytes memory initcode2,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](2);
        calls[0] = TempoCall({ to: address(0), value: 0, data: initcode1 }); // First CREATE
        calls[1] = TempoCall({ to: address(0), value: 0, data: initcode2 }); // Second CREATE

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(DEFAULT_CREATE_GAS_LIMIT * 2).withCalls(calls).withNonceKey(nonceKey)
            .withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build Tempo CREATE with value > 0 (invalid for Tempo - C4)
    function buildTempoCreateWithValue(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        uint256 value,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: address(0), value: value, data: initcode });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(DEFAULT_CREATE_GAS_LIMIT).withCalls(calls).withNonceKey(nonceKey)
            .withNonce(txNonce);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    /// @notice Build Tempo CREATE with authorization list (invalid - C3)
    function buildTempoCreateWithAuthList(
        VmRlp vmRlp,
        Vm vm,
        bytes memory initcode,
        TempoAuthorization[] memory authList,
        uint64 nonceKey,
        uint64 txNonce,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        TempoCall[] memory calls = new TempoCall[](1);
        calls[0] = TempoCall({ to: address(0), value: 0, data: initcode });

        TempoTransaction memory tx_ = TempoTransactionLib.create()
            .withChainId(uint64(block.chainid)).withMaxFeePerGas(DEFAULT_GAS_PRICE)
            .withGasLimit(DEFAULT_CREATE_GAS_LIMIT).withCalls(calls).withNonceKey(nonceKey)
            .withNonce(txNonce).withAuthorizationList(authList);

        return _signTempo(vmRlp, vm, tx_, privateKey);
    }

    // ============ Internal Helpers - Legacy Signing ============

    function _signLegacy(VmRlp vmRlp, Vm vm, LegacyTransaction memory tx_, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        return signLegacy(
            vmRlp,
            vm,
            tx_,
            SigningParams(SigningStrategy.Secp256k1, privateKey, bytes32(0), bytes32(0), address(0))
        );
    }

    function _signTempo(VmRlp vmRlp, Vm vm, TempoTransaction memory tx_, uint256 privateKey)
        internal
        view
        returns (bytes memory)
    {
        return signTempo(
            vmRlp,
            vm,
            tx_,
            SigningParams(SigningStrategy.Secp256k1, privateKey, bytes32(0), bytes32(0), address(0))
        );
    }

    // ============ Unified Signing (Internal) ============

    /// @dev Create signature bytes for any strategy
    function _createSignature(Vm vm, bytes32 txHash, SigningParams memory params)
        internal
        view
        returns (bytes memory)
    {
        if (params.strategy == SigningStrategy.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.privateKey, txHash);
            return abi.encodePacked(r, s, v);
        } else if (params.strategy == SigningStrategy.P256) {
            return
                _createP256Signature(vm, txHash, params.privateKey, params.pubKeyX, params.pubKeyY);
        } else if (params.strategy == SigningStrategy.WebAuthn) {
            return _createWebAuthnSignature(
                vm, txHash, params.privateKey, params.pubKeyX, params.pubKeyY
            );
        } else if (params.strategy == SigningStrategy.KeychainSecp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.privateKey, txHash);
            bytes memory innerSig = abi.encodePacked(r, s, v);
            return abi.encodePacked(SIGNATURE_TYPE_KEYCHAIN, params.userAddress, innerSig);
        } else {
            // KeychainP256
            bytes memory innerSig =
                _createP256Signature(vm, txHash, params.privateKey, params.pubKeyX, params.pubKeyY);
            return abi.encodePacked(SIGNATURE_TYPE_KEYCHAIN, params.userAddress, innerSig);
        }
    }

    function _createP256Signature(
        Vm vm,
        bytes32 txHash,
        uint256 privateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, txHash);
        s = _normalizeP256S(s);
        return abi.encodePacked(SIGNATURE_TYPE_P256, r, s, pubKeyX, pubKeyY, uint8(0));
    }

    function _createWebAuthnSignature(
        Vm vm,
        bytes32 txHash,
        uint256 privateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        bytes memory webauthnData = _buildWebAuthnData(txHash);
        bytes memory authData = _slice(webauthnData, 0, 37);
        bytes memory clientDataJSON = _slice(webauthnData, 37, webauthnData.length - 37);
        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(clientDataJSON)));

        (bytes32 r, bytes32 s) = vm.signP256(privateKey, messageHash);
        s = _normalizeP256S(s);
        return abi.encodePacked(SIGNATURE_TYPE_WEBAUTHN, webauthnData, r, s, pubKeyX, pubKeyY);
    }

    /// @notice Sign a legacy tx with unified params (only secp256k1 supported)
    function signLegacy(
        VmRlp vmRlp,
        Vm vm,
        LegacyTransaction memory tx_,
        SigningParams memory params
    ) internal view returns (bytes memory) {
        require(
            params.strategy == SigningStrategy.Secp256k1,
            "Legacy transactions only support secp256k1 signatures"
        );

        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.privateKey, txHash);
        return tx_.encodeWithSignature(vmRlp, v, r, s);
    }

    /// @notice Sign a tempo tx with unified params
    function signTempo(VmRlp vmRlp, Vm vm, TempoTransaction memory tx_, SigningParams memory params)
        internal
        view
        returns (bytes memory)
    {
        bytes memory unsignedTx = tx_.encode(vmRlp);
        bytes32 txHash = keccak256(unsignedTx);

        if (params.strategy == SigningStrategy.Secp256k1) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(params.privateKey, txHash);
            return tx_.encodeWithSignature(vmRlp, v, r, s);
        }

        bytes memory signature = _createSignature(vm, txHash, params);
        return _encodeSignedTempo(vmRlp, tx_, signature);
    }

    // ============ Legacy Internal Helpers (for backward compat) ============

    function _signTempoP256(
        VmRlp vmRlp,
        Vm vm,
        TempoTransaction memory tx_,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        return signTempo(
            vmRlp,
            vm,
            tx_,
            SigningParams(SigningStrategy.P256, p256PrivateKey, pubKeyX, pubKeyY, address(0))
        );
    }

    function _signTempoWebAuthn(
        VmRlp vmRlp,
        Vm vm,
        TempoTransaction memory tx_,
        uint256 p256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY
    ) internal view returns (bytes memory) {
        return signTempo(
            vmRlp,
            vm,
            tx_,
            SigningParams(SigningStrategy.WebAuthn, p256PrivateKey, pubKeyX, pubKeyY, address(0))
        );
    }

    function _signTempoKeychain(
        VmRlp vmRlp,
        Vm vm,
        TempoTransaction memory tx_,
        uint256 accessKeyPrivateKey,
        address userAddress
    ) internal view returns (bytes memory) {
        return signTempo(
            vmRlp,
            vm,
            tx_,
            SigningParams(
                SigningStrategy.KeychainSecp256k1,
                accessKeyPrivateKey,
                bytes32(0),
                bytes32(0),
                userAddress
            )
        );
    }

    function _signTempoKeychainP256(
        VmRlp vmRlp,
        Vm vm,
        TempoTransaction memory tx_,
        uint256 accessKeyP256PrivateKey,
        bytes32 pubKeyX,
        bytes32 pubKeyY,
        address userAddress
    ) internal view returns (bytes memory) {
        return signTempo(
            vmRlp,
            vm,
            tx_,
            SigningParams(
                SigningStrategy.KeychainP256, accessKeyP256PrivateKey, pubKeyX, pubKeyY, userAddress
            )
        );
    }

    /// @notice Encode a signed Tempo transaction with arbitrary signature bytes
    function _encodeSignedTempo(VmRlp vmRlp, TempoTransaction memory tx_, bytes memory signature)
        internal
        pure
        returns (bytes memory)
    {
        // 13 or 14 tx fields + 1 signature field
        uint256 fieldCount = tx_.hasKeyAuthorization ? 15 : 14;
        bytes[] memory fields = new bytes[](fieldCount);

        // Encode all transaction fields (same as unsigned)
        fields[0] = TxRlp.encodeString(TxRlp.encodeUint(tx_.chainId));
        fields[1] = TxRlp.encodeString(TxRlp.encodeUint(tx_.maxPriorityFeePerGas));
        fields[2] = TxRlp.encodeString(TxRlp.encodeUint(tx_.maxFeePerGas));
        fields[3] = TxRlp.encodeString(TxRlp.encodeUint(tx_.gasLimit));
        fields[4] = TempoTransactionLib.encodeCalls(vmRlp, tx_.calls);
        fields[5] = TempoTransactionLib.encodeAccessList(vmRlp, tx_.accessList);
        fields[6] = TxRlp.encodeString(TxRlp.encodeUint(tx_.nonceKey));
        fields[7] = TxRlp.encodeString(TxRlp.encodeUint(tx_.nonce));
        fields[8] = TxRlp.encodeString(
            tx_.hasValidBefore ? TxRlp.encodeUint(tx_.validBefore) : TxRlp.encodeNone()
        );
        fields[9] = TxRlp.encodeString(
            tx_.hasValidAfter ? TxRlp.encodeUint(tx_.validAfter) : TxRlp.encodeNone()
        );
        fields[10] = TxRlp.encodeString(
            tx_.hasFeeToken ? TxRlp.encodeAddress(tx_.feeToken) : TxRlp.encodeNone()
        );
        fields[11] = tx_.hasFeePayerSignature
            ? _encodeFeePayerSignature(tx_.feePayerSignature)
            : TxRlp.encodeString(TxRlp.encodeNone());
        fields[12] = TempoTransactionLib.encodeAuthorizationList(vmRlp, tx_.authorizationList);

        uint256 sigFieldIdx;
        if (tx_.hasKeyAuthorization) {
            fields[13] = TxRlp.encodeString(tx_.keyAuthorization);
            sigFieldIdx = 14;
        } else {
            sigFieldIdx = 13;
        }

        // Signature field: encoded as RLP bytes string
        fields[sigFieldIdx] = TxRlp.encodeString(signature);

        bytes memory rlpPayload = TxRlp.encodeRawList(fields);
        return abi.encodePacked(uint8(0x76), rlpPayload);
    }

    /// @notice Encodes fee payer signature as RLP list [r, s, v]
    function _encodeFeePayerSignature(bytes memory sig) private pure returns (bytes memory) {
        require(sig.length == 65, "Invalid fee payer signature length");

        // Parse signature: first 32 bytes = r, next 32 = s, last byte = v
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        // Encode as RLP list [r, s, v] matching Rust's write_rlp_vrs order
        bytes[] memory sigFields = new bytes[](3);
        sigFields[0] = TxRlp.encodeString(TxRlp.encodeBytes32(r));
        sigFields[1] = TxRlp.encodeString(TxRlp.encodeBytes32(s));
        sigFields[2] = TxRlp.encodeString(TxRlp.encodeUint(v));
        return TxRlp.encodeRawList(sigFields);
    }

    // ============ WebAuthn Helpers ============

    /// @notice Build WebAuthn data (authenticatorData || clientDataJSON)
    /// @dev authenticatorData: rpIdHash (32) || flags (1) || signCount (4) = 37 bytes
    function _buildWebAuthnData(bytes32 challenge) internal pure returns (bytes memory) {
        // rpIdHash: sha256 of origin (using dummy "localhost")
        bytes32 rpIdHash = sha256("localhost");

        // flags: UP (0x01) = user present
        uint8 flags = 0x01;

        // signCount: 4 bytes, using 0
        bytes4 signCount = bytes4(0);

        // authenticatorData: 37 bytes
        bytes memory authData = abi.encodePacked(rpIdHash, flags, signCount);

        // clientDataJSON: contains the challenge as base64url
        // Format: {"type":"webauthn.get","challenge":"<base64url>","origin":"https://localhost"}
        string memory challengeBase64 = _base64UrlEncode(abi.encodePacked(challenge));
        bytes memory clientDataJSON = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            challengeBase64,
            '","origin":"https://localhost"}'
        );

        return abi.encodePacked(authData, clientDataJSON);
    }

    /// @notice Base64url encode bytes (no padding)
    function _base64UrlEncode(bytes memory data) internal pure returns (string memory) {
        string memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        bytes memory tableBytes = bytes(table);

        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        bytes memory result = new bytes(encodedLen);

        uint256 resultIndex = 0;
        for (uint256 i = 0; i < data.length; i += 3) {
            uint256 a = uint8(data[i]);
            uint256 b = i + 1 < data.length ? uint8(data[i + 1]) : 0;
            uint256 c = i + 2 < data.length ? uint8(data[i + 2]) : 0;

            result[resultIndex++] = tableBytes[(a >> 2) & 0x3F];
            result[resultIndex++] = tableBytes[((a & 0x3) << 4) | ((b >> 4) & 0xF)];
            if (i + 1 < data.length) {
                result[resultIndex++] = tableBytes[((b & 0xF) << 2) | ((c >> 6) & 0x3)];
            }
            if (i + 2 < data.length) {
                result[resultIndex++] = tableBytes[c & 0x3F];
            }
        }

        // Trim to actual length (no padding)
        bytes memory trimmed = new bytes(resultIndex);
        for (uint256 i = 0; i < resultIndex; i++) {
            trimmed[i] = result[i];
        }

        return string(trimmed);
    }

    // ============ P256 Helpers ============

    /// @notice Normalize P256 s value to low-s form
    function _normalizeP256S(bytes32 s) internal pure returns (bytes32) {
        uint256 sVal = uint256(s);
        if (sVal > P256N_HALF) {
            return bytes32(P256_ORDER - sVal);
        }
        return s;
    }

    /// @notice Slice bytes array
    function _slice(bytes memory data, uint256 start, uint256 length)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }

    // ============ Address Computation ============

    /// @notice Compute CREATE address from sender and nonce
    /// @dev address = keccak256(rlp([sender, nonce]))[12:]
    function computeCreateAddress(address sender, uint256 nonce) internal pure returns (address) {
        bytes memory rlpEncoded;

        if (nonce == 0x00) {
            rlpEncoded = abi.encodePacked(bytes1(0xd6), bytes1(0x94), sender, bytes1(0x80));
        } else if (nonce <= 0x7f) {
            rlpEncoded = abi.encodePacked(bytes1(0xd6), bytes1(0x94), sender, uint8(nonce));
        } else if (nonce <= 0xff) {
            rlpEncoded =
                abi.encodePacked(bytes1(0xd7), bytes1(0x94), sender, bytes1(0x81), uint8(nonce));
        } else if (nonce <= 0xffff) {
            rlpEncoded =
                abi.encodePacked(bytes1(0xd8), bytes1(0x94), sender, bytes1(0x82), uint16(nonce));
        } else if (nonce <= 0xffffff) {
            rlpEncoded =
                abi.encodePacked(bytes1(0xd9), bytes1(0x94), sender, bytes1(0x83), uint24(nonce));
        } else {
            rlpEncoded =
                abi.encodePacked(bytes1(0xda), bytes1(0x94), sender, bytes1(0x84), uint32(nonce));
        }

        return address(uint160(uint256(keccak256(rlpEncoded))));
    }

    /// @notice Derive address from P256 public key
    /// @dev address = keccak256(pubKeyX || pubKeyY)[12:]
    function deriveP256Address(bytes32 pubKeyX, bytes32 pubKeyY) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(pubKeyX, pubKeyY)))));
    }

}
