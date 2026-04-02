// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { ISignatureVerifier } from "../../src/interfaces/ISignatureVerifier.sol";
import { BaseTest } from "../BaseTest.t.sol";

/// @title SignatureVerifier Invariant Tests
/// @notice Fuzz-based invariant tests for the TIP-1020 Signature Verification Precompile
/// @dev Tests invariants SV1-SV4, SV6, SV7 from the TIP-1020 spec. The precompile is
///      stateless, so each handler tests a specific property via direct calls.
///      SV5 (gas schedule) requires dedicated low-level gas tests and is NOT covered here.
/// forge-config: default.hardfork = "tempo:T3"
/// forge-config: ci.invariant.depth = 300
contract SignatureVerifierInvariantTest is BaseTest {

    address internal constant SIG_VERIFIER = 0x5165300000000000000000000000000000000000;

    uint256 internal constant P256_ORDER =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant P256N_HALF =
        0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8;
    uint256 internal constant _SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant _SECP256K1_N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    uint8 internal constant TYPE_P256 = 0x01;
    uint8 internal constant TYPE_WEBAUTHN = 0x02;
    uint8 internal constant TYPE_KEYCHAIN_SECP = 0x03;
    uint8 internal constant TYPE_KEYCHAIN_P256 = 0x04;

    ISignatureVerifier internal verifier = ISignatureVerifier(SIG_VERIFIER);

    uint256[] internal _secpKeys;
    address[] internal _secpAddrs;
    uint256[] internal _p256Keys;
    bytes32[] internal _p256PubX;
    bytes32[] internal _p256PubY;
    address[] internal _p256Addrs;

    // Coverage counters
    uint256 internal ghost_sv1_secpOk;
    uint256 internal ghost_sv1_p256Ok;
    uint256 internal ghost_sv1_webauthnOk;
    uint256 internal ghost_sv1_verifyWrongSignerOk;
    uint256 internal ghost_sv2_secpHighSRejected;
    uint256 internal ghost_sv2_p256HighSRejected;
    uint256 internal ghost_sv2_webauthnHighSRejected;
    uint256 internal ghost_sv3_sizeRejected;
    uint256 internal ghost_sv4_garbageRejected;
    uint256 internal ghost_sv4_ecrecoverDiffOk;
    uint256 internal ghost_sv6_unknownTypeRejected;
    uint256 internal ghost_sv7_keychainRejected;

    // Bug counters - must be 0
    uint256 internal ghost_sv1_mismatch;
    uint256 internal ghost_sv2_highSAllowed;
    uint256 internal ghost_sv3_badSizeAllowed;
    uint256 internal ghost_sv4_garbageAllowed;
    uint256 internal ghost_sv4_ecrecoverDiffFailed;
    uint256 internal ghost_sv4_wrongError;
    uint256 internal ghost_sv6_unknownTypeAllowed;
    uint256 internal ghost_sv7_keychainAllowed;

    function setUp() public override {
        super.setUp();

        targetContract(address(this));

        if (!isTempo) return;

        for (uint256 i = 0; i < 5; i++) {
            string memory label = string(abi.encodePacked("sv_secp_", vm.toString(i)));
            (address addr, uint256 pk) = makeAddrAndKey(label);
            _secpKeys.push(pk);
            _secpAddrs.push(addr);
        }

        for (uint256 i = 0; i < 5; i++) {
            string memory label = string(abi.encodePacked("sv_p256_", vm.toString(i)));
            uint256 pk = uint256(keccak256(abi.encodePacked("p256_", label))) % (P256_ORDER - 1);
            if (pk == 0) pk = 1;
            _p256Keys.push(pk);
            (uint256 pubX, uint256 pubY) = vm.publicKeyP256(pk);
            _p256PubX.push(bytes32(pubX));
            _p256PubY.push(bytes32(pubY));
            _p256Addrs.push(address(uint160(uint256(keccak256(abi.encodePacked(pubX, pubY))))));
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV1: DIFFERENTIAL VERIFICATION
    //////////////////////////////////////////////////////////////*/

    /// @notice SV1 (secp256k1): recover() matches ecrecover, verify() returns true
    function handler_sv1_secpRecoverAndVerify(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _secpKeys.length;
        address expected = _secpAddrs[idx];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_secpKeys[idx], hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        address ecRecovered = ecrecover(hash, v, r, s);
        try verifier.recover(hash, sig) returns (address recovered) {
            if (recovered != ecRecovered || recovered != expected) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }

        try verifier.verify(expected, hash, sig) returns (bool result) {
            if (!result) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }

        ghost_sv1_secpOk++;
    }

    /// @notice SV1 (secp256k1): v normalization - raw v (0/1) accepted
    function handler_sv1_secpVNormalization(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _secpKeys.length;
        address expected = _secpAddrs[idx];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_secpKeys[idx], hash);
        bytes memory rawSig = abi.encodePacked(r, s, uint8(v - 27));

        try verifier.recover(hash, rawSig) returns (address recovered) {
            if (recovered != expected) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }
        ghost_sv1_secpOk++;
    }

    /// @notice SV1 (P256): recover() + verify() match expected address
    function handler_sv1_p256RecoverAndVerify(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        bytes memory sig = _signP256(idx, hash);

        try verifier.recover(hash, sig) returns (address recovered) {
            if (recovered != _p256Addrs[idx]) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }

        try verifier.verify(_p256Addrs[idx], hash, sig) returns (bool result) {
            if (!result) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }
        ghost_sv1_p256Ok++;
    }

    /// @notice SV1 (WebAuthn): recover() + verify() match expected address
    function handler_sv1_webauthnRecoverAndVerify(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        bytes memory sig = _signWebAuthn(idx, hash);

        try verifier.recover(hash, sig) returns (address recovered) {
            if (recovered != _p256Addrs[idx]) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }

        try verifier.verify(_p256Addrs[idx], hash, sig) returns (bool result) {
            if (!result) {
                ghost_sv1_mismatch++;
                return;
            }
        } catch {
            ghost_sv1_mismatch++;
            return;
        }
        ghost_sv1_webauthnOk++;
    }

    /// @notice SV1: verify() with wrong signer returns false
    function handler_sv1_verifyWrongSigner(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _secpKeys.length;
        uint256 wrongIdx = (idx + 1) % _secpAddrs.length;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_secpKeys[idx], hash);
        bytes memory sig = abi.encodePacked(r, s, v);

        try verifier.verify(_secpAddrs[wrongIdx], hash, sig) returns (bool result) {
            if (result) {
                ghost_sv1_mismatch++;
            } else {
                ghost_sv1_verifyWrongSignerOk++;
            }
        } catch {
            ghost_sv1_verifyWrongSignerOk++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV2: MALLEABILITY RESISTANCE
    //////////////////////////////////////////////////////////////*/

    /// @notice SV2 (secp256k1): high-s must be rejected
    function handler_sv2_secpHighS(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _secpKeys.length;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_secpKeys[idx], hash);

        uint256 sVal = uint256(s);
        uint8 highV = v;
        if (sVal <= _SECP256K1_N_HALF) {
            sVal = _SECP256K1_N - sVal;
            highV = v == 27 ? uint8(28) : uint8(27);
        }
        bytes memory highSSig = abi.encodePacked(r, bytes32(sVal), highV);

        if (_callBothRevert(hash, highSSig, _secpAddrs[idx])) {
            ghost_sv2_highSAllowed++;
        } else {
            ghost_sv2_secpHighSRejected++;
        }
    }

    /// @notice SV2 (P256): high-s must be rejected
    function handler_sv2_p256HighS(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        (bytes32 r, bytes32 s) = vm.signP256(_p256Keys[idx], hash);

        uint256 sVal = uint256(s);
        if (sVal > P256N_HALF) sVal = P256_ORDER - sVal;
        uint256 highS = P256_ORDER - sVal;

        bytes memory highSSig = abi.encodePacked(
            TYPE_P256, r, bytes32(highS), _p256PubX[idx], _p256PubY[idx], uint8(0)
        );

        if (_callBothRevert(hash, highSSig, _p256Addrs[idx])) {
            ghost_sv2_highSAllowed++;
        } else {
            ghost_sv2_p256HighSRejected++;
        }
    }

    /// @notice SV2 (WebAuthn): high-s on inner P256 sig must be rejected
    function handler_sv2_webauthnHighS(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;

        bytes memory webauthnData = _buildWebAuthnData(hash);
        bytes memory authData = _slice(webauthnData, 0, 37);
        bytes memory clientDataJSON = _slice(webauthnData, 37, webauthnData.length - 37);
        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(clientDataJSON)));

        (bytes32 r, bytes32 s) = vm.signP256(_p256Keys[idx], messageHash);
        uint256 sVal = uint256(s);
        if (sVal > P256N_HALF) sVal = P256_ORDER - sVal;
        uint256 highS = P256_ORDER - sVal;

        bytes memory highSSig = abi.encodePacked(
            TYPE_WEBAUTHN, webauthnData, r, bytes32(highS), _p256PubX[idx], _p256PubY[idx]
        );

        if (_callBothRevert(hash, highSSig, _p256Addrs[idx])) {
            ghost_sv2_highSAllowed++;
        } else {
            ghost_sv2_webauthnHighSRejected++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV3: SIGNATURE SIZE ENFORCEMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice SV3: wrong-sized secp256k1 sigs revert
    function handler_sv3_secpBadSize(uint256 sizeSeed) external {
        if (!isTempo) return;
        uint256 size = bound(sizeSeed, 0, 200);
        if (size == 65) size = 66;

        bytes memory sig = new bytes(size);
        for (uint256 i = 0; i < size; i++) {
            sig[i] = bytes1(uint8(i + 1));
        }
        if (size > 0 && uint8(sig[0]) <= 0x04) sig[0] = 0x05;

        if (_callBothRevert(keccak256("sv3"), sig, address(0xdead))) {
            ghost_sv3_badSizeAllowed++;
        } else {
            ghost_sv3_sizeRejected++;
        }
    }

    /// @notice SV3: wrong-sized P256 sigs revert
    function handler_sv3_p256BadSize(uint256 sizeSeed) external {
        if (!isTempo) return;
        uint256 size = bound(sizeSeed, 1, 250);
        if (size == 130) size = 131;

        bytes memory sig = new bytes(size);
        sig[0] = bytes1(TYPE_P256);
        for (uint256 i = 1; i < size; i++) {
            sig[i] = bytes1(uint8(i));
        }

        if (_callBothRevert(keccak256("sv3"), sig, address(0xdead))) {
            ghost_sv3_badSizeAllowed++;
        } else {
            ghost_sv3_sizeRejected++;
        }
    }

    /// @notice SV3: wrong-sized WebAuthn sigs revert
    function handler_sv3_webauthnBadSize(uint256 sizeSeed) external {
        if (!isTempo) return;
        uint256 size;
        if (sizeSeed % 2 == 0) {
            size = bound(sizeSeed, 1, 128);
        } else {
            size = bound(sizeSeed, 2050, 3000);
        }

        bytes memory sig = new bytes(size);
        sig[0] = bytes1(TYPE_WEBAUTHN);
        for (uint256 i = 1; i < size; i++) {
            sig[i] = bytes1(uint8(i % 256));
        }

        if (_callBothRevert(keccak256("sv3"), sig, address(0xdead))) {
            ghost_sv3_badSizeAllowed++;
        } else {
            ghost_sv3_sizeRejected++;
        }
    }

    /// @notice SV3: zero-length input reverts
    function handler_sv3_emptyInput() external {
        if (!isTempo) return;
        if (_callBothRevert(keccak256("sv3"), new bytes(0), address(0xdead))) {
            ghost_sv3_badSizeAllowed++;
        } else {
            ghost_sv3_sizeRejected++;
        }
    }

    /// @notice SV3: oversized calldata (exceeding ABI-encoded max for verify) must revert
    function handler_sv3_oversizedCalldata(uint256 sizeSeed) external {
        if (!isTempo) return;
        // MAX_CALLDATA_LEN = 4 + 32*4 + ceil((2048+1)/32)*32 = 2212
        uint256 sigSize = bound(sizeSeed, 2050, 3000);
        bytes memory sig = new bytes(sigSize);
        sig[0] = bytes1(TYPE_WEBAUTHN);
        for (uint256 i = 1; i < sigSize; i++) {
            sig[i] = bytes1(uint8(i % 256));
        }

        if (_callBothRevert(keccak256("sv3"), sig, address(0xdead))) {
            ghost_sv3_badSizeAllowed++;
        } else {
            ghost_sv3_sizeRejected++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV4: REVERT ON FAILURE
    //////////////////////////////////////////////////////////////*/

    /// @notice SV4: garbage secp256k1 sigs revert
    function handler_sv4_garbageSecp(bytes32 garbageR, bytes32 garbageS, uint8 garbageV) external {
        if (!isTempo) return;
        garbageV = (garbageV % 2 == 0) ? 27 : 28;
        bytes memory sig = abi.encodePacked(garbageR, garbageS, garbageV);
        bytes32 hash = keccak256("sv4_secp");

        // Only test cases where ecrecover returns address(0) (truly invalid)
        address ecResult = ecrecover(hash, garbageV, garbageR, garbageS);
        if (ecResult != address(0)) return;

        if (_callBothRevert(hash, sig, address(0xdead))) {
            ghost_sv4_garbageAllowed++;
        } else {
            ghost_sv4_garbageRejected++;
        }
    }

    /// @notice SV4: garbage P256 sigs revert
    function handler_sv4_garbageP256(
        uint256 actorSeed,
        bytes32 garbageR,
        bytes32 garbageS
    )
        external
    {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        bytes memory sig = abi.encodePacked(
            TYPE_P256, garbageR, garbageS, _p256PubX[idx], _p256PubY[idx], uint8(0)
        );

        if (_callBothRevert(keccak256("sv4_p256"), sig, _p256Addrs[idx])) {
            ghost_sv4_garbageAllowed++;
        } else {
            ghost_sv4_garbageRejected++;
        }
    }

    /// @notice SV4: garbage WebAuthn sigs revert
    function handler_sv4_garbageWebAuthn(
        uint256 actorSeed,
        bytes32 garbageR,
        bytes32 garbageS
    )
        external
    {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        bytes32 hash = keccak256("sv4_webauthn");
        bytes memory webauthnData = _buildWebAuthnData(hash);
        bytes memory sig = abi.encodePacked(
            TYPE_WEBAUTHN, webauthnData, garbageR, garbageS, _p256PubX[idx], _p256PubY[idx]
        );

        if (_callBothRevert(hash, sig, _p256Addrs[idx])) {
            ghost_sv4_garbageAllowed++;
        } else {
            ghost_sv4_garbageRejected++;
        }
    }

    /// @notice SV4: ecrecover returns address(0) → precompile must revert (not return zero)
    function handler_sv4_ecrecoverDifferential(
        bytes32 hash,
        bytes32 fuzzR,
        bytes32 fuzzS,
        uint8 fuzzV
    )
        external
    {
        if (!isTempo) return;
        fuzzV = (fuzzV % 2 == 0) ? 27 : 28;

        address ecResult = ecrecover(hash, fuzzV, fuzzR, fuzzS);
        if (ecResult != address(0)) return;

        bytes memory sig = abi.encodePacked(fuzzR, fuzzS, fuzzV);
        bytes memory cd = abi.encodeCall(verifier.recover, (hash, sig));
        (bool ok,) = SIG_VERIFIER.staticcall(cd);

        if (ok) {
            ghost_sv4_ecrecoverDiffFailed++;
        } else {
            ghost_sv4_ecrecoverDiffOk++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV6: TYPE DISAMBIGUATION
    //////////////////////////////////////////////////////////////*/

    /// @notice SV6: unknown type prefix bytes revert
    function handler_sv6_unknownType(uint8 typeByte, uint256 sizeSeed) external {
        if (!isTempo) return;
        if (typeByte >= TYPE_P256 && typeByte <= TYPE_KEYCHAIN_P256) typeByte = 0x05;
        uint256 size = bound(sizeSeed, 66, 300);

        bytes memory sig = new bytes(size);
        sig[0] = bytes1(typeByte);
        for (uint256 i = 1; i < size; i++) {
            sig[i] = bytes1(uint8(i % 256));
        }

        if (_callBothRevert(keccak256("sv6"), sig, address(0xdead))) {
            ghost_sv6_unknownTypeAllowed++;
        } else {
            ghost_sv6_unknownTypeRejected++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                     SV7: KEYCHAIN REJECTION
    //////////////////////////////////////////////////////////////*/

    /// @notice SV7: 0x03 prefix (Keychain secp256k1) rejected with valid-looking envelope
    function handler_sv7_keychainSecp(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _secpKeys.length;
        address user = _secpAddrs[idx];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_secpKeys[idx], hash);
        bytes memory sig = abi.encodePacked(TYPE_KEYCHAIN_SECP, user, r, s, v);

        if (_callBothRevert(hash, sig, user)) {
            ghost_sv7_keychainAllowed++;
        } else {
            ghost_sv7_keychainRejected++;
        }
    }

    /// @notice SV7: 0x04 prefix (Keychain P256) rejected with valid-looking envelope
    function handler_sv7_keychainP256(uint256 actorSeed, bytes32 hash) external {
        if (!isTempo) return;
        uint256 idx = actorSeed % _p256Keys.length;
        (bytes32 r, bytes32 s) = vm.signP256(_p256Keys[idx], hash);
        s = _normalizeP256S(s);
        bytes memory sig = abi.encodePacked(
            TYPE_KEYCHAIN_P256,
            _p256Addrs[idx],
            TYPE_P256,
            r,
            s,
            _p256PubX[idx],
            _p256PubY[idx],
            uint8(0)
        );

        if (_callBothRevert(hash, sig, _p256Addrs[idx])) {
            ghost_sv7_keychainAllowed++;
        } else {
            ghost_sv7_keychainRejected++;
        }
    }

    /*//////////////////////////////////////////////////////////////
                        MASTER INVARIANT
    //////////////////////////////////////////////////////////////*/

    function invariant_signatureVerifier() public view {
        assertEq(ghost_sv1_mismatch, 0, "SV1: recover/verify mismatch");
        assertEq(ghost_sv2_highSAllowed, 0, "SV2: high-s signature was accepted");
        assertEq(ghost_sv3_badSizeAllowed, 0, "SV3: wrong-sized signature was accepted");
        assertEq(ghost_sv4_garbageAllowed, 0, "SV4: garbage signature was accepted");
        assertEq(
            ghost_sv4_ecrecoverDiffFailed,
            0,
            "SV4: precompile accepted where ecrecover returned address(0)"
        );
        assertEq(ghost_sv4_wrongError, 0, "SV4: wrong error selector returned");
        assertEq(ghost_sv6_unknownTypeAllowed, 0, "SV6: unknown type prefix was accepted");
        assertEq(ghost_sv7_keychainAllowed, 0, "SV7: keychain prefix was accepted");
    }

    function afterInvariant() public view {
        if (!isTempo) return;

        // Bug counters
        assertEq(ghost_sv1_mismatch, 0, "SV1: mismatch count > 0");
        assertEq(ghost_sv2_highSAllowed, 0, "SV2: high-s allowed count > 0");
        assertEq(ghost_sv3_badSizeAllowed, 0, "SV3: bad size allowed count > 0");
        assertEq(ghost_sv4_garbageAllowed, 0, "SV4: garbage allowed count > 0");
        assertEq(ghost_sv4_ecrecoverDiffFailed, 0, "SV4: ecrecover diff failed count > 0");
        assertEq(ghost_sv4_wrongError, 0, "SV4: wrong error count > 0");
        assertEq(ghost_sv6_unknownTypeAllowed, 0, "SV6: unknown type allowed count > 0");
        assertEq(ghost_sv7_keychainAllowed, 0, "SV7: keychain allowed count > 0");

        // Coverage: each property was exercised at least once
        assertGt(ghost_sv1_secpOk + ghost_sv1_p256Ok + ghost_sv1_webauthnOk, 0, "SV1: no coverage");
        assertGt(
            ghost_sv2_secpHighSRejected + ghost_sv2_p256HighSRejected
                + ghost_sv2_webauthnHighSRejected,
            0,
            "SV2: no coverage"
        );
        assertGt(ghost_sv3_sizeRejected, 0, "SV3: no coverage");
        assertGt(ghost_sv6_unknownTypeRejected, 0, "SV6: no coverage");
        assertGt(ghost_sv7_keychainRejected, 0, "SV7: no coverage");
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/

    bytes4 internal constant _INVALID_FORMAT_SEL = ISignatureVerifier.InvalidFormat.selector;
    bytes4 internal constant _INVALID_SIG_SEL = ISignatureVerifier.InvalidSignature.selector;

    /// @dev Returns true if either recover() or verify() accepted (bug), false if both reverted.
    ///      Also checks that recover()'s revert error is one of the two known selectors
    ///      (InvalidFormat or InvalidSignature); increments ghost_sv4_wrongError otherwise.
    function _callBothRevert(
        bytes32 hash,
        bytes memory sig,
        address signer
    )
        internal
        returns (bool accepted)
    {
        bytes memory recoverCd = abi.encodeCall(verifier.recover, (hash, sig));
        (bool recoverOk, bytes memory recoverRet) = SIG_VERIFIER.staticcall(recoverCd);
        if (recoverOk) {
            accepted = true;
        } else if (recoverRet.length >= 4) {
            bytes4 sel;
            assembly {
                sel := mload(add(recoverRet, 32))
            }
            if (sel != _INVALID_FORMAT_SEL && sel != _INVALID_SIG_SEL) ghost_sv4_wrongError++;
        }

        bytes memory verifyCd = abi.encodeCall(verifier.verify, (signer, hash, sig));
        (bool verifyOk,) = SIG_VERIFIER.staticcall(verifyCd);
        if (verifyOk) accepted = true;
    }

    function _signP256(uint256 idx, bytes32 hash) internal view returns (bytes memory) {
        (bytes32 r, bytes32 s) = vm.signP256(_p256Keys[idx], hash);
        s = _normalizeP256S(s);
        return abi.encodePacked(TYPE_P256, r, s, _p256PubX[idx], _p256PubY[idx], uint8(0));
    }

    function _signWebAuthn(uint256 idx, bytes32 hash) internal view returns (bytes memory) {
        bytes memory webauthnData = _buildWebAuthnData(hash);
        bytes memory authData = _slice(webauthnData, 0, 37);
        bytes memory clientDataJSON = _slice(webauthnData, 37, webauthnData.length - 37);
        bytes32 messageHash = sha256(abi.encodePacked(authData, sha256(clientDataJSON)));

        (bytes32 r, bytes32 s) = vm.signP256(_p256Keys[idx], messageHash);
        s = _normalizeP256S(s);
        return abi.encodePacked(TYPE_WEBAUTHN, webauthnData, r, s, _p256PubX[idx], _p256PubY[idx]);
    }

    function _buildWebAuthnData(bytes32 challenge) internal pure returns (bytes memory) {
        bytes32 rpIdHash = sha256("localhost");
        bytes memory authData = abi.encodePacked(rpIdHash, uint8(0x01), bytes4(0));
        string memory challengeBase64 = _base64UrlEncode(abi.encodePacked(challenge));
        bytes memory clientDataJSON = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            challengeBase64,
            '","origin":"https://localhost"}'
        );
        return abi.encodePacked(authData, clientDataJSON);
    }

    function _normalizeP256S(bytes32 s) internal pure returns (bytes32) {
        uint256 sVal = uint256(s);
        if (sVal > P256N_HALF) return bytes32(P256_ORDER - sVal);
        return s;
    }

    function _slice(
        bytes memory data,
        uint256 start,
        uint256 length
    )
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

    function _base64UrlEncode(bytes memory data) internal pure returns (string memory) {
        bytes memory table =
            bytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        bytes memory result = new bytes(encodedLen);
        uint256 resultIdx = 0;

        for (uint256 i = 0; i < data.length; i += 3) {
            uint256 a = uint8(data[i]);
            uint256 b = i + 1 < data.length ? uint8(data[i + 1]) : 0;
            uint256 c = i + 2 < data.length ? uint8(data[i + 2]) : 0;
            uint256 triple = (a << 16) | (b << 8) | c;
            result[resultIdx++] = table[(triple >> 18) & 0x3F];
            result[resultIdx++] = table[(triple >> 12) & 0x3F];
            if (i + 1 < data.length) result[resultIdx++] = table[(triple >> 6) & 0x3F];
            if (i + 2 < data.length) result[resultIdx++] = table[triple & 0x3F];
        }

        bytes memory trimmed = new bytes(resultIdx);
        for (uint256 i = 0; i < resultIdx; i++) {
            trimmed[i] = result[i];
        }
        return string(trimmed);
    }

}
