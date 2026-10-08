pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/poseidon.circom";
include "lib/array.circom";
include "lib/base64.circom";
include "lib/bigint.circom";
include "lib/json.circom";
include "lib/sha256.circom";

// TIP-1133 hash_bytes: Poseidon(len, c_0, ..., c_{k-1}) over 31-byte big-endian chunks. Bytes at
// len and above must be zero, and len at most maxLen.
template HashBytes(maxLen) {
    var k = (maxLen + 30) \ 31;
    signal input bytes[maxLen];
    signal input len;
    signal output out;

    component hash = Poseidon(k + 1);
    hash.inputs[0] <== len;
    for (var i = 0; i < k; i++) {
        var chunk = 0;
        for (var t = 0; t < 31; t++) {
            if (31 * i + t < maxLen) {
                chunk += bytes[31 * i + t] * (1 << (8 * (30 - t)));
            }
        }
        hash.inputs[1 + i] <== chunk;
    }
    out <== hash.out;
}

// Packs '"', three name bytes, '"', and ':' least significant byte first.
function memberPattern3(c0, c1, c2) {
    return 0x22 + (c0 << 8) + (c1 << 16) + (c2 << 24) + (0x22 << 32) + (0x3a << 40);
}

// Limb t of the EMSA-PKCS1-v1_5 encoding of a SHA-256 digest of zero: 0x00 0x01, 202 bytes of
// 0xff, 0x00, the DigestInfo prefix, then the digest in the low 256 bits.
function emsaConstantLimb(n, t) {
    var digestInfo = 0x3031300d060960864801650304020105000420;
    var limb = 0;
    for (var u = 0; u < n; u++) {
        var g = n * t + u;
        var bit = 0;
        if (g >= 256 && g < 408) {
            bit = (digestInfo >> (g - 256)) & 1;
        }
        if (g >= 416 && g <= 2032) {
            bit = 1;
        }
        limb += bit << u;
    }
    return limb;
}

// TIP-1133 scheme 0x01: an RS256-signed OpenID Connect ID token whose key hashes to key_hash
// identifies a user and commits to an access key or a message. The only public signal is
// public_input.
template OidcRs256() {
    var maxSigned = 1024;
    var maxPayload = 768;
    var n = 121;
    var k = 17;
    var maxIss = 128;
    var maxAud = 128;
    var maxSub = 64;
    var maxDigits = 10;
    var httpsLen = 8;

    // base64url(header) || "." || base64url(payload), zero-padded, and its length L.
    signal input signedInput[maxSigned];
    signal input signedInputLen;
    // RSA signature and modulus in 121-bit limbs, least significant first.
    signal input signature[k];
    signal input modulus[k];
    // Quotients and remainders of the 16 squarings and the final multiplication of s^65537.
    signal input rsaQuotient[17][k];
    signal input rsaRemainder[16][k];
    // Lengths of the iss, aud, and sub string values, and digit counts of iat and exp.
    signal input issLen;
    signal input audLen;
    signal input subLen;
    signal input iatLen;
    signal input expLen;
    signal input salt;
    signal input blinding;
    signal input commitA;
    signal input commitB;

    signal output publicInput;

    // Constraints 1 and 5: SHA-256 over exactly L bytes, zero past L.
    component sha = Sha256Bytes(maxSigned);
    sha.in <== signedInput;
    sha.len <== signedInputLen;

    // Constraint 2: one '.' below L at index j, base64url bytes elsewhere below L, and a payload
    // length L - j - 1 that is not 1 mod 4.
    component chars[maxSigned];
    signal isDot[maxSigned];
    signal dot[maxSigned];
    signal sextet[maxSigned];
    var dots = 0;
    var dotIndex = 0;
    for (var i = 0; i < maxSigned; i++) {
        chars[i] = Base64UrlChar();
        chars[i].bits <== sha.bits[i];
        isDot[i] <== IsEqual()([signedInput[i], 46]);
        dot[i] <== sha.inRange[i] * isDot[i];
        sha.inRange[i] * (1 - chars[i].valid - isDot[i]) === 0;
        sextet[i] <== sha.inRange[i] * chars[i].value;
        dots += dot[i];
        dotIndex += i * dot[i];
    }
    dots === 1;
    signal payloadChars <== signedInputLen - dotIndex - 1;
    signal payloadCharBits[10] <== Num2Bits(10)(payloadChars);
    payloadCharBits[0] * (1 - payloadCharBits[1]) === 0;

    // Constraint 7: decode the payload four characters at a time. Sextets past L are zero.
    signal payloadSextets[maxSigned] <== ShiftLeft(maxSigned, maxSigned, 10)(sextet, dotIndex + 1);
    component groups[maxSigned \ 4];
    signal payloadBits[maxPayload][8];
    for (var g = 0; g < maxSigned \ 4; g++) {
        groups[g] = Num2Bits(24);
        groups[g].in <== payloadSextets[4 * g] * (1 << 18) + payloadSextets[4 * g + 1] * (1 << 12)
            + payloadSextets[4 * g + 2] * (1 << 6) + payloadSextets[4 * g + 3];
        for (var u = 0; u < 8; u++) {
            payloadBits[3 * g][u] <== groups[g].out[16 + u];
            payloadBits[3 * g + 1][u] <== groups[g].out[8 + u];
            payloadBits[3 * g + 2][u] <== groups[g].out[u];
        }
    }
    // A length of 4q + r characters decodes to 3q + max(r - 1, 0) bytes, for r in {0, 2, 3}.
    var quads = 0;
    for (var b = 2; b < 10; b++) {
        quads += payloadCharBits[b] * (1 << (b - 2));
    }
    signal payloadLen <== 3 * quads + payloadCharBits[0] + payloadCharBits[1];
    signal active[maxPayload] <== PrefixMask(maxPayload)(payloadLen);
    signal payload[maxPayload];
    for (var i = 0; i < maxPayload; i++) {
        var byte = 0;
        for (var u = 0; u < 8; u++) {
            byte += payloadBits[i][u] * (1 << u);
        }
        payload[i] <== active[i] * byte;
    }

    // Constraints 8 and 9: lex the payload as a compact JSON object.
    component json = JsonObject(maxPayload);
    json.bits <== payloadBits;
    json.active <== active;

    // Constraints 10 to 12: one top-level member per required name, with checked values.
    signal issStart <== TopLevelMember(maxPayload, 6, memberPattern3(0x69, 0x73, 0x73))(
        payload, json.nameStart
    );
    signal audStart <== TopLevelMember(maxPayload, 6, memberPattern3(0x61, 0x75, 0x64))(
        payload, json.nameStart
    );
    signal subStart <== TopLevelMember(maxPayload, 6, memberPattern3(0x73, 0x75, 0x62))(
        payload, json.nameStart
    );
    signal iatStart <== TopLevelMember(maxPayload, 6, memberPattern3(0x69, 0x61, 0x74))(
        payload, json.nameStart
    );
    signal expStart <== TopLevelMember(maxPayload, 6, memberPattern3(0x65, 0x78, 0x70))(
        payload, json.nameStart
    );
    // '"nonce":' packed least significant byte first.
    signal nonceStart <== TopLevelMember(maxPayload, 8, 0x3a2265636e6f6e22)(
        payload, json.nameStart
    );

    signal issWindow[maxIss + httpsLen + 3] <== ShiftLeft(maxPayload, maxIss + httpsLen + 3, 10)(
        payload, issStart
    );
    signal iss[maxIss + httpsLen] <== StringValue(maxIss + httpsLen)(issWindow, issLen);
    signal audWindow[maxAud + 3] <== ShiftLeft(maxPayload, maxAud + 3, 10)(payload, audStart);
    signal aud[maxAud] <== StringValue(maxAud)(audWindow, audLen);
    signal subWindow[maxSub + 3] <== ShiftLeft(maxPayload, maxSub + 3, 10)(payload, subStart);
    signal sub[maxSub] <== StringValue(maxSub)(subWindow, subLen);
    signal nonceWindow[46] <== ShiftLeft(maxPayload, 46, 10)(payload, nonceStart);
    signal iatWindow[maxDigits + 1] <== ShiftLeft(maxPayload, maxDigits + 1, 10)(payload, iatStart);
    signal issuedAt <== NumberValue(maxDigits)(iatWindow, iatLen);
    signal expWindow[maxDigits + 1] <== ShiftLeft(maxPayload, maxDigits + 1, 10)(payload, expStart);
    signal expiry <== NumberValue(maxDigits)(expWindow, expLen);

    // Constraint 13: drop one leading "https://" from iss, then hash at most 128 bytes.
    var prefix = 0;
    for (var t = 0; t < httpsLen; t++) {
        prefix += iss[t] * (1 << (8 * t));
    }
    // "https://" packed least significant byte first.
    signal hasHttps <== IsEqual()([prefix, 0x2f2f3a7370747468]);
    signal issNormalized[maxIss];
    for (var t = 0; t < maxIss; t++) {
        issNormalized[t] <== iss[t] + hasHttps * (iss[t + httpsLen] - iss[t]);
    }
    signal issNormalizedLen <== issLen - httpsLen * hasHttps;
    signal issSlack[8] <== Num2Bits(8)(maxIss - issNormalizedLen);
    signal issuer <== HashBytes(maxIss)(issNormalized, issNormalizedLen);

    // Constraint 14: the nonce is base64url(be32(Poseidon(commit_a, commit_b, blinding))). The
    // 43 characters encode 256 bits and two zero bits.
    nonceWindow[0] === 34;
    nonceWindow[44] === 34;
    (nonceWindow[45] - 44) * (nonceWindow[45] - 125) === 0;
    signal nonceHash <== Poseidon(3)([commitA, commitB, blinding]);
    signal nonceHashBits[254] <== Num2Bits_strict()(nonceHash);
    var encoded[258];
    encoded[0] = 0;
    encoded[1] = 0;
    for (var x = 0; x < 254; x++) {
        encoded[2 + x] = nonceHashBits[253 - x];
    }
    encoded[256] = 0;
    encoded[257] = 0;
    component nonceCharBits[43];
    component nonceChars[43];
    for (var t = 0; t < 43; t++) {
        nonceCharBits[t] = Num2Bits(8);
        nonceCharBits[t].in <== nonceWindow[1 + t];
        nonceChars[t] = Base64UrlChar();
        nonceChars[t].bits <== nonceCharBits[t].out;
        nonceChars[t].valid === 1;
        var expected = 0;
        for (var u = 0; u < 6; u++) {
            expected += encoded[6 * t + u] * (1 << (5 - u));
        }
        nonceChars[t].value === expected;
    }

    // Constraint 16.
    signal subHash <== HashBytes(maxSub)(sub, subLen);
    signal audHash <== HashBytes(maxAud)(aud, audLen);
    signal addressSeed <== Poseidon(4)([1, subHash, audHash, salt]);

    // Constraint 17: the signature form bounds commit_a and commit_b, and expires by exp.
    signal isMessage <== IsEqual()([commitB, 1 << 64]);
    signal accessKey <== commitA * (1 - isMessage);
    signal validUntil <== commitB * (1 - isMessage);
    signal tokenExpiry <== expiry * (1 - isMessage);
    signal accessKeyBits[160] <== Num2Bits(160)(accessKey);
    signal validUntilBits[64] <== Num2Bits(64)(validUntil);
    signal withinExpiry <== LessEqThan(64)([validUntil, tokenExpiry]);
    withinExpiry === 1;

    // Constraint 3: range-checked limbs, a modulus of exactly 2048 bits, and 0 < s < n. The top
    // limb holds bits 1936 to 2047.
    component modulusBits[k];
    component signatureBits[k];
    for (var i = 0; i < k; i++) {
        var width = i == k - 1 ? 2048 - n * (k - 1) : n;
        modulusBits[i] = Num2Bits(width);
        modulusBits[i].in <== modulus[i];
        signatureBits[i] = Num2Bits(width);
        signatureBits[i].in <== signature[i];
    }
    modulusBits[k - 1].out[2048 - n * (k - 1) - 1] === 1;
    signal signatureBelowModulus <== BigLessThan(n, k)(signature, modulus);
    signatureBelowModulus === 1;

    // Constraint 6: key_hash = hash_bytes(n as 256 big-endian bytes, 256).
    var modulusBytes[256];
    for (var t = 0; t < 256; t++) {
        var value = 0;
        for (var u = 0; u < 8; u++) {
            var g = 8 * (255 - t) + u;
            value += modulusBits[g \ n].out[g % n] * (1 << u);
        }
        modulusBytes[t] = value;
    }
    component keyHash = Poseidon(10);
    keyHash.inputs[0] <== 256;
    for (var i = 0; i < 9; i++) {
        var chunk = 0;
        for (var t = 0; t < 31; t++) {
            if (31 * i + t < 256) {
                chunk += modulusBytes[31 * i + t] * (1 << (8 * (30 - t)));
            }
        }
        keyHash.inputs[1 + i] <== chunk;
    }

    // Constraint 4: s^65537 mod n equals the EMSA-PKCS1-v1_5 encoding of the digest.
    component quotientBits[17][k];
    component remainderBits[16][k];
    for (var i = 0; i < 17; i++) {
        for (var j = 0; j < k; j++) {
            quotientBits[i][j] = Num2Bits(n);
            quotientBits[i][j].in <== rsaQuotient[i][j];
            if (i < 16) {
                remainderBits[i][j] = Num2Bits(n);
                remainderBits[i][j].in <== rsaRemainder[i][j];
            }
        }
    }
    var encodedMessage[k];
    for (var t = 0; t < k; t++) {
        encodedMessage[t] = emsaConstantLimb(n, t);
        for (var u = 0; u < n; u++) {
            var g = n * t + u;
            if (g < 256) {
                encodedMessage[t] += sha.digest[255 - g] * (1 << u);
            }
        }
    }
    // 16 squarings give s^65536, and a final multiplication by s gives s^65537.
    component square[16];
    for (var i = 0; i < 16; i++) {
        square[i] = ModSquareCheck(n, k);
        for (var j = 0; j < k; j++) {
            if (i == 0) {
                square[i].a[j] <== signature[j];
            } else {
                square[i].a[j] <== rsaRemainder[i - 1][j];
            }
            square[i].m[j] <== modulus[j];
            square[i].q[j] <== rsaQuotient[i][j];
            square[i].r[j] <== rsaRemainder[i][j];
        }
    }
    component multiply = ModMulCheck(n, k);
    for (var j = 0; j < k; j++) {
        multiply.a[j] <== rsaRemainder[15][j];
        multiply.b[j] <== signature[j];
        multiply.m[j] <== modulus[j];
        multiply.q[j] <== rsaQuotient[16][j];
        multiply.r[j] <== encodedMessage[j];
    }

    // Constraint 18.
    publicInput <== Poseidon(7)([1, issuer, keyHash.out, addressSeed, commitA, commitB, issuedAt]);
}
