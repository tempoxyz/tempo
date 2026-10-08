pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/sha256/sha256compression.circom";
include "array.circom";

// SHA-256 of the first len bytes of in, with padding computed in the circuit from len. Bytes at
// len and above must be zero. Outputs the digest bits most significant first, the bits of each
// padded byte least significant first, and the mask of bytes below len.
template Sha256Bytes(maxLen) {
    assert(maxLen < 8192);
    var maxBlocks = (maxLen + 8) \ 64 + 1;

    signal input in[maxLen];
    signal input len;
    signal output digest[256];
    signal output bits[maxLen][8];
    signal output inRange[maxLen];

    inRange <== PrefixMask(maxLen)(len);
    for (var i = 0; i < maxLen; i++) {
        in[i] * (1 - inRange[i]) === 0;
    }

    // The message ends in block blocks - 1, which also holds the 0x80 byte and the length.
    signal blocks;
    blocks <-- (len + 8) \ 64 + 1;
    signal blockOffset[6] <== Num2Bits(6)(len + 8 - 64 * (blocks - 1));
    signal isLast[maxBlocks];
    var lastCount = 0;
    for (var b = 0; b < maxBlocks; b++) {
        isLast[b] <== IsEqual()([blocks, b + 1]);
        lastCount += isLast[b];
    }
    lastCount === 1;

    // The bit length 8 * len is below 2^16, so only the final two bytes of the field are set.
    signal lenBits[13] <== Num2Bits(13)(len);
    var lenHigh = 0;
    for (var k = 5; k < 13; k++) {
        lenHigh += lenBits[k] * (1 << (k - 5));
    }
    var lenLow = 0;
    for (var k = 0; k < 5; k++) {
        lenLow += lenBits[k] * (1 << (k + 3));
    }
    signal lenHighAt[maxBlocks];
    signal lenLowAt[maxBlocks];
    for (var b = 0; b < maxBlocks; b++) {
        lenHighAt[b] <== isLast[b] * lenHigh;
        lenLowAt[b] <== isLast[b] * lenLow;
    }

    component paddedBits[64 * maxBlocks];
    for (var i = 0; i < 64 * maxBlocks; i++) {
        var byte = 0;
        if (i < maxLen) {
            byte += in[i];
        }
        // 0x80 sits where the mask drops from 1 to 0, at i = len.
        if (i <= maxLen) {
            var before = 1;
            if (i > 0) {
                before = inRange[i - 1];
            }
            var after = 0;
            if (i < maxLen) {
                after = inRange[i];
            }
            byte += 128 * (before - after);
        }
        if (i % 64 == 62) {
            byte += lenHighAt[i \ 64];
        }
        if (i % 64 == 63) {
            byte += lenLowAt[i \ 64];
        }
        paddedBits[i] = Num2Bits(8);
        paddedBits[i].in <== byte;
        if (i < maxLen) {
            bits[i] <== paddedBits[i].out;
        }
    }

    // circomlib takes the chaining value least significant bit first within each word, and the
    // message and output most significant bit first.
    var iv[8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    component compress[maxBlocks];
    for (var b = 0; b < maxBlocks; b++) {
        compress[b] = Sha256compression();
        for (var w = 0; w < 8; w++) {
            for (var k = 0; k < 32; k++) {
                if (b == 0) {
                    compress[b].hin[32 * w + k] <== (iv[w] >> k) & 1;
                } else {
                    compress[b].hin[32 * w + k] <== compress[b - 1].out[32 * w + 31 - k];
                }
            }
        }
        for (var t = 0; t < 64; t++) {
            for (var u = 0; u < 8; u++) {
                compress[b].inp[8 * t + u] <== paddedBits[64 * b + t].out[7 - u];
            }
        }
    }

    // Select the last block's output word by word, then split the words back into bits.
    signal selected[maxBlocks][8];
    component wordBits[8];
    for (var w = 0; w < 8; w++) {
        var word = 0;
        for (var b = 0; b < maxBlocks; b++) {
            var value = 0;
            for (var m = 0; m < 32; m++) {
                value += compress[b].out[32 * w + m] * (1 << (31 - m));
            }
            selected[b][w] <== isLast[b] * value;
            word += selected[b][w];
        }
        wordBits[w] = Num2Bits(32);
        wordBits[w].in <== word;
        for (var m = 0; m < 32; m++) {
            digest[32 * w + m] <== wordBits[w].out[31 - m];
        }
    }
}
