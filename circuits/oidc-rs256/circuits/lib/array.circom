pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";

function minimum(a, b) {
    return a < b ? a : b;
}

// Outputs out[i] = 1 for i < len and 0 otherwise. Unsatisfiable when len > N.
template PrefixMask(N) {
    signal input len;
    signal output out[N];

    // Booleans that never rise again and sum to len form exactly the prefix of length len.
    var sum = 0;
    for (var i = 0; i < N; i++) {
        out[i] <-- i < len ? 1 : 0;
        out[i] * (out[i] - 1) === 0;
        if (i > 0) {
            out[i] * (1 - out[i - 1]) === 0;
        }
        sum += out[i];
    }
    sum === len;
}

// One barrel shifter stage: out[k] = in[k + step] when bit is 1, otherwise in[k].
template ShiftStage(nIn, nOut, step) {
    signal input in[nIn];
    signal input bit;
    signal output out[nOut];

    for (var k = 0; k < nOut; k++) {
        if (k + step < nIn) {
            out[k] <== in[k] + bit * (in[k + step] - in[k]);
        } else {
            out[k] <== in[k] - bit * in[k];
        }
    }
}

// Outputs out[k] = in[k + shift] for k < W, reading zeros past the end. Unsatisfiable when
// shift >= 2^B.
template ShiftLeft(N, W, B) {
    signal input in[N];
    signal input shift;
    signal output out[W];

    signal bits[B] <== Num2Bits(B)(shift);

    // Apply the largest steps first. After bit b, at most 2^b - 1 more shift remains, so each
    // stage keeps only the elements later stages can still reach.
    var len[B + 1];
    len[B] = N;
    for (var b = B - 1; b >= 0; b--) {
        len[b] = minimum(W + (1 << b) - 1, len[b + 1]);
    }

    component stage[B];
    for (var b = B - 1; b >= 0; b--) {
        stage[b] = ShiftStage(len[b + 1], len[b], 1 << b);
        stage[b].bit <== bits[b];
        for (var k = 0; k < len[b + 1]; k++) {
            if (b == B - 1) {
                stage[b].in[k] <== in[k];
            } else {
                stage[b].in[k] <== stage[b + 1].out[k];
            }
        }
    }

    for (var k = 0; k < W; k++) {
        if (k < len[0]) {
            out[k] <== stage[0].out[k];
        } else {
            out[k] <== 0;
        }
    }
}
