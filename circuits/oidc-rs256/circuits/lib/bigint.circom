pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// Checks that the polynomial with coefficients in, evaluated at 2^n, is zero as an integer.
// Coefficients must be below 2^(n + carryBits - 2) in absolute value.
template CarryToZero(n, len, carryBits) {
    signal input in[len];

    // carry[j] * 2^n = in[j] + carry[j - 1]. The range check bounds each carry to
    // [-2^(carryBits - 1), 2^(carryBits - 1)), so the relations hold over the integers.
    signal carry[len - 1];
    component range[len - 1];
    for (var j = 0; j < len - 1; j++) {
        if (j == 0) {
            carry[j] <== in[j] / (1 << n);
        } else {
            carry[j] <== (in[j] + carry[j - 1]) / (1 << n);
        }
        range[j] = Num2Bits(carryBits);
        range[j].in <== carry[j] + (1 << (carryBits - 1));
    }
    in[len - 1] + carry[len - 2] === 0;
}

// Checks a * b = q * m + r as integers, for k limbs of n bits each, least significant first.
// Callers range-check every limb of a, b, m, q, and r.
template ModMulCheck(n, k) {
    signal input a[k];
    signal input b[k];
    signal input m[k];
    signal input q[k];
    signal input r[k];

    signal ab[k][k];
    signal qm[k][k];
    for (var i = 0; i < k; i++) {
        for (var j = 0; j < k; j++) {
            ab[i][j] <== a[i] * b[j];
            qm[i][j] <== q[i] * m[j];
        }
    }

    // Coefficients are below k * 2^(2n) in absolute value.
    component check = CarryToZero(n, 2 * k - 1, n + 8);
    for (var c = 0; c < 2 * k - 1; c++) {
        var t = 0;
        for (var i = 0; i < k; i++) {
            if (c - i >= 0 && c - i < k) {
                t += ab[i][c - i] - qm[i][c - i];
            }
        }
        if (c < k) {
            t -= r[c];
        }
        check.in[c] <== t;
    }
}

// Checks a * a = q * m + r as integers, sharing the symmetric products of a * a.
template ModSquareCheck(n, k) {
    signal input a[k];
    signal input m[k];
    signal input q[k];
    signal input r[k];

    // aa holds a[i] * a[j] for i <= j, row by row.
    signal aa[k * (k + 1) \ 2];
    signal qm[k][k];
    var index = 0;
    for (var i = 0; i < k; i++) {
        for (var j = 0; j < k; j++) {
            if (j >= i) {
                aa[index] <== a[i] * a[j];
                index++;
            }
            qm[i][j] <== q[i] * m[j];
        }
    }

    component check = CarryToZero(n, 2 * k - 1, n + 8);
    for (var c = 0; c < 2 * k - 1; c++) {
        var t = 0;
        for (var i = 0; i < k; i++) {
            var j = c - i;
            if (j >= 0 && j < k) {
                // Row i starts at i * k - i * (i - 1) / 2 and column j sits j - i past it.
                var row = i * k - i * (i - 1) \ 2;
                if (j > i) {
                    t += 2 * aa[row + j - i];
                } else if (j == i) {
                    t += aa[row];
                }
                t -= qm[i][j];
            }
        }
        if (c < k) {
            t -= r[c];
        }
        check.in[c] <== t;
    }
}

// Outputs 1 when a < b, for k limbs of n bits each, least significant first. Callers
// range-check every limb.
template BigLessThan(n, k) {
    signal input a[k];
    signal input b[k];
    signal output out;

    signal lt[k];
    signal eq[k];
    signal acc[k];
    for (var i = 0; i < k; i++) {
        lt[i] <== LessThan(n)([a[i], b[i]]);
        eq[i] <== IsEqual()([a[i], b[i]]);
    }
    // Scan from the least significant limb: a < b over limbs [0, i] when limb i is lower, or
    // equal with the lower limbs deciding.
    acc[0] <== lt[0];
    for (var i = 1; i < k; i++) {
        acc[i] <== lt[i] + eq[i] * acc[i - 1];
    }
    out <== acc[k - 1];
}
