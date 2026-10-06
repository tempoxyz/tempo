pragma circom 2.1.0;

include "../../circuits/lib/bigint.circom";

template BigInt() {
    signal input a[17];
    signal input b[17];
    signal input m[17];
    signal input q[17];
    signal input r[17];
    signal input sq[17];
    signal input sr[17];
    signal output less;

    component multiply = ModMulCheck(121, 17);
    multiply.a <== a;
    multiply.b <== b;
    multiply.m <== m;
    multiply.q <== q;
    multiply.r <== r;

    component square = ModSquareCheck(121, 17);
    square.a <== a;
    square.m <== m;
    square.q <== sq;
    square.r <== sr;

    less <== BigLessThan(121, 17)(a, b);
}

component main = BigInt();
