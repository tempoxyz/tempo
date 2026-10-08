pragma circom 2.1.0;

include "../../circuits/lib/array.circom";

template Array() {
    signal input in[40];
    signal input shift;
    signal input len;
    signal output shifted[9];
    signal output mask[12];

    shifted <== ShiftLeft(40, 9, 6)(in, shift);
    mask <== PrefixMask(12)(len);
}

component main = Array();
