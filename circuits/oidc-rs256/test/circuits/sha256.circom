pragma circom 2.1.0;

include "../../circuits/lib/sha256.circom";

template Sha256() {
    signal input in[200];
    signal input len;
    signal output digest[256];

    component sha = Sha256Bytes(200);
    sha.in <== in;
    sha.len <== len;
    digest <== sha.digest;
}

component main = Sha256();
