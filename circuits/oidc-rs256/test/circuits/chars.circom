pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "../../circuits/lib/base64.circom";
include "../../circuits/lib/json.circom";

// Classifies every byte value at once.
template Chars() {
    signal input bytes[256];
    signal output base64Valid[256];
    signal output base64Value[256];
    signal output json[256][9];

    component bits[256];
    component base64[256];
    component jsonChar[256];
    for (var i = 0; i < 256; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        base64[i] = Base64UrlChar();
        base64[i].bits <== bits[i].out;
        base64Valid[i] <== base64[i].valid;
        base64Value[i] <== base64[i].value;
        jsonChar[i] = JsonChar();
        jsonChar[i].bits <== bits[i].out;
        json[i][0] <== jsonChar[i].quote;
        json[i][1] <== jsonChar[i].backslash;
        json[i][2] <== jsonChar[i].lbrace;
        json[i][3] <== jsonChar[i].rbrace;
        json[i][4] <== jsonChar[i].lbracket;
        json[i][5] <== jsonChar[i].rbracket;
        json[i][6] <== jsonChar[i].comma;
        json[i][7] <== jsonChar[i].allowedOutside;
        json[i][8] <== jsonChar[i].printable;
    }
}

component main = Chars();
