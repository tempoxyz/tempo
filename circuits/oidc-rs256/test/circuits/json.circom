pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "../../circuits/oidc_rs256.circom";

// Reads the top-level sub member of a payload of up to 96 bytes, as the main circuit does.
template Json() {
    signal input bytes[96];
    signal input len;
    signal input subLen;
    signal output sub[16];

    component bits[96];
    signal active[96] <== PrefixMask(96)(len);
    signal payload[96];
    component json = JsonObject(96);
    for (var i = 0; i < 96; i++) {
        bits[i] = Num2Bits(8);
        bits[i].in <== bytes[i];
        json.bits[i] <== bits[i].out;
        payload[i] <== bytes[i] * active[i];
    }
    json.active <== active;

    signal start <== TopLevelMember(96, 6, memberPattern3(0x73, 0x75, 0x62))(
        payload, json.nameStart
    );
    signal window[19] <== ShiftLeft(96, 19, 7)(payload, start);
    sub <== StringValue(16)(window, subLen);
}

component main = Json();
