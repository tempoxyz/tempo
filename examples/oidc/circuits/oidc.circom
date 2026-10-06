pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";

template AtMost(bits, bound) {
    signal input in;
    component range = Num2Bits(bits);
    range.in <== in;
    component cmp = LessEqThan(bits);
    cmp.in[0] <== in;
    cmp.in[1] <== bound;
    cmp.out === 1;
}

template HashBytes(maxLen) {
    signal input bytes[maxLen];
    signal input len;
    signal output out;
    component bound = AtMost(10, maxLen);
    bound.in <== len;
    component active[maxLen];
    component byteRange[maxLen];
    for (var i = 0; i < maxLen; i++) {
        active[i] = LessThan(10);
        active[i].in[0] <== i;
        active[i].in[1] <== len;
        bytes[i] * (1 - active[i].out) === 0;
        byteRange[i] = Num2Bits(8);
        byteRange[i].in <== bytes[i];
    }
    var chunks = (maxLen + 30) \ 31;
    component hash = Poseidon(chunks + 1);
    hash.inputs[0] <== len;
    for (var i = 0; i < chunks; i++) {
        var packed = 0;
        for (var j = 0; j < 31; j++) {
            packed *= 256;
            if (31*i+j < maxLen) { packed += bytes[31*i+j]; }
        }
        hash.inputs[i+1] <== packed;
    }
    out <== hash.out;
}

template Alphabet() {
    signal input ch;
    signal input active;
    signal output value;
    component lo[3];
    component hi[3];
    signal group[3];
    var starts[3] = [65, 97, 48];
    var ends[3] = [90, 122, 57];
    var offsets[3] = [0, 26, 52];
    signal contributions[3];
    for (var i = 0; i < 3; i++) {
        lo[i] = GreaterEqThan(8);
        hi[i] = LessEqThan(8);
        lo[i].in[0] <== ch; lo[i].in[1] <== starts[i];
        hi[i].in[0] <== ch; hi[i].in[1] <== ends[i];
        group[i] <== lo[i].out * hi[i].out;
        contributions[i] <== group[i] * (ch - starts[i] + offsets[i]);
    }
    component dash = IsEqual(); dash.in[0] <== ch; dash.in[1] <== 45;
    component underscore = IsEqual(); underscore.in[0] <== ch; underscore.in[1] <== 95;
    active * (1 - group[0] - group[1] - group[2] - dash.out - underscore.out) === 0;
    ch * (1 - active) === 0;
    value <== contributions[0] + contributions[1] + contributions[2] + 62*dash.out + 63*underscore.out;
}

template Lexer() {
    signal input bytes[768];
    signal input len;
    signal output memberStart[768];
    signal inside[769];
    signal escape[769];
    signal depth[769];
    signal name[769];
    signal quote[768];
    signal outside[768];
    signal open[768];
    signal close[768];
    signal stringEnd[768];
    signal nameEnd[768];
    signal nameCandidate[768];
    signal unescapedQuote[768];
    signal unfinished[768];
    signal startOutside[768];
    signal unescapedSlash[768];
    component eq[768][11];
    component active[768];
    component depthBits[769];
    component top[768];
    component printable[768];
    component letterLo[768][2];
    component letterHi[768][2];
    signal letters[768][2];
    component digitLo[768];
    component digitHi[768];
    signal digit[768];
    component last[768];
    component nonzeroDepth[768];
    var symbols[11] = [34, 92, 123, 125, 91, 93, 44, 58, 45, 43, 46];
    inside[0] <== 0; escape[0] <== 0; depth[0] <== 0; name[0] <== 0;
    bytes[0] === 123;
    for (var i = 0; i < 768; i++) {
        active[i] = LessThan(10); active[i].in[0] <== i; active[i].in[1] <== len;
        for (var s = 0; s < 11; s++) {
            eq[i][s] = IsEqual(); eq[i][s].in[0] <== bytes[i]; eq[i][s].in[1] <== symbols[s];
        }
        unescapedQuote[i] <== eq[i][0].out * (1 - escape[i]);
        quote[i] <== unescapedQuote[i] * active[i].out;
        inside[i+1] <== inside[i] + quote[i] - 2*inside[i]*quote[i];
        unescapedSlash[i] <== eq[i][1].out * (1-escape[i]);
        escape[i+1] <== inside[i] * unescapedSlash[i];
        outside[i] <== active[i].out * (1 - inside[i]);
        open[i] <== outside[i] * (eq[i][2].out + eq[i][4].out);
        close[i] <== outside[i] * (eq[i][3].out + eq[i][5].out);
        depth[i+1] <== depth[i] + open[i] - close[i];
        depthBits[i] = Num2Bits(10); depthBits[i].in <== depth[i];
        nonzeroDepth[i] = IsZero(); nonzeroDepth[i].in <== depth[i+1];
        last[i] = IsEqual(); last[i].in[0] <== i+1; last[i].in[1] <== len;
        unfinished[i] <== active[i].out * (1 - last[i].out);
        unfinished[i] * nonzeroDepth[i].out === 0;
        last[i].out * (bytes[i] - 125) === 0;
        top[i] = IsEqual(); top[i].in[0] <== depth[i]; top[i].in[1] <== 1;
        if (i == 0) { nameCandidate[i] <== 0; }
        else { nameCandidate[i] <== top[i].out * (eq[i-1][2].out + eq[i-1][6].out); }
        startOutside[i] <== outside[i] * eq[i][0].out;
        memberStart[i] <== startOutside[i] * nameCandidate[i];
        stringEnd[i] <== inside[i] * quote[i];
        nameEnd[i] <== stringEnd[i] * name[i];
        name[i+1] <== name[i] + memberStart[i] - nameEnd[i];
        name[i] * eq[i][1].out === 0;
        if (i < 767) { nameEnd[i] * (bytes[i+1] - 58) === 0; }
        else { nameEnd[i] === 0; }
        printable[i] = GreaterEqThan(8); printable[i].in[0] <== bytes[i]; printable[i].in[1] <== 32;
        inside[i] * (1-printable[i].out) === 0;
        for (var g = 0; g < 2; g++) {
            letterLo[i][g] = GreaterEqThan(8); letterHi[i][g] = LessEqThan(8);
            letterLo[i][g].in[0] <== bytes[i]; letterLo[i][g].in[1] <== 65+32*g;
            letterHi[i][g].in[0] <== bytes[i]; letterHi[i][g].in[1] <== 90+32*g;
            letters[i][g] <== letterLo[i][g].out * letterHi[i][g].out;
        }
        digitLo[i] = GreaterEqThan(8); digitHi[i] = LessEqThan(8);
        digitLo[i].in[0] <== bytes[i]; digitLo[i].in[1] <== 48;
        digitHi[i].in[0] <== bytes[i]; digitHi[i].in[1] <== 57;
        digit[i] <== digitLo[i].out * digitHi[i].out;
        outside[i] * (1-eq[i][0].out-eq[i][2].out-eq[i][3].out-eq[i][4].out-eq[i][5].out-eq[i][6].out-eq[i][7].out-eq[i][8].out-eq[i][9].out-eq[i][10].out-letters[i][0]-letters[i][1]-digit[i]) === 0;
    }
    depthBits[768] = Num2Bits(10); depthBits[768].in <== depth[768];
    inside[768] === 0; escape[768] === 0; depth[768] === 0; name[768] === 0;
}

template Member(key, maxLen, numeric) {
    signal input payload[768];
    signal input payloadLen;
    signal input starts[768];
    signal input offset;
    signal input len;
    signal output bytes[maxLen];
    signal output number;
    var keyLen = 0;
    for (var j = 0; j < 5; j++) { if (key[j] != 0) { keyLen++; } }
    var prefix = keyLen + 3 + (1-numeric);
    var suffix = 1 + (1-numeric);
    component bound = AtMost(10, maxLen); bound.in <== len;
    component offBound = AtMost(10, 767); offBound.in <== offset;
    component endBound = LessEqThan(11);
    endBound.in[0] <== offset + prefix + len + suffix;
    endBound.in[1] <== payloadLen;
    endBound.out === 1;
    component match[768][7];
    signal chain[768][8];
    var count = 0;
    var weighted = 0;
    for (var i = 0; i < 768; i++) {
        chain[i][0] <== starts[i];
        for (var j = 0; j < keyLen+2; j++) {
            match[i][j] = IsEqual();
            if (i+j+1 < 768) { match[i][j].in[0] <== payload[i+j+1]; }
            else { match[i][j].in[0] <== 0; }
            if (j < keyLen) { match[i][j].in[1] <== key[j]; }
            else if (j == keyLen) { match[i][j].in[1] <== 34; }
            else { match[i][j].in[1] <== 58; }
            chain[i][j+1] <== chain[i][j] * match[i][j].out;
        }
        count += chain[i][keyLen+2];
        weighted += i*chain[i][keyLen+2];
    }
    count === 1; weighted === offset;
    component window = VarShiftLeft(768, maxLen+prefix+suffix);
    window.in <== payload; window.shift <== offset;
    if (!numeric) { window.out[prefix-1] === 34; }
    component active[maxLen+1];
    component atEnd[maxLen+1];
    component comma[maxLen+1];
    component close[maxLen+1];
    component slash[maxLen];
    component quote[maxLen];
    component lo[maxLen];
    component hi[maxLen];
    signal digit[maxLen];
    signal accumulated[maxLen+1];
    accumulated[0] <== 0;
    for (var i = 0; i < maxLen+1; i++) {
        atEnd[i] = IsEqual(); atEnd[i].in[0] <== i; atEnd[i].in[1] <== len;
        if (!numeric) { atEnd[i].out * (window.out[prefix+i]-34) === 0; }
        comma[i] = IsEqual(); close[i] = IsEqual();
        comma[i].in[0] <== window.out[prefix+i+1-numeric]; comma[i].in[1] <== 44;
        close[i].in[0] <== window.out[prefix+i+1-numeric]; close[i].in[1] <== 125;
        atEnd[i].out * (1-comma[i].out-close[i].out) === 0;
        if (i < maxLen) {
            active[i] = LessThan(10); active[i].in[0] <== i; active[i].in[1] <== len;
            bytes[i] <== active[i].out * window.out[prefix+i];
            if (!numeric) {
                slash[i] = IsEqual(); slash[i].in[0] <== bytes[i]; slash[i].in[1] <== 92;
                quote[i] = IsEqual(); quote[i].in[0] <== bytes[i]; quote[i].in[1] <== 34;
                slash[i].out === 0; quote[i].out === 0;
                accumulated[i+1] <== 0;
            } else {
                lo[i] = GreaterEqThan(8); hi[i] = LessEqThan(8);
                lo[i].in[0] <== window.out[prefix+i]; lo[i].in[1] <== 48;
                hi[i].in[0] <== window.out[prefix+i]; hi[i].in[1] <== 57;
                digit[i] <== lo[i].out * hi[i].out;
                active[i].out * (1-digit[i]) === 0;
                accumulated[i+1] <== accumulated[i] + active[i].out * (9*accumulated[i] + window.out[prefix+i]-48);
            }
        }
    }
    number <== accumulated[maxLen];
    if (numeric) {
        component nonempty = IsZero(); nonempty.in <== len; nonempty.out === 0;
        component leadingZero = IsEqual(); leadingZero.in[0] <== bytes[0]; leadingZero.in[1] <== 48;
        active[1].out * leadingZero.out === 0;
    }
}

template Oidc() {
    signal input signed_input[1024];
    signal input signed_input_len;
    signal input period;
    signal input payload_len;
    signal input modulus[17];
    signal input signature[17];
    signal input member_offsets[6];
    signal input member_lengths[6];
    signal input salt;
    signal input blinding;
    signal input commit_a;
    signal input commit_b;
    signal input issued_at;
    signal input issuer;
    signal input key_hash;
    signal input address_seed;
    signal input public_input;
    component inputBound = AtMost(11, 1024); inputBound.in <== signed_input_len;
    component periodBound = AtMost(10, 1023); periodBound.in <== period;
    component payloadBound = AtMost(10, 768); payloadBound.in <== payload_len;
    component active[1024]; component dots[1024]; component alphabet[1024];
    component inputBytes[1024]; component dotPosition[1024];
    var dotCount = 0;
    for (var i = 0; i < 1024; i++) {
        inputBytes[i] = Num2Bits(8); inputBytes[i].in <== signed_input[i];
        active[i] = LessThan(11); active[i].in[0] <== i; active[i].in[1] <== signed_input_len;
        signed_input[i]*(1-active[i].out) === 0;
        dots[i] = IsEqual(); dots[i].in[0] <== signed_input[i]; dots[i].in[1] <== 46;
        dotPosition[i] = IsEqual(); dotPosition[i].in[0] <== i; dotPosition[i].in[1] <== period;
        dots[i].out === dotPosition[i].out;
        dotCount += dots[i].out;
        alphabet[i] = Alphabet();
        alphabet[i].ch <== signed_input[i] - 46*dots[i].out;
        alphabet[i].active <== active[i].out - dots[i].out;
    }
    dotCount === 1;
    component headerNonempty = IsZero(); headerNonempty.in <== period; headerNonempty.out === 0;
    signal payloadGroups; signal payloadRemainder;
    payloadGroups <-- payload_len \ 3;
    payloadRemainder <-- payload_len % 3;
    payload_len === 3*payloadGroups + payloadRemainder;
    component groupsBound = AtMost(9, 256); groupsBound.in <== payloadGroups;
    component remBound = AtMost(2, 2); remBound.in <== payloadRemainder;
    component remZero = IsZero(); remZero.in <== payloadRemainder;
    signal encoded_len;
    encoded_len <== 4*payloadGroups + payloadRemainder + 1-remZero.out;
    signed_input_len === period + 1 + encoded_len;
    component shifted = VarShiftLeft(1024, 1024); shifted.in <== signed_input; shifted.shift <== period+1;
    component b64Active[1024]; component b64[1024]; component sextets[1024];
    for (var i = 0; i < 1024; i++) {
        b64Active[i] = LessThan(11); b64Active[i].in[0] <== i; b64Active[i].in[1] <== encoded_len;
        b64[i] = Alphabet(); b64[i].ch <== shifted.out[i]*b64Active[i].out; b64[i].active <== b64Active[i].out;
        sextets[i] = Num2Bits(6); sextets[i].in <== b64[i].value;
    }
    signal payload[768]; component decodedByte[768]; component decodedActive[768];
    for (var i = 0; i < 768; i++) {
        decodedByte[i] = Bits2Num(8);
        for (var b = 0; b < 8; b++) {
            var bitIndex = 8*i+b;
            decodedByte[i].in[7-b] <== sextets[bitIndex\6].out[5-bitIndex%6];
        }
        payload[i] <== decodedByte[i].out;
        decodedActive[i] = LessThan(10); decodedActive[i].in[0] <== i; decodedActive[i].in[1] <== payload_len;
        payload[i]*(1-decodedActive[i].out) === 0;
    }
    signal padded[1088]; signal blocks; signal paddingRest;
    blocks <-- (signed_input_len+72) \ 64;
    paddingRest <-- (signed_input_len+72) % 64;
    signed_input_len + 72 === blocks*64 + paddingRest;
    component blockBound = AtMost(5, 17); blockBound.in <== blocks;
    component restBound = Num2Bits(6); restBound.in <== paddingRest;
    component bitLength = Num2Bits(14); bitLength.in <== signed_input_len*8;
    component marker[1088]; component highLen[1088]; component lowLen[1088];
    signal highContribution[1088]; signal lowContribution[1088];
    for (var i = 0; i < 1088; i++) {
        marker[i] = IsEqual(); marker[i].in[0] <== i; marker[i].in[1] <== signed_input_len;
        highLen[i] = IsEqual(); highLen[i].in[0] <== i; highLen[i].in[1] <== blocks*64-2;
        lowLen[i] = IsEqual(); lowLen[i].in[0] <== i; lowLen[i].in[1] <== blocks*64-1;
        var high = 0; var low = 0;
        for (var b = 0; b < 8; b++) {
            low += (1<<b)*bitLength.out[b];
            if (b+8 < 14) { high += (1<<b)*bitLength.out[b+8]; }
        }
        var original = 0;
        if (i < 1024) { original = signed_input[i]; }
        highContribution[i] <== high*highLen[i].out;
        lowContribution[i] <== low*lowLen[i].out;
        padded[i] <== original + 128*marker[i].out + highContribution[i] + lowContribution[i];
    }
    component sha = Sha256Bytes(1088); sha.paddedIn <== padded; sha.paddedInLength <== blocks*64;
    component rsa = RSAVerifier65537(121, 17);
    rsa.modulus <== modulus; rsa.signature <== signature;
    component digestLimbs[17]; component nBits[17]; component sNonzero = IsZero();
    var signatureSum = 0;
    signal modulusBytes[256]; component modulusByte[256];
    for (var i = 0; i < 17; i++) {
        nBits[i] = Num2Bits(121); nBits[i].in <== modulus[i];
        digestLimbs[i] = Bits2Num(121);
        for (var b = 0; b < 121; b++) {
            var idx = i*121+b;
            if (idx < 256) { digestLimbs[i].in[b] <== sha.out[255-idx]; }
            else { digestLimbs[i].in[b] <== 0; }
            if (idx == 2047) { nBits[i].out[b] === 1; }
            if (idx >= 2048) { nBits[i].out[b] === 0; }
        }
        rsa.message[i] <== digestLimbs[i].out;
        signatureSum += signature[i];
    }
    sNonzero.in <== signatureSum; sNonzero.out === 0;
    for (var i = 0; i < 256; i++) {
        modulusByte[i] = Bits2Num(8);
        for (var b = 0; b < 8; b++) {
            var idx = (255-i)*8+b;
            modulusByte[i].in[b] <== nBits[idx\121].out[idx%121];
        }
        modulusBytes[i] <== modulusByte[i].out;
    }
    component keyHash = HashBytes(256); keyHash.bytes <== modulusBytes; keyHash.len <== 256; keyHash.out === key_hash;
    component lexer = Lexer(); lexer.bytes <== payload; lexer.len <== payload_len;
    component iss = Member([105,115,115,0,0],136,0);
    component aud = Member([97,117,100,0,0],128,0);
    component sub = Member([115,117,98,0,0],64,0);
    component nonce = Member([110,111,110,99,101],43,0);
    component iat = Member([105,97,116,0,0],10,1);
    component exp = Member([101,120,112,0,0],10,1);
    iss.payload <== payload; iss.payloadLen <== payload_len; iss.starts <== lexer.memberStart; iss.offset <== member_offsets[0]; iss.len <== member_lengths[0];
    aud.payload <== payload; aud.payloadLen <== payload_len; aud.starts <== lexer.memberStart; aud.offset <== member_offsets[1]; aud.len <== member_lengths[1];
    sub.payload <== payload; sub.payloadLen <== payload_len; sub.starts <== lexer.memberStart; sub.offset <== member_offsets[2]; sub.len <== member_lengths[2];
    nonce.payload <== payload; nonce.payloadLen <== payload_len; nonce.starts <== lexer.memberStart; nonce.offset <== member_offsets[3]; nonce.len <== 43;
    member_lengths[3] === 43;
    iat.payload <== payload; iat.payloadLen <== payload_len; iat.starts <== lexer.memberStart; iat.offset <== member_offsets[4]; iat.len <== member_lengths[4];
    exp.payload <== payload; exp.payloadLen <== payload_len; exp.starts <== lexer.memberStart; exp.offset <== member_offsets[5]; exp.len <== member_lengths[5];
    iat.number === issued_at;
    component issuedRange = Num2Bits(64); issuedRange.in <== issued_at;
    component prefixMatch[8]; signal prefixChain[9]; prefixChain[0] <== 1;
    var prefixBytes[8] = [104,116,116,112,115,58,47,47];
    for (var i = 0; i < 8; i++) {
        prefixMatch[i] = IsEqual(); prefixMatch[i].in[0] <== iss.bytes[i]; prefixMatch[i].in[1] <== prefixBytes[i];
        prefixChain[i+1] <== prefixChain[i]*prefixMatch[i].out;
    }
    component issuerHash = HashBytes(128); issuerHash.len <== member_lengths[0]-8*prefixChain[8];
    for (var i = 0; i < 128; i++) { issuerHash.bytes[i] <== iss.bytes[i]+prefixChain[8]*(iss.bytes[i+8]-iss.bytes[i]); }
    issuerHash.out === issuer;
    component audHash = HashBytes(128); audHash.bytes <== aud.bytes; audHash.len <== member_lengths[1];
    component subHash = HashBytes(64); subHash.bytes <== sub.bytes; subHash.len <== member_lengths[2];
    component seed = Poseidon(4); seed.inputs[0] <== 1; seed.inputs[1] <== subHash.out; seed.inputs[2] <== audHash.out; seed.inputs[3] <== salt; seed.out === address_seed;
    component nonceHash = Poseidon(3); nonceHash.inputs[0] <== commit_a; nonceHash.inputs[1] <== commit_b; nonceHash.inputs[2] <== blinding;
    component nonceBits = Num2Bits_strict(); nonceBits.in <== nonceHash.out;
    component nonceValues[43]; component below26[43]; component below52[43]; component below62[43]; component at62[43]; component at63[43];
    signal encoded[43][3];
    for (var i = 0; i < 43; i++) {
        nonceValues[i] = Bits2Num(6);
        for (var b = 0; b < 6; b++) {
            var idx = 255-6*i-b;
            if (idx >= 0 && idx < 254) { nonceValues[i].in[5-b] <== nonceBits.out[idx]; }
            else { nonceValues[i].in[5-b] <== 0; }
        }
        below26[i] = LessThan(6); below26[i].in[0] <== nonceValues[i].out; below26[i].in[1] <== 26;
        below52[i] = LessThan(6); below52[i].in[0] <== nonceValues[i].out; below52[i].in[1] <== 52;
        below62[i] = LessThan(6); below62[i].in[0] <== nonceValues[i].out; below62[i].in[1] <== 62;
        at62[i] = IsEqual(); at62[i].in[0] <== nonceValues[i].out; at62[i].in[1] <== 62;
        at63[i] = IsEqual(); at63[i].in[0] <== nonceValues[i].out; at63[i].in[1] <== 63;
        encoded[i][0] <== below26[i].out*(nonceValues[i].out+65);
        encoded[i][1] <== (below52[i].out-below26[i].out)*(nonceValues[i].out+71);
        encoded[i][2] <== (below62[i].out-below52[i].out)*(nonceValues[i].out-4);
        nonce.bytes[i] === encoded[i][0]+encoded[i][1]+encoded[i][2]+45*at62[i].out+95*at63[i].out;
    }
    component message = IsEqual(); message.in[0] <== commit_b; message.in[1] <== 18446744073709551616;
    component commitBits = Num2Bits(160); commitBits.in <== commit_a*(1-message.out);
    component expiryBits = Num2Bits(64); expiryBits.in <== commit_b*(1-message.out);
    component expiry = LessEqThan(64); expiry.in[0] <== commit_b*(1-message.out); expiry.in[1] <== exp.number;
    expiry.out === 1;
    component statement = Poseidon(7);
    statement.inputs[0] <== 1; statement.inputs[1] <== issuer; statement.inputs[2] <== key_hash; statement.inputs[3] <== address_seed;
    statement.inputs[4] <== commit_a; statement.inputs[5] <== commit_b; statement.inputs[6] <== issued_at;
    statement.out === public_input;
}

component main {public [public_input]} = Oidc();
