pragma circom 2.1.0;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";
include "array.circom";

// Classifies one byte, given its bits least significant first, for the JSON lexer.
template JsonChar() {
    signal input bits[8];
    signal output quote;
    signal output backslash;
    signal output lbrace;
    signal output rbrace;
    signal output lbracket;
    signal output rbracket;
    signal output comma;
    // One of the bytes TIP-1133 allows outside strings.
    signal output allowedOutside;
    // At least 0x20.
    signal output printable;

    // One-hot high nibble for 0x20 to 0x7f.
    signal n7 <== 1 - bits[7];
    signal low <== n7 * (1 - bits[6]);
    signal r23 <== low * bits[5];
    signal h3 <== r23 * bits[4];
    var h2 = r23 - h3;
    signal r47 <== n7 * bits[6];
    signal r67 <== r47 * bits[5];
    var r45 = r47 - r67;
    signal h5 <== r45 * bits[4];
    var h4 = r45 - h5;
    signal h7 <== r67 * bits[4];
    var h6 = r67 - h7;

    // Low nibble from bit pairs (3, 2) and (1, 0).
    signal p11 <== bits[3] * bits[2];
    var p10 = bits[3] - p11;
    var p00 = 1 - bits[3] - bits[2] + p11;
    signal q11 <== bits[1] * bits[0];
    var q10 = bits[1] - q11;
    var q01 = bits[0] - q11;
    var q00 = 1 - bits[1] - bits[0] + q11;
    signal l2 <== p00 * q10;
    signal l10 <== p10 * q10;
    signal l11 <== p10 * q11;
    signal l12 <== p11 * q00;
    signal l13 <== p11 * q01;
    signal l14 <== p11 * q10;
    signal p10b1 <== p10 * bits[1];
    var le9 = 1 - bits[3] + p10 - p10b1;
    var le10 = le9 + l10;
    signal zeroNibble <== p00 * q00;
    var ge1 = 1 - zeroNibble;

    quote <== h2 * l2;
    signal plus <== h2 * l11;
    comma <== h2 * l12;
    signal dash <== h2 * l13;
    signal dot <== h2 * l14;
    signal colon <== h3 * l10;
    lbracket <== h5 * l11;
    backslash <== h5 * l12;
    rbracket <== h5 * l13;
    lbrace <== h7 * l11;
    rbrace <== h7 * l13;
    signal digit <== h3 * le9;
    // A to O and a to o, then P to Z and p to z.
    signal lettersLow <== (h4 + h6) * ge1;
    signal lettersHigh <== (h5 + h7) * le10;

    allowedOutside <== quote + plus + comma + dash + dot + colon + lbracket + rbracket + lbrace
        + rbrace + digit + lettersLow + lettersHigh;
    printable <== 1 - low + r23;
}

// Lexes a compact JSON object of len bytes, given each byte's bits least significant first,
// enforcing TIP-1133 constraints 8 and 9. active must be PrefixMask(N) of len.
// nameStart[i] is 1 where a top-level member name opens.
template JsonObject(N) {
    signal input bits[N][8];
    signal input active[N];
    signal output nameStart[N];

    component ch[N];
    // State after each byte.
    signal inString[N];
    signal escaped[N];
    signal depth[N];
    signal nameFlag[N];

    signal escapeCandidate[N];
    signal escapedQuote[N];
    signal activeOutside[N];
    signal depthZero[N];
    signal depthOne[N];
    signal openingQuote[N];
    signal openingAtDepthOne[N];
    signal afterSeparator[N];

    active[0] === 1;

    for (var i = 0; i < N; i++) {
        ch[i] = JsonChar();
        ch[i].bits <== bits[i];

        var inBefore = 0;
        var escapedBefore = 0;
        var depthBefore = 0;
        if (i > 0) {
            inBefore = inString[i - 1];
            escapedBefore = escaped[i - 1];
            depthBefore = depth[i - 1];
        }

        // Inside a string, an unescaped backslash escapes the next byte.
        escapeCandidate[i] <== inBefore * ch[i].backslash;
        escaped[i] <== escapeCandidate[i] - escapeCandidate[i] * escapedBefore;

        // Outside a string a quote opens one; inside, only an unescaped quote closes it.
        escapedQuote[i] <== escapedBefore * ch[i].quote;
        inString[i] <== ch[i].quote + inBefore * (1 - 2 * ch[i].quote + escapedQuote[i]);

        // Braces and brackets change depth only outside strings.
        var delta = ch[i].lbrace + ch[i].lbracket - ch[i].rbrace - ch[i].rbracket;
        depth[i] <== depthBefore + delta - inBefore * delta;

        activeOutside[i] <== active[i] * (1 - inBefore);
        activeOutside[i] * (1 - ch[i].allowedOutside) === 0;
        (active[i] - activeOutside[i]) * (1 - ch[i].printable) === 0;

        // Depth stays positive until the last byte, which is '}' and returns it to zero. Each
        // byte moves depth by at most one, so depth never wraps.
        var nextActive = 0;
        if (i + 1 < N) {
            nextActive = active[i + 1];
        }
        depthZero[i] <== IsZero()(depth[i]);
        nextActive * depthZero[i] === 0;
        (active[i] - nextActive) * (1 - depthZero[i]) === 0;
        (active[i] - nextActive) * (1 - ch[i].rbrace) === 0;

        // A top-level member name is a quote opened at depth 1 right after '{' or ','.
        if (i == 0) {
            depthOne[i] <== 0;
            openingQuote[i] <== 0;
            openingAtDepthOne[i] <== 0;
            afterSeparator[i] <== 0;
            nameStart[i] <== 0;
            nameFlag[i] <== 0;
        } else {
            depthOne[i] <== IsEqual()([depthBefore, 1]);
            openingQuote[i] <== ch[i].quote - ch[i].quote * inBefore;
            openingAtDepthOne[i] <== openingQuote[i] * depthOne[i];
            afterSeparator[i] <== openingAtDepthOne[i] * (ch[i - 1].lbrace + ch[i - 1].comma);
            nameStart[i] <== afterSeparator[i] * active[i];

            // Member names hold no backslash, so their bytes compare without unescaping.
            nameFlag[i] <== nameStart[i] + nameFlag[i - 1] * inString[i];
            nameFlag[i - 1] * ch[i].backslash === 0;
        }
    }

    ch[0].lbrace === 1;
}

// Finds the one top-level member whose name and colon pack, least significant byte first, to
// pattern over P bytes, and outputs where its value starts.
template TopLevelMember(N, P, pattern) {
    signal input bytes[N];
    signal input nameStart[N];
    signal output valueStart;

    signal match[N];
    signal member[N];
    var count = 0;
    var start = 0;
    for (var i = 0; i < N; i++) {
        var window = 0;
        for (var k = 0; k < P; k++) {
            if (i + k < N) {
                window += bytes[i + k] * (1 << (8 * k));
            }
        }
        match[i] <== IsEqual()([window, pattern]);
        member[i] <== nameStart[i] * match[i];
        count += member[i];
        start += (i + P) * member[i];
    }
    count === 1;
    valueStart <== start;
}

// Checks a string value at the start of bytes: a quote, len bytes without '"' or '\', a
// quote, then ',' or '}'. Outputs the content, zero past len. Unsatisfiable when len > C.
template StringValue(C) {
    signal input bytes[C + 3];
    signal input len;
    signal output content[C];

    bytes[0] === 34;

    signal inContent[C] <== PrefixMask(C)(len);
    signal isQuote[C];
    signal isBackslash[C];
    signal end[C + 1];
    signal next[C + 1];
    var closing = 0;
    var terminator = 0;
    for (var k = 0; k <= C; k++) {
        // end[k] is 1 exactly at k = len.
        var before = 1;
        if (k > 0) {
            before = inContent[k - 1];
        }
        var after = 0;
        if (k < C) {
            after = inContent[k];
        }
        end[k] <== bytes[1 + k] * (before - after);
        next[k] <== bytes[2 + k] * (before - after);
        closing += end[k];
        terminator += next[k];

        if (k < C) {
            isQuote[k] <== IsEqual()([bytes[1 + k], 34]);
            isBackslash[k] <== IsEqual()([bytes[1 + k], 92]);
            inContent[k] * (isQuote[k] + isBackslash[k]) === 0;
            content[k] <== bytes[1 + k] * inContent[k];
        }
    }
    closing === 34;
    (terminator - 44) * (terminator - 125) === 0;
}

// Checks 1 to D decimal digits at the start of bytes followed by ',' or '}', and outputs
// their value. Unsatisfiable when len is 0 or exceeds D.
template NumberValue(D) {
    signal input bytes[D + 1];
    signal input len;
    signal output value;

    signal inDigits[D] <== PrefixMask(D)(len);
    inDigits[0] === 1;

    signal digit[D];
    signal digitBits[D][4];
    signal digitHigh[D];
    signal digitAbove9[D];
    signal acc[D];
    signal next[D + 1];
    var terminator = 0;
    for (var k = 0; k <= D; k++) {
        var before = 1;
        if (k > 0) {
            before = inDigits[k - 1];
        }
        var after = 0;
        if (k < D) {
            after = inDigits[k];
        }
        next[k] <== bytes[k] * (before - after);
        terminator += next[k];

        if (k < D) {
            // Each digit byte minus '0' lies in [0, 9].
            digit[k] <== inDigits[k] * (bytes[k] - 48);
            digitBits[k] <== Num2Bits(4)(digit[k]);
            digitHigh[k] <== digitBits[k][2] + digitBits[k][1] - digitBits[k][2] * digitBits[k][1];
            digitAbove9[k] <== digitBits[k][3] * digitHigh[k];
            digitAbove9[k] === 0;

            var previous = 0;
            if (k > 0) {
                previous = acc[k - 1];
            }
            acc[k] <== previous + inDigits[k] * (9 * previous + bytes[k] - 48);
        }
    }
    (terminator - 44) * (terminator - 125) === 0;
    value <== acc[D - 1];
}
