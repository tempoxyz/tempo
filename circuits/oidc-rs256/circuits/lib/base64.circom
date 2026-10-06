pragma circom 2.1.0;

// Classifies one byte, given its bits least significant first, as a base64url character
// (RFC 4648 section 5). value is the 6-bit value for the 64 alphabet characters, otherwise 0.
template Base64UrlChar() {
    signal input bits[8];
    signal output valid;
    signal output value;

    signal n7 <== 1 - bits[7];

    // 0x40 to 0x7f holds the letters and '_'.
    signal rowLetters <== n7 * bits[6];
    // 0x30 to 0x3f holds the digits, and 0x20 to 0x2f holds '-'.
    signal lowHalf <== n7 * (1 - bits[6]);
    signal rowSymbols <== lowHalf * bits[5];
    signal rowDigits <== rowSymbols * bits[4];
    signal rowDash <== rowSymbols - rowDigits;

    // Digits: the low nibble is at most 9, so not (bit 3 and (bit 2 or bit 1)).
    signal b21 <== bits[2] * bits[1];
    signal nibbleAbove9 <== bits[3] * (bits[2] + bits[1] - b21);
    signal isDigit <== rowDigits * (1 - nibbleAbove9);

    // '-' is 0x2d: low nibble 1101.
    signal b32 <== bits[3] * bits[2];
    signal b10 <== bits[1] * bits[0];
    signal nibble13 <== b32 * (bits[0] - b10);
    signal isDash <== rowDash * nibble13;

    // Letters: the low five bits u are in [1, 26], and bit 5 selects lowercase.
    signal z43 <== (1 - bits[4]) * (1 - bits[3]);
    signal z21 <== (1 - bits[2]) * (1 - bits[1]);
    signal z4321 <== z43 * z21;
    signal uZero <== z4321 * (1 - bits[0]);
    signal b43 <== bits[4] * bits[3];
    signal b210 <== bits[2] * b10;
    // u >= 27 when bits 4 and 3 are set and the low three bits are at least 3.
    signal uAbove26 <== b43 * (bits[2] + b10 - b210);
    signal letterRange <== (1 - uZero) * (1 - uAbove26);
    signal isLetter <== rowLetters * letterRange;

    // '_' is 0x5f: u = 31 with bit 5 clear.
    signal u31 <== b43 * b210;
    signal underscoreRow <== rowLetters * u31;
    signal isUnderscore <== underscoreRow - underscoreRow * bits[5];

    var u = bits[0] + 2 * bits[1] + 4 * bits[2] + 8 * bits[3] + 16 * bits[4];
    var nibble = bits[0] + 2 * bits[1] + 4 * bits[2] + 8 * bits[3];
    signal letterValue <== isLetter * (u - 1 + 26 * bits[5]);
    signal digitValue <== isDigit * (nibble + 52);

    valid <== isLetter + isDigit + isDash + isUnderscore;
    value <== letterValue + digitValue + 62 * isDash + 63 * isUnderscore;
}
