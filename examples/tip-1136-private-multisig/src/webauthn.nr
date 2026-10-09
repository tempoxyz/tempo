// Minimal, strict WebAuthn assertion check for a passkey approval.
//
// Accepted clientDataJSON must begin exactly with
//   {"type":"webauthn.get","challenge":"<43 base64url chars of digest>",
// which is the canonical ordering produced by current browsers. Anything else is
// rejected rather than parsed. authenticatorData is the 37-byte no-extension form.
// Origin is not checked in-circuit; the RP ID hash (committed per member) is, and
// the authenticator enforces the RP ID <-> origin relationship.

use crate::MAX_CDJ;

global PREFIX: [u8; 36] = "{\"type\":\"webauthn.get\",\"challenge\":\"".as_bytes();
global B64URL: [u8; 64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".as_bytes();

global FLAG_UP: u8 = 0x01;
global FLAG_UV: u8 = 0x04;

/// base64url without padding of a 32-byte value: exactly 43 chars.
pub fn b64url_32(d: [u8; 32]) -> [u8; 43] {
    let mut out = [0; 43];
    let mut o = 0;
    for g in 0..11 {
        let b0 = d[3 * g] as u32;
        let b1 = if 3 * g + 1 < 32 { d[3 * g + 1] as u32 } else { 0 };
        let b2 = if 3 * g + 2 < 32 { d[3 * g + 2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        for k in 0..4 {
            if o < 43 {
                out[o] = B64URL[(n >> (18 - 6 * k)) & 63];
                o += 1;
            }
        }
    }
    out
}

pub fn assertion_message(
    digest: [u8; 32],
    rp_id_hash: [u8; 32],
    auth_data: [u8; 37],
    cdj: [u8; MAX_CDJ],
    cdj_len: u32,
) -> [u8; 32] {
    assert(cdj_len <= MAX_CDJ, "clientDataJSON too long");
    for i in 0..36 {
        assert(cdj[i] == PREFIX[i], "clientDataJSON prefix");
    }
    let challenge = b64url_32(digest);
    for i in 0..43 {
        assert(cdj[36 + i] == challenge[i], "challenge != authorization digest");
    }
    assert(cdj[79] == 34, "challenge must be terminated"); // '"'

    for i in 0..32 {
        assert(auth_data[i] == rp_id_hash[i], "rpIdHash mismatch");
    }
    let flags = auth_data[32];
    assert((flags & FLAG_UP) != 0, "user presence required");
    assert((flags & FLAG_UV) != 0, "user verification required");

    let client_hash = sha256::sha256_var(cdj, cdj_len);
    let mut signed = [0; 69];
    for i in 0..37 {
        signed[i] = auth_data[i];
    }
    for i in 0..32 {
        signed[37 + i] = client_hash[i];
    }
    sha256::digest(signed)
}
