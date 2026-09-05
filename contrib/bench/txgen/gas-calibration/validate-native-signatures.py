"""Independent ABI, hash, signer and ECDSA checks; not native runtime execution.

uv run --with cryptography==50.0.0 --with pycryptodome==3.23.0 python validate-native-signatures.py
"""

import base64
import hashlib
import json
from pathlib import Path

from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


def digest(data):
    return keccak.new(digest_bits=256, data=data).digest()


def validate(row):
    assert row["address"].lower() == "0x5165300000000000000000000000000000000000"
    data = bytes.fromhex(row["input"][2:])
    verify = row["name"].endswith("-verify")
    declaration = b"verify(address,bytes32,bytes)" if verify else b"recover(bytes32,bytes)"
    assert data[:4] == digest(declaration)[:4]
    args = data[4:]
    head_words = 3 if verify else 2
    expected_offset = 32 * head_words
    assert int.from_bytes(args[expected_offset-32:expected_offset], "big") == expected_offset
    size = int.from_bytes(args[expected_offset:expected_offset+32], "big")
    signature = args[expected_offset+32:expected_offset+32+size]
    assert len(signature) == size and size <= 512
    assert len(args) == expected_offset + 32 + ((size + 31) // 32) * 32
    assert not any(args[expected_offset+32+size:])
    challenge = args[32:64] if verify else args[:32]
    assert challenge == bytes([170]) * 32

    if "secp256k1" in row["name"]:
        assert len(signature) == 65 and signature[64] in (27, 28)
        public = ec.derive_private_key(int.from_bytes(bytes([7])*32, "big"), ec.SECP256K1()).public_key()
        r, s = (int.from_bytes(signature[i:i+32], "big") for i in (0, 32))
        message = challenge
    else:
        if "webauthn" in row["name"]:
            assert signature[0] == 2
            auth, client = signature[1:38], signature[38:-128]
            assert len(auth) == 37 and auth[32:] == bytes([5, 0, 0, 0, 0])
            assert auth[:32] == hashlib.sha256(b"bench.example").digest()
            fields = json.loads(client)
            assert fields["type"] == "webauthn.get"
            assert fields["challenge"] == base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
            assert fields["origin"] == "https://bench.example" and fields["crossOrigin"] is False
            message = hashlib.sha256(auth + hashlib.sha256(client).digest()).digest()
            parts = signature[-128:]
        else:
            assert len(signature) == 130 and signature[0] == 1
            expected_prehash = "prehash" in row["name"]
            assert signature[-1] == int(expected_prehash)
            message = hashlib.sha256(challenge).digest() if expected_prehash else challenge
            parts = signature[1:-1]
        r, s, x, y = (int.from_bytes(parts[i:i+32], "big") for i in (0, 32, 64, 96))
        public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        assert public.public_numbers() == ec.derive_private_key(int.from_bytes(bytes([11])*32, "big"), ec.SECP256R1()).public_key().public_numbers()
    public.verify(utils.encode_dss_signature(r, s), message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    numbers = public.public_numbers()
    signer = digest(numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"))[-20:]
    signer_word = bytes(12) + signer
    if verify:
        assert args[:32] == signer_word
    expected = (1).to_bytes(32, "big") if verify else signer_word
    assert bytes.fromhex(row["expected"][2:]) == expected


if __name__ == "__main__":
    rows = json.loads(Path(__file__).with_name("native-signature-fixtures.json").read_text())
    expected_names = {f"native-{kind}-{method}" for kind in ("secp256k1", "p256-raw", "p256-prehash", "webauthn") for method in ("recover", "verify")}
    assert len(rows) == 8 and {row["name"] for row in rows} == expected_names
    for row in rows:
        validate(row)
    print("All eight native signature fixtures pass independent ABI/hash/signer/ECDSA checks; native execution remains a separate runtime gate.")
