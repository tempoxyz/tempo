"""Run with the same pinned Python dependencies as validate-native-signatures.py."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest

from cryptography.exceptions import InvalidSignature

root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("native_check", root / "validate-native-signatures.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fixtures = json.loads((root / "native-signature-fixtures.json").read_text())


class SignatureFixtureTests(unittest.TestCase):
    def test_all_valid_fixtures(self):
        for row in fixtures:
            with self.subTest(name=row["name"]):
                module.validate(row)

    def mutated(self, name, byte_offset):
        row = deepcopy(next(row for row in fixtures if row["name"] == name))
        encoded = bytearray.fromhex(row["input"][2:])
        encoded[byte_offset] ^= 1
        row["input"] = "0x" + encoded.hex()
        return row

    def test_wrong_selector(self):
        with self.assertRaises(AssertionError):
            module.validate(self.mutated("native-p256-raw-recover", 0))

    def test_wrong_dynamic_offset(self):
        with self.assertRaises(AssertionError):
            module.validate(self.mutated("native-p256-raw-recover", 67))

    def test_wrong_expected_signer(self):
        row = deepcopy(fixtures[0])
        row["expected"] = "0x" + "00" * 32
        with self.assertRaises(AssertionError):
            module.validate(row)

    def test_wrong_target(self):
        row = deepcopy(fixtures[0])
        row["address"] = "0x" + "00" * 20
        with self.assertRaises(AssertionError):
            module.validate(row)

    def test_wrong_challenge(self):
        with self.assertRaises(AssertionError):
            module.validate(self.mutated("native-webauthn-recover", 4))

    def test_changed_p256_signature(self):
        # recover head is 64 bytes, followed by length and type byte; then r.
        with self.assertRaises((AssertionError, InvalidSignature, ValueError)):
            module.validate(self.mutated("native-p256-raw-recover", 101))


if __name__ == "__main__":
    unittest.main()
