#!/usr/bin/env python3
"""Emit Prover.toml for the 3-of-5 example (alice=k1, carol=passkey, eve=k1).

Roster root/paths come from `nargo test print_witness_material --show-output`,
so Poseidon2 is computed only by the circuit's own code.
"""
import re, subprocess, pathlib
root = pathlib.Path(__file__).resolve().parent.parent
out = subprocess.run(["nargo", "test", "print_witness_material", "--show-output"], cwd=root, capture_output=True, text=True).stdout
lines = [l for l in out.splitlines() if l.startswith("0x") or l.startswith("[0x")]
roster_root, paths = lines[0], [re.findall(r"0x[0-9a-f]+", l) for l in lines[1:6]]
commit = subprocess.run(["nargo", "test", "print_public_statement", "--show-output"], cwd=root, capture_output=True, text=True).stdout
commitment = re.search(r"^0x[0-9a-f]+", commit, re.M).group(0)

vec = (root / "src/vectors.nr").read_text()
def g(name):
    v = re.search(rf"pub global {name}: [^=]+= (.+);", vec).group(1)
    return v
WEIGHTS = {"ALICE": 1, "BOB": 1, "CAROL": 1, "DAVE": 2, "EVE": 1}
INDEX = {"ALICE": 0, "BOB": 1, "CAROL": 2, "DAVE": 3, "EVE": 4}
q = lambda s: '"' + s + '"'
arrq = lambda xs: "[" + ", ".join(q(x) for x in xs) + "]"
zeros = lambda n: "[" + ", ".join(['"0"'] * n) + "]"

t = [f"policy_commitment_pub = {q(commitment)}",
     f"authorization_digest_hi = {q(str(int(g('DIGEST_HI'), 16)))}",
     f"authorization_digest_lo = {q(str(int(g('DIGEST_LO'), 16)))}",
     f"roster_root = {q(roster_root)}", 'threshold = "3"', 'salt = "0x5a17ed5a17ed5a17ed"', ""]
def nums(s): return "[" + ", ".join(q(x.strip()) for x in s.strip("[]").split(",")) + "]"
for m in ["ALICE", "CAROL", "EVE", None]:
    t.append("[[approvals]]")
    if m is None:
        t += ['enabled = false', 'kind = "0"', 'weight = "0"', 'leaf_index = "0"', f"path = {zeros(4)}",
              f"pk_x = {zeros(32)}", f"pk_y = {zeros(32)}", f"rp_id_hash = {zeros(32)}", f"signature = {zeros(64)}",
              f"auth_data = {zeros(37)}", f"client_data_json = {zeros(256)}", 'client_data_json_len = "0"']
    else:
        t += ['enabled = true', f'kind = "{g(m + "_KIND")}"', f'weight = "{WEIGHTS[m]}"', f'leaf_index = "{INDEX[m]}"',
              f"path = {arrq(paths[INDEX[m]])}", f"pk_x = {nums(g(m+'_X'))}", f"pk_y = {nums(g(m+'_Y'))}",
              f"rp_id_hash = {nums(g(m+'_RP'))}", f"signature = {nums(g(m+'_SIG'))}", f"auth_data = {nums(g(m+'_AD'))}",
              f"client_data_json = {nums(g(m+'_CDJ'))}", f'client_data_json_len = "{g(m+"_CDJ_LEN")}"']
    t.append("")
(root / "Prover.toml").write_text("\n".join(t))
print("wrote Prover.toml; commitment", commitment)
