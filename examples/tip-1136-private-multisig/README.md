# TIP-1136 reference circuit: private weighted multisig

A working Noir circuit for the `PrivateAuthorizationV1` relation in TIP-1136,
specialized to a **private weighted multisig with mixed signer types**.

> Research reference. Unaudited. Test keys only. Not for custody.

## What the chain learns

```text
public:  policy_commitment          // stored in the account's policy-owner descriptor
         authorization_digest (hi,lo) // reconstructed by the chain from the exact operation
```

That is all. The proof says: *"a set of members of the roster committed to in
`policy_commitment`, whose weights sum to at least the committed threshold,
each approved exactly `authorization_digest`."*

Hidden: roster size and membership, each member's key/kind/weight, the threshold,
which members signed and how many (up to the profile bound).

## Policy

```text
leaf_i            = Poseidon2("tempo:member:v1", kind, weight, pkX(hi,lo), pkY(hi,lo), rpIdHash(hi,lo))
roster_root       = Merkle_Poseidon2(depth 4, 16 leaves, unused = 0)
policy_commitment = Poseidon2("tempo:policy:v1", roster_root, threshold, salt)
```

Example policy used by the tests (threshold 3):

| idx | member | kind | weight |
|---|---|---|---|
| 0 | alice | secp256k1 key (hardware wallet) | 1 |
| 1 | bob   | secp256k1 key | 1 |
| 2 | carol | WebAuthn passkey (P-256) | 1 |
| 3 | dave  | WebAuthn passkey (CFO) | 2 |
| 4 | eve   | secp256k1 key | 1 |

## Relation (src/main.nr)

For up to `MAX_APPROVALS = 4` slots:

1. `Poseidon2(policy) == policy_commitment` (private threshold/salt/root).
2. Each enabled slot opens a leaf in `roster_root` — kind and **weight are inside the leaf**, so a prover cannot inflate weight.
3. Enabled slots are packed first, with strictly increasing `leaf_index` → no member counted twice; padding is inert.
4. Signature check over the exact digest:
   - secp256k1: ECDSA over the 32-byte digest.
   - passkey: strict WebAuthn — `clientDataJSON` must start with
     `{"type":"webauthn.get","challenge":"<base64url(digest)>"`, authenticatorData rpIdHash must equal the committed one,
     UP and UV flags required, P-256 over `sha256(authData ‖ sha256(clientDataJSON))`.
5. `Σ weight ≥ threshold`.

## Run

```sh
noirup -v 1.0.0-beta.26
nargo test                         # 18 tests: 3 accept, 13 adversarial, 2 helpers
python3 scripts/gen_vectors.py     # regenerate deterministic test keys/signatures
python3 scripts/gen_prover_toml.py # alice(k1) + carol(passkey) + eve(k1)
nargo execute
nargo info                         # ~14.2k ACIR opcodes
```

With ProveKit (pinned `c87957a`):

```sh
provekit-cli prepare
provekit-cli prove
provekit-cli verify
```

## Adversarial tests

| test | attack |
|---|---|
| `two_light_signers_insufficient` | weight 2 < 3 |
| `same_member_twice` / `out_of_order` | double count a member |
| `padding_gap` | smuggle approvals behind a disabled slot |
| `inflated_weight` | claim a larger weight than committed |
| `outsider_with_stolen_path` | non-member key reusing a member's Merkle path |
| `signature_over_other_action` / `passkey_over_other_action` | replay approval for a different digest |
| `wrong_salt` / `prover_lowers_threshold` | open the policy differently |
| `passkey_without_user_verification` | UV bit cleared, validly signed |
| `passkey_for_other_rp` | assertion for another RP |
| `tampered_client_data` | modify signed clientDataJSON |

## Known limitations

- Origin is not checked in-circuit; only the committed RP ID hash. `clientDataJSON` must use the canonical browser prefix.
- 37-byte authenticatorData only (no extensions). Signature counter not enforced.
- "Distinct members" are distinct roster positions; a policy that lists the same key twice counts it twice.
- Profile bounds (16 members / 4 approvals) are observable; larger profiles are separate registered circuits.
- Google OIDC (RSA + JWT) and SMS attestation factors are not in this example; they slot in as additional `kind`s.
- No chain-side wrapper or verifier is included here.
